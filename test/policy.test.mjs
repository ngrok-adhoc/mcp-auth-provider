import assert from "node:assert/strict";
import test from "node:test";
import { createPolicy, createValidationPolicy } from "../lib/policy.mjs";

const settings = {
  issuer: "https://example.ngrok.app",
  mcpInternalUrl: "https://mcp.internal",
  validationUrl: "https://validator.internal",
  gatewaySecret: "private-per-run-secret",
  ownerEmail: "owner@example.com",
};
const expression = (rule) => (rule.expressions ?? []).join(" && ");
const withAction = (rules, type) =>
  rules.filter((rule) => rule.actions.some((action) => action.type === type));

test("only an exact allowed Google owner receives trusted helper access", () => {
  const ownerEmail = 'owner"\\@example.com';
  const rules = createPolicy({ ...settings, ownerEmail }).on_http_request;
  assert.deepEqual(rules[0].actions[0].config.headers, [
    "x-demo-gateway-secret",
    "x-mcp-auth-gateway-secret",
  ]);
  const google = withAction(rules, "oauth");
  assert.equal(google.length, 1);
  assert.match(expression(google[0]), /mcp-debug/);
  assert.match(expression(google[0]), /interaction/);
  assert.match(expression(google[0]), /ngrok/);
  const grants = withAction(rules, "add-headers");
  assert.equal(grants.length, 1);
  assert.ok(expression(grants[0]).includes(`identity.email == ${JSON.stringify(ownerEmail)}`));
  assert.match(expression(grants[0]), /has\(actions.ngrok.oauth.identity.email\)/);
  assert.equal(
    grants[0].actions.at(-1).config.headers["x-demo-gateway-secret"],
    settings.gatewaySecret,
  );
  assert.throws(() => createPolicy({ ...settings, ownerEmail: "" }), /OWNER_EMAIL/);
});

test("MCP forwarding requires an exact positive validator response and fails closed", () => {
  const rules = createPolicy(settings).on_http_request;
  const forwarding = withAction(rules, "forward-internal").find((rule) =>
    rule.actions.some((action) => action.config?.url === settings.mcpInternalUrl),
  );
  assert.match(expression(forwarding), /status_code == 200/);
  assert.ok(expression(forwarding).includes(`body == '{"valid":true}'`));
  assert.equal(forwarding.actions[0].type, "remove-headers");
  assert.deepEqual(forwarding.actions[0].config.headers, ["authorization"]);
  assert.equal(forwarding.actions[1].config.on_error, "continue");
  assert.equal(forwarding.actions[2].config.status_code, 503);
  assert.match(forwarding.actions[2].config.body, /MCP_URL/);
  const after = rules[rules.indexOf(forwarding) + 1];
  assert.equal(after.actions[0].config.status_code, 401);
  assert.match(after.actions[0].config.headers["www-authenticate"], /resource_metadata=/);
  const request = withAction(rules, "http-request")[0].actions[0];
  assert.equal(request.config.max_redirects, 0);
  assert.equal(request.config.on_error, "continue");
  assert.equal(
    rules.find((rule) => expression(rule).includes("!has(actions.ngrok.http_request.res)"))
      .actions[0].config.status_code,
    503,
  );
});

test("OAuth, debug and app routes remain on the public listener's upstream", () => {
  const rules = createPolicy(settings).on_http_request;
  const forwarding = withAction(rules, "forward-internal");
  assert.equal(forwarding.length, 1);
  assert.equal(
    forwarding[0].actions.find((action) => action.type === "forward-internal").config.url,
    settings.mcpInternalUrl,
  );
  assert.equal(expression(forwarding[0]).startsWith("req.url.path == '/mcp' &&"), true);
  assert.ok(
    !rules.some(
      (rule) =>
        rule.expressions === undefined &&
        rule.actions.some((action) => action.type !== "remove-headers"),
    ),
  );
  assert.ok(!rules.some((rule) => expression(rule).includes("req.url.path == '/'")));
  const reserved = rules.filter((rule) =>
    rule.actions.some((action) => action.config?.status_code === 404),
  );
  assert.equal(reserved.length, 1);
  assert.equal(expression(reserved[0]), "req.url.path.startsWith('/mcp/')");
});

test("JWT validator positively requires verified audience, scope and parsed time", () => {
  const rules = createValidationPolicy({
    issuer: settings.issuer,
    jwksUrl: `${settings.issuer}/jwks?v=current`,
  }).on_http_request;
  const jwt = rules[0].actions[0].config;
  assert.equal(jwt.audience.allow_list[0].value, `${settings.issuer}/mcp`);
  assert.deepEqual(jwt.jws.allowed_algorithms, ["RS256"]);
  assert.equal(rules[1].actions[0].config.status_code, 403);
  const allow = rules.find((rule) =>
    rule.actions.some((action) => action.config?.body === '{"valid":true}'),
  );
  assert.match(expression(allow), /tokens\[0\].verified/);
  assert.match(expression(allow), /'exp' in/);
  assert.match(expression(allow), /timestamp\(time.now\)/);
  assert.match(expression(allow), /payload.nbf/);
  assert.equal(rules.at(-1).actions[0].config.status_code, 401);
});

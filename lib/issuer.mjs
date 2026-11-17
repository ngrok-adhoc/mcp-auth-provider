import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import Provider, { errors } from "oidc-provider";

const equal = (a, b) => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};
const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char],
  );

export function createIssuer({
  issuer,
  gatewaySecret,
  jwks,
  resource = `${new URL(issuer).origin}/mcp`,
}) {
  const base = new URL(issuer);
  if (
    base.href !== `${base.origin}/` ||
    (base.protocol !== "https:" &&
      !(base.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname)))
  ) {
    throw new Error("Issuer must be an HTTPS origin (HTTP loopback is allowed for tests).");
  }
  if (typeof gatewaySecret !== "string" || gatewaySecret.length < 32)
    throw new Error("A gateway secret of at least 32 characters is required.");
  const target = new URL(resource);
  if (
    (target.protocol !== "https:" &&
      !(
        target.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname)
      )) ||
    target.username ||
    target.password ||
    target.hash
  ) {
    throw new Error("Resource must be an HTTPS URL (HTTP loopback is allowed for tests).");
  }
  resource = target.href;
  const cookieKey = randomBytes(32).toString("base64url");
  // shortcut: default in-memory adapter and per-run cookies invalidate sessions on restart; persist before sharing beyond a demo.
  const provider = new Provider(base.origin, {
    jwks,
    cookies: {
      keys: [cookieKey],
      short: { secure: base.protocol === "https:", sameSite: "lax" },
      long: { secure: base.protocol === "https:", sameSite: "lax" },
    },
    clients: [],
    clientDefaults: {
      application_type: "native",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    },
    extraClientMetadata: {
      properties: ["client_name"],
      validator(_ctx, _key, _value, metadata) {
        // Some CLI clients label loopback callbacks as web; the explicit redirect check below is the boundary.
        if (
          !["native", "web"].includes(metadata.application_type) ||
          metadata.token_endpoint_auth_method !== "none" ||
          metadata.grant_types.some(
            (type) => !["authorization_code", "refresh_token"].includes(type),
          ) ||
          metadata.response_types.some((type) => type !== "code")
        ) {
          throw new errors.InvalidClientMetadata(
            "Only public authorization-code clients are supported.",
          );
        }
        if (
          Buffer.byteLength(JSON.stringify(metadata)) > 16384 ||
          metadata.redirect_uris.some((value) => {
            const url = new URL(value);
            return (
              url.protocol !== "http:" ||
              !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
              url.username ||
              url.password ||
              url.hash
            );
          })
        )
          throw new errors.InvalidClientMetadata(
            "Use HTTP loopback redirects and metadata smaller than 16 KiB.",
          );
      },
    },
    responseTypes: ["code"],
    scopes: ["mcp:use"],
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: true, issueRegistrationAccessToken: false },
      userinfo: { enabled: false },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => resource,
        useGrantedResource: () => true,
        getResourceServerInfo(_ctx, target) {
          if (target !== resource) throw new errors.InvalidTarget();
          return {
            scope: "mcp:use",
            audience: resource,
            accessTokenFormat: "jwt",
            accessTokenTTL: 300,
            jwt: { sign: { alg: "RS256" } },
          };
        },
      },
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    findAccount: (_ctx, id) => ({ accountId: id, claims: async () => ({ sub: id }) }),
    // CLI clients register refresh_token alongside code; accept that metadata without issuing refresh tokens.
    issueRefreshToken: () => false,
    ttl: { AccessToken: 300, AuthorizationCode: 60, Interaction: 600, Session: 3600, Grant: 3600 },
  });
  provider.proxy = true;
  provider.use(async (ctx, next) => {
    if (ctx.path === "/auth" && ctx.method === "GET" && !ctx.query.scope) {
      const query = new URLSearchParams(ctx.querystring);
      query.set("scope", "mcp:use");
      ctx.querystring = query.toString();
    }
    await next();
  });
  const callback = provider.callback();
  const csrf = (uid) => createHmac("sha256", cookieKey).update(uid).digest("base64url");
  function reply(res, status, message, type = "text/plain", callbackOrigin = "") {
    res.writeHead(status, {
      "Content-Type": `${type}; charset=utf-8`,
      "Cache-Control": "no-store",
      "Referrer-Policy": "same-origin",
      "X-Frame-Options": "DENY",
      // Browser form redirects must reach this already-validated client callback.
      "Content-Security-Policy": `default-src 'none'; form-action 'self' ${callbackOrigin}; frame-ancestors 'none'`,
    });
    res.end(message);
  }
  async function handle(req, res) {
    try {
      const path = new URL(req.url ?? "/", base).pathname;
      if (!path.startsWith("/interaction/")) {
        if (path === "/.well-known/oauth-authorization-server")
          req.url = "/.well-known/openid-configuration";
        await callback(req, res);
        return;
      }
      const secret = req.headers["x-mcp-oauth-provider-secret"];
      if (typeof secret !== "string" || !equal(secret, gatewaySecret))
        return reply(res, 403, "Open this authorization page through the ngrok sign-in gateway.");
      if (!["GET", "POST"].includes(req.method)) {
        res.setHeader("Allow", "GET, POST");
        return reply(res, 405, "Use GET or POST.");
      }
      const interaction = await provider.interactionDetails(req, res);
      if (path !== `/interaction/${interaction.uid}`)
        return reply(res, 400, "Restart authorization.");
      if (req.method === "GET") {
        return reply(
          res,
          200,
          `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MCP OAuth Provider</title><h1>Authorize MCP access</h1><p>Allow this client to use your MCP server?</p><dl><dt>Client</dt><dd>${escape(interaction.params.client_id)}</dd><dt>Redirect</dt><dd>${escape(interaction.params.redirect_uri)}</dd><dt>Permission</dt><dd>mcp:use</dd></dl><form method="post" action="/interaction/${escape(interaction.uid)}"><input type="hidden" name="csrf" value="${csrf(interaction.uid)}"><button name="decision" value="deny">Deny</button> <button name="decision" value="allow">Allow</button></form></html>`,
          "text/html",
          new URL(interaction.params.redirect_uri).origin,
        );
      }
      if (
        req.headers.origin !== base.origin ||
        req.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded"
      )
        return reply(res, 403, "Reload this page and submit its authorization form.");
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 4096) return reply(res, 413, "Authorization form is too large.");
        chunks.push(Buffer.from(chunk));
      }
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      if (form.getAll("csrf").length !== 1 || !equal(form.get("csrf") ?? "", csrf(interaction.uid)))
        return reply(res, 403, "Authorization form expired. Restart authorization.");
      if (form.getAll("decision").length !== 1 || !["allow", "deny"].includes(form.get("decision")))
        return reply(res, 400, "Choose Allow or Deny.");
      if (form.get("decision") === "deny")
        return provider.interactionFinished(
          req,
          res,
          { error: "access_denied", error_description: "The owner denied access." },
          { mergeWithLastSubmission: false },
        );
      if (interaction.prompt.name === "login")
        return provider.interactionFinished(
          req,
          res,
          { login: { accountId: "owner", amr: ["ngrok"], remember: true } },
          { mergeWithLastSubmission: false },
        );
      if (interaction.prompt.name !== "consent" || interaction.session?.accountId !== "owner")
        return reply(res, 400, "Restart authorization.");
      const grant = interaction.grantId
        ? await provider.Grant.find(interaction.grantId)
        : new provider.Grant({
            accountId: "owner",
            clientId: String(interaction.params.client_id),
          });
      if (!grant) return reply(res, 400, "Authorization expired. Restart authorization.");
      if (interaction.prompt.details.missingOIDCScope)
        grant.addOIDCScope(interaction.prompt.details.missingOIDCScope);
      if (interaction.prompt.details.missingOIDCClaims)
        grant.addOIDCClaims(interaction.prompt.details.missingOIDCClaims);
      grant.addResourceScope(resource, "mcp:use");
      return provider.interactionFinished(
        req,
        res,
        { consent: { grantId: await grant.save() } },
        { mergeWithLastSubmission: true },
      );
    } catch (error) {
      if (!res.headersSent)
        reply(
          res,
          error.statusCode && error.statusCode < 500 ? error.statusCode : 400,
          "Authorization request failed. Restart authorization.",
        );
      else if (!res.writableEnded) res.end();
    }
  }
  return { provider, handle };
}

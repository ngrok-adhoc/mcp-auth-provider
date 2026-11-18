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
      grant_types: ["authorization_code", "refresh_token"],
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
            jwt: { sign: { alg: "RS256" } },
          };
        },
      },
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    findAccount: (_ctx, id) => ({ accountId: id, claims: async () => ({ sub: id }) }),
    issueRefreshToken: (_ctx, client) => client.grantTypeAllowed("refresh_token"),
    rotateRefreshToken: true,
    // Access and refresh expire with the original grant, even after rotation or browser-session expiry.
    expiresWithSession: () => false,
    ttl: {
      AccessToken: (ctx) => ctx.oidc.entities.Grant.remainingTTL,
      AuthorizationCode: 15 * 60,
      Interaction: 24 * 60 * 60,
      Session: 24 * 60 * 60,
      Grant: 90 * 24 * 60 * 60,
      RefreshToken: (ctx) => ctx.oidc.entities.Grant.remainingTTL,
    },
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
      "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${callbackOrigin}; frame-ancestors 'none'`,
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
      // The gateway already authenticated the owner; only consent needs a browser form.
      if (req.method === "GET" && interaction.prompt.name === "login")
        return provider.interactionFinished(
          req,
          res,
          { login: { accountId: "owner", amr: ["ngrok"], remember: true } },
          { mergeWithLastSubmission: false },
        );
      if (interaction.prompt.name !== "consent" || interaction.session?.accountId !== "owner")
        return reply(res, 400, "Restart authorization.");
      if (req.method === "GET") {
        const client = await provider.Client.find(String(interaction.params.client_id));
        const name = client?.metadata().client_name;
        const clientName = typeof name === "string" && name.trim() ? name : "MCP client";
        return reply(
          res,
          200,
          `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCP OAuth Provider</title><style>
:root{color-scheme:light dark;--base:#fafafa;--surface:#fff;--ink:#171717;--muted:#666;--line:#e5e5e5;--focus:#006b9c;--inverse:#fff}*{box-sizing:border-box}body{margin:0;background:var(--base);color:var(--ink);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.provider{text-align:center;font-size:15px;font-weight:600;padding:32px 24px}main{max-width:880px;margin:52px auto 64px;padding:0 32px}.intro{text-align:center;margin-bottom:56px}h1{font-size:38px;line-height:1.2;letter-spacing:-1px;font-weight:500;margin:0 0 20px;overflow-wrap:anywhere}.intro p{margin:0 auto;max-width:56ch;color:var(--muted)}.server{display:block;color:var(--ink);margin-top:14px;overflow-wrap:anywhere}.permission{border:1px solid var(--line);border-radius:12px;background:var(--surface);padding:28px 32px}h2{font-size:20px;line-height:1.4;font-weight:600;margin:0 0 10px}p{margin:0}.permission p+p{margin-top:14px}.muted{color:var(--muted);font-size:14px}details{margin-top:24px;font-size:14px;color:var(--muted)}summary{cursor:pointer;width:fit-content}dl{display:grid;grid-template-columns:140px minmax(0,1fr);gap:10px 20px;margin:20px 0}dt{font-weight:500}dd{margin:0;overflow-wrap:anywhere;color:var(--ink)}code{font:13px/1.6 ui-monospace,SFMono-Regular,monospace}form{margin-top:40px;border-top:1px solid var(--line);padding-top:24px;display:flex;align-items:center;justify-content:space-between;gap:24px}.expiry{font-size:14px;color:var(--muted)}.actions{display:flex;gap:10px;flex-shrink:0}button{height:36px;display:inline-flex;align-items:center;justify-content:center;padding:7px 16px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink);font:500 14px/20px ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer}.primary{background:var(--ink);color:var(--inverse);border-color:var(--ink)}button:hover{filter:brightness(.94)}button:focus-visible,summary:focus-visible{outline:3px solid var(--focus);outline-offset:4px}@media(prefers-color-scheme:dark){:root{--base:#121212;--surface:#171717;--ink:#fafafa;--muted:#a3a3a3;--line:#333;--focus:#61ccff;--inverse:#171717}}@media(max-width:820px){main{margin:36px auto 48px;padding:0 28px}.intro{margin-bottom:36px}h1{font-size:32px}.permission{padding:24px}}@media(max-width:560px){main{padding:0 20px}h1{font-size:28px}form{align-items:flex-start;flex-direction:column;gap:18px}.actions{align-self:flex-end}dl{grid-template-columns:1fr;gap:4px}dd{margin-bottom:10px}}
</style></head><body><header class="provider">MCP OAuth Provider</header><main><section class="intro"><h1>${escape(clientName)} wants to connect to your MCP server</h1><p>You are authorizing access to your development server.<span class="server">${escape(new URL(resource).host)}</span></p></section><section class="permission" aria-labelledby="permission-title"><h2 id="permission-title">Use your MCP server</h2><p>Allow this client to discover and call the tools your server exposes.</p><p class="muted">This connection does not separate read-only and write access. Only authorize a client you trust with your development server.</p></section><details><summary>Connection details</summary><dl><dt>Client name</dt><dd>${escape(clientName)} <span class="muted">(provided by the client)</span></dd><dt>Client ID</dt><dd><code>${escape(interaction.params.client_id)}</code></dd><dt>MCP endpoint</dt><dd><code>${escape(resource)}</code></dd><dt>Return address</dt><dd><code>${escape(interaction.params.redirect_uri)}</code></dd></dl></details><form method="post" action="/interaction/${escape(interaction.uid)}"><input type="hidden" name="csrf" value="${csrf(interaction.uid)}"><p class="expiry">Access lasts up to 90 days.</p><div class="actions"><button type="submit" name="decision" value="deny">Cancel</button><button type="submit" class="primary" name="decision" value="allow">Authorize</button></div></form></main></body></html>`,
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
        return reply(res, 400, "Choose Authorize or Cancel.");
      if (form.get("decision") === "deny")
        return provider.interactionFinished(
          req,
          res,
          { error: "access_denied", error_description: "The owner denied access." },
          { mergeWithLastSubmission: false },
        );
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

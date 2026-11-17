const json = (body, status_code = 200, headers = {}) => ({
  type: "custom-response",
  config: {
    status_code,
    body: JSON.stringify(body),
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  },
});

export function createPolicy({ issuer, mcpInternalUrl, validationUrl, gatewaySecret, ownerEmail }) {
  if (typeof ownerEmail !== "string" || !ownerEmail.trim())
    throw new Error("Set OWNER_EMAIL to the Google account allowed to connect.");
  const challenge = `Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource/mcp", scope="mcp:use"`;
  const protectedBrowser =
    "(req.url.path.startsWith('/interaction/') || req.url.path == '/mcp-debug' || req.url.path.startsWith('/mcp-debug/'))";
  const allowedOwner = `has(actions.ngrok.oauth.identity.email) && actions.ngrok.oauth.identity.email == ${JSON.stringify(ownerEmail)}`;
  return {
    on_http_request: [
      {
        actions: [
          {
            type: "remove-headers",
            config: { headers: ["x-demo-gateway-secret", "x-mcp-auth-gateway-secret"] },
          },
        ],
      },
      {
        expressions: [`${protectedBrowser} || req.url.path.startsWith('/ngrok/')`],
        actions: [{ type: "oauth", config: { provider: "google" } }],
      },
      {
        expressions: [`${protectedBrowser} && !(${allowedOwner})`],
        actions: [
          json(
            {
              error: "owner_required",
              message: "Sign in with the Google account configured in OWNER_EMAIL.",
            },
            403,
          ),
        ],
      },
      {
        expressions: [`${protectedBrowser} && (${allowedOwner})`],
        actions: [
          { type: "remove-headers", config: { headers: ["authorization"] } },
          { type: "add-headers", config: { headers: { "x-demo-gateway-secret": gatewaySecret } } },
        ],
      },
      {
        expressions: [
          "req.url.path in ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']",
        ],
        actions: [
          json({
            resource: `${issuer}/mcp`,
            authorization_servers: [issuer],
            scopes_supported: ["mcp:use"],
            bearer_methods_supported: ["header"],
          }),
        ],
      },
      {
        expressions: ["req.url.path.startsWith('/mcp/')"],
        actions: [
          json(
            {
              error: "mcp_path",
              message: "Connect your MCP client to /mcp without a trailing slash or extra path.",
            },
            404,
          ),
        ],
      },
      {
        expressions: ["req.url.path == '/mcp' && !hasReqHeader('authorization')"],
        actions: [json({ error: "OAuth required" }, 401, { "www-authenticate": challenge })],
      },
      {
        expressions: ["req.url.path == '/mcp'"],
        actions: [
          {
            type: "http-request",
            config: {
              url: validationUrl,
              method: "POST",
              headers: {
                authorization: "${getReqHeader('authorization')[0]}",
                "content-type": "application/json",
              },
              body: "{}",
              timeout: "3s",
              max_redirects: 0,
              on_error: "continue",
            },
          },
        ],
      },
      {
        expressions: [
          "req.url.path == '/mcp' && (!has(actions.ngrok.http_request.res) || actions.ngrok.http_request.res.status_code == 404 || actions.ngrok.http_request.res.status_code >= 500)",
        ],
        actions: [
          json(
            {
              error: "validation_unavailable",
              message:
                "The token validator is unavailable. Check the CLI terminal and restart MCP Auth Provider.",
            },
            503,
          ),
        ],
      },
      {
        expressions: [
          `req.url.path == '/mcp' && actions.ngrok.http_request.res.status_code == 403 && actions.ngrok.http_request.res.body == '{"error":"insufficient_scope"}'`,
        ],
        actions: [json({ error: "insufficient_scope" }, 403, { "www-authenticate": challenge })],
      },
      {
        expressions: [
          "req.url.path == '/mcp' && actions.ngrok.http_request.res.status_code != 200",
        ],
        actions: [json({ error: "invalid_token" }, 401, { "www-authenticate": challenge })],
      },
      {
        expressions: [
          "req.url.path == '/mcp' && has(actions.ngrok.http_request.res) && actions.ngrok.http_request.res.status_code == 200 && actions.ngrok.http_request.res.body == '{\"valid\":true}'",
        ],
        actions: [
          { type: "remove-headers", config: { headers: ["authorization"] } },
          { type: "forward-internal", config: { url: mcpInternalUrl, on_error: "continue" } },
          json(
            {
              error: "mcp_unavailable",
              message:
                "The MCP connection is offline. Start your MCP server and check MCP_URL in .env; see /mcp-debug.",
            },
            503,
          ),
        ],
      },
      {
        expressions: ["req.url.path == '/mcp'"],
        actions: [json({ error: "invalid_token" }, 401, { "www-authenticate": challenge })],
      },
    ],
  };
}

// The outer policy converts ngrok's JWT failures into MCP's 401 challenge.
export function createValidationPolicy({ issuer, jwksUrl }) {
  const challenge = `Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource/mcp", scope="mcp:use"`;
  return {
    on_http_request: [
      {
        actions: [
          {
            type: "jwt-validation",
            config: {
              issuer: { allow_list: [{ value: issuer }] },
              audience: { allow_list: [{ value: `${issuer}/mcp` }] },
              http: {
                tokens: [
                  {
                    type: "access_token",
                    method: "header",
                    name: "authorization",
                    prefix: "Bearer ",
                  },
                ],
              },
              jws: {
                allowed_algorithms: ["RS256"],
                keys: { sources: { additional_jkus: [jwksUrl] } },
              },
            },
          },
        ],
      },
      {
        expressions: [
          "(!('scope' in actions.ngrok.jwt_validation.tokens[0].payload) || !('mcp:use' in actions.ngrok.jwt_validation.tokens[0].payload.scope.split(' ')))",
        ],
        actions: [json({ error: "insufficient_scope" }, 403, { "www-authenticate": challenge })],
      },
      // ngrok exposes temporal JWT claims as Go-formatted UTC strings; parsing failures fall through to denial.
      {
        expressions: [
          "actions.ngrok.jwt_validation.tokens[0].verified && 'exp' in actions.ngrok.jwt_validation.tokens[0].payload && timestamp(actions.ngrok.jwt_validation.tokens[0].payload.exp.replace(' +0000 UTC','Z').replace(' ','T')) > timestamp(time.now) && (!('nbf' in actions.ngrok.jwt_validation.tokens[0].payload) || timestamp(actions.ngrok.jwt_validation.tokens[0].payload.nbf.replace(' +0000 UTC','Z').replace(' ','T')) <= timestamp(time.now))",
        ],
        actions: [json({ valid: true })],
      },
      { actions: [json({ error: "invalid_token" }, 401)] },
    ],
  };
}

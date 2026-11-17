import { randomBytes } from "node:crypto";
import https from "node:https";

import { createPolicy, createValidationPolicy } from "./policy.mjs";

function publicOrigin(value) {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  )
    throw new Error("PUBLIC_URL must be an HTTPS origin without a path.");
  return url.origin;
}

function localOrigin(value) {
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  )
    throw new Error("The local tunnel upstream must be an HTTP loopback origin.");
  return url.origin;
}

async function closeResources(session, listeners) {
  await Promise.allSettled(listeners.map((listener) => listener.close()));
  await session.close().catch(() => {});
}

export async function reservePublicUrl({ authtoken, publicUrl, sdk }) {
  sdk ??= (await import("@ngrok/ngrok")).default;
  const session = await new sdk.SessionBuilder().authtoken(authtoken).connect();
  let provisional;
  try {
    let issuer;
    if (publicUrl) issuer = publicOrigin(publicUrl);
    else {
      provisional = await session
        .httpEndpoint()
        .binding("public")
        .trafficPolicy(
          JSON.stringify({
            on_http_request: [
              {
                actions: [
                  {
                    type: "custom-response",
                    config: {
                      status_code: 503,
                      body: "MCP Auth Provider is starting. Retry shortly.",
                      headers: { "content-type": "text/plain", "cache-control": "no-store" },
                    },
                  },
                ],
              },
            ],
          }),
        )
        .listen();
      issuer = publicOrigin(provisional.url());
      await provisional.close();
      provisional = undefined;
    }
    return {
      session,
      issuer,
      close: () => closeResources(session, provisional ? [provisional] : []),
    };
  } catch (error) {
    await closeResources(session, provisional ? [provisional] : []);
    throw error;
  }
}

async function waitForJwks(url) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const ready = await new Promise((resolve) => {
      const request = https.get(url, { agent: false }, (response) => {
        response.resume();
        resolve(response.statusCode === 200);
      });
      request.on("error", () => resolve(false));
      request.setTimeout(2000, () => {
        request.destroy();
        resolve(false);
      });
    });
    if (ready) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(
    "The public signing-key endpoint did not become reachable. Check ngrok connectivity and restart MCP Auth Provider.",
  );
}

export async function startTunnels({
  session,
  issuer,
  helperUrl,
  mcpUrl,
  gatewaySecret,
  ownerEmail,
  jwksUrl,
}) {
  const listeners = [];
  try {
    issuer = publicOrigin(issuer);
    helperUrl = localOrigin(helperUrl);
    mcpUrl = localOrigin(mcpUrl);
    const suffix = randomBytes(8).toString("hex");
    const mcpInternalUrl = `https://mcp-auth-backend-${suffix}.internal`;
    const validationUrl = `https://mcp-auth-validator-${suffix}.internal`;
    jwksUrl ??= `${issuer}/jwks?v=${suffix}`;
    const keyUrl = new URL(jwksUrl);
    if (keyUrl.origin !== issuer || keyUrl.pathname !== "/jwks")
      throw new Error("Signing keys must be served by this provider's /jwks endpoint.");
    const policy = createPolicy({
      issuer,
      mcpInternalUrl,
      validationUrl,
      gatewaySecret,
      ownerEmail,
    });
    listeners.push(
      await session
        .httpEndpoint()
        .domain(new URL(mcpInternalUrl).hostname)
        .binding("internal")
        .listenAndForward(mcpUrl),
    );
    listeners.push(
      await session
        .httpEndpoint()
        .domain(new URL(issuer).hostname)
        .binding("public")
        .trafficPolicy(JSON.stringify(policy))
        .listenAndForward(helperUrl),
    );
    // The JWT validator fetches signing keys when its policy is registered.
    await waitForJwks(jwksUrl);
    listeners.push(
      await session
        .httpEndpoint()
        .domain(new URL(validationUrl).hostname)
        .binding("internal")
        .trafficPolicy(JSON.stringify(createValidationPolicy({ issuer, jwksUrl })))
        .listen(),
    );
    return { issuer, listeners, close: () => closeResources(session, listeners) };
  } catch (error) {
    await closeResources(session, listeners);
    throw error;
  }
}

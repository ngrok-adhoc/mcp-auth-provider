import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";

import { createIssuer } from "../lib/issuer.mjs";

test("loopback OAuth: gateway, consent, PKCE, JWT audience and one-time codes", async (t) => {
  let handle;
  const server = createServer((req, res) => handle(req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const issuer = `http://127.0.0.1:${server.address().port}`;
  const gatewaySecret = "test-gateway-secret-".repeat(3);
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const key = {
    ...privateKey.export({ format: "jwk" }),
    kid: "issuer-test",
    use: "sig",
    alg: "RS256",
  };
  const resource = "https://mcp-auth-provider.example/mcp";
  ({ handle } = createIssuer({ issuer, gatewaySecret, jwks: { keys: [key] }, resource }));
  const cookies = new Map();
  async function request(path, options = {}) {
    const response = await fetch(new URL(path, issuer), {
      ...options,
      redirect: "manual",
      headers: {
        Cookie: [...cookies].map(([name, value]) => `${name}=${value}`).join("; "),
        ...options.headers,
      },
    });
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(";");
      const index = pair.indexOf("=");
      cookies.set(pair.slice(0, index), pair.slice(index + 1));
    }
    return response;
  }
  const registration = {
    application_type: "native",
    client_name: "Local test",
    redirect_uris: ["http://127.0.0.1:9988/callback"],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
  const register = (body) =>
    request("/reg", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  assert.equal(
    (await register({ ...registration, redirect_uris: ["https://example.com/callback"] })).status,
    400,
  );
  assert.equal(
    (
      await register({
        ...registration,
        application_type: "web",
        redirect_uris: ["https://example.com/callback"],
      })
    ).status,
    400,
  );
  assert.equal(
    (await register({ ...registration, grant_types: ["client_credentials"] })).status,
    400,
  );
  assert.equal((await register(registration)).status, 201);
  const registered = await register({
    ...registration,
    application_type: "web",
    grant_types: ["authorization_code", "refresh_token"],
  });
  assert.equal(registered.status, 201, await registered.clone().text());
  const client = await registered.json();
  const metadata = await (await request("/.well-known/oauth-authorization-server")).json();
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
  assert.ok(metadata.grant_types_supported.includes("authorization_code"));
  const verifier = randomBytes(32).toString("base64url");
  const params = {
    client_id: client.client_id,
    redirect_uri: registration.redirect_uris[0],
    response_type: "code",
    scope: "mcp:use",
    resource,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state: "test-state",
  };
  const authorize = (extra = {}) =>
    request(`/auth?${new URLSearchParams({ ...params, ...extra })}`);
  let response = await authorize({ code_challenge: "", code_challenge_method: "" });
  assert.match(response.headers.get("location") ?? (await response.text()), /invalid_request/);
  response = await authorize({ code_challenge_method: "plain" });
  assert.match(response.headers.get("location") ?? (await response.text()), /invalid_request/);
  async function code() {
    let result = await authorize();
    for (let step = 0; step < 10; step++) {
      const location = result.headers.get("location");
      assert.ok(location, `Expected OAuth redirect, got ${result.status}: ${await result.text()}`);
      if (location.startsWith(registration.redirect_uris[0])) {
        const url = new URL(location);
        assert.equal(url.searchParams.get("state"), "test-state");
        assert.ok(url.searchParams.get("code"), location);
        return url.searchParams.get("code");
      }
      if (location.startsWith("/interaction/")) {
        assert.equal((await request(location)).status, 403);
        assert.equal(
          (await request(location, { headers: { "x-demo-gateway-secret": "incorrect" } })).status,
          403,
        );
        assert.equal(
          (
            await request(location, {
              method: "DELETE",
              headers: { "x-demo-gateway-secret": gatewaySecret },
            })
          ).status,
          405,
        );
        const page = await request(location, {
          headers: { "x-demo-gateway-secret": gatewaySecret },
        });
        assert.equal(page.status, 200, await page.clone().text());
        assert.ok(page.headers.get("content-security-policy").includes("http://127.0.0.1:9988"));
        const html = await page.text();
        assert.match(html, /<title>MCP Auth Provider<\/title>/);
        assert.match(html, /Allow this client to use your MCP server\?/);
        const csrf = /name="csrf" value="([^"]+)"/.exec(html)[1];
        const submit = (token, origin = issuer) =>
          request(location, {
            method: "POST",
            headers: {
              "x-demo-gateway-secret": gatewaySecret,
              Origin: origin,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({ csrf: token, decision: "allow" }),
          });
        assert.equal((await submit("wrong")).status, 403);
        assert.equal((await submit(csrf, "https://other.example")).status, 403);
        result = await submit(csrf);
      } else result = await request(location);
    }
    assert.fail("OAuth interaction did not finish");
  }
  const exchange = (authorizationCode, codeVerifier) =>
    request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: client.client_id,
        redirect_uri: registration.redirect_uris[0],
        resource,
        code: authorizationCode,
        code_verifier: codeVerifier,
      }),
    });
  const invalid = await exchange(await code(), randomBytes(32).toString("base64url"));
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error, "invalid_grant");
  const authorizationCode = await code();
  const exchanged = await exchange(authorizationCode, verifier);
  assert.equal(exchanged.status, 200, await exchanged.clone().text());
  const token = await exchanged.json();
  assert.equal(token.expires_in, 300);
  assert.equal(token.refresh_token, undefined);
  const claims = JSON.parse(Buffer.from(token.access_token.split(".")[1], "base64url"));
  const [header, payload, signature] = token.access_token.split(".");
  assert.ok(
    verify(
      "RSA-SHA256",
      Buffer.from(`${header}.${payload}`),
      publicKey,
      Buffer.from(signature, "base64url"),
    ),
  );
  assert.equal(claims.iss, issuer);
  assert.equal(claims.aud, resource);
  assert.equal(claims.sub, "owner");
  assert.equal(claims.scope, "mcp:use");
  const replayed = await exchange(authorizationCode, verifier);
  assert.equal(replayed.status, 400);
  assert.equal((await replayed.json()).error, "invalid_grant");
  const refresh = await request("/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: client.client_id,
      refresh_token: "not-issued",
    }),
  });
  assert.equal(refresh.status, 400);
  assert.equal((await refresh.json()).error, "invalid_grant");
});

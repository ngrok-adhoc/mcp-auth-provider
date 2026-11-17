import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";

import { createIssuer } from "../lib/issuer.mjs";

test("loopback OAuth: gateway, consent, PKCE, JWT audience, rotating refresh and one-time codes", async (t) => {
  let now = Date.now();
  t.mock.method(Date, "now", () => now);
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
  const resource = "https://mcp-oauth-provider.example/mcp";
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
    client_name: '<img src=x onerror="alert(1)">',
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
  const codeOnly = await (await register(registration)).json();
  const { grant_types: _grantTypes, ...defaultRegistration } = registration;
  const defaultClient = await (await register(defaultRegistration)).json();
  assert.deepEqual(defaultClient.grant_types, ["authorization_code", "refresh_token"]);
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
  assert.ok(metadata.grant_types_supported.includes("refresh_token"));
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
  let authorizationCount = 0;
  async function code(extra = {}, decision = "allow") {
    let consentForms = 0;
    let result = await authorize(extra);
    for (let step = 0; step < 10; step++) {
      const location = result.headers.get("location");
      assert.ok(location, `Expected OAuth redirect, got ${result.status}: ${await result.text()}`);
      if (location.startsWith(registration.redirect_uris[0])) {
        const url = new URL(location);
        assert.equal(url.searchParams.get("state"), "test-state");
        assert.ok(consentForms <= 1, "One approval form is sufficient");
        if (authorizationCount++ === 0) assert.equal(consentForms, 1);
        if (decision === "deny") {
          assert.equal(url.searchParams.get("code"), null);
          return url.searchParams.get("error");
        }
        assert.ok(url.searchParams.get("code"), location);
        return url.searchParams.get("code");
      }
      if (location.startsWith("/interaction/")) {
        assert.equal((await request(location)).status, 403);
        assert.equal(
          (await request(location, { headers: { "x-mcp-oauth-provider-secret": "incorrect" } }))
            .status,
          403,
        );
        assert.equal(
          (
            await request(location, {
              method: "DELETE",
              headers: { "x-mcp-oauth-provider-secret": gatewaySecret },
            })
          ).status,
          405,
        );
        const page = await request(location, {
          headers: { "x-mcp-oauth-provider-secret": gatewaySecret },
        });
        if (page.status === 303) {
          result = page;
          continue;
        }
        assert.equal(page.status, 200, await page.clone().text());
        consentForms++;
        assert.ok(page.headers.get("content-security-policy").includes("http://127.0.0.1:9988"));
        const html = await page.text();
        assert.match(html, /<title>MCP OAuth Provider<\/title>/);
        assert.match(html, /wants to connect to your MCP server/);
        assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
        assert.doesNotMatch(html, /<img|<script|ngrok/);
        assert.equal((html.match(/<form\b/g) ?? []).length, 1);
        assert.match(html, /<details><summary>Connection details<\/summary>/);
        assert.match(html, />Cancel<\/button>/);
        assert.match(html, />Authorize<\/button>/);
        assert.match(
          page.headers.get("content-security-policy"),
          /default-src 'none'; style-src 'unsafe-inline'/,
        );
        assert.doesNotMatch(page.headers.get("content-security-policy"), /script-src/);
        const csrf = /name="csrf" value="([^"]+)"/.exec(html)[1];
        const submit = (token, origin = issuer) =>
          request(location, {
            method: "POST",
            headers: {
              "x-mcp-oauth-provider-secret": gatewaySecret,
              Origin: origin,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({ csrf: token, decision }),
          });
        assert.equal((await submit("wrong")).status, 403);
        assert.equal((await submit(csrf, "https://other.example")).status, 403);
        result = await submit(csrf);
      } else result = await request(location);
    }
    assert.fail("OAuth interaction did not finish");
  }
  const exchange = (authorizationCode, codeVerifier, clientId = client.client_id) =>
    request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        redirect_uri: registration.redirect_uris[0],
        resource,
        code: authorizationCode,
        code_verifier: codeVerifier,
      }),
    });
  assert.equal(await code({}, "deny"), "access_denied");
  const invalid = await exchange(await code(), randomBytes(32).toString("base64url"));
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error, "invalid_grant");
  const authorizationCode = await code();
  const exchanged = await exchange(authorizationCode, verifier);
  assert.equal(exchanged.status, 200, await exchanged.clone().text());
  const token = await exchanged.json();
  assert.equal(token.expires_in, 7 * 24 * 60 * 60);
  assert.equal(typeof token.refresh_token, "string");
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
  assert.equal(claims.exp - claims.iat, 7 * 24 * 60 * 60);
  const refresh = (value, extra = {}) =>
    request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: client.client_id,
        refresh_token: value,
        resource,
        ...extra,
      }),
    });
  const rejected = async (response, error) => {
    assert.equal(response.status, 400, await response.clone().text());
    assert.equal((await response.json()).error, error);
  };
  await rejected(await refresh("not-issued"), "invalid_grant");
  const otherClient = await (
    await register({
      ...registration,
      grant_types: ["authorization_code", "refresh_token"],
    })
  ).json();
  await rejected(
    await refresh(token.refresh_token, { client_id: otherClient.client_id }),
    "invalid_grant",
  );
  await rejected(await refresh(token.refresh_token, { scope: "mcp:use admin" }), "invalid_scope");

  now += 301_000;
  assert.ok(claims.exp > Math.floor(now / 1000));
  const renewed = await refresh(token.refresh_token);
  assert.equal(renewed.status, 200, await renewed.clone().text());
  const renewedToken = await renewed.json();
  assert.equal(renewedToken.expires_in, 7 * 24 * 60 * 60 - 301);
  assert.notEqual(renewedToken.refresh_token, token.refresh_token);
  const renewedClaims = JSON.parse(
    Buffer.from(renewedToken.access_token.split(".")[1], "base64url"),
  );
  assert.equal(renewedClaims.iss, issuer);
  assert.equal(renewedClaims.aud, resource);
  assert.equal(renewedClaims.sub, "owner");
  assert.equal(renewedClaims.scope, "mcp:use");
  assert.equal(renewedClaims.exp, claims.exp);

  await rejected(await refresh(token.refresh_token), "invalid_grant");
  // Reusing a consumed refresh revokes the entire grant, including its current rotation.
  await rejected(await refresh(renewedToken.refresh_token), "invalid_grant");
  const replayed = await exchange(authorizationCode, verifier);
  await rejected(replayed, "invalid_grant");

  const withoutRefresh = await exchange(
    await code({ client_id: codeOnly.client_id }),
    verifier,
    codeOnly.client_id,
  );
  assert.equal(withoutRefresh.status, 200, await withoutRefresh.clone().text());
  assert.equal((await withoutRefresh.json()).refresh_token, undefined);

  const targetToken = await (await exchange(await code(), verifier)).json();
  await rejected(
    await refresh(targetToken.refresh_token, { resource: "https://other.example/mcp" }),
    "invalid_target",
  );

  const lifetimeToken = await (await exchange(await code(), verifier)).json();
  const issuedAt = now;
  const lifetimeClaims = JSON.parse(
    Buffer.from(lifetimeToken.access_token.split(".")[1], "base64url"),
  );
  assert.equal(lifetimeClaims.exp - lifetimeClaims.iat, 7 * 24 * 60 * 60);
  now += 2 * 24 * 60 * 60 * 1000;
  const afterBrowserSession = await refresh(lifetimeToken.refresh_token);
  assert.equal(afterBrowserSession.status, 200, await afterBrowserSession.clone().text());
  const middleToken = await afterBrowserSession.json();
  assert.notEqual(middleToken.refresh_token, lifetimeToken.refresh_token);
  assert.equal(middleToken.expires_in, 5 * 24 * 60 * 60);
  assert.equal(
    JSON.parse(Buffer.from(middleToken.access_token.split(".")[1], "base64url")).exp,
    lifetimeClaims.exp,
  );
  now = issuedAt + (7 * 24 * 60 * 60 - 60) * 1000;
  const nearLimit = await refresh(middleToken.refresh_token);
  assert.equal(nearLimit.status, 200, await nearLimit.clone().text());
  const lastToken = await nearLimit.json();
  assert.equal(lastToken.expires_in, 60);
  const lastClaims = JSON.parse(Buffer.from(lastToken.access_token.split(".")[1], "base64url"));
  assert.equal(lastClaims.exp, lifetimeClaims.exp);
  now = issuedAt + (7 * 24 * 60 * 60 + 1) * 1000;
  assert.ok(lastClaims.exp < Math.floor(now / 1000));
  await rejected(await refresh(lastToken.refresh_token), "invalid_grant");
});

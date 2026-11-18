import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { createServer, request as httpRequest } from "node:http";
import { createConnection } from "node:net";
import test from "node:test";

import { startServers } from "../lib/server.mjs";

async function listen(server, port = 0) {
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  return `http://127.0.0.1:${server.address().port}`;
}
const close = (server) =>
  new Promise((resolve) => {
    server.closeAllConnections();
    server.close(resolve);
  });
const gatewaySecret = "test-gateway-secret-".repeat(3);
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwks = {
  keys: [{ ...privateKey.export({ format: "jwk" }), kid: "server-test", use: "sig", alg: "RS256" }],
};

async function fixture(t, handler, mcpHost) {
  const upstream = createServer(handler);
  const url = await listen(upstream);
  const mcpUrl = new URL(`${url}/private-mcp`);
  if (mcpHost) mcpUrl.hostname = mcpHost;
  const servers = await startServers({
    appUrl: url,
    mcpUrl: mcpUrl.href,
    issuer: "https://provider.example",
    gatewaySecret,
    jwks,
  });
  t.after(async () => {
    await servers.close();
    await close(upstream);
  });
  return { upstream, url, ...servers };
}

test("app routing, fixed MCP target and reserved paths preserve the auth boundary", async (t) => {
  const { helperUrl, mcpProxyUrl } = await fixture(t, async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    res.writeHead(req.url === "/private-mcp" ? 201 : 200, {
      "content-type": "application/json",
      "x-upstream": "preserved",
    });
    res.end(
      JSON.stringify({
        url: req.url,
        body,
        authorization: req.headers.authorization,
        secret: req.headers["x-mcp-oauth-provider-secret"],
      }),
    );
  });
  const app = await fetch(`${helperUrl}/assets/app.css?theme=blue`, {
    headers: { authorization: "Bearer app-session", "x-mcp-oauth-provider-secret": gatewaySecret },
  });
  assert.equal(app.status, 200);
  assert.deepEqual(await app.json(), {
    url: "/assets/app.css?theme=blue",
    body: "",
    authorization: "Bearer app-session",
  });
  assert.equal((await fetch(`${helperUrl}/`)).status, 200);
  for (const path of ["/mcp", "/mcp/child", "/private-mcp", "/private-mcp/child", "/%70rivate-mcp"])
    assert.equal((await fetch(`${helperUrl}${path}`)).status, 404, path);
  const mcp = await fetch(`${mcpProxyUrl}/mcp?ignored=secret`, {
    method: "POST",
    body: "unchanged MCP payload",
    headers: {
      authorization: "Bearer not-for-upstream",
      "x-mcp-oauth-provider-secret": gatewaySecret,
    },
  });
  assert.equal(mcp.status, 201);
  assert.equal(mcp.headers.get("x-upstream"), "preserved");
  assert.deepEqual(await mcp.json(), { url: "/private-mcp", body: "unchanged MCP payload" });
  assert.equal((await fetch(`${mcpProxyUrl}/other`)).status, 404);
  const malformedStatus = await new Promise((resolve, reject) => {
    const target = new URL(mcpProxyUrl);
    const request = httpRequest(
      { hostname: target.hostname, port: target.port, path: "http://[", method: "GET" },
      (response) => {
        response.resume();
        resolve(response.statusCode);
      },
    );
    request.on("error", reject);
    request.end();
  });
  assert.equal(malformedStatus, 400);
  assert.equal((await fetch(`${helperUrl}/.well-known/oauth-authorization-server`)).status, 200);
});

test("debug requires gateway identity and reports no secrets or request payloads", async (t) => {
  const { helperUrl, mcpProxyUrl } = await fixture(t, (req, res) => {
    res.writeHead(req.url === "/private-mcp" ? 405 : 200).end("upstream");
  });
  assert.equal((await fetch(`${helperUrl}/mcp-debug`)).status, 403);
  assert.equal(
    (await fetch(`${helperUrl}/mcp-debug`, { headers: { "x-mcp-oauth-provider-secret": "wrong" } }))
      .status,
    403,
  );
  assert.equal(
    (
      await fetch(`${helperUrl}/mcp-debug/`, {
        method: "POST",
        headers: { "x-mcp-oauth-provider-secret": gatewaySecret },
      })
    ).status,
    405,
  );
  await fetch(`${mcpProxyUrl}/mcp?code=sensitive-code`, {
    method: "POST",
    body: "sensitive-body",
    headers: { authorization: "Bearer sensitive-token", cookie: "sensitive-cookie" },
  });
  const response = await fetch(`${helperUrl}/mcp-debug?code=debug-code`, {
    headers: { "x-mcp-oauth-provider-secret": gatewaySecret },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(
    response.headers.get("content-security-policy"),
    "default-src 'none'; style-src 'unsafe-inline'; font-src https://assets.ngrok.com; frame-ancestors 'none'",
  );
  const html = await response.text();
  assert.match(html, /HTTP 405 — reachable; MCP protocol not verified/);
  assert.match(html, /Recent MCP forwarding results/);
  assert.match(html, /<td>405<\/td>/);
  for (const value of [
    gatewaySecret,
    "sensitive-code",
    "sensitive-body",
    "sensitive-token",
    "sensitive-cookie",
    "debug-code",
  ])
    assert.ok(!html.includes(value), value);
});

test("offline upstream returns a useful 503 and recovers without provider restart", async (t) => {
  const { upstream, url, helperUrl, mcpProxyUrl } = await fixture(t, (req, res) =>
    res.end("recovered"),
  );
  const port = new URL(url).port;
  await close(upstream);
  const mcp = await fetch(`${mcpProxyUrl}/mcp`);
  assert.equal(mcp.status, 503);
  const error = await mcp.json();
  assert.equal(error.error, "mcp_upstream_unavailable");
  assert.match(error.action, /Start the server/);
  assert.match(error.action, /mcp-debug/);
  const app = await fetch(`${helperUrl}/`);
  assert.equal(app.status, 503);
  assert.match(await app.text(), /Check connection status/);
  await listen(upstream, Number(port));
  assert.equal(await (await fetch(`${mcpProxyUrl}/mcp`)).text(), "recovered");
});

test("established MCP requests can wait beyond the app deadline for response headers", async (t) => {
  let finish;
  let received;
  const waiting = new Promise((resolve) => (received = resolve));
  const { mcpProxyUrl } = await fixture(t, (_req, res) => {
    finish = () => res.end("slow tool result");
    received();
  });
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const response = new Promise((resolve, reject) => {
    const req = httpRequest(`${mcpProxyUrl}/mcp`, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
  await waiting;
  t.mock.timers.tick(300001);
  finish();
  assert.deepEqual(await response, { status: 200, body: "slow tool result" });
});

test("MCP responses stream before the upstream closes", async (t) => {
  let finish;
  const { mcpProxyUrl } = await fixture(t, (_req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write("data: first\n\n");
    finish = () => res.end("data: last\n\n");
  });
  const response = await fetch(`${mcpProxyUrl}/mcp`);
  const reader = response.body.getReader();
  assert.match(new TextDecoder().decode((await reader.read()).value), /data: first/);
  finish();
  assert.match(new TextDecoder().decode((await reader.read()).value), /data: last/);
  assert.equal((await reader.read()).done, true);
});

test("case-insensitive MCP routes cannot bypass auth through loopback host aliases", async (t) => {
  for (const hostname of [
    "127.0.0.1",
    "localhost",
    "[::1]",
    "host.docker.internal",
    "mcp-service",
  ]) {
    const { helperUrl, url } = await fixture(
      t,
      (req, res) =>
        res.end(req.url.toLowerCase().startsWith("/private-mcp") ? "PRIVATE MCP" : "app"),
      hostname,
    );
    assert.equal(await (await fetch(`${url}/PRIVATE-MCP`)).text(), "PRIVATE MCP");
    assert.equal(await (await fetch(`${helperUrl}/`)).text(), "app");
    for (const path of ["/PRIVATE-MCP", "/Private-Mcp/child", "/%50RIVATE-MCP"])
      assert.equal((await fetch(`${helperUrl}${path}`)).status, 404, `${hostname}${path}`);
  }
});

test("normalized MCP paths cannot bypass authorization through app forwarding", async (t) => {
  for (const mcpPath of ["/private/mcp", "/private//mcp"]) {
    let requests = 0;
    let upgrades = 0;
    const upstream = createServer((req, res) => {
      requests++;
      const path = new URL(
        `http://upstream${decodeURIComponent(req.url).replaceAll("\\", "/")}`,
      ).pathname.replace(/\/+/g, "/");
      res.end(
        path === "/private/mcp" || decodeURIComponent(req.url).startsWith("/private/mcp/")
          ? "PRIVATE MCP"
          : "app",
      );
    });
    upstream.on("upgrade", (_req, socket) => {
      upgrades++;
      socket.end(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
      );
    });
    const url = await listen(upstream);
    const servers = await startServers({
      appUrl: url,
      mcpUrl: `${url}${mcpPath}`,
      issuer: "https://provider.example",
      gatewaySecret,
      jwks,
    });
    t.after(async () => {
      await servers.close();
      await close(upstream);
    });
    for (const path of [
      "/private/mcp",
      "/private//mcp",
      "/private/%2fmcp",
      "/%2fprivate/mcp",
      "/public%2f..%2fprivate/mcp",
      "/private%5cmcp",
      "/private/mcp/public%2f..%2f..%2f..%2fassets",
    ]) {
      assert.equal(await (await fetch(`${url}${path}`)).text(), "PRIVATE MCP", path);
      assert.equal((await fetch(`${servers.helperUrl}${path}`)).status, 404, path);
      const status = await new Promise((resolve, reject) => {
        const req = httpRequest(
          `${servers.helperUrl}${path}`,
          { headers: { connection: "Upgrade", upgrade: "websocket" } },
          (res) => {
            res.resume();
            resolve(res.statusCode);
          },
        );
        req.on("error", reject);
        req.on("upgrade", (_res, socket) => {
          socket.destroy();
          reject(new Error("Normalized MCP route upgraded without authorization"));
        });
        req.end();
      });
      assert.equal(status, 404, path);
    }
    assert.equal(upgrades, 0);
    assert.equal(requests, 7, "Only the direct upstream checks reached MCP");
    assert.equal(await (await fetch(`${servers.mcpProxyUrl}/mcp`)).text(), "PRIVATE MCP");
    assert.equal(await (await fetch(`${servers.helperUrl}/assets/app.css`)).text(), "app");
  }
});

test(
  "root-mounted MCP blocks all app fallthrough even through hostname aliases",
  { timeout: 5000 },
  async (t) => {
    let requests = 0;
    let upgrades = 0;
    const upstream = createServer(async (req, res) => {
      requests++;
      let body = "";
      for await (const chunk of req) body += chunk;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ url: req.url, body, result: "PRIVATE MCP" }));
    });
    upstream.on("upgrade", (_req, socket) => {
      upgrades++;
      socket.end(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
      );
    });
    const url = await listen(upstream);
    const appUrl = new URL(url);
    appUrl.hostname = "localhost.";
    const servers = await startServers({
      appUrl: appUrl.href,
      mcpUrl: `${url}/`,
      issuer: "https://provider.example",
      gatewaySecret,
      jwks,
    });
    t.after(async () => {
      await servers.close();
      await close(upstream);
    });
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" });
    const alias = await fetch(appUrl, { method: "POST", body });
    assert.equal((await alias.json()).result, "PRIVATE MCP");
    requests = 0;
    for (const path of ["/", "/anything"]) {
      assert.equal(
        (await fetch(`${servers.helperUrl}${path}`, { method: "POST", body })).status,
        404,
      );
      const status = await new Promise((resolve, reject) => {
        const req = httpRequest(
          `${servers.helperUrl}${path}`,
          { headers: { connection: "Upgrade", upgrade: "websocket" } },
          (res) => {
            res.resume();
            resolve(res.statusCode);
          },
        );
        req.on("error", reject);
        req.on("upgrade", (_res, socket) => {
          socket.destroy();
          reject(new Error("Root MCP alias was exposed through an app upgrade"));
        });
        req.end();
      });
      assert.equal(status, 404, path);
    }
    assert.equal(requests, 0);
    assert.equal(upgrades, 0);
    const authorized = await fetch(`${servers.mcpProxyUrl}/mcp`, {
      method: "POST",
      body,
      headers: { "x-mcp-oauth-provider-secret": gatewaySecret },
    });
    assert.equal(authorized.status, 200);
    assert.deepEqual(await authorized.json(), { url: "/", body, result: "PRIVATE MCP" });
    assert.equal(requests, 1);
  },
);

test(
  "app WebSocket upgrades preserve bidirectional bytes and deny reserved paths",
  { timeout: 5000 },
  async (t) => {
    const { helperUrl, upstream } = await fixture(t, (_req, res) => res.end("app"), "localhost");
    let upgrades = 0;
    upstream.on("upgrade", (req, socket, head) => {
      upgrades++;
      assert.equal(req.url, "/hmr?version=1");
      assert.equal(req.headers["x-mcp-oauth-provider-secret"], undefined);
      socket.on("error", () => {});
      socket.on("end", () => socket.end());
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nserver-head",
      );
      if (head.length) socket.write(`echo:${head}`);
      socket.on("data", (bytes) => socket.write(`echo:${bytes}`));
    });
    const socket = createConnection({ host: "127.0.0.1", port: Number(new URL(helperUrl).port) });
    t.after(() => socket.destroy());
    await once(socket, "connect");
    let received = "";
    socket.on("data", (bytes) => {
      received += bytes;
    });
    const until = async (value) => {
      while (!received.includes(value)) await once(socket, "data");
    };
    socket.write(
      `GET /hmr?version=1 HTTP/1.1\r\nHost: provider.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nx-mcp-oauth-provider-secret: ${gatewaySecret}\r\n\r\nclient-head`,
    );
    await until("echo:client-head");
    assert.match(received, /HTTP\/1.1 101 Switching Protocols/);
    assert.ok(received.includes("server-head"));
    socket.write("client-later");
    await until("echo:client-later");
    for (const path of ["/mcp", "/PRIVATE-MCP", "/auth", "/mcp-debug"]) {
      const status = await new Promise((resolve, reject) => {
        const req = httpRequest(
          `${helperUrl}${path}`,
          { headers: { connection: "Upgrade", upgrade: "websocket" } },
          (res) => {
            res.resume();
            resolve(res.statusCode);
          },
        );
        req.on("error", reject);
        req.on("upgrade", (_res, conn) => {
          conn.destroy();
          reject(new Error("Reserved route upgraded"));
        });
        req.end();
      });
      assert.equal(status, 404, path);
    }
    assert.equal(upgrades, 1);
    socket.destroy();
    await close(upstream);
    const unavailable = await new Promise((resolve, reject) => {
      const req = httpRequest(
        `${helperUrl}/hmr`,
        { headers: { connection: "Upgrade", upgrade: "websocket" } },
        (res) => {
          let body = "";
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () => resolve({ status: res.statusCode, body }));
        },
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(unavailable.status, 503);
    assert.match(unavailable.body, /Start .* and retry/);
  },
);

test(
  "rejected half-open upgrades cannot keep provider shutdown waiting",
  { timeout: 5000 },
  async (t) => {
    const servers = await fixture(t, (_req, res) => res.end("app"));
    const socket = createConnection({
      host: "127.0.0.1",
      port: Number(new URL(servers.helperUrl).port),
      allowHalfOpen: true,
    });
    t.after(() => socket.destroy());
    socket.on("error", () => {});
    await once(socket, "connect");
    let response = "";
    socket.on("data", (bytes) => {
      response += bytes;
    });
    const ended = once(socket, "end");
    socket.write(
      "GET /auth HTTP/1.1\r\nHost: provider.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    );
    await ended;
    assert.match(response, /HTTP\/1.1 404 Not Found/);
    assert.equal(socket.writableEnded, false);
    let timeout;
    try {
      await Promise.race([
        servers.close(),
        new Promise((_resolve, reject) => {
          timeout = setTimeout(
            () => reject(new Error("Provider shutdown hung on rejected upgrade")),
            1000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  },
);

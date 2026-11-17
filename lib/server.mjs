import { timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

import { createIssuer } from "./issuer.mjs";

const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char],
  );
const visibleUrl = (value) => {
  const url = new URL(value);
  return `${url.origin}${url.pathname}`;
};
const trusted = (value, secret) =>
  typeof value === "string" &&
  Buffer.byteLength(value) === Buffer.byteLength(secret) &&
  timingSafeEqual(Buffer.from(value), Buffer.from(secret));
const send = (res, status, body, type = "application/json") => {
  if (!res.destroyed && !res.headersSent)
    res
      .writeHead(status, { "content-type": `${type}; charset=utf-8`, "cache-control": "no-store" })
      .end(body);
};
const json = (res, status, body) => send(res, status, JSON.stringify(body));
const transport = (url) => (url.protocol === "https:" ? httpsRequest : httpRequest);

function headersWithoutHopByHop(headers) {
  const copy = { ...headers };
  for (const name of [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    ...String(headers.connection ?? "")
      .split(",")
      .map((name) => name.trim().toLowerCase()),
  ])
    delete copy[name];
  return copy;
}

async function reachable(value, active) {
  const url = new URL(value);
  return new Promise((resolve) => {
    let completed = false;
    const finish = (message) => {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      resolve(message);
      req.destroy();
    };
    const req = transport(url)(url, { method: "GET" }, (res) => {
      finish(`HTTP ${res.statusCode} — reachable; MCP protocol not verified`);
      res.destroy();
    });
    active.add(req);
    req.on("close", () => active.delete(req));
    const timer = setTimeout(
      () => finish("Timed out — check the upstream and reload this page"),
      2000,
    );
    req.on("error", () => finish("Unavailable — start the upstream and reload this page"));
    req.end();
  });
}

function debugPage({ issuer, appUrl, mcpUrl, health, recent }) {
  const rows = [
    ["Public MCP", `${issuer}/mcp`, "Connect your MCP client here"],
    ["App upstream", visibleUrl(appUrl), health[0]],
    ["MCP upstream", visibleUrl(mcpUrl), health[1]],
  ];
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCP Auth Provider — connection status</title><style>
:root{color-scheme:light dark;--paper:#fff;--ink:#1b2945;--muted:#5b6678;--line:#d8dfeb;--blue:#3357d6;--wash:#edf2ff}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 Avenir,"Segoe UI",sans-serif}main{max-width:1040px;margin:auto;padding:40px 28px}h1{font-size:30px;line-height:1.2;margin:0 0 14px}h2{font-size:21px;margin-top:30px}p{max-width:78ch}a{color:var(--blue);text-underline-offset:3px}a:focus-visible{outline:3px solid var(--blue);outline-offset:4px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{background:var(--wash)}td:first-child{font-weight:600;width:20%}.muted{color:var(--muted)}code{font-size:.9em;overflow-wrap:anywhere}@media(prefers-color-scheme:dark){:root{--paper:#131b2a;--ink:#edf2fc;--muted:#bbc6d8;--line:#39475e;--blue:#a2b6ff;--wash:#202e48}}@media(max-width:820px){main{padding:28px 20px}th,td{padding:9px}}
</style><main><h1>MCP Auth Provider</h1><p>Connection status for your app and MCP server. Reload this page to check again.</p><table><thead><tr><th>Connection</th><th>URL</th><th>Current check</th></tr></thead><tbody>${rows.map(([name, url, status]) => `<tr><td>${name}</td><td><code>${escape(url)}</code></td><td>${escape(status)}</td></tr>`).join("")}</tbody></table><p class="muted">A reachable HTTP server can still reject an MCP request. Authorization and tool calls must also succeed in your MCP client.</p><h2>Recent MCP forwarding results</h2>${recent.length ? `<table><thead><tr><th>Status</th><th>Duration</th></tr></thead><tbody>${recent.map(({ status, duration }) => `<tr><td>${status}</td><td>${duration} ms</td></tr>`).join("")}</tbody></table>` : "<p>No MCP requests forwarded yet.</p>"}<h2>Where to look next</h2><p>Confirm the two upstream URLs above. If a server is unavailable, start it and retry; you do not need to restart this provider. For authentication failures, reconnect the MCP client. Provider state resets when this process restarts.</p><p><a href="https://dashboard.ngrok.com/traffic-inspector" target="_blank" rel="noreferrer">Open ngrok Traffic Inspector</a> for gateway status and routing. This page records only status and duration, never tokens, authorization codes, cookies or request bodies.</p></main></html>`;
}

export async function startServers({ appUrl, mcpUrl, issuer, gatewaySecret, jwks }) {
  const auth = createIssuer({ issuer, gatewaySecret, jwks });
  const active = new Set();
  const recent = [];
  const sockets = new Set();
  const appBase = new URL(appUrl);
  const mcpBase = new URL(mcpUrl);
  const loopback = new Set(["localhost", "127.0.0.1", "[::1]"]);
  const effectivePort = (url) => url.port || (url.protocol === "https:" ? "443" : "80");
  const sharedOrigin =
    appBase.origin === mcpBase.origin ||
    (loopback.has(appBase.hostname) &&
      loopback.has(mcpBase.hostname) &&
      appBase.protocol === mcpBase.protocol &&
      effectivePort(appBase) === effectivePort(mcpBase));
  const mcpPath = decodeURIComponent(mcpBase.pathname).replace(/\/+$/, "").toLowerCase() || "/";
  function reservedAppPath(pathname) {
    const path = decodeURIComponent(pathname).toLowerCase();
    return (
      [
        "/mcp",
        "/mcp-debug",
        "/auth",
        "/token",
        "/reg",
        "/jwks",
        "/interaction",
        "/ngrok",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
      ].some((route) => path === route || path.startsWith(`${route}/`)) ||
      (sharedOrigin && (mcpPath === "/" || path === mcpPath || path.startsWith(`${mcpPath}/`)))
    );
  }
  function appTarget(incoming) {
    const target = new URL(appUrl);
    target.pathname = incoming.pathname;
    target.search = incoming.search;
    return target;
  }
  function forward(req, res, target, kind) {
    const started = performance.now();
    let recorded = false;
    const record = (status) => {
      if (kind === "MCP" && !recorded) {
        recorded = true;
        recent.unshift({ status, duration: Math.round(performance.now() - started) });
        recent.splice(10);
      }
    };
    const headers = headersWithoutHopByHop(req.headers);
    delete headers["x-demo-gateway-secret"];
    if (kind === "MCP") delete headers.authorization;
    headers.host = target.host;
    const upstream = transport(target)(target, { method: req.method, headers }, (response) => {
      clearTimeout(deadline);
      record(response.statusCode);
      res.writeHead(response.statusCode, headersWithoutHopByHop(response.headers));
      response.on("error", () => res.destroy());
      response.pipe(res);
    });
    active.add(upstream);
    upstream.on("close", () => {
      clearTimeout(deadline);
      active.delete(upstream);
    });
    upstream.on("error", () => {
      record(503);
      if (res.headersSent) return res.destroy();
      const message = `${kind} upstream is unavailable.`;
      const action = `Start the server at ${visibleUrl(target)} and retry. Open /mcp-debug for connection status.`;
      if (kind === "MCP") json(res, 503, { error: "mcp_upstream_unavailable", message, action });
      else
        send(
          res,
          503,
          `<!doctype html><html lang="en"><meta charset="utf-8"><title>App unavailable</title><h1>${message}</h1><p>${escape(action)}</p><a href="/mcp-debug">Check connection status</a></html>`,
          "text/html",
        );
    });
    // Bound time to response headers without timing out a live MCP event stream.
    const deadline = setTimeout(() => upstream.destroy(), 10000);
    req.on("aborted", () => upstream.destroy());
    res.on("close", () => {
      if (!res.writableEnded) upstream.destroy();
    });
    req.pipe(upstream);
  }
  const helper = createServer(async (req, res) => {
    try {
      const incoming = new URL(req.url ?? "/", issuer);
      const path = incoming.pathname;
      if (path === "/mcp-debug" || path === "/mcp-debug/") {
        if (!trusted(req.headers["x-demo-gateway-secret"], gatewaySecret))
          return json(res, 403, {
            error: "Open this page through the ngrok Google sign-in gateway.",
          });
        if (req.method !== "GET") return json(res, 405, { error: "Reload this page with GET." });
        res.setHeader(
          "content-security-policy",
          "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        );
        res.setHeader("referrer-policy", "no-referrer");
        const health = await Promise.all([reachable(appUrl, active), reachable(mcpUrl, active)]);
        return send(res, 200, debugPage({ issuer, appUrl, mcpUrl, health, recent }), "text/html");
      }
      if (
        [
          "/auth",
          "/token",
          "/reg",
          "/jwks",
          "/.well-known/openid-configuration",
          "/.well-known/oauth-authorization-server",
        ].includes(path) ||
        path.startsWith("/auth/") ||
        path.startsWith("/interaction/")
      )
        return await auth.handle(req, res);
      if (reservedAppPath(path))
        return json(res, 404, { error: "Use the protected public /mcp connection URL." });
      forward(req, res, appTarget(incoming), "App");
    } catch {
      json(res, 400, { error: "Invalid request. Check the URL and retry." });
    }
  });
  helper.on("upgrade", (req, socket, head) => {
    // Rejected upgrades are detached from HTTP connection tracking too.
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    const fail = (status, message) => {
      if (!socket.destroyed)
        socket.end(
          `HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n${message}`,
        );
    };
    try {
      const incoming = new URL(req.url ?? "/", issuer);
      if (reservedAppPath(incoming.pathname))
        return fail("404 Not Found", "Use the protected MCP connection or debug page.");
      if (req.headers.upgrade?.toLowerCase() !== "websocket")
        return fail("400 Bad Request", "Only app WebSocket upgrades are supported.");
      const target = appTarget(incoming);
      const headers = headersWithoutHopByHop(req.headers);
      delete headers["x-demo-gateway-secret"];
      Object.assign(headers, { host: target.host, connection: "Upgrade", upgrade: "websocket" });
      const upstream = transport(target)(target, { method: req.method, headers });
      active.add(upstream);
      let upgraded = false;
      const deadline = setTimeout(() => upstream.destroy(), 10000);
      upstream.on("close", () => {
        clearTimeout(deadline);
        active.delete(upstream);
      });
      upstream.on("error", () => {
        if (upgraded) socket.destroy();
        else
          fail(
            "503 Service Unavailable",
            `App upstream is unavailable. Start ${visibleUrl(target)} and retry. Open /mcp-debug for connection status.`,
          );
      });
      socket.on("error", () => upstream.destroy());
      socket.on("close", () => {
        if (!upgraded) upstream.destroy();
      });
      upstream.on("upgrade", (response, upstreamSocket, upstreamHead) => {
        clearTimeout(deadline);
        upgraded = true;
        for (const [current, other] of [
          [socket, upstreamSocket],
          [upstreamSocket, socket],
        ]) {
          sockets.add(current);
          current.on("error", () => other.destroy());
          current.on("close", () => {
            sockets.delete(current);
            other.destroy();
          });
        }
        const responseHeaders = response.rawHeaders.reduce(
          (text, value, index, all) =>
            index % 2 === 0 ? `${text}${value}: ${all[index + 1]}\r\n` : text,
          "",
        );
        socket.write(
          `HTTP/${response.httpVersion} ${response.statusCode} ${response.statusMessage}\r\n${responseHeaders}\r\n`,
        );
        if (upstreamHead.length) socket.write(upstreamHead);
        if (head.length) upstreamSocket.write(head);
        socket.pipe(upstreamSocket).pipe(socket);
      });
      upstream.on("response", (response) => {
        clearTimeout(deadline);
        const headers = headersWithoutHopByHop(response.headers);
        headers.connection = "close";
        socket.write(
          `HTTP/${response.httpVersion} ${response.statusCode} ${response.statusMessage}\r\n${Object.entries(
            headers,
          )
            .flatMap(([name, value]) =>
              (Array.isArray(value) ? value : [value]).map((item) => `${name}: ${item}\r\n`),
            )
            .join("")}\r\n`,
        );
        response.on("error", () => socket.destroy());
        response.pipe(socket);
      });
      upstream.end();
    } catch {
      fail("400 Bad Request", "Invalid upgrade request. Check the URL and retry.");
    }
  });
  const mcp = createServer((req, res) => {
    try {
      const path = new URL(req.url ?? "/", issuer).pathname;
      if (path !== "/mcp") return json(res, 404, { error: "Use /mcp." });
      forward(req, res, new URL(mcpUrl), "MCP");
    } catch {
      json(res, 400, { error: "Invalid request. Check the URL and retry." });
    }
  });
  async function close() {
    for (const req of active) req.destroy();
    for (const socket of sockets) socket.destroy();
    await Promise.all(
      [helper, mcp].map(
        (server) =>
          new Promise((resolve) => {
            server.closeAllConnections();
            server.close(resolve);
          }),
      ),
    );
  }
  try {
    for (const server of [helper, mcp]) {
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
    }
  } catch (error) {
    await close();
    throw error;
  }
  return {
    helperUrl: `http://127.0.0.1:${helper.address().port}`,
    mcpProxyUrl: `http://127.0.0.1:${mcp.address().port}`,
    close,
  };
}

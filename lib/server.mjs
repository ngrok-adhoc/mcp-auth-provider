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
    ["App upstream", visibleUrl(appUrl), health[0]],
    ["MCP upstream", visibleUrl(mcpUrl), health[1]],
  ];
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCP OAuth Provider — connection status</title><style>
@font-face{font-family:Roobert;font-style:normal;font-weight:300 900;font-display:swap;src:url(https://assets.ngrok.com/fonts/roobert/roobert-proportional-vf.woff2) format("woff2")}@font-face{font-family:"JetBrains Mono";font-style:normal;font-weight:100 800;font-display:swap;src:url(https://assets.ngrok.com/fonts/jetbrains/jetbrainsmono-wght.woff2) format("woff2")}
:root{color-scheme:light dark;--base:#fafafa;--surface:#fff;--ink:#171717;--muted:#666;--line:#e5e5e5;--wash:#f5f5f5;--link:#006b9c;--success:#007d55;--warning:#9c6200;--inverse:#fff}*{box-sizing:border-box}body{margin:0;background:var(--base);color:var(--ink);font:15px/1.5 Roobert,ui-sans-serif,system-ui,sans-serif}a{color:var(--link);text-underline-offset:3px}a:focus-visible{outline:3px solid var(--link);outline-offset:4px}header{background:var(--surface);border-bottom:1px solid var(--line)}.brandbar{max-width:1184px;margin:auto;min-height:76px;padding:16px 32px;display:flex;align-items:center;gap:22px}.wordmark{color:var(--ink);display:flex;align-items:center}.wordmark svg{width:94px;height:36px}.product{padding-left:22px;border-left:1px solid var(--line);font-size:15px;font-weight:500}.private{margin-left:auto;color:var(--muted);font-size:13px;display:flex;align-items:center;gap:7px}.private svg{width:15px;height:15px}main{max-width:1184px;margin:auto;padding:44px 32px 56px}.heading{display:flex;justify-content:space-between;gap:24px;align-items:center;margin-bottom:28px}h1{font-size:32px;line-height:1.2;letter-spacing:-.6px;font-weight:500;margin:0 0 10px}h2{font-size:18px;line-height:1.4;font-weight:500;margin:0}p{margin:0;max-width:76ch}.muted{color:var(--muted)}.actions{display:flex;gap:8px;flex-shrink:0}.button{height:36px;padding:7px 12px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink);display:inline-flex;align-items:center;justify-content:center;font:500 14px/20px Roobert,ui-sans-serif,system-ui,sans-serif;text-decoration:none;white-space:nowrap}.button.primary{background:var(--ink);color:var(--inverse);border-color:var(--ink)}.button:hover{filter:brightness(.94)}.endpoint{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:20px 24px;margin-bottom:24px}.endpoint-label{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted);margin-bottom:10px}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--success);flex-shrink:0}.endpoint code{font-size:16px;color:var(--ink)}code{font:13px/1.6 "JetBrains Mono",ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere}.panel{background:var(--surface);border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-bottom:24px}.panel-heading{padding:20px 24px 16px}.panel-heading p{font-size:14px;color:var(--muted);margin-top:5px}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:13px 24px;vertical-align:top;overflow-wrap:anywhere}thead{background:var(--wash);color:var(--muted)}th{font-size:12px;font-weight:500}td{border-top:1px solid var(--line)}td:first-child{font-weight:500;width:20%}.connections td:nth-child(2){width:36%}.check{display:inline-flex;align-items:flex-start;gap:8px}.check .dot{margin-top:7px}.check.unavailable .dot{background:var(--warning)}.panel-note{max-width:none;padding:15px 24px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}.empty{padding:16px 24px 24px;color:var(--muted);font-size:14px}.help{display:grid;grid-template-columns:1fr 1fr;gap:40px;border-top:1px solid var(--line);padding-top:24px;font-size:14px}.help h2{font-size:15px;margin-bottom:8px}.help p+p{margin-top:12px}.request-code{font-family:"JetBrains Mono",ui-monospace,monospace}.footer{margin-top:28px;font-size:12px;color:var(--muted)}@media(prefers-color-scheme:dark){:root{--base:#121212;--surface:#171717;--ink:#fafafa;--muted:#a3a3a3;--line:#333;--wash:#222;--link:#61ccff;--success:#40d9a5;--warning:#ffc363;--inverse:#171717}}@media(max-width:820px){.brandbar{padding:16px 24px}.private{font-size:12px}main{padding:32px 24px}.heading{align-items:flex-start;flex-direction:column;gap:16px}.help{gap:24px}th,td{padding:12px 16px}.panel-heading,.endpoint{padding:18px 20px}.panel-note{padding:14px 20px}}@media(max-width:580px){.brandbar{gap:14px}.product{padding-left:14px;font-size:13px}.private{display:none}.connections thead{display:none}.connections tr{display:block;padding:14px 20px;border-top:1px solid var(--line)}.connections td{display:block;width:auto!important;border:0;padding:3px 0}.help{grid-template-columns:1fr}h1{font-size:28px}}
</style></head><body><header><div class="brandbar"><a class="wordmark" href="https://ngrok.com" aria-label="ngrok home" rel="noreferrer"><svg aria-hidden="true" fill="currentColor" height="1em" viewBox="0 0 94 36" width="2.61em"><path d="M32.272 12.011c-1.298-1.466-2.904-2.205-4.812-2.205-1.176 0-2.26.233-3.255.7a7.995 7.995 0 0 0-2.581 1.906 9.205 9.205 0 0 0-1.715 2.853 9.773 9.773 0 0 0-.628 3.546c0 1.25.194 2.39.58 3.419.362.98.918 1.877 1.635 2.636A7.543 7.543 0 0 0 24 26.584c.965.41 2.025.617 3.176.617.522 0 1.005-.041 1.445-.116.439-.075.858-.2 1.26-.37.4-.175.79-.398 1.18-.664.385-.27.792-.612 1.21-1.018v4.353h-.005v.421h-5.33l-4.005 4.64v.798h15.037v-24.98h-5.697v1.746Zm-.014 7.979a4.25 4.25 0 0 1-.786 1.215 3.555 3.555 0 0 1-2.592 1.1 3.627 3.627 0 0 1-1.464-.292 3.508 3.508 0 0 1-1.166-.808 3.93 3.93 0 0 1-1.054-2.72c0-.519.097-1.006.298-1.457a3.77 3.77 0 0 1 .804-1.181 4.114 4.114 0 0 1 1.162-.808 3.484 3.484 0 0 1 2.817-.016c.448.19.844.463 1.181.81.336.347.6.743.804 1.194.202.452.298.95.298 1.493 0 .505-.104 1.005-.302 1.47m-16.261-7.708a6.173 6.173 0 0 0-2.06-1.602 4.875 4.875 0 0 0-.57-.22 6.383 6.383 0 0 0-.923-.216H8.383L5.697 13.39v-3.082H.002v16.61h5.695V15.712h5.35l.444-.01v11.214h5.697V16.528c0-.885-.084-1.674-.25-2.366a4.655 4.655 0 0 0-.941-1.877zm38.367-2.018h-6.213l-2.47 2.863v-2.864h-5.7v16.61h5.71l.004-11.117h4.144l4.526-5.26zm31.051 7.672 7.79-7.392v-.281H85.7l-5.975 5.991V0h-5.696v26.87h5.696v-6.766l6.262 6.763h7.663v-.316l-8.233-8.617zm-16.11-5.78a9.436 9.436 0 0 0-3.085-1.842 10.953 10.953 0 0 0-3.855-.664c-1.407 0-2.705.226-3.884.678a9.611 9.611 0 0 0-3.072 1.858 8.488 8.488 0 0 0-2.016 2.788 8.281 8.281 0 0 0-.722 3.449c0 1.362.24 2.596.722 3.707a8.52 8.52 0 0 0 2.002 2.862c.85.798 1.86 1.415 3.036 1.847 1.177.432 2.455.647 3.842.647 1.406 0 2.707-.215 3.919-.647 1.204-.431 2.24-1.04 3.098-1.833a8.583 8.583 0 0 0 2.031-2.816c.493-1.09.742-2.29.742-3.611 0-1.316-.244-2.52-.722-3.612a8.424 8.424 0 0 0-2.035-2.81Zm-3.558 7.864c-.2.461-.463.869-.786 1.215a3.573 3.573 0 0 1-2.592 1.1c-.502 0-.981-.096-1.434-.291a3.44 3.44 0 0 1-1.16-.809 4.155 4.155 0 0 1-.788-1.215 3.825 3.825 0 0 1-.297-1.537c0-.517.098-1.004.297-1.456.201-.451.46-.849.787-1.194a3.579 3.579 0 0 1 2.597-1.1c.502 0 .98.096 1.43.29.448.19.839.461 1.16.81.328.345.586.752.786 1.214.2.461.297.954.297 1.471 0 .538-.096 1.04-.297 1.502"></path></svg></a><span class="product">MCP OAuth Provider</span><span class="private"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>Owner diagnostics</span></div></header><main><div class="heading"><div><h1>Connection status</h1><p class="muted">Check your upstreams and see requests forwarded to your MCP server.</p></div><div class="actions"><a class="button" href="${escape(issuer)}/">Open app</a><a class="button primary" href="/mcp-debug">Reload status</a></div></div><section class="endpoint" aria-label="Public MCP endpoint"><div class="endpoint-label">Connect your MCP client here</div><code>${escape(issuer)}/mcp</code></section><section class="panel"><div class="panel-heading"><h2>Upstream connections</h2><p>These checks run when you load this page.</p></div><table class="connections"><thead><tr><th scope="col">Connection</th><th scope="col">Local URL</th><th scope="col">Current check</th></tr></thead><tbody>${rows.map(([name, url, status]) => `<tr><td>${name}</td><td><code>${escape(url)}</code></td><td><span class="check ${status.startsWith("HTTP") ? "" : "unavailable"}"><span class="dot" aria-hidden="true"></span><span>${escape(status)}</span></span></td></tr>`).join("")}</tbody></table><p class="panel-note">A reachable HTTP server can still reject an MCP request. Authorization and tool calls must also succeed in your MCP client.</p></section><section class="panel"><div class="panel-heading"><h2>Recent MCP forwarding results</h2><p>The ten most recent responses from your MCP upstream.</p></div>${recent.length ? `<table><thead><tr><th scope="col">Status</th><th scope="col">Duration</th></tr></thead><tbody>${recent.map(({ status, duration }) => `<tr><td>${status}</td><td class="request-code">${duration} ms</td></tr>`).join("")}</tbody></table>` : `<p class="empty">No MCP requests forwarded yet. Connect a client to the public MCP URL above and call a tool, then reload this page.</p>`}<p class="panel-note">Only status and duration are recorded. Tokens, authorization codes, cookies and request bodies are never stored here.</p></section><div class="help"><section><h2>Upstream unavailable?</h2><p>Start the server at its configured URL and retry. You do not need to restart this provider when an upstream comes back online.</p></section><section><h2>Check authentication and routing</h2><p>Reconnect your MCP client if authorization fails. <a href="https://dashboard.ngrok.com/traffic-inspector" target="_blank" rel="noreferrer">Open ngrok Traffic Inspector</a> for gateway status and routing.</p></section></div><p class="footer">Provider keys, registrations and sessions are temporary. Restarting this process requires client reauthorization.</p></main></body></html>`;
}

export async function startServers({ appUrl, mcpUrl, issuer, gatewaySecret, jwks }) {
  const auth = createIssuer({ issuer, gatewaySecret, jwks });
  const active = new Set();
  const recent = [];
  const sockets = new Set();
  const mcpBase = new URL(mcpUrl);
  const mcpPath = decodeURIComponent(mcpBase.pathname).replace(/\/+$/, "").toLowerCase() || "/";
  // Hostname aliases can share an upstream, so root-mounted MCP disables all app forwarding.
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
      (mcpPath !== "/" && (path === mcpPath || path.startsWith(`${mcpPath}/`))) ||
      mcpPath === "/"
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
    delete headers["x-mcp-oauth-provider-secret"];
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
    // MCP tools may compute before sending headers; bound connection setup instead.
    const deadline = setTimeout(() => upstream.destroy(), 10000);
    if (kind === "MCP")
      upstream.on("socket", (socket) => {
        if (upstream.reusedSocket) clearTimeout(deadline);
        else
          socket.once(target.protocol === "https:" ? "secureConnect" : "connect", () =>
            clearTimeout(deadline),
          );
      });
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
        if (!trusted(req.headers["x-mcp-oauth-provider-secret"], gatewaySecret))
          return json(res, 403, {
            error: "Open this page through the ngrok Google sign-in gateway.",
          });
        if (req.method !== "GET") return json(res, 405, { error: "Reload this page with GET." });
        res.setHeader(
          "content-security-policy",
          "default-src 'none'; style-src 'unsafe-inline'; font-src https://assets.ngrok.com; frame-ancestors 'none'",
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
      delete headers["x-mcp-oauth-provider-secret"];
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

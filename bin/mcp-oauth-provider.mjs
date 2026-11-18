#!/usr/bin/env node
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { openDebugPage } from "../lib/browser.mjs";
import { readConfig } from "../lib/config.mjs";
import { startServers } from "../lib/server.mjs";
import { reservePublicUrl, startTunnels } from "../lib/tunnel.mjs";

let config;
let reservation;
let servers;
let tunnels;
let stopping = false;
const secrets = [];
async function stop() {
  if (stopping) return;
  stopping = true;
  await tunnels?.close();
  await reservation?.close();
  await servers?.close();
}
const help = `MCP OAuth Provider

Run this command from your MCP server’s project directory. Settings come from .env or environment:
  NGROK_AUTHTOKEN  Your ngrok agent authtoken (required)
  OWNER_EMAIL      Allowed Google account (required)
  APP_URL          Optional web app origin (default http://127.0.0.1:3000)
  MCP_URL          Existing MCP URL (default http://127.0.0.1:3001/mcp)
  NGROK_URL        Optional public HTTPS origin; otherwise allocated automatically

Your MCP server keeps its existing code. No separate web app is required. Paid internal endpoints required.
Connect your MCP client at /mcp. Open /mcp-debug for protected diagnostics.
The protected debug page opens automatically. Use --no-debug to skip opening it.
Use --help or --version. Stop with Ctrl+C.
`;
async function main() {
  const { values } = parseArgs({
    options: {
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
      "no-debug": { type: "boolean" },
    },
  });
  if (values.help) return console.log(help);
  if (values.version)
    return console.log(
      JSON.parse(await readFile(new URL("../package.json", import.meta.url))).version,
    );
  config = await readConfig();
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => void stop());
  console.log("Connecting to ngrok…");
  reservation = await reservePublicUrl(config);
  if (stopping) {
    await reservation.close();
    return;
  }
  const { issuer } = reservation;
  const gatewaySecret = randomBytes(32).toString("base64url");
  secrets.push(gatewaySecret);
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = randomBytes(12).toString("hex");
  const jwks = {
    keys: [{ ...privateKey.export({ format: "jwk" }), kid, use: "sig", alg: "RS256" }],
  };
  servers = await startServers({ ...config, issuer, gatewaySecret, jwks });
  if (stopping) {
    await servers.close();
    return;
  }
  tunnels = await startTunnels({
    ...config,
    session: reservation.session,
    issuer,
    helperUrl: servers.helperUrl,
    mcpUrl: servers.mcpProxyUrl,
    gatewaySecret,
    jwksUrl: `${issuer}/jwks?v=${kid}`,
  });
  if (stopping) {
    await tunnels.close();
    await servers.close();
    return;
  }
  console.log(
    `\nMCP OAuth Provider is ready\n\nApp:     ${issuer}/\nMCP:     ${issuer}/mcp\nDebug:   ${issuer}/mcp-debug\nOwner:   ${config.ownerEmail}\n\nRun your existing MCP server at ${config.mcpUrl}.\nOptional web app: ${config.appUrl}.\nSign in with Google when connecting your MCP client. Ctrl+C stops the provider.\n`,
  );
  if (!values["no-debug"]) openDebugPage(`${issuer}/mcp-debug`);
}
main().catch(async (error) => {
  await stop().catch(() => {});
  let message = error.message ?? String(error);
  for (const secret of [...secrets, config?.authtoken].filter(Boolean))
    message = message.replaceAll(secret, "[redacted]");
  console.error(
    `\nMCP OAuth Provider could not start: ${message}\nCheck .env and your ngrok account permissions, then rerun. Use --help for settings.`,
  );
  process.exitCode = 1;
});

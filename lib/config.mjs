import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseEnv } from "node:util";

export async function readConfig({ cwd = process.cwd(), env = process.env } = {}) {
  let local = {};
  try {
    local = parseEnv(await readFile(resolve(cwd, ".env"), "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw new Error(`Cannot read .env: ${error.message}`);
  }
  const values = { ...local, ...env };
  const ownerEmail = values.OWNER_EMAIL?.trim().toLowerCase();
  if (!ownerEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ownerEmail))
    throw new Error("Set OWNER_EMAIL in .env to the Google account allowed to connect.");
  const authtoken = values.NGROK_AUTHTOKEN?.trim();
  if (!authtoken || /\s/.test(authtoken))
    throw new Error("Set NGROK_AUTHTOKEN in .env using your ngrok agent authtoken.");
  const upstream = (name, fallback, originOnly = false) => {
    let url;
    try {
      url = new URL(values[name] || fallback);
    } catch {
      throw new Error(`${name} must be an HTTP(S) URL.`);
    }
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (originOnly && url.pathname !== "/")
    )
      throw new Error(
        `${name} must be an HTTP(S) ${originOnly ? "origin" : "URL"} without credentials, query or fragment.`,
      );
    return url.href;
  };
  let publicUrl;
  if (values.NGROK_URL) {
    let url;
    try {
      url = new URL(values.NGROK_URL);
    } catch {
      throw new Error("NGROK_URL must be an HTTPS origin.");
    }
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    )
      throw new Error("NGROK_URL must be an HTTPS origin without a path.");
    publicUrl = url.origin;
  }
  return {
    ownerEmail,
    authtoken,
    publicUrl,
    appUrl: upstream("APP_URL", "http://127.0.0.1:3000", true),
    mcpUrl: upstream("MCP_URL", "http://127.0.0.1:3001/mcp"),
  };
}

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { readConfig } from "../lib/config.mjs";

test("working-directory .env, environment precedence and URL boundaries", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "mcp-oauth-config-"));
  try {
    await writeFile(
      join(cwd, ".env"),
      'OWNER_EMAIL="Owner@example.com"\nNGROK_AUTHTOKEN=fixture\nAPP_URL=http://localhost:4321\nMCP_URL=http://localhost:4322/custom-mcp\n',
    );
    const config = await readConfig({ cwd, env: { APP_URL: "http://127.0.0.1:5000" } });
    assert.equal(config.ownerEmail, "owner@example.com");
    assert.equal(config.appUrl, "http://127.0.0.1:5000/");
    assert.equal(config.mcpUrl, "http://localhost:4322/custom-mcp");
    assert.equal(config.publicUrl, undefined);
    for (const env of [
      { APP_URL: "not a URL" },
      { APP_URL: "ftp://app:3000" },
      { APP_URL: "http://app:3000/path" },
      { APP_URL: "http://app:3000/?query=secret" },
      { MCP_URL: "file:///mcp" },
      { MCP_URL: "http://mcp:8000/mcp?secret=value" },
      { MCP_URL: "http://mcp:8000/mcp#fragment" },
      { MCP_URL: "http://x:y@localhost/mcp" },
      { NGROK_URL: "https://example.com/path" },
      { OWNER_EMAIL: "" },
      { NGROK_AUTHTOKEN: "" },
    ]) {
      await assert.rejects(readConfig({ cwd, env }));
    }
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test("trusted configured upstreams support Docker host names and service DNS", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "mcp-oauth-container-config-"));
  const credentials = { OWNER_EMAIL: "owner@example.com", NGROK_AUTHTOKEN: "fixture" };
  try {
    const defaults = await readConfig({ cwd, env: credentials });
    assert.equal(defaults.appUrl, "http://127.0.0.1:3000/");
    assert.equal(defaults.mcpUrl, "http://127.0.0.1:3001/mcp");
    for (const [appUrl, mcpUrl] of [
      ["http://host.docker.internal:3000", "http://host.docker.internal:3001/mcp"],
      ["http://app:3000", "http://mcp:8000/custom-mcp"],
      ["https://app.internal", "https://mcp.internal/mcp"],
    ]) {
      const config = await readConfig({
        cwd,
        env: { ...credentials, APP_URL: appUrl, MCP_URL: mcpUrl },
      });
      assert.equal(config.appUrl, new URL(appUrl).href);
      assert.equal(config.mcpUrl, mcpUrl);
    }
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

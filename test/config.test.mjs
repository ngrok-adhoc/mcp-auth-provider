import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { readConfig } from "../lib/config.mjs";

test("working-directory .env, environment precedence and URL boundaries", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "mcp-auth-config-"));
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
      { APP_URL: "http://example.com" },
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

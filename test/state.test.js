import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, rmdir, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { openOAuthState } from "../dist/lib/state.js";

test("OAuth state is private, Git-ignored, and recovers after a process is killed", async (t) => {
  const cwd = await mkdtemp(join(tmpdir(), "mcp-oauth-state-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  const issuer = "https://provider.example";
  const users = ["owner@example.com"];
  const moduleUrl = new URL("../dist/lib/state.js", import.meta.url);
  const child = (body) =>
    spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import { openOAuthState } from ${JSON.stringify(moduleUrl.href)};
         const state = await openOAuthState(${JSON.stringify(issuer)}, ${JSON.stringify(users)});
         ${body}`,
      ],
      { cwd, encoding: "utf8", timeout: 10000 },
    );
  const initial = await openOAuthState(issuer, users, cwd);
  const directory = join(cwd, ".mcp-oauth-provider");
  const snapshot = join(directory, "oauth.json");
  try {
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
    assert.equal((await stat(snapshot)).mode & 0o777, 0o600);
    execFileSync("git", ["init", "-q"], { cwd });
    execFileSync("git", ["check-ignore", "-q", snapshot], { cwd });
    const blocked = child("await state.close();");
    assert.equal(blocked.status, 1, blocked.stderr);
    assert.match(blocked.stderr, /already locked/);
  } finally {
    await initial.close();
  }
  const crashed = child(`
    const sessions = state.adapter("Session");
    await sessions.upsert("session", { uid: "uid", accountId: "owner" }, 60);
    process.kill(process.pid, "SIGKILL");
  `);
  assert.equal(crashed.signal, "SIGKILL", crashed.stderr);
  await assert.rejects(() => openOAuthState(issuer, users, cwd), /already locked/);
  await rmdir(join(directory, ".lock"));
  const recovered = await openOAuthState(issuer, users, cwd);
  try {
    assert.equal(recovered.kid, initial.kid);
    assert.deepEqual(await recovered.adapter("Session").findByUid("uid"), {
      uid: "uid",
      accountId: "owner",
    });
  } finally {
    await recovered.close();
  }

  const state = await openOAuthState(issuer, users, cwd);
  const pending = join(directory, ".oauth.json.tmp");
  await mkdir(pending);
  try {
    await assert.rejects(
      state.adapter("Session").upsert("failed", { uid: "failed" }, 60),
      /Could not save OAuth state/,
    );
    await assert.rejects(state.adapter("Session").find("session"), /Could not save OAuth state/);
  } finally {
    await rmdir(pending);
    await state.close();
  }
  const beforeReset = await openOAuthState(issuer, users, cwd);
  try {
    assert.ok(await beforeReset.adapter("Session").find("session"));
    assert.equal(await beforeReset.adapter("Session").find("failed"), undefined);
  } finally {
    await beforeReset.close();
  }

  const changedIssuer = await openOAuthState("https://replacement.example", users, cwd);
  try {
    assert.notEqual(changedIssuer.kid, initial.kid);
    assert.equal(await changedIssuer.adapter("Session").find("session"), undefined);
  } finally {
    await changedIssuer.close();
  }

  await writeFile(snapshot, "{invalid");
  await assert.rejects(() => openOAuthState(issuer, users, cwd), /Cannot read OAuth state/);
  assert.equal(await readFile(snapshot, "utf8"), "{invalid");
  await chmod(snapshot, 0o644);
  await assert.rejects(() => openOAuthState(issuer, users, cwd), /state file must be.*private/);
});

test("S3 stores OAuth state directly and rejects stale and failed writes", async (t) => {
  const { createHash } = await import("node:crypto");
  const { once } = await import("node:events");
  const { createServer } = await import("node:http");
  const cwd = await mkdtemp(join(tmpdir(), "mcp-oauth-s3-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));

  let snapshot;
  let etag;
  let unavailable = false;
  const calls = [];
  const server = createServer(async (req, res) => {
    assert.equal(new URL(req.url, "http://localhost").pathname, "/fixture-bucket/provider.json");
    calls.push(req.method);
    if (req.method === "GET") {
      if (snapshot) return res.writeHead(200, { etag }).end(snapshot);
      return res
        .writeHead(404, { "content-type": "application/xml" })
        .end("<Error><Code>NoSuchKey</Code><Message>Missing key</Message></Error>");
    }
    assert.equal(req.method, "PUT");
    let body = "";
    for await (const chunk of req) body += chunk;
    if (unavailable) return res.writeHead(503).end();
    if (etag ? req.headers["if-match"] !== etag : req.headers["if-none-match"] !== "*") {
      return res
        .writeHead(412, { "content-type": "application/xml" })
        .end("<Error><Code>PreconditionFailed</Code><Message>Stale write</Message></Error>");
    }
    snapshot = body;
    etag = `"${createHash("sha256").update(body).digest("hex")}"`;
    res.writeHead(200, { etag }).end();
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const endpoint = process.env.AWS_ENDPOINT_URL_S3;
  process.env.AWS_ENDPOINT_URL_S3 = `http://127.0.0.1:${server.address().port}`;
  t.after(() => {
    if (endpoint === undefined) delete process.env.AWS_ENDPOINT_URL_S3;
    else process.env.AWS_ENDPOINT_URL_S3 = endpoint;
  });

  const issuer = "https://provider.example";
  const users = ["owner@example.com"];
  const s3 = {
    bucket: "fixture-bucket",
    key: "provider.json",
    required: true,
    region: "us-east-1",
    credentials: { accessKeyId: "test", secretAccessKey: "test" },
  };
  const first = await openOAuthState(issuer, users, cwd, s3);
  t.after(() => first.close());
  assert.deepEqual(calls, ["GET", "PUT"]);
  const records = first.adapter("Session");
  await Promise.all([records.upsert("a", { uid: "a" }, 60), records.upsert("b", { uid: "b" }, 60)]);
  assert.equal(JSON.parse(snapshot).records.length, 2);

  const second = await openOAuthState(issuer, users, cwd, s3);
  t.after(() => second.close());
  assert.equal(first.kid, second.kid);
  await assert.rejects(records.upsert("stale", { uid: "stale" }, 60), /changed in S3/);
  assert.deepEqual(await second.adapter("Session").findByUid("a"), { uid: "a" });
  assert.equal(await second.adapter("Session").find("stale"), undefined);

  unavailable = true;
  await assert.rejects(
    second.adapter("Session").upsert("lost", { uid: "lost" }, 60),
    /Cannot save OAuth state to s3/,
  );
  await assert.rejects(second.adapter("Session").find("a"), /Cannot save OAuth state to s3/);
  assert.equal(JSON.parse(snapshot).records.length, 2);
  await assert.rejects(stat(join(cwd, ".mcp-oauth-provider")), { code: "ENOENT" });

  unavailable = false;
  const changed = await openOAuthState(issuer, ["new@example.com"], cwd, s3);
  t.after(() => changed.close());
  assert.notEqual(changed.kid, first.kid);
  assert.equal(await changed.adapter("Session").find("a"), undefined);
});

test("automatic S3 falls back without credentials and required S3 fails closed", async (t) => {
  const cwd = await mkdtemp(join(tmpdir(), "mcp-oauth-s3-credentials-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  const source = new URL("../dist/lib/state.js", import.meta.url);
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
      import assert from "node:assert/strict";
      import { stat } from "node:fs/promises";
      import { openOAuthState } from ${JSON.stringify(source.href)};
      const issuer = "https://provider.example";
      const users = ["owner@example.com"];
      const options = {bucket:"fixture-bucket", key:"provider.json", region:"us-east-1"};
      await assert.rejects(
        openOAuthState(issuer, users, process.cwd(), {...options, required:true}),
        /Cannot resolve AWS credentials/,
      );
      await assert.rejects(stat(".mcp-oauth-provider"), {code:"ENOENT"});
      const local = await openOAuthState(issuer, users, process.cwd(), {...options, required:false});
      await local.close();
      assert.ok(await stat(".mcp-oauth-provider/oauth.json"));
    `,
    ],
    {
      cwd,
      encoding: "utf8",
      timeout: 10000,
      env: {
        HOME: cwd,
        USERPROFILE: cwd,
        AWS_CONFIG_FILE: join(cwd, "aws-config"),
        AWS_SHARED_CREDENTIALS_FILE: join(cwd, "aws-credentials"),
        AWS_EC2_METADATA_DISABLED: "true",
      },
    },
  );
  assert.equal(result.status, 0, result.stderr || String(result.error));
});

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { openDebugPage } from "../lib/browser.mjs";

test("browser launch passes URLs as data and failures do not stop the provider", () => {
  for (const platform of ["darwin", "linux", "win32"]) {
    const child = new EventEmitter();
    let detached = false;
    child.unref = () => {
      detached = true;
    };
    let warnings = 0;
    const url = "https://provider.example/mcp-debug";
    openDebugPage(url, {
      platform,
      spawn(command, args, options) {
        assert.equal(options.stdio, "ignore");
        assert.equal(options.shell, undefined);
        if (platform === "win32")
          assert.equal(
            Buffer.from(args.at(-1), "base64").toString("utf16le"),
            `Start-Process '${url}'`,
          );
        else assert.deepEqual(args, [url]);
        assert.ok(command);
        return child;
      },
      warn() {
        warnings++;
      },
    });
    assert.equal(detached, true);
    child.emit("error", new Error("No desktop"));
    child.emit("exit", 1);
    assert.equal(warnings, 1);
  }
});

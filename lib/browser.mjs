import { spawn as spawnProcess } from "node:child_process";

export function openDebugPage(
  url,
  { platform = process.platform, spawn = spawnProcess, warn = console.warn } = {},
) {
  let command;
  let args;
  if (platform === "darwin") {
    command = "open";
    args = [url];
  } else if (platform === "win32") {
    command = "powershell.exe";
    const script = `Start-Process '${url.replaceAll("'", "''")}'`;
    args = [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(script, "utf16le").toString("base64"),
    ];
  } else {
    command = "xdg-open";
    args = [url];
  }
  let failed = false;
  const failure = () => {
    if (failed) return;
    failed = true;
    warn(
      `Could not open the debug page automatically. Open ${url} in your browser, or use --no-debug to skip automatic opening.`,
    );
  };
  try {
    const child = spawn(command, args, { stdio: "ignore", detached: true, windowsHide: true });
    child.once("error", failure);
    child.once("exit", (code) => {
      if (code) failure();
    });
    child.unref();
  } catch {
    failure();
  }
}

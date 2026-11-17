# MCP OAuth Provider

Connect an existing local HTTP MCP server through ngrok-managed Google sign-in, without changing the server. Keep your app at `/`, connect MCP clients at `/mcp`, and check the connection at `/mcp-debug`.

This is a lightweight developer tool: ngrok Traffic Policy handles access checks and routing; the provider handles OAuth registration, consent and tokens.

## Run

Requires **Node.js 24+**, npm/npx, and an ngrok account with paid internal endpoints and the required Traffic Policy actions. No separate ngrok executable, Google Cloud project or custom OAuth application is needed.

For now, use a local package; it has not been published to npm. Prepare it once from the source checkout:

```sh
git clone --branch mcp-oauth-provider-cli https://github.com/ngrok-adhoc/mcp-oauth-provider.git
cd mcp-oauth-provider
npm ci
npm pack
```

This creates `mcp-oauth-provider-0.1.0.tgz`. If someone has already provided that file, skip the checkout and packaging steps. Then switch to your app directory:

```sh
cd /path/to/your/existing-app
```

Add these settings to that directory's `.env`:

```dotenv
NGROK_AUTHTOKEN=your_ngrok_agent_authtoken
OWNER_EMAIL=you@example.com
```

Keep `.env` out of Git. Use your **agent authtoken**, not an ngrok API key. The SDK needs this value even if the ngrok CLI is already signed in.

Start your app and MCP server as usual, then run:

```sh
npx --yes --package=/absolute/path/to/mcp-oauth-provider-0.1.0.tgz mcp-oauth-provider
```

`npx` installs the package's dependencies automatically; your app needs no additional install step.

The command prints the app, MCP and debug URLs and opens the protected debug page in your default browser. Add `--no-debug` to skip automatic opening; the protected page remains available. Add the printed `/mcp` URL to your OAuth-capable MCP client, sign in with the configured Google account, and approve access. Stop the provider with **Ctrl+C**; your app and MCP processes keep running.

The defaults are `http://127.0.0.1:3000` for the app and `http://127.0.0.1:3001/mcp` for MCP. If yours differ, add:

```dotenv
APP_URL=http://127.0.0.1:3000
MCP_URL=http://127.0.0.1:3001/mcp
# Optional; omit to let ngrok allocate the public URL.
# NGROK_URL=https://your-assigned-dev-domain.ngrok-free.app
```

Upstreams are trusted HTTP(S) URLs from your `.env` or environment. Use loopback addresses locally, or host/service names on a private Docker network; never accept these settings from a public request. `APP_URL` is an origin; `MCP_URL` includes the existing MCP path. `NGROK_URL`, when set, is an HTTPS origin available to your account. A dev-domain name does not make the required paid actions free.

The provider reads `.env` from the **working directory**. Existing environment variables take precedence. No `.mjs` or YAML configuration needs editing; `.mjs` files are the implementation. Use `--help` for settings or `--version` for the package version.

## What runs where

```text
One public ngrok URL
  /mcp          -> Traffic Policy validates token -> private MCP route
  OAuth routes  -> local provider issues tokens and handles consent
  /mcp-debug    -> Google-protected connection status
  other paths   -> existing app
```

The CLI uses the ngrok Node SDK to start **one public endpoint and two internal endpoints**. JWT signature, issuer, audience, scope and time checks run in Traffic Policy. A small local forwarding adapter provides useful upstream errors; it does not implement MCP tools or change your server.

The provider also serves the approval page; your app needs no authorization route. It grants one connection permission (`mcp:use`), allowing the client to call the tools your MCP server exposes. It does not implement app-specific read/write permissions.

Reserved paths are `/mcp`, `/mcp/*`, `/mcp-debug`, `/mcp-debug/*`, `/auth`, `/auth/*`, `/token`, `/reg`, `/jwks`, `/interaction/*`, the provider's OAuth/MCP `/.well-known/` discovery paths, and ngrok's `/ngrok/*` login callbacks. Other app paths and query strings pass through. The configured non-root MCP path is also reserved from app fallthrough, including case and encoded variants, so hostname aliases cannot bypass authorization.

## Start alongside Python or Node

Your MCP application never imports this package. A shell process runner can start both independent commands and stop the companion when either exits:

```sh
npx --yes --package=concurrently concurrently --kill-others \
  "python server.py" \
  "npx --yes --package=/absolute/path/mcp-oauth-provider-0.1.0.tgz mcp-oauth-provider"
```

Use your existing HTTP server command (for example `node server.mjs`) instead of `python server.py`. Add the app command as a third entry if it runs separately. Put the command in a project script or task file if you want a short alias such as `just dev`; no MCP source changes are needed.

## Docker and background use

From the provider checkout, build the local image and use the example as a sidecar for host services. Put an ignored `.env` beside `compose.example.yml` or point its `env_file` to your existing settings:

```sh
docker build -t mcp-oauth-provider:local .
docker compose -f compose.example.yml up --build
# Run in the background:
docker compose -f compose.example.yml up --build -d
# Stop:
docker compose -f compose.example.yml down
```

The image runs as a nonroot user, opens no local ports, and defaults to `--no-debug` for headless use. Set `APP_URL` and `MCP_URL` to `host.docker.internal` for host services or Compose service names such as `http://app:3000` and `http://mcp:8000/mcp`. Container `localhost` means the provider container. On Linux, host-gateway cannot reach a service bound only to host loopback: use a shared Compose network or an appropriately reachable host address.

To start your existing containerized app/MCP too, add the provider service from the example to their Compose stack and run `docker compose up`. The example's `restart: unless-stopped` supplies service-like process supervision. It does not make OAuth state persistent or remove token expiry. No OS service installer or container-registry publication is included.

## Test with a complete Docker stack

[Run the Docker Compose tutorial](https://github.com/ngrok-adhoc/mcp-oauth-provider/blob/mcp-oauth-provider-cli/docs/python.md) to start a tiny app, an HTTP MCP `hello` tool and the provider from one Compose file, then call the tool through ngrok using Codex or Claude Code. No existing MCP server is needed; the CLI package contains no demo app.

## Diagnose a connection

Open the printed **`/mcp-debug`** URL and sign in as `OWNER_EMAIL`. It shows app/MCP reachability and the ten most recent forwarded MCP response statuses and durations. Reload to check again.

A reachability result such as HTTP 405 means an HTTP server answered; it does **not** prove an MCP session or tool call works. Verify those in your MCP client.

| Symptom                                                           | What to do                                                                                                                         |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `App upstream is unavailable` or `mcp_upstream_unavailable` (503) | Start that server, check `APP_URL` or `MCP_URL`, and retry. Restarting the upstream does not require restarting the provider.      |
| `owner_required` (403)                                            | Sign in with the exact Google account in `OWNER_EMAIL`.                                                                            |
| `invalid_token` (401) or an expired connection                    | Reauthorize the MCP client. After a provider restart, Claude may need logout before login.                                         |
| CLI cannot start                                                  | Read its error, check the two required `.env` values, your chosen public URL and paid endpoint permissions, then rerun.            |
| ngrok 3200 / endpoint offline                                     | The provider or its tunnel is not running. Check the terminal and restart it. An offline process cannot serve a custom error page. |

Use [ngrok Traffic Inspector](https://dashboard.ngrok.com/traffic-inspector) for gateway-level requests and routing. The embedded SDK does not provide the ngrok CLI's local port-4040 inspector. The debug page stores only status and duration, never request bodies, tokens, cookies or authorization codes. Full captures in Traffic Inspector can contain sensitive OAuth traffic; control access and capture settings accordingly.

## Demo limits

Access tokens last seven days. Rotating refresh tokens share the same seven-day authorization window; renewed access tokens expire when that window ends. A copied bearer token remains usable until its expiry. Keys, registrations, grants and sessions are in memory, so restarting requires client login. This is a local development tool.

- One Google owner, one HTTP MCP resource, and HTTP loopback client callbacks. Hosted callbacks, multiple MCPs and stdio translation are outside this tool.
- Keep local listeners private. Only configured public routes should reach the app and MCP.

## Develop

```sh
npm ci
npm run check
```

For harmless manual fixtures, run `node test/fixtures/upstreams.mjs` and set `APP_URL=http://127.0.0.1:54831` and `MCP_URL=http://127.0.0.1:54832/original-mcp`.

The package's `bin` entry is the CLI; tests exercise configuration, OAuth boundaries, forwarding and Traffic Policy generation. Public npm publication and binary distribution are separate future steps.

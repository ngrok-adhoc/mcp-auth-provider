# MCP OAuth Provider

Connect an existing local HTTP MCP server through ngrok-managed Google sign-in, without changing the server. Keep your app at `/`, connect MCP clients at `/mcp`, and check the connection at `/mcp-debug`.

This is a lightweight developer tool: ngrok Traffic Policy handles access checks and routing; the provider handles OAuth registration, consent and tokens.

[Run with npx from Git](#run-with-npx), or use Docker with the [Compose tutorial](https://github.com/ngrok-adhoc/mcp-oauth-provider/blob/main/docs/python.md).

## Try with Docker Compose

Requires Docker with Compose, a Google account and an ngrok account with the required paid endpoints and Traffic Policy actions. No local Python, Node installation or repository checkout is needed.

> The image is published but currently private. Registry pulls require an authorized GitHub login with package-read access and any organization SSO approval. For a local build, follow [Build the image locally](#build-the-image-locally).

```sh
mkdir mcp-demo
cd mcp-demo
```

Create `.env` in that directory:

```dotenv
NGROK_AUTHTOKEN=your_agent_authtoken
OWNER_EMAIL=your_google_email
# Optional: choose an HTTPS domain available to your account.
# NGROK_URL=https://your-assigned-dev-domain.ngrok-free.app
```

Use your **ngrok agent authtoken**, not an API key. Keep `.env` private and out of Git. Copy the single [Compose example from the tutorial](https://github.com/ngrok-adhoc/mcp-oauth-provider/blob/main/docs/python.md#start-the-stack) into `compose.yaml` in the same directory, then run:

For a registry pull, first run `docker login ghcr.io -u YOUR_GITHUB_USERNAME` with a classic PAT that has package-read access and the required organization SSO authorization. Local builds use `--pull never` instead.

```sh
docker compose --env-file .env up -d
docker compose --env-file .env logs -f provider
```

Docker pulls the provider image and starts a minimal Python HTTP MCP server with a `hello` tool. There is no demo web app or published container port. A 404 at the bare public `/` is expected.

**Connect clients to the printed public HTTPS ngrok URL ending in `/mcp`, not localhost or `http://mcp:8000/mcp`.** Localhost may appear during the browser OAuth callback; that callback is not the MCP server address.

The commands below use the current test endpoint, `https://mcp-oauth-compose.ngrok.video/mcp`. For your own stack, replace it with the printed MCP URL.

For Codex, open a second terminal:

```sh
codex mcp add hello-compose --url https://mcp-oauth-compose.ngrok.video/mcp
codex
```

Complete browser sign-in and approve the connection. If adding did not start sign-in, run `codex mcp login hello-compose` before starting Codex.

For Claude Code:

```sh
claude mcp add --transport http hello-compose https://mcp-oauth-compose.ngrok.video/mcp
claude mcp login hello-compose
claude
```

Ask either client:

> Call the hello tool from hello-compose and show its exact result.

Approve the tool call if prompted. Expect **`Hello from Python!`**. The provider hosts sign-in, approval and token handling; the downstream MCP server needs no OAuth routes, provider imports or token-handling code. It only needs an existing HTTP MCP endpoint reachable by the provider. No separate app is required; stdio servers are outside this tool.

See the [Compose guide](https://github.com/ngrok-adhoc/mcp-oauth-provider/blob/main/docs/python.md) for shutdown and reconnecting after a provider restart.

## Run with npx

Requires **Node.js 24+**, npm/npx, Git, and an ngrok account with paid internal endpoints and the required Traffic Policy actions. No separate ngrok executable, Google Cloud project or custom OAuth application is needed.

Run directly from the repository’s `main` branch with `npx`; no manual clone, packaging or npm publication is needed. Start in your app directory:

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
npx --yes \
  --package=git+https://github.com/ngrok-adhoc/mcp-oauth-provider.git#main \
  mcp-oauth-provider
```

`npx` fetches the package from GitHub and installs its dependencies in npm’s cache; your app needs no package changes.

Replace `#main` with a release tag or commit SHA to pin a revision.

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
  "npx --yes --package=git+https://github.com/ngrok-adhoc/mcp-oauth-provider.git#main mcp-oauth-provider"
```

Use your existing HTTP server command (for example `node server.mjs`) instead of `python server.py`. Add the app command as a third entry if it runs separately. Put the command in a project script or task file if you want a short alias such as `just dev`; no MCP source changes are needed.

## Docker and background use

Use `ghcr.io/ngrok-adhoc/mcp-oauth-provider:latest` with the [tutorial's Compose example](https://github.com/ngrok-adhoc/mcp-oauth-provider/blob/main/docs/python.md). It runs in the background with `up -d`; use `logs -f provider` to see connection URLs and `down` to stop the stack.

The image runs as a nonroot user, opens no local ports, and defaults to `--no-debug` for headless use. Set `APP_URL` and `MCP_URL` to trusted services on your Compose network, such as `http://app:3000` and `http://mcp:8000/mcp`. Container `localhost` means the provider container. Host services can use `host.docker.internal`; on Linux, a host-gateway mapping still cannot reach a listener bound only to host loopback.

The provider can run beside an existing MCP container; the MCP server never imports this package. Process supervision does not make OAuth state persistent. No custom supervisor or OS service installer is included.

## Build the image locally

Build from `main` and tag the image name used by the tutorial:

```sh
git clone --branch main https://github.com/ngrok-adhoc/mcp-oauth-provider.git
cd mcp-oauth-provider
docker build --tag ghcr.io/ngrok-adhoc/mcp-oauth-provider:latest .
```

Then return to your separate consumer directory containing `.env` and the copied `compose.yaml`:

```sh
cd /path/to/mcp-demo
docker compose --env-file .env up -d --pull never
```

`--pull never` uses the locally built image. Make sure `python:3.13-slim` is available locally first (`docker pull python:3.13-slim`). This verifies the local build, not registry access.

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

Access tokens last 90 days. Rotating refresh tokens share the same 90-day authorization window; renewed access tokens expire when that window ends. A copied bearer token remains usable until its expiry. Keys, registrations, grants and sessions are in memory, so restarting requires client login. This is a local development tool.

MCP upstreams get two minutes to establish a connection. Once connected, tool calls may wait for response headers or stream until completion or client cancellation. App response headers and WebSocket handshakes get five minutes. Consent and browser sessions last one day; authorization codes last 15 minutes.

- One Google owner, one HTTP MCP resource, and HTTP loopback client callbacks. Hosted callbacks, multiple MCPs and stdio translation are outside this tool.
- Keep local listeners private. Only configured public routes should reach the app and MCP.
- When the configured MCP upstream is mounted at `/`, optional app forwarding is disabled. Hostname aliases cannot safely distinguish a separate app from that root-mounted MCP server; the protected public `/mcp` route still works.

## Develop

```sh
npm ci
npm run check
```

For harmless manual fixtures, run `node test/fixtures/upstreams.mjs` and set `APP_URL=http://127.0.0.1:54831` and `MCP_URL=http://127.0.0.1:54832/original-mcp`.

The package's `bin` entry is the CLI; tests exercise configuration, OAuth boundaries, forwarding and Traffic Policy generation. Public npm publication and binary distribution are separate future steps.

## Publish a Docker release

Maintainers release from a clean `main` checkout matching `origin/main`, after the change has been reviewed and merged. Commit the intended version in `package.json` first, then supply that exact version:

```sh
npm run tag-release -- 0.1.0
```

The command creates an annotated `v0.1.0` tag without overwriting existing tags. Its push runs **Publish image**, publishing Linux amd64/arm64 images to `ghcr.io/ngrok-adhoc/mcp-oauth-provider` with `0.1.0`, `v0.1.0`, a commit SHA tag and `latest`. Main-branch builds only warm the build cache. Wait for the image workflow to succeed before updating tutorial image versions.

The GHCR package remains private. Consumers need package-read access and an authorized registry login; organization SSO approval may also be required. Public visibility and anonymous-pull verification are deferred. A successful publishing workflow does not prove that a consumer can pull the image.

If an automated release creates its tag using `GITHUB_TOKEN`, explicitly dispatch the publishing workflow at that tag because that token's tag push does not trigger another workflow:

```sh
gh workflow run publish-image.yml --ref v0.1.0
```

The workflow must already be on the default branch for dispatch. Retry a failed image build at the same tag; never overwrite the tag or create another version merely to retry a build.

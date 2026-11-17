# MCP Auth Provider

Connect an existing local HTTP MCP server through ngrok-managed Google sign-in, without changing the server. Keep your app at `/`, connect MCP clients at `/mcp`, and check the connection at `/mcp-debug`.

This is a lightweight developer tool: ngrok Traffic Policy handles access checks and routing; the provider handles OAuth registration, consent and tokens.

## Run

Requires **Node.js 24+**, npm/npx, and an ngrok account with paid internal endpoints and the required Traffic Policy actions. No separate ngrok executable, Google Cloud project or custom OAuth application is needed.

For now, use a local package; it has not been published to npm. Prepare it once from the source checkout:

```sh
git clone https://github.com/ngrok-adhoc/mcp-auth-provider.git
cd mcp-auth-provider
npm ci
npm pack
```

This creates `mcp-auth-provider-0.1.0.tgz`. If someone has already provided that file, skip the checkout and packaging steps. Then switch to your app directory:

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
npx --yes --package=/absolute/path/to/mcp-auth-provider-0.1.0.tgz mcp-auth-provider
```

`npx` installs the package's dependencies automatically; your app needs no additional install step.

The command prints the app, MCP and debug URLs. Add the printed `/mcp` URL to your OAuth-capable MCP client, sign in with the configured Google account, and approve access. Stop the provider with **Ctrl+C**; your app and MCP processes keep running.

The defaults are `http://127.0.0.1:3000` for the app and `http://127.0.0.1:3001/mcp` for MCP. If yours differ, add:

```dotenv
APP_URL=http://127.0.0.1:3000
MCP_URL=http://127.0.0.1:3001/mcp
# Optional; omit to let ngrok allocate the public URL.
# NGROK_URL=https://your-assigned-dev-domain.ngrok-free.app
```

Upstreams must use loopback HTTP(S) URLs. `APP_URL` is an origin; `MCP_URL` includes the existing MCP path. `NGROK_URL`, when set, is an HTTPS origin available to your account. A dev-domain name does not make the required paid actions free.

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

Reserved paths are `/mcp`, `/mcp/*`, `/mcp-debug`, `/mcp-debug/*`, `/auth`, `/auth/*`, `/token`, `/reg`, `/jwks`, `/interaction/*`, the provider's OAuth/MCP `/.well-known/` discovery paths, and ngrok's `/ngrok/*` login callbacks. Other app paths and query strings pass through. If app and MCP share a local origin, the configured MCP path is also blocked from app fallthrough so it cannot bypass authorization.

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

- Keys, registrations, grants and sessions are in memory. Restarting requires client reauthorization.
- Access tokens last five minutes; no refresh tokens are issued. This is not unattended production authentication.
- One Google owner, one HTTP MCP resource, and HTTP loopback client callbacks. Hosted callbacks, multiple MCPs and stdio translation are outside this tool.
- Keep local listeners private. Only configured public routes should reach the app and MCP.

## Develop

```sh
npm ci
npm run check
```

For harmless manual fixtures, run `node test/fixtures/upstreams.mjs` and set `APP_URL=http://127.0.0.1:54831` and `MCP_URL=http://127.0.0.1:54832/original-mcp`.

The package's `bin` entry is the CLI; tests exercise configuration, OAuth boundaries, forwarding and Traffic Policy generation. Public npm publication and binary distribution are separate future steps.

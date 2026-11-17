# Test end to end with Docker Compose

Start a tiny Python app, an HTTP MCP `hello` tool and the OAuth provider with one Compose file. You need no existing app or MCP server, and no local Python or Node installation.

```text
Codex / Claude Code → https://your-ngrok-host/mcp
                      ngrok Traffic Policy → provider → mcp:8000/mcp
Browser             → https://your-ngrok-host/ → provider → mcp:8000/
```

The [Compose file](compose.yaml) injects the Python code into an official Python container and installs the pinned official MCP SDK. App and MCP share one process; Python contains no OAuth or provider imports. Neither container publishes a host port. The only public entry is ngrok.

## Start the stack

Requires Docker with Compose, an ngrok account with the required paid endpoints/Traffic Policy actions, and a Google account for sign-in. No custom Google application is needed.

The provider image is not registry-published yet, so build it from this checkout:

```sh
git clone --branch mcp-oauth-provider-cli https://github.com/ngrok-adhoc/mcp-oauth-provider.git
cd mcp-oauth-provider
```

Create `.env` in the checkout root with your **agent authtoken** and allowed Google email:

```dotenv
NGROK_AUTHTOKEN=your_ngrok_agent_authtoken
OWNER_EMAIL=you@example.com
# Optional: use an HTTPS domain available to your account.
# NGROK_URL=https://your-assigned-dev-domain.ngrok-free.app
```

Keep `.env` private and ignored. Run from the checkout root:

```sh
docker compose --env-file .env -f docs/compose.yaml up --build
```

Wait for the provider's printed app, MCP and debug URLs. Open the app URL: expect **My Python app**. The Python health check must pass before the provider starts. The first run downloads images and Python dependencies; no extra source files are needed.

Open the printed `/mcp-debug` URL yourself; the headless container skips browser opening. Sign in as `OWNER_EMAIL`. HTTP reachability alone does not verify MCP—call the tool next.

## Test with Codex

In a second terminal, replace the URL below with the printed public MCP URL:

```sh
codex mcp add hello-compose --url https://your-ngrok-host/mcp
codex
```

Complete Google sign-in and approve access when prompted. If adding did not start login, run `codex mcp login hello-compose` first. In the new Codex session, ask:

> Call the hello tool from hello-compose and show its exact result.

Approve the tool call if Codex prompts. Expect an actual MCP tool call returning **Hello from Python!**. Use `/mcp` to inspect the server if the tool is unavailable. These commands follow the [Codex MCP guide](https://developers.openai.com/codex/mcp).

## Test with Claude Code

From the same directory:

```sh
claude mcp add --transport http hello-compose https://your-ngrok-host/mcp
claude mcp login hello-compose
claude
```

Complete the browser flow, then ask the same question. In Claude Code, `/mcp` also shows connection status and an **Authenticate** action. These commands follow the [Claude Code MCP guide](https://code.claude.com/docs/en/mcp).

The provider hosts the approval page. Its single connection permission allows the client to use the MCP tools; your Python app implements no authorization route or permission UI. Client tool-call confirmations still apply.

Reload `/mcp-debug` after the call: it should show a successful forwarding response. A plain `curl` to public `/mcp` without a token should return **401**; that is the expected access check. The app page remains at `/`.

## Keep running, stop or reconnect

Access tokens last seven days, and rotating refresh tokens share that same seven-day authorization window. Renewed access tokens are capped at the window’s remaining time; a copied bearer token remains usable until its expiry. Provider keys and OAuth state are in memory, so restarting or rebuilding requires a fresh client login. After a restart, use `codex mcp logout hello-compose` then `codex mcp login hello-compose`, or the equivalent `claude mcp logout` / `claude mcp login` commands.

Restarting only the `mcp` service keeps authorization intact. For background use, add `-d` to `up`, then view URLs with:

```sh
docker compose --env-file .env -f docs/compose.yaml logs -f provider
```

Stop the stack:

```sh
docker compose --env-file .env -f docs/compose.yaml down
```

If startup fails, check Docker and the provider logs, `.env` and account entitlements. If forwarding fails, check `docker compose --env-file .env -f docs/compose.yaml logs mcp` and the [connection diagnostics](../README.md#diagnose-a-connection).

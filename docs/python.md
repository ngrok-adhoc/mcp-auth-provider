# Test end to end with Docker Compose

Start an HTTP MCP `hello` server and the OAuth provider with one Compose file. You need no existing MCP server and no local Python or Node installation. There is no demo web app.

```text
Codex / Claude Code → https://your-ngrok-host/mcp
                      ngrok Traffic Policy → provider → mcp:8000/mcp
```

The Compose example below uses the provider image from GitHub Container Registry and injects a minimal server into an official Python container with the pinned MCP SDK. Python contains no OAuth or provider imports. Neither container publishes a host port. The only public entry is ngrok.

## Start the stack

Requires Docker with Compose, an ngrok account with the required paid endpoints/Traffic Policy actions, and a Google account for sign-in. No custom Google application is needed.

> The image is published but currently private. Registry pulls require an authorized GitHub login with package-read access and any organization SSO approval. To use a local build instead, follow [Build the image locally](../README.md#build-the-image-locally), then start Compose with `--pull never`.

Create a new directory:

```sh
mkdir mcp-demo
cd mcp-demo
```

Create `.env` in that directory with your **agent authtoken** and allowed Google email:

```dotenv
NGROK_AUTHTOKEN=your_ngrok_agent_authtoken
OWNER_EMAIL=you@example.com
# Optional: use an HTTPS domain available to your account.
# NGROK_URL=https://your-assigned-dev-domain.ngrok-free.app
```

Keep `.env` private and out of Git. Save this as `compose.yaml` in the same directory:

```yaml
services:
  mcp:
    image: python:3.13-slim
    init: true
    command:
      - sh
      - -ec
      - |
        pip install --no-cache-dir 'mcp==2.3.0'
        exec python -u - <<'PY'
        from mcp.server import MCPServer
        from mcp.types import ToolAnnotations

        mcp = MCPServer("Hello Python")

        @mcp.tool(annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                             idempotent_hint=True, open_world_hint=False))
        async def hello() -> str:
            """Return a greeting from the Python container."""
            return "Hello from Python!"

        mcp.run("streamable-http", host="0.0.0.0", port=8000,
                stateless_http=True, json_response=True)
        PY
    healthcheck:
      test:
        [
          "CMD",
          "python",
          "-c",
          "import socket; socket.create_connection(('127.0.0.1', 8000), timeout=2).close()",
        ]
      interval: 3s
      timeout: 3s
      retries: 30
      start_period: 30s

  provider:
    image: ghcr.io/ngrok-adhoc/mcp-oauth-provider:latest
    init: true
    depends_on:
      mcp:
        condition: service_healthy
    environment:
      NGROK_AUTHTOKEN: ${NGROK_AUTHTOKEN:?Set NGROK_AUTHTOKEN in .env}
      OWNER_EMAIL: ${OWNER_EMAIL:?Set OWNER_EMAIL in .env}
      NGROK_URL: ${NGROK_URL:-}
      APP_URL: http://mcp:8000
      MCP_URL: http://mcp:8000/mcp
```

Start the stack. Docker pulls the images automatically; no repository checkout or local build is needed:

For a registry pull, first run `docker login ghcr.io -u YOUR_GITHUB_USERNAME` with a classic PAT that has package-read access and the required organization SSO authorization. Local builds use `--pull never` instead.

```sh
docker compose --env-file .env up -d
docker compose --env-file .env logs -f provider
```

Wait for the provider’s printed **MCP** and **Debug** URLs. Use the public HTTPS MCP URL ending in `/mcp`, not `localhost` or the private Docker service address. The TCP health check must pass before the provider starts. The first run downloads images and Python dependencies; no extra source files are needed.

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

The MCP client may open a `localhost` callback during browser sign-in; that is normal and is not the MCP server URL.

The provider hosts the approval page. Its single connection permission allows the client to use the MCP tools; your Python app implements no authorization route or permission UI. Client tool-call confirmations still apply.

Reload `/mcp-debug` after the call: it should show a successful forwarding response. A plain `curl` to public `/mcp` without a token should return **401**; that is the expected access check. This MCP-only example has no app page at `/`; a 404 there is expected.

## Keep running, stop or reconnect

Access tokens last 90 days, and rotating refresh tokens share that same 90-day authorization window. Renewed access tokens are capped at the window’s remaining time; a copied bearer token remains usable until its expiry. Provider keys and OAuth state are in memory, so restarting or rebuilding requires a fresh client login. After a restart, use `codex mcp logout hello-compose` then `codex mcp login hello-compose`, or the equivalent `claude mcp logout` / `claude mcp login` commands.

Restarting only the `mcp` service keeps authorization intact. View startup URLs and errors with:

```sh
docker compose --env-file .env logs -f provider
```

Stop the stack:

```sh
docker compose --env-file .env down
```

If startup fails, check Docker and the provider logs, `.env` and account entitlements. If forwarding fails, check `docker compose --env-file .env logs mcp` and the [connection diagnostics](../README.md#diagnose-a-connection).

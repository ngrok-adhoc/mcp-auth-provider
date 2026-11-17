# Connect a small Python app

This example serves an app at `/` and an HTTP MCP tool at `/mcp` from one Python process. It uses the official MCP SDK's built-in HTTP server; no Flask or provider import is needed.

Requires [uv](https://docs.astral.sh/uv/), Node.js 24+, and the [local provider package](../README.md#run). The provider requires paid ngrok endpoints and Traffic Policy actions.

## Start Python

In a new directory, save this as `server.py`:

```python
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp==2.3.0"]
# ///
from mcp.server import MCPServer
from starlette.requests import Request
from starlette.responses import HTMLResponse

mcp = MCPServer("Hello Python")


@mcp.tool()
async def hello() -> str:
    """Return a greeting from Python."""
    return "Hello from Python!"


@mcp.custom_route("/", methods=["GET"])
async def homepage(request: Request) -> HTMLResponse:
    return HTMLResponse("<h1>My Python app</h1><p>Connect your MCP client at /mcp.</p>")


if __name__ == "__main__":
    mcp.run("streamable-http", host="127.0.0.1", port=8000,
            stateless_http=True, json_response=True)
```

Run it and leave the terminal open:

```sh
uv run --python 3.13 server.py
```

Open `http://127.0.0.1:8000/` to check the app. Keep this listener bound to loopback; the provider exposes its public routes.

## Start the provider

In the same directory, create an ignored `.env`:

```dotenv
NGROK_AUTHTOKEN=your_ngrok_agent_authtoken
OWNER_EMAIL=you@example.com
APP_URL=http://127.0.0.1:8000
MCP_URL=http://127.0.0.1:8000/mcp
```

In a second terminal, from that directory, run:

```sh
npx --yes --package=/absolute/path/to/mcp-oauth-provider-0.1.0.tgz mcp-oauth-provider
```

The provider prints the public app, MCP and debug URLs and opens `/mcp-debug`. Sign in as `OWNER_EMAIL`. An HTTP response from the MCP health check only proves reachability; the next step verifies the protocol.

## Call the tool

1. Open the printed app URL. It shows **My Python app**.
2. Add the printed `/mcp` URL to an OAuth-capable MCP client.
3. Sign in with the configured Google account and approve access.
4. Ask the client to call `hello`. Expect **Hello from Python!**.
5. Reload `/mcp-debug` to see the forwarding status. Use [connection diagnostics](../README.md#diagnose-a-connection) if it fails.

Python contains no OAuth code. The separate provider and ngrok Traffic Policy handle authorization. Stop each terminal with Ctrl+C. Tokens expire after five minutes, and restarting the provider requires client reauthorization.

For an existing app, keep its server code and normal start command; set `APP_URL` and `MCP_URL` to its listeners. See [one-command startup](../README.md#start-alongside-python-or-node) to start both processes together.

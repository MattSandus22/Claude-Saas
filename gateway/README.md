# MCPGuard Gateway — inline enforcement sidecar

A transparent stdio proxy that wraps a real MCP server and enforces MCPGuard
policy **in band**. Unlike passive monitoring (reporting copies of messages
after the fact), the gateway can **block a tool call before it executes**.

```
 client ──stdin──▶  [ mcpguard-gateway ]  ──stdin──▶  real MCP server
 client ◀─stdout──  [ mcpguard-gateway ]  ◀─stdout──  real MCP server
                          │
                          ├─ tools/call  → POST /api/v1/inspect  (block if denied)
                          └─ tools/list  → POST /api/v1/servers  (drift detection)
```

## What it does

- **Blocks denied `tools/call` requests.** Every tool call is sent to
  `/api/v1/inspect`. If MCPGuard blocks it (policy deny or a critical threat
  score), the gateway returns a JSON-RPC error to the client and never forwards
  the call to the server.
- **Feeds drift detection.** Tool definitions advertised in `tools/list`
  responses are reported to `/api/v1/servers`, which fingerprints them and
  raises an R9 alert if a definition changed since approval (rug-pull defense).
- **Fails closed by default.** If the MCPGuard control plane is unreachable,
  tool calls are blocked (set `MCPGUARD_FAIL_OPEN=true` to invert this). An
  unmonitored tool call is exactly what the sidecar exists to prevent.

## Requirements

Python 3.11+ standard library only — **no dependencies**, so it can run
anywhere the MCP server runs (it just needs to launch that server).

## Configuration (environment variables)

| Var | Required | Default | Purpose |
|---|---|---|---|
| `MCPGUARD_URL` | – | `http://localhost:8000/api/v1` | MCPGuard API base |
| `MCPGUARD_API_KEY` | yes | – | Ingest-scoped key (`mcpg_…`) from the API Keys page |
| `MCPGUARD_SERVER_NAME` | – | `gateway-server` | Logical server name in MCPGuard |
| `MCPGUARD_SERVER_ENDPOINT` | – | `stdio:<name>` | Stable endpoint id used for dedupe/drift |
| `MCPGUARD_AGENT_ID` | – | `gateway` | Agent id attributed to calls |
| `MCPGUARD_FAIL_OPEN` | – | `false` | Allow calls when MCPGuard is unreachable |
| `MCPGUARD_TIMEOUT` | – | `5` | Per-request timeout (seconds) |

Secrets are read from the environment only — never pass the API key on the
command line (argv is world-readable via `/proc`).

## Usage

Everything after `--` is the real MCP server command:

```bash
MCPGUARD_URL=https://mcpguard.internal/api/v1 \
MCPGUARD_API_KEY=mcpg_xxxxxxxx \
MCPGUARD_SERVER_NAME=filesystem \
python mcpguard_gateway.py -- npx -y @modelcontextprotocol/server-filesystem /data
```

### Wiring it into an MCP client

In a client config (e.g. Claude Desktop's `mcpServers`), point the server entry
at the gateway and move the real command after `--`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python",
      "args": ["/opt/mcpguard/gateway/mcpguard_gateway.py", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"],
      "env": {
        "MCPGUARD_URL": "https://mcpguard.internal/api/v1",
        "MCPGUARD_API_KEY": "mcpg_xxxxxxxx",
        "MCPGUARD_SERVER_NAME": "filesystem"
      }
    }
  }
}
```

The client talks to the gateway exactly as it would to the real server; the
gateway is transparent except that denied calls come back as errors.

## HTTP/SSE mode (`mcpguard_http_gateway.py`)

For `url`-style MCP servers, run the reverse-proxy variant instead. It listens on
a local address, forwards to the upstream MCP server URL, and enforces the same
inline block on `tools/call` — plus SSE streaming and deny-safe batch handling
(a JSON-RPC batch containing any blocked call is rejected whole).

```bash
MCPGUARD_URL=https://mcpguard.internal/api/v1 \
MCPGUARD_API_KEY=mcpg_xxxxxxxx \
MCPGUARD_SERVER_NAME=remote-tools \
MCPGUARD_UPSTREAM_URL=https://tools.example.com \
MCPGUARD_LISTEN=127.0.0.1:8899 \
python mcpguard_http_gateway.py
```

Point the MCP client at `http://127.0.0.1:8899` instead of the upstream URL.
Extra env vars: `MCPGUARD_UPSTREAM_URL` (required, the real server), `MCPGUARD_LISTEN`
(default `127.0.0.1:8899`). All the shared vars above (`MCPGUARD_URL`, `_API_KEY`,
`_FAIL_OPEN`, …) apply identically.

## Tests

```bash
python -m pytest -q
```

Covers both modes. Stdio: the enforcement decision (fail-open/closed, block
parsing) and the pump — a denied `tools/call` is answered to the client and never
reaches the server; benign traffic passes; `tools/list` is harvested for drift.
HTTP: single + batch `enforce_jsonrpc`, plus an end-to-end proxy round trip
against a fake upstream (blocked call never reaches upstream, allowed call passes,
`tools/list` harvested).

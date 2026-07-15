#!/usr/bin/env python3
"""MCPGuard stdio gateway — inline MCP enforcement sidecar.

This process sits transparently between an MCP client (e.g. Claude Desktop, an
IDE, a custom agent) and a real stdio MCP server. It launches the real server as
a child process and shuttles JSON-RPC messages both ways, but on the way through
it enforces MCPGuard policy *in band*:

  client ──stdin──▶  [ gateway ]  ──stdin──▶  real MCP server
  client ◀─stdout──  [ gateway ]  ◀─stdout──  real MCP server

Enforcement points:
  * tools/call request  -> POST /api/v1/inspect. If MCPGuard blocks it, the
    call is NEVER forwarded to the server; the client receives a JSON-RPC error
    instead. This is the difference from passive monitoring: the gateway can
    stop a poisoned or policy-violating call before it executes.
  * tools/list response -> the advertised tool definitions are reported to
    POST /api/v1/servers, which runs drift detection (R9). A server that swaps
    a tool definition mid-flight (rug pull) is flagged automatically.

Design decisions:
  * Fail-open vs fail-closed is configurable (MCPGUARD_FAIL_OPEN). Default is
    fail-CLOSED for tools/call: if MCPGuard is unreachable, the call is blocked,
    because an unmonitored tool call is exactly what this sidecar exists to
    prevent. Non-enforced traffic (initialize, ping, resources) always passes so
    a control-plane outage never bricks the data plane for read-only ops.
  * Auth uses an ingest-scoped API key (X-API-Key), never a user token.
  * Config is via environment variables only — no secrets on the command line
    (argv is world-readable via /proc on many systems).

Usage:
  MCPGUARD_URL=https://mcpguard.internal/api/v1 \
  MCPGUARD_API_KEY=mcpg_xxx \
  MCPGUARD_SERVER_NAME=filesystem \
  python mcpguard_gateway.py -- npx -y @modelcontextprotocol/server-filesystem /data

Everything after `--` is the real MCP server command and its args.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from typing import Any

# ---- Configuration (env only) ----------------------------------------------
MCPGUARD_URL = os.environ.get("MCPGUARD_URL", "http://localhost:8000/api/v1").rstrip("/")
API_KEY = os.environ.get("MCPGUARD_API_KEY", "")
SERVER_NAME = os.environ.get("MCPGUARD_SERVER_NAME", "gateway-server")
SERVER_ENDPOINT = os.environ.get("MCPGUARD_SERVER_ENDPOINT", f"stdio:{SERVER_NAME}")
AGENT_ID = os.environ.get("MCPGUARD_AGENT_ID", "gateway")
# Fail-open only if explicitly requested; default fail-closed on tools/call.
FAIL_OPEN = os.environ.get("MCPGUARD_FAIL_OPEN", "false").lower() in ("1", "true", "yes")
HTTP_TIMEOUT = float(os.environ.get("MCPGUARD_TIMEOUT", "5"))

# JSON-RPC error code returned to the client for a blocked call. -32001 is in
# the implementation-defined server-error range.
BLOCKED_ERROR_CODE = -32001


def _log(msg: str) -> None:
    # Gateway logs go to stderr so they never corrupt the stdout JSON-RPC stream.
    print(f"[mcpguard-gateway] {msg}", file=sys.stderr, flush=True)


def _post(path: str, body: dict[str, Any]) -> dict[str, Any] | None:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{MCPGUARD_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def inspect_call(tool_name: str | None, arguments: Any) -> tuple[bool, str]:
    """Return (blocked, reason). Applies fail-open/closed on transport error."""
    try:
        result = _post(
            "/inspect",
            {
                "server_endpoint": SERVER_ENDPOINT,
                "method": "tools/call",
                "tool_name": tool_name,
                "agent_id": AGENT_ID,
                "direction": "request",
                "payload": {"arguments": arguments},
            },
        )
        if result is None:
            raise ValueError("empty response")
        blocked = bool(result.get("blocked"))
        reasons = result.get("reasons") or []
        return blocked, "; ".join(reasons) if reasons else "policy decision"
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        if FAIL_OPEN:
            _log(f"inspect unreachable ({exc}); FAIL-OPEN, allowing call")
            return False, "mcpguard unreachable (fail-open)"
        _log(f"inspect unreachable ({exc}); FAIL-CLOSED, blocking call")
        return True, "MCPGuard control plane unreachable (fail-closed)"


def report_tools(tools: list[dict[str, Any]]) -> None:
    """Report advertised tools to MCPGuard for drift detection. Best-effort."""
    try:
        _post(
            "/servers",
            {
                "name": SERVER_NAME,
                "endpoint": SERVER_ENDPOINT,
                "transport": "stdio",
                "source": "runtime",
                "tools": [
                    {
                        "name": str(t.get("name", "")),
                        "description": str(t.get("description", "")),
                        "input_schema": t.get("inputSchema") or t.get("input_schema") or {},
                    }
                    for t in tools
                    if isinstance(t, dict)
                ],
            },
        )
        _log(f"reported {len(tools)} tool(s) for drift detection")
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        _log(f"tool report failed (non-fatal): {exc}")


def _blocked_response(msg_id: Any, tool_name: str | None, reason: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": BLOCKED_ERROR_CODE,
            "message": "Blocked by MCPGuard policy",
            "data": {"tool": tool_name, "reason": reason},
        },
    }


class Gateway:
    """Bidirectional JSON-RPC pump between client stdio and the server subprocess.

    Streams are injectable so the enforcement logic can be unit-tested without a
    real subprocess: `client_in`/`client_out` default to stdio, `server_in`/
    `server_out` default to the subprocess pipes.
    """

    def __init__(self, proc, *, client_in=None, client_out=None):
        self.proc = proc
        self.client_in = client_in if client_in is not None else sys.stdin
        self.client_out = client_out if client_out is not None else sys.stdout
        self.server_in = proc.stdin
        self.server_out = proc.stdout

    def _write_to_client(self, obj: dict[str, Any]) -> None:
        line = json.dumps(obj)
        self.client_out.write(line + "\n")
        self.client_out.flush()

    def _write_to_server(self, raw: str) -> None:
        self.server_in.write(raw + "\n")
        self.server_in.flush()

    def pump_client_to_server(self) -> None:
        """Read client requests; enforce tools/call; forward the rest."""
        for raw in self.client_in:
            raw = raw.strip()
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                # Not our job to police malformed frames; pass through verbatim.
                self._write_to_server(raw)
                continue

            if isinstance(msg, dict) and msg.get("method") == "tools/call":
                params = msg.get("params") or {}
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                blocked, reason = inspect_call(tool_name, arguments)
                if blocked:
                    _log(f"BLOCKED tools/call '{tool_name}': {reason}")
                    # Respond to the client directly; do not touch the server.
                    self._write_to_client(_blocked_response(msg.get("id"), tool_name, reason))
                    continue

            self._write_to_server(raw)

        # Client closed stdin: close server stdin so it can shut down.
        try:
            self.server_in.close()
        except OSError:
            pass

    def pump_server_to_client(self) -> None:
        """Read server responses; harvest tools/list for drift; forward all."""
        for raw in self.server_out:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                self.client_out.write(raw + "\n")
                self.client_out.flush()
                continue

            # Harvest advertised tools from a tools/list result.
            if isinstance(msg, dict):
                result = msg.get("result")
                if isinstance(result, dict) and isinstance(result.get("tools"), list):
                    # Report on a background thread so we never stall the stream.
                    threading.Thread(
                        target=report_tools, args=(result["tools"],), daemon=True
                    ).start()

            self.client_out.write(raw + "\n")
            self.client_out.flush()


def main() -> int:
    if "--" not in sys.argv:
        _log("usage: mcpguard_gateway.py -- <server-command> [args...]")
        return 2
    server_cmd = sys.argv[sys.argv.index("--") + 1:]
    if not server_cmd:
        _log("no server command provided after --")
        return 2
    if not API_KEY:
        _log("WARNING: MCPGUARD_API_KEY not set; /inspect calls will be rejected")

    import subprocess

    _log(f"launching server: {' '.join(server_cmd)} (fail-open={FAIL_OPEN})")
    proc = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    gw = Gateway(proc)
    # Server->client on a background thread; client->server on the main thread.
    t = threading.Thread(target=gw.pump_server_to_client, daemon=True)
    t.start()
    try:
        gw.pump_client_to_server()
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return proc.returncode or 0


if __name__ == "__main__":
    raise SystemExit(main())

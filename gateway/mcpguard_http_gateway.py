#!/usr/bin/env python3
"""MCPGuard HTTP gateway — reverse proxy for HTTP/SSE MCP servers.

The stdio sidecar (mcpguard_gateway.py) covers `command`-style servers; this
covers `url`-style ones. Point the MCP client at this proxy instead of the real
server URL and it enforces MCPGuard policy on the way through:

  client ──HTTP──▶ [ mcpguard-http-gateway ] ──HTTP──▶ real MCP server (URL)

Enforcement:
  * POST bodies (JSON-RPC): `tools/call` requests are inspected via
    /api/v1/inspect; a denied call is answered with a JSON-RPC error and never
    forwarded. Batch requests containing ANY blocked call are rejected whole
    (deny-safe: partial forwarding could reorder or split side effects).
  * JSON responses containing a `result.tools` list are reported for drift
    detection (R9), same as the stdio gateway.
  * GET requests (SSE streams) are passed through with chunked streaming.

Same security posture as the stdio gateway: env-only config, ingest-scoped API
key, fail-closed by default, stdlib-only (no dependencies).

Usage:
  MCPGUARD_URL=https://mcpguard.internal/api/v1 \
  MCPGUARD_API_KEY=mcpg_xxx \
  MCPGUARD_SERVER_NAME=remote-tools \
  MCPGUARD_UPSTREAM_URL=https://tools.example.com \
  MCPGUARD_LISTEN=127.0.0.1:8899 \
  python mcpguard_http_gateway.py
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urljoin, urlsplit

# Reuse the enforcement core from the stdio gateway (same directory).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcpguard_gateway import (  # noqa: E402
    BLOCKED_ERROR_CODE,
    _blocked_response,
    _log,
    inspect_call,
    report_tools,
)

UPSTREAM_URL = os.environ.get("MCPGUARD_UPSTREAM_URL", "").rstrip("/")
LISTEN = os.environ.get("MCPGUARD_LISTEN", "127.0.0.1:8899")
HTTP_TIMEOUT = float(os.environ.get("MCPGUARD_TIMEOUT", "30"))

# Bound request bodies to stop memory exhaustion through the proxy.
MAX_BODY_BYTES = 10 * 1024 * 1024

# Hop-by-hop headers must not be forwarded (RFC 7230 §6.1).
_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


def enforce_jsonrpc(parsed: Any) -> dict | list | None:
    """Inspect a parsed JSON-RPC body; return error response(s) if blocked.

    Returns None when the body may be forwarded. For a batch (list), if ANY
    element is blocked the whole batch is rejected and errors are returned for
    every blocked element — deny-safe, since forwarding a partial batch could
    execute calls the operator expected to be sequenced with the blocked one.
    """
    if isinstance(parsed, dict):
        if parsed.get("method") == "tools/call":
            params = parsed.get("params") or {}
            blocked, reason = inspect_call(params.get("name"), params.get("arguments", {}))
            if blocked:
                _log(f"BLOCKED tools/call '{params.get('name')}': {reason}")
                return _blocked_response(parsed.get("id"), params.get("name"), reason)
        return None

    if isinstance(parsed, list):
        errors = []
        for item in parsed:
            if isinstance(item, dict) and item.get("method") == "tools/call":
                params = item.get("params") or {}
                blocked, reason = inspect_call(
                    params.get("name"), params.get("arguments", {})
                )
                if blocked:
                    _log(f"BLOCKED (batch) tools/call '{params.get('name')}': {reason}")
                    errors.append(
                        _blocked_response(item.get("id"), params.get("name"), reason)
                    )
        return errors if errors else None

    return None


def harvest_tools_from_response(body: bytes) -> None:
    """Report advertised tools from a tools/list JSON response (best-effort)."""
    try:
        msg = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    result = msg.get("result") if isinstance(msg, dict) else None
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        threading.Thread(target=report_tools, args=(result["tools"],), daemon=True).start()


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MCPGuardGateway/1.0"

    def log_message(self, fmt, *args):  # route access logs to stderr via _log
        _log(fmt % args)

    def _forward_headers(self) -> dict[str, str]:
        headers = {}
        for k, v in self.headers.items():
            if k.lower() not in _HOP_HEADERS:
                headers[k] = v
        return headers

    def _respond_json(self, obj: Any, status: int = 200) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _upstream(self, method: str, body: bytes | None) -> None:
        """Forward the request to the upstream MCP server and relay the reply."""
        url = urljoin(UPSTREAM_URL + "/", self.path.lstrip("/"))
        req = urllib.request.Request(
            url, data=body, headers=self._forward_headers(), method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                content_type = resp.headers.get("Content-Type", "application/json")
                is_stream = "text/event-stream" in content_type
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in _HOP_HEADERS:
                        self.send_header(k, v)
                if is_stream:
                    # SSE: stream chunks through without buffering.
                    self.end_headers()
                    while True:
                        chunk = resp.read(4096)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                else:
                    data = resp.read()
                    if "Content-Length" not in resp.headers:
                        self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    harvest_tools_from_response(data)
        except urllib.error.HTTPError as exc:
            data = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            _log(f"upstream error: {exc}")
            self._respond_json(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32002, "message": "Upstream MCP server unreachable"}},
                status=502,
            )

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            self._respond_json(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32003, "message": "Request body too large"}},
                status=413,
            )
            return
        body = self.rfile.read(length) if length else b""

        try:
            parsed = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = None  # not JSON-RPC; forward as-is (enforcement N/A)

        if parsed is not None:
            error = enforce_jsonrpc(parsed)
            if error is not None:
                self._respond_json(error)
                return

        self._upstream("POST", body)

    def do_GET(self):
        self._upstream("GET", None)

    def do_DELETE(self):
        # Streamable HTTP uses DELETE to end sessions; pass through.
        self._upstream("DELETE", None)


def main() -> int:
    if not UPSTREAM_URL:
        _log("MCPGUARD_UPSTREAM_URL is required")
        return 2
    scheme = urlsplit(UPSTREAM_URL).scheme
    if scheme not in ("http", "https"):
        _log("MCPGUARD_UPSTREAM_URL must be http(s)")
        return 2

    host, _, port = LISTEN.partition(":")
    server = ThreadingHTTPServer((host, int(port or 8899)), ProxyHandler)
    _log(f"listening on {host}:{port or 8899} → upstream {UPSTREAM_URL}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

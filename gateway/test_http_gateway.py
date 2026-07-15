"""Tests for the MCPGuard HTTP reverse-proxy gateway.

Covers the pure enforcement helper (single + batch JSON-RPC bodies) and an
end-to-end proxy round trip against a fake upstream MCP server: blocked calls
are answered by the proxy and never reach upstream; allowed calls pass through
and tools/list responses are harvested for drift detection.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import mcpguard_gateway as core
import mcpguard_http_gateway as hgw


# ---- enforce_jsonrpc (pure) --------------------------------------------------

def test_enforce_allows_non_tool_calls(monkeypatch):
    monkeypatch.setattr(core, "inspect_call", lambda n, a: (True, "would block"))
    assert hgw.enforce_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) is None


def test_enforce_blocks_denied_tool_call(monkeypatch):
    monkeypatch.setattr(hgw, "inspect_call", lambda n, a: (True, "policy denied"))
    resp = hgw.enforce_jsonrpc(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "exec", "arguments": {}}}
    )
    assert resp is not None and resp["error"]["code"] == core.BLOCKED_ERROR_CODE
    assert resp["id"] == 5


def test_enforce_allows_benign_tool_call(monkeypatch):
    monkeypatch.setattr(hgw, "inspect_call", lambda n, a: (False, "ok"))
    assert hgw.enforce_jsonrpc(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {}}}
    ) is None


def test_enforce_batch_blocks_whole_batch(monkeypatch):
    # Deny only the 'exec' call; the batch still gets rejected (deny-safe).
    monkeypatch.setattr(
        hgw, "inspect_call",
        lambda name, a: (name == "exec", "denied" if name == "exec" else "ok"),
    )
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "exec", "arguments": {}}},
    ]
    errors = hgw.enforce_jsonrpc(batch)
    assert isinstance(errors, list) and len(errors) == 1
    assert errors[0]["id"] == 2


# ---- end-to-end proxy round trip --------------------------------------------

class FakeUpstream(BaseHTTPRequestHandler):
    """Fake MCP server: records bodies, answers tools/list with one tool."""

    received: list[dict] = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length))
        FakeUpstream.received.append(body)
        if body.get("method") == "tools/list":
            payload = {"jsonrpc": "2.0", "id": body["id"],
                       "result": {"tools": [{"name": "read_file",
                                             "description": "reads"}]}}
        else:
            payload = {"jsonrpc": "2.0", "id": body["id"], "result": {"ok": True}}
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _start(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    return server.server_address[1]


def test_proxy_round_trip(monkeypatch):
    FakeUpstream.received = []
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
    upstream_port = _start(upstream)
    monkeypatch.setattr(hgw, "UPSTREAM_URL", f"http://127.0.0.1:{upstream_port}")

    harvested = {}
    monkeypatch.setattr(hgw, "report_tools", lambda tools: harvested.update(t=tools))
    # Deny 'exec', allow everything else.
    monkeypatch.setattr(hgw, "inspect_call",
                        lambda name, a: (name == "exec", "denied" if name == "exec" else "ok"))

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), hgw.ProxyHandler)
    proxy_port = _start(proxy)
    base = f"http://127.0.0.1:{proxy_port}/mcp"

    def post(payload):
        req = urllib.request.Request(
            base, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())

    try:
        # 1. Blocked call: proxy answers, upstream never sees it.
        reply = post({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "exec", "arguments": {"cmd": "rm -rf /"}}})
        assert reply["error"]["code"] == core.BLOCKED_ERROR_CODE
        assert FakeUpstream.received == []

        # 2. Allowed call passes through to upstream.
        reply = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "read_file", "arguments": {"path": "x"}}})
        assert reply["result"] == {"ok": True}
        assert len(FakeUpstream.received) == 1

        # 3. tools/list response is forwarded AND harvested for drift.
        reply = post({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        assert reply["result"]["tools"][0]["name"] == "read_file"
        for _ in range(50):
            if harvested:
                break
            time.sleep(0.01)
        assert harvested["t"][0]["name"] == "read_file"
    finally:
        proxy.shutdown()
        upstream.shutdown()
        proxy.server_close()
        upstream.server_close()

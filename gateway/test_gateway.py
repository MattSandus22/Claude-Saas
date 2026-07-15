"""Tests for the MCPGuard stdio gateway sidecar.

Covers the enforcement decision logic (fail-open/closed, block parsing) and the
end-to-end pump behavior: a blocked tools/call must be answered to the client
with a JSON-RPC error and NEVER forwarded to the wrapped server, while benign
traffic passes through untouched.
"""

from __future__ import annotations

import io
import json

import mcpguard_gateway as gw


class _CapturingBuffer(io.StringIO):
    """StringIO that preserves its contents after close() for assertions."""

    def close(self):
        self.captured = self.getvalue()
        super().close()


class FakeProc:
    """Minimal stand-in for a Popen: exposes writable stdin, readable stdout."""

    def __init__(self, server_out: str = ""):
        self.stdin = _CapturingBuffer()
        self.stdout = io.StringIO(server_out)
        self.returncode = 0

    def written_to_server(self) -> str:
        if hasattr(self.stdin, "captured"):
            return self.stdin.captured
        return self.stdin.getvalue()


def test_blocked_response_shape():
    resp = gw._blocked_response(7, "exec", "policy denied")
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 7
    assert resp["error"]["code"] == gw.BLOCKED_ERROR_CODE
    assert resp["error"]["data"]["tool"] == "exec"
    assert "policy denied" in resp["error"]["data"]["reason"]


def test_inspect_call_parses_block(monkeypatch):
    monkeypatch.setattr(
        gw, "_post",
        lambda path, body: {"blocked": True, "reasons": ["tool 'exec' is denied"]},
    )
    blocked, reason = gw.inspect_call("exec", {"cmd": "rm -rf /"})
    assert blocked is True
    assert "denied" in reason


def test_inspect_call_allows_benign(monkeypatch):
    monkeypatch.setattr(gw, "_post", lambda path, body: {"blocked": False, "reasons": []})
    blocked, _ = gw.inspect_call("read_file", {"path": "notes.txt"})
    assert blocked is False


def test_inspect_call_fail_closed_on_error(monkeypatch):
    def boom(path, body):
        raise OSError("connection refused")

    monkeypatch.setattr(gw, "_post", boom)
    monkeypatch.setattr(gw, "FAIL_OPEN", False)
    blocked, reason = gw.inspect_call("exec", {})
    assert blocked is True
    assert "fail-closed" in reason


def test_inspect_call_fail_open_when_configured(monkeypatch):
    def boom(path, body):
        raise OSError("connection refused")

    monkeypatch.setattr(gw, "_post", boom)
    monkeypatch.setattr(gw, "FAIL_OPEN", True)
    blocked, reason = gw.inspect_call("exec", {})
    assert blocked is False
    assert "fail-open" in reason


def test_pump_blocks_denied_tool_call(monkeypatch):
    """A denied tools/call is answered to the client and not sent to the server."""
    monkeypatch.setattr(gw, "inspect_call", lambda name, args: (True, "blocked by policy"))

    proc = FakeProc()
    client_in = io.StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "exec", "arguments": {"cmd": "rm -rf /"}}}) + "\n"
    )
    client_out = io.StringIO()
    g = gw.Gateway(proc, client_in=client_in, client_out=client_out)
    g.pump_client_to_server()

    # Nothing forwarded to the server.
    assert proc.written_to_server() == ""
    # Client got a JSON-RPC error for the right id.
    reply = json.loads(client_out.getvalue().strip())
    assert reply["id"] == 1
    assert reply["error"]["code"] == gw.BLOCKED_ERROR_CODE


def test_pump_forwards_allowed_traffic(monkeypatch):
    monkeypatch.setattr(gw, "inspect_call", lambda name, args: (False, "ok"))

    proc = FakeProc()
    # A benign tools/call plus a non-enforced initialize both forward.
    frames = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {"path": "notes.txt"}}},
    ]
    client_in = io.StringIO("\n".join(json.dumps(f) for f in frames) + "\n")
    g = gw.Gateway(proc, client_in=client_in, client_out=io.StringIO())
    g.pump_client_to_server()

    forwarded = [json.loads(l) for l in proc.written_to_server().splitlines() if l.strip()]
    assert len(forwarded) == 2
    assert {f["id"] for f in forwarded} == {1, 2}


def test_pump_server_harvests_tools(monkeypatch):
    reported = {}

    def fake_report(tools):
        reported["tools"] = tools

    monkeypatch.setattr(gw, "report_tools", fake_report)

    tools_list = {
        "jsonrpc": "2.0", "id": 3,
        "result": {"tools": [{"name": "read_file", "description": "reads a file"}]},
    }
    proc = FakeProc(server_out=json.dumps(tools_list) + "\n")
    client_out = io.StringIO()
    g = gw.Gateway(proc, client_in=io.StringIO(), client_out=client_out)
    g.pump_server_to_client()

    # Response is still forwarded verbatim to the client...
    assert json.loads(client_out.getvalue().strip())["id"] == 3
    # ...and the tool list was harvested for drift detection (thread joined below).
    import time
    for _ in range(50):
        if "tools" in reported:
            break
        time.sleep(0.01)
    assert reported.get("tools") == [{"name": "read_file", "description": "reads a file"}]

"""PagerDuty + CEF/SIEM alert formats (Phase 16) tests.

Pure builders (PagerDuty Events API v2, ArcSight CEF) plus format selection and
the notify_alerts send shape captured against a stub httpx client — no live
PagerDuty/SIEM needed.
"""

from __future__ import annotations

import pytest

from app.services import notify as notify_mod
from app.services.notify import (
    build_cef_payload,
    build_pagerduty_payload,
    _select_format,
)


def _p(rule_id, title, severity, description="d", server_id=None, created_at=None):
    return {"id": "x", "rule_id": rule_id, "title": title, "severity": severity,
            "description": description, "server_id": server_id, "created_at": created_at}


# ---- PagerDuty ----
def test_pagerduty_event_shape():
    payloads = [_p("R2", "Injection", "high"), _p("R4", "Destructive", "critical")]
    ev = build_pagerduty_payload(payloads, "RK-123")
    assert ev["routing_key"] == "RK-123"
    assert ev["event_action"] == "trigger"
    # Worst severity (critical) maps to PagerDuty 'critical'.
    assert ev["payload"]["severity"] == "critical"
    assert ev["payload"]["source"] == "mcpguard"
    assert ev["payload"]["custom_details"]["alert_count"] == 2
    assert ev["dedup_key"].startswith("mcpguard-critical-")


def test_pagerduty_severity_mapping():
    assert build_pagerduty_payload([_p("R", "t", "high")], "k")["payload"]["severity"] == "error"
    assert build_pagerduty_payload([_p("R", "t", "medium")], "k")["payload"]["severity"] == "warning"
    assert build_pagerduty_payload([_p("R", "t", "low")], "k")["payload"]["severity"] == "info"


# ---- CEF ----
def test_cef_line_shape_and_severity_scale():
    line = build_cef_payload([_p("R4", "Destructive op", "critical",
                                 description="rm -rf", server_id="srv1")])
    assert line.startswith("CEF:0|MCPGuard|MCPGuard|1.0|R4|Destructive op|10|")
    assert "cs1Label=ruleId cs1=R4" in line
    assert "cs3Label=serverId cs3=srv1" in line
    assert "msg=rm -rf" in line


def test_cef_escapes_header_pipe_and_extension_specials():
    # A pipe in the title must be escaped in the CEF header; '=' and newlines in
    # the extension value must be neutralized.
    line = build_cef_payload([_p("R2", "a|b", "high", description="x=y\nz")])
    header = line.split("|7|")[0]
    assert "a\\|b" in header  # header pipe escaped
    ext = line.split("|7|")[1]
    assert "x\\=y" in ext  # extension '=' escaped
    assert "\n" not in ext  # newline flattened


def test_cef_one_line_per_alert():
    lines = build_cef_payload([_p("R1", "t1", "low"), _p("R2", "t2", "high")])
    assert len(lines.splitlines()) == 2


# ---- selection ----
def test_auto_detects_pagerduty(monkeypatch):
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "auto")
    assert _select_format("https://events.pagerduty.com/v2/enqueue") == "pagerduty"


def test_cef_requires_explicit_selection(monkeypatch):
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "auto")
    # No host auto-detects to CEF; it must be chosen explicitly.
    assert _select_format("https://siem.example.com/http") == "generic"
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "cef")
    assert _select_format("https://siem.example.com/http") == "cef"


# ---- send shape ----
class _Alert:
    def __init__(self, severity="critical"):
        self.id = "a1"
        self.rule_id = "R4"
        self.title = "Destructive op"
        self.severity = severity
        self.description = "rm -rf /"
        self.server_id = None
        self.created_at = None


def _stub_client(sent: dict):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, content=None, headers=None):
            sent["url"] = url
            sent["json"] = json
            sent["content"] = content
            sent["headers"] = headers

    return _Client


@pytest.mark.asyncio
async def test_notify_sends_pagerduty_event(monkeypatch):
    sent = {}
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_URL",
                        "https://events.pagerduty.com/v2/enqueue")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "auto")
    monkeypatch.setattr(notify_mod.settings, "PAGERDUTY_ROUTING_KEY", "RK-xyz")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_MIN_SEVERITY", "high")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_ALLOW_PRIVATE", True)
    monkeypatch.setattr(notify_mod.httpx, "AsyncClient", _stub_client(sent))

    n = await notify_mod.notify_alerts([_Alert("critical")])
    assert n == 1
    assert sent["json"]["event_action"] == "trigger"
    assert sent["json"]["routing_key"] == "RK-xyz"


@pytest.mark.asyncio
async def test_notify_pagerduty_without_key_does_not_send(monkeypatch):
    sent = {}
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_URL",
                        "https://events.pagerduty.com/v2/enqueue")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "pagerduty")
    monkeypatch.setattr(notify_mod.settings, "PAGERDUTY_ROUTING_KEY", None)
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_MIN_SEVERITY", "high")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_ALLOW_PRIVATE", True)
    monkeypatch.setattr(notify_mod.httpx, "AsyncClient", _stub_client(sent))

    n = await notify_mod.notify_alerts([_Alert("critical")])
    assert n == 0  # refused for lack of routing key
    assert sent == {}


@pytest.mark.asyncio
async def test_notify_sends_cef_as_text(monkeypatch):
    sent = {}
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_URL",
                        "https://siem.example.com/http")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "cef")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_MIN_SEVERITY", "high")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_ALLOW_PRIVATE", True)
    monkeypatch.setattr(notify_mod.httpx, "AsyncClient", _stub_client(sent))

    n = await notify_mod.notify_alerts([_Alert("critical")])
    assert n == 1
    # Sent as text/plain CEF, not JSON.
    assert sent["json"] is None
    assert sent["content"].startswith("CEF:0|MCPGuard")
    assert sent["headers"]["Content-Type"] == "text/plain"

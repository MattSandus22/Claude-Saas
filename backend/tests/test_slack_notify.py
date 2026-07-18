"""Slack-format alert routing (Phase 15) tests.

Covers the pure Slack Block Kit builder, format auto-detection/override, and
that notify_alerts sends the Slack shape to a Slack URL — verified by capturing
the outbound request against a stub httpx client (no live Slack needed).
"""

from __future__ import annotations

import pytest

from app.services import notify as notify_mod
from app.services.notify import build_slack_payload, _select_format


def _p(rule_id, title, severity, description="d"):
    return {"id": "x", "rule_id": rule_id, "title": title, "severity": severity,
            "description": description, "server_id": None, "created_at": None}


def test_slack_payload_shape_and_worst_severity():
    payloads = [_p("R2", "Injection", "high"), _p("R4", "Destructive", "critical")]
    msg = build_slack_payload(payloads)
    # Fallback text + a color bar keyed to the worst severity (critical -> red).
    assert "2 alert(s)" in msg["text"]
    assert msg["attachments"][0]["color"] == "#d03b3b"
    blocks = msg["attachments"][0]["blocks"]
    assert blocks[0]["type"] == "header"
    assert "CRITICAL" in blocks[0]["text"]["text"]
    # Each alert contributes a section; both rule ids appear.
    rendered = str(blocks)
    assert "R2" in rendered and "R4" in rendered


def test_slack_payload_truncates_and_summarizes():
    payloads = [_p(f"R{i}", f"t{i}", "medium") for i in range(15)]
    msg = build_slack_payload(payloads)
    rendered = str(msg["attachments"][0]["blocks"])
    # Only 10 shown, with a "…and 5 more" summary.
    assert "and 5 more" in rendered


def test_single_alert_singular_wording():
    msg = build_slack_payload([_p("R9", "Drift", "high")])
    assert "1 alerts" not in msg["attachments"][0]["blocks"][0]["text"]["text"]
    assert "1 alert" in msg["attachments"][0]["blocks"][0]["text"]["text"]


def test_format_auto_detects_slack_host(monkeypatch):
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "auto")
    assert _select_format("https://hooks.slack.com/services/T/B/x") == "slack"
    assert _select_format("https://example.com/webhook") == "generic"


def test_format_override_wins(monkeypatch):
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "generic")
    # Even a slack.com URL is sent generic when explicitly overridden.
    assert _select_format("https://hooks.slack.com/services/x") == "generic"
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "slack")
    assert _select_format("https://example.com/x") == "slack"


class _Alert:
    def __init__(self, severity):
        self.id = "a1"
        self.rule_id = "R4"
        self.title = "Destructive op"
        self.severity = severity
        self.description = "rm -rf /"
        self.server_id = None
        self.created_at = None


@pytest.mark.asyncio
async def test_notify_sends_slack_shape(monkeypatch):
    """With a Slack URL configured, notify_alerts POSTs the Slack Block Kit body."""
    sent = {}

    class _Resp:
        pass

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            sent["url"] = url
            sent["json"] = json
            return _Resp()

    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_URL",
                        "https://hooks.slack.com/services/T/B/x")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "auto")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_MIN_SEVERITY", "high")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_ALLOW_PRIVATE", True)
    monkeypatch.setattr(notify_mod.httpx, "AsyncClient", _Client)

    n = await notify_mod.notify_alerts([_Alert("critical")])
    assert n == 1
    # Slack shape: has attachments with blocks, not the generic {source, alerts}.
    assert "attachments" in sent["json"]
    assert "alerts" not in sent["json"]
    assert sent["json"]["attachments"][0]["color"] == "#d03b3b"


@pytest.mark.asyncio
async def test_notify_sends_generic_shape_to_plain_url(monkeypatch):
    sent = {}

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            sent["json"] = json

    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_URL",
                        "https://alerts.example.com/hook")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_FORMAT", "auto")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_MIN_SEVERITY", "high")
    monkeypatch.setattr(notify_mod.settings, "ALERT_WEBHOOK_ALLOW_PRIVATE", True)
    monkeypatch.setattr(notify_mod.httpx, "AsyncClient", _Client)

    await notify_mod.notify_alerts([_Alert("high")])
    # Generic shape.
    assert sent["json"]["source"] == "mcpguard"
    assert "alerts" in sent["json"]

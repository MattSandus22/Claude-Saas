"""Prometheus /metrics exposition (Phase 18) tests.

Unit tests cover the pure text-exposition formatter (HELP/TYPE lines, labels,
integer rendering, escaping). Integration tests cover the endpoint's security
gate: 404 when the token is unset (disabled), 401 without/with a wrong bearer,
and a valid scrape returning the exposition with live counts.
"""

from __future__ import annotations

import pytest

from app.services import prometheus as prom
from app.services.prometheus import render_exposition


def test_render_help_type_and_samples():
    out = render_exposition([
        {"name": "m_gauge", "type": "gauge", "help": "a gauge",
         "samples": [({"status": "active"}, 3), (None, 5)]},
    ])
    assert "# HELP m_gauge a gauge" in out
    assert "# TYPE m_gauge gauge" in out
    assert 'm_gauge{status="active"} 3' in out
    assert "m_gauge 5" in out


def test_integer_values_render_without_dot():
    out = render_exposition([
        {"name": "c", "type": "counter", "help": "c", "samples": [(None, 42.0)]},
    ])
    assert "c 42" in out
    assert "42.0" not in out


def test_label_escaping():
    out = render_exposition([
        {"name": "m", "type": "gauge", "help": "h",
         "samples": [({"k": 'a"b\\c'}, 1)]},
    ])
    # Double-quote and backslash escaped in the label value.
    assert 'k="a\\"b\\\\c"' in out


@pytest.mark.asyncio
async def test_metrics_disabled_returns_404(client, auth_headers, monkeypatch):
    monkeypatch.setattr(prom_settings(), "PROMETHEUS_BEARER_TOKEN", None)
    resp = await client.get("/metrics")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_metrics_requires_bearer(client, monkeypatch):
    monkeypatch.setattr(prom_settings(), "PROMETHEUS_BEARER_TOKEN", "scrape-secret")
    # No auth header -> 401.
    resp = await client.get("/metrics")
    assert resp.status_code == 401
    # Wrong token -> 401.
    resp = await client.get("/metrics", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_metrics_scrape_returns_exposition(client, auth_headers, monkeypatch):
    monkeypatch.setattr(prom_settings(), "PROMETHEUS_BEARER_TOKEN", "scrape-secret")
    # Generate some data: a destructive message -> event + alerts + incident.
    await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "exec", "agent_id": "prom-agent",
              "payload": {"cmd": "rm -rf /"}},
        headers=auth_headers,
    )
    resp = await client.get("/metrics", headers={"Authorization": "Bearer scrape-secret"})
    assert resp.status_code == 200
    body = resp.text
    assert "# TYPE mcpguard_events_total counter" in body
    assert "mcpguard_events_total" in body
    assert "mcpguard_alerts" in body
    assert "mcpguard_incidents_open" in body
    assert "mcpguard_sla_breaches" in body
    # Prometheus exposition content type.
    assert "text/plain" in resp.headers["content-type"]


def prom_settings():
    """The settings object referenced by the /metrics endpoint (app.core.config)."""
    from app.core import config
    return config.settings

"""Incident assignments + SLAs (Phase 13) tests.

Unit tests cover the pure SLA computation (target by severity, on-track vs
due-soon vs breached, met on ack). Integration tests cover assignment, that
acknowledging stops the SLA clock, and that breaches surface in metrics.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.models import Incident, Severity
from app.services.sla import sla_status, sla_target_seconds


def _incident(severity, first_seen, acknowledged_at=None) -> Incident:
    return Incident(group_key="k", title="t", severity=severity,
                    first_seen=first_seen, last_seen=first_seen,
                    acknowledged_at=acknowledged_at)


def test_targets_scale_with_severity():
    assert sla_target_seconds(Severity.critical) == settings.SLA_CRITICAL_SECONDS
    assert sla_target_seconds(Severity.low) == settings.SLA_LOW_SECONDS
    assert sla_target_seconds(Severity.critical) < sla_target_seconds(Severity.low)


def test_open_within_target_on_track():
    now = datetime.now(timezone.utc)
    inc = _incident(Severity.high, now - timedelta(seconds=60))
    s = sla_status(inc, now=now)
    assert s["status"] == "on_track"
    assert s["breached"] is False


def test_open_near_target_due_soon():
    now = datetime.now(timezone.utc)
    # 80% of the 1h high target elapsed -> due_soon (>= 75%).
    inc = _incident(Severity.high, now - timedelta(seconds=int(3600 * 0.8)))
    assert sla_status(inc, now=now)["status"] == "due_soon"


def test_open_past_target_breached():
    now = datetime.now(timezone.utc)
    inc = _incident(Severity.critical, now - timedelta(seconds=settings.SLA_CRITICAL_SECONDS + 60))
    s = sla_status(inc, now=now)
    assert s["status"] == "breached" and s["breached"] is True


def test_acknowledged_in_time_is_met():
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=1000)
    inc = _incident(Severity.high, start, acknowledged_at=start + timedelta(seconds=120))
    s = sla_status(inc, now=now)
    assert s["status"] == "met" and s["acknowledged"] is True


def test_acknowledged_late_is_breached():
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=5)
    # Acknowledged 2h after open, but high target is 1h -> breached.
    inc = _incident(Severity.high, start, acknowledged_at=start + timedelta(hours=2))
    assert sla_status(inc, now=now)["status"] == "breached"


async def _make_incident(client, auth_headers, agent: str) -> dict:
    await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "exec", "agent_id": agent,
              "payload": {"cmd": "rm -rf /"}},
        headers=auth_headers,
    )
    return next(i for i in (await client.get("/api/v1/incidents", headers=auth_headers)).json()
                if i["agent_id"] == agent)


@pytest.mark.asyncio
async def test_incident_list_carries_sla(client, auth_headers):
    inc = await _make_incident(client, auth_headers, "sla-agent")
    assert inc["sla"] is not None
    assert inc["sla"]["status"] in ("on_track", "due_soon", "breached")
    assert inc["sla"]["acknowledged"] is False


@pytest.mark.asyncio
async def test_assign_and_unassign(client, auth_headers):
    inc = await _make_incident(client, auth_headers, "assign-agent")
    # Assign to the admin (seeded user).
    resp = await client.post(f"/api/v1/incidents/{inc['id']}/assign",
                             json={"assignee_email": "admin@test.local"},
                             headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["assignee_id"] is not None

    # Unassign.
    resp = await client.post(f"/api/v1/incidents/{inc['id']}/assign",
                             json={"assignee_email": None}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["assignee_id"] is None


@pytest.mark.asyncio
async def test_assign_unknown_user_404(client, auth_headers):
    inc = await _make_incident(client, auth_headers, "assign-404-agent")
    resp = await client.post(f"/api/v1/incidents/{inc['id']}/assign",
                             json={"assignee_email": "nobody@test.local"},
                             headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_ack_stops_sla_clock(client, auth_headers):
    inc = await _make_incident(client, auth_headers, "ack-agent")
    # Acknowledge -> SLA becomes 'met' (acknowledged well within target).
    await client.patch(f"/api/v1/incidents/{inc['id']}",
                       json={"status": "acknowledged"}, headers=auth_headers)
    detail = (await client.get(f"/api/v1/incidents/{inc['id']}",
                               headers=auth_headers)).json()
    assert detail["sla"]["acknowledged"] is True
    assert detail["sla"]["status"] == "met"


@pytest.mark.asyncio
async def test_metrics_include_sla_breaches(client, auth_headers):
    resp = await client.get("/api/v1/incidents/metrics", headers=auth_headers)
    assert resp.status_code == 200
    assert "sla_breaches" in resp.json()
    assert isinstance(resp.json()["sla_breaches"], int)

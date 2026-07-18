"""Incident metrics + timeline (Phase 12) tests.

Unit tests cover the pure MTTR math and timeline merge. Integration tests drive
the endpoints: metrics reflect resolved cases and MTTR, the timeline orders
opening + alerts + triage actions, and /metrics is not captured as an incident id.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models import Alert, AuditLog, Incident, Severity
from app.services.metrics import build_timeline, mean_time_to_resolve


def test_mttr_math():
    now = datetime.now(timezone.utc)
    pairs = [
        (now, now + timedelta(seconds=60)),
        (now, now + timedelta(seconds=120)),
    ]
    assert mean_time_to_resolve(pairs) == 90.0
    assert mean_time_to_resolve([]) is None


def test_build_timeline_orders_events():
    now = datetime.now(timezone.utc)
    inc = Incident(group_key="k", title="case", first_seen=now, last_seen=now,
                   severity=Severity.high)
    alerts = [
        Alert(rule_id="R2", title="injection", severity=Severity.high,
              created_at=now + timedelta(seconds=10), evidence={}),
    ]
    audit = [
        AuditLog(actor="admin@test", action="incident.update",
                 created_at=now + timedelta(seconds=20), detail={}),
    ]
    events = build_timeline(inc, alerts, audit)
    assert [e["kind"] for e in events] == ["opened", "alert", "action"]
    # Timestamps serialized to ISO strings, in order.
    assert events[0]["at"] <= events[1]["at"] <= events[2]["at"]


async def _make_incident(client, auth_headers, agent: str) -> str:
    await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "exec", "agent_id": agent,
              "payload": {"cmd": "rm -rf /"}},
        headers=auth_headers,
    )
    inc = next(i for i in (await client.get("/api/v1/incidents", headers=auth_headers)).json()
               if i["agent_id"] == agent)
    return inc["id"]


@pytest.mark.asyncio
async def test_metrics_reflect_resolution(client, auth_headers):
    inc_id = await _make_incident(client, auth_headers, "metrics-agent")

    before = (await client.get("/api/v1/incidents/metrics", headers=auth_headers)).json()
    assert before["open_incidents"] >= 1

    # Resolve it -> resolved count rises, MTTR becomes a number.
    await client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "resolved"},
                       headers=auth_headers)
    after = (await client.get("/api/v1/incidents/metrics", headers=auth_headers)).json()
    assert after["resolved_incidents"] >= 1
    assert after["mttr_seconds"] is not None
    assert after["mttr_seconds"] >= 0


@pytest.mark.asyncio
async def test_reopen_clears_resolved(client, auth_headers):
    inc_id = await _make_incident(client, auth_headers, "reopen-agent")
    await client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "resolved"},
                       headers=auth_headers)
    # Reopen: the case should count as open again.
    await client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "open"},
                       headers=auth_headers)
    detail = (await client.get(f"/api/v1/incidents/{inc_id}", headers=auth_headers)).json()
    assert detail["status"] == "open"


@pytest.mark.asyncio
async def test_timeline_endpoint(client, auth_headers):
    inc_id = await _make_incident(client, auth_headers, "timeline-agent")
    await client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "acknowledged"},
                       headers=auth_headers)

    tl = (await client.get(f"/api/v1/incidents/{inc_id}/timeline",
                           headers=auth_headers)).json()
    kinds = [e["kind"] for e in tl["events"]]
    assert kinds[0] == "opened"
    assert "alert" in kinds
    assert "action" in kinds  # the acknowledge shows up as an audited action


@pytest.mark.asyncio
async def test_metrics_not_captured_as_id(client, auth_headers):
    # /incidents/metrics must hit the metrics route, not get_incident("metrics").
    resp = await client.get("/api/v1/incidents/metrics", headers=auth_headers)
    assert resp.status_code == 200
    assert "total_incidents" in resp.json()

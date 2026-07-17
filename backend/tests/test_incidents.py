"""Incident case management (Phase 10) tests.

Verifies alerts are grouped into incidents, the severity rolls up to the worst
member, triaging a case cascades to its alerts, and different subjects get
different cases.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db.session import AsyncSessionLocal
from app.models import Alert, AlertStatus, Incident, Severity
from app.services.incidents import attach_alerts_to_incident, group_key


def test_group_key_is_subject_stable():
    assert group_key("s1", "a1") == group_key("s1", "a1")
    assert group_key("s1", "a1") != group_key("s1", "a2")
    assert group_key(None, None) == "srv:none|agt:none"


@pytest.mark.asyncio
async def test_alerts_group_into_one_incident_with_severity_rollup():
    async with AsyncSessionLocal() as db:
        a1 = Alert(rule_id="R2", title="injection", description="d",
                   severity=Severity.high, status=AlertStatus.open, evidence={})
        a2 = Alert(rule_id="R4", title="destructive", description="d",
                   severity=Severity.critical, status=AlertStatus.open, evidence={})
        db.add_all([a1, a2])
        await db.flush()
        incident = await attach_alerts_to_incident(
            db, [a1, a2], server_id="srv-x", agent_id="agent-x")
        await db.commit()
        await db.refresh(incident)

    assert incident.alert_count == 2
    assert incident.severity == Severity.critical  # rolled up to worst
    assert set(incident.rule_ids) == {"R2", "R4"}
    assert a1.incident_id == incident.id and a2.incident_id == incident.id


@pytest.mark.asyncio
async def test_second_message_joins_open_incident():
    async with AsyncSessionLocal() as db:
        a1 = Alert(rule_id="R2", title="t", description="d",
                   severity=Severity.medium, status=AlertStatus.open, evidence={})
        db.add(a1)
        await db.flush()
        inc1 = await attach_alerts_to_incident(
            db, [a1], server_id="srv-join", agent_id="agent-join")
        await db.commit()
        inc1_id = inc1.id

        a2 = Alert(rule_id="R7", title="t2", description="d",
                   severity=Severity.high, status=AlertStatus.open, evidence={})
        db.add(a2)
        await db.flush()
        inc2 = await attach_alerts_to_incident(
            db, [a2], server_id="srv-join", agent_id="agent-join")
        await db.commit()

    # Same subject within window -> same incident, count grows, severity rises.
    assert inc2.id == inc1_id
    assert inc2.alert_count == 2
    assert inc2.severity == Severity.high


@pytest.mark.asyncio
async def test_different_subjects_get_different_incidents():
    async with AsyncSessionLocal() as db:
        a1 = Alert(rule_id="R2", title="t", description="d",
                   severity=Severity.medium, status=AlertStatus.open, evidence={})
        a2 = Alert(rule_id="R2", title="t", description="d",
                   severity=Severity.medium, status=AlertStatus.open, evidence={})
        db.add_all([a1, a2])
        await db.flush()
        inc_a = await attach_alerts_to_incident(db, [a1], server_id="srv-1", agent_id="ag")
        inc_b = await attach_alerts_to_incident(db, [a2], server_id="srv-2", agent_id="ag")
        await db.commit()
    assert inc_a.id != inc_b.id


@pytest.mark.asyncio
async def test_stale_incident_not_joined():
    """An open incident older than the window starts a fresh case."""
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        old = Incident(group_key=group_key("srv-stale", "ag-stale"),
                       title="old", server_id="srv-stale", agent_id="ag-stale",
                       severity=Severity.low, status=AlertStatus.open, alert_count=1,
                       rule_ids=["R2"], first_seen=now - timedelta(hours=48),
                       last_seen=now - timedelta(hours=48))
        db.add(old)
        await db.flush()
        old_id = old.id

        a = Alert(rule_id="R7", title="t", description="d",
                  severity=Severity.high, status=AlertStatus.open, evidence={})
        db.add(a)
        await db.flush()
        fresh = await attach_alerts_to_incident(
            db, [a], server_id="srv-stale", agent_id="ag-stale", now=now)
        await db.commit()
    assert fresh.id != old_id


@pytest.mark.asyncio
async def test_incident_created_and_triaged_via_api(client, auth_headers):
    """End-to-end: a poisoned message creates an incident; resolving it cascades."""
    # A destructive payload -> blocked, raises alerts -> forms an incident.
    resp = await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "exec",
              "agent_id": "inc-e2e-agent", "payload": {"cmd": "rm -rf /"}},
        headers=auth_headers,
    )
    assert resp.status_code == 200

    incidents = (await client.get("/api/v1/incidents", headers=auth_headers)).json()
    mine = [i for i in incidents if i["agent_id"] == "inc-e2e-agent"]
    assert len(mine) == 1
    inc = mine[0]
    assert inc["alert_count"] >= 1
    assert inc["severity"] in ("high", "critical")

    # Detail view returns member alerts, each linked back to the incident.
    detail = (await client.get(f"/api/v1/incidents/{inc['id']}",
                               headers=auth_headers)).json()
    assert len(detail["alerts"]) == inc["alert_count"]
    assert all(a["incident_id"] == inc["id"] for a in detail["alerts"])

    # Resolving the case cascades to its member alerts.
    resp = await client.patch(f"/api/v1/incidents/{inc['id']}",
                              json={"status": "resolved"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"
    assert all(a["status"] == "resolved" for a in resp.json()["alerts"])

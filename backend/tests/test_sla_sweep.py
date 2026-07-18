"""SLA breach sweep (Phase 14) tests.

The sweep turns a passive (read-time) SLA status into a push notification.
Verifies: a breached open case yields one breach alert attached to it and marks
the case notified; a second sweep is idempotent (no duplicate); an acknowledged
case is never swept; the endpoint is admin-only; and the breach alert fires the
notifier (simulation mode).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models import Alert, AlertStatus, Incident, Severity
from app.services.sla_sweep import sweep_sla_breaches


async def _make_breached_incident(agent: str, *, acknowledged: bool = False) -> str:
    """Create an open incident whose first_seen is well past the high SLA target."""
    old = datetime.now(timezone.utc) - timedelta(seconds=settings.SLA_HIGH_SECONDS + 600)
    async with AsyncSessionLocal() as db:
        inc = Incident(
            group_key=f"k-{agent}", title=f"case {agent}", agent_id=agent,
            severity=Severity.high, status=AlertStatus.open,
            first_seen=old, last_seen=old,
            acknowledged_at=old + timedelta(seconds=30) if acknowledged else None,
        )
        db.add(inc)
        await db.commit()
        await db.refresh(inc)
        return inc.id


@pytest.mark.asyncio
async def test_sweep_raises_and_marks_breach():
    inc_id = await _make_breached_incident("sweep-breach")
    async with AsyncSessionLocal() as db:
        created = await sweep_sla_breaches(db)
    ids = [a.incident_id for a in created]
    assert inc_id in ids
    alert = next(a for a in created if a.incident_id == inc_id)
    assert alert.rule_id == "SLA"
    assert alert.severity == Severity.high

    # The case is now flagged so a second sweep does nothing for it.
    async with AsyncSessionLocal() as db:
        again = await sweep_sla_breaches(db)
    assert inc_id not in [a.incident_id for a in again]


@pytest.mark.asyncio
async def test_acknowledged_case_not_swept():
    inc_id = await _make_breached_incident("sweep-acked", acknowledged=True)
    async with AsyncSessionLocal() as db:
        created = await sweep_sla_breaches(db)
    assert inc_id not in [a.incident_id for a in created]


@pytest.mark.asyncio
async def test_sweep_fires_notifier(caplog):
    await _make_breached_incident("sweep-notify")
    async with AsyncSessionLocal() as db:
        with caplog.at_level(logging.WARNING, logger="mcpguard.notify"):
            created = await sweep_sla_breaches(db)
    assert created
    assert any("ALERT-SIMULATION" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_sweep_endpoint_admin_only(client, auth_headers):
    # Analyst is forbidden.
    await client.post(
        "/api/v1/auth/users",
        json={"email": "analyst14@test.local", "password": "AnalystPass123!",
              "role": "analyst"},
        headers=auth_headers,
    )
    login = await client.post(
        "/api/v1/auth/login",
        data={"username": "analyst14@test.local", "password": "AnalystPass123!"},
    )
    analyst = {"Authorization": f"Bearer {login.json()['access_token']}"}
    resp = await client.post("/api/v1/incidents/sweep-sla", headers=analyst)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_sweep_endpoint_returns_breach_ids(client, auth_headers):
    inc_id = await _make_breached_incident("sweep-endpoint")
    resp = await client.post("/api/v1/incidents/sweep-sla", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["newly_breached"] >= 1
    assert inc_id in body["incident_ids"]

    # The breach alert shows up under the incident and in the alert list.
    detail = (await client.get(f"/api/v1/incidents/{inc_id}", headers=auth_headers)).json()
    assert any(a["rule_id"] == "SLA" for a in detail["alerts"])

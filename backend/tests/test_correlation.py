"""Cross-agent correlation (R13) tests — coordinated-campaign detection.

Attack simulation: an attacker spreads activity across many agents so each stays
under every per-agent threshold, while together they swarm one server. Verifies:
- many distinct agents on one server in the window -> R13 fan-in (high);
- multiple distinct *blocked* agents on one server -> R13 coordinated burst (critical);
- a server touched by only a few agents -> not flagged;
- activity keyed on a *different* server does not cross-trigger;
- the campaign alert deduplicates (one per server+subrule per window).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db.session import AsyncSessionLocal
from app.detection.correlation import detect_correlation_anomaly
from app.models import Alert, AlertStatus, MCPEvent, Severity


async def _seed_agents(server_id: str, n_agents: int, *, now: datetime,
                       blocked: bool = False, prefix: str = "agent"):
    """Seed one recent event per distinct agent against a server."""
    async with AsyncSessionLocal() as db:
        for i in range(n_agents):
            db.add(MCPEvent(server_id=server_id, agent_id=f"{prefix}-{i}",
                            method="tools/call", tool_name="t", direction="request",
                            payload={}, blocked=blocked,
                            created_at=now - timedelta(seconds=10)))
        await db.commit()


@pytest.mark.asyncio
async def test_fan_in_surge_raises_r13():
    server = "corr-server-fanin"
    now = datetime.now(timezone.utc)
    await _seed_agents(server, 8, now=now)  # >= CORRELATION_MIN_AGENTS
    async with AsyncSessionLocal() as db:
        findings = await detect_correlation_anomaly(db, server_id=server, now=now)
    fan = [f for f in findings if f.evidence["subrule"] == "fan_in"]
    assert len(fan) == 1
    assert fan[0].rule_id == "R13"
    assert fan[0].severity == "high"
    assert fan[0].evidence["distinct_agents"] == 8


@pytest.mark.asyncio
async def test_coordinated_blocked_burst_critical():
    server = "corr-server-blocked"
    now = datetime.now(timezone.utc)
    # 3 distinct agents all blocked on the same server -> coordinated burst.
    await _seed_agents(server, 3, now=now, blocked=True)
    async with AsyncSessionLocal() as db:
        findings = await detect_correlation_anomaly(db, server_id=server, now=now)
    burst = [f for f in findings if f.evidence["subrule"] == "blocked_burst"]
    assert len(burst) == 1
    assert burst[0].severity == "critical"
    assert burst[0].evidence["blocked_agents"] == 3


@pytest.mark.asyncio
async def test_few_agents_not_flagged():
    server = "corr-server-quiet"
    now = datetime.now(timezone.utc)
    await _seed_agents(server, 3, now=now)  # below fan-in threshold, none blocked
    async with AsyncSessionLocal() as db:
        findings = await detect_correlation_anomaly(db, server_id=server, now=now)
    assert findings == []


@pytest.mark.asyncio
async def test_other_server_does_not_cross_trigger():
    server_a = "corr-server-a"
    server_b = "corr-server-b"
    now = datetime.now(timezone.utc)
    await _seed_agents(server_a, 10, now=now)
    # Querying server_b (which had no activity) must not see server_a's swarm.
    async with AsyncSessionLocal() as db:
        findings = await detect_correlation_anomaly(db, server_id=server_b, now=now)
    assert findings == []


@pytest.mark.asyncio
async def test_campaign_alert_deduplicates():
    server = "corr-server-dedupe"
    now = datetime.now(timezone.utc)
    await _seed_agents(server, 9, now=now)
    async with AsyncSessionLocal() as db:
        first = await detect_correlation_anomaly(db, server_id=server, now=now)
        assert any(f.evidence["subrule"] == "fan_in" for f in first)
        # Persist the alert as the inspector would, then re-run: no duplicate.
        for f in first:
            db.add(Alert(server_id=server, rule_id=f.rule_id, title=f.title,
                         description=f.detail, severity=Severity(f.severity),
                         status=AlertStatus.open, evidence=f.evidence))
        await db.commit()
        second = await detect_correlation_anomaly(db, server_id=server, now=now)
    assert [f for f in second if f.evidence["subrule"] == "fan_in"] == []


@pytest.mark.asyncio
async def test_correlation_end_to_end_via_inspect(client, auth_headers):
    """Register a server, seed a swarm, then one live /inspect raises R13."""
    resp = await client.post(
        "/api/v1/servers",
        json={"name": "corr-e2e", "endpoint": "stdio: corr-e2e",
              "transport": "stdio", "source": "manual", "tools": []},
        headers=auth_headers,
    )
    server_id = resp.json()["id"]
    now = datetime.now(timezone.utc)
    await _seed_agents(server_id, 8, now=now, prefix="e2e-agent")

    resp = await client.post(
        "/api/v1/inspect",
        json={"server_id": server_id, "method": "tools/call", "tool_name": "t",
              "agent_id": "e2e-agent-final", "payload": {}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    alerts = (await client.get("/api/v1/alerts", headers=auth_headers)).json()
    r13 = [a for a in alerts if a["rule_id"] == "R13"
           and a["evidence"].get("server_id") == server_id]
    assert len(r13) >= 1

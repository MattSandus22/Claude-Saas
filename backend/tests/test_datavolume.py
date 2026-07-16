"""Data-volume baseline (R12) tests — per-agent payload-byte anomaly.

Attack simulation: an agent whose call *count* stays flat but whose data volume
spikes (a few large reads) — slow exfiltration. Verifies:
- a byte-volume spike far above the agent's own baseline raises one R12 alert;
- an agent still learning (too few observations) is not flagged;
- a consistently high-volume agent is not flagged (no global threshold);
- a spike below the absolute MIN_BYTES floor is suppressed as noise;
- the combined baseline endpoint returns both R10 and R12 views.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db.session import AsyncSessionLocal
from app.detection.datavolume import compute_data_baseline, detect_data_volume_anomaly
from app.models import MCPEvent


async def _seed_bytes(agent_id: str, bucket_bytes: list[int], *, now: datetime,
                      bucket_seconds: int = 3600):
    """Seed one event per PAST bucket carrying `bucket_bytes[i]` payload bytes."""
    async with AsyncSessionLocal() as db:
        for i, nbytes in enumerate(bucket_bytes):
            base = now - timedelta(seconds=bucket_seconds * (i + 1))
            db.add(MCPEvent(agent_id=agent_id, method="tools/call", tool_name="read",
                            direction="response", payload={}, payload_bytes=nbytes,
                            created_at=base))
        await db.commit()


async def _seed_current(agent_id: str, nbytes: int, *, now: datetime):
    async with AsyncSessionLocal() as db:
        db.add(MCPEvent(agent_id=agent_id, method="tools/call", tool_name="read",
                        direction="response", payload={}, payload_bytes=nbytes,
                        created_at=now))
        await db.commit()


@pytest.mark.asyncio
async def test_data_spike_raises_r12():
    agent = "dv-spike-agent"
    now = datetime.now(timezone.utc)
    # 6 consistent historical hours ~2 KB each, then a huge current-bucket read.
    await _seed_bytes(agent, [2000, 2100, 1900, 2050, 1950, 2000], now=now)
    await _seed_current(agent, 500_000, now=now)  # 500 KB exfil

    async with AsyncSessionLocal() as db:
        stats = await compute_data_baseline(db, agent, now=now)
        assert stats["observations"] == 6
        assert stats["current_bytes"] == 500_000
        assert stats["zscore"] > 3.0
        findings = await detect_data_volume_anomaly(db, agent_id=agent, now=now)
    assert len(findings) == 1
    assert findings[0].rule_id == "R12"
    assert findings[0].severity == "high"
    assert findings[0].evidence["current_bytes"] == 500_000


@pytest.mark.asyncio
async def test_learning_window_not_flagged():
    agent = "dv-new-agent"
    now = datetime.now(timezone.utc)
    await _seed_bytes(agent, [2000, 2100], now=now)  # < MIN_OBSERVATIONS
    await _seed_current(agent, 999_999, now=now)
    async with AsyncSessionLocal() as db:
        findings = await detect_data_volume_anomaly(db, agent_id=agent, now=now)
    assert findings == []


@pytest.mark.asyncio
async def test_consistent_high_volume_not_flagged():
    agent = "dv-steady-agent"
    now = datetime.now(timezone.utc)
    # Consistently ~1 MB/hr; current bucket also ~1 MB -> not anomalous.
    await _seed_bytes(agent, [1_000_000, 980_000, 1_020_000, 1_010_000,
                              990_000, 1_000_000], now=now)
    await _seed_current(agent, 1_000_000, now=now)
    async with AsyncSessionLocal() as db:
        findings = await detect_data_volume_anomaly(db, agent_id=agent, now=now)
    assert findings == []


@pytest.mark.asyncio
async def test_tiny_volume_spike_suppressed():
    agent = "dv-tiny-agent"
    now = datetime.now(timezone.utc)
    # Baseline of a few bytes; a jump to 500 bytes is a huge z-score but below the
    # MIN_BYTES floor (10_000), so R12 stays quiet (noise suppression).
    await _seed_bytes(agent, [10, 12, 9, 11, 10, 10], now=now)
    await _seed_current(agent, 500, now=now)
    async with AsyncSessionLocal() as db:
        stats = await compute_data_baseline(db, agent, now=now)
        assert stats["zscore"] > 3.0  # statistically a spike...
        findings = await detect_data_volume_anomaly(db, agent_id=agent, now=now)
    assert findings == []  # ...but below the absolute floor, so not flagged


@pytest.mark.asyncio
async def test_combined_baseline_endpoint(client, auth_headers):
    resp = await client.get("/api/v1/agents/dv-endpoint-agent/baseline",
                            headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    # R10 view at the top level, R12 view nested under data_volume.
    assert body["agent_id"] == "dv-endpoint-agent"
    assert "current_count" in body
    assert body["data_volume"]["agent_id"] == "dv-endpoint-agent"
    assert "current_bytes" in body["data_volume"]
    assert body["data_volume"]["learning"] is True


@pytest.mark.asyncio
async def test_data_volume_anomaly_end_to_end_via_inspect(client, auth_headers):
    """A large payload through /inspect, after a small-volume baseline, raises R12."""
    agent = "dv-e2e-agent"
    now = datetime.now(timezone.utc)
    await _seed_bytes(agent, [1500, 1600, 1400, 1550, 1450, 1500], now=now)

    # A single benign call carrying a large payload. The sanitizer caps any one
    # string at 50 KB, so the *recorded* volume is ~50 KB — still a massive spike
    # over the ~1.5 KB baseline, and R12 fires on the recorded (post-sanitize) size.
    big = {"data": "x" * 200_000}
    resp = await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "read_file",
              "agent_id": agent, "direction": "response", "payload": big},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    alerts = (await client.get("/api/v1/alerts", headers=auth_headers)).json()
    r12 = [a for a in alerts if a["rule_id"] == "R12"
           and a["evidence"].get("agent_id") == agent]
    assert len(r12) == 1
    assert r12[0]["evidence"]["current_bytes"] >= 40_000  # sanitizer-capped, still a spike

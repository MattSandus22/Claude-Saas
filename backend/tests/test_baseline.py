"""Statistical baseline (R10) tests — per-agent learned volume anomaly.

Unit tests cover the pure stats (mean/stddev/z-score). Integration tests seed an
agent's history directly (controlled timestamps), then drive the detector:
- a spike far above the agent's own baseline raises exactly one R10 alert;
- an agent still in its learning window (too few observations) is never flagged;
- a busy-but-consistent agent is not flagged (no global threshold to trip).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.detection.baseline import (
    compute_agent_baseline,
    detect_statistical_anomaly,
    summarize,
    zscore,
)
from app.db.session import AsyncSessionLocal
from app.models import MCPEvent


def test_summarize_and_zscore():
    mean, stddev = summarize([10, 10, 10, 10])
    assert mean == 10 and stddev == 0.0
    mean, stddev = summarize([2, 4, 6])
    assert mean == 4.0 and round(stddev, 3) == 2.0
    # z-score is undefined with no spread -> 0.0 (never flags a flat baseline).
    assert zscore(100, 10, 0) == 0.0
    assert zscore(20, 10, 5) == 2.0


def test_summarize_empty():
    assert summarize([]) == (0.0, 0.0)


async def _seed_events(agent_id: str, bucket_counts: list[int], *, now: datetime,
                       bucket_seconds: int = 3600):
    """Insert `bucket_counts[i]` events into the i-th PAST bucket for an agent."""
    async with AsyncSessionLocal() as db:
        for i, count in enumerate(bucket_counts):
            # Place each historical bucket i+1 windows before now.
            base = now - timedelta(seconds=bucket_seconds * (i + 1))
            for _ in range(count):
                db.add(MCPEvent(agent_id=agent_id, method="tools/call",
                                tool_name="t", direction="request",
                                payload={}, created_at=base))
        await db.commit()


@pytest.mark.asyncio
async def test_spike_raises_r10():
    agent = "baseline-spike-agent"
    now = datetime.now(timezone.utc)
    # 6 consistent historical hours around ~10 calls, then a current-bucket spike.
    await _seed_events(agent, [10, 11, 9, 10, 12, 8], now=now)
    # Current bucket: many events "now".
    async with AsyncSessionLocal() as db:
        for _ in range(80):
            db.add(MCPEvent(agent_id=agent, method="tools/call", tool_name="t",
                            direction="request", payload={}, created_at=now))
        await db.commit()

    async with AsyncSessionLocal() as db:
        stats = await compute_agent_baseline(db, agent, now=now)
        assert stats["observations"] == 6
        assert stats["current_count"] == 80
        assert stats["zscore"] > 3.0

        findings = await detect_statistical_anomaly(db, agent_id=agent, now=now)
    assert len(findings) == 1
    assert findings[0].rule_id == "R10"
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_learning_window_not_flagged():
    agent = "baseline-new-agent"
    now = datetime.now(timezone.utc)
    # Only 2 historical buckets (< MIN_OBSERVATIONS=5): still learning.
    await _seed_events(agent, [5, 6], now=now)
    async with AsyncSessionLocal() as db:
        for _ in range(200):
            db.add(MCPEvent(agent_id=agent, method="tools/call", tool_name="t",
                            direction="request", payload={}, created_at=now))
        await db.commit()
    async with AsyncSessionLocal() as db:
        findings = await detect_statistical_anomaly(db, agent_id=agent, now=now)
    assert findings == []


@pytest.mark.asyncio
async def test_consistent_busy_agent_not_flagged():
    agent = "baseline-steady-agent"
    now = datetime.now(timezone.utc)
    # Consistently busy history (~100/hr); current bucket also ~100 -> not anomalous.
    await _seed_events(agent, [100, 98, 102, 101, 99, 100], now=now)
    async with AsyncSessionLocal() as db:
        for _ in range(100):
            db.add(MCPEvent(agent_id=agent, method="tools/call", tool_name="t",
                            direction="request", payload={}, created_at=now))
        await db.commit()
    async with AsyncSessionLocal() as db:
        findings = await detect_statistical_anomaly(db, agent_id=agent, now=now)
    assert findings == []


@pytest.mark.asyncio
async def test_baseline_endpoint(client, auth_headers):
    resp = await client.get("/api/v1/agents/some-unseen-agent/baseline",
                            headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_id"] == "some-unseen-agent"
    assert body["observations"] == 0
    assert body["learning"] is True

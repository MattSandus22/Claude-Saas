"""Statistical anomaly detection — rule R10 (per-agent learned baseline).

R6-R8 use fixed thresholds: the same limit for every agent. That misses two
cases — a low-volume agent whose 15 calls/hour is wildly abnormal *for it* stays
under a global cap, while a legitimately busy agent trips the cap every hour and
trains operators to ignore it.

R10 instead learns each agent's *own* normal. It buckets the agent's historical
activity into fixed time windows (default 1 hour), computes the mean and standard
deviation of its per-bucket call volume, and flags the current bucket when it
deviates by more than Z standard deviations above that mean (a z-score). This
catches a novel spike — a runaway loop, a hijacked agent suddenly exfiltrating —
relative to the agent's baseline, with no global threshold to tune.

Design choices:
- We only score once an agent has at least MIN_OBSERVATIONS completed buckets of
  history (learn before you judge), so a brand-new agent is never flagged.
- Only buckets that actually had activity count toward the baseline. Counting the
  idle hours in between would drag the mean toward zero and make every active
  hour look anomalous.
- Everything is computed from the existing MCPEvent table — no extra state to
  keep in sync, and the math (mean/stddev/z-score) is a pure, unit-tested helper.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.detection.anomaly import AnomalyFinding
from app.models import Alert, AlertStatus, MCPEvent


def summarize(counts: list[int]) -> tuple[float, float]:
    """Return (mean, sample_stddev) of a list of per-bucket counts.

    Uses the sample standard deviation (n-1). With fewer than two points the
    stddev is 0 (undefined spread), and the caller guards on MIN_OBSERVATIONS.
    """
    n = len(counts)
    if n == 0:
        return 0.0, 0.0
    mean = sum(counts) / n
    if n < 2:
        return mean, 0.0
    variance = sum((c - mean) ** 2 for c in counts) / (n - 1)
    return mean, math.sqrt(variance)


def zscore(value: float, mean: float, stddev: float) -> float:
    """Standard score. Returns 0.0 when there is no spread to measure against."""
    if stddev <= 0:
        return 0.0
    return (value - mean) / stddev


def _bucket_index(dt: datetime, bucket_seconds: int) -> int:
    return int(dt.timestamp()) // bucket_seconds


async def _recent_r10_exists(
    db: AsyncSession, agent_id: str, within_seconds: int
) -> bool:
    """Dedup: has an R10 alert already fired for this agent in the current bucket?"""
    since = datetime.now(timezone.utc).timestamp() - within_seconds
    stmt = select(Alert.evidence, Alert.created_at).where(
        Alert.rule_id == "R10", Alert.status == AlertStatus.open
    )
    for evidence, created_at in (await db.execute(stmt)).all():
        if created_at.timestamp() < since:
            continue
        if (evidence or {}).get("agent_id") == agent_id:
            return True
    return False


async def compute_agent_baseline(
    db: AsyncSession, agent_id: str, *, now: datetime | None = None
) -> dict:
    """Compute an agent's baseline stats. Exposed for the observability API.

    Returns mean/stddev of historical active-bucket volume, the current bucket's
    running count, and the resulting z-score.
    """
    now = now or datetime.now(timezone.utc)
    bucket_seconds = settings.BASELINE_BUCKET_SECONDS
    window_seconds = bucket_seconds * settings.BASELINE_WINDOW_BUCKETS
    since = datetime.fromtimestamp(now.timestamp() - window_seconds, tz=timezone.utc)

    rows = (
        await db.execute(
            select(MCPEvent.created_at).where(
                MCPEvent.agent_id == agent_id, MCPEvent.created_at >= since
            )
        )
    ).all()

    current_idx = _bucket_index(now, bucket_seconds)
    buckets: dict[int, int] = {}
    for (created_at,) in rows:
        buckets[_bucket_index(created_at, bucket_seconds)] = (
            buckets.get(_bucket_index(created_at, bucket_seconds), 0) + 1
        )

    current_count = buckets.get(current_idx, 0)
    # Baseline = completed buckets only (exclude the in-progress current one).
    history = [c for idx, c in buckets.items() if idx != current_idx]
    mean, stddev = summarize(history)
    z = zscore(current_count, mean, stddev)

    return {
        "agent_id": agent_id,
        "bucket_seconds": bucket_seconds,
        "observations": len(history),
        "mean": round(mean, 3),
        "stddev": round(stddev, 3),
        "current_count": current_count,
        "zscore": round(z, 3),
        "learning": len(history) < settings.BASELINE_MIN_OBSERVATIONS,
    }


async def detect_statistical_anomaly(
    db: AsyncSession, *, agent_id: str | None, now: datetime | None = None
) -> list[AnomalyFinding]:
    """Flag the current bucket if it deviates from the agent's learned baseline."""
    if not agent_id:
        return []
    stats = await compute_agent_baseline(db, agent_id, now=now)

    # Learn before judging.
    if stats["observations"] < settings.BASELINE_MIN_OBSERVATIONS:
        return []
    # Need real spread and an above-baseline current bucket to call it anomalous.
    if stats["stddev"] <= 0 or stats["current_count"] <= stats["mean"]:
        return []
    if stats["zscore"] < settings.BASELINE_Z_THRESHOLD:
        return []
    if await _recent_r10_exists(db, agent_id, settings.BASELINE_BUCKET_SECONDS):
        return []

    return [
        AnomalyFinding(
            rule_id="R10",
            title="Statistical volume anomaly (deviates from agent baseline)",
            severity="high",
            detail=(
                f"Agent '{agent_id}' has {stats['current_count']} calls in the current "
                f"{stats['bucket_seconds']}s window — its learned baseline is "
                f"{stats['mean']} ± {stats['stddev']} (z={stats['zscore']}). A spike this "
                "far above the agent's own normal suggests a runaway loop or a hijacked agent."
            ),
            evidence={
                "agent_id": agent_id,
                "current_count": stats["current_count"],
                "baseline_mean": stats["mean"],
                "baseline_stddev": stats["stddev"],
                "zscore": stats["zscore"],
                "observations": stats["observations"],
            },
        )
    ]

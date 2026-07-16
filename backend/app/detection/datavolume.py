"""Data-access volume anomaly — rule R12 (per-agent byte-volume baseline).

R10 learns an agent's normal *number of calls*. But a patient exfiltrator keeps
the call count flat and instead pulls more *data* per call — a handful of large
reads that never trip a rate or sequence rule. R12 closes that gap by learning
each agent's normal **data volume** (summed payload bytes per time bucket) and
flagging a window that spikes far above the agent's own baseline.

It reuses R10's statistics (mean / sample-stddev / z-score) but over summed
`MCPEvent.payload_bytes` instead of event counts. `payload_bytes` is recorded at
write time, so the baseline is a cheap SQL SUM per bucket — no payload re-scan.

Design mirrors R10:
- Learn before judging (MIN_OBSERVATIONS active buckets required).
- Only active buckets count toward the baseline (idle hours would drag the mean
  down and make every active hour look anomalous).
- A minimum absolute byte floor (MIN_BYTES) suppresses noise for agents that
  normally move trivial amounts of data, where a small jump yields a huge z.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.detection.anomaly import AnomalyFinding
from app.detection.baseline import summarize, zscore
from app.models import Alert, AlertStatus, MCPEvent


def _bucket_index(dt: datetime, bucket_seconds: int) -> int:
    return int(dt.timestamp()) // bucket_seconds


async def _recent_r12_exists(db: AsyncSession, agent_id: str, within_seconds: int) -> bool:
    since = datetime.now(timezone.utc).timestamp() - within_seconds
    stmt = select(Alert.evidence, Alert.created_at).where(
        Alert.rule_id == "R12", Alert.status == AlertStatus.open
    )
    for evidence, created_at in (await db.execute(stmt)).all():
        if created_at.timestamp() < since:
            continue
        if (evidence or {}).get("agent_id") == agent_id:
            return True
    return False


async def compute_data_baseline(
    db: AsyncSession, agent_id: str, *, now: datetime | None = None
) -> dict:
    """Compute an agent's data-volume baseline (bytes per bucket)."""
    now = now or datetime.now(timezone.utc)
    bucket_seconds = settings.DATAVOL_BUCKET_SECONDS
    window_seconds = bucket_seconds * settings.DATAVOL_WINDOW_BUCKETS
    since = datetime.fromtimestamp(now.timestamp() - window_seconds, tz=timezone.utc)

    rows = (
        await db.execute(
            select(MCPEvent.created_at, MCPEvent.payload_bytes).where(
                MCPEvent.agent_id == agent_id, MCPEvent.created_at >= since
            )
        )
    ).all()

    current_idx = _bucket_index(now, bucket_seconds)
    buckets: dict[int, int] = {}
    for created_at, payload_bytes in rows:
        idx = _bucket_index(created_at, bucket_seconds)
        buckets[idx] = buckets.get(idx, 0) + int(payload_bytes or 0)

    current_bytes = buckets.get(current_idx, 0)
    history = [b for idx, b in buckets.items() if idx != current_idx]
    mean, stddev = summarize(history)
    z = zscore(current_bytes, mean, stddev)

    return {
        "agent_id": agent_id,
        "bucket_seconds": bucket_seconds,
        "observations": len(history),
        "mean_bytes": round(mean, 1),
        "stddev_bytes": round(stddev, 1),
        "current_bytes": current_bytes,
        "zscore": round(z, 3),
        "learning": len(history) < settings.DATAVOL_MIN_OBSERVATIONS,
    }


async def detect_data_volume_anomaly(
    db: AsyncSession, *, agent_id: str | None, now: datetime | None = None
) -> list[AnomalyFinding]:
    """Flag the current bucket if the agent's data volume spikes above baseline."""
    if not agent_id:
        return []
    stats = await compute_data_baseline(db, agent_id, now=now)

    if stats["observations"] < settings.DATAVOL_MIN_OBSERVATIONS:
        return []
    # Suppress noise for trivially-small-volume agents.
    if stats["current_bytes"] < settings.DATAVOL_MIN_BYTES:
        return []
    if stats["stddev_bytes"] <= 0 or stats["current_bytes"] <= stats["mean_bytes"]:
        return []
    if stats["zscore"] < settings.DATAVOL_Z_THRESHOLD:
        return []
    if await _recent_r12_exists(db, agent_id, settings.DATAVOL_BUCKET_SECONDS):
        return []

    return [
        AnomalyFinding(
            rule_id="R12",
            title="Data-access volume anomaly (deviates from agent baseline)",
            severity="high",
            detail=(
                f"Agent '{agent_id}' moved {stats['current_bytes']} bytes in the current "
                f"{stats['bucket_seconds']}s window — its learned baseline is "
                f"{stats['mean_bytes']} ± {stats['stddev_bytes']} bytes "
                f"(z={stats['zscore']}). A data-volume spike this far above the agent's "
                "own normal, without a matching rise in call count, is the shape of "
                "slow exfiltration."
            ),
            evidence={
                "agent_id": agent_id,
                "current_bytes": stats["current_bytes"],
                "baseline_mean_bytes": stats["mean_bytes"],
                "baseline_stddev_bytes": stats["stddev_bytes"],
                "zscore": stats["zscore"],
                "observations": stats["observations"],
            },
        )
    ]

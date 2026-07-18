"""Incident metrics + per-case timeline.

Operational reporting over the incident case load: how many are open, how fast
they close (MTTR), the severity mix, and a resolved-per-day trend. Plus a
chronological timeline for a single case, reconstructed from data already on
record (the incident's own timestamps, its member alerts, and the audit trail)
so no extra event storage is needed.

The timeline‑building and MTTR math are pure functions, unit‑tested in isolation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, AlertStatus, AuditLog, Incident, Severity


def mean_time_to_resolve(pairs: list[tuple[datetime, datetime]]) -> float | None:
    """Mean seconds between (first_seen, resolved_at). None if no closed cases."""
    if not pairs:
        return None
    total = sum((resolved - first).total_seconds() for first, resolved in pairs)
    return round(total / len(pairs), 1)


def build_timeline(
    incident: Incident, alerts: list[Alert], audit: list[AuditLog]
) -> list[dict[str, Any]]:
    """Merge case lifecycle, member alerts, and audit actions into one ordered log."""
    events: list[dict[str, Any]] = [
        {
            "at": incident.first_seen,
            "kind": "opened",
            "detail": f"Incident opened ({incident.title}).",
        }
    ]
    for a in alerts:
        events.append({
            "at": a.created_at,
            "kind": "alert",
            "detail": f"[{a.rule_id}] {a.title}",
            "severity": str(getattr(a.severity, "value", a.severity)),
        })
    for log in audit:
        events.append({
            "at": log.created_at,
            "kind": "action",
            "detail": f"{log.action} by {log.actor}",
        })
    events.sort(key=lambda e: e["at"])
    # Serialize timestamps last so sorting stays on real datetimes.
    for e in events:
        e["at"] = e["at"].isoformat() if hasattr(e["at"], "isoformat") else e["at"]
    return events


async def incident_metrics(db: AsyncSession, *, days: int = 7) -> dict[str, Any]:
    """Aggregate incident metrics for the reporting dashboard."""
    total = (await db.execute(select(func.count(Incident.id)))).scalar_one() or 0
    open_count = (
        await db.execute(
            select(func.count(Incident.id)).where(Incident.status == AlertStatus.open)
        )
    ).scalar_one() or 0
    resolved_count = (
        await db.execute(
            select(func.count(Incident.id)).where(
                Incident.status == AlertStatus.resolved
            )
        )
    ).scalar_one() or 0

    # MTTR over resolved cases that have both timestamps.
    rows = (
        await db.execute(
            select(Incident.first_seen, Incident.resolved_at).where(
                Incident.status == AlertStatus.resolved,
                Incident.resolved_at.is_not(None),
            )
        )
    ).all()
    mttr = mean_time_to_resolve([(f, r) for f, r in rows if f and r])

    # Severity mix.
    sev_rows = await db.execute(
        select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    )
    by_severity = {
        str(getattr(s, "value", s)): c for s, c in sev_rows.all()
    }

    # Resolved-per-day trend.
    since = datetime.now(timezone.utc) - timedelta(days=days)
    trend_rows = await db.execute(
        select(Incident.resolved_at).where(
            Incident.resolved_at.is_not(None), Incident.resolved_at >= since
        )
    )
    buckets: dict[str, int] = {}
    for (resolved_at,) in trend_rows.all():
        day = resolved_at.date().isoformat()
        buckets[day] = buckets.get(day, 0) + 1
    resolved_trend = [{"date": d, "resolved": c} for d, c in sorted(buckets.items())]

    return {
        "total_incidents": total,
        "open_incidents": open_count,
        "resolved_incidents": resolved_count,
        "mttr_seconds": mttr,
        "by_severity": by_severity,
        "resolved_last_days": resolved_trend,
    }

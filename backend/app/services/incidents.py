"""Incident case management — grouping related alerts into cases.

An analyst works incidents, not individual alerts. This service takes the alerts
raised for one inspected message and attaches each to an incident, opening a new
one or joining an existing open one that shares the same subject and is still
within the grouping window.

Grouping key: (server_id, agent_id). A coordinated attack hitting one server from
one agent — however many rules it trips — collapses into a single case. Alerts
with no server and no agent (rare) get their own singleton incident so nothing is
silently dropped.

Severity rollup: an incident is as severe as its worst member alert. The count
and the set of contributing rule ids are maintained so the case shows breadth
(how many rules) and depth (how many alerts) at a glance.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import Alert, AlertStatus, Incident, Severity

# Severity ordering for the rollup (max wins).
_SEVERITY_RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


def group_key(server_id: str | None, agent_id: str | None) -> str:
    """Stable subject key for grouping. Falls back to 'unknown' components."""
    return f"srv:{server_id or 'none'}|agt:{agent_id or 'none'}"


def _title(server_id: str | None, agent_id: str | None) -> str:
    subj = []
    if agent_id:
        subj.append(f"agent '{agent_id}'")
    if server_id:
        subj.append(f"server '{server_id}'")
    who = " on ".join(subj) if subj else "unattributed activity"
    return f"Incident: {who}"


async def attach_alerts_to_incident(
    db: AsyncSession,
    alerts: list[Alert],
    *,
    server_id: str | None,
    agent_id: str | None,
    now: datetime | None = None,
) -> Incident | None:
    """Group `alerts` (already persisted) into an open incident. Caller commits.

    Returns the incident, or None when there is nothing to group.
    """
    if not alerts:
        return None
    now = now or datetime.now(timezone.utc)
    key = group_key(server_id, agent_id)
    window = timedelta(seconds=settings.INCIDENT_WINDOW_SECONDS)

    # Find an open incident for this subject whose last activity is within window.
    existing = (
        await db.execute(
            select(Incident)
            .where(
                Incident.group_key == key,
                Incident.status == AlertStatus.open,
                Incident.last_seen >= now - window,
            )
            .order_by(Incident.last_seen.desc())
        )
    ).scalars().first()

    incident = existing
    if incident is None:
        # Open the case at its earliest alert's time (the alerts were persisted a
        # moment before grouping ran), so the "opened" event precedes its alerts
        # on the timeline and MTTR measures from when the case actually began.
        # SQLite returns naive datetimes after refresh; coerce to UTC-aware so
        # the comparison with `now` is well-defined.
        alert_times = [
            a.created_at if a.created_at.tzinfo else a.created_at.replace(tzinfo=timezone.utc)
            for a in alerts
            if a.created_at is not None
        ]
        opened_at = min([now, *alert_times]) if alert_times else now
        incident = Incident(
            group_key=key,
            title=_title(server_id, agent_id),
            server_id=server_id,
            agent_id=agent_id,
            severity=Severity.info,
            status=AlertStatus.open,
            alert_count=0,
            rule_ids=[],
            first_seen=opened_at,
            last_seen=now,
        )
        db.add(incident)
        await db.flush()  # get incident.id

    rule_ids = set(incident.rule_ids or [])
    for alert in alerts:
        alert.incident_id = incident.id
        incident.severity = _max_severity(incident.severity, alert.severity)
        incident.alert_count += 1
        rule_ids.add(alert.rule_id)
    # Reassign (not mutate) so SQLAlchemy detects the JSON column change.
    incident.rule_ids = sorted(rule_ids)
    incident.last_seen = now
    return incident

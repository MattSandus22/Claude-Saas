"""SLA breach sweep — proactive notification on missed response times.

The SLA status is computed live on read (services/sla.py), but a status nobody
looks at helps no one. This sweep is the *push* half: it finds open cases that
have breached their response-time SLA and haven't been flagged yet, raises a
synthetic breach alert attached to the case, and fires the alert notifier
(webhook, or simulation-logged when unconfigured) — exactly once per case.

Run it on a schedule (cron/systemd timer hitting POST /incidents/sweep-sla) or
on demand. It is idempotent: the `sla_breach_notified` flag ensures a breach
notifies once, and acknowledging a case before the sweep runs prevents it
entirely (an acknowledged case is no longer breaching-while-open).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, AlertStatus, Incident, Severity
from app.services.notify import notify_alerts
from app.services.sla import sla_status


async def sweep_sla_breaches(
    db: AsyncSession, *, now: datetime | None = None
) -> list[Alert]:
    """Raise + notify a breach alert for each newly-breached open case.

    Returns the alerts created (empty if nothing newly breached).
    """
    now = now or datetime.now(timezone.utc)
    open_incidents = (
        await db.execute(
            select(Incident).where(
                Incident.status == AlertStatus.open,
                Incident.sla_breach_notified.is_(False),
            )
        )
    ).scalars().all()

    created: list[Alert] = []
    for incident in open_incidents:
        status = sla_status(incident, now=now)
        if not status["breached"]:
            continue
        alert = Alert(
            server_id=incident.server_id,
            incident_id=incident.id,
            rule_id="SLA",
            title="SLA breach: case not acknowledged in time",
            description=(
                f"Incident '{incident.title}' ({incident.severity.value}) has been open "
                f"{int(status['elapsed_seconds'])}s without acknowledgement — past its "
                f"{status['target_seconds']}s response-time SLA."
            ),
            # A breach is at least high; a critical case's breach stays critical.
            severity=Severity.critical if incident.severity == Severity.critical
            else Severity.high,
            status=AlertStatus.open,
            evidence={
                "incident_id": incident.id,
                "agent_id": incident.agent_id,
                "case_severity": incident.severity.value,
                "target_seconds": status["target_seconds"],
                "elapsed_seconds": status["elapsed_seconds"],
            },
        )
        db.add(alert)
        incident.sla_breach_notified = True
        created.append(alert)

    if created:
        await db.commit()
        for a in created:
            await db.refresh(a)
        # Fire notifications (webhook or simulation). Never raises.
        await notify_alerts(created)
    return created

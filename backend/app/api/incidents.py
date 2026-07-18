"""Incident (case) triage endpoints.

Incidents group related alerts into a single case (see services/incidents.py).
Analysts list open cases, drill into one to see its member alerts, and triage the
whole case in one action. Resolving an incident cascades to its member alerts so
the two views never disagree.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models import Alert, AlertStatus, AuditLog, Incident, MCPServer, ServerStatus, User
from app.schemas import (
    AlertOut,
    ApplyActionRequest,
    ApplyActionResult,
    IncidentAssign,
    IncidentDetail,
    IncidentOut,
    IncidentUpdate,
    RecommendedActionOut,
    SlaStatus,
    SlaSweepResult,
)
from app.services.audit import record
from app.services.metrics import build_timeline, incident_metrics
from app.services.recommend import recommend_actions
from app.services.response import block_agent
from app.services.sla import sla_status
from app.services.sla_sweep import sweep_sla_breaches


def _to_out(incident: Incident) -> IncidentOut:
    """Serialize an incident with its live SLA status attached."""
    out = IncidentOut.model_validate(incident)
    out.sla = SlaStatus(**sla_status(incident))
    return out

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
async def list_incidents(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    limit: int = Query(default=100, le=500),
):
    """List incidents, most-recently-active first."""
    stmt = select(Incident).order_by(Incident.last_seen.desc())
    if status_filter:
        stmt = stmt.where(Incident.status == AlertStatus(status_filter))
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    return [_to_out(i) for i in result.scalars().all()]


@router.get("/metrics")
async def metrics(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    days: int = Query(default=7, ge=1, le=90),
):
    """Operational metrics over the case load (MTTR, volume, severity mix).

    Declared before /{incident_id} so the literal path is not captured as an id.
    """
    return await incident_metrics(db, days=days)


@router.post("/sweep-sla", response_model=SlaSweepResult)
async def sweep_sla(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Raise + notify a breach alert for each newly-breached open case.

    Idempotent (each breach notifies once). Intended to be hit on a schedule
    (cron/systemd timer) or on demand. Literal path, declared before
    /{incident_id}. Admin-only: it can generate alerts and outbound webhooks.
    """
    created = await sweep_sla_breaches(db)
    if created:
        await record(db, actor=admin.email, action="incident.sla_sweep",
                     detail={"newly_breached": len(created)})
    return SlaSweepResult(
        newly_breached=len(created),
        incident_ids=[a.incident_id for a in created if a.incident_id],
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """One incident with its member alerts (newest first)."""
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = (
        await db.execute(
            select(Alert)
            .where(Alert.incident_id == incident_id)
            .order_by(Alert.created_at.desc())
        )
    ).scalars().all()
    detail = IncidentDetail.model_validate(_to_out(incident).model_dump())
    detail.alerts = [AlertOut.model_validate(a) for a in alerts]
    return detail


@router.patch("/{incident_id}", response_model=IncidentDetail)
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Triage a whole case. Acknowledging/resolving cascades to member alerts."""
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    new_status = AlertStatus(body.status)
    incident.status = new_status
    # Stop the response-time SLA clock on the FIRST time the case leaves 'open'
    # (acknowledged or resolved). Keep the earliest ack; don't reset it on later
    # transitions, so the SLA reflects when a human first responded.
    if new_status != AlertStatus.open and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    # Track closure time for MTTR; clear it if a resolved case is reopened so
    # metrics only reflect genuine closures.
    if new_status == AlertStatus.resolved:
        incident.resolved_at = now
    else:
        incident.resolved_at = None
    # Cascade to member alerts so the alert view and case view stay consistent.
    member_alerts = (
        await db.execute(select(Alert).where(Alert.incident_id == incident_id))
    ).scalars().all()
    for alert in member_alerts:
        alert.status = new_status
    await db.commit()
    await db.refresh(incident)
    await record(db, actor=user.email, action="incident.update", target=incident_id,
                 detail={"status": body.status, "alerts_updated": len(member_alerts)})

    detail = IncidentDetail.model_validate(_to_out(incident).model_dump())
    detail.alerts = [AlertOut.model_validate(a) for a in member_alerts]
    return detail


@router.post("/{incident_id}/assign", response_model=IncidentOut)
async def assign_incident(
    incident_id: str,
    body: IncidentAssign,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Assign a case to a user by email (or unassign with a null email)."""
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    if body.assignee_email is None:
        incident.assignee_id = None
        detail = {"assignee": None}
    else:
        assignee = (
            await db.execute(select(User).where(User.email == body.assignee_email))
        ).scalar_one_or_none()
        if assignee is None:
            raise HTTPException(status_code=404, detail="Assignee user not found")
        incident.assignee_id = assignee.id
        detail = {"assignee": assignee.email}

    await db.commit()
    await db.refresh(incident)
    await record(db, actor=user.email, action="incident.assign", target=incident_id,
                 detail=detail)
    return _to_out(incident)


@router.get("/{incident_id}/recommended-actions", response_model=list[RecommendedActionOut])
async def recommended_actions(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Advisory containment actions for this case (most urgent first).

    Read-only: computing suggestions never changes state. Applying one is a
    separate admin action below.
    """
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return [RecommendedActionOut(**vars(a)) for a in recommend_actions(incident)]


@router.post("/{incident_id}/apply-action", response_model=ApplyActionResult)
async def apply_action(
    incident_id: str,
    body: ApplyActionRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Execute a containment action from the case. Admin-only and audited.

    Only actions the recommender suggested for THIS incident are allowed — an
    analyst cannot use a case as a lever to quarantine/contain an unrelated
    subject. The action reuses the same containment paths as the servers/agents
    APIs (no new bypass surface).
    """
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    suggested = {a.action: a for a in recommend_actions(incident)}
    rec = suggested.get(body.action)
    if rec is None:
        raise HTTPException(
            status_code=422,
            detail=f"Action '{body.action}' is not recommended for this incident",
        )

    if body.action == "contain_agent":
        agents = await block_agent(db, rec.target)
        await record(db, actor=admin.email, action="incident.contain_agent",
                     target=incident_id, detail={"agent_id": rec.target})
        return ApplyActionResult(
            applied="contain_agent", target=rec.target,
            detail=f"Agent contained; blocklist now has {len(agents)} agent(s).",
        )

    # quarantine_server
    server = await db.get(MCPServer, rec.target)
    if server is None:
        raise HTTPException(status_code=404, detail="Server no longer exists")
    server.status = ServerStatus.quarantined
    await db.commit()
    await record(db, actor=admin.email, action="incident.quarantine_server",
                 target=incident_id, detail={"server_id": rec.target})
    return ApplyActionResult(
        applied="quarantine_server", target=rec.target,
        detail=f"Server '{server.name}' quarantined; its traffic is now denied.",
    )


@router.get("/{incident_id}/timeline")
async def timeline(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Chronological activity for a case: opening, each alert, and triage actions.

    Reconstructed from the incident, its member alerts, and the audit trail — no
    separate event log to keep in sync.
    """
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = (
        await db.execute(select(Alert).where(Alert.incident_id == incident_id))
    ).scalars().all()
    audit = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.target == incident_id)
            .order_by(AuditLog.created_at.asc())
        )
    ).scalars().all()
    return {"incident_id": incident_id, "events": build_timeline(incident, alerts, audit)}

"""Incident (case) triage endpoints.

Incidents group related alerts into a single case (see services/incidents.py).
Analysts list open cases, drill into one to see its member alerts, and triage the
whole case in one action. Resolving an incident cascades to its member alerts so
the two views never disagree.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models import Alert, AlertStatus, Incident, User
from app.schemas import AlertOut, IncidentDetail, IncidentOut, IncidentUpdate
from app.services.audit import record

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
    return list(result.scalars().all())


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
    detail = IncidentDetail.model_validate(incident)
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

    new_status = AlertStatus(body.status)
    incident.status = new_status
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

    detail = IncidentDetail.model_validate(incident)
    detail.alerts = [AlertOut.model_validate(a) for a in member_alerts]
    return detail

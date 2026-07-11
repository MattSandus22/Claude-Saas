"""Alert triage endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models import Alert, AlertStatus, User
from app.schemas import AlertOut, AlertUpdate
from app.services.audit import record

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    limit: int = Query(default=100, le=500),
):
    stmt = select(Alert).order_by(Alert.created_at.desc())
    if status_filter:
        stmt = stmt.where(Alert.status == AlertStatus(status_filter))
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: str,
    body: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = AlertStatus(body.status)
    await db.commit()
    await db.refresh(alert)
    await record(db, actor=user.email, action="alert.update", target=alert_id,
                 detail={"status": body.status})
    return alert

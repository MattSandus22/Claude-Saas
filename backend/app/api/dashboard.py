"""Dashboard aggregation + audit log endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models import (
    Alert,
    AlertStatus,
    AuditLog,
    MCPEvent,
    MCPServer,
    MCPTool,
    ServerStatus,
    User,
)
from app.schemas import DashboardStats

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/stats", response_model=DashboardStats)
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    async def scalar(stmt) -> int:
        return (await db.execute(stmt)).scalar_one() or 0

    total_servers = await scalar(select(func.count(MCPServer.id)))
    active_servers = await scalar(
        select(func.count(MCPServer.id)).where(MCPServer.status == ServerStatus.active)
    )
    quarantined = await scalar(
        select(func.count(MCPServer.id)).where(
            MCPServer.status == ServerStatus.quarantined
        )
    )
    suspicious_tools = await scalar(
        select(func.count(MCPTool.id)).where(MCPTool.is_suspicious.is_(True))
    )
    total_events = await scalar(select(func.count(MCPEvent.id)))
    blocked_events = await scalar(
        select(func.count(MCPEvent.id)).where(MCPEvent.blocked.is_(True))
    )
    open_alerts = await scalar(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.open)
    )

    # Alerts by severity.
    sev_rows = await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )
    alerts_by_severity = {str(sev.value if hasattr(sev, "value") else sev): c
                          for sev, c in sev_rows.all()}

    # Events over the last 7 days (bucketed by date).
    since = datetime.now(timezone.utc) - timedelta(days=7)
    ev_rows = await db.execute(
        select(MCPEvent.created_at, MCPEvent.blocked).where(MCPEvent.created_at >= since)
    )
    buckets: dict[str, dict[str, int]] = {}
    for created_at, blocked in ev_rows.all():
        day = created_at.date().isoformat()
        b = buckets.setdefault(day, {"total": 0, "blocked": 0})
        b["total"] += 1
        if blocked:
            b["blocked"] += 1
    events_last_7d = [
        {"date": day, "total": v["total"], "blocked": v["blocked"]}
        for day, v in sorted(buckets.items())
    ]

    # Top risky servers.
    risky_rows = await db.execute(
        select(MCPServer.id, MCPServer.name, MCPServer.risk_score, MCPServer.status)
        .order_by(MCPServer.risk_score.desc())
        .limit(5)
    )
    top_risky_servers = [
        {"id": rid, "name": name, "risk_score": rs,
         "status": st.value if hasattr(st, "value") else st}
        for rid, name, rs, st in risky_rows.all()
    ]

    return DashboardStats(
        total_servers=total_servers,
        active_servers=active_servers,
        quarantined_servers=quarantined,
        suspicious_tools=suspicious_tools,
        total_events=total_events,
        blocked_events=blocked_events,
        open_alerts=open_alerts,
        alerts_by_severity=alerts_by_severity,
        events_last_7d=events_last_7d,
        top_risky_servers=top_risky_servers,
    )


@router.get("/audit")
async def list_audit(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
    limit: int = Query(default=100, le=500),
):
    """Audit trail (admin-only)."""
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    )
    return [
        {
            "id": a.id,
            "actor": a.actor,
            "action": a.action,
            "target": a.target,
            "detail": a.detail,
            "created_at": a.created_at.isoformat(),
        }
        for a in result.scalars().all()
    ]

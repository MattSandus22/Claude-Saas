"""MCP event ingestion + inspection endpoints.

`/inspect` is the real-time enforcement hook: an agent gateway or proxy posts an
MCP message here and gets an allow/block decision plus any alerts. `/events`
lists the monitored history.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models import MCPEvent, MCPServer, User
from app.schemas import AlertOut, EventOut, InspectResult, MCPMessageIn
from app.services.inspector import inspect_message

router = APIRouter(tags=["events"])


@router.post("/inspect", response_model=InspectResult)
async def inspect(
    body: MCPMessageIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Inspect a single MCP message: detect threats + apply policy."""
    server_id = body.server_id
    # Resolve by endpoint if only that was provided.
    if not server_id and body.server_endpoint:
        res = await db.execute(
            select(MCPServer).where(MCPServer.endpoint == body.server_endpoint)
        )
        srv = res.scalar_one_or_none()
        server_id = srv.id if srv else None

    outcome = await inspect_message(
        db,
        server_id=server_id,
        method=body.method,
        tool_name=body.tool_name,
        agent_id=body.agent_id,
        direction=body.direction,
        payload=body.payload,
    )
    return InspectResult(
        event_id=outcome.event.id if outcome.event else None,
        threat_score=outcome.threat_score,
        blocked=outcome.blocked,
        allowed_by_policy=outcome.allowed_by_policy,
        alerts=[AlertOut.model_validate(a) for a in outcome.alerts],
        reasons=outcome.reasons,
    )


@router.get("/events", response_model=list[EventOut])
async def list_events(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    server_id: str | None = None,
    blocked: bool | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(MCPEvent).order_by(MCPEvent.created_at.desc())
    if server_id:
        stmt = stmt.where(MCPEvent.server_id == server_id)
    if blocked is not None:
        stmt = stmt.where(MCPEvent.blocked.is_(blocked))
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    return list(result.scalars().all())

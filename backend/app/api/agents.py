"""Agent containment (response actions).

Block/unblock endpoints are admin-only: containment changes the enforced policy
surface, so it must be an authenticated privileged action and is fully audited.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.detection.baseline import compute_agent_baseline
from app.models import User
from app.schemas import BlockedAgents
from app.services.audit import record
from app.services.response import block_agent, list_blocked_agents, unblock_agent

router = APIRouter(prefix="/agents", tags=["agents"])

# Agent ids are attacker-influenced strings; bound length and keep them opaque.
_AGENT_ID = Path(..., max_length=255, min_length=1)


@router.get("/blocked", response_model=BlockedAgents)
async def get_blocked(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return BlockedAgents(blocked_agents=await list_blocked_agents(db))


@router.get("/{agent_id}/baseline")
async def get_baseline(
    agent_id: str = _AGENT_ID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """The agent's learned volume baseline (R10): mean/stddev, current bucket,
    and the current z-score. Useful for tuning and for explaining an alert."""
    return await compute_agent_baseline(db, agent_id)


@router.post("/{agent_id}/block", response_model=BlockedAgents)
async def block(
    agent_id: str = _AGENT_ID,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Contain an agent: every subsequent MCP message from it is denied."""
    agents = await block_agent(db, agent_id)
    await record(db, actor=admin.email, action="agent.block", target=agent_id)
    return BlockedAgents(blocked_agents=agents)


@router.post("/{agent_id}/unblock", response_model=BlockedAgents)
async def unblock(
    agent_id: str = _AGENT_ID,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    agents = await unblock_agent(db, agent_id)
    await record(db, actor=admin.email, action="agent.unblock", target=agent_id)
    return BlockedAgents(blocked_agents=agents)

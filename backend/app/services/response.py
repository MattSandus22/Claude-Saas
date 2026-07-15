"""Response actions — turning a detection into containment.

The detection engine can tell you an agent is misbehaving (e.g. an R7 "repeated
blocked attempts" alert on a prompt-injected agent). This module lets an analyst
*act* on that: block the agent so every subsequent MCP message it sends is denied
by policy, until an admin explicitly unblocks it.

Implementation: a single managed policy named `MANAGED_BLOCKLIST_NAME` holds the
agent denylist in its `deny_agents` rule. The existing policy engine already
enforces `deny_agents` on every `/inspect`, so blocking is just maintaining that
list — no new enforcement path, no bypass surface. The policy is created lazily
and is clearly named so it is auditable alongside hand-written policies.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Policy

MANAGED_BLOCKLIST_NAME = "Response — Blocked Agents"
_DESCRIPTION = (
    "Auto-managed containment policy. Agents listed here are denied on every MCP "
    "message. Maintained via the response API (block/unblock); edit with care."
)


async def _get_or_create_blocklist(db: AsyncSession) -> Policy:
    result = await db.execute(select(Policy).where(Policy.name == MANAGED_BLOCKLIST_NAME))
    policy = result.scalar_one_or_none()
    if policy is None:
        policy = Policy(
            name=MANAGED_BLOCKLIST_NAME,
            description=_DESCRIPTION,
            enabled=True,
            # default allow so this policy ONLY blocks listed agents and never
            # interferes with other traffic.
            rules={"default": "allow", "deny_agents": []},
        )
        db.add(policy)
        await db.flush()
    return policy


def _current_agents(policy: Policy) -> list[str]:
    agents = (policy.rules or {}).get("deny_agents", [])
    return [str(a) for a in agents] if isinstance(agents, list) else []


async def block_agent(db: AsyncSession, agent_id: str) -> list[str]:
    """Add an agent to the containment denylist. Returns the new denylist."""
    policy = await _get_or_create_blocklist(db)
    agents = _current_agents(policy)
    if agent_id not in agents:
        agents.append(agent_id)
    # Reassign rules dict so SQLAlchemy detects the JSON change.
    policy.rules = {**(policy.rules or {}), "deny_agents": agents, "default": "allow"}
    policy.enabled = True
    await db.commit()
    return agents


async def unblock_agent(db: AsyncSession, agent_id: str) -> list[str]:
    """Remove an agent from the containment denylist. Returns the new denylist."""
    policy = await _get_or_create_blocklist(db)
    agents = [a for a in _current_agents(policy) if a != agent_id]
    policy.rules = {**(policy.rules or {}), "deny_agents": agents, "default": "allow"}
    await db.commit()
    return agents


async def list_blocked_agents(db: AsyncSession) -> list[str]:
    result = await db.execute(select(Policy).where(Policy.name == MANAGED_BLOCKLIST_NAME))
    policy = result.scalar_one_or_none()
    return _current_agents(policy) if policy else []

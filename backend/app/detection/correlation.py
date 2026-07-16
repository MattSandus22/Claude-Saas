"""Cross-agent correlation — rule R13 (campaign / coordinated-attack detection).

Every rule so far judges one agent in isolation. That misses the coordinated
case: an attacker who spreads activity across *many* agents so each stays under
every per-agent threshold, while together they hammer a single server. The whole
is an attack; no part is.

R13 is an aggregate detector keyed on the *server*, not the agent. In a short
window it looks at one server and flags two campaign shapes:

  R13a  Fan-in surge: an unusually large number of *distinct* agents touched the
        same server in the window — a sudden swarm where the server normally sees
        a handful of agents.
  R13b  Coordinated blocked burst: multiple *distinct* agents had messages to the
        server blocked in the window — several agents independently tripping
        enforcement at once is the signature of a scripted campaign probing the
        same target, not one agent misbehaving.

Both are computed from the existing MCPEvent table with a single grouped query,
and deduplicate per server so a sustained campaign yields one alert, not one per
message. Thresholds are env-tunable (`CORRELATION_*`).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.detection.anomaly import AnomalyFinding
from app.models import Alert, AlertStatus, MCPEvent


async def _recent_r13_exists(
    db: AsyncSession, server_id: str, subrule: str, within_seconds: int
) -> bool:
    """Dedup per (server, subrule): one alert per campaign window, not per message."""
    since = datetime.now(timezone.utc).timestamp() - within_seconds
    stmt = select(Alert.evidence, Alert.created_at).where(
        Alert.rule_id == "R13", Alert.status == AlertStatus.open
    )
    for evidence, created_at in (await db.execute(stmt)).all():
        if created_at.timestamp() < since:
            continue
        ev = evidence or {}
        if ev.get("server_id") == server_id and ev.get("subrule") == subrule:
            return True
    return False


async def _distinct_agents(
    db: AsyncSession, server_id: str, since: datetime, *, blocked_only: bool
) -> int:
    stmt = select(func.count(func.distinct(MCPEvent.agent_id))).where(
        MCPEvent.server_id == server_id,
        MCPEvent.agent_id.is_not(None),
        MCPEvent.created_at >= since,
    )
    if blocked_only:
        stmt = stmt.where(MCPEvent.blocked.is_(True))
    return (await db.execute(stmt)).scalar_one() or 0


async def detect_correlation_anomaly(
    db: AsyncSession, *, server_id: str | None, now: datetime | None = None
) -> list[AnomalyFinding]:
    """Flag coordinated multi-agent activity against a single server."""
    if not server_id:
        return []  # aggregate detector keys on the target server
    now = now or datetime.now(timezone.utc)
    window = settings.CORRELATION_WINDOW_SECONDS
    since = datetime.fromtimestamp(now.timestamp() - window, tz=timezone.utc)

    findings: list[AnomalyFinding] = []

    # R13a: fan-in surge — many distinct agents on one server at once.
    distinct = await _distinct_agents(db, server_id, since, blocked_only=False)
    if distinct >= settings.CORRELATION_MIN_AGENTS and not await _recent_r13_exists(
        db, server_id, "fan_in", window
    ):
        findings.append(
            AnomalyFinding(
                rule_id="R13",
                title="Coordinated multi-agent surge on a server",
                severity="high",
                detail=(
                    f"{distinct} distinct agents accessed server '{server_id}' within "
                    f"{window}s (threshold {settings.CORRELATION_MIN_AGENTS}). A sudden "
                    "swarm of agents on one server is the shape of a coordinated "
                    "campaign that keeps each agent under its own limits."
                ),
                evidence={"server_id": server_id, "subrule": "fan_in",
                          "distinct_agents": distinct, "window_seconds": window},
            )
        )

    # R13b: coordinated blocked burst — multiple agents blocked on one server.
    blocked_agents = await _distinct_agents(db, server_id, since, blocked_only=True)
    if blocked_agents >= settings.CORRELATION_MIN_BLOCKED_AGENTS and not await _recent_r13_exists(
        db, server_id, "blocked_burst", window
    ):
        findings.append(
            AnomalyFinding(
                rule_id="R13",
                title="Coordinated blocked attempts from multiple agents",
                severity="critical",
                detail=(
                    f"{blocked_agents} distinct agents had messages to server "
                    f"'{server_id}' blocked within {window}s (threshold "
                    f"{settings.CORRELATION_MIN_BLOCKED_AGENTS}). Several agents "
                    "independently tripping enforcement on the same target at once "
                    "indicates a scripted, distributed campaign."
                ),
                evidence={"server_id": server_id, "subrule": "blocked_burst",
                          "blocked_agents": blocked_agents, "window_seconds": window},
            )
        )

    return findings

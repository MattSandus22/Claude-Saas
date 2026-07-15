"""Behavioral anomaly detection over recent event history.

Static rules (rules.py) inspect one message in isolation; these rules look at
*patterns across events* — the signals that catch a compromised or misbehaving
agent even when each individual message looks benign:

  R6  Rapid-fire activity: an agent issuing an abnormal volume of MCP calls in
      a short window (runaway loop or automated abuse).
  R7  Repeated blocked attempts: an agent that keeps hitting policy denials or
      detection blocks (probing behavior).
  R8  Tool enumeration: one agent touching many *distinct* tools in a short
      window (reconnaissance / capability mapping).

Each detector deduplicates against recent open alerts for the same (rule,
agent) so a burst produces one alert, not hundreds.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import Alert, AlertStatus, MCPEvent

# Thresholds live in core/config.py (ANOMALY_* env settings) and are read at
# call time, so deployments tune them without code changes.


@dataclass
class AnomalyFinding:
    rule_id: str
    title: str
    severity: str
    detail: str
    evidence: dict


async def _recent_alert_exists(
    db: AsyncSession, rule_id: str, agent_id: str | None
) -> bool:
    since = datetime.now(timezone.utc) - timedelta(seconds=settings.ANOMALY_DEDUPE_WINDOW_S)
    stmt = select(func.count(Alert.id)).where(
        Alert.rule_id == rule_id,
        Alert.status == AlertStatus.open,
        Alert.created_at >= since,
    )
    rows = await db.execute(stmt)
    if (rows.scalar_one() or 0) == 0:
        return False
    # Cheap secondary filter on the evidence agent (JSON query support varies
    # by backend, so we filter the small recent set in Python).
    stmt = select(Alert.evidence).where(
        Alert.rule_id == rule_id,
        Alert.status == AlertStatus.open,
        Alert.created_at >= since,
    )
    for (evidence,) in (await db.execute(stmt)).all():
        if (evidence or {}).get("agent_id") == agent_id:
            return True
    return False


async def detect_anomalies(
    db: AsyncSession, *, agent_id: str | None, server_id: str | None
) -> list[AnomalyFinding]:
    """Run behavioral detectors for the agent that just produced an event."""
    if not agent_id:
        return []  # behavioral rules key on agent identity

    now = datetime.now(timezone.utc)
    findings: list[AnomalyFinding] = []

    # R6: rapid-fire volume.
    rf_window = settings.ANOMALY_RAPID_FIRE_WINDOW_S
    rf_threshold = settings.ANOMALY_RAPID_FIRE_THRESHOLD
    since = now - timedelta(seconds=rf_window)
    count = (
        await db.execute(
            select(func.count(MCPEvent.id)).where(
                MCPEvent.agent_id == agent_id, MCPEvent.created_at >= since
            )
        )
    ).scalar_one() or 0
    if count >= rf_threshold and not await _recent_alert_exists(db, "R6", agent_id):
        findings.append(
            AnomalyFinding(
                rule_id="R6",
                title="Rapid-fire MCP activity",
                severity="medium",
                detail=(
                    f"Agent '{agent_id}' issued {count} MCP calls in the last "
                    f"{rf_window}s (threshold {rf_threshold}). "
                    "Possible runaway loop or automated abuse."
                ),
                evidence={"agent_id": agent_id, "count": count,
                          "window_seconds": rf_window},
            )
        )

    # R7: repeated blocked attempts.
    bl_window = settings.ANOMALY_BLOCKED_WINDOW_S
    bl_threshold = settings.ANOMALY_BLOCKED_THRESHOLD
    since = now - timedelta(seconds=bl_window)
    blocked = (
        await db.execute(
            select(func.count(MCPEvent.id)).where(
                MCPEvent.agent_id == agent_id,
                MCPEvent.blocked.is_(True),
                MCPEvent.created_at >= since,
            )
        )
    ).scalar_one() or 0
    if blocked >= bl_threshold and not await _recent_alert_exists(db, "R7", agent_id):
        findings.append(
            AnomalyFinding(
                rule_id="R7",
                title="Repeated blocked attempts (probing)",
                severity="high",
                detail=(
                    f"Agent '{agent_id}' had {blocked} blocked messages in the last "
                    f"{bl_window // 60} minutes. This pattern suggests an agent "
                    "probing policy boundaries or under prompt-injection control."
                ),
                evidence={"agent_id": agent_id, "blocked_count": blocked,
                          "window_seconds": bl_window},
            )
        )

    # R8: distinct-tool enumeration.
    en_window = settings.ANOMALY_ENUM_WINDOW_S
    en_threshold = settings.ANOMALY_ENUM_DISTINCT_TOOLS
    since = now - timedelta(seconds=en_window)
    distinct_tools = (
        await db.execute(
            select(func.count(func.distinct(MCPEvent.tool_name))).where(
                MCPEvent.agent_id == agent_id,
                MCPEvent.tool_name.is_not(None),
                MCPEvent.created_at >= since,
            )
        )
    ).scalar_one() or 0
    if distinct_tools >= en_threshold and not await _recent_alert_exists(
        db, "R8", agent_id
    ):
        findings.append(
            AnomalyFinding(
                rule_id="R8",
                title="Tool enumeration behavior",
                severity="medium",
                detail=(
                    f"Agent '{agent_id}' called {distinct_tools} distinct tools within "
                    f"{en_window // 60} minutes — consistent with capability "
                    "reconnaissance before an attack."
                ),
                evidence={"agent_id": agent_id, "distinct_tools": distinct_tools,
                          "window_seconds": en_window, "server_id": server_id},
            )
        )

    return findings

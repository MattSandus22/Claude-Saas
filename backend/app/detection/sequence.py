"""Tool-sequence anomaly detection — rule R11 (per-agent transition baseline).

R10 catches an agent doing *too much*. R11 catches an agent doing something
*out of order* — a slow-exfiltration pattern where every individual call is
allowed and the volume is normal, but the agent suddenly chains tools in a way
it never has before (e.g. `read_file` → `http_post`, i.e. read a secret then
ship it out).

Approach: model each agent's behavior as a first-order Markov chain over tool
names. From history we learn which transitions (toolA → toolB bigrams) the agent
normally makes. When the just-observed transition has never been seen for this
agent — or is vanishingly rare — we flag it. A transition whose *destination* is
a sensitive sink (network / write / exec) is treated as higher severity, because
that is the tail end of an exfiltration chain.

Design choices mirror R10:
- Learn before judging: require MIN_TRANSITIONS observed transitions before any
  scoring, so a new agent is never flagged for simply being new.
- Computed from the existing MCPEvent table (ordered by time) — no new state.
- Pure transition-model helpers are unit-tested in isolation.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.detection.anomaly import AnomalyFinding
from app.models import Alert, AlertStatus, MCPEvent

# Tool-name patterns that indicate a data *sink* — the dangerous end of an
# exfiltration chain. Matched case-insensitively against the destination tool.
_SENSITIVE_SINK = re.compile(
    r"(http|fetch|post|send|upload|email|webhook|curl|request|network|"
    r"write|put|exec|shell|run_command|delete)",
    re.IGNORECASE,
)


def build_transition_model(tool_sequence: list[str]) -> dict[str, dict[str, int]]:
    """Build a first-order transition count model from an ordered tool list.

    Returns {from_tool: {to_tool: count}}. Consecutive identical tools still
    count as a self-transition (a legitimate part of an agent's behavior).
    """
    model: dict[str, dict[str, int]] = {}
    for a, b in zip(tool_sequence, tool_sequence[1:]):
        model.setdefault(a, {})[b] = model.setdefault(a, {}).get(b, 0) + 1
    return model


def total_transitions(model: dict[str, dict[str, int]]) -> int:
    return sum(sum(dests.values()) for dests in model.values())


def transition_probability(
    model: dict[str, dict[str, int]], src: str, dst: str
) -> float:
    """P(dst | src) under the learned model. 0.0 if src or the edge is unseen."""
    dests = model.get(src)
    if not dests:
        return 0.0
    total = sum(dests.values())
    if total == 0:
        return 0.0
    return dests.get(dst, 0) / total


def is_sensitive_sink(tool_name: str | None) -> bool:
    return bool(tool_name) and bool(_SENSITIVE_SINK.search(tool_name))


async def _recent_r11_exists(db: AsyncSession, agent_id: str, within_seconds: int) -> bool:
    since = datetime.now(timezone.utc).timestamp() - within_seconds
    stmt = select(Alert.evidence, Alert.created_at).where(
        Alert.rule_id == "R11", Alert.status == AlertStatus.open
    )
    for evidence, created_at in (await db.execute(stmt)).all():
        if created_at.timestamp() < since:
            continue
        if (evidence or {}).get("agent_id") == agent_id:
            return True
    return False


async def detect_sequence_anomaly(
    db: AsyncSession, *, agent_id: str | None, now: datetime | None = None
) -> list[AnomalyFinding]:
    """Flag the most recent tool transition if it is anomalous for this agent."""
    if not agent_id:
        return []
    now = now or datetime.now(timezone.utc)
    window_seconds = settings.SEQUENCE_WINDOW_SECONDS
    since = datetime.fromtimestamp(now.timestamp() - window_seconds, tz=timezone.utc)

    rows = (
        await db.execute(
            select(MCPEvent.tool_name)
            .where(
                MCPEvent.agent_id == agent_id,
                MCPEvent.tool_name.is_not(None),
                MCPEvent.created_at >= since,
            )
            .order_by(MCPEvent.created_at.asc(), MCPEvent.id.asc())
        )
    ).all()

    tools = [t for (t,) in rows if t]
    if len(tools) < 2:
        return []

    # The transition we are judging is the last one; the model is everything
    # before it (so the current transition can be "never seen").
    src, dst = tools[-2], tools[-1]
    history = tools[:-1]
    model = build_transition_model(history)

    if total_transitions(model) < settings.SEQUENCE_MIN_TRANSITIONS:
        return []  # still learning this agent's normal sequences

    prob = transition_probability(model, src, dst)
    if prob > settings.SEQUENCE_RARE_PROB:
        return []  # a common transition for this agent — normal

    if await _recent_r11_exists(db, agent_id, window_seconds):
        return []

    sink = is_sensitive_sink(dst)
    severity = "high" if sink else "medium"
    never_seen = prob == 0.0
    qualifier = "never-before-seen" if never_seen else f"rare (p={round(prob, 4)})"
    sink_note = (
        " The destination is a sensitive data sink (network/write/exec) — this is "
        "the shape of an exfiltration chain." if sink else ""
    )

    return [
        AnomalyFinding(
            rule_id="R11",
            title="Anomalous tool sequence for agent",
            severity=severity,
            detail=(
                f"Agent '{agent_id}' made a {qualifier} transition '{src}' → '{dst}' "
                f"that departs from its learned behavior.{sink_note}"
            ),
            evidence={
                "agent_id": agent_id,
                "from_tool": src,
                "to_tool": dst,
                "probability": round(prob, 5),
                "sensitive_sink": sink,
                "observed_transitions": total_transitions(model),
            },
        )
    ]

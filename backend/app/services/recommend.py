"""Incident response recommendations.

Closes the loop from detection to action: given an incident (its severity, the
subject it concerns, and the set of detection rules that fired), suggest the
concrete containment actions an analyst should consider — and let them apply one
from the case view instead of navigating away to the servers or agents pages.

This is a pure decision function (unit-tested in isolation). The suggestions map
rule families to the response that actually addresses them:

  * Agent-behavior rules (R6-R8, R10-R12) implicate the *agent* — the fix is to
    contain the agent (deny its future messages).
  * Server/tool rules (R9 drift/rug-pull) and campaign correlation (R13)
    implicate the *server* — the fix is to quarantine it.
  * Content rules (R1-R5) on their own are per-message; a high/critical case that
    concerns a server still warrants quarantine, and one concerning an agent
    warrants containment.

Recommendations are advisory only. Applying one is a separate, admin-only,
audited action (see the incidents API). We never auto-contain.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models import Incident, Severity

# Rule families -> which subject they implicate.
_AGENT_RULES = {"R6", "R7", "R8", "R10", "R11", "R12"}
_SERVER_RULES = {"R9", "R13"}

_SEVERITY_RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


@dataclass
class RecommendedAction:
    action: str  # "contain_agent" | "quarantine_server"
    target: str  # agent id or server id
    reason: str
    urgency: str  # "recommended" | "urgent"
    triggering_rules: list[str] = field(default_factory=list)


def recommend_actions(incident: Incident) -> list[RecommendedAction]:
    """Return advisory response actions for an incident, most urgent first."""
    rules = set(incident.rule_ids or [])
    sev_rank = _SEVERITY_RANK.get(incident.severity, 0)
    high_or_worse = sev_rank >= _SEVERITY_RANK[Severity.high]
    actions: list[RecommendedAction] = []

    agent_rules = sorted(rules & _AGENT_RULES)
    server_rules = sorted(rules & _SERVER_RULES)

    # Contain the agent when agent-behavior rules fired, or a high+ case is
    # attributed to a specific agent.
    if incident.agent_id and (agent_rules or high_or_worse):
        triggers = agent_rules or sorted(rules)
        actions.append(
            RecommendedAction(
                action="contain_agent",
                target=incident.agent_id,
                reason=(
                    f"Agent '{incident.agent_id}' is implicated by "
                    f"{', '.join(triggers)}. Containing it denies its future MCP "
                    "messages until an admin releases it."
                ),
                urgency="urgent" if incident.severity == Severity.critical else "recommended",
                triggering_rules=triggers,
            )
        )

    # Quarantine the server on drift/rug-pull or a coordinated campaign, or a
    # high+ case attributed to a specific server.
    if incident.server_id and (server_rules or high_or_worse):
        triggers = server_rules or sorted(rules)
        reason = (
            f"Server activity is implicated by {', '.join(triggers)}. "
            "Quarantining it denies all its traffic until reviewed."
        )
        if "R9" in server_rules:
            reason = (
                "A tool definition changed after approval (R9 rug-pull). "
                "Quarantine the server until its tools are re-reviewed."
            )
        elif "R13" in server_rules:
            reason = (
                "Multiple agents are coordinating against this server (R13). "
                "Quarantine it to halt the campaign."
            )
        actions.append(
            RecommendedAction(
                action="quarantine_server",
                target=incident.server_id,
                reason=reason,
                urgency="urgent" if high_or_worse else "recommended",
                triggering_rules=triggers,
            )
        )

    # Most urgent first (urgent before recommended); stable otherwise.
    actions.sort(key=lambda a: 0 if a.urgency == "urgent" else 1)
    return actions

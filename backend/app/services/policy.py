"""Policy-as-code engine.

Policies are declarative JSON/YAML documents evaluated against an MCP message.
Design goals: simple, auditable, no arbitrary code execution (no eval), and
deterministic. A policy answers one question: *is this action allowed?*

Policy document shape (all fields optional):
{
  "default": "allow" | "deny",          # fallback decision
  "allow_tools": ["read_file", ...],    # allowlist (if set, only these pass)
  "deny_tools": ["exec_shell", ...],    # explicit denylist (wins over allow)
  "deny_methods": ["tools/call"],       # block whole MCP methods
  "max_threat_score": 70,               # deny if detection score >= this
  "deny_agents": ["untrusted-agent"],   # block specific agent ids
  "require_agent_id": false             # deny messages without an agent id
}

Multiple enabled policies are combined with DENY-overrides-ALLOW semantics: if
any policy denies, the action is denied. This is the safe default for security.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PolicyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    matched_policies: list[str] = field(default_factory=list)


def _evaluate_single(
    policy_name: str,
    rules: dict[str, Any],
    *,
    method: str,
    tool_name: str | None,
    agent_id: str | None,
    threat_score: float,
) -> tuple[bool, list[str]]:
    """Evaluate one policy. Returns (allowed, reasons)."""
    reasons: list[str] = []
    default = str(rules.get("default", "allow")).lower()

    deny_methods = {str(m).lower() for m in rules.get("deny_methods", [])}
    if method.lower() in deny_methods:
        return False, [f"[{policy_name}] method '{method}' is denied"]

    deny_tools = {str(t).lower() for t in rules.get("deny_tools", [])}
    if tool_name and tool_name.lower() in deny_tools:
        return False, [f"[{policy_name}] tool '{tool_name}' is explicitly denied"]

    deny_agents = {str(a).lower() for a in rules.get("deny_agents", [])}
    if agent_id and agent_id.lower() in deny_agents:
        return False, [f"[{policy_name}] agent '{agent_id}' is denied"]

    if rules.get("require_agent_id") and not agent_id:
        return False, [f"[{policy_name}] messages must carry an agent id"]

    max_score = rules.get("max_threat_score")
    if isinstance(max_score, (int, float)) and threat_score >= max_score:
        return False, [
            f"[{policy_name}] threat score {threat_score} >= max {max_score}"
        ]

    allow_tools = rules.get("allow_tools")
    if isinstance(allow_tools, list) and allow_tools:
        allow_set = {str(t).lower() for t in allow_tools}
        # Allowlist only constrains tool calls.
        if tool_name is not None and tool_name.lower() not in allow_set:
            return False, [
                f"[{policy_name}] tool '{tool_name}' not in allowlist"
            ]
        reasons.append(f"[{policy_name}] tool permitted by allowlist")
        return True, reasons

    if default == "deny":
        return False, [f"[{policy_name}] denied by default policy"]
    return True, [f"[{policy_name}] allowed by default"]


def evaluate_policies(
    policies: list[dict[str, Any]],
    *,
    method: str,
    tool_name: str | None,
    agent_id: str | None,
    threat_score: float,
) -> PolicyDecision:
    """Evaluate all enabled policies with deny-overrides semantics.

    `policies` is a list of {"name": str, "rules": dict}. If no policies are
    provided, the action is allowed (fail-open only when *no policy exists*;
    once any policy is defined, its default governs).
    """
    if not policies:
        return PolicyDecision(allowed=True, reasons=["no policies defined; default allow"])

    decision = PolicyDecision(allowed=True)
    for p in policies:
        allowed, reasons = _evaluate_single(
            p.get("name", "unnamed"),
            p.get("rules", {}) or {},
            method=method,
            tool_name=tool_name,
            agent_id=agent_id,
            threat_score=threat_score,
        )
        decision.reasons.extend(reasons)
        decision.matched_policies.append(p.get("name", "unnamed"))
        if not allowed:
            decision.allowed = False  # deny overrides; keep scanning for full reasons

    return decision

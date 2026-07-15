"""Policy dry-run / simulation.

Runs the exact same detection + policy pipeline as `/inspect` but persists
nothing: no event row, no alerts, no server risk changes, no webhooks. This lets
an analyst answer "what would this policy do?" before deploying a change — the
safe way to iterate on policy-as-code.

Reuses the pure detection rules and policy engine so simulation and enforcement
can never diverge in their verdict logic.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sanitize import PayloadTooComplex, sanitize
from app.detection.rules import analyze_message, combine_score
from app.models import Policy
from app.services.inspector import CRITICAL_BLOCK_THRESHOLD
from app.services.policy import evaluate_policies


async def simulate_message(
    db: AsyncSession,
    *,
    method: str,
    tool_name: str | None,
    agent_id: str | None,
    payload: dict,
    candidate_policies: list[dict] | None = None,
) -> dict:
    """Return the decision for a message without any side effects.

    `candidate_policies` (each {"name", "rules"}) overrides stored policies when
    provided, so a proposed policy can be tested in isolation.
    """
    try:
        clean = sanitize(payload)
    except PayloadTooComplex as exc:
        clean = {"_sanitizer": f"rejected: {exc}"}

    findings = analyze_message(method, tool_name, clean)
    threat_score = combine_score(findings)

    used_candidate = candidate_policies is not None
    if used_candidate:
        policies = candidate_policies
    else:
        result = await db.execute(select(Policy).where(Policy.enabled.is_(True)))
        policies = [{"name": p.name, "rules": p.rules} for p in result.scalars().all()]

    decision = evaluate_policies(
        policies,
        method=method,
        tool_name=tool_name,
        agent_id=agent_id,
        threat_score=threat_score,
    )
    blocked = not decision.allowed or threat_score >= CRITICAL_BLOCK_THRESHOLD
    reasons = list(decision.reasons)
    if threat_score >= CRITICAL_BLOCK_THRESHOLD and decision.allowed:
        reasons.append(
            f"would be blocked by safety backstop: threat score {threat_score} "
            f">= {CRITICAL_BLOCK_THRESHOLD}"
        )

    return {
        "threat_score": threat_score,
        "blocked": blocked,
        "allowed_by_policy": decision.allowed,
        "reasons": reasons,
        "findings": [
            {"rule_id": f.rule_id, "title": f.title, "severity": f.severity,
             "detail": f.detail}
            for f in findings
        ],
        "used_candidate_policies": used_candidate,
    }

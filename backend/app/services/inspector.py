"""Message inspection pipeline.

Given an incoming MCP message this service:
  1. Sanitizes the payload.
  2. Runs threat-detection rules -> findings + threat score.
  3. Loads enabled policies and evaluates allow/deny.
  4. Persists an MCPEvent, raises Alerts for findings, and (optionally) marks the
     event blocked when policy denies or score crosses the block threshold.

Returned as a structured result so the API and tests can assert on it.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sanitize import PayloadTooComplex, sanitize
from app.detection.anomaly import detect_anomalies
from app.detection.baseline import detect_statistical_anomaly
from app.detection.rules import analyze_message, combine_score
from app.models import Alert, AlertStatus, MCPEvent, MCPServer, Policy, ServerStatus, Severity
from app.services.notify import notify_alerts
from app.services.policy import evaluate_policies

# If a message scores at/above this and no policy explicitly allows, we block it
# even absent a policy. This is a safety backstop for critical findings.
CRITICAL_BLOCK_THRESHOLD = 90.0


class InspectionOutcome:
    def __init__(self):
        self.event: MCPEvent | None = None
        self.threat_score: float = 0.0
        self.blocked: bool = False
        self.allowed_by_policy: bool = True
        self.alerts: list[Alert] = []
        self.reasons: list[str] = []


async def inspect_message(
    db: AsyncSession,
    *,
    server_id: str | None,
    method: str,
    tool_name: str | None,
    agent_id: str | None,
    direction: str,
    payload: dict,
) -> InspectionOutcome:
    outcome = InspectionOutcome()

    # 0. Quarantine gate: a quarantined server is untrusted — every message to
    # or from it is denied outright, regardless of content or policy. Loaded
    # first so the decision applies before any other evaluation.
    server = await db.get(MCPServer, server_id) if server_id else None
    quarantined = server is not None and server.status == ServerStatus.quarantined
    if quarantined:
        outcome.reasons.append(
            f"server '{server.name}' is quarantined; all traffic denied"
        )

    # 1. Sanitize (reject pathological payloads).
    try:
        clean_payload = sanitize(payload)
    except PayloadTooComplex as exc:
        clean_payload = {"_sanitizer": f"rejected: {exc}"}
        outcome.reasons.append(f"payload rejected by sanitizer: {exc}")

    # 2. Detect.
    findings = analyze_message(method, tool_name, clean_payload)
    threat_score = combine_score(findings)
    outcome.threat_score = threat_score

    # 3. Policy.
    result = await db.execute(select(Policy).where(Policy.enabled.is_(True)))
    policies = [{"name": p.name, "rules": p.rules} for p in result.scalars().all()]
    decision = evaluate_policies(
        policies,
        method=method,
        tool_name=tool_name,
        agent_id=agent_id,
        threat_score=threat_score,
    )
    outcome.allowed_by_policy = decision.allowed
    outcome.reasons.extend(decision.reasons)

    blocked = (
        quarantined
        or not decision.allowed
        or threat_score >= CRITICAL_BLOCK_THRESHOLD
    )
    if threat_score >= CRITICAL_BLOCK_THRESHOLD and decision.allowed:
        outcome.reasons.append(
            f"blocked by safety backstop: threat score {threat_score} >= {CRITICAL_BLOCK_THRESHOLD}"
        )
    outcome.blocked = blocked

    # 4. Persist event.
    event = MCPEvent(
        server_id=server_id,
        method=method,
        tool_name=tool_name,
        agent_id=agent_id,
        direction=direction,
        payload=clean_payload,
        threat_score=threat_score,
        blocked=blocked,
    )
    db.add(event)
    await db.flush()  # get event.id
    outcome.event = event

    # Raise alerts for each finding.
    for f in findings:
        alert = Alert(
            server_id=server_id,
            event_id=event.id,
            rule_id=f.rule_id,
            title=f.title,
            description=f.detail,
            severity=Severity(f.severity),
            status=AlertStatus.open,
            evidence=f.evidence,
        )
        db.add(alert)
        outcome.alerts.append(alert)

    # Bump server risk + last_seen if we know the server (loaded at step 0).
    if server is not None:
        server.risk_score = max(server.risk_score, threat_score)
        if threat_score >= CRITICAL_BLOCK_THRESHOLD:
            server.status = ServerStatus.quarantined

    await db.commit()
    await db.refresh(event)

    # 5. Behavioral anomaly pass (needs the event committed so counts include it).
    #    Fixed-threshold rules (R6-R8) plus the per-agent statistical baseline (R10).
    anomalies = await detect_anomalies(db, agent_id=agent_id, server_id=server_id)
    anomalies += await detect_statistical_anomaly(db, agent_id=agent_id)
    for af in anomalies:
        alert = Alert(
            server_id=server_id,
            event_id=event.id,
            rule_id=af.rule_id,
            title=af.title,
            description=af.detail,
            severity=Severity(af.severity),
            status=AlertStatus.open,
            evidence=af.evidence,
        )
        db.add(alert)
        outcome.alerts.append(alert)
        outcome.reasons.append(f"anomaly: {af.title}")
    if anomalies:
        await db.commit()

    for a in outcome.alerts:
        await db.refresh(a)

    # 6. Notify (or simulate) for high/critical alerts. Never raises.
    await notify_alerts(outcome.alerts)
    return outcome

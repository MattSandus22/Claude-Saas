"""Prometheus metrics exposition.

Exposes MCPGuard's operational counts in the Prometheus text exposition format
so a scraper can graph and alert on the platform's own posture — servers under
management, events processed, alerts by severity, open/breached incidents.

The text formatter is a pure, dependency-free helper (like the CEF/Slack alert
builders), unit-tested in isolation; the aggregator is a thin DB read.

Security: the endpoint is disabled unless PROMETHEUS_BEARER_TOKEN is set, and
when set requires that bearer token — internal counts are not exposed
unauthenticated by default.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Alert,
    AlertStatus,
    Incident,
    MCPEvent,
    MCPServer,
    MCPTool,
    ServerStatus,
)
from app.services.sla import sla_status


def _fmt_labels(labels: dict[str, str] | None) -> str:
    if not labels:
        return ""
    # Escape backslash, double-quote, and newline per the exposition format.
    parts = []
    for k, v in labels.items():
        esc = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        parts.append(f'{k}="{esc}"')
    return "{" + ",".join(parts) + "}"


def render_exposition(metrics: list[dict]) -> str:
    """Render metrics to Prometheus text exposition format.

    Each metric: {"name", "type", "help", "samples": [(labels|None, value), ...]}.
    Emits a HELP and TYPE line once per metric name, then one line per sample.
    """
    lines: list[str] = []
    for m in metrics:
        name = m["name"]
        lines.append(f"# HELP {name} {m['help']}")
        lines.append(f"# TYPE {name} {m['type']}")
        for labels, value in m["samples"]:
            # Integers render without a trailing .0; floats stay as-is.
            v = int(value) if isinstance(value, bool) or float(value).is_integer() else value
            lines.append(f"{name}{_fmt_labels(labels)} {v}")
    return "\n".join(lines) + "\n"


async def _count(db: AsyncSession, stmt) -> int:
    return (await db.execute(stmt)).scalar_one() or 0


async def collect_metrics(db: AsyncSession) -> list[dict]:
    """Aggregate live platform counts into a metrics list for render_exposition."""
    # Servers by status.
    server_rows = (
        await db.execute(
            select(MCPServer.status, func.count(MCPServer.id)).group_by(MCPServer.status)
        )
    ).all()
    server_samples = [
        ({"status": str(getattr(s, "value", s))}, c) for s, c in server_rows
    ]

    suspicious_tools = await _count(
        db, select(func.count(MCPTool.id)).where(MCPTool.is_suspicious.is_(True))
    )
    total_events = await _count(db, select(func.count(MCPEvent.id)))
    blocked_events = await _count(
        db, select(func.count(MCPEvent.id)).where(MCPEvent.blocked.is_(True))
    )

    # Alerts by severity + status.
    alert_rows = (
        await db.execute(
            select(Alert.severity, Alert.status, func.count(Alert.id)).group_by(
                Alert.severity, Alert.status
            )
        )
    ).all()
    alert_samples = [
        ({"severity": str(getattr(sev, "value", sev)),
          "status": str(getattr(st, "value", st))}, c)
        for sev, st, c in alert_rows
    ]

    open_incidents = await _count(
        db, select(func.count(Incident.id)).where(Incident.status == AlertStatus.open)
    )
    resolved_incidents = await _count(
        db, select(func.count(Incident.id)).where(Incident.status == AlertStatus.resolved)
    )

    # SLA breaches among open cases (computed, like the metrics endpoint).
    open_cases = (
        await db.execute(select(Incident).where(Incident.status == AlertStatus.open))
    ).scalars().all()
    sla_breaches = sum(1 for i in open_cases if sla_status(i)["breached"])

    return [
        {"name": "mcpguard_servers", "type": "gauge",
         "help": "MCP servers under management, by status.",
         "samples": server_samples or [({"status": "none"}, 0)]},
        {"name": "mcpguard_suspicious_tools", "type": "gauge",
         "help": "Tool definitions flagged suspicious.",
         "samples": [(None, suspicious_tools)]},
        {"name": "mcpguard_events_total", "type": "counter",
         "help": "MCP messages inspected.",
         "samples": [(None, total_events)]},
        {"name": "mcpguard_events_blocked_total", "type": "counter",
         "help": "MCP messages blocked by policy or backstop.",
         "samples": [(None, blocked_events)]},
        {"name": "mcpguard_alerts", "type": "gauge",
         "help": "Alerts by severity and triage status.",
         "samples": alert_samples or [({"severity": "none", "status": "none"}, 0)]},
        {"name": "mcpguard_incidents_open", "type": "gauge",
         "help": "Open incident cases.",
         "samples": [(None, open_incidents)]},
        {"name": "mcpguard_incidents_resolved", "type": "gauge",
         "help": "Resolved incident cases.",
         "samples": [(None, resolved_incidents)]},
        {"name": "mcpguard_sla_breaches", "type": "gauge",
         "help": "Open incidents past their response-time SLA.",
         "samples": [(None, sla_breaches)]},
    ]

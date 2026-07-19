"""Alert notifications via outbound webhook.

Fires a JSON POST for alerts at/above a configured severity. If no webhook URL
is configured we run in *simulation mode*: the notification is logged and
recorded in the audit trail, satisfying the MVP's alert-simulation requirement
without external infrastructure.

Security decisions (SSRF hardening):
- HTTPS-only by default; plain HTTP allowed only when explicitly opted-in for
  local development (ALERT_WEBHOOK_ALLOW_INSECURE=true).
- The resolved destination must not be a private/loopback/link-local address
  unless ALERT_WEBHOOK_ALLOW_PRIVATE=true. This stops a misconfigured (or
  attacker-supplied) URL from reaching internal services (cloud metadata
  endpoints, internal admin panels).
- Short timeout, no redirects followed, response body ignored.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

import httpx

from app.core.config import settings

logger = logging.getLogger("mcpguard.notify")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


def _is_private_host(hostname: str) -> bool:
    """Resolve and check every address; private/loopback/link-local => True.

    Resolution failure is treated as private (fail closed).
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return True
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


def validate_webhook_url(url: str) -> tuple[bool, str]:
    """Return (ok, reason)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        if not settings.ALERT_WEBHOOK_ALLOW_INSECURE:
            return False, "webhook URL must be https (set ALERT_WEBHOOK_ALLOW_INSECURE for dev)"
    if not parsed.hostname:
        return False, "webhook URL has no host"
    if not settings.ALERT_WEBHOOK_ALLOW_PRIVATE and _is_private_host(parsed.hostname):
        return False, "webhook host resolves to a private/loopback address (SSRF guard)"
    return True, "ok"


# Severity -> Slack visual cues (attachment color bar + a leading emoji).
_SEVERITY_EMOJI = {
    "info": ":information_source:",
    "low": ":large_blue_circle:",
    "medium": ":large_yellow_circle:",
    "high": ":large_orange_circle:",
    "critical": ":red_circle:",
}
_SEVERITY_COLOR = {
    "info": "#3987e5",
    "low": "#0ca30c",
    "medium": "#fab219",
    "high": "#ec835a",
    "critical": "#d03b3b",
}


def _worst_severity(payloads: list[dict]) -> str:
    return max((p["severity"] for p in payloads), key=_severity_rank, default="info")


def build_slack_payload(payloads: list[dict]) -> dict:
    """Build a Slack incoming-webhook message (Block Kit) from alert payloads.

    Pure and dependency-free so it is unit-tested in isolation. Uses a header +
    one context/section block per alert, and an attachment color bar keyed to the
    single worst severity so the message reads at a glance in a channel.
    """
    n = len(payloads)
    worst = _worst_severity(payloads)
    header = (
        f"{_SEVERITY_EMOJI.get(worst, '')} MCPGuard: {n} "
        f"{'alert' if n == 1 else 'alerts'} ({worst.upper()})"
    ).strip()

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": header[:150]}}
    ]
    # Slack caps blocks (~50); keep well under and summarize the remainder.
    shown = payloads[:10]
    for p in shown:
        emoji = _SEVERITY_EMOJI.get(p["severity"], "")
        line = f"{emoji} *{p['rule_id']}* — {p['title']}"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": line[:3000]}})
        if p.get("description"):
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": str(p["description"])[:1000]}],
            })
    if n > len(shown):
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"_…and {n - len(shown)} more_"}],
        })

    # `text` is the notification fallback (required for accessibility/mobile).
    fallback = f"MCPGuard: {n} alert(s), worst {worst.upper()}"
    return {
        "text": fallback,
        "attachments": [{"color": _SEVERITY_COLOR.get(worst, "#3987e5"), "blocks": blocks}],
    }


# PagerDuty Events API v2 severity vocabulary (critical|error|warning|info).
_PD_SEVERITY = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


def build_pagerduty_payload(payloads: list[dict], routing_key: str) -> dict:
    """Build a PagerDuty Events API v2 'trigger' event from alert payloads.

    One event represents the batch, keyed to the worst severity. Individual
    alerts ride along in custom_details so responders see the full context.
    Pure/dependency-free for unit testing.
    """
    worst = _worst_severity(payloads)
    n = len(payloads)
    lead = payloads[0]
    summary = (
        f"MCPGuard: {n} {'alert' if n == 1 else 'alerts'} — "
        f"{lead['rule_id']} {lead['title']}"
    )[:1024]
    # Dedup key groups a burst on the same worst-severity + lead rule into one
    # PagerDuty incident rather than paging N times.
    dedup_key = f"mcpguard-{worst}-{lead['rule_id']}-{lead.get('server_id') or 'none'}"
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key[:255],
        "payload": {
            "summary": summary,
            "source": "mcpguard",
            "severity": _PD_SEVERITY.get(worst, "warning"),
            "custom_details": {
                "alert_count": n,
                "worst_severity": worst,
                "alerts": payloads[:20],
            },
        },
    }


# CEF severity is 0-10; map our five levels onto that scale.
_CEF_SEVERITY = {"info": 1, "low": 3, "medium": 5, "high": 7, "critical": 10}


def _cef_escape(value: str, *, header: bool) -> str:
    """Escape a value per the CEF spec.

    Headers escape backslash and pipe; extension values escape backslash and '='
    (and newlines). Both are applied to strings only.
    """
    s = str(value).replace("\\", "\\\\")
    if header:
        return s.replace("|", "\\|")
    return s.replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def build_cef_payload(payloads: list[dict]) -> str:
    """Build ArcSight CEF text — one line per alert — for SIEM ingestion.

    Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    Pure and unit-tested; the caller sends it as text/plain.
    """
    lines: list[str] = []
    for p in payloads:
        sev = _CEF_SEVERITY.get(p["severity"], 5)
        header = (
            f"CEF:0|MCPGuard|MCPGuard|1.0|{_cef_escape(p['rule_id'], header=True)}"
            f"|{_cef_escape(p['title'], header=True)}|{sev}|"
        )
        ext_parts = [
            f"cs1Label=ruleId cs1={_cef_escape(p['rule_id'], header=False)}",
            f"cs2Label=severity cs2={_cef_escape(p['severity'], header=False)}",
            f"msg={_cef_escape(p.get('description') or '', header=False)}",
        ]
        if p.get("server_id"):
            ext_parts.append(f"cs3Label=serverId cs3={_cef_escape(p['server_id'], header=False)}")
        if p.get("created_at"):
            ext_parts.append(f"rt={_cef_escape(p['created_at'], header=False)}")
        lines.append(header + " ".join(ext_parts))
    return "\n".join(lines)


def _select_format(url: str) -> str:
    """Resolve the payload format for a URL, honoring config and auto-detection."""
    fmt = (settings.ALERT_WEBHOOK_FORMAT or "auto").lower()
    if fmt in ("slack", "generic", "pagerduty", "cef"):
        return fmt
    # auto: detect well-known destinations by host; fall back to generic.
    host = (urlparse(url).hostname or "").lower()
    if host.endswith("slack.com"):
        return "slack"
    if host.endswith("pagerduty.com"):
        return "pagerduty"
    return "generic"


async def notify_alerts(alerts: list) -> int:
    """Send qualifying alerts to the configured webhook. Returns count sent.

    Never raises: notification failures must not break the inspection path.
    """
    min_rank = _severity_rank(settings.ALERT_WEBHOOK_MIN_SEVERITY)
    qualifying = [
        a for a in alerts
        if _severity_rank(str(getattr(a.severity, "value", a.severity))) >= min_rank
    ]
    if not qualifying:
        return 0

    payloads = [
        {
            "id": a.id,
            "rule_id": a.rule_id,
            "title": a.title,
            "severity": str(getattr(a.severity, "value", a.severity)),
            "description": a.description,
            "server_id": a.server_id,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in qualifying
    ]

    url = settings.ALERT_WEBHOOK_URL
    if not url:
        # Simulation mode: log instead of send.
        for p in payloads:
            logger.warning(
                "[ALERT-SIMULATION] %s (%s) rule=%s server=%s",
                p["title"], p["severity"], p["rule_id"], p["server_id"],
            )
        return len(payloads)

    ok, reason = validate_webhook_url(url)
    if not ok:
        logger.error("Webhook not sent: %s", reason)
        return 0

    fmt = _select_format(url)
    # CEF is a text format (SIEM syslog-over-HTTP); everything else is JSON.
    json_body = None
    text_body = None
    if fmt == "slack":
        json_body = build_slack_payload(payloads)
    elif fmt == "pagerduty":
        routing_key = settings.PAGERDUTY_ROUTING_KEY
        if not routing_key:
            logger.error("Webhook not sent: pagerduty format needs PAGERDUTY_ROUTING_KEY")
            return 0
        json_body = build_pagerduty_payload(payloads, routing_key)
    elif fmt == "cef":
        text_body = build_cef_payload(payloads)
    else:
        json_body = {"source": "mcpguard", "alerts": payloads}

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            if text_body is not None:
                await client.post(url, content=text_body,
                                  headers={"Content-Type": "text/plain"})
            else:
                await client.post(url, json=json_body)
        return len(payloads)
    except httpx.HTTPError as exc:
        logger.error("Webhook delivery failed: %s", exc)
        return 0

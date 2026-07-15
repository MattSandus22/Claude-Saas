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

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            await client.post(url, json={"source": "mcpguard", "alerts": payloads})
        return len(payloads)
    except httpx.HTTPError as exc:
        logger.error("Webhook delivery failed: %s", exc)
        return 0

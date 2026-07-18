"""Response-time SLAs for incidents.

Every case carries an implicit promise: someone will *look at it* within a time
budget that scales with severity — a critical case can't sit untouched as long
as a low one. This module computes, for a case, its SLA target and current
status: on-track, due-soon, or breached, based on how long the case stayed
'open' before its first acknowledgement (or, if still open, how long it has been
open so far).

Pure functions, unit-tested in isolation. The clock starts at the case's
first_seen and stops at acknowledged_at (or 'now' while still open).
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import settings
from app.models import Incident, Severity

# Fraction of the target at which we warn "due soon" before an outright breach.
_DUE_SOON_FRACTION = 0.75


def sla_target_seconds(severity: Severity) -> int:
    return {
        Severity.critical: settings.SLA_CRITICAL_SECONDS,
        Severity.high: settings.SLA_HIGH_SECONDS,
        Severity.medium: settings.SLA_MEDIUM_SECONDS,
        Severity.low: settings.SLA_LOW_SECONDS,
        Severity.info: settings.SLA_LOW_SECONDS,
    }.get(severity, settings.SLA_LOW_SECONDS)


def _aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; treat them as UTC for arithmetic."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def sla_status(incident: Incident, *, now: datetime | None = None) -> dict:
    """Return the case's SLA target, elapsed response time, and status.

    status: "met" (acknowledged within target), "breached" (target passed),
    "due_soon" (>= 75% of target elapsed, still open), or "on_track".
    """
    now = now or datetime.now(timezone.utc)
    target = sla_target_seconds(incident.severity)
    start = _aware(incident.first_seen)

    if incident.acknowledged_at is not None:
        elapsed = (_aware(incident.acknowledged_at) - start).total_seconds()
        status = "met" if elapsed <= target else "breached"
    else:
        elapsed = (now - start).total_seconds()
        if elapsed > target:
            status = "breached"
        elif elapsed >= target * _DUE_SOON_FRACTION:
            status = "due_soon"
        else:
            status = "on_track"

    return {
        "target_seconds": target,
        "elapsed_seconds": round(max(0.0, elapsed), 1),
        "acknowledged": incident.acknowledged_at is not None,
        "status": status,
        "breached": status == "breached",
    }

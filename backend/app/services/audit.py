"""Audit logging helper.

Every security-relevant action (login, scan, policy change, alert triage,
quarantine) is recorded. Audit rows are append-only by convention; there is no
API to mutate or delete them.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


async def record(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    detail: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditLog:
    log = AuditLog(actor=actor, action=action, target=target, detail=detail or {})
    db.add(log)
    if commit:
        await db.commit()
    return log

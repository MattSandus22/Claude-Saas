"""First-run bootstrap: seed an admin user and a starter policy.

Idempotent: only seeds when the respective tables are empty. The admin password
comes from settings (env) — never hard-coded in the image.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.models import Policy, Role, User
from app.services.audit import record

logger = logging.getLogger("mcpguard.bootstrap")


async def seed_admin(db: AsyncSession) -> None:
    count = (await db.execute(select(func.count(User.id)))).scalar_one()
    if count:
        return
    admin = User(
        email=settings.FIRST_ADMIN_EMAIL.lower(),
        hashed_password=hash_password(settings.FIRST_ADMIN_PASSWORD),
        role=Role.admin,
    )
    db.add(admin)
    await db.commit()
    await record(db, actor="system", action="bootstrap.seed_admin",
                 target=admin.email)
    logger.warning(
        "Seeded initial admin '%s'. CHANGE THIS PASSWORD IMMEDIATELY.",
        settings.FIRST_ADMIN_EMAIL,
    )


async def seed_default_policy(db: AsyncSession) -> None:
    count = (await db.execute(select(func.count(Policy.id)))).scalar_one()
    if count:
        return
    # A sensible starter policy: block known-destructive tools, require agent id,
    # and deny anything the detection engine scores as high-risk.
    db.add(
        Policy(
            name="Baseline Guardrail",
            description=(
                "Default protective policy: blocks destructive tools, requires an "
                "agent identity, and denies high threat-score messages."
            ),
            enabled=True,
            rules={
                "default": "allow",
                "deny_tools": ["exec_shell", "run_command", "delete_file", "rm"],
                "deny_methods": [],
                # Block on HIGH severity or above. Severity->score mapping is
                # info5/low15/medium35/high65/critical90, so 65 blocks any single
                # high-confidence finding (e.g. prompt injection, exfil).
                "max_threat_score": 65,
                "require_agent_id": True,
            },
        )
    )
    await db.commit()
    logger.info("Seeded default 'Baseline Guardrail' policy.")

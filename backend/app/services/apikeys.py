"""API key generation and verification.

Key format: "mcpg_" + 43 chars of URL-safe randomness (256 bits). Only the
SHA-256 hash is persisted; verification is a single indexed lookup on the hash,
which is constant-time with respect to key content (hash comparison happens in
the DB on an exact match of a fixed-length digest).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiKey

KEY_PREFIX = "mcpg_"


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


async def create_api_key(
    db: AsyncSession, *, name: str, scope: str, created_by: str
) -> tuple[ApiKey, str]:
    """Create a key; returns (record, plaintext). Plaintext is never stored."""
    plaintext = generate_key()
    record = ApiKey(
        name=name,
        prefix=plaintext[: len(KEY_PREFIX) + 6],
        key_hash=hash_key(plaintext),
        scope=scope,
        created_by=created_by,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record, plaintext


async def verify_api_key(db: AsyncSession, presented: str) -> ApiKey | None:
    """Return the active ApiKey matching `presented`, updating last_used_at."""
    if not presented or not presented.startswith(KEY_PREFIX) or len(presented) > 128:
        return None
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.key_hash == hash_key(presented), ApiKey.revoked.is_(False)
        )
    )
    record = result.scalar_one_or_none()
    if record is not None:
        record.last_used_at = datetime.now(timezone.utc)
        await db.commit()
    return record

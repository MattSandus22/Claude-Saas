"""Password hashing and JWT helpers.

Security decisions:
- Passwords hashed with bcrypt (using the maintained `bcrypt` library directly;
  passlib is unmaintained and breaks against modern bcrypt). We never store or
  log plaintext.
- bcrypt silently ignores bytes beyond 72; to support arbitrary-length
  passphrases safely we first SHA-256 the password and base64-encode it, giving
  a fixed 44-byte input that fits under the limit with no truncation surprise.
- JWTs are short-lived and signed HS256 with the env-provided secret.
- Token payloads carry the minimum: subject (user id), role, and expiry.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings


def _prehash(password: str) -> bytes:
    """SHA-256 then base64 so any-length input maps to a fixed 44 bytes."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(plain), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str, role: str, expires_minutes: int | None = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload: dict[str, Any] = {
        "sub": str(subject),
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None

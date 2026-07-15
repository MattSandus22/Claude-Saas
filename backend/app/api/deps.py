"""Auth dependencies and RBAC guards."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models import Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")
# Variant that doesn't auto-401, for endpoints that also accept an API key.
oauth2_scheme_optional = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/login", auto_error=False
)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    creds_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise creds_exc
    user = await db.get(User, payload["sub"])
    if user is None or not user.is_active:
        raise creds_exc
    return user


def require_role(*roles: Role):
    """Dependency factory enforcing that the user holds one of `roles`."""

    async def _guard(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges for this action",
            )
        return user

    return _guard


require_admin = require_role(Role.admin)


class Principal:
    """Unified identity for endpoints reachable by users OR integration keys."""

    def __init__(self, *, actor: str, kind: str):
        self.actor = actor  # user email or "apikey:<name>"
        self.kind = kind  # "user" | "api_key"


async def get_ingest_principal(
    request: Request,
    token: str | None = Depends(oauth2_scheme_optional),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    """Authenticate either a logged-in user (JWT) or an integration (X-API-Key).

    Used by the ingestion surface (/inspect, /servers/scan, server registration)
    so agent gateways and CI scanners can integrate without a user session.
    API keys carry the narrow 'ingest' scope only — they can never read data,
    manage users, or change policies.
    """
    api_key = request.headers.get("x-api-key")
    if api_key:
        from app.services.apikeys import verify_api_key

        record = await verify_api_key(db, api_key)
        if record is not None:
            return Principal(actor=f"apikey:{record.name}", kind="api_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key"
        )

    if token:
        payload = decode_access_token(token)
        if payload and "sub" in payload:
            user = await db.get(User, payload["sub"])
            if user is not None and user.is_active:
                return Principal(actor=user.email, kind="user")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Provide a bearer token or X-API-Key",
        headers={"WWW-Authenticate": "Bearer"},
    )

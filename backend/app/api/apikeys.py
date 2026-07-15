"""API key management endpoints (admin-only).

The plaintext key is returned exactly once, in the creation response. There is
no endpoint to retrieve it later — only revocation and metadata listing.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.session import get_db
from app.models import ApiKey, User
from app.schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyOut
from app.services.apikeys import create_api_key
from app.services.audit import record

router = APIRouter(prefix="/apikeys", tags=["apikeys"])


@router.post("", response_model=ApiKeyCreated, status_code=201)
async def create_key(
    body: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    api_key, plaintext = await create_api_key(
        db, name=body.name, scope=body.scope, created_by=admin.email
    )
    await record(db, actor=admin.email, action="apikey.create", target=api_key.id,
                 detail={"name": body.name, "scope": body.scope})
    return ApiKeyCreated(**ApiKeyOut.model_validate(api_key).model_dump(), key=plaintext)


@router.get("", response_model=list[ApiKeyOut])
async def list_keys(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    result = await db.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))
    return list(result.scalars().all())


@router.post("/{key_id}/revoke", response_model=ApiKeyOut)
async def revoke_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    api_key = await db.get(ApiKey, key_id)
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.revoked = True
    await db.commit()
    await db.refresh(api_key)
    await record(db, actor=admin.email, action="apikey.revoke", target=key_id)
    return api_key

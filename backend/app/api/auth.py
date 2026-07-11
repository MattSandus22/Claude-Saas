"""Authentication + user management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models import Role, User
from app.schemas import Token, UserCreate, UserOut
from app.services.audit import record

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """OAuth2 password login. `username` field carries the email.

    Security: identical error for unknown-user and bad-password to avoid user
    enumeration; password verified with constant-time bcrypt compare.
    """
    result = await db.execute(select(User).where(User.email == form.username.lower()))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    token = create_access_token(subject=user.id, role=user.role.value)
    await record(db, actor=user.email, action="auth.login", target=user.id)
    return Token(access_token=token)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)):
    return user


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Create a user. Admin-only (RBAC)."""
    email = body.email.lower()
    exists = await db.execute(select(User).where(User.email == email))
    if exists.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(
        email=email,
        hashed_password=hash_password(body.password),
        role=Role(body.role),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await record(db, actor=admin.email, action="user.create", target=user.id,
                 detail={"role": body.role})
    return user


@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())

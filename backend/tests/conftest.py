"""Pytest fixtures: isolated in-memory DB + authenticated test client."""

from __future__ import annotations

import asyncio
import os

import pytest
import pytest_asyncio

# Force an isolated in-memory SQLite DB and a fixed secret BEFORE app import.
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-secret-not-for-production"
os.environ["ENV"] = "test"
os.environ["FIRST_ADMIN_EMAIL"] = "admin@test.local"
os.environ["FIRST_ADMIN_PASSWORD"] = "TestAdminPass123!"

from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.db.session import AsyncSessionLocal, engine, init_db  # noqa: E402
from app.db.session import Base  # noqa: E402
from app.main import app  # noqa: E402
from app.services.bootstrap import seed_admin, seed_default_policy  # noqa: E402


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _prepare_db():
    # Create schema once for the in-memory DB and seed baseline rows.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        await seed_admin(db)
        await seed_default_policy(db)
    yield


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin_token(client) -> str:
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "admin@test.local", "password": "TestAdminPass123!"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest_asyncio.fixture
async def auth_headers(admin_token) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}

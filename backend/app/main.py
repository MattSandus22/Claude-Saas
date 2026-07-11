"""MCPGuard FastAPI application entrypoint.

Security-relevant app config:
- Security headers on every response (CSP, X-Frame-Options, nosniff, HSTS).
- CORS restricted to configured origins (no wildcard with credentials).
- Rate limiting middleware on the API surface.
- Global handler converts unexpected errors to a generic 500 (no stack leakage).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import alerts, auth, dashboard, events, policies, servers
from app.core.config import settings
from app.core.ratelimit import RateLimitMiddleware
from app.db.session import AsyncSessionLocal, init_db
from app.services.bootstrap import seed_admin, seed_default_policy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcpguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async with AsyncSessionLocal() as db:
        await seed_admin(db)
        await seed_default_policy(db)
    if not settings.REDIS_URL:
        logger.warning(
            "REDIS_URL not set: rate limiting uses an in-process counter. "
            "Set REDIS_URL in multi-replica production deployments."
        )
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise MCP Security & Governance Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — explicit origins only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting.
app.add_middleware(RateLimitMiddleware)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    # HSTS only meaningful over HTTPS; harmless otherwise for API clients.
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Never leak internal details to clients.
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "service": settings.PROJECT_NAME, "version": "0.1.0"}


# Mount routers under the versioned prefix.
_p = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=_p)
app.include_router(servers.router, prefix=_p)
app.include_router(events.router, prefix=_p)
app.include_router(alerts.router, prefix=_p)
app.include_router(policies.router, prefix=_p)
app.include_router(dashboard.router, prefix=_p)

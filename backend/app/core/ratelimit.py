"""Rate limiting middleware.

Uses Redis for a distributed fixed-window counter when REDIS_URL is set;
otherwise falls back to an in-process counter (fine for single-instance dev).
Keyed by authenticated user id when available, else client IP. This throttles
brute-force auth and abusive event ingestion.

Security note: the fallback is per-process, so behind multiple replicas without
Redis the effective limit multiplies. Production deployments should set
REDIS_URL. We log/emit a warning at startup in that case.
"""

from __future__ import annotations

import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import settings

try:  # redis is optional at runtime
    import redis.asyncio as aioredis
except Exception:  # pragma: no cover
    aioredis = None


class _InProcessWindow:
    """Simple fixed-window counter kept in memory."""

    def __init__(self) -> None:
        self._buckets: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))

    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.time()
        count, start = self._buckets[key]
        if now - start >= window:
            count, start = 0, now
        count += 1
        self._buckets[key] = (count, start)
        remaining = max(0, limit - count)
        return count <= limit, remaining


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        self._mem = _InProcessWindow()
        self._redis = None
        if settings.REDIS_URL and aioredis is not None:
            try:
                self._redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            except Exception:
                self._redis = None

    async def _hit_redis(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        # INCR + EXPIRE on first hit = fixed window.
        try:
            current = await self._redis.incr(key)
            if current == 1:
                await self._redis.expire(key, window)
            return current <= limit, max(0, limit - current)
        except Exception:
            # If Redis is unreachable, fail open to a memory counter rather than
            # blocking all traffic on an infra hiccup.
            return self._mem.hit(key, limit, window)

    def _client_identity(self, request: Request) -> str:
        # Prefer authenticated subject if the auth layer set it; else IP.
        auth = request.headers.get("authorization", "")
        if auth:
            return f"tok:{hash(auth) & 0xFFFFFFFF}"
        client = request.client.host if request.client else "unknown"
        return f"ip:{client}"

    async def dispatch(self, request: Request, call_next):
        # Only rate-limit the API surface; skip health/docs/static.
        path = request.url.path
        if not path.startswith(settings.API_V1_PREFIX):
            return await call_next(request)

        limit = settings.RATE_LIMIT_REQUESTS
        window = settings.RATE_LIMIT_WINDOW_SECONDS
        ident = self._client_identity(request)
        key = f"rl:{ident}:{int(time.time() // window)}"

        if self._redis is not None:
            allowed, remaining = await self._hit_redis(key, limit, window)
        else:
            allowed, remaining = self._mem.hit(ident, limit, window)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Slow down."},
                headers={"Retry-After": str(window)},
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

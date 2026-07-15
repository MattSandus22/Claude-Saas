"""Application configuration.

Security decision: all secrets come from environment variables (12-factor).
We fail fast in production if a JWT secret is not provided, so a deploy can
never silently fall back to a predictable key. In development we generate an
ephemeral key so local runs work without setup, but tokens do not survive a
restart (acceptable for dev, never used in prod).
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ENV: str = Field(default="development")
    PROJECT_NAME: str = "MCPGuard"
    API_V1_PREFIX: str = "/api/v1"

    # Database. Defaults to a local SQLite file so the app is runnable with zero
    # infrastructure; production should set DATABASE_URL to a Postgres DSN.
    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./mcpguard.db")

    # Auth
    JWT_SECRET: str = Field(default="")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Redis (optional). If unset, rate limiting falls back to an in-process store.
    REDIS_URL: str | None = Field(default=None)

    # Rate limiting: requests allowed per window per client identity.
    RATE_LIMIT_REQUESTS: int = 120
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # CORS: comma-separated origins. Never use "*" together with credentials.
    CORS_ORIGINS: List[str] = Field(default=["http://localhost:3000"])

    # Alert webhook. Unset => simulation mode (alerts logged, not sent).
    ALERT_WEBHOOK_URL: str | None = Field(default=None)
    ALERT_WEBHOOK_MIN_SEVERITY: str = "high"
    # Dev-only escape hatches for the SSRF guard; never enable in production.
    ALERT_WEBHOOK_ALLOW_INSECURE: bool = False
    ALERT_WEBHOOK_ALLOW_PRIVATE: bool = False

    # Bootstrap admin (seeded on first run if no users exist).
    FIRST_ADMIN_EMAIL: str = "admin@mcpguard.local"
    FIRST_ADMIN_PASSWORD: str = "ChangeMe!Admin123"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @field_validator("JWT_SECRET", mode="before")
    @classmethod
    def _ensure_secret(cls, v, info):
        if v:
            return v
        # No secret provided. In production this is a hard error.
        env = (info.data.get("ENV") or "development").lower()
        if env == "production":
            raise ValueError(
                "JWT_SECRET must be set in production. Refusing to start with a "
                "generated key because it would invalidate tokens on restart and "
                "may be guessable across replicas."
            )
        # Dev-only ephemeral key.
        return secrets.token_urlsafe(48)

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

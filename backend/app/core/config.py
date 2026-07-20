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
from typing import Annotated, List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


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
    # NoDecode: pydantic-settings otherwise tries to JSON-parse list-typed env
    # vars before our validator runs, so a plain comma-separated string (the
    # documented .env.example format) would crash at startup. NoDecode hands
    # the raw string straight to the "before" validator below.
    CORS_ORIGINS: Annotated[List[str], NoDecode] = Field(
        default=["http://localhost:3000"]
    )

    # Behavioral anomaly thresholds (R6-R8). Tune per deployment; conservative
    # defaults. Window values are seconds.
    ANOMALY_RAPID_FIRE_WINDOW_S: int = 60
    ANOMALY_RAPID_FIRE_THRESHOLD: int = 30
    ANOMALY_BLOCKED_WINDOW_S: int = 600
    ANOMALY_BLOCKED_THRESHOLD: int = 3
    ANOMALY_ENUM_WINDOW_S: int = 300
    ANOMALY_ENUM_DISTINCT_TOOLS: int = 10
    ANOMALY_DEDUPE_WINDOW_S: int = 600

    # Statistical baseline (R10): per-agent learned volume anomaly.
    BASELINE_BUCKET_SECONDS: int = 3600  # size of each activity bucket (1h)
    BASELINE_WINDOW_BUCKETS: int = 168  # history window (7 days of hours)
    BASELINE_MIN_OBSERVATIONS: int = 5  # active buckets required before scoring
    BASELINE_Z_THRESHOLD: float = 3.0  # std deviations above mean to flag

    # Tool-sequence baseline (R11): per-agent tool-transition (bigram) anomaly.
    SEQUENCE_WINDOW_SECONDS: int = 604800  # history window to learn from (7 days)
    SEQUENCE_MIN_TRANSITIONS: int = 20  # learned transitions required before scoring
    SEQUENCE_RARE_PROB: float = 0.02  # P(dst|src) at/below this is "rare"

    # Data-volume baseline (R12): per-agent payload-byte volume anomaly.
    DATAVOL_BUCKET_SECONDS: int = 3600  # size of each volume bucket (1h)
    DATAVOL_WINDOW_BUCKETS: int = 168  # history window (7 days of hours)
    DATAVOL_MIN_OBSERVATIONS: int = 5  # active buckets required before scoring
    DATAVOL_Z_THRESHOLD: float = 3.0  # std deviations above mean to flag
    DATAVOL_MIN_BYTES: int = 10_000  # absolute floor to suppress tiny-volume noise

    # Cross-agent correlation (R13): coordinated multi-agent campaign detection.
    CORRELATION_WINDOW_SECONDS: int = 300  # campaign observation window (5 min)
    CORRELATION_MIN_AGENTS: int = 8  # distinct agents on one server -> fan-in surge
    CORRELATION_MIN_BLOCKED_AGENTS: int = 3  # distinct blocked agents -> coordinated burst

    # Incident case management: window in which new alerts join an open incident
    # for the same subject (server + agent) instead of opening a fresh case.
    INCIDENT_WINDOW_SECONDS: int = 3600  # 1 hour

    # Response-time SLAs (seconds to first acknowledgement), by severity. A case
    # breaches if it is still 'open' past its target. Defaults: tighter for worse
    # severities. Env-tunable per deployment.
    SLA_CRITICAL_SECONDS: int = 900  # 15 min
    SLA_HIGH_SECONDS: int = 3600  # 1 hour
    SLA_MEDIUM_SECONDS: int = 14400  # 4 hours
    SLA_LOW_SECONDS: int = 86400  # 24 hours

    # Alert webhook. Unset => simulation mode (alerts logged, not sent).
    ALERT_WEBHOOK_URL: str | None = Field(default=None)
    ALERT_WEBHOOK_MIN_SEVERITY: str = "high"
    # Payload shape: "auto" | "generic" | "slack" | "pagerduty" | "cef".
    #   generic   -> {source, alerts} JSON
    #   slack     -> Slack incoming-webhook Block Kit message
    #   pagerduty -> PagerDuty Events API v2 enqueue event
    #   cef       -> ArcSight CEF text lines (Splunk/QRadar/generic SIEM)
    # "auto" detects Slack (hooks.slack.com) and PagerDuty (events.pagerduty.com),
    # falling back to generic. CEF must be selected explicitly.
    ALERT_WEBHOOK_FORMAT: str = "auto"
    # PagerDuty Events API v2 routing key (integration key). Required for the
    # pagerduty format; sent in the event body, never logged.
    PAGERDUTY_ROUTING_KEY: str | None = Field(default=None)
    # Dev-only escape hatches for the SSRF guard; never enable in production.
    ALERT_WEBHOOK_ALLOW_INSECURE: bool = False
    ALERT_WEBHOOK_ALLOW_PRIVATE: bool = False

    # Prometheus /metrics exposition. Disabled by default (secure default:
    # internal counts should not be exposed unauthenticated). When a token is
    # set, the root-level /metrics endpoint requires `Authorization: Bearer
    # <token>`; when unset, /metrics returns 404.
    PROMETHEUS_BEARER_TOKEN: str | None = Field(default=None)

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

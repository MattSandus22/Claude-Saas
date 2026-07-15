"""SQLAlchemy ORM models for MCPGuard.

Entities:
- User: auth identity with a role (admin/analyst).
- MCPServer: a discovered or registered MCP server instance.
- MCPTool: a tool definition exposed by a server (scanned for poisoning).
- MCPEvent: a monitored MCP message (tool call, resource access, etc.).
- Alert: a threat finding raised by the detection engine.
- Policy: policy-as-code rule set governing allowed tools/actions.
- AuditLog: immutable-ish record of user/system actions.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ServerStatus(str, enum.Enum):
    discovered = "discovered"
    active = "active"
    quarantined = "quarantined"
    inactive = "inactive"


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.analyst, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class MCPServer(Base):
    __tablename__ = "mcp_servers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Transport endpoint or command (e.g. "https://x/mcp", "stdio: npx server").
    endpoint: Mapped[str] = mapped_column(String(1024), nullable=False)
    transport: Mapped[str] = mapped_column(String(32), default="unknown")  # stdio|http|sse
    source: Mapped[str] = mapped_column(String(64), default="manual")  # scan|runtime|manual
    status: Mapped[ServerStatus] = mapped_column(
        Enum(ServerStatus), default=ServerStatus.discovered
    )
    # Highest risk score observed for this server (0-100).
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    server_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    tools: Mapped[list["MCPTool"]] = relationship(
        back_populates="server", cascade="all, delete-orphan"
    )


class MCPTool(Base):
    __tablename__ = "mcp_tools"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    server_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    # Raw input schema as declared by the tool.
    input_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    # Detection: whether this tool definition looks poisoned/suspicious.
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    # SHA-256 over (name, description, input_schema) — the attestation baseline
    # for drift detection. A changed fingerprint on re-registration means the
    # server altered an advertised tool after approval (rug-pull signal).
    fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    server: Mapped["MCPServer"] = relationship(back_populates="tools")


class MCPEvent(Base):
    __tablename__ = "mcp_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    server_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="SET NULL"), index=True, nullable=True
    )
    # MCP method, e.g. "tools/call", "resources/read", "prompts/get".
    method: Mapped[str] = mapped_column(String(128), index=True)
    tool_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    agent_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    direction: Mapped[str] = mapped_column(String(16), default="request")  # request|response
    # Sanitized payload (never trusted as executable).
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    # Populated by detection engine.
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    server_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="SET NULL"), index=True, nullable=True
    )
    event_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_events.id", ondelete="SET NULL"), nullable=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.medium)
    status: Mapped[AlertStatus] = mapped_column(Enum(AlertStatus), default=AlertStatus.open)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Declarative rule document (see policy engine). Stored as-is.
    rules: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class PolicyVersion(Base):
    """Immutable snapshot of a policy at each change.

    Written on create, update, and rollback — never mutated or deleted — so the
    full history of what was enforced (and by whom it was changed) is auditable
    and any prior version can be restored.
    """

    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    rules: Mapped[dict] = mapped_column(JSON, default=dict)
    changed_by: Mapped[str] = mapped_column(String(255), default="system")
    change_note: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ApiKey(Base):
    """Programmatic access key for integrations (gateways, CI scanners).

    Security: only a SHA-256 hash of the key is stored — the plaintext is shown
    exactly once at creation. High-entropy random keys make unsalted SHA-256
    safe here (no dictionary to attack), and hashing must be deterministic to
    allow O(1) lookup by hash.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # First characters of the key, kept for display/identification only.
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    # What the key may do. MVP scopes: "ingest" (inspect/scan) is the only one.
    scope: Mapped[str] = mapped_column(String(32), default="ingest")
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    actor: Mapped[str] = mapped_column(String(255), index=True)  # user email or "system"
    action: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )

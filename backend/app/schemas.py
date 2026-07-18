"""Pydantic request/response schemas.

These form the validated boundary between untrusted input and the app. All MCP
payloads pass through here before any processing, giving us a single choke point
for size limits and type enforcement.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

# Enterprise security tools frequently run on internal domains (.local, .corp,
# .internal), which strict RFC email validators reject. We do a structural check
# and normalize to lowercase, deliberately permitting internal TLDs.
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def _validate_email(v: str) -> str:
    v = v.strip().lower()
    if len(v) > 320 or not _EMAIL_RE.match(v):
        raise ValueError("invalid email address")
    return v


Email = Annotated[str, AfterValidator(_validate_email)]


# ---- Auth ----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: Email
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    email: Email
    password: str = Field(min_length=10, max_length=256)
    role: Literal["admin", "analyst"] = "analyst"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: Email
    role: str
    is_active: bool
    created_at: datetime


# ---- Servers / tools ----
class ToolDefinition(BaseModel):
    name: str = Field(max_length=255)
    description: str = Field(default="", max_length=20_000)
    input_schema: dict[str, Any] = Field(default_factory=dict)


class MCPServerCreate(BaseModel):
    name: str = Field(max_length=255)
    endpoint: str = Field(max_length=1024)
    transport: Literal["stdio", "http", "sse", "unknown"] = "unknown"
    source: Literal["scan", "runtime", "manual"] = "manual"
    tools: list[ToolDefinition] = Field(default_factory=list, max_length=500)


class ToolOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: str
    is_suspicious: bool
    risk_score: float


class MCPServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    endpoint: str
    transport: str
    source: str
    status: str
    risk_score: float
    first_seen: datetime
    last_seen: datetime
    tools: list[ToolOut] = []


# ---- Discovery / scanning ----
class ScanRequest(BaseModel):
    """A static scan submission: file contents keyed by path.

    We accept file *contents* (not disk paths) so the scanner never touches the
    server's filesystem and cannot be abused for path traversal / SSRF.
    """

    files: dict[str, str] = Field(
        default_factory=dict,
        description="Map of filename -> file text content",
        max_length=2000,
    )


class ScanFinding(BaseModel):
    file: str
    kind: str
    detail: str
    endpoint: str | None = None
    transport: str | None = None


class ScanResult(BaseModel):
    discovered_servers: int
    findings: list[ScanFinding]
    server_ids: list[str]


# ---- Events / monitoring ----
class MCPMessageIn(BaseModel):
    """An MCP message reported to MCPGuard for monitoring/inspection."""

    server_id: str | None = None
    server_endpoint: str | None = Field(default=None, max_length=1024)
    method: str = Field(max_length=128)
    tool_name: str | None = Field(default=None, max_length=255)
    agent_id: str | None = Field(default=None, max_length=255)
    direction: Literal["request", "response"] = "request"
    # Bounded to prevent memory-exhaustion from a malicious reporter.
    payload: dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    server_id: str | None
    method: str
    tool_name: str | None
    agent_id: str | None
    direction: str
    threat_score: float
    blocked: bool
    created_at: datetime


class InspectResult(BaseModel):
    event_id: str | None
    threat_score: float
    blocked: bool
    allowed_by_policy: bool
    alerts: list["AlertOut"]
    reasons: list[str]


# ---- Alerts ----
class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    server_id: str | None
    rule_id: str
    title: str
    description: str
    severity: str
    status: str
    evidence: dict[str, Any]
    incident_id: str | None = None
    created_at: datetime


class AlertUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


# ---- Incidents (case management) ----
class SlaStatus(BaseModel):
    target_seconds: int
    elapsed_seconds: float
    acknowledged: bool
    status: Literal["on_track", "due_soon", "breached", "met"]
    breached: bool


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    title: str
    server_id: str | None
    agent_id: str | None
    severity: str
    status: str
    alert_count: int
    rule_ids: list[str]
    assignee_id: str | None = None
    first_seen: datetime
    last_seen: datetime
    sla: SlaStatus | None = None


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut] = []


class IncidentUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


class IncidentAssign(BaseModel):
    # Assign to a user by email; None unassigns.
    assignee_email: Email | None = None


class RecommendedActionOut(BaseModel):
    action: Literal["contain_agent", "quarantine_server"]
    target: str
    reason: str
    urgency: Literal["recommended", "urgent"]
    triggering_rules: list[str]


class ApplyActionRequest(BaseModel):
    action: Literal["contain_agent", "quarantine_server"]


class ApplyActionResult(BaseModel):
    applied: str
    target: str
    detail: str


# ---- Policies ----
class PolicyCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str = Field(default="", max_length=5000)
    enabled: bool = True
    rules: dict[str, Any] = Field(default_factory=dict)


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: str
    enabled: bool
    rules: dict[str, Any]
    created_at: datetime
    updated_at: datetime


# ---- API keys ----
class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scope: Literal["ingest"] = "ingest"


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    prefix: str
    scope: str
    revoked: bool
    last_used_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    """Returned only at creation time; `key` is never retrievable again."""

    key: str


class PolicyVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    policy_id: str
    version: int
    name: str
    description: str
    enabled: bool
    rules: dict[str, Any]
    changed_by: str
    change_note: str
    created_at: datetime


# ---- Response actions ----
class BlockedAgents(BaseModel):
    blocked_agents: list[str]


# ---- Policy simulation (dry-run) ----
class SimulateRequest(BaseModel):
    """Evaluate a message against detection + policy WITHOUT persisting anything.

    `candidate_policies` optionally overrides the stored policies, so an analyst
    can test a policy edit before saving it. When omitted, current enabled
    policies are used.
    """

    method: str = Field(max_length=128)
    tool_name: str | None = Field(default=None, max_length=255)
    agent_id: str | None = Field(default=None, max_length=255)
    payload: dict[str, Any] = Field(default_factory=dict)
    candidate_policies: list[PolicyCreate] | None = None


class SimulateResult(BaseModel):
    threat_score: float
    blocked: bool
    allowed_by_policy: bool
    reasons: list[str]
    findings: list[dict[str, Any]]
    used_candidate_policies: bool


# ---- Dashboard ----
class DashboardStats(BaseModel):
    total_servers: int
    active_servers: int
    quarantined_servers: int
    suspicious_tools: int
    total_events: int
    blocked_events: int
    open_alerts: int
    open_incidents: int = 0
    alerts_by_severity: dict[str, int]
    events_last_7d: list[dict[str, Any]]
    top_risky_servers: list[dict[str, Any]]


InspectResult.model_rebuild()

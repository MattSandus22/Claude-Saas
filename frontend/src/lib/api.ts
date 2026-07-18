/**
 * Typed API client for the MCPGuard backend.
 *
 * Security note: the JWT is kept in memory + localStorage on the client. For a
 * production hardening pass this should move to an httpOnly cookie set by a thin
 * Next.js route handler so the token is not reachable from JS (XSS resistance).
 * We keep it simple for the MVP and document the tradeoff.
 */

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000/api/v1";

const TOKEN_KEY = "mcpguard_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  window.localStorage.removeItem(TOKEN_KEY);
}

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined" && window.location.pathname !== "/login") {
      window.location.href = "/login";
    }
    throw new ApiError(401, "Unauthorized");
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* ignore parse errors */
    }
    throw new ApiError(res.status, typeof detail === "string" ? detail : "Request failed");
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export async function login(email: string, password: string): Promise<string> {
  // Backend uses OAuth2 password form (username = email).
  const body = new URLSearchParams({ username: email, password });
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(res.status, b.detail || "Login failed");
  }
  const data = await res.json();
  setToken(data.access_token);
  return data.access_token;
}

// ---- Types (mirror backend schemas) ----
export interface CurrentUser {
  id: string;
  email: string;
  role: "admin" | "analyst";
  is_active: boolean;
  created_at: string;
}

export interface Tool {
  id: string;
  name: string;
  description: string;
  is_suspicious: boolean;
  risk_score: number;
}

export interface MCPServer {
  id: string;
  name: string;
  endpoint: string;
  transport: string;
  source: string;
  status: string;
  risk_score: number;
  first_seen: string;
  last_seen: string;
  tools: Tool[];
}

export interface Alert {
  id: string;
  server_id: string | null;
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  evidence: Record<string, unknown>;
  incident_id: string | null;
  created_at: string;
}

export interface SlaStatus {
  target_seconds: number;
  elapsed_seconds: number;
  acknowledged: boolean;
  status: "on_track" | "due_soon" | "breached" | "met";
  breached: boolean;
}

export interface Incident {
  id: string;
  title: string;
  server_id: string | null;
  agent_id: string | null;
  severity: string;
  status: string;
  alert_count: number;
  rule_ids: string[];
  assignee_id: string | null;
  first_seen: string;
  last_seen: string;
  sla: SlaStatus | null;
}

export interface IncidentDetail extends Incident {
  alerts: Alert[];
}

export interface RecommendedAction {
  action: "contain_agent" | "quarantine_server";
  target: string;
  reason: string;
  urgency: "recommended" | "urgent";
  triggering_rules: string[];
}

export interface IncidentMetrics {
  total_incidents: number;
  open_incidents: number;
  resolved_incidents: number;
  mttr_seconds: number | null;
  sla_breaches: number;
  by_severity: Record<string, number>;
  resolved_last_days: { date: string; resolved: number }[];
}

export interface TimelineEvent {
  at: string;
  kind: "opened" | "alert" | "action";
  detail: string;
  severity?: string;
}

export interface MCPEvent {
  id: string;
  server_id: string | null;
  method: string;
  tool_name: string | null;
  agent_id: string | null;
  direction: string;
  threat_score: number;
  blocked: boolean;
  created_at: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rules: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  total_servers: number;
  active_servers: number;
  quarantined_servers: number;
  suspicious_tools: number;
  total_events: number;
  blocked_events: number;
  open_alerts: number;
  open_incidents: number;
  alerts_by_severity: Record<string, number>;
  events_last_7d: { date: string; total: number; blocked: number }[];
  top_risky_servers: { id: string; name: string; risk_score: number; status: string }[];
}

export interface InspectResult {
  event_id: string | null;
  threat_score: number;
  blocked: boolean;
  allowed_by_policy: boolean;
  alerts: Alert[];
  reasons: string[];
}

export interface SimulateResult {
  threat_score: number;
  blocked: boolean;
  allowed_by_policy: boolean;
  reasons: string[];
  findings: { rule_id: string; title: string; severity: string; detail: string }[];
  used_candidate_policies: boolean;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scope: string;
  revoked: boolean;
  last_used_at: string | null;
  created_at: string;
}

export interface ApiKeyCreated extends ApiKey {
  /** Plaintext key — returned exactly once at creation, never again. */
  key: string;
}

// ---- Endpoints ----
export const api = {
  me: () => request<CurrentUser>("/auth/me"),
  stats: () => request<DashboardStats>("/dashboard/stats"),
  servers: () => request<MCPServer[]>("/servers"),
  scan: (files: Record<string, string>) =>
    request<{ discovered_servers: number; findings: unknown[]; server_ids: string[] }>(
      "/servers/scan",
      { method: "POST", body: JSON.stringify({ files }) }
    ),
  quarantine: (id: string) =>
    request<MCPServer>(`/servers/${id}/quarantine`, { method: "POST" }),
  events: (params = "") => request<MCPEvent[]>(`/events${params}`),
  inspect: (msg: Record<string, unknown>) =>
    request<InspectResult>("/inspect", { method: "POST", body: JSON.stringify(msg) }),
  alerts: (params = "") => request<Alert[]>(`/alerts${params}`),
  updateAlert: (id: string, status: string) =>
    request<Alert>(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  policies: () => request<Policy[]>("/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    request<Policy>("/policies", { method: "POST", body: JSON.stringify(body) }),
  deletePolicy: (id: string) => request<void>(`/policies/${id}`, { method: "DELETE" }),
  audit: () => request<Record<string, unknown>[]>("/audit"),
  simulate: (body: Record<string, unknown>) =>
    request<SimulateResult>("/policies/simulate", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  blockedAgents: () => request<{ blocked_agents: string[] }>("/agents/blocked"),
  blockAgent: (agentId: string) =>
    request<{ blocked_agents: string[] }>(
      `/agents/${encodeURIComponent(agentId)}/block`,
      { method: "POST" }
    ),
  unblockAgent: (agentId: string) =>
    request<{ blocked_agents: string[] }>(
      `/agents/${encodeURIComponent(agentId)}/unblock`,
      { method: "POST" }
    ),
  incidents: (params = "") => request<Incident[]>(`/incidents${params}`),
  incident: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  updateIncident: (id: string, status: string) =>
    request<IncidentDetail>(`/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  incidentMetrics: () => request<IncidentMetrics>("/incidents/metrics"),
  assignIncident: (id: string, assignee_email: string | null) =>
    request<Incident>(`/incidents/${id}/assign`, {
      method: "POST",
      body: JSON.stringify({ assignee_email }),
    }),
  incidentTimeline: (id: string) =>
    request<{ incident_id: string; events: TimelineEvent[] }>(
      `/incidents/${id}/timeline`
    ),
  incidentActions: (id: string) =>
    request<RecommendedAction[]>(`/incidents/${id}/recommended-actions`),
  applyIncidentAction: (id: string, action: string) =>
    request<{ applied: string; target: string; detail: string }>(
      `/incidents/${id}/apply-action`,
      { method: "POST", body: JSON.stringify({ action }) }
    ),
  apiKeys: () => request<ApiKey[]>("/apikeys"),
  createApiKey: (name: string) =>
    request<ApiKeyCreated>("/apikeys", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),
  revokeApiKey: (id: string) =>
    request<ApiKey>(`/apikeys/${id}/revoke`, { method: "POST" }),
};

export { ApiError };

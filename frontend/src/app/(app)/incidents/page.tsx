"use client";

import { useEffect, useState } from "react";
import {
  api,
  type Incident,
  type IncidentDetail,
  type IncidentMetrics,
  type RecommendedAction,
  type TimelineEvent,
} from "@/lib/api";
import { Card, Badge, Button, EmptyState, StatTile } from "@/components/ui";
import { formatDate, severityColor, statusColor } from "@/lib/utils";
import { useAuth } from "@/lib/auth";

const STATUS_FILTERS = ["all", "open", "acknowledged", "resolved"];

function formatDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

export default function IncidentsPage() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<IncidentMetrics | null>(null);
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [actions, setActions] = useState<RecommendedAction[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [notice, setNotice] = useState<string | null>(null);

  async function load() {
    try {
      const q = filter === "all" ? "" : `?status=${filter}`;
      const [list, m] = await Promise.all([api.incidents(q), api.incidentMetrics()]);
      setIncidents(list);
      setMetrics(m);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function toggle(id: string) {
    if (expanded === id) {
      setExpanded(null);
      setDetail(null);
      setActions([]);
      setTimeline([]);
      return;
    }
    setExpanded(id);
    setNotice(null);
    const [d, a, tl] = await Promise.all([
      api.incident(id),
      api.incidentActions(id),
      api.incidentTimeline(id),
    ]);
    setDetail(d);
    setActions(a);
    setTimeline(tl.events);
  }

  async function triage(id: string, status: string) {
    await api.updateIncident(id, status);
    setExpanded(null);
    setDetail(null);
    setActions([]);
    setTimeline([]);
    load();
  }

  async function applyAction(id: string, action: string) {
    try {
      const res = await api.applyIncidentAction(id, action);
      setNotice(res.detail);
      setActions(await api.incidentActions(id));
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Failed to apply action");
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Incidents</h1>
          <p className="text-sm text-muted">
            Related alerts grouped into cases by subject. Triage the whole case at once.
          </p>
        </div>
        <div className="flex gap-2">
          {STATUS_FILTERS.map((f) => (
            <Button key={f} variant={filter === f ? "primary" : "ghost"} onClick={() => setFilter(f)}>
              {f}
            </Button>
          ))}
        </div>
      </div>

      {metrics && (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatTile label="Open cases" value={metrics.open_incidents} />
          <StatTile label="Resolved" value={metrics.resolved_incidents} />
          <StatTile label="Total" value={metrics.total_incidents} />
          <StatTile
            label="Mean time to resolve"
            value={formatDuration(metrics.mttr_seconds)}
          />
        </div>
      )}

      {error && <EmptyState message={error} />}
      {incidents.length === 0 && !error ? (
        <EmptyState message="No incidents match this filter." />
      ) : (
        <div className="space-y-3">
          {incidents.map((inc) => (
            <Card key={inc.id} className="space-y-3">
              <div className="flex items-start justify-between gap-4">
                <button
                  onClick={() => toggle(inc.id)}
                  className="min-w-0 flex-1 text-left"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className={severityColor(inc.severity)}>{inc.severity}</Badge>
                    <Badge className={statusColor(inc.status)}>{inc.status}</Badge>
                    <Badge className="border-border bg-surface-2 text-muted">
                      {inc.alert_count} alert{inc.alert_count === 1 ? "" : "s"}
                    </Badge>
                    {inc.rule_ids.map((r) => (
                      <Badge key={r} className="border-border bg-surface-2 text-muted">
                        {r}
                      </Badge>
                    ))}
                  </div>
                  <h3 className="mt-2 text-sm font-medium text-white">{inc.title}</h3>
                  <p className="mt-1 text-xs text-muted">
                    {inc.agent_id ? `agent ${inc.agent_id}` : "unattributed"} · last activity{" "}
                    {formatDate(inc.last_seen)}
                  </p>
                </button>
                <div className="flex shrink-0 flex-col gap-2">
                  {inc.status !== "acknowledged" && inc.status !== "resolved" && (
                    <Button variant="ghost" className="text-xs" onClick={() => triage(inc.id, "acknowledged")}>
                      Acknowledge
                    </Button>
                  )}
                  {inc.status !== "resolved" && (
                    <Button variant="ghost" className="text-xs" onClick={() => triage(inc.id, "resolved")}>
                      Resolve case
                    </Button>
                  )}
                </div>
              </div>

              {expanded === inc.id && detail && (
                <div className="space-y-3 border-t border-border pt-3">
                  {actions.length > 0 && (
                    <div className="rounded-lg border border-warn/40 bg-warn/5 p-3">
                      <p className="mb-2 text-xs font-medium uppercase tracking-wide text-warn">
                        Recommended response
                      </p>
                      {notice && <p className="mb-2 text-xs text-ok">{notice}</p>}
                      <div className="space-y-2">
                        {actions.map((a) => (
                          <div key={a.action} className="flex items-start justify-between gap-3">
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2">
                                <Badge
                                  className={
                                    a.urgency === "urgent"
                                      ? "border-critical/40 text-critical"
                                      : "border-warn/40 text-warn"
                                  }
                                >
                                  {a.urgency}
                                </Badge>
                                <span className="text-sm font-medium text-white">
                                  {a.action === "contain_agent"
                                    ? "Contain agent"
                                    : "Quarantine server"}
                                </span>
                              </div>
                              <p className="mt-1 text-xs text-muted">{a.reason}</p>
                            </div>
                            {user?.role === "admin" && (
                              <Button
                                variant="danger"
                                className="text-xs"
                                onClick={() => applyAction(inc.id, a.action)}
                              >
                                Apply
                              </Button>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {detail.alerts.map((a) => (
                    <div key={a.id} className="rounded-lg border border-border bg-bg p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={severityColor(a.severity)}>{a.severity}</Badge>
                        <Badge className="border-border bg-surface-2 text-muted">{a.rule_id}</Badge>
                        <span className="text-xs text-muted">{formatDate(a.created_at)}</span>
                      </div>
                      <p className="mt-1 text-sm text-white">{a.title}</p>
                      <p className="text-xs text-muted">{a.description}</p>
                    </div>
                  ))}

                  {timeline.length > 0 && (
                    <div>
                      <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted">
                        Timeline
                      </p>
                      <ol className="space-y-1 border-l border-border pl-4">
                        {timeline.map((e, i) => (
                          <li key={i} className="relative text-xs text-muted">
                            <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full bg-border" />
                            <span className="text-slate-400">{formatDate(e.at)}</span>{" "}
                            <span className="text-slate-200">{e.detail}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

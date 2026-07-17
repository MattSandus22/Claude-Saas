"use client";

import { useEffect, useState } from "react";
import { api, type Incident, type IncidentDetail } from "@/lib/api";
import { Card, Badge, Button, EmptyState } from "@/components/ui";
import { formatDate, severityColor, statusColor } from "@/lib/utils";

const STATUS_FILTERS = ["all", "open", "acknowledged", "resolved"];

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);

  async function load() {
    try {
      const q = filter === "all" ? "" : `?status=${filter}`;
      setIncidents(await api.incidents(q));
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
      return;
    }
    setExpanded(id);
    setDetail(await api.incident(id));
  }

  async function triage(id: string, status: string) {
    await api.updateIncident(id, status);
    setExpanded(null);
    setDetail(null);
    load();
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
                <div className="space-y-2 border-t border-border pt-3">
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
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

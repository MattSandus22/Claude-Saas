"use client";

import { useEffect, useState } from "react";
import { api, type Alert } from "@/lib/api";
import { Card, Badge, Button, EmptyState } from "@/components/ui";
import { formatDate, severityColor, statusColor } from "@/lib/utils";

const STATUS_FILTERS = ["all", "open", "acknowledged", "resolved"];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const q = filter === "all" ? "" : `?status=${filter}`;
      setAlerts(await api.alerts(q));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function triage(id: string, status: string) {
    await api.updateAlert(id, status);
    load();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Threat Alerts</h1>
          <p className="text-sm text-muted">Findings raised by the detection engine, ready for triage.</p>
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
      {alerts.length === 0 && !error ? (
        <EmptyState message="No alerts match this filter." />
      ) : (
        <div className="space-y-3">
          {alerts.map((a) => (
            <Card key={a.id} className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={severityColor(a.severity)}>{a.severity}</Badge>
                  <Badge className="border-border bg-surface-2 text-muted">{a.rule_id}</Badge>
                  <Badge className={statusColor(a.status)}>{a.status}</Badge>
                  <span className="text-xs text-muted">{formatDate(a.created_at)}</span>
                </div>
                <h3 className="mt-2 text-sm font-medium text-white">{a.title}</h3>
                <p className="mt-1 text-sm text-muted">{a.description}</p>
                {a.evidence && Object.keys(a.evidence).length > 0 && (
                  <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-bg p-2 text-xs text-slate-400">
                    {JSON.stringify(a.evidence, null, 2)}
                  </pre>
                )}
              </div>
              <div className="flex shrink-0 flex-col gap-2">
                {a.status !== "acknowledged" && a.status !== "resolved" && (
                  <Button variant="ghost" className="text-xs" onClick={() => triage(a.id, "acknowledged")}>
                    Acknowledge
                  </Button>
                )}
                {a.status !== "resolved" && (
                  <Button variant="ghost" className="text-xs" onClick={() => triage(a.id, "resolved")}>
                    Resolve
                  </Button>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

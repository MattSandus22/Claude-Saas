"use client";

import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Server, ShieldAlert, Ban, Bug } from "lucide-react";
import { api, type DashboardStats } from "@/lib/api";
import { Card, StatTile, EmptyState, Badge } from "@/components/ui";
import { riskColor, severityColor } from "@/lib/utils";

// Validated status palette (see dataviz validation). Severity bars are labeled,
// so color is never the sole encoding.
const SEVERITY_COLOR: Record<string, string> = {
  critical: "#d03b3b",
  high: "#ec835a",
  medium: "#fab219",
  low: "#3987e5",
  info: "#898781",
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

// Chart chrome for the dark surface.
const GRID = "#2c2c2a";
const AXIS = "#898781";

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs shadow-lg">
      <div className="mb-1 font-medium text-slate-200">{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} className="flex items-center gap-2 text-slate-300">
          <span className="h-2 w-2 rounded-full" style={{ background: p.color || p.fill }} />
          <span className="capitalize">{p.name}:</span>
          <span className="font-mono tabular-nums text-white">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.stats().then(setStats).catch((e) => setError(e.message));
  }, []);

  if (error) return <EmptyState message={`Failed to load dashboard: ${error}`} />;
  if (!stats) return <EmptyState message="Loading dashboard…" />;

  const severityData = SEVERITY_ORDER.filter(
    (s) => (stats.alerts_by_severity[s] ?? 0) > 0
  ).map((s) => ({ severity: s, count: stats.alerts_by_severity[s] ?? 0 }));

  const blockRate =
    stats.total_events > 0
      ? Math.round((stats.blocked_events / stats.total_events) * 100)
      : 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Security Overview</h1>
        <p className="text-sm text-muted">
          Real-time posture across your MCP surface — discovery, monitoring, and threats.
        </p>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile
          label="MCP Servers"
          value={stats.total_servers}
          hint={`${stats.active_servers} active · ${stats.quarantined_servers} quarantined`}
        />
        <StatTile
          label="Open Alerts"
          value={stats.open_alerts}
          accent={stats.open_alerts > 0 ? "text-danger" : "text-ok"}
          hint="Awaiting triage"
        />
        <StatTile
          label="Suspicious Tools"
          value={stats.suspicious_tools}
          accent={stats.suspicious_tools > 0 ? "text-warn" : "text-ok"}
          hint="Flagged by scanner"
        />
        <StatTile
          label="Blocked Events"
          value={stats.blocked_events}
          accent={stats.blocked_events > 0 ? "text-critical" : "text-ok"}
          hint={`${blockRate}% of ${stats.total_events} inspected`}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Events over time */}
        <Card className="lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-medium text-slate-200">Inspected events (7 days)</h2>
            <div className="flex items-center gap-4 text-xs text-muted">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ background: "#3987e5" }} />
                Total
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ background: "#d03b3b" }} />
                Blocked
              </span>
            </div>
          </div>
          {stats.events_last_7d.length === 0 ? (
            <EmptyState message="No events in the last 7 days. Send messages to /inspect to populate." />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={stats.events_last_7d} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3987e5" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#3987e5" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#d03b3b" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#d03b3b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke={GRID} vertical={false} />
                <XAxis dataKey="date" stroke={AXIS} fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke={AXIS} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} />
                <Area
                  type="monotone"
                  dataKey="total"
                  name="total"
                  stroke="#3987e5"
                  strokeWidth={2}
                  fill="url(#gTotal)"
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  name="blocked"
                  stroke="#d03b3b"
                  strokeWidth={2}
                  fill="url(#gBlocked)"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </Card>

        {/* Alerts by severity */}
        <Card>
          <h2 className="mb-4 text-sm font-medium text-slate-200">Alerts by severity</h2>
          {severityData.length === 0 ? (
            <EmptyState message="No alerts yet." />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={severityData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke={GRID} vertical={false} />
                <XAxis dataKey="severity" stroke={AXIS} fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke={AXIS} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "#ffffff08" }} />
                <Bar dataKey="count" name="alerts" radius={[4, 4, 0, 0]} maxBarSize={48}>
                  {severityData.map((d) => (
                    <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {/* Top risky servers */}
      <Card>
        <h2 className="mb-4 text-sm font-medium text-slate-200">Highest-risk servers</h2>
        {stats.top_risky_servers.length === 0 ? (
          <EmptyState message="No servers registered yet. Run a discovery scan to begin." />
        ) : (
          <div className="space-y-2">
            {stats.top_risky_servers.map((s) => (
              <div
                key={s.id}
                className="flex items-center justify-between rounded-lg border border-border bg-surface-2 px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <Server size={16} className="text-muted" />
                  <span className="text-sm text-slate-200">{s.name}</span>
                  <Badge className={severityColor(s.status === "quarantined" ? "critical" : "info")}>
                    {s.status}
                  </Badge>
                </div>
                <div className="flex items-center gap-3">
                  <div className="h-1.5 w-32 overflow-hidden rounded-full bg-border">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${s.risk_score}%`,
                        background:
                          s.risk_score >= 65 ? "#d03b3b" : s.risk_score >= 35 ? "#fab219" : "#3987e5",
                      }}
                    />
                  </div>
                  <span className={`w-10 text-right font-mono text-sm tabular-nums ${riskColor(s.risk_score)}`}>
                    {s.risk_score.toFixed(0)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

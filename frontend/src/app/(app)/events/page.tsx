"use client";

import { useEffect, useState } from "react";
import { api, type MCPEvent } from "@/lib/api";
import { Card, Badge, EmptyState, Th, Td, Button } from "@/components/ui";
import { formatDate, riskColor } from "@/lib/utils";

export default function EventsPage() {
  const [events, setEvents] = useState<MCPEvent[]>([]);
  const [onlyBlocked, setOnlyBlocked] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const q = onlyBlocked ? "?blocked=true&limit=200" : "?limit=200";
      setEvents(await api.events(q));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onlyBlocked]);

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">MCP Events</h1>
          <p className="text-sm text-muted">
            Monitored MCP messages with detection scores and enforcement decisions.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant={onlyBlocked ? "ghost" : "primary"} onClick={() => setOnlyBlocked(false)}>
            All
          </Button>
          <Button variant={onlyBlocked ? "primary" : "ghost"} onClick={() => setOnlyBlocked(true)}>
            Blocked only
          </Button>
        </div>
      </div>

      {error && <EmptyState message={error} />}
      {events.length === 0 && !error ? (
        <EmptyState message="No events recorded. Use the Discovery simulator or POST to /api/v1/inspect." />
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead className="border-b border-border bg-surface-2">
                <tr>
                  <Th>Time</Th>
                  <Th>Method</Th>
                  <Th>Tool</Th>
                  <Th>Agent</Th>
                  <Th>Direction</Th>
                  <Th>Threat</Th>
                  <Th>Decision</Th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id} className="border-b border-border/60 hover:bg-surface-2/50">
                    <Td className="whitespace-nowrap text-xs text-muted">{formatDate(e.created_at)}</Td>
                    <Td className="font-mono text-xs">{e.method}</Td>
                    <Td className="font-mono text-xs text-slate-300">{e.tool_name || "—"}</Td>
                    <Td className="text-xs text-muted">{e.agent_id || "—"}</Td>
                    <Td className="text-xs text-muted">{e.direction}</Td>
                    <Td>
                      <span className={`font-mono font-semibold tabular-nums ${riskColor(e.threat_score)}`}>
                        {e.threat_score.toFixed(0)}
                      </span>
                    </Td>
                    <Td>
                      {e.blocked ? (
                        <Badge className="border-critical/40 bg-critical/10 text-critical">blocked</Badge>
                      ) : (
                        <Badge className="border-ok/40 bg-ok/10 text-ok">allowed</Badge>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

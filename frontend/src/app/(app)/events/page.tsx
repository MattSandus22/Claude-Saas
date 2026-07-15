"use client";

import { useCallback, useEffect, useState } from "react";
import { Ban, ShieldCheck } from "lucide-react";
import { api, type MCPEvent } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Card, Badge, EmptyState, Th, Td, Button } from "@/components/ui";
import { formatDate, riskColor } from "@/lib/utils";

export default function EventsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [events, setEvents] = useState<MCPEvent[]>([]);
  const [onlyBlocked, setOnlyBlocked] = useState(false);
  const [blocked, setBlocked] = useState<Set<string>>(new Set());
  const [busyAgent, setBusyAgent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const q = onlyBlocked ? "?blocked=true&limit=200" : "?limit=200";
      const [ev, ba] = await Promise.all([
        api.events(q),
        api.blockedAgents().catch(() => ({ blocked_agents: [] })),
      ]);
      setEvents(ev);
      setBlocked(new Set(ba.blocked_agents));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }, [onlyBlocked]);

  useEffect(() => {
    load();
  }, [load]);

  async function toggleAgent(agentId: string) {
    setBusyAgent(agentId);
    setError(null);
    try {
      const res = blocked.has(agentId)
        ? await api.unblockAgent(agentId)
        : await api.blockAgent(agentId);
      setBlocked(new Set(res.blocked_agents));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusyAgent(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">MCP Events</h1>
          <p className="text-sm text-muted">
            Monitored MCP messages with detection scores and enforcement decisions.
            {isAdmin && " Contain a suspicious agent to deny all its future calls."}
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
                  <Th>Threat</Th>
                  <Th>Decision</Th>
                  {isAdmin && <Th className="text-right">Response</Th>}
                </tr>
              </thead>
              <tbody>
                {events.map((e) => {
                  const agentBlocked = e.agent_id ? blocked.has(e.agent_id) : false;
                  return (
                    <tr key={e.id} className="border-b border-border/60 hover:bg-surface-2/50">
                      <Td className="whitespace-nowrap text-xs text-muted">{formatDate(e.created_at)}</Td>
                      <Td className="font-mono text-xs">{e.method}</Td>
                      <Td className="font-mono text-xs text-slate-300">{e.tool_name || "—"}</Td>
                      <Td className="text-xs text-muted">
                        <span className="inline-flex items-center gap-1.5">
                          {e.agent_id || "—"}
                          {agentBlocked && (
                            <Badge className="border-critical/40 bg-critical/10 text-critical">
                              contained
                            </Badge>
                          )}
                        </span>
                      </Td>
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
                      {isAdmin && (
                        <Td className="text-right">
                          {e.agent_id ? (
                            <Button
                              variant={agentBlocked ? "ghost" : "danger"}
                              onClick={() => toggleAgent(e.agent_id as string)}
                              disabled={busyAgent === e.agent_id}
                            >
                              {agentBlocked ? (
                                <>
                                  <ShieldCheck size={14} /> Release
                                </>
                              ) : (
                                <>
                                  <Ban size={14} /> Contain
                                </>
                              )}
                            </Button>
                          ) : (
                            <span className="text-xs text-muted">—</span>
                          )}
                        </Td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

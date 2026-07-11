"use client";

import { Fragment, useEffect, useState } from "react";
import { ShieldBan, ChevronDown, ChevronRight } from "lucide-react";
import { api, type MCPServer } from "@/lib/api";
import { Card, Badge, Button, EmptyState, Th, Td } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { formatDate, riskColor, statusColor } from "@/lib/utils";

export default function ServersPage() {
  const { user } = useAuth();
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      setServers(await api.servers());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function quarantine(id: string) {
    await api.quarantine(id);
    load();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">MCP Servers</h1>
        <p className="text-sm text-muted">
          Every discovered or registered MCP server, its transport, and computed risk.
        </p>
      </div>

      {error && <EmptyState message={error} />}

      {servers.length === 0 && !error ? (
        <EmptyState message="No servers yet. Use Discovery to scan code/config for MCP servers." />
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead className="border-b border-border bg-surface-2">
                <tr>
                  <Th className="w-8"> </Th>
                  <Th>Name</Th>
                  <Th>Endpoint</Th>
                  <Th>Transport</Th>
                  <Th>Source</Th>
                  <Th>Status</Th>
                  <Th>Risk</Th>
                  <Th>Last seen</Th>
                  <Th>Actions</Th>
                </tr>
              </thead>
              <tbody>
                {servers.map((s) => (
                  <Fragment key={s.id}>
                    <tr
                      className="cursor-pointer border-b border-border/60 hover:bg-surface-2/50"
                      onClick={() => setExpanded(expanded === s.id ? null : s.id)}
                    >
                      <Td>
                        {expanded === s.id ? (
                          <ChevronDown size={15} className="text-muted" />
                        ) : (
                          <ChevronRight size={15} className="text-muted" />
                        )}
                      </Td>
                      <Td className="font-medium text-white">{s.name}</Td>
                      <Td className="max-w-[240px] truncate font-mono text-xs text-muted">
                        {s.endpoint}
                      </Td>
                      <Td>
                        <Badge className="border-border bg-surface-2 text-slate-300">
                          {s.transport}
                        </Badge>
                      </Td>
                      <Td className="text-muted">{s.source}</Td>
                      <Td>
                        <Badge className={statusColor(s.status)}>{s.status}</Badge>
                      </Td>
                      <Td>
                        <span className={`font-mono font-semibold tabular-nums ${riskColor(s.risk_score)}`}>
                          {s.risk_score.toFixed(0)}
                        </span>
                      </Td>
                      <Td className="text-xs text-muted">{formatDate(s.last_seen)}</Td>
                      <Td>
                        {user?.role === "admin" && s.status !== "quarantined" && (
                          <Button
                            variant="danger"
                            className="px-2 py-1 text-xs"
                            onClick={(e) => {
                              e.stopPropagation();
                              quarantine(s.id);
                            }}
                          >
                            <ShieldBan size={13} /> Quarantine
                          </Button>
                        )}
                      </Td>
                    </tr>
                    {expanded === s.id && (
                      <tr className="border-b border-border/60 bg-bg/40">
                        <td colSpan={9} className="px-6 py-4">
                          <div className="text-xs font-medium uppercase tracking-wide text-muted">
                            Tool definitions ({s.tools.length})
                          </div>
                          {s.tools.length === 0 ? (
                            <p className="mt-2 text-sm text-muted">No tool definitions captured.</p>
                          ) : (
                            <div className="mt-3 grid gap-2 md:grid-cols-2">
                              {s.tools.map((t) => (
                                <div
                                  key={t.id}
                                  className={`rounded-lg border p-3 ${
                                    t.is_suspicious
                                      ? "border-critical/40 bg-critical/5"
                                      : "border-border bg-surface"
                                  }`}
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-mono text-sm text-slate-200">{t.name}</span>
                                    {t.is_suspicious && (
                                      <Badge className="border-critical/40 bg-critical/10 text-critical">
                                        suspicious · {t.risk_score.toFixed(0)}
                                      </Badge>
                                    )}
                                  </div>
                                  <p className="mt-1 line-clamp-2 text-xs text-muted">
                                    {t.description || "No description"}
                                  </p>
                                </div>
                              ))}
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

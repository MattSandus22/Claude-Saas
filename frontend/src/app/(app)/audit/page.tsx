"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card, EmptyState, Th, Td, Badge } from "@/components/ui";
import { formatDate } from "@/lib/utils";

interface AuditRow {
  id: string;
  actor: string;
  action: string;
  target: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

export default function AuditPage() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .audit()
      .then((r) => setRows(r as unknown as AuditRow[]))
      .catch((e) => setError(e.message));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Audit Log</h1>
        <p className="text-sm text-muted">
          Append-only trail of security-relevant actions. Admin access only.
        </p>
      </div>

      {error && <EmptyState message={error} />}
      {rows.length === 0 && !error ? (
        <EmptyState message="No audit entries yet." />
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead className="border-b border-border bg-surface-2">
                <tr>
                  <Th>Time</Th>
                  <Th>Actor</Th>
                  <Th>Action</Th>
                  <Th>Target</Th>
                  <Th>Detail</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="border-b border-border/60 hover:bg-surface-2/50">
                    <Td className="whitespace-nowrap text-xs text-muted">{formatDate(r.created_at)}</Td>
                    <Td className="text-xs text-slate-300">{r.actor}</Td>
                    <Td>
                      <Badge className="border-border bg-surface-2 font-mono text-slate-300">
                        {r.action}
                      </Badge>
                    </Td>
                    <Td className="max-w-[200px] truncate font-mono text-xs text-muted">
                      {r.target || "—"}
                    </Td>
                    <Td className="max-w-[280px] truncate text-xs text-muted">
                      {Object.keys(r.detail).length ? JSON.stringify(r.detail) : "—"}
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

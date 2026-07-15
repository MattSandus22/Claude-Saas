"use client";

/**
 * API key management (admin-only).
 *
 * The plaintext key is displayed exactly once after creation — the backend
 * stores only a hash. Revocation is immediate.
 */

import { useCallback, useEffect, useState } from "react";
import { Copy, KeyRound, Plus, ShieldOff } from "lucide-react";
import { api, ApiKey, ApiKeyCreated } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge, Button, Card, EmptyState, Td, Th } from "@/components/ui";

export default function ApiKeysPage() {
  const { user } = useAuth();
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [name, setName] = useState("");
  const [justCreated, setJustCreated] = useState<ApiKeyCreated | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const load = useCallback(() => {
    api.apiKeys().then(setKeys).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (user && user.role !== "admin") {
    return <EmptyState message="API key management requires the admin role." />;
  }

  async function createKey(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const created = await api.createApiKey(name.trim());
      setJustCreated(created);
      setName("");
      setCopied(false);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create key");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    try {
      await api.revokeApiKey(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to revoke key");
    }
  }

  async function copyKey() {
    if (!justCreated) return;
    await navigator.clipboard.writeText(justCreated.key);
    setCopied(true);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">API Keys</h1>
        <p className="mt-1 text-sm text-muted">
          Integration keys for agent gateways and CI scanners. Keys carry the
          narrow <code className="text-slate-300">ingest</code> scope: they can
          submit messages for inspection and run discovery scans, but can never
          read data or change configuration.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger">
          {error}
        </div>
      )}

      <Card>
        <form onSubmit={createKey} className="flex items-end gap-3">
          <div className="flex-1">
            <label className="mb-1 block text-xs uppercase tracking-wide text-muted">
              Key name
            </label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. prod-agent-gateway"
              maxLength={255}
              className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-slate-200 outline-none focus:border-brand"
            />
          </div>
          <Button type="submit" disabled={busy || !name.trim()}>
            <Plus size={16} /> Create key
          </Button>
        </form>

        {justCreated && (
          <div className="mt-4 rounded-lg border border-warn/40 bg-warn/10 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-medium text-warn">
              <KeyRound size={16} />
              Copy this key now — it will never be shown again.
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 overflow-x-auto rounded-md bg-surface-2 px-3 py-2 font-mono text-xs text-slate-200">
                {justCreated.key}
              </code>
              <Button variant="ghost" onClick={copyKey} type="button">
                <Copy size={14} /> {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <p className="mt-2 text-xs text-muted">
              Use it as the <code>X-API-Key</code> header on{" "}
              <code>POST /api/v1/inspect</code> and <code>POST /api/v1/servers/scan</code>.
            </p>
          </div>
        )}
      </Card>

      <Card className="p-0">
        {keys.length === 0 ? (
          <EmptyState message="No API keys yet. Create one to integrate a gateway or scanner." />
        ) : (
          <table className="w-full">
            <thead className="border-b border-border">
              <tr>
                <Th>Name</Th>
                <Th>Prefix</Th>
                <Th>Scope</Th>
                <Th>Status</Th>
                <Th>Last used</Th>
                <Th>Created</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {keys.map((k) => (
                <tr key={k.id}>
                  <Td className="font-medium text-white">{k.name}</Td>
                  <Td>
                    <code className="font-mono text-xs">{k.prefix}…</code>
                  </Td>
                  <Td>
                    <Badge className="border-brand/40 text-brand">{k.scope}</Badge>
                  </Td>
                  <Td>
                    {k.revoked ? (
                      <Badge className="border-danger/40 text-danger">revoked</Badge>
                    ) : (
                      <Badge className="border-ok/40 text-ok">active</Badge>
                    )}
                  </Td>
                  <Td className="text-muted">
                    {k.last_used_at
                      ? new Date(k.last_used_at).toLocaleString()
                      : "never"}
                  </Td>
                  <Td className="text-muted">
                    {new Date(k.created_at).toLocaleDateString()}
                  </Td>
                  <Td className="text-right">
                    {!k.revoked && (
                      <Button variant="danger" onClick={() => revoke(k.id)}>
                        <ShieldOff size={14} /> Revoke
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

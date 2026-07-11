"use client";

import { useEffect, useState } from "react";
import { Plus, Trash2, Lock } from "lucide-react";
import { api, type Policy } from "@/lib/api";
import { Card, Badge, Button, EmptyState } from "@/components/ui";
import { useAuth } from "@/lib/auth";

const NEW_POLICY_TEMPLATE = `{
  "default": "allow",
  "deny_tools": ["exec_shell", "delete_file"],
  "max_threat_score": 65,
  "require_agent_id": true
}`;

export default function PoliciesPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rules, setRules] = useState(NEW_POLICY_TEMPLATE);
  const [formErr, setFormErr] = useState<string | null>(null);

  async function load() {
    try {
      setPolicies(await api.policies());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function create() {
    setFormErr(null);
    try {
      const parsed = JSON.parse(rules);
      await api.createPolicy({ name, description, enabled: true, rules: parsed });
      setShowForm(false);
      setName("");
      setDescription("");
      setRules(NEW_POLICY_TEMPLATE);
      load();
    } catch (e) {
      setFormErr(e instanceof Error ? e.message : "Invalid JSON or request failed");
    }
  }

  async function remove(id: string) {
    await api.deletePolicy(id);
    load();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Policy Engine</h1>
          <p className="text-sm text-muted">
            Policy-as-code governing allowed tools, methods, and risk thresholds.
            Deny always overrides allow.
          </p>
        </div>
        {isAdmin && (
          <Button onClick={() => setShowForm((s) => !s)}>
            <Plus size={15} /> New policy
          </Button>
        )}
      </div>

      {!isAdmin && (
        <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 px-4 py-2 text-xs text-muted">
          <Lock size={13} /> Read-only view — policy changes require an admin role.
        </div>
      )}

      {showForm && isAdmin && (
        <Card className="space-y-3">
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="text-xs text-muted">Name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="mt-1 w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-white outline-none focus:border-brand"
                placeholder="e.g. Production Guardrail"
              />
            </div>
            <div>
              <label className="text-xs text-muted">Description</label>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="mt-1 w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-white outline-none focus:border-brand"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-muted">Rules (JSON)</label>
            <textarea
              value={rules}
              onChange={(e) => setRules(e.target.value)}
              spellCheck={false}
              className="mt-1 h-40 w-full resize-none rounded-lg border border-border bg-bg p-3 font-mono text-xs text-slate-200 outline-none focus:border-brand"
            />
            <p className="mt-1 text-xs text-muted">
              Allowed keys: default, allow_tools, deny_tools, deny_methods,
              max_threat_score, deny_agents, require_agent_id.
            </p>
          </div>
          {formErr && (
            <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
              {formErr}
            </div>
          )}
          <div className="flex gap-2">
            <Button onClick={create} disabled={!name}>
              Create policy
            </Button>
            <Button variant="ghost" onClick={() => setShowForm(false)}>
              Cancel
            </Button>
          </div>
        </Card>
      )}

      {error && <EmptyState message={error} />}
      {policies.length === 0 && !error ? (
        <EmptyState message="No policies defined." />
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {policies.map((p) => (
            <Card key={p.id} className="space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-medium text-white">{p.name}</h3>
                    <Badge
                      className={
                        p.enabled
                          ? "border-ok/40 bg-ok/10 text-ok"
                          : "border-border bg-surface-2 text-muted"
                      }
                    >
                      {p.enabled ? "enabled" : "disabled"}
                    </Badge>
                  </div>
                  <p className="mt-1 text-xs text-muted">{p.description || "No description"}</p>
                </div>
                {isAdmin && (
                  <button
                    onClick={() => remove(p.id)}
                    className="text-muted transition-colors hover:text-danger"
                    title="Delete policy"
                  >
                    <Trash2 size={15} />
                  </button>
                )}
              </div>
              <pre className="overflow-x-auto rounded-lg border border-border bg-bg p-3 text-xs text-slate-400">
                {JSON.stringify(p.rules, null, 2)}
              </pre>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

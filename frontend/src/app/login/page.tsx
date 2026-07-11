"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { login } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui";

export default function LoginPage() {
  const [email, setEmail] = useState("admin@mcpguard.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const { refresh } = useAuth();

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(email, password);
      await refresh();
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-dark/20 text-brand">
            <ShieldCheck size={30} />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-white">MCPGuard</h1>
            <p className="text-sm text-muted">MCP Security &amp; Governance Platform</p>
          </div>
        </div>

        <form
          onSubmit={onSubmit}
          className="space-y-4 rounded-2xl border border-border bg-surface p-6 shadow-lg"
        >
          <div className="space-y-1.5">
            <label className="text-sm text-slate-300" htmlFor="email">
              Email
            </label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-white outline-none focus:border-brand"
              required
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-sm text-slate-300" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-white outline-none focus:border-brand"
              required
            />
          </div>

          {error && (
            <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
              {error}
            </div>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? "Signing in…" : "Sign in"}
          </Button>

          <p className="text-center text-xs text-muted">
            Default dev admin is seeded on first backend run. Change the password
            immediately in production.
          </p>
        </form>
      </div>
    </div>
  );
}

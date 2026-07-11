"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldCheck,
  LayoutDashboard,
  Server,
  Activity,
  Bell,
  ScrollText,
  FileLock2,
  LogOut,
  Radar,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/servers", label: "MCP Servers", icon: Server },
  { href: "/discovery", label: "Discovery", icon: Radar },
  { href: "/events", label: "Events", icon: Activity },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/policies", label: "Policies", icon: FileLock2 },
  { href: "/audit", label: "Audit Log", icon: ScrollText, adminOnly: true },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  return (
    <div className="flex min-h-screen bg-bg">
      <aside className="flex w-60 shrink-0 flex-col border-r border-border bg-surface">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-dark/20 text-brand">
            <ShieldCheck size={20} />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold text-white">MCPGuard</div>
            <div className="text-[10px] uppercase tracking-wider text-muted">
              Security &amp; Governance
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          {NAV.filter((n) => !n.adminOnly || user?.role === "admin").map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-brand-dark/15 text-brand"
                    : "text-slate-400 hover:bg-surface-2 hover:text-slate-200"
                )}
              >
                <Icon size={17} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="border-t border-border p-3">
          <div className="mb-2 px-2 text-xs text-muted">
            <div className="truncate text-slate-300">{user?.email}</div>
            <div className="uppercase tracking-wide">{user?.role}</div>
          </div>
          <button
            onClick={logout}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-slate-400 transition-colors hover:bg-surface-2 hover:text-danger"
          >
            <LogOut size={17} />
            Sign out
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-x-hidden">
        <div className="mx-auto max-w-7xl px-8 py-8">{children}</div>
      </main>
    </div>
  );
}

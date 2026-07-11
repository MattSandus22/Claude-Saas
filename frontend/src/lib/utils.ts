import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(sev: string): string {
  switch (sev) {
    case "critical":
      return "text-critical bg-critical/10 border-critical/30";
    case "high":
      return "text-danger bg-danger/10 border-danger/30";
    case "medium":
      return "text-warn bg-warn/10 border-warn/30";
    case "low":
      return "text-brand bg-brand/10 border-brand/30";
    default:
      return "text-muted bg-muted/10 border-muted/30";
  }
}

export function riskColor(score: number): string {
  if (score >= 90) return "text-critical";
  if (score >= 65) return "text-danger";
  if (score >= 35) return "text-warn";
  if (score > 0) return "text-brand";
  return "text-ok";
}

export function statusColor(status: string): string {
  switch (status) {
    case "quarantined":
      return "text-critical bg-critical/10 border-critical/30";
    case "active":
      return "text-ok bg-ok/10 border-ok/30";
    case "discovered":
      return "text-warn bg-warn/10 border-warn/30";
    case "open":
      return "text-danger bg-danger/10 border-danger/30";
    case "acknowledged":
      return "text-warn bg-warn/10 border-warn/30";
    case "resolved":
      return "text-ok bg-ok/10 border-ok/30";
    default:
      return "text-muted bg-muted/10 border-muted/30";
  }
}

export function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

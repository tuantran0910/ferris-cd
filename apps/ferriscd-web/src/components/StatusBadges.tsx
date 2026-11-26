import {
  AlertCircle,
  CheckCircle2,
  CircleDashed,
  HeartPulse,
  HelpCircle,
  PauseCircle,
  RefreshCw,
  XCircle,
} from "lucide-react";

/**
 * Trap Guard T16.2:
 * Sync Status and Health Status MUST ALWAYS be rendered as separate, explicitly
 * labeled badges — never merged into a single vague "Status" indicator.
 */

export function normalizeSyncStatus(status?: string | null): string {
  if (!status || status.trim().length === 0) {
    return "Unknown";
  }
  return status;
}

export function normalizeHealthStatus(status?: string | null): string {
  if (!status || status.trim().length === 0) {
    return "Unknown";
  }
  return status;
}

export function getSyncBadgeClasses(status: string): string {
  switch (status) {
    case "Synced":
      return "border-emerald-500/40 bg-emerald-500/15 text-emerald-300";
    case "OutOfSync":
      return "border-amber-500/40 bg-amber-500/15 text-amber-300";
    default:
      return "border-slate-600/60 bg-slate-800 text-slate-300";
  }
}

export function getHealthBadgeClasses(status: string): string {
  switch (status) {
    case "Healthy":
      return "border-emerald-500/40 bg-emerald-500/15 text-emerald-300";
    case "Progressing":
      return "border-sky-500/40 bg-sky-500/15 text-sky-300";
    case "Degraded":
      return "border-rose-500/40 bg-rose-500/15 text-rose-300";
    case "Suspended":
      return "border-violet-500/40 bg-violet-500/15 text-violet-300";
    case "Missing":
      return "border-orange-500/40 bg-orange-500/15 text-orange-300";
    default:
      return "border-slate-600/60 bg-slate-800 text-slate-300";
  }
}

export function SyncStatusBadge({
  status,
  compact = false,
}: {
  status?: string | null;
  compact?: boolean;
}) {
  const normalized = normalizeSyncStatus(status);
  const Icon =
    normalized === "Synced"
      ? CheckCircle2
      : normalized === "OutOfSync"
        ? RefreshCw
        : HelpCircle;

  return (
    <span
      data-testid="sync-status-badge"
      data-sync-status={normalized}
      className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${
        compact ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs"
      } ${getSyncBadgeClasses(normalized)}`}
    >
      <Icon className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} aria-hidden="true" />
      <span className="opacity-75">Sync:</span>
      <span>{normalized}</span>
    </span>
  );
}

export function HealthStatusBadge({
  status,
  compact = false,
}: {
  status?: string | null;
  compact?: boolean;
}) {
  const normalized = normalizeHealthStatus(status);
  const Icon =
    normalized === "Healthy"
      ? HeartPulse
      : normalized === "Progressing"
        ? CircleDashed
        : normalized === "Degraded"
          ? XCircle
          : normalized === "Suspended"
            ? PauseCircle
            : normalized === "Missing"
              ? AlertCircle
              : HelpCircle;

  return (
    <span
      data-testid="health-status-badge"
      data-health-status={normalized}
      className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${
        compact ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs"
      } ${getHealthBadgeClasses(normalized)}`}
    >
      <Icon className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} aria-hidden="true" />
      <span className="opacity-75">Health:</span>
      <span>{normalized}</span>
    </span>
  );
}

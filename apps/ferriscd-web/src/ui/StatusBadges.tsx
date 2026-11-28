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
import { Badge, type BadgeTone } from "./Badge";

/**
 * Trap Guard T16.2:
 * Sync Status and Health Status MUST ALWAYS be rendered as separate, explicitly
 * labeled badges — never merged into a single vague "Status" indicator.
 *
 * Both badges render an icon plus the literal text ("Sync: OutOfSync"), so the
 * state survives a greyscale screenshot and a colour-blind operator; the tone
 * only *reinforces* the label. Badges never animate, so nothing here can draw
 * attention away from the two status signals.
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

export function getSyncTone(status: string): BadgeTone {
  switch (status) {
    case "Synced":
      return "success";
    case "OutOfSync":
      return "warning";
    default:
      return "neutral";
  }
}

export function getHealthTone(status: string): BadgeTone {
  switch (status) {
    case "Healthy":
      return "success";
    case "Progressing":
      return "info";
    case "Degraded":
      return "danger";
    case "Suspended":
      return "violet";
    case "Missing":
      return "orange";
    default:
      return "neutral";
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
    <Badge
      data-testid="sync-status-badge"
      data-sync-status={normalized}
      tone={getSyncTone(normalized)}
      size={compact ? "sm" : "md"}
    >
      <Icon
        className={compact ? "h-3 w-3" : "h-3.5 w-3.5"}
        aria-hidden="true"
      />
      <span>Sync:</span>
      <span>{normalized}</span>
    </Badge>
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
    <Badge
      data-testid="health-status-badge"
      data-health-status={normalized}
      tone={getHealthTone(normalized)}
      size={compact ? "sm" : "md"}
    >
      <Icon
        className={compact ? "h-3 w-3" : "h-3.5 w-3.5"}
        aria-hidden="true"
      />
      <span>Health:</span>
      <span>{normalized}</span>
    </Badge>
  );
}

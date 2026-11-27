import { AlertTriangle, CheckCircle2, Info } from "lucide-react";
import type { ApplicationEventView } from "../../../api/types";
import { Badge } from "../../../ui/Badge";
import { EmptyState } from "../../../ui/EmptyState";
import { LiveRegion } from "../../../ui/LiveRegion";
import { formatTimestamp } from "../../../utils/format";

export interface EventsTimelineProps {
  events: ApplicationEventView[];
  /** `true` when the server cut the timeline at its bound (more events exist). */
  truncated?: boolean;
}

/**
 * Kubernetes events timeline for one `Application` (`T17.3`).
 *
 * Renders exactly what `GET .../events` returns: `Normal`/`Warning` events, newest first, already
 * redacted server-side (the component must never be the place a secret is masked — it cannot see the
 * unredacted value, and it does not try).
 *
 * Accessibility notes:
 * - it is an ordered list, so "the third attempt failed" is a position a screen reader announces;
 * - `type` is rendered as **text** (`Normal`/`Warning`) inside the badge, so the severity survives
 *   greyscale and colour-blind operation — the colour only reinforces it;
 * - a live region announces how many events are on screen, because a refreshed timeline changes
 *   without any user action.
 */
export function EventsTimeline({ events, truncated = false }: EventsTimelineProps) {
  return (
    <section
      aria-label="Kubernetes events timeline"
      data-testid="events-timeline"
      className="space-y-3"
    >
      <LiveRegion
        message={
          events.length === 0
            ? "No Kubernetes events for this application."
            : `${events.length} Kubernetes events, ${countWarnings(events)} of them warnings.`
        }
        data-testid="events-live-region"
      />

      {events.length === 0 ? (
        <EmptyState bordered={false}>
          No Kubernetes events recorded for this Application yet. The controller publishes one when a
          sync succeeds, fails, or prunes resources.
        </EmptyState>
      ) : (
        <ol className="relative space-y-3 border-l border-slate-800 pl-6">
          {events.map((event, index) => {
            const isWarning = event.type === "Warning";
            return (
              <li
                key={`${event.name}-${event.lastObservedAt ?? index}`}
                data-testid="event-row"
                data-event-type={event.type}
                className="relative rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs"
              >
                <span
                  aria-hidden="true"
                  className={`absolute -left-[33px] top-4 flex h-5 w-5 items-center justify-center rounded-full border ${
                    isWarning
                      ? "border-amber-500/50 bg-amber-950 text-amber-300"
                      : "border-emerald-500/50 bg-emerald-950 text-emerald-300"
                  }`}
                >
                  {isWarning ? (
                    <AlertTriangle className="h-3 w-3" />
                  ) : (
                    <CheckCircle2 className="h-3 w-3" />
                  )}
                </span>

                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={isWarning ? "warning" : "success"} size="sm">
                      {isWarning ? (
                        <AlertTriangle aria-hidden="true" className="h-3 w-3" />
                      ) : (
                        <CheckCircle2 aria-hidden="true" className="h-3 w-3" />
                      )}
                      {isWarning ? "Warning" : "Normal"}
                    </Badge>
                    <span className="font-semibold text-slate-100">{event.reason}</span>
                    {event.action && (
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-200">
                        {event.action}
                      </span>
                    )}
                    {event.count > 1 && (
                      <span
                        className="rounded bg-indigo-500/15 px-1.5 py-0.5 font-mono text-[11px] text-indigo-200"
                        title={`This event recurred ${event.count} times`}
                      >
                        ×{event.count}
                      </span>
                    )}
                  </div>
                  {event.lastObservedAt && (
                    <time
                      dateTime={event.lastObservedAt}
                      title={event.lastObservedAt}
                      className="font-mono text-[11px] text-slate-300"
                    >
                      {formatTimestamp(event.lastObservedAt)}
                    </time>
                  )}
                </div>

                <p className="mt-2 break-words leading-relaxed text-slate-200">
                  {event.message || "—"}
                </p>

                {event.reportingComponent && (
                  <p className="mt-1.5 flex items-center gap-1 text-[11px] text-slate-300">
                    <Info aria-hidden="true" className="h-3 w-3 text-sky-300" />
                    reported by <span className="font-mono">{event.reportingComponent}</span>
                  </p>
                )}
              </li>
            );
          })}
        </ol>
      )}

      {truncated && (
        <p role="status" className="text-xs text-slate-300">
          Showing the most recent 50 events. Older events are still in the cluster
          (<code className="font-mono">kubectl get events</code>).
        </p>
      )}
    </section>
  );
}

function countWarnings(events: ApplicationEventView[]): number {
  return events.filter((event) => event.type === "Warning").length;
}

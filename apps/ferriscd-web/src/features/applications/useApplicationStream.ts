import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { ApiClientError } from "../../api/client";
import { openApplicationStream } from "../../api/sse";
import type { ApplicationListView } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { queryKeys } from "./hooks";

/** Connection state surfaced to the page so the operator knows how the list is updated. */
export type ApplicationStreamStatus = "idle" | "connecting" | "live" | "polling";

export interface ApplicationStreamState {
  status: ApplicationStreamStatus;
  /** The latest streamed snapshot, preferred over a slower poll while connected. */
  snapshot: ApplicationListView | null;
}

/** Streamed data is authoritative only while the stream is actually live; polling otherwise. */
export function selectApplicationsData(
  status: ApplicationStreamStatus,
  snapshot: ApplicationListView | null,
  polled: ApplicationListView | undefined,
): ApplicationListView | undefined {
  return status === "live" && snapshot ? snapshot : polled;
}

/** No snapshot for this long means the connection is half-open (a proxy black-holed it). */
export const STREAM_STALL_MS = 15_000;

export function isStreamStalled(
  lastFrameAt: number,
  now: number,
  thresholdMs = STREAM_STALL_MS,
): boolean {
  return now - lastFrameAt >= thresholdMs;
}

/** Five fast retries (0.5 s, 1 s, 2 s, 4 s, 8 s with jitter) before falling back to polling. */
export const MAX_FAST_ATTEMPTS = 5;
export const BASE_RETRY_MS = 500;
export const MAX_RETRY_MS = 30_000;
/** While polling, keep trying the stream once a minute so a recovered proxy resumes live updates. */
export const RETRY_WHILE_POLLING_MS = 60_000;

/** Bounded exponential backoff with jitter for one failed attempt (1-based). */
export function retryDelayMs(attempt: number, random: () => number = Math.random): number {
  const backoff = Math.min(MAX_RETRY_MS, BASE_RETRY_MS * 2 ** Math.max(0, attempt - 1));
  return backoff * (1 + random() * 0.2);
}

/** Whether the fast-retry budget is exhausted (the hook then falls back to polling). */
export function shouldFallBackToPolling(attempt: number): boolean {
  return attempt > MAX_FAST_ATTEMPTS;
}

/**
 * Consumes `GET /api/v1/applications/stream` (`T17.3`) and writes every RBAC-filtered snapshot into
 * the TanStack Query cache, so dashboards update without reloading or waiting for the next poll.
 *
 * Best-practice behaviour:
 * - `fetch()` streaming with `Authorization: Bearer` (never `EventSource`/query tokens);
 * - bounded exponential backoff with jitter, reset after a clean connection;
 * - after the retry budget, fall back to the existing 10 s polling and retry the stream once a
 *   minute (corporate proxies silently drop long-lived connections);
 * - a `401` stops the stream and signs the session out instead of retrying with a dead token;
 * - the `AbortController` is aborted on unmount, so no reader outlives the page.
 */
export function useApplicationStream(enabled = true): ApplicationStreamState {
  const { token, baseUrl, logout } = useAuth();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<ApplicationStreamStatus>("idle");
  const [snapshot, setSnapshot] = useState<ApplicationListView | null>(null);

  useEffect(() => {
    if (!enabled || !token) {
      setStatus("idle");
      return;
    }

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let watchdog: ReturnType<typeof setInterval> | undefined;
    let controller: AbortController | undefined;
    let attempt = 0;
    let lastFrameAt = Date.now();
    let stalled = false;

    const schedule = (delayMs: number) => {
      timer = setTimeout(() => {
        void connect();
      }, delayMs);
    };

    const connect = async (): Promise<void> => {
      if (cancelled) {
        return;
      }
      controller = new AbortController();
      stalled = false;
      lastFrameAt = Date.now();
      setStatus("connecting");
      // Server snapshots arrive every ~2 s; silence means a half-open socket that will never
      // reject on its own. Force it into the retry path instead of freezing a "live" dashboard.
      watchdog = setInterval(() => {
        if (isStreamStalled(lastFrameAt, Date.now())) {
          stalled = true;
          controller?.abort();
        }
      }, 1_000);
      try {
        await openApplicationStream({
          baseUrl,
          token,
          signal: controller.signal,
          onSnapshot: (snapshot) => {
            lastFrameAt = Date.now();
            // A slower in-flight poll must not overwrite a newer streamed snapshot.
            void queryClient.cancelQueries(
              { queryKey: queryKeys.applications() },
              { revert: false },
            );
            queryClient.setQueryData(queryKeys.applications(), snapshot);
            setSnapshot(snapshot);
            setStatus("live");
          },
        });
        if (cancelled) {
          return;
        }
        // The server ended the stream cleanly: reconnect promptly, then resume polling meanwhile.
        attempt = 0;
        setStatus("polling");
        schedule(1_000);
      } catch (error) {
        if (cancelled) {
          return;
        }
        if (controller.signal.aborted && !stalled) {
          return;
        }
        if (error instanceof ApiClientError && error.isUnauthorized) {
          setStatus("polling");
          logout("Your session token was rejected by the live update stream. Please sign in again.");
          return;
        }
        attempt += 1;
        if (shouldFallBackToPolling(attempt)) {
          attempt = 0;
          setStatus("polling");
          schedule(RETRY_WHILE_POLLING_MS);
          return;
        }
        schedule(retryDelayMs(attempt));
      } finally {
        if (watchdog !== undefined) {
          clearInterval(watchdog);
          watchdog = undefined;
        }
      }
    };

    void connect();

    return () => {
      cancelled = true;
      controller?.abort();
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      if (watchdog !== undefined) {
        clearInterval(watchdog);
      }
    };
  }, [enabled, token, baseUrl, queryClient, logout]);

  return { status, snapshot };
}

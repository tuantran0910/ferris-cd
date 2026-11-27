import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { ApiClientError } from "../../api/client";
import { openApplicationStream } from "../../api/sse";
import { useAuth } from "../../auth/AuthContext";
import { queryKeys } from "./hooks";

/** Connection state surfaced to the page so the operator knows how the list is updated. */
export type ApplicationStreamStatus = "idle" | "connecting" | "live" | "polling";

/** Five fast retries (0.5 s, 1 s, 2 s, 4 s, 8 s with jitter) before falling back to polling. */
const MAX_FAST_ATTEMPTS = 5;
const BASE_RETRY_MS = 500;
const MAX_RETRY_MS = 30_000;
/** While polling, keep trying the stream once a minute so a recovered proxy resumes live updates. */
const RETRY_WHILE_POLLING_MS = 60_000;

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
export function useApplicationStream(enabled = true): ApplicationStreamStatus {
  const { token, baseUrl, logout } = useAuth();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<ApplicationStreamStatus>("idle");

  useEffect(() => {
    if (!enabled || !token) {
      setStatus("idle");
      return;
    }

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let attempt = 0;

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
      setStatus("connecting");
      try {
        await openApplicationStream({
          baseUrl,
          token,
          signal: controller.signal,
          onSnapshot: (snapshot) => {
            queryClient.setQueryData(queryKeys.applications(), snapshot);
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
        if (cancelled || controller.signal.aborted) {
          return;
        }
        if (error instanceof ApiClientError && error.isUnauthorized) {
          setStatus("polling");
          logout("Your session token was rejected by the live update stream. Please sign in again.");
          return;
        }
        attempt += 1;
        if (attempt > MAX_FAST_ATTEMPTS) {
          attempt = 0;
          setStatus("polling");
          schedule(RETRY_WHILE_POLLING_MS);
          return;
        }
        const backoff = Math.min(MAX_RETRY_MS, BASE_RETRY_MS * 2 ** (attempt - 1));
        const jittered = backoff * (1 + Math.random() * 0.2);
        schedule(jittered);
      }
    };

    void connect();

    return () => {
      cancelled = true;
      controller?.abort();
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    };
  }, [enabled, token, baseUrl, queryClient, logout]);

  return status;
}

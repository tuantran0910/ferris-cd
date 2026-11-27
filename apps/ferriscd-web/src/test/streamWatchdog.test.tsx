import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { useApplicationStream } from "../features/applications/useApplicationStream";
import { createMockApiClient } from "./fixtures";

const encoder = new TextEncoder();
const frame = `event: applications\ndata: ${JSON.stringify({ items: [] })}\n\n`;

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={createMockApiClient()}>
        {children}
      </AuthProvider>
    </QueryClientProvider>
  );
}

/** A `text/event-stream` response whose producer controls when (and whether) frames arrive. */
function streamResponse(
  start: (controller: ReadableStreamDefaultController<Uint8Array>, signal?: AbortSignal) => void,
  signal?: AbortSignal,
): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      signal?.addEventListener("abort", () =>
        controller.error(new DOMException("aborted", "AbortError")),
      );
      start(controller, signal);
    },
  });
  return new Response(body, { status: 200 });
}

describe("useApplicationStream liveness watchdog", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    setStoredToken("test-token");
  });

  it("aborts a half-open stream into the retry path and never retries after unmount", async () => {
    const nativeFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes("/api/v1/applications/stream")) {
        calls += 1;
        if (calls === 1) {
          // One frame, then silence (a proxy black-holes the socket).
          return Promise.resolve(
            streamResponse((controller) => controller.enqueue(encoder.encode(frame)), init?.signal ?? undefined),
          );
        }
        return Promise.resolve(streamResponse(() => undefined, init?.signal ?? undefined));
      }
      return nativeFetch(input, init);
    }) as typeof fetch;

    try {
      const { result, unmount } = renderHook(
        () => useApplicationStream(true, { stallMs: 50 }),
        { wrapper },
      );
      await waitFor(() => expect(result.current.status).toBe("live"));
      await waitFor(() => expect(calls).toBeGreaterThanOrEqual(2), { timeout: 3_000 });
      expect(result.current.status).not.toBe("live");

      unmount();
      const afterUnmount = calls;
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 300));
      });
      expect(calls).toBe(afterUnmount);
    } finally {
      globalThis.fetch = nativeFetch;
    }
  });

  it("does not abort a healthy stream that keeps sending frames", async () => {
    const nativeFetch = globalThis.fetch;
    let calls = 0;
    let interval: ReturnType<typeof setInterval> | undefined;
    globalThis.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes("/api/v1/applications/stream")) {
        calls += 1;
        return Promise.resolve(
          streamResponse((controller) => {
            controller.enqueue(encoder.encode(frame));
            interval = setInterval(() => {
              try {
                controller.enqueue(encoder.encode(frame));
              } catch {
                clearInterval(interval);
              }
            }, 20);
          }, init?.signal ?? undefined),
        );
      }
      return nativeFetch(input, init);
    }) as typeof fetch;

    try {
      const { result, unmount } = renderHook(
        () => useApplicationStream(true, { stallMs: 250 }),
        { wrapper },
      );
      await waitFor(() => expect(result.current.status).toBe("live"));
      // Outlive the stall threshold *and* the first retry backoff, so a spurious abort would
      // surface as a second fetch instead of staying invisible inside the window.
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 1_500));
      });
      expect(calls).toBe(1);
      expect(result.current.status).toBe("live");
      unmount();
    } finally {
      if (interval !== undefined) {
        clearInterval(interval);
      }
      globalThis.fetch = nativeFetch;
    }
  });
});

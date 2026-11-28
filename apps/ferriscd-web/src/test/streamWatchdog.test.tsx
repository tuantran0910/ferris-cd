import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { useApplicationStream } from "../features/applications/useApplicationStream";
import { createMockApiClient } from "./fixtures";

const encoder = new TextEncoder();
const frame = `event: applications\ndata: ${JSON.stringify({ items: [] })}\n\n`;
let nativeFetch: typeof fetch;

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

/** Advances fake time and flushes the promise/effect work it unblocks. */
async function tick(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe("useApplicationStream liveness watchdog", () => {
  beforeEach(() => {
    nativeFetch = globalThis.fetch;
    resetTokenMemoryCache();
    setStoredToken("test-token");
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    globalThis.fetch = nativeFetch;
  });

  it("aborts a half-open stream into the retry path and never retries after unmount", async () => {
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

    const { result, unmount } = renderHook(
      () => useApplicationStream(true, { stallMs: 100 }),
      { wrapper },
    );

    await tick(0);
    expect(result.current.status).toBe("live");
    expect(calls).toBe(1);

    // Stall watchdog fires at ~100ms; the first retry backoff is 500-600ms.
    await tick(700);
    expect(calls).toBeGreaterThanOrEqual(2);
    expect(result.current.status).not.toBe("live");

    unmount();
    const afterUnmount = calls;
    await tick(120_000);
    expect(calls).toBe(afterUnmount);
  });

  it("does not abort a healthy stream that keeps sending frames", async () => {
    let calls = 0;
    globalThis.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes("/api/v1/applications/stream")) {
        calls += 1;
        return Promise.resolve(
          streamResponse((controller) => {
            controller.enqueue(encoder.encode(frame));
            setInterval(() => {
              try {
                controller.enqueue(encoder.encode(frame));
              } catch {
                // The abort listener already errored the controller.
              }
            }, 20);
          }, init?.signal ?? undefined),
        );
      }
      return nativeFetch(input, init);
    }) as typeof fetch;

    const { result, unmount } = renderHook(
      () => useApplicationStream(true, { stallMs: 250 }),
      { wrapper },
    );

    await tick(0);
    expect(result.current.status).toBe("live");

    // Three seconds of 20ms frames against a 250ms watchdog: never a false stall.
    await tick(3_000);
    expect(calls).toBe(1);
    expect(result.current.status).toBe("live");
    unmount();
  });
});

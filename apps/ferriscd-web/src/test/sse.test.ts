import { describe, expect, it, vi } from "vitest";

import {
  applicationStreamUrl,
  openApplicationStream,
  SseParser,
} from "../api/sse";
import type { ApplicationListView } from "../api/types";
import {
  BASE_RETRY_MS,
  MAX_FAST_ATTEMPTS,
  MAX_RETRY_MS,
  RETRY_WHILE_POLLING_MS,
  retryDelayMs,
  shouldFallBackToPolling,
} from "../features/applications/useApplicationStream";

const snapshot: ApplicationListView = { items: [] };

describe("SseParser", () => {
  it("reassembles frames split across chunks and ignores keep-alive comments", () => {
    const parser = new SseParser();
    expect(parser.push(": keep-alive\n\nevent: appl")).toEqual([]);
    const frames = parser.push(
      'ications\ndata: {"items":[]}\n\nevent: applications\r\ndata: {"items"',
    );
    expect(frames).toEqual([{ event: "applications", data: '{"items":[]}' }]);
    expect(parser.push(':[]}\r\n\r\n')).toEqual([
      { event: "applications", data: '{"items":[]}' },
    ]);
  });

  it("joins multi-line data fields with newlines", () => {
    const parser = new SseParser();
    expect(parser.push("event: applications\ndata: a\ndata: b\n\n")).toEqual([
      { event: "applications", data: "a\nb" },
    ]);
  });
});

describe("openApplicationStream", () => {
  it("authenticates with the Authorization header and never puts the token in the URL", async () => {
    const frames = new TextEncoder().encode(
      `event: applications\ndata: ${JSON.stringify(snapshot)}\n\n`,
    );
    const fetchImpl = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(frames);
            controller.close();
          },
        }),
        { status: 200, headers: { "Content-Type": "text/event-stream" } },
      ),
    );
    const onSnapshot = vi.fn();
    const controller = new AbortController();

    await openApplicationStream({
      baseUrl: "https://ferriscd.example.com",
      token: "secret-token",
      signal: controller.signal,
      onSnapshot,
      fetchImpl,
    });

    expect(onSnapshot).toHaveBeenCalledWith(snapshot);
    const call = fetchImpl.mock.calls[0];
    expect(call).toBeDefined();
    const [url, init] = call!;
    expect(String(url)).toBe(applicationStreamUrl("https://ferriscd.example.com"));
    expect(String(url)).not.toContain("secret-token");
    expect(new Headers(init?.headers).get("Authorization")).toBe(
      "Bearer secret-token",
    );
  });

  it("rejects with a typed error when the server sends a terminal error frame", async () => {
    const frames = new TextEncoder().encode(
      'event: error\ndata: {"error":{"code":"BackendUnavailable","message":"boom"}}\n\n',
    );
    const fetchImpl = vi.fn(async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(frames);
            controller.close();
          },
        }),
        { status: 200, headers: { "Content-Type": "text/event-stream" } },
      ),
    );

    await expect(
      openApplicationStream({
        baseUrl: "https://ferriscd.example.com",
        token: "t",
        signal: new AbortController().signal,
        onSnapshot: vi.fn(),
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "BackendUnavailable" });
  });
});

describe("application stream retry policy", () => {
  it("backs off exponentially with bounded jitter and falls back after the budget", () => {
    expect(retryDelayMs(1, () => 0)).toBe(BASE_RETRY_MS);
    expect(retryDelayMs(2, () => 0)).toBe(BASE_RETRY_MS * 2);
    expect(retryDelayMs(4, () => 0)).toBe(BASE_RETRY_MS * 8);
    expect(retryDelayMs(10, () => 1)).toBeCloseTo(MAX_RETRY_MS * 1.2);
    expect(shouldFallBackToPolling(MAX_FAST_ATTEMPTS)).toBe(false);
    expect(shouldFallBackToPolling(MAX_FAST_ATTEMPTS + 1)).toBe(true);
    expect(RETRY_WHILE_POLLING_MS).toBe(60_000);
  });
});

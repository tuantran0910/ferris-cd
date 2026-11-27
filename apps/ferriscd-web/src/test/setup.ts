import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";

// The dashboard opens the SSE feed on mount. Tests never talk to a network: the stream stays open
// (and aborts cleanly) unless a test overrides `fetch` itself.
const nativeFetch = globalThis.fetch?.bind(globalThis);
afterEach(() => {
  vi.clearAllMocks();
});
const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
  const url =
    typeof input === "string"
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;
  if (url.includes("/api/v1/applications/stream")) {
    const signal = init?.signal;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        signal?.addEventListener("abort", () => {
          controller.error(new DOMException("aborted", "AbortError"));
        });
      },
    });
    return Promise.resolve(
      new Response(body, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      }),
    );
  }
  if (!nativeFetch) {
    return Promise.reject(new Error(`no fetch implementation for ${url}`));
  }
  return nativeFetch(input, init);
}) as typeof fetch;
globalThis.fetch = fetchMock;

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = ResizeObserverStub;
}

if (typeof globalThis.DOMMatrixReadOnly === "undefined") {
  // Minimal polyfill for React Flow in jsdom
  (globalThis as unknown as Record<string, unknown>).DOMMatrixReadOnly = class {
    m22 = 1;
    constructor() {}
  };
}

Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
  configurable: true,
  value: 560,
});

Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
  configurable: true,
  value: 1024,
});

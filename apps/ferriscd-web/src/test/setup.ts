import "@testing-library/jest-dom/vitest";

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

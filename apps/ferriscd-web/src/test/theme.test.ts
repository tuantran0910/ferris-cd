import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyMode,
  applyThemeTransition,
  currentTheme,
  nextMode,
  readMode,
  resolveMode,
} from "../app/theme";

describe("theme", () => {
  beforeEach(() => {
    delete document.documentElement.dataset.theme;
    delete document.documentElement.dataset.themeMode;
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("applies a mode, stores it and resolves system to the OS preference", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: true,
    } as MediaQueryList);
    expect(applyMode("system")).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.documentElement.dataset.themeMode).toBe("system");
    expect(window.localStorage.getItem("ferriscd-theme")).toBe("system");
    expect(currentTheme()).toBe("light");
    expect(readMode()).toBe("system");
    expect(resolveMode("dark")).toBe("dark");
  });

  it("cycles light -> dark -> system -> light", () => {
    expect(nextMode("light")).toBe("dark");
    expect(nextMode("dark")).toBe("system");
    expect(nextMode("system")).toBe("light");
  });
});

describe("theme transition", () => {
  afterEach(() => vi.restoreAllMocks());

  it("uses one view transition and falls back when unsupported", () => {
    const commit = vi.fn();
    const start = vi.fn((cb: () => void) => cb());
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: false,
    } as MediaQueryList);
    Object.defineProperty(document, "startViewTransition", {
      configurable: true,
      value: start,
    });
    applyThemeTransition(commit);
    expect(start).toHaveBeenCalledTimes(1);
    expect(commit).toHaveBeenCalledTimes(1);

    start.mockClear();
    commit.mockClear();
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: true,
    } as MediaQueryList);
    applyThemeTransition(commit);
    expect(start).not.toHaveBeenCalled();
    expect(commit).toHaveBeenCalledTimes(1);
    delete (document as unknown as Record<string, unknown>).startViewTransition;
  });
});

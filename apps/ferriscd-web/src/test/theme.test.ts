import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyMode,
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

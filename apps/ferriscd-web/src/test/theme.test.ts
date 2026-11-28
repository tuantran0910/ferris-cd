import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { applyTheme, currentTheme, nextTheme } from "../app/theme";

describe("theme", () => {
  beforeEach(() => {
    delete document.documentElement.dataset.theme;
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("applies the theme to the document and remembers it", () => {
    applyTheme("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(window.localStorage.getItem("ferriscd-theme")).toBe("light");
    expect(currentTheme()).toBe("light");
  });

  it("toggles between light and dark", () => {
    expect(nextTheme("light")).toBe("dark");
    expect(nextTheme("dark")).toBe("light");
  });

  it("falls back to the OS preference when nothing was applied", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: true,
    } as MediaQueryList);
    expect(currentTheme()).toBe("light");
  });
});

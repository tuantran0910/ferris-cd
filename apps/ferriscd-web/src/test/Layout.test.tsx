import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Layout } from "../app/Layout";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { expectNoA11yViolations } from "./a11y";
import { createMockApiClient } from "./fixtures";

function renderShell(initialEntry = "/") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const mockClient = createMockApiClient();

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={mockClient}>
        <MemoryRouter initialEntries={[initialEntry]}>
          <Routes>
            <Route element={<Layout />}>
              <Route path="/" element={<h1>Applications</h1>} />
              <Route path="/overview" element={<h1>Fleet overview</h1>} />
              <Route path="/projects" element={<h1>Projects</h1>} />
              <Route path="/clusters" element={<h1>Clusters</h1>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("Layout accessibility (T17.3)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    window.localStorage.removeItem("ferriscd-theme");
    delete document.documentElement.dataset.theme;
    delete document.documentElement.dataset.themeMode;
    setStoredToken("test-token");
  });

  it("puts a working skip-to-content link first in the tab order", async () => {
    const user = userEvent.setup();
    renderShell();

    const skip = screen.getByTestId("skip-to-content");
    expect(skip).toHaveTextContent("Skip to main content");
    expect(skip).toHaveAttribute("href", "#main-content");

    // The `main` landmark is a focus target, so following the link actually moves focus.
    const main = screen.getByRole("main");
    expect(main).toHaveAttribute("id", "main-content");
    expect(main).toHaveAttribute("tabindex", "-1");

    // One Tab from the top of the document lands on the skip link, before the logo or the nav.
    await user.tab();
    expect(document.activeElement).toBe(skip);
  });

  it("marks the current page in the primary navigation with aria-current", async () => {
    renderShell("/projects");

    const nav = screen.getByRole("navigation", { name: "Primary" });
    const current = nav.querySelector('[aria-current="page"]');
    expect(current).not.toBeNull();
    expect(current).toHaveTextContent("Projects");
    // The other links are not marked, so the state is not implied by colour alone.
    expect(nav.querySelectorAll('[aria-current="page"]')).toHaveLength(1);
  });

  it("toggles the theme and persists the choice", async () => {
    const user = userEvent.setup();
    window.localStorage.setItem("ferriscd-theme", "light");
    document.documentElement.dataset.theme = "light";
    renderShell();

    await user.click(screen.getByTestId("theme-toggle"));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(window.localStorage.getItem("ferriscd-theme")).toBe("dark");

    await user.click(screen.getByTestId("theme-toggle"));
    expect(document.documentElement.dataset.themeMode).toBe("system");
    expect(window.localStorage.getItem("ferriscd-theme")).toBe("system");

    await user.click(screen.getByTestId("theme-toggle"));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(window.localStorage.getItem("ferriscd-theme")).toBe("light");
  });

  it("follows the OS theme while in system mode and cleans the listener up", async () => {
    window.localStorage.clear();
    delete document.documentElement.dataset.theme;
    delete document.documentElement.dataset.themeMode;
    let listener: (() => void) | undefined;
    const query = {
      matches: false,
      addEventListener: (_: string, cb: () => void) => {
        listener = cb;
      },
      removeEventListener: vi.fn(),
    };
    const matchMedia = vi
      .spyOn(window, "matchMedia")
      .mockReturnValue(query as unknown as MediaQueryList);

    const view = renderShell();
    expect(document.documentElement.dataset.themeMode).toBe("system");
    query.matches = true;
    listener?.();
    expect(document.documentElement.dataset.theme).toBe("light");

    view.unmount();
    expect(query.removeEventListener).toHaveBeenCalled();
    matchMedia.mockRestore();
  });

  it("offers Insights-free primary navigation to Applications, Projects and Clusters", () => {
    renderShell();

    const nav = screen.getByRole("navigation", { name: "Primary" });
    for (const name of ["Applications", "Projects", "Clusters"]) {
      expect(nav.querySelector(`a[href="${name === "Applications" ? "/" : `/${name.toLowerCase()}`}"]`))
        .not.toBeNull();
    }
  });

  it("offers the fleet overview as a primary destination (T20.5)", () => {
    renderShell("/overview");

    const nav = screen.getByRole("navigation", { name: "Primary" });
    const overview = nav.querySelector('a[href="/overview"]');
    expect(overview).not.toBeNull();
    expect(overview).toHaveTextContent("Overview");
  });

  it("opens the command palette from the header button and from the shortcut", async () => {
    const user = userEvent.setup();
    renderShell();

    const open = screen.getByRole("button", { name: /Search/i });
    expect(open).toHaveAttribute("aria-keyshortcuts", "Meta+K Control+K");
    await user.click(open);
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await user.keyboard("{Control>}k{/Control}");
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });

  it("has no critical/serious WCAG 2.2 AA violation with the palette open", async () => {
    const user = userEvent.setup();
    renderShell("/projects");
    await user.click(screen.getByRole("button", { name: /Search/i }));
    await screen.findByRole("dialog");
    await expectNoA11yViolations(document.body);
  });
});

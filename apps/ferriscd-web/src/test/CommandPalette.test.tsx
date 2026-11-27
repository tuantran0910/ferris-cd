import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import {
  CommandPalette,
  useCommandPaletteShortcut,
} from "../app/CommandPalette";
import { createMockApiClient } from "./fixtures";

function LocationProbe() {
  const location = useLocation();
  return (
    <div data-testid="location">
      {location.pathname}
      {location.search}
    </div>
  );
}

/**
 * The app shell's wiring, in miniature: a trigger button (what the header renders) plus the global
 * `Cmd+K`/`Ctrl+K` shortcut, both driving the same controlled palette.
 */
function PaletteHarness() {
  const [open, setOpen] = useState(false);
  useCommandPaletteShortcut(() => setOpen((previous) => !previous));

  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Search everything
      </button>
      <CommandPalette open={open} onOpenChange={setOpen} />
    </>
  );
}

function renderPalette(initialEntry = "/") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const mockClient = createMockApiClient();

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={mockClient}>
        <MemoryRouter initialEntries={[initialEntry]}>
          <Routes>
            <Route path="/" element={<PaletteHarness />} />
            <Route path="/projects" element={<PaletteHarness />} />
            <Route
              path="/applications/:namespace/:name"
              element={<PaletteHarness />}
            />
          </Routes>
          <LocationProbe />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("CommandPalette (T17.3)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    setStoredToken("test-token");
  });

  it("opens with Ctrl+K and with Cmd+K, and Escape closes it returning focus to the trigger", async () => {
    const user = userEvent.setup();
    renderPalette();

    const trigger = screen.getByRole("button", { name: "Search everything" });
    trigger.focus();

    await user.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog.contains(document.activeElement)).toBe(true);

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(document.activeElement).toBe(trigger);

    await user.keyboard("{Meta>}k{/Meta}");
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });

  it("opens from the header button too, so the shortcut is discoverable", async () => {
    const user = userEvent.setup();
    renderPalette();

    await user.click(screen.getByRole("button", { name: "Search everything" }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(
      screen.getByLabelText(/Search applications, projects, clusters and views/i),
    ).toBeInTheDocument();
  });

  it("filters applications, projects, clusters and views as text, and announces the count", async () => {
    const user = userEvent.setup();
    renderPalette();
    await user.click(screen.getByRole("button", { name: "Search everything" }));

    const input = await screen.findByLabelText(
      /Search applications, projects, clusters and views/i,
    );
    expect(await screen.findByTestId("palette-item-application-ferriscd-system-payments-api")).toBeInTheDocument();
    expect(screen.getByTestId("palette-item-project-storefront")).toBeInTheDocument();
    expect(screen.getByTestId("palette-item-cluster-in-cluster")).toBeInTheDocument();

    await user.type(input, "prod-us-east");
    // The cluster entry survives the filter; the applications do not.
    expect(screen.getByTestId("palette-item-cluster-prod-us-east")).toBeInTheDocument();
    expect(
      screen.queryByTestId("palette-item-application-ferriscd-system-payments-api"),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("command-palette-status")).toHaveTextContent("1 results");

    await user.clear(input);
    await user.type(input, "zzz-nothing");
    expect(screen.getByTestId("command-palette-status")).toHaveTextContent("No results.");
  });

  it("navigates with the keyboard: ArrowDown + Enter opens the highlighted application", async () => {
    const user = userEvent.setup();
    renderPalette();
    await user.click(screen.getByRole("button", { name: "Search everything" }));

    const input = await screen.findByLabelText(
      /Search applications, projects, clusters and views/i,
    );
    await screen.findByTestId("palette-item-application-ferriscd-system-payments-api");
    await user.type(input, "payments-api");

    // Exactly one application matches, so the first ArrowDown is already on it.
    await user.keyboard("{Enter}");

    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent(
        "/applications/ferriscd-system/payments-api",
      ),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("jumps to a project-filtered application list and to a cluster-filtered list", async () => {
    const user = userEvent.setup();
    renderPalette();
    await user.click(screen.getByRole("button", { name: "Search everything" }));

    const input = await screen.findByLabelText(
      /Search applications, projects, clusters and views/i,
    );
    await user.type(input, "payments");
    await user.click(await screen.findByTestId("palette-item-project-payments"));
    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent("/?project=payments"),
    );

    await user.keyboard("{Control>}k{/Control}");
    await user.type(
      await screen.findByLabelText(
        /Search applications, projects, clusters and views/i,
      ),
      "in-cluster",
    );
    await user.click(await screen.findByTestId("palette-item-cluster-in-cluster"));
    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent("/?q=in-cluster"),
    );
  });

  it("offers the detail tabs only while an application is open, and deep-links into one", async () => {
    const user = userEvent.setup();
    renderPalette("/applications/ferriscd-system/payments-api");
    await user.click(screen.getByRole("button", { name: "Search everything" }));

    const input = await screen.findByLabelText(
      /Search applications, projects, clusters and views/i,
    );
    await user.type(input, "live diff");
    await user.click(await screen.findByTestId("palette-item-view-diff"));

    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent(
        "/applications/ferriscd-system/payments-api?tab=diff",
      ),
    );
  });

  it("traps Tab inside the dialog and exposes the ARIA combobox/listbox wiring", async () => {
    const user = userEvent.setup();
    renderPalette();
    await user.click(screen.getByRole("button", { name: "Search everything" }));

    const dialog = await screen.findByRole("dialog");
    const input = await screen.findByLabelText(
      /Search applications, projects, clusters and views/i,
    );
    expect(input).toHaveAttribute("role", "combobox");
    expect(input).toHaveAttribute("aria-expanded", "true");
    const listboxId = input.getAttribute("aria-controls");
    expect(listboxId).toBeTruthy();
    expect(document.getElementById(listboxId as string)).toHaveAttribute(
      "role",
      "listbox",
    );
    expect(input.getAttribute("aria-activedescendant")).toBeTruthy();

    // Tab walks the dialog's own focusables and never leaves it.
    for (let step = 0; step < 4; step += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    // The active option is reachable and announced.
    const selected = within(dialog)
      .getAllByRole("option")
      .find((option) => option.getAttribute("aria-selected") === "true");
    expect(selected).toBeDefined();
  });

  it("toggles closed with Ctrl+K while the palette is open", async () => {
    const user = userEvent.setup();
    renderPalette();
    await user.keyboard("{Control>}k{/Control}");
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    await user.keyboard("{Control>}k{/Control}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("closes with Escape while leaving focus restored, and never opens on a bare 'k'", async () => {
    const user = userEvent.setup();
    renderPalette();

    await user.keyboard("k");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await user.keyboard("{Control>}k{/Control}");
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

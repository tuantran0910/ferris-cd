import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClientError } from "../api/client";
import { AuthProvider } from "../auth/AuthContext";
import { getStoredToken, resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { ApplicationsPage } from "../features/applications/ApplicationsPage";
import { createMockApiClient, sampleApps } from "./fixtures";

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location-search">{location.search}</div>;
}

function renderApplicationsPage(
  overrides: Parameters<typeof createMockApiClient>[0] = {},
  initialEntry = "/",
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const mockClient = createMockApiClient(overrides);

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={mockClient}>
        <MemoryRouter initialEntries={[initialEntry]}>
          <ApplicationsPage />
          <LocationProbe />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("ApplicationsPage (T16.2 & Trap Guard T16.2)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    setStoredToken("test-token");
  });

  it("renders separate Sync Status and Health Status badges for every application", async () => {
    renderApplicationsPage();

    const paymentsCard = await screen.findByTestId(
      "app-card-ferriscd-system-payments-api",
    );
    const syncBadge = within(paymentsCard).getByTestId("sync-status-badge");
    const healthBadge = within(paymentsCard).getByTestId("health-status-badge");

    expect(syncBadge).toHaveTextContent("Sync:OutOfSync");
    expect(healthBadge).toHaveTextContent("Health:Healthy");
    expect(syncBadge).not.toBe(healthBadge);

    const checkoutCard = screen.getByTestId(
      "app-card-ferriscd-system-checkout-web",
    );
    expect(
      within(checkoutCard).getByTestId("sync-status-badge"),
    ).toHaveTextContent("Sync:Synced");
    expect(
      within(checkoutCard).getByTestId("health-status-badge"),
    ).toHaveTextContent("Health:Degraded");
  });

  it("applies an SSE snapshot to the list without a refetch", async () => {
    const streamed = { ...sampleApps[0], name: "live-only" };
    const encoder = new TextEncoder();
    const nativeFetch = globalThis.fetch;
    const streamFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes("/api/v1/applications/stream")) {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(
              encoder.encode(
                `event: applications\ndata: ${JSON.stringify({ items: [streamed] })}\n\n`,
              ),
            );
            init?.signal?.addEventListener("abort", () =>
              controller.error(new DOMException("aborted", "AbortError")),
            );
          },
        });
        return new Response(body, { status: 200 });
      }
      return nativeFetch(input, init);
    });
    globalThis.fetch = streamFetch as typeof fetch;

    try {
      renderApplicationsPage();
      expect(await screen.findByText("live-only")).toBeInTheDocument();
      expect(screen.getByText(/Live updates connected/)).toBeInTheDocument();
    } finally {
      globalThis.fetch = nativeFetch;
    }
  });

  it("signs out instead of retrying when the stream rejects the token", async () => {
    const nativeFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => new Response(null, { status: 401 })) as typeof fetch;
    try {
      renderApplicationsPage();
      await waitFor(() => expect(getStoredToken()).toBeNull());
    } finally {
      globalThis.fetch = nativeFetch;
    }
  });

  it("filters instantly by project, syncStatus, healthStatus, and search query", async () => {
    const user = userEvent.setup();
    renderApplicationsPage();

    expect(await screen.findByText("payments-api")).toBeInTheDocument();
    expect(screen.getByText("checkout-web")).toBeInTheDocument();
    expect(screen.getByText("observability-stack")).toBeInTheDocument();

    const pick = async (label: RegExp, optionName: string) => {
      await user.click(screen.getByRole("combobox", { name: label }));
      await user.click(screen.getByRole("option", { name: optionName }));
    };

    // Filter by project
    await pick(/Filter by project/i, "payments");
    expect(screen.getByText("payments-api")).toBeInTheDocument();
    expect(screen.queryByText("checkout-web")).not.toBeInTheDocument();

    // Reset project and filter by health status
    await pick(/Filter by project/i, "All Projects");
    await pick(/Filter by health status/i, "Degraded");
    expect(screen.getByText("checkout-web")).toBeInTheDocument();
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();

    // Reset health and filter by sync status
    await pick(/Filter by health status/i, "All Health Statuses");
    await pick(/Filter by sync status/i, "OutOfSync");
    expect(screen.getByText("payments-api")).toBeInTheDocument();
    expect(screen.queryByText("observability-stack")).not.toBeInTheDocument();

    // Reset sync and filter by search text
    await pick(/Filter by sync status/i, "All Sync Statuses");
    await user.type(screen.getByLabelText(/Search applications/i), "monitoring");
    expect(screen.getByText("observability-stack")).toBeInTheDocument();
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();
  });

  it("keeps filters and layout in the URL so a filtered view survives navigation (H6)", async () => {
    const user = userEvent.setup();
    const { unmount } = renderApplicationsPage();

    expect(await screen.findByTestId("applications-grid")).toBeInTheDocument();

    await user.click(
      screen.getByRole("combobox", { name: /Filter by project/i }),
    );
    await user.click(screen.getByRole("option", { name: "payments" }));
    await user.click(screen.getByRole("button", { name: /Table view/i }));
    await user.type(screen.getByLabelText(/Search applications/i), "payments");

    const search = screen.getByTestId("location-search").textContent ?? "";
    expect(search).toContain("project=payments");
    expect(search).toContain("view=table");
    expect(search).toContain("q=payments");

    // Unmount (navigate away) then mount again with only the URL to go on.
    unmount();
    renderApplicationsPage({}, `/${search}`);
    expect(await screen.findByTestId("applications-table")).toBeInTheDocument();
    expect(screen.getByText("ferriscd-system/payments-api")).toBeInTheDocument();
    expect(screen.queryByText("checkout-web")).not.toBeInTheDocument();
    expect(screen.getByLabelText(/Search applications/i)).toHaveValue(
      "payments",
    );
  });

  it("does not claim 'No Applications visible' when the list request itself failed (H1)", async () => {
    renderApplicationsPage({
      listApplications: async () => {
        throw new ApiClientError(502, "BackendUnavailable", "cluster read failed");
      },
    });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "cluster read failed",
    );
    expect(
      screen.queryByText("No Applications visible to your identity."),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("No Applications match the current filters."),
    ).not.toBeInTheDocument();
  });

  it("renders a network-failure headline instead of 'HTTP_0' when the server is unreachable", async () => {
    renderApplicationsPage({
      listApplications: async () => {
        throw new ApiClientError(0, "HTTP_0", "Network error communicating with FerrisCD API server.");
      },
    });

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("API Server Unreachable");
    expect(alert).not.toHaveTextContent("HTTP_0");
    expect(alert).toHaveTextContent("could not be reached");
  });

  it("supports switching between Grid View and Table View", async () => {
    const user = userEvent.setup();
    renderApplicationsPage();

    expect(await screen.findByTestId("applications-grid")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Table view/i }));
    expect(screen.getByTestId("applications-table")).toBeInTheDocument();
  });

  it("seeds canonical sync/health options and keeps selected filter stable across polling updates (M5)", async () => {
    const user = userEvent.setup();
    let callCount = 0;
    renderApplicationsPage({
      listApplications: async () => {
        callCount += 1;
        if (callCount === 1) {
          return { items: sampleApps };
        }
        // Second fetch: all apps recovered to Healthy
        return {
          items: sampleApps.map((a) => ({
            ...a,
            health: { status: "Healthy", message: null },
          })),
        };
      },
    });

    expect(await screen.findByText("checkout-web")).toBeInTheDocument();

    // Canonical statuses are always available even if no current app has them
    const healthSelect = screen.getByRole("combobox", {
      name: /Filter by health status/i,
    });
    await user.click(healthSelect);
    expect(
      screen.getByRole("option", { name: "Suspended" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("option", { name: "Progressing" }),
    ).toBeInTheDocument();

    // Select Degraded, then refresh when all apps become Healthy
    await user.click(screen.getByRole("option", { name: "Degraded" }));
    expect(healthSelect).toHaveTextContent("Degraded");
    expect(screen.getByText("checkout-web")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Refresh/i }));
    expect(
      await screen.findByText("No Applications match the current filters."),
    ).toBeInTheDocument();
    expect(healthSelect).toHaveTextContent("Degraded");

    // ...and the operator can recover with one click.
    await user.click(screen.getByRole("button", { name: /Clear filters/i }));
    expect(await screen.findByText("checkout-web")).toBeInTheDocument();
  });
});

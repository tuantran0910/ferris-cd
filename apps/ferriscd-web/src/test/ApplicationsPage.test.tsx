import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { ApplicationsPage } from "../pages/ApplicationsPage";
import { createMockApiClient, sampleApps } from "./fixtures";

function renderApplicationsPage(
  overrides: Parameters<typeof createMockApiClient>[0] = {},
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const mockClient = createMockApiClient(overrides);

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={mockClient}>
        <MemoryRouter>
          <ApplicationsPage />
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

  it("filters instantly by project, syncStatus, healthStatus, and search query", async () => {
    const user = userEvent.setup();
    renderApplicationsPage();

    expect(await screen.findByText("payments-api")).toBeInTheDocument();
    expect(screen.getByText("checkout-web")).toBeInTheDocument();
    expect(screen.getByText("observability-stack")).toBeInTheDocument();

    // Filter by project
    await user.selectOptions(
      screen.getByLabelText(/Filter by project/i),
      "payments",
    );
    expect(screen.getByText("payments-api")).toBeInTheDocument();
    expect(screen.queryByText("checkout-web")).not.toBeInTheDocument();

    // Reset project and filter by health status
    await user.selectOptions(screen.getByLabelText(/Filter by project/i), "ALL");
    await user.selectOptions(
      screen.getByLabelText(/Filter by health status/i),
      "Degraded",
    );
    expect(screen.getByText("checkout-web")).toBeInTheDocument();
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();

    // Reset health and filter by sync status
    await user.selectOptions(
      screen.getByLabelText(/Filter by health status/i),
      "ALL",
    );
    await user.selectOptions(
      screen.getByLabelText(/Filter by sync status/i),
      "OutOfSync",
    );
    expect(screen.getByText("payments-api")).toBeInTheDocument();
    expect(screen.queryByText("observability-stack")).not.toBeInTheDocument();

    // Reset sync and filter by search text
    await user.selectOptions(
      screen.getByLabelText(/Filter by sync status/i),
      "ALL",
    );
    await user.type(screen.getByLabelText(/Search applications/i), "monitoring");
    expect(screen.getByText("observability-stack")).toBeInTheDocument();
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();
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
    const healthSelect = screen.getByLabelText(
      /Filter by health status/i,
    ) as HTMLSelectElement;
    expect(
      within(healthSelect).getByRole("option", { name: "Suspended" }),
    ).toBeInTheDocument();
    expect(
      within(healthSelect).getByRole("option", { name: "Progressing" }),
    ).toBeInTheDocument();

    // Select Degraded, then refresh when all apps become Healthy
    await user.selectOptions(healthSelect, "Degraded");
    expect(healthSelect.value).toBe("Degraded");
    expect(screen.getByText("checkout-web")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Refresh/i }));
    expect(
      await screen.findByText("No Applications match the current filters."),
    ).toBeInTheDocument();
    expect(healthSelect.value).toBe("Degraded");
  });
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClientError, type FerrisApiClient } from "../api/client";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { ApplicationDetailPage } from "../features/applications/ApplicationDetailPage";
import { createMockApiClient, sampleAppDetail, sampleApps } from "./fixtures";

function renderDetailPage(overrides: Partial<FerrisApiClient> = {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const mockClient = createMockApiClient(overrides);

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={mockClient}>
        <MemoryRouter initialEntries={["/applications/ferriscd-system/payments-api"]}>
          <Routes>
            <Route
              path="/applications/:namespace/:name"
              element={<ApplicationDetailPage />}
            />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("ApplicationDetailPage (T16.2 & T16.4 integration)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    setStoredToken("test-token");
  });

  it("supports APG arrow/Home/End navigation between detail tabs", async () => {
    const user = userEvent.setup();
    renderDetailPage();
    await screen.findByRole("heading", { name: "payments-api" });

    const resources = screen.getByRole("tab", { name: /Resources/ });
    expect(resources).toHaveAttribute("aria-controls", "app-tabpanel");
    expect(resources).toHaveAttribute("tabindex", "0");
    resources.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Live Diff" })).toHaveFocus();
    await user.keyboard("{End}");
    expect(screen.getByRole("tab", { name: /History/ })).toHaveFocus();
    await user.keyboard("{Home}");
    expect(screen.getByRole("tab", { name: /Resources/ })).toHaveFocus();
    expect(screen.getByRole("tabpanel")).toHaveAttribute(
      "aria-labelledby",
      "app-tab-resources",
    );
  });

  it("displays separate Sync and Health badges, source/destination summary, conditions timeline, and history table", async () => {
    const user = userEvent.setup();
    renderDetailPage();

    expect(
      await screen.findByRole("heading", { name: "payments-api" }),
    ).toBeInTheDocument();

    // Separate Sync & Health badges in header (Trap Guard T16.2)
    const syncBadges = screen.getAllByTestId("sync-status-badge");
    const healthBadges = screen.getAllByTestId("health-status-badge");
    expect(syncBadges[0]).toHaveTextContent("Sync:OutOfSync");
    expect(healthBadges[0]).toHaveTextContent("Health:Healthy");

    // Source & destination summary
    const summarySection = screen.getByLabelText(
      "Source and destination summary",
    );
    expect(
      within(summarySection).getByText(
        "https://github.com/acme/gitops-payments.git",
      ),
    ).toBeInTheDocument();
    expect(within(summarySection).getByText("prod-us-east")).toBeInTheDocument();

    // Conditions timeline tab
    await user.click(screen.getByRole("tab", { name: /Conditions/i }));
    const timeline = screen.getByTestId("conditions-timeline");
    expect(timeline).toHaveTextContent("Reconciled");
    expect(timeline).toHaveTextContent("Deployment replicas differ from Git");

    // History table tab
    await user.click(screen.getByRole("tab", { name: /History/i }));
    const historyTable = screen.getByTestId("history-table");
    expect(historyTable).toHaveTextContent("#2");
    expect(historyTable).toHaveTextContent("#1");

    // Diff tab
    await user.click(screen.getByRole("tab", { name: /Live Diff/i }));
    expect(
      await screen.findByText("***REDACTED(sha256:9f86d081)***"),
    ).toBeInTheDocument();
  });

  it("disables Sync action and displays read-only notice when server responds 403 Forbidden", async () => {
    const user = userEvent.setup();
    renderDetailPage({
      syncApplication: async () => {
        throw new ApiClientError(
          403,
          "Forbidden",
          "caller cannot sync project payments",
        );
      },
    });

    const syncButton = await screen.findByRole("button", { name: /^Sync$/i });
    await user.click(syncButton);
    await user.click(screen.getByRole("button", { name: /Confirm Sync/i }));

    expect(await screen.findByTestId("sync-rbac-forbidden")).toHaveTextContent(
      "caller cannot sync project payments",
    );
    await user.click(screen.getByRole("button", { name: /Cancel/i }));

    expect(screen.getByTestId("detail-rbac-readonly-notice")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Sync$/i })).toBeDisabled();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("resets RBAC 403 disabled state and modal state when navigating from App A to App B (H2)", async () => {
    const user = userEvent.setup();
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const appBDetail = {
      ...sampleAppDetail,
      application: sampleApps[1]!,
    };
    const mockClient = createMockApiClient({
      getApplication: async (_ns, name) =>
        name === "checkout-web" ? appBDetail : sampleAppDetail,
      syncApplication: async (_ns, name) => {
        if (name === "payments-api") {
          throw new ApiClientError(
            403,
            "Forbidden",
            "caller cannot sync project payments",
          );
        }
        return {
          status: "accepted",
          operation: "sync",
          namespace: "ferriscd-system",
          name,
          request: '{"sync":{}}',
        };
      },
      rollbackApplication: async (_ns, name) => {
        if (name === "payments-api") {
          throw new ApiClientError(
            403,
            "Forbidden",
            "caller cannot roll back project payments",
          );
        }
        return {
          status: "accepted",
          operation: "rollback",
          namespace: "ferriscd-system",
          name,
          request: '{"rollback":{"id":1}}',
        };
      },
    });

    render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider clientOverride={mockClient}>
          <MemoryRouter
            initialEntries={["/applications/ferriscd-system/payments-api"]}
          >
            <Link to="/applications/ferriscd-system/checkout-web">
              Go to App B
            </Link>
            <Routes>
              <Route
                path="/applications/:namespace/:name"
                element={<ApplicationDetailPage />}
              />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>,
    );

    // Trigger 403 on App A (Sync + Rollback)
    await user.click(await screen.findByRole("button", { name: /^Sync$/i }));
    await user.click(screen.getByRole("button", { name: /Confirm Sync/i }));
    expect(await screen.findByTestId("sync-rbac-forbidden")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Cancel/i }));

    await user.click(screen.getByRole("button", { name: /^Rollback$/i }));
    await user.click(screen.getByRole("button", { name: /Confirm Rollback/i }));
    expect(
      await screen.findByTestId("rollback-rbac-forbidden"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Cancel/i }));

    expect(screen.getByRole("button", { name: /^Sync$/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /^Rollback$/i })).toBeDisabled();
    expect(
      screen.getByTestId("detail-rbac-readonly-notice"),
    ).toBeInTheDocument();

    // Navigate to App B -> RBAC state must reset cleanly
    await user.click(screen.getByRole("link", { name: "Go to App B" }));
    expect(
      await screen.findByRole("heading", { name: "checkout-web" }),
    ).toBeInTheDocument();

    expect(screen.getByRole("button", { name: /^Sync$/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /^Rollback$/i })).toBeEnabled();
    expect(
      screen.queryByTestId("detail-rbac-readonly-notice"),
    ).not.toBeInTheDocument();
  });

  it("clears diffFilterKey when clicking the Live Diff tab directly (M4)", async () => {
    const user = userEvent.setup();
    renderDetailPage();

    expect(
      await screen.findByRole("heading", { name: "payments-api" }),
    ).toBeInTheDocument();

    // Inspect a single resource from Resource Table View -> opens filtered Live Diff
    await user.click(
      await screen.findByRole("button", { name: /Resource Table View/i }),
    );
    await user.click(
      within(screen.getByTestId("resource-table-view")).getByText(
        "payments-api",
      ),
    );
    await user.click(
      screen.getByRole("button", { name: /View Resource in Diff/i }),
    );

    const diffSearch = await screen.findByLabelText(/Filter diff resources/i);
    expect(diffSearch).toHaveValue("apps/Deployment/payments/payments-api");

    // Clicking the Live Diff tab directly must clear diffFilterKey
    await user.click(screen.getByRole("tab", { name: /Live Diff/i }));
    expect(screen.getByLabelText(/Filter diff resources/i)).toHaveValue("");
  });

  it("returns to the filtered list view via the back link carried in router state (H6)", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider clientOverride={createMockApiClient()}>
          <MemoryRouter
            initialEntries={[
              {
                pathname: "/applications/ferriscd-system/payments-api",
                state: { listSearch: "?project=payments&view=table" },
              },
            ]}
          >
            <Routes>
              <Route
                path="/applications/:namespace/:name"
                element={<ApplicationDetailPage />}
              />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>,
    );

    const backLinks = await screen.findAllByRole("link", {
      name: /Applications/i,
    });
    expect(backLinks[0]).toHaveAttribute(
      "href",
      "/?project=payments&view=table",
    );
  });

  it("stops detail polling when the server returns 403 or 404 (M8)", async () => {
    vi.useFakeTimers();

    for (const err of [
      new ApiClientError(404, "NotFound", "Application not found"),
      new ApiClientError(403, "Forbidden", "Access denied"),
    ]) {
      const getApplication = vi.fn().mockRejectedValue(err);
      const { unmount } = renderDetailPage({ getApplication });

      // Let initial query reject and render error alert
      await act(async () => {
        await vi.advanceTimersByTimeAsync(50);
      });
      expect(getApplication).toHaveBeenCalledTimes(1);

      // Advance well past 10_000ms poll interval -> must not refetch on 403/404
      await act(async () => {
        await vi.advanceTimersByTimeAsync(25_000);
      });
      expect(getApplication).toHaveBeenCalledTimes(1);
      unmount();
    }
  });
});

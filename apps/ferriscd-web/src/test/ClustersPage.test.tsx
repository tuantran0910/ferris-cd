import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { ApiClientError } from "../api/client";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { ClustersPage } from "../features/clusters/ClustersPage";
import { createMockApiClient, sampleApps } from "./fixtures";

function LocationProbe() {
  const location = useLocation();
  return (
    <div data-testid="location">
      {location.pathname}
      {location.search}
    </div>
  );
}

function renderClustersPage(
  overrides: Parameters<typeof createMockApiClient>[0] = {},
  entry = "/clusters",
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const mockClient = createMockApiClient(overrides);

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={mockClient}>
        <MemoryRouter initialEntries={[entry]}>
          <Routes>
            <Route path="/clusters" element={<ClustersPage />} />
            <Route path="/" element={<div>applications-list</div>} />
          </Routes>
          <LocationProbe />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("ClustersPage (T17.3)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    setStoredToken("test-token");
  });

  it("shows in-cluster and remote clusters the caller may deploy to, with a health rollup", async () => {
    renderClustersPage();

    const inCluster = (await screen.findByTestId("cluster-card-in-cluster")).closest("li");
    expect(inCluster).not.toBeNull();
    const localCard = within(inCluster as HTMLElement);
    expect(localCard.getByRole("link", { name: "in-cluster" })).toBeInTheDocument();
    // `sampleApps` on `in-cluster`: checkout-web (Degraded) + observability-stack (Healthy).
    expect(localCard.getByTestId("cluster-metric-applications")).toHaveTextContent("2");
    expect(localCard.getByTestId("cluster-metric-degraded")).toHaveTextContent("1");
    expect(localCard.getByTestId("cluster-metric-out-of-sync")).toHaveTextContent("0");
    expect(localCard.getByText("in-cluster", { selector: "span" })).toBeInTheDocument();

    const remote = screen.getByTestId("cluster-card-prod-us-east");
    // payments-api is OutOfSync on prod-us-east.
    expect(within(remote).getByTestId("cluster-metric-out-of-sync")).toHaveTextContent("1");
    expect(within(remote).getByTestId("cluster-metric-applications")).toHaveTextContent("1");
    expect(within(remote).getByText("remote")).toBeInTheDocument();

    expect(screen.getByTestId("clusters-live-region")).toHaveTextContent(
      `Showing 2 clusters with ${sampleApps.length} visible applications.`,
    );
  });

  it("rolls up sync/health per cluster instead of showing a bare total", async () => {
    renderClustersPage();

    const inCluster = (await screen.findByTestId("cluster-card-in-cluster")).closest("li");
    expect(inCluster).not.toBeNull();
    // Healthy: observability-stack; Degraded: checkout-web. The breakdown is textual, so the
    // values survive a greyscale screenshot.
    const card = within(inCluster as HTMLElement);
    expect(card.getByTestId("cluster-health-healthy")).toHaveTextContent("Healthy: 1");
    expect(card.getByTestId("cluster-health-degraded")).toHaveTextContent("Degraded: 1");
    expect(card.getByTestId("cluster-health-progressing")).toHaveTextContent("Progressing: 0");
    // The rollup badges name the worst state on the cluster, not a bare colour.
    expect(card.getByTestId("sync-status-badge")).toHaveTextContent("Sync:Synced");
    expect(card.getByTestId("health-status-badge")).toHaveTextContent("Health:Degraded");
  });

  it("links a cluster to the filtered application list", async () => {
    const user = userEvent.setup();
    renderClustersPage();

    const card = await screen.findByTestId("cluster-card-prod-us-east");
    await user.click(within(card).getByRole("link", { name: "prod-us-east" }));
    expect(screen.getByTestId("location")).toHaveTextContent("/?q=prod-us-east");
    expect(screen.getByText("applications-list")).toBeInTheDocument();
  });

  it("renders a cluster with no visible applications without inventing a status", async () => {
    renderClustersPage({
      listApplications: async () => ({ items: [] }),
    });

    const card = await screen.findByTestId("cluster-card-in-cluster");
    expect(card).toHaveTextContent("no visible applications");
    expect(within(card).queryByTestId("sync-status-badge")).not.toBeInTheDocument();
  });

  it("never claims 'no clusters' when the request itself failed", async () => {
    renderClustersPage({
      listClusters: async () => {
        throw new ApiClientError(502, "BackendUnavailable", "cluster read failed");
      },
    });

    expect(await screen.findByRole("alert")).toHaveTextContent("cluster read failed");
    expect(
      screen.queryByText(/No destination clusters are visible to your identity/i),
    ).not.toBeInTheDocument();
  });

  it("explains an empty registry with the AppProject rule that produces it", async () => {
    renderClustersPage({ listClusters: async () => ({ items: [] }) });

    expect(
      await screen.findByText(/No destination clusters are visible to your identity/i),
    ).toBeInTheDocument();
  });

  it("filters by ?q and explains an empty match with a way back", async () => {
    renderClustersPage({}, "/clusters?q=nope");
    expect(await screen.findByText(/No cluster matches/i)).toBeInTheDocument();
    expect(
      screen.getByText(/0 of 2 clusters match “nope”/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /clear the filter/i })).toHaveAttribute(
      "href",
      "/clusters",
    );
  });

  it("uses singular agreement when one of one cluster matches", async () => {
    renderClustersPage({}, "/clusters?q=in-cluster");
    expect(
      await screen.findByText(/1 of 2 clusters matches “in-cluster”/i),
    ).toBeInTheDocument();
    expect(screen.getByTestId("cluster-card-in-cluster")).toBeInTheDocument();
    expect(screen.queryByTestId("cluster-card-prod-us-east")).not.toBeInTheDocument();
  });
});

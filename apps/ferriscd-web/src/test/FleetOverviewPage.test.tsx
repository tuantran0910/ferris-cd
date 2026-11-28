import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import type { ApplicationSummary } from "../api/types";
import { App } from "../app/App";
import { Layout } from "../app/Layout";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { FleetOverviewPage, TRIAGE_LIMIT } from "../features/overview/FleetOverviewPage";
import { expectNoA11yViolations } from "./a11y";
import { createMockApiClient, sampleApps } from "./fixtures";

/** An `Application` summary with the fields the overview reads, overridable per test. */
function app(overrides: Partial<ApplicationSummary> = {}): ApplicationSummary {
  return {
    namespace: "ferriscd-system",
    name: "app",
    project: "payments",
    resourceCount: 10,
    source: {
      sourceType: "git",
      repoUrl: "https://github.com/acme/gitops.git",
      path: "apps/app",
      targetRevision: "main",
      renderer: "plainYaml",
    },
    destination: { cluster: "in-cluster", namespace: "app" },
    sync: { status: "Synced" },
    health: { status: "Healthy" },
    conditions: [],
    ...overrides,
  };
}

function renderOverview(
  overrides: Parameters<typeof createMockApiClient>[0] = {},
  initialEntry = "/overview",
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const client = createMockApiClient(overrides);
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={client}>
        <MemoryRouter initialEntries={[initialEntry]}>
          <FleetOverviewPage />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

function kpiValue(testId: string): string {
  return screen.getByTestId(`overview-kpi-${testId}-value`).textContent!;
}

describe("FleetOverviewPage (T20.5)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    window.localStorage.clear();
    setStoredToken("test-token");
  });

  it("rolls up cross-cluster sync and health KPIs from the visible applications", async () => {
    renderOverview();

    await screen.findByTestId("overview-kpi-total");

    // The default fixture: 3 applications across 2 clusters and 3 projects.
    expect(kpiValue("total")).toBe("3");
    expect(kpiValue("synced")).toBe("2");
    expect(kpiValue("out-of-sync")).toBe("1");
    expect(kpiValue("degraded")).toBe("1"); // checkout-web is Degraded
    expect(kpiValue("policy-violations")).toBe("0");
    expect(
      within(screen.getByTestId("overview-kpi-total")).getByText("45 tracked resources"),
    ).toBeInTheDocument();

    // Cluster breakdown: prod-us-east carries the out-of-sync app, in-cluster the degraded one.
    const clusters = screen.getByTestId("overview-clusters");
    const prodRow = within(clusters).getByTestId("overview-clusters-prod-us-east");
    expect(within(prodRow).getByRole("rowheader")).toHaveTextContent("prod-us-east");
    const prodCells = within(prodRow).getAllByRole("cell").map((cell) => cell.textContent);
    expect(prodCells).toEqual(["1", "1", "0", "0", "0"]);

    const inClusterRow = within(clusters).getByTestId("overview-clusters-in-cluster");
    const inClusterCells = within(inClusterRow)
      .getAllByRole("cell")
      .map((cell) => cell.textContent);
    expect(inClusterCells).toEqual(["2", "0", "1", "0", "0"]);

    // Project breakdown is the tenant partition (the axis RBAC scopes on).
    const projects = screen.getByTestId("overview-projects");
    expect(
      within(within(projects).getByTestId("overview-projects-payments")).getAllByRole(
        "cell",
      )[0],
    ).toHaveTextContent("1");
    expect(
      within(projects).getByTestId("overview-projects-platform"),
    ).toBeInTheDocument();
    expect(
      within(projects).getByTestId("overview-projects-storefront"),
    ).toBeInTheDocument();
  });

  it("queues degraded and out-of-sync applications for triage, most urgent first", async () => {
    renderOverview();

    const triage = await screen.findByTestId("overview-triage");
    const rows = within(triage).getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    // Degraded outranks OutOfSync.
    expect(rows[0]).toHaveTextContent("ferriscd-system/checkout-web");
    expect(rows[0]).toHaveTextContent("Pod checkout-web-0 CrashLoopBackOff");
    expect(rows[1]).toHaveTextContent("ferriscd-system/payments-api");
    expect(rows[1]).toHaveTextContent("out of sync with Git");
    // The healthy application is not in the queue.
    expect(
      within(triage).queryByText("ferriscd-system/observability-stack"),
    ).not.toBeInTheDocument();
    // Each entry links to the application it names.
    expect(
      within(rows[0]!).getByRole("link", { name: "ferriscd-system/checkout-web" }),
    ).toHaveAttribute("href", "/applications/ferriscd-system/checkout-web");
  });

  it("counts a blocking policy violation from the Ready condition the controller writes", async () => {
    const blocked = app({
      name: "payments-api",
      conditions: [
        {
          type: "Ready",
          status: "False",
          reason: "PolicyViolation",
          message: 'policy "no-privileged" rejected Deployment payments/api',
          lastTransitionTime: "2026-11-28T10:00:00Z",
          observedGeneration: 2,
        },
      ],
      sync: { status: "OutOfSync" },
      health: { status: "Degraded", message: "refused by policy" },
    });
    renderOverview({
      listApplications: async () => ({ items: [blocked] }),
      listProjects: async () => ({ items: [{ name: "payments" }] }),
      listClusters: async () => ({
        items: [{ name: "in-cluster", inCluster: true }],
      }),
    });

    await screen.findByTestId("overview-kpi-total");
    expect(kpiValue("policy-violations")).toBe("1");
    const row = screen.getByTestId("overview-clusters-in-cluster");
    expect(within(row).getAllByRole("cell").map((cell) => cell.textContent)).toEqual([
      "1",
      "1",
      "1",
      "0",
      "1",
    ]);
    // A policy violation is the most urgent triage reason, so it heads the queue.
    const firstRow = within(screen.getByTestId("overview-triage")).getAllByRole(
      "listitem",
    )[0]!;
    expect(firstRow).toHaveTextContent("blocked by an Enforce policy rule");
  });

  it("trap guard: a restricted tenant sees only its own slice, never a cluster-wide total", async () => {
    // The server filters `GET /api/v1/applications` to the caller's projects (`T14.4`), and the
    // catalogue endpoints are scoped the same way. This fixture models that restricted answer: the
    // tenant may see one application, while the other tenants' applications exist in the cluster.
    const visible = sampleApps.filter((entry) => entry.project === "storefront");
    const hidden = sampleApps.filter((entry) => entry.project !== "storefront");
    expect(hidden.length).toBeGreaterThan(0);

    renderOverview({
      listApplications: async () => ({ items: visible }),
      listProjects: async () => ({ items: [{ name: "storefront" }] }),
      listClusters: async () => ({
        items: [{ name: "in-cluster", inCluster: true }],
      }),
    });

    await screen.findByTestId("overview-kpi-total");

    // Every figure is a rollup over the one visible application — never over the fleet.
    expect(kpiValue("total")).toBe("1");
    expect(kpiValue("synced")).toBe("1");
    expect(kpiValue("out-of-sync")).toBe("0");
    expect(kpiValue("degraded")).toBe("1"); // checkout-web itself is Degraded

    // And no hidden tenant's identity or cluster appears anywhere in the document.
    const text = document.body.textContent ?? "";
    for (const entry of hidden) {
      expect(text).not.toContain(entry.name);
      expect(text).not.toContain(entry.source.repoUrl);
      expect(text).not.toContain(`${entry.destination.cluster}/${entry.destination.namespace}`);
    }
    expect(text).not.toContain("prod-us-east");
    // The cluster table has exactly the one visible destination; a fleet-wide total would need a
    // second, unscoped source, and no such number exists on the page.
    expect(
      within(screen.getByTestId("overview-clusters")).getAllByRole("row"),
    ).toHaveLength(2); // header + in-cluster
  });

  it("says so honestly when the caller can see no applications at all", async () => {
    renderOverview({
      listApplications: async () => ({ items: [] }),
      listProjects: async () => ({ items: [] }),
      listClusters: async () => ({ items: [] }),
    });

    expect(
      await screen.findByText("No Applications are visible to your identity."),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("overview-kpi-total")).not.toBeInTheDocument();
  });

  it("caps the triage queue and links to the full filtered list", async () => {
    const many = Array.from({ length: TRIAGE_LIMIT + 3 }, (_, index) =>
      app({
        name: `degraded-${String(index).padStart(2, "0")}`,
        health: { status: "Degraded", message: "broken" },
      }),
    );
    renderOverview({
      listApplications: async () => ({ items: many }),
      listProjects: async () => ({ items: [{ name: "payments" }] }),
      listClusters: async () => ({
        items: [{ name: "in-cluster", inCluster: true }],
      }),
    });

    const triage = await screen.findByTestId("overview-triage");
    expect(within(triage).getAllByRole("listitem")).toHaveLength(TRIAGE_LIMIT);
    // The queue mixes degraded, out-of-sync, missing and policy-blocked applications,
    // so the link must not narrow the list to `health=Degraded` (that would hide the
    // other entries the operator was just shown).
    expect(
      screen.getByRole("link", { name: "Review every application" }),
    ).toHaveAttribute("href", "/");
  });

  it("is reachable from the primary navigation and marks itself current", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const client = createMockApiClient();
    render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider clientOverride={client}>
          <MemoryRouter initialEntries={["/overview"]}>
            <Routes>
              <Route element={<Layout />}>
                <Route path="/overview" element={<FleetOverviewPage />} />
              </Route>
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>,
    );

    const nav = screen.getByRole("navigation", { name: "Primary" });
    const link = nav.querySelector('a[href="/overview"]');
    expect(link).not.toBeNull();
    expect(link).toHaveAttribute("aria-current", "page");
    expect(link).toHaveTextContent("Overview");
    expect(nav.querySelectorAll('[aria-current="page"]')).toHaveLength(1);
    expect(
      await screen.findByRole("heading", { level: 1, name: "Fleet overview" }),
    ).toBeInTheDocument();
  });

  it("is registered as a route in the application shell", async () => {
    window.history.replaceState({}, "", "/overview");
    try {
      render(<App clientOverride={createMockApiClient()} />);
      expect(
        await screen.findByRole("heading", { level: 1, name: "Fleet overview" }),
      ).toBeInTheDocument();
    } finally {
      window.history.replaceState({}, "", "/");
    }
  });

  it("has no critical/serious WCAG 2.2 AA violation (dark and light)", async () => {
    const { container, unmount } = renderOverview();
    await screen.findByTestId("overview-kpi-total");
    await expectNoA11yViolations(container);
    unmount();

    document.documentElement.dataset.theme = "light";
    try {
      const light = renderOverview();
      await screen.findByTestId("overview-kpi-total");
      await expectNoA11yViolations(light.container);
    } finally {
      delete document.documentElement.dataset.theme;
    }
  });
});

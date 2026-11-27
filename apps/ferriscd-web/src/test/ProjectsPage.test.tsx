import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { ApiClientError } from "../api/client";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { ProjectsPage } from "../features/projects/ProjectsPage";
import { createMockApiClient, sampleProjects } from "./fixtures";

function LocationProbe() {
  const location = useLocation();
  return (
    <div data-testid="location">
      {location.pathname}
      {location.search}
    </div>
  );
}

function renderProjectsPage(
  overrides: Parameters<typeof createMockApiClient>[0] = {},
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const mockClient = createMockApiClient(overrides);

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={mockClient}>
        <MemoryRouter initialEntries={["/projects"]}>
          <Routes>
            <Route path="/projects" element={<ProjectsPage />} />
            <Route path="/" element={<div>applications-list</div>} />
          </Routes>
          <LocationProbe />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("ProjectsPage (T17.3)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    setStoredToken("test-token");
  });

  it("shows every tenancy boundary of a project: repos, namespaces, destinations and ServiceAccounts", async () => {
    renderProjectsPage();

    const card = (await screen.findByText("payments")).closest("li");
    expect(card).not.toBeNull();

    expect(within(card as HTMLElement).getByText("PCI-scoped payment services")).toBeInTheDocument();
    expect(
      within(card as HTMLElement).getByTestId("project-source-repos-payments"),
    ).toHaveTextContent("https://github.com/acme/gitops-payments.git");
    expect(
      within(card as HTMLElement).getByTestId("project-source-namespaces-payments"),
    ).toHaveTextContent("ferriscd-system");
    expect(
      within(card as HTMLElement).getByTestId("project-destinations-payments"),
    ).toHaveTextContent("prod-us-east/payments");
    expect(
      within(card as HTMLElement).getByTestId("project-destinations-payments"),
    ).toHaveTextContent("in-cluster/payments");
    expect(
      within(card as HTMLElement).getByTestId("project-service-accounts-payments"),
    ).toHaveTextContent("payments-deployer");

    // An empty allow-list is stated, not hidden: "no ServiceAccounts" is the important fact.
    expect(
      screen.getByTestId("project-service-accounts-storefront"),
    ).toHaveTextContent("none");
  });

  it("rolls up the visible applications per project and announces the filtered count", async () => {
    renderProjectsPage();

    // `sampleApps`: two applications in `payments` (payments-api, checkout-web is storefront) —
    // the rollup is derived from the same list the Applications page shows.
    expect(
      await screen.findByTestId("project-app-count-payments"),
    ).toHaveTextContent("1 application");
    expect(
      screen.getByTestId("project-app-count-storefront"),
    ).toHaveTextContent("1 application");
    expect(screen.getByTestId("projects-live-region")).toHaveTextContent(
      "Showing 2 of 2 projects.",
    );
  });

  it("filters by repository, namespace or ServiceAccount and clears back to the full list", async () => {
    const user = userEvent.setup();
    renderProjectsPage();

    expect(await screen.findByText("payments")).toBeInTheDocument();
    expect(screen.getByText("storefront")).toBeInTheDocument();

    const search = screen.getByLabelText(/Search projects/i);
    await user.type(search, "payments-deployer");
    expect(screen.getByText("payments")).toBeInTheDocument();
    expect(screen.queryByText("storefront")).not.toBeInTheDocument();
    expect(screen.getByTestId("projects-live-region")).toHaveTextContent(
      "Showing 1 of 2 projects.",
    );

    await user.clear(search);
    await user.type(search, "gitops-storefront");
    expect(screen.getByText("storefront")).toBeInTheDocument();
    expect(screen.queryByText("payments")).not.toBeInTheDocument();

    await user.clear(search);
    expect(screen.getByText("payments")).toBeInTheDocument();
    expect(screen.getByText("storefront")).toBeInTheDocument();
  });

  it("links a project to the filtered application list (the filter lives in the URL)", async () => {
    const user = userEvent.setup();
    renderProjectsPage();

    await user.click(await screen.findByRole("link", { name: "payments" }));
    expect(screen.getByTestId("location")).toHaveTextContent("/?project=payments");
    expect(screen.getByText("applications-list")).toBeInTheDocument();
  });

  it("does not claim 'no projects' when the request itself failed", async () => {
    renderProjectsPage({
      listProjects: async () => {
        throw new ApiClientError(502, "BackendUnavailable", "cluster read failed");
      },
    });

    expect(await screen.findByRole("alert")).toHaveTextContent("cluster read failed");
    expect(
      screen.queryByText("No AppProjects are visible to your identity."),
    ).not.toBeInTheDocument();
  });

  it("offers an honest empty state when no project is visible", async () => {
    renderProjectsPage({ listProjects: async () => ({ items: [] }) });

    expect(
      await screen.findByText("No AppProjects are visible to your identity."),
    ).toBeInTheDocument();
    expect(sampleProjects.items?.length).toBeGreaterThan(0);
  });
});

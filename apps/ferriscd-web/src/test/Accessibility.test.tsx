import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { CommandPalette } from "../app/CommandPalette";
import { Layout } from "../app/Layout";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { ApplicationDetailPage } from "../features/applications/ApplicationDetailPage";
import { ApplicationsPage } from "../features/applications/ApplicationsPage";
import { ClustersPage } from "../features/clusters/ClustersPage";
import { ProjectsPage } from "../features/projects/ProjectsPage";
import { RollbackModal } from "../features/sync/RollbackModal";
import { SyncModal } from "../features/sync/SyncModal";
import { expectNoA11yViolations } from "./a11y";
import { createMockApiClient, sampleAppDetail } from "./fixtures";

/**
 * Automated WCAG 2.2 AA regression suite (`T17.3`).
 *
 * Every surface the task adds — the two new pages, the events tab, the command palette — plus the
 * two modals that already had a focus trap are scanned with axe-core. The criterion is the roadmap's:
 * **zero critical or serious violations**.
 *
 * Colour contrast is verified separately (`contrast.test.ts`) because jsdom has no layout engine and
 * axe reports `color-contrast` as "incomplete" rather than "pass" there; keyboard behaviour is
 * asserted with `userEvent` in the component suites.
 */
function renderWithProviders(ui: React.ReactNode, initialEntry = "/") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const mockClient = createMockApiClient();

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={mockClient}>
        <MemoryRouter initialEntries={[initialEntry]}>{ui}</MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("WCAG 2.2 AA automated checks (T17.3)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    setStoredToken("test-token");
  });

  it("ApplicationsPage", async () => {
    const { container } = renderWithProviders(<ApplicationsPage />);
    await screen.findByTestId("applications-grid");
    await expectNoA11yViolations(container);
  });

  it("ApplicationsPage in light mode", async () => {
    document.documentElement.dataset.theme = "light";
    try {
      const { container } = renderWithProviders(<ApplicationsPage />);
      await screen.findByTestId("applications-grid");
      await expectNoA11yViolations(container);
    } finally {
      delete document.documentElement.dataset.theme;
    }
  });

  it("ProjectsPage", async () => {
    const { container } = renderWithProviders(<ProjectsPage />);
    await screen.findByText("payments");
    await expectNoA11yViolations(container);
  });

  it("ClustersPage", async () => {
    const { container } = renderWithProviders(<ClustersPage />);
    await screen.findByTestId("cluster-card-in-cluster");
    await expectNoA11yViolations(container);
  });

  it("ApplicationDetailPage with the events timeline open", async () => {
    const { container } = renderWithProviders(
      <Routes>
        <Route
          path="/applications/:namespace/:name"
          element={<ApplicationDetailPage />}
        />
      </Routes>,
      "/applications/ferriscd-system/payments-api?tab=events",
    );
    await screen.findByTestId("events-timeline");
    await expectNoA11yViolations(container);
  });

  it("the command palette dialog", async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <Layout />,
      "/",
    );
    // `Layout` renders the routed outlet; without a matching route the outlet is empty, which is
    // fine for the shell's own landmarks and the palette it owns.
    await user.click(screen.getByRole("button", { name: /Search/i }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("combobox")).toBeInTheDocument();
    // The dialog is portalled to `document.body`, so the body is the container under test.
    await expectNoA11yViolations(document.body);
  });

  it("the app shell (skip link, nav, main landmark)", async () => {
    renderWithProviders(
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<div>dashboard</div>} />
        </Route>
      </Routes>,
    );
    expect(screen.getByTestId("skip-to-content")).toBeInTheDocument();
    await expectNoA11yViolations(document.body);
  });

  it("SyncModal (focus trap + Escape already covered in its own suite)", async () => {
    render(
      <SyncModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        onClose={() => {}}
        onConfirm={async () => {
          throw new Error("not used");
        }}
      />,
    );
    // The dialog is portalled to `document.body`.
    await expectNoA11yViolations(document.body);
  });

  it("RollbackModal (focus trap + Escape already covered in its own suite)", async () => {
    render(
      <RollbackModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        history={sampleAppDetail.history ?? []}
        onClose={() => {}}
        onConfirm={async () => {
          throw new Error("not used");
        }}
      />,
    );
    await expectNoA11yViolations(document.body);
  });

  it("renders no critical/serious violation while the palette is filtered and empty", async () => {
    const user = userEvent.setup();
    renderWithProviders(<CommandPalette open onOpenChange={() => {}} />);
    await screen.findByRole("dialog");
    await user.type(
      screen.getByLabelText(/Search applications, projects, clusters and views/i),
      "zzz-no-such-thing",
    );
    expect(screen.getByTestId("command-palette-status")).toHaveTextContent("No results.");
    await expectNoA11yViolations(document.body);
  });
});

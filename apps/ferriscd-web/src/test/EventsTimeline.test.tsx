import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { ApiClientError } from "../api/client";
import { AuthProvider } from "../auth/AuthContext";
import { resetTokenMemoryCache, setStoredToken } from "../auth/tokenStorage";
import { ApplicationDetailPage } from "../features/applications/ApplicationDetailPage";
import { EventsTimeline } from "../features/applications/components/EventsTimeline";
import { createMockApiClient, sampleEvents } from "./fixtures";

describe("EventsTimeline (T17.3)", () => {
  it("renders Normal and Warning events newest-first with reason, count and timestamp", () => {
    render(<EventsTimeline events={sampleEvents.items ?? []} />);

    const rows = screen.getAllByTestId("event-row");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveAttribute("data-event-type", "Warning");
    expect(rows[0]).toHaveTextContent("Warning");
    expect(rows[0]).toHaveTextContent("SyncFailed");
    expect(rows[0]).toHaveTextContent("quota exceeded");
    // The recurrence count is stated ("×3"), not implied by a colour.
    expect(rows[0]).toHaveTextContent("×3");
    expect(rows[0]).toHaveTextContent("2026-11-25 19:15:00 UTC");
    expect(rows[0]).toHaveTextContent("ferriscd.io/controller");

    expect(rows[1]).toHaveAttribute("data-event-type", "Normal");
    expect(rows[1]).toHaveTextContent("SyncSucceeded");
  });

  it("announces the event count and the number of warnings", () => {
    render(<EventsTimeline events={sampleEvents.items ?? []} />);

    expect(screen.getByTestId("events-live-region")).toHaveTextContent(
      "2 Kubernetes events, 1 of them warnings.",
    );
  });

  it("explains an empty timeline instead of rendering a blank panel", () => {
    render(<EventsTimeline events={[]} />);

    expect(
      screen.getByText(/No Kubernetes events recorded for this Application yet/i),
    ).toBeInTheDocument();
    expect(screen.queryAllByTestId("event-row")).toHaveLength(0);
    expect(screen.getByTestId("events-live-region")).toHaveTextContent(
      "No Kubernetes events for this application.",
    );
  });

  it("says so when the server truncated the timeline", () => {
    render(<EventsTimeline events={sampleEvents.items ?? []} truncated />);

    expect(screen.getByText(/Showing the most recent 50 events/i)).toBeInTheDocument();
  });
});

describe("ApplicationDetailPage Events tab (T17.3)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    setStoredToken("test-token");
  });

  function renderDetailPage(
    overrides: Parameters<typeof createMockApiClient>[0] = {},
    entry = "/applications/ferriscd-system/payments-api",
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

  it("opens the events timeline from the tab strip", async () => {
    const user = userEvent.setup();
    renderDetailPage();

    await screen.findByRole("heading", { name: "payments-api" });
    expect(screen.queryByTestId("events-timeline")).not.toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /^Events$/ }));

    const timeline = await screen.findByTestId("events-timeline");
    expect(within(timeline).getAllByTestId("event-row")).toHaveLength(2);
    expect(timeline).toHaveTextContent("SyncFailed");
  });

  it("keeps the tab in the URL so a palette jump or a pasted link opens the same section", async () => {
    renderDetailPage(
      {},
      "/applications/ferriscd-system/payments-api?tab=events",
    );

    await screen.findByRole("heading", { name: "payments-api" });
    // The events query only fires for `?tab=events`: the section is addressable.
    expect(await screen.findByTestId("events-timeline")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^Events$/ })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  it("reports an events request failure without pretending there are no events", async () => {
    renderDetailPage(
      {
        getApplicationEvents: async () => {
          throw new ApiClientError(403, "Forbidden", "no get grant on project payments");
        },
      },
      "/applications/ferriscd-system/payments-api?tab=events",
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "no get grant on project payments",
    );
    expect(
      screen.queryByText(/No Kubernetes events recorded for this Application yet/i),
    ).not.toBeInTheDocument();
  });
});

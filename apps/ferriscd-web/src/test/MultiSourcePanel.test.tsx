import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { ApplicationSummary } from "../api/types";
import { SourcePanel } from "../features/applications/components/SourcePanel";
import { sampleApps, sampleMultiSourceApp } from "./fixtures";

const CHART_DIGEST =
  "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e";

/**
 * Renders the panel and returns its source card.
 *
 * The `Sync Metadata` card is a sibling of the source card inside the same
 * section, so anything about revisions is queried from `screen`, not from the
 * card.
 */
function sourceCard(app: ApplicationSummary): HTMLElement {
  render(
    <MemoryRouter>
      <SourcePanel app={app} />
    </MemoryRouter>,
  );
  return screen.getByTestId("source-card");
}

describe("SourcePanel multi-source (T20.1)", () => {
  it("badges the application as multi-source and names every declared source", () => {
    const card = sourceCard(sampleMultiSourceApp);

    // The count is stated in words, so the badge is not colour-only.
    expect(within(card).getByTestId("multi-source-badge")).toHaveTextContent(
      "2 sources",
    );

    const declared = within(card).getByTestId("declared-sources");
    expect(within(declared).getByText("Declared sources")).toBeInTheDocument();
    const list = within(declared).getByRole("list", {
      name: "Declared sources",
    });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);

    // Declaration order is what the controller renders in, and it is what the
    // per-source revision list is indexed against.
    expect(items[0]).toHaveTextContent("ref: chart");
    expect(items[0]).toHaveTextContent(
      "oci://registry.ferriscd-system.svc:5000/charts/payments",
    );
    // A renderer means "this source contributes manifests".
    expect(items[0]).toHaveTextContent("helm");
    expect(items[0]).toHaveTextContent("OCI");

    expect(items[1]).toHaveTextContent("ref: values");
    expect(items[1]).toHaveTextContent("https://github.com/acme/payments-values.git");
    // No renderer means values-only, which the row has to say out loud.
    expect(items[1]).toHaveTextContent("values");
    expect(items[1]).toHaveTextContent("Git");
    expect(items[1]).toHaveTextContent("@main");
  });

  it("labels an unaliased source by position instead of rendering a blank row", () => {
    const card = sourceCard({
      ...sampleMultiSourceApp,
      source: {
        ...sampleMultiSourceApp.source,
        sources: [
          {
            sourceType: "git",
            repoUrl: "https://github.com/acme/charts.git",
            path: "charts/api",
            targetRevision: "main",
            renderer: "helm",
          },
          ...(sampleMultiSourceApp.source.sources ?? []).slice(1),
        ],
      },
    });

    const list = within(
      within(card).getByTestId("declared-sources"),
    ).getByRole("list", { name: "Declared sources" });
    expect(within(list).getAllByRole("listitem")[0]).toHaveTextContent(
      "source 1",
    );
  });

  it("pluralizes the source count so a one-entry list never says `1 sources`", () => {
    const card = sourceCard({
      ...sampleMultiSourceApp,
      source: {
        ...sampleMultiSourceApp.source,
        sources: [
          {
            ref: "chart",
            sourceType: "git",
            repoUrl: "https://github.com/acme/charts.git",
            path: "charts/api",
            targetRevision: "main",
            renderer: "helm",
          },
        ],
      },
    });

    // Anchored: a substring match would also accept the ungrammatical `1 sources`.
    expect(within(card).getByTestId("multi-source-badge")).toHaveTextContent(
      /^1 source$/,
    );
  });

  it("lists one revision per source next to the composite revision", () => {
    sourceCard(sampleMultiSourceApp);

    const revisions = screen.getByTestId("per-source-revisions");
    expect(within(revisions).getByText("Source Revisions")).toBeInTheDocument();
    const rows = within(revisions).getAllByRole("listitem");
    expect(rows).toHaveLength(2);

    // The OCI chart revision is a digest; `shortRevision` truncates but the
    // full value stays available in the `title`.
    expect(within(rows[0]!).getByText("chart")).toBeInTheDocument();
    expect(within(rows[0]!).getByTitle(CHART_DIGEST)).toBeInTheDocument();
    expect(
      within(rows[0]!).getByText(`${CHART_DIGEST.slice(0, 12)}\u2026`),
    ).toBeInTheDocument();

    // Revisions copy on click; they are not external links.
    expect(within(rows[1]!).getByText("values")).toBeInTheDocument();
    expect(
      within(rows[1]!).getByRole("button", {
        name: "Copy source values revision",
      }),
    ).toBeInTheDocument();
  });

  it("shows no per-source block for a multi-source app that has never synced", () => {
    // `T20.1` finding N2: the block is gated on the revision data, not on the
    // multi-source badge. An unsynced multi-source application still renders the
    // badge and the declared sources, but an empty `Source Revisions` heading
    // would read as a controller bug.
    const { sync: _unsynced, ...withoutSync } = sampleMultiSourceApp;
    render(
    <MemoryRouter>
      <SourcePanel app={withoutSync} />
    </MemoryRouter>,
  );

    expect(screen.getByTestId("multi-source-badge")).toHaveTextContent(
      "2 sources",
    );
    expect(screen.queryByTestId("per-source-revisions")).not.toBeInTheDocument();
    expect(screen.queryByText("Source Revisions")).not.toBeInTheDocument();
  });

  it("shows no per-source block when the pass reported an empty revision list", () => {
    // The same guard, from the other direction: `sync` exists (status, composite
    // revision, timestamps) but `revisions` is empty — what a partially
    // reconciled or `v1.0`-shaped payload looks like.
    render(
      <MemoryRouter>
      <SourcePanel
        app={{
          ...sampleMultiSourceApp,
          // `status` is restated because `sync` is optional on the payload, so
          // spreading it would widen the required field.
          sync: { ...sampleMultiSourceApp.sync, status: "Synced", revisions: [] },
        }}
      />
      </MemoryRouter>,
    );

    expect(screen.getByText("Rendered Revision")).toBeInTheDocument();
    expect(screen.queryByTestId("per-source-revisions")).not.toBeInTheDocument();
    expect(screen.queryByText("Source Revisions")).not.toBeInTheDocument();
  });

  it("keeps the single-source card free of multi-source furniture", () => {
    const card = sourceCard(sampleApps[0]!);

    expect(
      within(card).queryByTestId("multi-source-badge"),
    ).not.toBeInTheDocument();
    expect(within(card).queryByTestId("declared-sources")).not.toBeInTheDocument();
    expect(screen.queryByTestId("per-source-revisions")).not.toBeInTheDocument();
    // …and the composite rows it always had are still there.
    expect(screen.getByText("Rendered Revision")).toBeInTheDocument();
    expect(screen.getByText("Last Synced Revision")).toBeInTheDocument();
    expect(screen.queryByText("Source Revisions")).not.toBeInTheDocument();
  });
});

import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { ApplicationSummary } from "../api/types";
import { SourcePanel } from "../features/applications/components/SourcePanel";
import { sampleApps, sampleOciApp } from "./fixtures";

const DIGEST =
  "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e";

/** Renders the panel and returns its source card. */
function sourceCard(app: ApplicationSummary): HTMLElement {
  render(
    <MemoryRouter>
      <SourcePanel app={app} />
    </MemoryRouter>,
  );
  return screen.getByTestId("source-card");
}

describe("SourcePanel (T18.4)", () => {
  it("names the source kind and splits an OCI tag from its pinned digest", () => {
    const card = sourceCard(sampleOciApp);

    // The kind is stated in words, not carried by an icon colour alone.
    expect(within(card).getByTestId("source-kind")).toHaveTextContent("OCI");

    // An OCI reference has a *registry*, not a "Repository".
    expect(within(card).getByText("Registry")).toBeInTheDocument();
    expect(within(card).queryByText("Repository")).not.toBeInTheDocument();
    expect(
      within(card).getByText(
        "oci://registry.ferriscd-system.svc:5000/payments/ledger",
      ),
    ).toBeInTheDocument();

    // Both facts the operator needs to answer "which artifact is deployed?".
    expect(within(card).getByTestId("source-tag")).toHaveTextContent("1.4.2");
    expect(within(card).getByTestId("source-digest")).toHaveTextContent(DIGEST);
    // …and the collapsed row is gone, so the pin cannot be hidden behind a tag.
    expect(within(card).queryByText("Target Revision")).not.toBeInTheDocument();

    // An `oci://` reference is never turned into a browsable web link.
    expect(within(card).queryByRole("link")).not.toBeInTheDocument();
  });

  it("renders a digest-only OCI source without inventing a tag", () => {
    const card = sourceCard({
      ...sampleOciApp,
      source: {
        ...sampleOciApp.source,
        targetRevision: DIGEST,
        tag: null,
        digest: DIGEST,
      },
    });

    expect(within(card).getByTestId("source-digest")).toHaveTextContent(DIGEST);
    expect(within(card).queryByTestId("source-tag")).not.toBeInTheDocument();
    expect(within(card).queryByText("Tag")).not.toBeInTheDocument();
  });

  it("falls back to a single revision row when the API omits both OCI fields", () => {
    // A pre-`T18.4` server (or a partially-populated status) must still render
    // something an operator can act on rather than an empty card.
    const card = sourceCard({
      ...sampleOciApp,
      source: {
        ...sampleOciApp.source,
        targetRevision: "1.4.2",
        tag: null,
        digest: null,
      },
    });

    expect(within(card).getByText("Target Revision")).toBeInTheDocument();
    expect(within(card).getByText("1.4.2")).toBeInTheDocument();
    expect(within(card).queryByTestId("source-tag")).not.toBeInTheDocument();
    expect(within(card).queryByTestId("source-digest")).not.toBeInTheDocument();
  });

  it("keeps the Git source card unchanged", () => {
    const card = sourceCard(sampleApps[0]!);

    expect(within(card).getByTestId("source-kind")).toHaveTextContent("Git");
    expect(within(card).getByText("Repository")).toBeInTheDocument();
    expect(within(card).getByText("Target Revision")).toBeInTheDocument();
    expect(within(card).queryByText("Registry")).not.toBeInTheDocument();
    expect(within(card).queryByTestId("source-tag")).not.toBeInTheDocument();
    expect(within(card).queryByTestId("source-digest")).not.toBeInTheDocument();
    // The HTTP(S) repo keeps its browsable link.
    expect(
      within(card).getByRole("link", {
        name: "https://github.com/acme/gitops-payments.git",
      }),
    ).toHaveAttribute("href", "https://github.com/acme/gitops-payments");
  });
});

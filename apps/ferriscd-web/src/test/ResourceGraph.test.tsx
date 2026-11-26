import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ResourceGraph } from "../features/resources/ResourceGraph";
import {
  buildResourceGraphElements,
  GRAPH_NODE_HEIGHT,
  GRAPH_NODE_WIDTH,
} from "../features/resources/dagreLayout";
import { make15NodeResourceGraph, makeLargeResourceGraph } from "./fixtures";

describe("ResourceGraph & dagre layout (T16.3 & Trap Guard T16.3)", () => {
  it("lays out a 15-node application hierarchy cleanly with zero bounding-box overlap", () => {
    const graph = make15NodeResourceGraph();
    expect(graph.nodes).toHaveLength(15);

    const { nodes, edges } = buildResourceGraphElements(
      "ferriscd-system",
      "payments-api",
      graph,
      "LR",
    );

    // 1 synthetic Application root + 15 resource nodes = 16 total nodes
    expect(nodes).toHaveLength(16);
    expect(edges).toHaveLength(15);

    // Verify Deployment -> ReplicaSet -> Pod edges exist
    expect(edges).toContainEqual(
      expect.objectContaining({
        source: "apps/Deployment/payments/payments-api",
        target: "apps/ReplicaSet/payments/payments-api-7f8d9",
      }),
    );
    expect(edges).toContainEqual(
      expect.objectContaining({
        source: "apps/ReplicaSet/payments/payments-api-7f8d9",
        target: "/Pod/payments/payments-api-7f8d9-aaa",
      }),
    );

    // Only nodes with outgoing edges expose a source handle (no dangling dot on leaves).
    const byId = new Map(nodes.map((n) => [n.id, n]));
    expect(
      byId.get("apps/ReplicaSet/payments/payments-api-7f8d9")?.data.hasChildren,
    ).toBe(true);
    expect(byId.get("/Pod/payments/payments-api-7f8d9-aaa")?.data.hasChildren).toBe(
      false,
    );

    // Pairwise axis-aligned bounding-box overlap check
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i]!;
        const b = nodes[j]!;
        const overlapX =
          a.position.x < b.position.x + GRAPH_NODE_WIDTH &&
          a.position.x + GRAPH_NODE_WIDTH > b.position.x;
        const overlapY =
          a.position.y < b.position.y + GRAPH_NODE_HEIGHT &&
          a.position.y + GRAPH_NODE_HEIGHT > b.position.y;
        expect(
          overlapX && overlapY,
          `Nodes ${a.id} and ${b.id} overlap`,
        ).toBe(false);
      }
    }
  });

  it("deduplicates duplicate resource keys and guards against self-loop parent edges", () => {
    const base = make15NodeResourceGraph();
    const dupNode = base.nodes[0]!;
    const selfLoopNode = {
      key: "/ConfigMap/payments/self-loop-cm",
      group: "",
      kind: "ConfigMap",
      namespace: "payments",
      name: "self-loop-cm",
      present: true,
      health: "Healthy",
      healthMessage: null,
      ownership: "Owned",
      parent: "/ConfigMap/payments/self-loop-cm",
    };

    const { nodes, edges } = buildResourceGraphElements(
      "ferriscd-system",
      "payments-api",
      {
        ...base,
        nodes: [...base.nodes, { ...dupNode }, selfLoopNode],
      },
      "LR",
    );

    // 1 root + 15 unique base nodes + 1 self-loop node = 17 nodes (duplicate dropped)
    expect(nodes).toHaveLength(17);
    expect(new Set(nodes.map((n) => n.id)).size).toBe(17);
    expect(edges).toHaveLength(16);

    // Self-loop node must attach to the root Application node, never to itself
    expect(edges).not.toContainEqual(
      expect.objectContaining({
        source: selfLoopNode.key,
        target: selfLoopNode.key,
      }),
    );
    expect(edges).toContainEqual(
      expect.objectContaining({
        source: "__app__/ferriscd-system/payments-api",
        target: selfLoopNode.key,
      }),
    );
  });

  it("defaults to Graph View for < 100 resources, opens ResourceInspector, and refreshes inspector on graph poll updates", async () => {
    const user = userEvent.setup();
    const onInspectDiff = vi.fn();
    const graph = make15NodeResourceGraph();

    const { rerender } = render(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="payments-api"
        graph={graph}
        onInspectDiff={onInspectDiff}
      />,
    );

    expect(screen.getByTestId("resource-graph-canvas")).toBeInTheDocument();
    expect(screen.queryByTestId("large-graph-banner")).not.toBeInTheDocument();

    // Switch to Resource Table View and click a resource row to inspect it
    await user.click(
      screen.getByRole("button", { name: /Resource Table View/i }),
    );
    expect(screen.getByTestId("resource-table-view")).toBeInTheDocument();

    await user.click(screen.getByText("payments-api-7f8d9-ccc"));

    const inspector = screen.getByTestId("resource-inspector");
    expect(inspector).toBeInTheDocument();
    expect(within(inspector).getByTestId("inspector-gknn")).toHaveTextContent(
      "/Pod/payments/payments-api-7f8d9-ccc",
    );
    expect(
      within(inspector).getByTestId("inspector-sync-wave"),
    ).toHaveTextContent("— (not reported by API)");
    expect(
      within(inspector).getByTestId("inspector-health-message"),
    ).toHaveTextContent("OOMKilled");

    // Simulate 10s poll update changing the selected Pod to Healthy / Running
    const updatedGraph = {
      ...graph,
      nodes: graph.nodes.map((n) =>
        n.key === "/Pod/payments/payments-api-7f8d9-ccc"
          ? { ...n, health: "Healthy", healthMessage: "Running after restart" }
          : n,
      ),
    };
    rerender(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="payments-api"
        graph={updatedGraph}
        onInspectDiff={onInspectDiff}
      />,
    );

    expect(
      within(screen.getByTestId("resource-inspector")).getByTestId(
        "inspector-health-message",
      ),
    ).toHaveTextContent("Running after restart");
    expect(
      within(screen.getByTestId("resource-inspector")).getByTestId(
        "health-status-badge",
      ),
    ).toHaveTextContent("Health:Healthy");

    await user.click(
      within(screen.getByTestId("resource-inspector")).getByRole("button", {
        name: /View Resource in Diff/i,
      }),
    );
    expect(onInspectDiff).toHaveBeenCalledWith(
      "/Pod/payments/payments-api-7f8d9-ccc",
    );
  });

  it("closes the ResourceInspector on a backdrop click and on Escape", async () => {
    const user = userEvent.setup();
    const graph = make15NodeResourceGraph();

    render(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="payments-api"
        graph={graph}
      />,
    );

    await user.click(
      screen.getByRole("button", { name: /Resource Table View/i }),
    );
    await user.click(screen.getByText("payments-api-7f8d9-ccc"));
    expect(screen.getByTestId("resource-inspector")).toBeInTheDocument();

    await user.click(screen.getByTestId("resource-inspector-backdrop"));
    expect(screen.queryByTestId("resource-inspector")).not.toBeInTheDocument();

    await user.click(screen.getByText("payments-api-7f8d9-ccc"));
    expect(screen.getByTestId("resource-inspector")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByTestId("resource-inspector")).not.toBeInTheDocument();
  });

  it("triggers auto-Table View at the exact 100-resource threshold and keeps 99 resources in Graph View", () => {
    const graph99 = makeLargeResourceGraph(99);
    const { unmount } = render(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="app-99"
        graph={graph99}
      />,
    );
    expect(screen.getByTestId("resource-graph-canvas")).toBeInTheDocument();
    expect(screen.queryByTestId("large-graph-banner")).not.toBeInTheDocument();
    unmount();

    const graph100 = makeLargeResourceGraph(100);
    render(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="app-100"
        graph={graph100}
      />,
    );
    expect(screen.getByTestId("large-graph-banner")).toHaveTextContent(
      "100 resources ≥ 100",
    );
    expect(screen.getByTestId("resource-table-view")).toBeInTheDocument();
    expect(
      screen.queryByTestId("resource-graph-canvas"),
    ).not.toBeInTheDocument();
  });

  it("attaches cyclic owner chains to the Application root so nothing floats disconnected (M2)", () => {
    const base = make15NodeResourceGraph();
    const cyclicA = {
      key: "apps/Deployment/payments/cycle-a",
      group: "apps",
      kind: "Deployment",
      namespace: "payments",
      name: "cycle-a",
      present: true,
      health: "Healthy",
      healthMessage: null,
      ownership: "Owned",
      parent: "apps/Deployment/payments/cycle-b",
    };
    const cyclicB = {
      ...cyclicA,
      key: "apps/Deployment/payments/cycle-b",
      name: "cycle-b",
      parent: "apps/Deployment/payments/cycle-a",
    };

    const { nodes, edges } = buildResourceGraphElements(
      "ferriscd-system",
      "payments-api",
      { ...base, nodes: [cyclicA, cyclicB] },
      "LR",
    );

    const root = nodes.find((n) => n.id === "__app__/ferriscd-system/payments-api");
    expect(root?.data.hasChildren).toBe(true);
    expect(edges).toEqual([
      expect.objectContaining({
        source: "__app__/ferriscd-system/payments-api",
        target: cyclicA.key,
      }),
      expect.objectContaining({
        source: "__app__/ferriscd-system/payments-api",
        target: cyclicB.key,
      }),
    ]);
  });

  it("resets the kind filter when a poll removes every node of the filtered kind (H2)", async () => {
    const user = userEvent.setup();
    const graph = make15NodeResourceGraph();
    const { rerender } = render(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="payments-api"
        graph={graph}
      />,
    );

    await user.click(
      screen.getByRole("button", { name: /Resource Table View/i }),
    );
    await user.click(
      screen.getByRole("combobox", { name: /Filter by resource kind/i }),
    );
    await user.click(screen.getByRole("option", { name: "Pod" }));
    expect(screen.getByText("Showing 5 of 15")).toBeInTheDocument();

    // The Pods disappear from the inventory on the next poll.
    const withoutPods = {
      ...graph,
      nodes: graph.nodes.filter((n) => n.kind !== "Pod"),
    };
    rerender(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="payments-api"
        graph={withoutPods}
      />,
    );

    expect(
      screen.getByRole("combobox", { name: /Filter by resource kind/i }),
    ).toHaveTextContent("All Kinds (10)");
    expect(screen.getByText("Showing 10 of 10")).toBeInTheDocument();
    expect(
      screen.queryByText("No resources match your search filter."),
    ).not.toBeInTheDocument();
  });

  it("closes the inspector when the inspected resource disappears from a poll (M3)", async () => {
    const user = userEvent.setup();
    const graph = make15NodeResourceGraph();
    const { rerender } = render(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="payments-api"
        graph={graph}
      />,
    );

    await user.click(
      screen.getByRole("button", { name: /Resource Table View/i }),
    );
    await user.click(screen.getByText("payments-api-7f8d9-ccc"));
    expect(screen.getByTestId("resource-inspector")).toBeInTheDocument();

    rerender(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="payments-api"
        graph={{
          ...graph,
          nodes: graph.nodes.filter(
            (n) => n.key !== "/Pod/payments/payments-api-7f8d9-ccc",
          ),
        }}
      />,
    );

    expect(screen.queryByTestId("resource-inspector")).not.toBeInTheDocument();
  });

  it("returns to the graph automatically when a large app shrinks below the threshold", () => {
    const large = makeLargeResourceGraph(100);
    const { rerender } = render(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="shrinking"
        graph={large}
      />,
    );
    expect(screen.getByTestId("resource-table-view")).toBeInTheDocument();

    rerender(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="shrinking"
        graph={makeLargeResourceGraph(40)}
      />,
    );

    expect(screen.getByTestId("resource-graph-canvas")).toBeInTheDocument();
    expect(screen.queryByTestId("large-graph-banner")).not.toBeInTheDocument();
  });

  it("handles 120-resource apps gracefully: auto-defaults to searchable Resource Table View and allows toggling to Graph View (Trap Guard T16.3)", async () => {
    const user = userEvent.setup();
    const largeGraph = makeLargeResourceGraph(120);
    expect(largeGraph.nodes).toHaveLength(120);

    render(
      <ResourceGraph
        appNamespace="ferriscd-system"
        appName="mega-monorepo"
        graph={largeGraph}
      />,
    );

    // Must auto-default to Table View and display large-graph banner
    expect(screen.getByTestId("large-graph-banner")).toHaveTextContent(
      "120 resources ≥ 100",
    );
    expect(screen.getByTestId("resource-table-view")).toBeInTheDocument();
    expect(
      screen.queryByTestId("resource-graph-canvas"),
    ).not.toBeInTheDocument();

    // Search filters 120 resources cleanly
    const searchInput = screen.getByLabelText(/Search resources/i);
    await user.type(searchInput, "workload-119");
    expect(screen.getByText("workload-119")).toBeInTheDocument();
    expect(screen.queryByText("workload-001")).not.toBeInTheDocument();
    expect(screen.getByText("Showing 1 of 120")).toBeInTheDocument();

    // Explicit toggle back to Graph View and back to Table View works
    await user.click(screen.getByRole("button", { name: /^Graph View$/i }));
    expect(screen.getByTestId("resource-graph-canvas")).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /Resource Table View/i }),
    );
    expect(screen.getByTestId("resource-table-view")).toBeInTheDocument();
  });
});

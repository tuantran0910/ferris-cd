import dagre from "dagre";
import { Position, type Edge, type Node } from "@xyflow/react";
import type { ResourceGraphView, ResourceNodeView } from "../../api/types";

export const GRAPH_NODE_WIDTH = 264;
export const GRAPH_NODE_HEIGHT = 104;
export const LARGE_GRAPH_THRESHOLD = 100;

export interface ResourceFlowNodeData extends Record<string, unknown> {
  isRootApplication: boolean;
  label: string;
  kind: string;
  group: string;
  namespace?: string | null;
  key: string;
  syncStatus: string;
  healthStatus: string;
  healthMessage?: string | null;
  present: boolean;
  hasChildren: boolean;
  ownership?: string | null;
  parent?: string | null;
  resource?: ResourceNodeView;
}

export type ResourceFlowNode = Node<ResourceFlowNodeData, "resourceNode">;

export interface DagreLayoutResult {
  nodes: ResourceFlowNode[];
  edges: Edge[];
}

export function buildResourceGraphElements(
  appNamespace: string,
  appName: string,
  graph: ResourceGraphView,
  direction: "LR" | "TB" = "LR",
): DagreLayoutResult {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: direction,
    nodesep: 40,
    ranksep: 88,
    marginx: 24,
    marginy: 24,
  });

  const rootId = `__app__/${appNamespace}/${appName}`;
  const nodeMap = new Map<string, ResourceNodeView>();
  for (const r of graph.nodes) {
    nodeMap.set(r.key, r);
  }

  // Usable owner edges only: a parent that is actually rendered, and never a
  // self-loop (`resource.parent === resource.key`).
  const parentOf = new Map<string, string>();
  for (const r of nodeMap.values()) {
    if (r.parent && r.parent !== r.key && nodeMap.has(r.parent)) {
      parentOf.set(r.key, r.parent);
    }
  }

  // A cyclic owner chain (`A -> B -> A`) has no resource root, so every node in
  // it would otherwise be unreachable from the synthetic Application node and
  // would float, disconnected, in the canvas. Such nodes are attached to the
  // Application instead, which keeps the graph a single connected tree.
  const terminatesCache = new Map<string, boolean>();
  const terminatesAtRoot = (start: string): boolean => {
    const path: string[] = [];
    const seen = new Set<string>();
    let current: string | undefined = start;
    let terminates = true;
    while (current !== undefined) {
      const cached = terminatesCache.get(current);
      if (cached !== undefined) {
        terminates = cached;
        break;
      }
      if (seen.has(current)) {
        terminates = false;
        break;
      }
      seen.add(current);
      path.push(current);
      current = parentOf.get(current);
    }
    for (const key of path) {
      terminatesCache.set(key, terminates);
    }
    return terminates;
  };

  const rawNodes: Array<{ id: string; data: ResourceFlowNodeData }> = [
    {
      id: rootId,
      data: {
        isRootApplication: true,
        label: appName,
        kind: "Application",
        group: "ferriscd.io",
        namespace: appNamespace,
        key: `ferriscd.io/Application/${appNamespace}/${appName}`,
        syncStatus: graph.syncStatus,
        healthStatus: graph.healthStatus,
        present: true,
        hasChildren: false,
      },
    },
  ];

  const edges: Edge[] = [];

  for (const resource of nodeMap.values()) {
    const derivedSync = resource.present ? graph.syncStatus : "OutOfSync";
    const derivedHealth = !resource.present
      ? "Missing"
      : resource.health ?? "Unknown";

    rawNodes.push({
      id: resource.key,
      data: {
        isRootApplication: false,
        label: resource.name,
        kind: resource.kind,
        group: resource.group,
        namespace: resource.namespace ?? null,
        key: resource.key,
        syncStatus: derivedSync,
        healthStatus: derivedHealth,
        healthMessage: resource.healthMessage ?? null,
        present: resource.present,
        hasChildren: false,
        ownership: resource.ownership ?? null,
        parent: resource.parent ?? null,
        resource,
      },
    });

    const parentKey = parentOf.get(resource.key);
    const sourceId =
      parentKey !== undefined && terminatesAtRoot(parentKey) ? parentKey : rootId;
    edges.push({
      id: `${sourceId}->${resource.key}`,
      source: sourceId,
      target: resource.key,
      animated: derivedHealth === "Progressing",
      style: {
        stroke:
          derivedHealth === "Degraded" || derivedHealth === "Missing"
            ? "var(--color-danger)"
            : "var(--color-border-line-emphasis)",
        strokeWidth: 1.5,
      },
    });
  }

  for (const n of rawNodes) {
    g.setNode(n.id, { width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT });
  }
  for (const e of edges) {
    g.setEdge(e.source, e.target);
  }

  // Only nodes that actually have an outgoing edge render a source handle, so leaf
  // resources do not show a dangling connector dot on their right edge.
  const parentIds = new Set(edges.map((e) => e.source));
  for (const n of rawNodes) {
    n.data.hasChildren = parentIds.has(n.id);
  }

  dagre.layout(g);

  const isHorizontal = direction === "LR";
  const layoutedNodes: ResourceFlowNode[] = rawNodes.map((n) => {
    const pos = g.node(n.id);
    return {
      id: n.id,
      type: "resourceNode",
      position: {
        x: Math.round(pos.x - GRAPH_NODE_WIDTH / 2),
        y: Math.round(pos.y - GRAPH_NODE_HEIGHT / 2),
      },
      // React Flow's MiniMap only draws nodes that carry explicit dimensions
      // (`measured ?? width ?? initialWidth`); DOM measurement alone is not
      // guaranteed to reach it. The card is fixed-size, so declare it.
      width: GRAPH_NODE_WIDTH,
      height: GRAPH_NODE_HEIGHT,
      // The synthetic Application root has no `resource` to inspect, so it must
      // not look/behave like a selectable node.
      ...(n.data.isRootApplication ? { selectable: false } : {}),
      sourcePosition: isHorizontal ? Position.Right : Position.Bottom,
      targetPosition: isHorizontal ? Position.Left : Position.Top,
      data: n.data,
    };
  });

  return { nodes: layoutedNodes, edges };
}

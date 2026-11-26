import dagre from "dagre";
import { Position, type Edge, type Node } from "@xyflow/react";
import type { ResourceGraphView, ResourceNodeView } from "../api/types";

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
        ownership: resource.ownership ?? null,
        parent: resource.parent ?? null,
        resource,
      },
    });

    const sourceId =
      resource.parent &&
      resource.parent !== resource.key &&
      nodeMap.has(resource.parent)
        ? resource.parent
        : rootId;
    edges.push({
      id: `${sourceId}->${resource.key}`,
      source: sourceId,
      target: resource.key,
      animated: derivedHealth === "Progressing",
      style: {
        stroke:
          derivedHealth === "Degraded" || derivedHealth === "Missing"
            ? "#f43f5e"
            : "#475569",
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
      sourcePosition: isHorizontal ? Position.Right : Position.Bottom,
      targetPosition: isHorizontal ? Position.Left : Position.Top,
      data: n.data,
    };
  });

  return { nodes: layoutedNodes, edges };
}

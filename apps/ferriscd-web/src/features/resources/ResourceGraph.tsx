import {
  Background,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import { AlertTriangle, GitFork, Table2 } from "lucide-react";
import { memo, useEffect, useMemo, useState } from "react";
import type { ResourceGraphView } from "../../api/types";
import { EmptyState } from "../../ui/EmptyState";
import { HealthStatusBadge, SyncStatusBadge } from "../../ui/StatusBadges";
import {
  buildResourceGraphElements,
  LARGE_GRAPH_THRESHOLD,
  type ResourceFlowNode,
} from "./dagreLayout";
import { ResourceInspector } from "./ResourceInspector";
import { ResourceTable } from "./ResourceTable";

function getNodeBorderClass(health: string, sync: string, isRoot: boolean): string {
  if (isRoot) {
    return "border-indigo-500/70 bg-slate-900 shadow-indigo-500/10";
  }
  if (health === "Degraded" || health === "Missing") {
    return "border-rose-500/70 bg-slate-900";
  }
  if (sync === "OutOfSync") {
    return "border-amber-500/70 bg-slate-900";
  }
  if (health === "Progressing") {
    return "border-sky-500/70 bg-slate-900";
  }
  if (health === "Healthy") {
    return "border-emerald-500/60 bg-slate-900";
  }
  return "border-slate-700 bg-slate-900";
}

const ResourceNodeCard = memo(function ResourceNodeCard({
  data,
  selected,
}: NodeProps<ResourceFlowNode>) {
  const borderClass = getNodeBorderClass(
    data.healthStatus,
    data.syncStatus,
    data.isRootApplication,
  );

  return (
    <div
      data-testid={
        data.isRootApplication ? "graph-root-node" : `graph-node-${data.key}`
      }
      className={`w-[264px] rounded-xl border-2 px-3 py-2.5 shadow-lg transition-colors ${borderClass} ${
        selected ? "ring-2 ring-indigo-400" : ""
      }`}
    >
      {data.isRootApplication ? null : (
        <Handle
          type="target"
          position={Position.Left}
          className="!h-2.5 !w-2.5 !border-slate-900 !bg-slate-400"
        />
      )}
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[10px] font-semibold uppercase tracking-wider text-indigo-300">
          {data.kind}
        </span>
        {data.namespace && (
          <span className="truncate font-mono text-[10px] text-slate-400">
            {data.namespace}
          </span>
        )}
      </div>
      <p
        className="mt-0.5 truncate text-sm font-semibold text-slate-100"
        title={data.label}
      >
        {data.label}
      </p>
      <div className="mt-2 flex flex-wrap gap-1">
        <SyncStatusBadge status={data.syncStatus} compact />
        <HealthStatusBadge status={data.healthStatus} compact />
      </div>
      {data.hasChildren && (
        <Handle
          type="source"
          position={Position.Right}
          className="!h-2.5 !w-2.5 !border-slate-900 !bg-indigo-400"
        />
      )}
    </div>
  );
});

const nodeTypes: NodeTypes = {
  resourceNode: ResourceNodeCard,
};

export interface ResourceGraphProps {
  appNamespace: string;
  appName: string;
  graph: ResourceGraphView;
  onInspectDiff?: (resourceKey: string) => void;
}

export function ResourceGraph({
  appNamespace,
  appName,
  graph,
  onInspectDiff,
}: ResourceGraphProps) {
  const isLargeGraph = graph.nodes.length >= LARGE_GRAPH_THRESHOLD;
  const [viewMode, setViewMode] = useState<"graph" | "table">(() =>
    isLargeGraph ? "table" : "graph",
  );
  const [userPickedMode, setUserPickedMode] = useState(false);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const selectedResource = useMemo(
    () =>
      selectedKey
        ? (graph.nodes.find((n) => n.key === selectedKey) ?? null)
        : null,
    [graph.nodes, selectedKey],
  );

  useEffect(() => {
    if (userPickedMode) {
      return;
    }
    // Follow the graph size until the operator makes an explicit choice: a big
    // app defaults to the table, and one that shrank back gets the canvas again
    // (otherwise it would sit on the table with no banner explaining why).
    setViewMode(
      graph.nodes.length >= LARGE_GRAPH_THRESHOLD ? "table" : "graph",
    );
  }, [graph.nodes.length, userPickedMode]);

  useEffect(() => {
    if (selectedKey && !graph.nodes.some((node) => node.key === selectedKey)) {
      // The inspected resource disappeared from a poll response: close the
      // inspector rather than leave a stale panel open on a vanished node.
      setSelectedKey(null);
    }
  }, [graph.nodes, selectedKey]);

  const handleSelectViewMode = (mode: "graph" | "table") => {
    setUserPickedMode(true);
    setViewMode(mode);
  };

  const layout = useMemo(
    () =>
      viewMode === "graph"
        ? buildResourceGraphElements(appNamespace, appName, graph, "LR")
        : { nodes: [], edges: [] },
    [appNamespace, appName, graph, viewMode],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span className="font-medium text-slate-200">
            {graph.nodes.length} resources
          </span>
          <span>•</span>
          <span>
            Cluster:{" "}
            <code className="break-all text-slate-300">{graph.cluster}</code>
          </span>
          <span>•</span>
          <span>
            Namespace:{" "}
            <code className="break-all text-slate-300">{graph.namespace}</code>
          </span>
        </div>

        <div
          role="group"
          aria-label="Resource view mode"
          className="inline-flex rounded-lg border border-slate-700 bg-slate-900 p-0.5"
        >
          <button
            type="button"
            onClick={() => handleSelectViewMode("graph")}
            aria-pressed={viewMode === "graph"}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === "graph"
                ? "bg-indigo-600 text-white"
                : "text-slate-300 hover:text-white"
            }`}
          >
            <GitFork className="h-3.5 w-3.5" />
            Graph View
          </button>
          <button
            type="button"
            onClick={() => handleSelectViewMode("table")}
            aria-pressed={viewMode === "table"}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === "table"
                ? "bg-indigo-600 text-white"
                : "text-slate-300 hover:text-white"
            }`}
          >
            <Table2 className="h-3.5 w-3.5" />
            Resource Table View
          </button>
        </div>
      </div>

      {isLargeGraph && (
        <div
          role="status"
          data-testid="large-graph-banner"
          className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-200 motion-fade-in"
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span>
              Large application detected ({graph.nodes.length} resources &ge;{" "}
              {LARGE_GRAPH_THRESHOLD}). Defaulted to searchable Resource Table
              View for responsive navigation.
            </span>
          </div>
          {viewMode === "table" && (
            <button
              type="button"
              onClick={() => handleSelectViewMode("graph")}
              className="rounded border border-amber-500/50 bg-amber-500/15 px-2.5 py-1 text-xs font-medium text-amber-100 transition-colors hover:bg-amber-500/25"
            >
              Switch to Graph View anyway
            </button>
          )}
        </div>
      )}

      {graph.truncated && (
        <div
          role="status"
          className="flex items-center gap-2 rounded-lg border border-sky-500/40 bg-sky-500/10 px-4 py-2 text-xs text-sky-200 motion-fade-in"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-sky-400" />
          <span>
            Graph response was truncated by the server&apos;s node limit (
            <code>MAX_GRAPH_NODES</code>).
          </span>
        </div>
      )}

      {graph.nodes.length === 0 ? (
        <EmptyState size="md">
          No tracked resources in inventory yet. Trigger a sync to reconcile
          this application.
        </EmptyState>
      ) : viewMode === "graph" ? (
        <div
          data-testid="resource-graph-canvas"
          className="h-[560px] w-full overflow-hidden rounded-xl border border-slate-800 bg-slate-950"
        >
          <ReactFlow
            nodes={layout.nodes}
            edges={layout.edges}
            nodeTypes={nodeTypes}
            // The topology is a read-only view: no dragging (a drag is lost on
            // the next 10s poll anyway), no connecting, no edge editing.
            nodesConnectable={false}
            nodesDraggable={false}
            edgesFocusable={false}
            edgesReconnectable={false}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.2}
            maxZoom={1.8}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_evt, node) => {
              const flowNode = node as ResourceFlowNode;
              if (flowNode.data.resource) {
                setSelectedKey(flowNode.data.resource.key);
              }
            }}
          >
            <Background color="#1e293b" gap={20} />
            <Controls />
            <MiniMap
              nodeColor={(n) => {
                const flowNode = n as ResourceFlowNode;
                if (flowNode.data?.healthStatus === "Degraded") return "#f43f5e";
                if (flowNode.data?.healthStatus === "Healthy") return "#10b981";
                if (flowNode.data?.healthStatus === "Progressing") return "#38bdf8";
                return "#64748b";
              }}
            />
          </ReactFlow>
        </div>
      ) : (
        <ResourceTable
          nodes={graph.nodes}
          graph={graph}
          onSelect={(key) => setSelectedKey(key)}
        />
      )}

      <ResourceInspector
        resource={selectedResource}
        appSyncStatus={graph.syncStatus}
        onClose={() => setSelectedKey(null)}
        onInspectDiff={
          onInspectDiff
            ? (key) => {
                setSelectedKey(null);
                onInspectDiff(key);
              }
            : undefined
        }
      />
    </div>
  );
}

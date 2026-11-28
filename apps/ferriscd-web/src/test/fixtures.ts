import type { FerrisApiClient } from "../api/client";
import { PolicyEnforcement } from "../api/types";
import type {
  ApplicationDetailView,
  ApplicationEventListView,
  ApplicationSummary,
  DiffPayload,
  DiffView,
  OperationResponse,
  ProjectListView,
  ResourceGraphView,
  ResourceNodeView,
  SyncWindowGateView,
} from "../api/types";

/** A project whose window blocks a manual sync with no override (`T17.4`). */
export const blockedSyncWindow: SyncWindowGateView = {
  blocked: true,
  reason: "denyWindowActive",
  message:
    "a deny sync window is active (deny \"0 9-17 * * MON-FRI\" in America/New_York); the next window transition is 2026-11-25T22:00:00Z (5h); manual sync does not override this window (set manualSync: true to allow it)",
  manualOverride: false,
  nextTransition: "2026-11-25T22:00:00Z",
};

/** The same block, on a window that opted into `manualSync: true` (`T17.4`). */
export const overridableSyncWindow: SyncWindowGateView = {
  blocked: true,
  reason: "denyWindowActive",
  message:
    "a deny sync window is active (deny \"0 9-17 * * MON-FRI\" in America/New_York); a manual sync may override this window (manualSync: true)",
  manualOverride: true,
  nextTransition: "2026-11-25T22:00:00Z",
};

export const sampleApps: ApplicationSummary[] = [
  {
    namespace: "ferriscd-system",
    name: "payments-api",
    project: "payments",
    resourceCount: 15,
    observedGeneration: 4,
    source: {
      sourceType: "git",
      repoUrl: "https://github.com/acme/gitops-payments.git",
      path: "deploy/prod",
      targetRevision: "main",
      renderer: "kustomize",
    },
    destination: {
      cluster: "prod-us-east",
      namespace: "payments",
    },
    sync: {
      status: "OutOfSync",
      revision: "a1b2c3d4e5f60000111122223333444455556666",
      lastSyncedRevision: "9999888877776666555544443333222211110000",
      lastSyncedAt: "2026-11-25T18:00:00Z",
    },
    health: {
      status: "Healthy",
      message: "All workloads healthy",
    },
    conditions: [
      {
        type: "Ready",
        status: "True",
        reason: "Reconciled",
        message: "Rendered 15 resources cleanly",
        lastTransitionTime: "2026-11-25T18:00:01Z",
        observedGeneration: 4,
      },
      {
        type: "DriftDetected",
        status: "False",
        reason: "OutOfSync",
        message: "Deployment replicas differ from Git",
        lastTransitionTime: "2026-11-25T19:15:00Z",
        observedGeneration: 4,
      },
    ],
  },
  {
    namespace: "ferriscd-system",
    name: "checkout-web",
    project: "storefront",
    resourceCount: 8,
    observedGeneration: 2,
    source: {
      sourceType: "git",
      repoUrl: "https://github.com/acme/gitops-storefront.git",
      path: "charts/checkout",
      targetRevision: "v2.4.0",
      renderer: "helm",
    },
    destination: {
      cluster: "in-cluster",
      namespace: "storefront",
    },
    sync: {
      status: "Synced",
      revision: "deadbeef1234567890abcdef",
      lastSyncedRevision: "deadbeef1234567890abcdef",
      lastSyncedAt: "2026-11-25T17:30:00Z",
    },
    health: {
      status: "Degraded",
      message: "Pod checkout-web-0 CrashLoopBackOff",
    },
    conditions: [],
  },
  {
    namespace: "ferriscd-system",
    name: "observability-stack",
    project: "platform",
    resourceCount: 22,
    observedGeneration: 7,
    source: {
      sourceType: "git",
      repoUrl: "https://github.com/acme/gitops-platform.git",
      path: "monitoring",
      targetRevision: "HEAD",
      renderer: "plainYaml",
    },
    destination: {
      cluster: "in-cluster",
      namespace: "monitoring",
    },
    sync: {
      status: "Synced",
      revision: "cafebabe0000111122223333",
      lastSyncedRevision: "cafebabe0000111122223333",
      lastSyncedAt: "2026-11-25T16:00:00Z",
    },
    health: {
      status: "Healthy",
      message: null,
    },
    conditions: [],
  },
];

/**
 * An OCI-sourced `Application` (`T18.4`): `sourceType: "oci"` with a tag to
 * resolve *and* the digest the operator pinned, which are the two facts the
 * source panel has to render separately.
 */
export const sampleOciApp: ApplicationSummary = {
  namespace: "ferriscd-system",
  name: "ledger-artifact",
  project: "payments",
  resourceCount: 4,
  observedGeneration: 1,
  source: {
    sourceType: "oci",
    repoUrl: "oci://registry.ferriscd-system.svc:5000/payments/ledger",
    path: "charts/ledger",
    targetRevision: "1.4.2",
    tag: "1.4.2",
    digest:
      "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
    renderer: "helm",
  },
  destination: {
    cluster: "in-cluster",
    namespace: "payments",
  },
  sync: {
    status: "Synced",
    revision:
      "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
    lastSyncedRevision:
      "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
    lastSyncedAt: "2026-11-25T20:10:00Z",
  },
  health: {
    status: "Healthy",
    message: null,
  },
  conditions: [],
};

/**
 * A split OCI chart + Git values `Application` (`T20.1`): the panel has to name
 * every declared source, which one renders, and the revision each one resolved
 * to — the composite `sync.revision` alone cannot say whether the values
 * repository moved.
 */
export const sampleMultiSourceApp: ApplicationSummary = {
  namespace: "ferriscd-system",
  name: "payments-multi",
  project: "payments",
  resourceCount: 6,
  observedGeneration: 3,
  source: {
    sourceType: "oci",
    repoUrl: "oci://registry.ferriscd-system.svc:5000/charts/payments",
    path: "",
    targetRevision: "1.4.2",
    tag: "1.4.2",
    digest:
      "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
    renderer: "helm",
    multiSource: true,
    sources: [
      {
        ref: "chart",
        sourceType: "oci",
        repoUrl: "oci://registry.ferriscd-system.svc:5000/charts/payments",
        path: "",
        targetRevision: "1.4.2",
        tag: "1.4.2",
        digest:
          "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
        renderer: "helm",
      },
      {
        ref: "values",
        sourceType: "git",
        repoUrl: "https://github.com/acme/payments-values.git",
        path: "",
        targetRevision: "main",
      },
    ],
  },
  destination: {
    cluster: "in-cluster",
    namespace: "payments",
  },
  sync: {
    status: "Synced",
    revision:
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    lastSyncedRevision:
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    lastSyncedAt: "2026-11-27T09:15:00Z",
    revisions: [
      "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
      "2222222222222222222222222222222222222222",
    ],
  },
  health: {
    status: "Healthy",
    message: null,
  },
  conditions: [],
};

export const sampleOciAppDetail: ApplicationDetailView = {
  application: sampleOciApp,
  history: [
    {
      id: 1,
      revision:
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      deployedAt: "2026-11-24T09:00:00Z",
    },
    {
      id: 2,
      revision:
        "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
      deployedAt: "2026-11-25T20:10:00Z",
    },
  ],
  operation: {
    phase: "Succeeded",
    currentWave: 0,
    startedAt: "2026-11-25T20:09:50Z",
    finishedAt: "2026-11-25T20:10:00Z",
    revision:
      "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
    message: "Applied wave 0 cleanly",
  },
};

export const sampleAppDetail: ApplicationDetailView = {
  application: sampleApps[0]!,
  history: [
    {
      id: 1,
      revision: "1111222233334444555566667777888899990000",
      deployedAt: "2026-11-24T10:00:00Z",
    },
    {
      id: 2,
      revision: "9999888877776666555544443333222211110000",
      deployedAt: "2026-11-25T18:00:00Z",
    },
  ],
  operation: {
    phase: "Succeeded",
    currentWave: 0,
    startedAt: "2026-11-25T17:59:45Z",
    finishedAt: "2026-11-25T18:00:00Z",
    revision: "9999888877776666555544443333222211110000",
    message: "Applied wave 0 cleanly",
  },
};

export function make15NodeResourceGraph(): ResourceGraphView {
  const nodes: ResourceNodeView[] = [
    // Root-level managed resources
    {
      key: "/Service/payments/payments-svc",
      group: "",
      kind: "Service",
      namespace: "payments",
      name: "payments-svc",
      present: true,
      health: "Healthy",
      healthMessage: "Endpoints ready",
      ownership: "Owned",
      parent: null,
    },
    {
      key: "/ConfigMap/payments/payments-cfg",
      group: "",
      kind: "ConfigMap",
      namespace: "payments",
      name: "payments-cfg",
      present: true,
      health: "Healthy",
      healthMessage: null,
      ownership: "Owned",
      parent: null,
    },
    {
      key: "/Secret/payments/payments-db-creds",
      group: "",
      kind: "Secret",
      namespace: "payments",
      name: "payments-db-creds",
      present: true,
      health: "Healthy",
      healthMessage: null,
      ownership: "Owned",
      parent: null,
    },
    {
      key: "/ServiceAccount/payments/payments-sa",
      group: "",
      kind: "ServiceAccount",
      namespace: "payments",
      name: "payments-sa",
      present: true,
      health: "Healthy",
      healthMessage: null,
      ownership: "Owned",
      parent: null,
    },
    {
      key: "networking.k8s.io/Ingress/payments/payments-ingress",
      group: "networking.k8s.io",
      kind: "Ingress",
      namespace: "payments",
      name: "payments-ingress",
      present: true,
      health: "Healthy",
      healthMessage: "LoadBalancer assigned",
      ownership: "Owned",
      parent: null,
    },
    {
      key: "apps/Deployment/payments/payments-api",
      group: "apps",
      kind: "Deployment",
      namespace: "payments",
      name: "payments-api",
      present: true,
      health: "Healthy",
      healthMessage: "3/3 replicas available",
      ownership: "Owned",
      parent: null,
    },
    {
      key: "apps/ReplicaSet/payments/payments-api-7f8d9",
      group: "apps",
      kind: "ReplicaSet",
      namespace: "payments",
      name: "payments-api-7f8d9",
      present: true,
      health: "Healthy",
      healthMessage: "3/3 ready",
      ownership: "Owned",
      parent: "apps/Deployment/payments/payments-api",
    },
    {
      key: "/Pod/payments/payments-api-7f8d9-aaa",
      group: "",
      kind: "Pod",
      namespace: "payments",
      name: "payments-api-7f8d9-aaa",
      present: true,
      health: "Healthy",
      healthMessage: "Running",
      ownership: "Owned",
      parent: "apps/ReplicaSet/payments/payments-api-7f8d9",
    },
    {
      key: "/Pod/payments/payments-api-7f8d9-bbb",
      group: "",
      kind: "Pod",
      namespace: "payments",
      name: "payments-api-7f8d9-bbb",
      present: true,
      health: "Progressing",
      healthMessage: "ContainerCreating",
      ownership: "Owned",
      parent: "apps/ReplicaSet/payments/payments-api-7f8d9",
    },
    {
      key: "/Pod/payments/payments-api-7f8d9-ccc",
      group: "",
      kind: "Pod",
      namespace: "payments",
      name: "payments-api-7f8d9-ccc",
      present: true,
      health: "Degraded",
      healthMessage: "OOMKilled",
      ownership: "Owned",
      parent: "apps/ReplicaSet/payments/payments-api-7f8d9",
    },
    {
      key: "apps/Deployment/payments/payments-worker",
      group: "apps",
      kind: "Deployment",
      namespace: "payments",
      name: "payments-worker",
      present: true,
      health: "Healthy",
      healthMessage: "2/2 replicas available",
      ownership: "Owned",
      parent: null,
    },
    {
      key: "apps/ReplicaSet/payments/payments-worker-4c2b1",
      group: "apps",
      kind: "ReplicaSet",
      namespace: "payments",
      name: "payments-worker-4c2b1",
      present: true,
      health: "Healthy",
      healthMessage: "2/2 ready",
      ownership: "Owned",
      parent: "apps/Deployment/payments/payments-worker",
    },
    {
      key: "/Pod/payments/payments-worker-4c2b1-111",
      group: "",
      kind: "Pod",
      namespace: "payments",
      name: "payments-worker-4c2b1-111",
      present: true,
      health: "Healthy",
      healthMessage: "Running",
      ownership: "Owned",
      parent: "apps/ReplicaSet/payments/payments-worker-4c2b1",
    },
    {
      key: "/Pod/payments/payments-worker-4c2b1-222",
      group: "",
      kind: "Pod",
      namespace: "payments",
      name: "payments-worker-4c2b1-222",
      present: true,
      health: "Healthy",
      healthMessage: "Running",
      ownership: "Owned",
      parent: "apps/ReplicaSet/payments/payments-worker-4c2b1",
    },
    {
      key: "policy/PodDisruptionBudget/payments/payments-pdb",
      group: "policy",
      kind: "PodDisruptionBudget",
      namespace: "payments",
      name: "payments-pdb",
      present: false,
      health: "Missing",
      healthMessage: "Not yet created in cluster",
      ownership: null,
      parent: null,
    },
  ];

  return {
    cluster: "prod-us-east",
    namespace: "payments",
    syncStatus: "OutOfSync",
    healthStatus: "Degraded",
    truncated: false,
    nodes,
  };
}

export function makeLargeResourceGraph(count = 120): ResourceGraphView {
  const nodes: ResourceNodeView[] = [];
  for (let i = 0; i < count; i++) {
    const kind = i % 3 === 0 ? "ConfigMap" : i % 3 === 1 ? "Service" : "Deployment";
    const group = kind === "Deployment" ? "apps" : "";
    const name = `workload-${String(i + 1).padStart(3, "0")}`;
    nodes.push({
      key: `${group}/${kind}/payments/${name}`,
      group,
      kind,
      namespace: "payments",
      name,
      present: true,
      health: i % 10 === 0 ? "Progressing" : "Healthy",
      healthMessage: i % 10 === 0 ? "Rolling out" : null,
      ownership: "Owned",
      parent: null,
    });
  }
  return {
    cluster: "prod-us-east",
    namespace: "payments",
    syncStatus: "Synced",
    healthStatus: "Healthy",
    truncated: false,
    nodes,
  };
}

export const sampleDiffPayload: DiffPayload = {
  revision: "a1b2c3d4e5f60000111122223333444455556666",
  desired: 4,
  wouldSync: true,
  summary: {
    total: 5,
    synced: 1,
    outOfSync: 2,
    missing: 1,
    orphaned: 1,
    ownershipConflicts: 0,
    fieldConflicts: 1,
  },
  resources: [
    {
      key: "apps/Deployment/payments/payments-api",
      status: "OutOfSync",
      truncated: false,
      conflicts: [
        {
          field: ".spec.replicas",
          manager: "kube-controller-manager",
        },
      ],
      changes: [
        {
          path: "/spec/replicas",
          kind: "modified",
          live: 2,
          predicted: 4,
        },
      ],
    },
    {
      key: "/Secret/payments/payments-db-creds",
      status: "OutOfSync",
      truncated: false,
      conflicts: [],
      changes: [
        {
          path: "/data/DATABASE_PASSWORD",
          kind: "modified",
          live: "***REDACTED(sha256:9f86d081)***",
          predicted: "***REDACTED(sha256:4b227777)***",
        },
      ],
    },
    {
      key: "policy/PodDisruptionBudget/payments/payments-pdb",
      status: "Missing",
      truncated: false,
      conflicts: [],
      changes: [],
    },
    {
      key: "/ConfigMap/payments/legacy-flags",
      status: "Orphaned",
      truncated: false,
      conflicts: [],
      changes: [],
    },
    {
      key: "/Service/payments/payments-svc",
      status: "Synced",
      truncated: false,
      conflicts: [],
      changes: [],
    },
  ],
};

/**
 * A `DiffView` the policy gate refused (`T20.2`): the manifests are exactly what Git says, but one
 * `Enforce` rule rejects them, so `wouldSync` is `false`. Nothing here may carry a `Secret` value —
 * the server scrubs violation messages before they leave the process.
 */
export const sampleDiffPayloadWithPolicyViolations: DiffPayload = {
  ...sampleDiffPayload,
  wouldSync: false,
  policyViolations: [
    {
      rule: "no-privileged",
      enforcement: PolicyEnforcement.Enforce,
      resourceKey: "apps/Deployment/payments/payments-api",
      message:
        "privileged containers are forbidden (policy \"no-privileged\")",
    },
    {
      rule: "prefer-approved-registry",
      enforcement: PolicyEnforcement.Warn,
      resourceKey: "apps/Deployment/payments/payments-api",
      message:
        "prefer the approved registry (policy \"prefer-approved-registry\")",
    },
  ],
};

export const sampleProjects: ProjectListView = {
  items: [
    {
      name: "payments",
      description: "PCI-scoped payment services",
      sourceRepos: ["https://github.com/acme/gitops-payments.git"],
      sourceNamespaces: ["ferriscd-system"],
      destinations: ["prod-us-east/payments", "in-cluster/payments"],
      allowedServiceAccounts: ["payments-deployer"],
      // `T17.4`: a change freeze that is open right now, and a Saturday release window.
      syncWindows: [
        {
          kind: "deny",
          schedule: "0 9-17 * * MON-FRI",
          duration: "8h",
          timeZone: "America/New_York",
          applications: ["payments-*"],
          namespaces: [],
          clusters: ["prod-*"],
          manualSync: false,
          active: true,
          startsAt: "2026-11-25T14:00:00Z",
          endsAt: "2026-11-25T22:00:00Z",
          nextStart: "2026-11-26T14:00:00Z",
        },
        {
          kind: "allow",
          schedule: "0 2 * * SAT",
          duration: "2h",
          timeZone: "UTC",
          applications: [],
          namespaces: [],
          clusters: [],
          manualSync: true,
          active: false,
          nextStart: "2026-11-28T02:00:00Z",
        },
      ],
      nextSyncWindowTransition: "2026-11-25T22:00:00Z",
    },
    {
      name: "storefront",
      description: "Customer-facing storefront",
      sourceRepos: ["https://github.com/acme/gitops-storefront.git"],
      sourceNamespaces: ["ferriscd-system"],
      destinations: ["in-cluster/storefront"],
      allowedServiceAccounts: [],
    },
  ],
};

export const sampleClusters = {
  items: [
    { name: "in-cluster", inCluster: true },
    { name: "prod-us-east", inCluster: false },
  ],
};

export const sampleEvents: ApplicationEventListView = {
  items: [
    {
      name: "payments-api.18f1",
      type: "Warning",
      reason: "SyncFailed",
      message: "failed to apply Deployment payments/api: quota exceeded",
      action: "Sync",
      count: 3,
      reportingComponent: "ferriscd.io/controller",
      lastObservedAt: "2026-11-25T19:15:00Z",
      firstObservedAt: "2026-11-25T18:55:00Z",
    },
    {
      name: "payments-api.18e2",
      type: "Normal",
      reason: "SyncSucceeded",
      message: "applied 15 resources from revision a1b2c3d",
      action: "Sync",
      count: 1,
      reportingComponent: "ferriscd.io/controller",
      lastObservedAt: "2026-11-25T18:00:00Z",
      firstObservedAt: "2026-11-25T18:00:00Z",
    },
  ],
  truncated: false,
};

export function createMockApiClient(
  overrides: Partial<FerrisApiClient> = {},
): FerrisApiClient {
  const defaultOp: OperationResponse = {
    status: "accepted",
    operation: "sync",
    namespace: "ferriscd-system",
    name: "payments-api",
    request: '{"sync":{}}',
    resourceVersion: "42",
  };

  return {
    raw: {} as FerrisApiClient["raw"],
    listApplications: async () => ({ items: sampleApps }),
    getApplication: async () => sampleAppDetail,
    getResources: async () => make15NodeResourceGraph(),
    getDiff: async () => sampleDiffPayload as unknown as DiffView,
    getApplicationEvents: async () => sampleEvents,
    syncApplication: async () => defaultOp,
    rollbackApplication: async (_ns, _name, body) => ({
      ...defaultOp,
      operation: "rollback",
      request: JSON.stringify({ rollback: { id: body.id } }),
    }),
    listProjects: async () => sampleProjects,
    listClusters: async () => sampleClusters,
    getAuthConfig: async () => ({
      authMode: "token-review",
      scopes: [],
      bffEnabled: false,
    }),
    logoutSession: async () => {},
    ...overrides,
  };
}

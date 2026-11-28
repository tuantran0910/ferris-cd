import { describe, expect, it } from "vitest";
import type { ApplicationSummary } from "../api/types";
import {
  EMPTY_COUNTS,
  POLICY_GATE_VIOLATION_REASON,
  POLICY_VIOLATION_REASON,
  addApplicationCounts,
  buildFleetRollup,
  hasBlockingPolicyViolation,
  percentOf,
  triageEntry,
} from "../features/overview/rollup";

function app(overrides: Partial<ApplicationSummary> = {}): ApplicationSummary {
  return {
    namespace: "ferriscd-system",
    name: "app",
    project: "payments",
    resourceCount: 4,
    source: {
      sourceType: "git",
      repoUrl: "https://github.com/acme/gitops.git",
      path: "apps/app",
      targetRevision: "main",
      renderer: "plainYaml",
    },
    destination: { cluster: "in-cluster", namespace: "app" },
    sync: { status: "Synced" },
    health: { status: "Healthy" },
    conditions: [],
    ...overrides,
  };
}

function countsOf(apps: ApplicationSummary[]) {
  const counts = { ...EMPTY_COUNTS };
  for (const entry of apps) {
    addApplicationCounts(counts, entry);
  }
  return counts;
}

describe("fleet rollup (T20.5)", () => {
  it("counts every sync and health verdict exactly once", () => {
    const counts = countsOf([
      app({ sync: { status: "Synced" }, health: { status: "Healthy" } }),
      app({ sync: { status: "OutOfSync" }, health: { status: "Degraded" } }),
      app({ sync: { status: "OutOfSync" }, health: { status: "Missing" } }),
      app({ sync: { status: "Unknown" }, health: { status: "Progressing" } }),
      app({ sync: null, health: null }),
      app({ sync: { status: "Synced" }, health: { status: "Suspended" } }),
    ]);

    expect(counts.total).toBe(6);
    expect(counts.synced).toBe(2);
    expect(counts.outOfSync).toBe(2);
    expect(counts.unknownSync).toBe(2); // an explicit "Unknown" and an absent verdict
    expect(counts.healthy).toBe(1);
    expect(counts.degraded).toBe(1);
    expect(counts.missing).toBe(1);
    expect(counts.progressing).toBe(1);
    expect(counts.suspended).toBe(1);
    expect(counts.unknownHealth).toBe(1);
    // The buckets partition the fleet: nothing is counted twice or dropped.
    expect(
      counts.synced + counts.outOfSync + counts.unknownSync,
    ).toBe(counts.total);
    expect(
      counts.healthy +
        counts.progressing +
        counts.degraded +
        counts.suspended +
        counts.missing +
        counts.unknownHealth,
    ).toBe(counts.total);
  });

  it("reads a blocking policy violation from the latest Ready condition only", () => {
    const blocked = app({
      conditions: [
        {
          type: "Ready",
          status: "False",
          reason: POLICY_VIOLATION_REASON,
          message: "rule no-privileged rejected the bundle",
          lastTransitionTime: "2026-11-28T09:00:00Z",
        },
      ],
    });
    expect(hasBlockingPolicyViolation(blocked)).toBe(true);

    // A later Ready verdict supersedes the earlier one: the violation was fixed.
    const recovered = app({
      conditions: [
        {
          type: "Ready",
          status: "False",
          reason: POLICY_VIOLATION_REASON,
          message: "rule no-privileged rejected the bundle",
          lastTransitionTime: "2026-11-28T09:00:00Z",
        },
        {
          type: "Ready",
          status: "True",
          reason: "Reconciled",
          message: "applied 4 resources",
          lastTransitionTime: "2026-11-28T09:05:00Z",
        },
      ],
    });
    expect(hasBlockingPolicyViolation(recovered)).toBe(false);

    // Some other Ready failure (a bad revision, an unreachable cluster) is not a policy violation.
    expect(
      hasBlockingPolicyViolation(
        app({
          conditions: [
            {
              type: "Ready",
              status: "False",
              reason: "RenderFailed",
              message: "kustomize exited 1",
              lastTransitionTime: "2026-11-28T09:00:00Z",
            },
          ],
        }),
      ),
    ).toBe(false);
    expect(hasBlockingPolicyViolation(app({ conditions: [] }))).toBe(false);
  });

  it("counts the policy gate verdict and the AppProject verdict, but not an unrelated failure", () => {
    // The controller writes `PolicyGateViolation` when the `T20.2` gate refuses a bundle, and
    // `PolicyViolation` when the `AppProject` allow-list does. Both block the sync.
    for (const reason of [POLICY_GATE_VIOLATION_REASON, POLICY_VIOLATION_REASON]) {
      expect(
        hasBlockingPolicyViolation(
          app({
            conditions: [
              {
                type: "Ready",
                status: "False",
                reason,
                message: "refused",
                lastTransitionTime: "2026-11-28T09:00:00Z",
              },
            ],
          }),
        ),
      ).toBe(true);
    }
    expect(POLICY_GATE_VIOLATION_REASON).toBe("PolicyGateViolation");
    expect(POLICY_VIOLATION_REASON).toBe("PolicyViolation");
  });

  it("triages policy violations before degraded, missing and out-of-sync", () => {
    expect(triageEntry(app())).toBeNull();

    const policy = triageEntry(
      app({
        name: "policy",
        conditions: [
          {
            type: "Ready",
            status: "False",
            reason: POLICY_VIOLATION_REASON,
            message: "rule x",
            lastTransitionTime: "2026-11-28T09:00:00Z",
          },
        ],
      }),
    );
    const degraded = triageEntry(
      app({ name: "degraded", health: { status: "Degraded", message: "CrashLoopBackOff" } }),
    );
    const missing = triageEntry(app({ name: "missing", health: { status: "Missing" } }));
    const outOfSync = triageEntry(app({ name: "oos", sync: { status: "OutOfSync" } }));
    const unknown = triageEntry(app({ name: "unknown", health: { status: "Unknown" } }));

    expect(policy?.severity).toBe(0);
    expect(degraded?.severity).toBe(1);
    expect(missing?.severity).toBe(2);
    expect(outOfSync?.severity).toBe(3);
    expect(unknown?.severity).toBe(4);
    // The health message is carried through verbatim — the operator wants the actual reason.
    expect(degraded?.reasons).toContain("CrashLoopBackOff");
    // A rollout in flight is the system working, not a queue item.
    expect(triageEntry(app({ health: { status: "Progressing" } }))).toBeNull();
  });

  it("orders the queue by severity, then by namespace/name, and keeps every app in exactly one bucket", () => {
    const apps = [
      app({ name: "b-out", sync: { status: "OutOfSync" } }),
      app({ name: "a-degraded", health: { status: "Degraded" } }),
      app({ name: "a-out", sync: { status: "OutOfSync" } }),
      app({ name: "healthy" }),
    ];
    const rollup = buildFleetRollup(apps, ["in-cluster", "prod-us-east"], ["payments"]);
    expect(rollup.triage.map((entry) => entry.app.name)).toEqual([
      "a-degraded",
      "a-out",
      "b-out",
    ]);

    expect(rollup.byCluster.map((bucket) => bucket.key)).toEqual([
      "in-cluster",
      "prod-us-east",
    ]);
    // A registered cluster with no visible application still gets an explicit zero row (it is the
    // cluster catalogue the server already scoped, not a fleet-wide total).
    const empty = rollup.byCluster.find((bucket) => bucket.key === "prod-us-east");
    expect(empty?.counts.total).toBe(0);
    expect(rollup.totals.total).toBe(4);
    expect(rollup.resources).toBe(16);
  });

  it("adds a row for a destination the catalogue no longer lists, so no app is dropped", () => {
    const rollup = buildFleetRollup(
      [app({ destination: { cluster: "retired-us-east", namespace: "app" }, project: "legacy" })],
      [],
      [],
    );
    expect(rollup.byCluster.map((bucket) => bucket.key)).toEqual(["retired-us-east"]);
    expect(rollup.byProject.map((bucket) => bucket.key)).toEqual(["legacy"]);
    expect(rollup.totals.total).toBe(1);
  });

  it("percentages never divide by zero", () => {
    expect(percentOf(0, 0)).toBe(0);
    expect(percentOf(1, 3)).toBe(33.3);
    expect(percentOf(3, 3)).toBe(100);
  });
});

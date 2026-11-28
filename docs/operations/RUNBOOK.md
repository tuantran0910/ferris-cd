# FerrisCD Production Operations Runbook (`v1.0`)

> Actionable Day-2 procedures verified against the `v1.0` `ferriscd` binary, Helm chart
> ([`deploy/helm/ferriscd/`](../../deploy/helm/ferriscd/)), Kustomize overlay
> ([`deploy/manifests/`](../../deploy/manifests/)), CRDs (`applications.ferriscd.io`,
> `appprojects.ferriscd.io`), and Prometheus metrics listener (`:9090/metrics`).
>
> **Safety first:** Before running any command below against a cluster, verify your `kubectl`
> context (`kubectl config current-context`) and namespace (`-n ferriscd-system`).

---

## 1. Installing & Upgrading FerrisCD

### 1.1 Helm Installation (Recommended)

**Single-replica (development / small clusters):**

```bash
helm install ferriscd deploy/helm/ferriscd \
  -n ferriscd-system --create-namespace
```

**Production High-Availability (2 active/standby replicas + Lease election + PDB + anti-affinity):**

```bash
helm install ferriscd deploy/helm/ferriscd \
  -n ferriscd-system --create-namespace \
  -f deploy/helm/ferriscd/values-ha.yaml \
  -f values-prod.yaml
```

Key `values-prod.yaml` overrides to set before production use:

* `image.repository` & `web.image.repository`: The chart defaults to `ghcr.io/ferriscd/ferriscd` and `ghcr.io/ferriscd/ferriscd-web`; when pulling images published by `.github/workflows/release.yml` from this repository or a fork, pass `--set image.repository=ghcr.io/<owner>/<repo>` and `--set web.image.repository=ghcr.io/<owner>/<repo>-web`.
* `rbacPolicy.rules`: Grant explicit project-scoped API access (`ferriscd-rbac-cm` defaults to `rules: []`, denying all authenticated API callers).
* `networkPolicy.ingress.apiFrom` & `networkPolicy.ingress.metricsFrom`: Allow your Ingress controller (port `8080`) and Prometheus namespace (port `9090`).
* `networkPolicy.egress.kubeApi.cidrs` & `networkPolicy.egress.gitHttps.cidrs`: Pin your cluster API server and Git server CIDRs (see [Lesson 16 §3](../lessons/16-packaging-hardening-and-production-gitops.md) on why pinning both avoids TCP/443 overlap).
* `defaultProject`: Narrow `sourceRepos`, `destinations`, and `allowedServiceAccounts` before enabling multi-tenancy (`multiTenant.applicationNamespaces` + `rbac.impersonation.enabled: true`).

Verify rollout:

```bash
kubectl -n ferriscd-system rollout status deployment/ferriscd
kubectl -n ferriscd-system rollout status deployment/ferriscd-web
```

### 1.2 Kustomize Installation

On a brand-new cluster, apply the CRDs first so `appprojects.ferriscd.io` establishes before
`default-project.yaml` is submitted:

```bash
kubectl apply --server-side -f deploy/crds/
kubectl wait --for=condition=Established --timeout=60s \
  crd/applications.ferriscd.io crd/appprojects.ferriscd.io
kubectl apply -k deploy/manifests
```

### 1.3 CRD Upgrade Discipline (Helm)

Helm **never** upgrades CRDs inside `crds/` on `helm upgrade` by design. Always apply updated CRD
manifests with Server-Side Apply **before** upgrading the Helm release:

```bash
# 1. Inspect CRD diff before applying
kubectl diff --server-side -f deploy/crds/

# 2. Apply updated CRDs and wait for Established condition
kubectl apply --server-side -f deploy/crds/
kubectl wait --for=condition=Established --timeout=60s \
  crd/applications.ferriscd.io crd/appprojects.ferriscd.io

# 3. Upgrade the Helm release
helm upgrade ferriscd deploy/helm/ferriscd \
  -n ferriscd-system \
  -f deploy/helm/ferriscd/values-ha.yaml \
  -f values-prod.yaml

# 4. Confirm rollout and health
kubectl -n ferriscd-system rollout status deployment/ferriscd
```

---

## 2. Troubleshooting Stuck Finalizers (`ferriscd.io/finalizer`)

Every `Application` reconciled by FerrisCD carries `metadata.finalizers: ["ferriscd.io/finalizer"]`.
When an `Application` is deleted:

* **Without** `ferriscd.io/cascade-delete: "true"`: the controller releases `ferriscd.io/finalizer`
  immediately, leaving live workload resources in place.
* **With** `ferriscd.io/cascade-delete: "true"`: the controller re-checks `AppProject` policy,
  verifies `ferriscd.io/tracking-id` on every resource in `status.inventory`, prunes owned resources
  in reverse dependency order, and then removes the finalizer.

### 2.1 Diagnose why an `Application` is stuck in `Terminating`

```bash
kubectl -n ferriscd-system get application <app-name> -o yaml
kubectl -n ferriscd-system describe application <app-name>
```

Check `status.conditions` (`Ready=False`) and recent Events for the root cause:

| Observed Condition / Reason | Root Cause | Safe Remedy |
|---|---|---|
| `reason=PolicyViolation` (missing/disallowed `serviceAccountName` or deleted `AppProject`) | Controller refuses to cascade-delete under an unauthorized identity (prevents privilege escalation) | Re-add the ServiceAccount to `AppProject.spec.allowedServiceAccounts` (or recreate the `AppProject`), or patch `spec.serviceAccountName` to an allowed ServiceAccount |
| `reason=CleanupSkipped` (remote cluster `Secret` deleted — Finding C5) | Remote cluster registration `Secret` (`ferriscd.io/secret-type=cluster`) was deleted while terminating; controller **automatically releases the finalizer with a warning** so the CR does not wedge | Verify whether workloads remain on the remote cluster and clean them up there; or recreate the cluster `Secret` before deleting future `Application`s |
| Transient API / RBAC / unreachable remote cluster error | Target API server unreachable or impersonated ServiceAccount lacks `delete` verb on a managed resource | Restore cluster connectivity or grant the missing `delete` verb to the tenant `ServiceAccount` |

### 2.2 Escape Hatch: Abandon Cascade Cleanup (`ferriscd.io/force-delete: "true"`)

If the destination cluster is permanently decommissioned or you intentionally want to delete the
`Application` CR **without** pruning its managed workloads, annotate it with the built-in escape
hatch:

```bash
kubectl -n ferriscd-system annotate application <app-name> \
  ferriscd.io/force-delete="true" --overwrite
```

The composite watch predicate detects `ferriscd.io/force-delete` immediately; the controller
releases `ferriscd.io/finalizer` without calling `Delete` on managed workloads. Remove any leftover
workloads manually if needed.

> **Emergency last resort (controller completely offline):** Only if the controller cannot run at
> all, remove the finalizer directly:
> ```bash
> kubectl -n ferriscd-system patch application <app-name> \
>   --type=merge -p '{"metadata":{"finalizers":[]}}'
> ```

---

## 3. Resolving SSA `409 FieldConflict` (Brownfield Adoption)

FerrisCD defaults `spec.syncPolicy.syncOptions.serverSideForce` to **`false`** so it never
silently overwrites fields owned by HPA (`kube-controller-manager`), VPA, cert-manager, or another
controller. When migrating existing ("brownfield") workloads previously applied with `kubectl apply`
or Helm, Server-Side Apply dry-run reports `409 Conflict` with the conflicting field manager names.

### 3.1 Inspect the conflict and existing `managedFields`

```bash
# View live, Secret-redacted diff including FieldConflict managers
ferriscd app diff <app-name> -n ferriscd-system

# Inspect exact managedFields ownership on the live Kubernetes object
kubectl -n <dest-ns> get <kind> <resource-name> -o yaml --show-managed-fields
```

### 3.2 Resolve safely (preferred order)

1. **Legitimate external controller (e.g., HPA owning `spec.replicas`):**
   Remove the conflicting field from your Git manifest (for example, omit `spec.replicas` when HPA
   manages scaling) or add a narrow RFC 6901 pointer in `spec.ignoreDifferences`. Do **not** force
   takeover.
2. **Legacy brownfield manager (e.g., `kubectl-client-side-apply` or `helm`):**
   Allowlist **only** that specific legacy manager in `spec.syncPolicy.syncOptions.takeoverFieldManagers`:

   ```yaml
   spec:
     syncPolicy:
       syncOptions:
         serverSideForce: false
         takeoverFieldManagers:
           - kubectl-client-side-apply
   ```

   FerrisCD retries SSA with `force: true` **only** when every conflicting manager on the resource
   is listed in `takeoverFieldManagers` — preserving conflict protection against HPA and all other
   managers.
3. **Clean up after adoption:** Once `ferriscd app diff <app-name>` exits `0` (`Synced`) and
   `--show-managed-fields` confirms `ferriscd` owns the desired fields, remove
   `takeoverFieldManagers` from the `Application` spec in Git.

---

## 4. Executing & Recovering from Rollback

FerrisCD maintains a bounded deployment history (`status.history`, default `revisionHistoryLimit: 10`,
max `20`). Executing a rollback deploys the pinned commit SHA from a previous history entry and
**automatically pauses `spec.syncPolicy.automated`** so self-heal does not immediately overwrite
the rollback with broken `HEAD`.

### 4.1 Execute a Rollback

```bash
# 1. Inspect deployment history IDs and commit SHAs
ferriscd app history <app-name> -n ferriscd-system

# 2. Trigger rollback to a known-good history ID (e.g., 3)
ferriscd app rollback <app-name> 3 -n ferriscd-system

# 3. Monitor convergence and verify `spec.syncPolicy.automated` was paused
ferriscd app get <app-name> -n ferriscd-system
kubectl -n ferriscd-system get application <app-name> \
  -o jsonpath='{.status.sync.status} {.status.health.status} rev={.status.sync.revision}{"\n"}'
```

*(Operators without REST API access can trigger the same operation directly on the CR by patching
the `ferriscd.io/operation` annotation: `kubectl -n ferriscd-system annotate application <app-name> ferriscd.io/operation='{"rollback":{"id":3}}' --overwrite`.)*

### 4.2 Recover and Resume Automated GitOps Sync

Because Git remains the source of truth, a rolled-back application stays paused until Git itself
is fixed:

1. **Revert or fix the bad commit in Git** (`git revert <bad-sha> && git push`).
2. **Verify zero unexpected drift** before re-enabling automation:
   ```bash
   ferriscd app diff <app-name> -n ferriscd-system
   # Exit code 0 = Synced, Exit code 2 = OutOfSync
   ```
3. **Re-enable `spec.syncPolicy.automated`** in your `Application` manifest (or patch it back):
   ```bash
   kubectl -n ferriscd-system patch application <app-name> --type=merge -p '{
     "spec": {
       "syncPolicy": {
         "automated": { "prune": true, "selfHeal": true }
       }
     }
   }'
   ```
4. **Confirm healthy steady state:**
   ```bash
   ferriscd app sync <app-name> -n ferriscd-system --watch
   ```

> **Note on `ferriscd app sync --prune`:** In `v1.0`, pruning is controlled declaratively via
> `spec.syncPolicy.automated.prune` in the `Application` spec; passing `--prune` to `ferriscd app sync`
> is refused by the server with HTTP `422`.

---

## 5. HA Lease Failover & Sharded Fleet Migration

### 5.1 Inspecting Active/Standby Leader Election (`coordination.k8s.io/v1` `Lease`)

When `replicaCount > 1` or `leaderElection.enabled: true` (as in
[`deploy/helm/ferriscd/values-ha.yaml`](../../deploy/helm/ferriscd/values-ha.yaml)), `ferriscd server`
runs with `--leader-election` over the namespaced Lease `ferriscd-controller-leader` in
`ferriscd-system`:

```bash
kubectl -n ferriscd-system get lease ferriscd-controller-leader -o yaml
```

Check `spec.holderIdentity`, `spec.renewTime`, `spec.leaseDurationSeconds`, and
`spec.leaseTransitions`.

* **Planned failover (graceful `SIGTERM`):** Deleting the leader pod triggers voluntary Lease
  release (holder cleared, 1s duration) so a standby takes over immediately:
  ```bash
  LEADER_POD=$(kubectl -n ferriscd-system get lease ferriscd-controller-leader \
    -o jsonpath='{.spec.holderIdentity}')
  echo "Current holder: ${LEADER_POD}"
  kubectl -n ferriscd-system delete pod <leader-pod-name>
  ```
* **Unplanned crash (`SIGKILL` / node loss):** Standby takes over after `leaseDurationSeconds`
  (default `15s`) plus one retry interval.
* **Configuration invariants enforced at startup:**
  * `--leader-election-renew-interval-seconds` (default `4`) **must be strictly less than one third**
    of `--leader-election-lease-duration-seconds` (default `15`).
  * Keep control-plane nodes synchronized via NTP (`chrony` / `systemd-timesyncd`); large clock skew
    delays failover or causes premature lease takeover.

### 5.2 Deterministic Sharding (`--shard-id` / `--total-shards`) & Stop-Then-Start Migration

Sharding partitions reconciliation deterministically by `sha256(namespace, name) % total-shards`.
Each shard acquires its own per-shard Lease (`ferriscd-leader-shard-<id>`). Note:

* `--shard-id` and `--total-shards` require `--leader-election` and **forbid**
  `--leader-election-lease-name` (enforced by both the CLI and the Helm chart).
* **NEVER rolling-update between unsharded and sharded fleets (or when changing `--total-shards`)!**
  An unsharded pod leads `ferriscd-controller-leader` while a sharded pod leads
  `ferriscd-leader-shard-0` — neither Lease excludes the other, causing double applies and racing
  prunes.

**Safe Stop-Then-Start Migration Procedure:**

```bash
# 1. Scale the current deployment/statefulset to 0 and wait for all pods to terminate
kubectl -n ferriscd-system scale deployment/ferriscd --replicas=0
kubectl -n ferriscd-system wait --for=delete pod \
  -l app.kubernetes.io/name=ferriscd,app.kubernetes.io/component=server --timeout=60s

# 2. Confirm no active Lease holder remains (delete stale Lease objects if switching modes)
kubectl -n ferriscd-system get leases

# 3. Deploy the new sharded topology (all replicas sharing the exact same `--total-shards`)
#    Using a StatefulSet with `FERRISCD_SHARD_ID` from `metadata.labels['apps.kubernetes.io/pod-index']`
#    and `FERRISCD_TOTAL_SHARDS="3"` (see deploy/README.md), OR per-shard Helm releases.

# 4. Verify each shard holds its own Lease `ferriscd-leader-shard-{0..N-1}`
kubectl -n ferriscd-system get leases
```

---

## 6. Observability Triage (Prometheus, OTLP & K8s Events)

### 6.1 Dedicated Metrics Endpoint (`:9090/metrics`)

`ferriscd` exposes strictly low-cardinality Prometheus metrics on `--metrics-addr` (default
`0.0.0.0:9090`, path `/metrics`), completely isolated from the `:8080` API port:

```bash
# Quick local scrape via port-forward
kubectl -n ferriscd-system port-forward svc/ferriscd 9090:9090 &
curl -sS http://127.0.0.1:9090/metrics | grep '^ferriscd_'
```

### 6.2 Recommended Production Prometheus Alerts

```yaml
groups:
  - name: ferriscd.rules
    rules:
      - alert: FerrisCDTerminalReconcileErrors
        expr: increase(ferriscd_reconcile_total{result="terminal"}[10m]) > 0
        for: 2m
        labels: { severity: warning }
        annotations:
          summary: "Terminal reconcile failure (invalid spec, policy violation, or bad credentials)"

      - alert: FerrisCDHighRetryableErrorRate
        expr: rate(ferriscd_reconcile_total{result="retryable"}[5m]) > 0.1
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Sustained retryable reconcile errors (Git outage, API 429/503, or network fault)"

      - alert: FerrisCDApplicationDegraded
        expr: ferriscd_app_health_status{status="Degraded"} == 1
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "Application {{ $labels.app_namespace }}/{{ $labels.app_name }} is Degraded"

      - alert: FerrisCDApplicationOutOfSyncStuck
        expr: ferriscd_app_sync_status{status="OutOfSync"} == 1
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "Application {{ $labels.app_namespace }}/{{ $labels.app_name }} OutOfSync > 15m"

      - alert: FerrisCDHighReconcileLatency
        expr: |
          histogram_quantile(0.95,
            sum by (le) (rate(ferriscd_reconcile_duration_seconds_bucket{result="success"}[5m]))
          ) > 5
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "p95 successful reconcile latency exceeds 5s"
```

Useful diagnostic queries:

* Render cache efficiency: `100 * rate(ferriscd_render_cache_total{outcome="hit"}[5m]) / clamp_min(sum(rate(ferriscd_render_cache_total[5m])), 1e-9)`
* In-flight concurrency saturation: `ferriscd_active_reconciles` (bounded at `8` per watched namespace scope)

### 6.3 OpenTelemetry OTLP Tracing

Enable distributed tracing by setting `telemetry.otlpEndpoint` in Helm (which sets
`OTEL_EXPORTER_OTLP_ENDPOINT` and opens `networkPolicy.egress.otlp`):

```bash
helm upgrade ferriscd deploy/helm/ferriscd -n ferriscd-system \
  --reuse-values \
  --set telemetry.otlpEndpoint=http://otel-collector.monitoring:4318 \
  --set telemetry.serviceName=ferriscd-controller
```

Traces emit spans for `reconcile`, `git_fetch`, `manifest_render`, `live_state_fetch`,
`diff_evaluate`, and `sync_execute` with zero secret payloads.

### 6.4 Rate-Limited Kubernetes Events

Inspect sync history and redacted failure diagnostics directly on any `Application`:

```bash
kubectl -n ferriscd-system describe application <app-name>
```

Expected Events: `Normal SyncSucceeded`, `Normal ResourcePruned`, and `Warning SyncFailed`.
Identical consecutive `Warning` reasons for the same `Application` are deduplicated for 5 minutes
to protect `etcd`; once a `Normal SyncSucceeded` occurs, the deduplication gate resets immediately.

---

## 7. Webhook, AuthN (`TokenReview`) & RBAC Troubleshooting

### 7.1 `401 Unauthorized` on `/api/v1/*` (`TokenReview`)

By default `ferriscd server` runs `--auth-policy token-review`, validating `Authorization: Bearer <token>`
against Kubernetes `authentication.k8s.io/v1` `TokenReview` (with a 30-second positive-only cache
keyed by token SHA-256).

Checklist when `ferriscd login` or API calls return `401`:

1. **Expired or invalid token:** Mint a fresh projected ServiceAccount token and re-login:
   ```bash
   kubectl -n ferriscd-system create token <sa-name> --duration=1h > /tmp/token
   chmod 0600 /tmp/token
   ferriscd login http://127.0.0.1:8080 --token-file /tmp/token
   rm -f /tmp/token
   ```
2. **Missing `TokenReview` RBAC on controller ServiceAccount:** Confirm the controller's
   `ClusterRole` grants `apiGroups: ["authentication.k8s.io"], resources: ["tokenreviews"], verbs: ["create"]`:
   ```bash
   kubectl auth can-i create tokenreviews.authentication.k8s.io \
     --as=system:serviceaccount:ferriscd-system:ferriscd
   ```
3. **Check controller logs for the one-way token fingerprint** (tokens themselves are never logged):
   ```bash
   kubectl -n ferriscd-system logs deploy/ferriscd --tail=100 | grep -i -E 'auth|tokenreview'
   ```

### 7.2 `403 Forbidden` or `404 Not Found` (`ferriscd-rbac-cm`)

`ferriscd server` loads project-scoped RBAC from `ConfigMap/ferriscd-rbac-cm` (key `policy.yaml`)
in the control-plane namespace (default-deny: `rules: []`) and watches it live via a namespaced
`ConfigMap` watch (`T17.1`), so updates apply automatically without restarting pods:

- **Valid update:** Atomically swaps the active policy snapshot and increments
  `ferriscd_rbac_reload_total{outcome="ok"}`.
- **Malformed YAML / duplicate keys / invalid rule / missing `policy.yaml`:** **Retains the last
  known-good policy** (or remains default-deny if startup never succeeded), logs a content-free
  `WARN` (never echoing group/user names), and increments
  `ferriscd_rbac_reload_total{outcome="error"}`. Watch-stream failures (API blips, terminated
  watches) are counted separately on `ferriscd_rbac_watch_errors_total` so the reload error series
  keeps meaning "a bad policy edit was rejected".
- **ConfigMap deletion:** Immediately transitions to default-deny (`rules: []`, refusing all
  authenticated callers) and increments `ferriscd_rbac_reload_total{outcome="deleted"}`.
- **Readiness (`/readyz`):** Returns `503 Service Unavailable` until `Application` watches
  (`InitDone`; with `--leader-election`, a standby replica that has observed a **healthy foreign
  leader** uses a separate gate, and a replica that acquires the lease must complete its own
  controller `InitDone`), the `ClusterManager` initial `Secret` seed, and the initial
  `ferriscd-rbac-cm` API load have all completed.

> **Important security behavior:** An identity with **no** grant on an application's project
> receives `404 Not Found` (identical to a nonexistent app) to prevent name enumeration. An identity
> that has `get` (read-only) receives `403 Forbidden` when attempting `sync` or `rollback`.
> `GET /api/v1/clusters` returns only clusters permitted by at least one `AppProject` visible to
> the caller.

Inspect and update `ferriscd-rbac-cm`:

```bash
# 1. Inspect the active policy
kubectl -n ferriscd-system get configmap ferriscd-rbac-cm -o jsonpath='{.data.policy\.yaml}{"\n"}'

# 2. Verify valid actions (`get`, `diff`, `sync`, `rollback`, `admin`) and subject kind (`user` | `group`)
# Example policy.yaml:
#   rules:
#     - subject: { kind: group, name: platform-admins }
#       project: "*"
#       actions: [admin]
#     - subject: { kind: user, name: system:serviceaccount:ferriscd-system:ci }
#       project: default
#       actions: [get, diff, sync]

# 3. Apply the updated ConfigMap — changes hot-reload in <= 2s without restarting pods;
#    confirm via `ferriscd_rbac_reload_total{outcome="ok"}` on `:9090/metrics`:
kubectl -n ferriscd-system apply -f ferriscd-rbac-cm.yaml
```

### 7.3 GitHub & GitLab Webhook Triage

Webhook endpoints are `/api/v1/webhooks/github` and `/api/v1/webhooks/gitlab` (unauthenticated by
`TokenReview`; authenticated solely by their webhook secret via `FERRISCD_GITHUB_WEBHOOK_SECRET`
and `FERRISCD_GITLAB_WEBHOOK_TOKEN` mounted from `webhooks.existingSecret`).

| HTTP Status / Response | Cause | Fix |
|---|---|---|
| `422 Unprocessable Entity` | `FERRISCD_GITHUB_WEBHOOK_SECRET` or `FERRISCD_GITLAB_WEBHOOK_TOKEN` is unset | Create the Secret in `ferriscd-system` and set `webhooks.existingSecret` in Helm values |
| `401 Unauthorized` | Invalid/missing `X-Hub-Signature-256` (`sha256=<hex>` HMAC over raw body) or `X-Gitlab-Token` | Verify secret parity between Git host and Secret key (`github-webhook-secret` / `gitlab-webhook-token`); ensure reverse proxy does not rewrite the raw body |
| `413 Payload Too Large` | Request body exceeded the 1 MiB `DefaultBodyLimit` | Check webhook event subscription (subscribe only to `push` events) |
| `200` with `duplicate` | Replayed `X-GitHub-Delivery` UUID within the 15-minute / 10,000-entry dedupe window | Expected replay protection; redeliver with a fresh delivery ID if re-testing |
| `200` with `ignored` | No `Application` matched the normalized repository URL + branch/tag | Verify `spec.source.git.repoURL` and `spec.source.git.targetRevision` match the pushed branch/tag |
| Sync delayed by 1–3s | Expected per-repo debounce (`--webhook-debounce-seconds`, default `2`) + fan-out jitter (`--webhook-max-jitter-millis`, default `500`) | Tune `webhooks.debounceSeconds` / `webhooks.maxJitterMillis` if required |

---

## 8. Disaster Recovery: `ferriscd backup export` / `restore`

Two things a `v1.0`+ FerrisCD installation cannot recover from Git: custom resources an operator
edited in-cluster, and the three control-plane `ConfigMap`s that are not part of any chart values
file. `ferriscd backup export` writes both into one versioned, **secret-free** bundle and
`ferriscd backup restore` puts them back with Server-Side Apply.

### 8.1 What the bundle contains (and what it never contains)

| Captured | Notes |
|---|---|
| `AppProject`, `ApplicationSet`, `Application` | every namespace, or only `--namespace` |
| `ConfigMap/ferriscd-rbac-cm`, `ferriscd-notifications-cm`, `ferriscd-policies-cm` | read from `--control-plane-namespace` (default `ferriscd-system`); absent ones are skipped with a note |
| one **stub** per `Secret` labelled `ferriscd.io/secret-type={repository,cluster,oidc,notifications}` **in `--control-plane-namespace`** | its namespace, name, `ferriscd.io/*` labels and the **names** of its data keys |

Never captured: `Secret.data`/`stringData` values (a stub records `password`, never its value),
`status`, `resourceVersion`, `uid`, `creationTimestamp`, `managedFields`, `generation`,
`metadata.ownerReferences`, and `kubectl.kubernetes.io/last-applied-configuration`.

Deliberate exclusions:

* `Application`s generated by an `ApplicationSet` (label `ferriscd.io/applicationset=…`) are listed by
  name under `generatedApplications` only. Their owner reference points at a uid a restore cannot
  reproduce, so the `ApplicationSet` regenerates them instead of a restore adopting a stale owner.
* Objects carrying a `metadata.deletionTimestamp` are listed under `skippedTerminating`: a
  half-deleted object is not DR material.
* **Labelled `Secret`s outside `--control-plane-namespace`.** The inventory is not "every labelled
  `Secret` in the cluster", because FerrisCD does not read credentials from anywhere else: Git
  credentials (`T12.4`), cluster registrations (`T13.1`), the OIDC `Secret` (`T19.1`) and
  notification channels (`T19.4`) are each read through a *namespaced* `Api<Secret>` in the
  controller's `--namespace`, and the shipped RBAC is a namespaced `Role` — a `Secret` a team creates
  in its own namespace is invisible to the controller by design, so it can never be a credential a
  restored control plane needs. Recording it would invent a restore dependency (and fail a restore
  over a `Secret` FerrisCD would never read). Restoring `team-a`'s `Application`s therefore needs
  `ferriscd-system`'s credentials, and that is what a bundle for `team-a` records. `--namespace`
  narrows the *objects*, never this list.
* `Secret`s FerrisCD never reads through the API — the chart's `webhooks.existingSecret`, which is
  mounted into the pod as an environment variable — are not inventoried: there is no labelled object
  to verify. Restore them by re-creating the `Secret` or re-applying the chart values.

Bundle anatomy:

```yaml
schemaVersion: ferriscd.io/backup/v1
exportedAt: "2026-11-28T09:13:25Z"
tool: ferriscd/0.1.0
controlPlaneNamespace: ferriscd-system
resources: [ ... ]   # ConfigMap -> AppProject -> ApplicationSet -> Application, then namespace/name
secrets: [ ... ]     # names, ferriscd.io/* labels and key names only
integrity:
  algorithm: sha256
  digest: sha256:<64 hex>   # over the canonical rendering of the restorable content
```

Ordering and the digest are deterministic, so a bundle committed to a DR repository produces clean
diffs. The digest detects corruption and accidental edits (the file is also parsed under the YAML
budgets — duplicate keys, alias bombs, depth and node limits — and is capped at 8 MiB / 1 000 items),
but it is **not** a signature: anyone who can rewrite the bundle can recompute it. Encrypt or sign it
out of band when it leaves your control (`age -r <recipient>`, `cosign sign-blob`, or `git-crypt`).

**Future extension — `--encrypt-secrets-with-age <pubkey>`.** Not implemented in this version: the
bundle carries no secret *values*, so encryption is not needed for confidentiality. What it would
protect is the inventory itself — the names and key shapes of a cluster's credentials — and it is
tracked as an additive flag, not a format change (an encrypted bundle would be a separate document
the restore detects and unwraps). Until then, the out-of-band options above are the answer.

### 8.2 Export

```bash
# Whole control plane; --output writes a 0600 file (stdout is the default sink)
ferriscd backup export --output ferriscd-dr-$(date -u +%Y%m%dT%H%M%SZ).yaml

# One namespace: bounded bundles for a fleet larger than the 1 000-item ceiling
ferriscd backup export --namespace payments --control-plane-namespace ferriscd-system \
  --output payments-dr.yaml
```

The summary goes to stderr (`exported N resource(s) … and M secret stub(s) [sha256:…]`), so a bundle
written to stdout stays a clean YAML document. `--output` writes the bundle atomically with mode
`0600` and refuses a path that is a symbolic link: the file names your cluster's credentials, so it
is never world-readable (it is created `0600` and renamed into place, so there is no window in which
it is `0644`) and never written through a link into some other file. The write is not `fsync`ed — a
power loss straight after the command can leave the previous bundle instead of the new one — so push
the bundle to your DR repository (or `sync`) before you rely on it.

**Clean diffs in a DR repository.** The only line in a bundle that changes between two exports of an
unchanged control plane is `exportedAt` (the integrity digest covers the restorable content and is
deliberately independent of the timestamp). `--exported-at <RFC3339>` pins it:

```bash
# Re-export with the timestamp the committed bundle already carries: no diff means no change.
stamp=$(yq -r '.exportedAt' ferriscd-dr.yaml)   # or grep '^exportedAt:' and strip the key
ferriscd backup export --exported-at "$stamp" --output ferriscd-dr.yaml
git -C ferriscd-dr diff --exit-code             # 0 = the live control plane still matches the bundle
```

Export then re-parses the rendered document through the very function `restore` starts with
(`parse_bundle`: the same YAML budgets, size/item ceilings, schema version and integrity digest) and
refuses to write a bundle that does not round-trip to the same content — so this tool cannot hand you
a file `parse_bundle` rejects.

**Credential inventory scope.** The inventory is the set of credentials a restored control plane will
consume, and FerrisCD consumes exactly four labelled types — `repository`, `cluster`, `oidc`,
`notifications` — from the control-plane namespace only (see §8.1). A whole-cluster export and a
`--namespace payments` export therefore record the *same* credentials: the ones in
`--control-plane-namespace`. Set it to the controller's `--namespace` (a single-tenant install that
runs the controller with `-n team-a` keeps its credentials there).

**RBAC / `--skip-secret-inventory`.** Export lists the labelled `Secret`s (`list` on `secrets`, in
`--control-plane-namespace` only — the same namespaced grant the controller already needs) purely to
record their shape. If the exporting identity may not list `Secret`s there, `export` fails with that
explanation instead of silently producing a bundle whose credentials cannot be verified on restore.
`--skip-secret-inventory` is the explicit opt-out, for when credentials are restored out of band.

### 8.3 Restore

```bash
# 1. Preview: parse + integrity check + namespace/credential pre-flight + SSA dry run (dryRun=All).
ferriscd backup restore payments-dr.yaml --dry-run

# 2. Restore: ConfigMaps -> AppProjects -> ApplicationSets -> Applications, force: false.
ferriscd backup restore payments-dr.yaml
```

* **Idempotent.** Server-Side Apply under the dedicated `ferriscd-backup` field manager compares
  ownership and values, so restoring the same bundle twice neither bumps `metadata.generation` nor
  re-creates anything.
* **Conflict policy.** `--on-conflict=abort` (default) stops at the first `409` field-ownership
  conflict and names the object; `--on-conflict=skip` reports it and continues with the rest of the
  bundle. A restore **never** forces (`force: false`, the `AGENTS.md` SSA default): a field another
  manager owns is resolved there — re-apply from its source of truth (Git/Helm), delete the object
  first, or restore into a clean namespace. A restore is not a transaction: objects applied before
  the conflict are left in place, and re-running the bundle afterwards completes it (each apply is
  idempotent).
* **Dependency order** is what the bundle is written in and what the restore re-derives: the policy
  `ConfigMap`s before the `AppProject`s that configure authorization, an `AppProject` before the
  `Application`s that name it, an `ApplicationSet` before the fleet it regenerates.
* **Pre-flight, before anything is written.** Missing namespaces fail the restore (create them
  first). Missing `ferriscd.io/secret-type=*` `Secret`s fail it too and are named individually —
  recreate them from your secret store, or stage the restore with `--allow-missing-secrets` (the
  affected `Application`s stay `Ready=False` until the credential exists; the flag prints a warning
  naming every credential it did not find, so a staged restore never hides a missing credential). A
  changed `secret-type` label or a missing data key is a warning, and so is an identity that may
  restore the control plane but not read credentials ("could not verify …", restore continues).
* **Bundle-supplied names are validated.** `metadata.name`/`metadata.namespace` (and the secret
  inventory's) must be DNS-1123 names before any request is built, so a hand-edited or hostile bundle
  cannot steer a restore's request path; the refusal names the item's position and kind, never the
  offending string.
* **What a restore does *not* create.** `Application`s generated by an `ApplicationSet` are listed
  under `generatedApplications` and left out: their owner reference points at a uid a restore cannot
  reproduce, so the `ApplicationSet` regenerates the fleet. The summary line reports that count, and
  a note follows when it is non-zero — a restore that silently omitted them would read as "everything
  came back".

### 8.4 Quarterly DR drill (verified procedure)

```bash
kubectl config use-context kind-ferriscd-dr        # never a production cluster
kubectl apply --server-side -f deploy/crds/
kubectl wait --for=condition=Established --timeout=60s \
  crd/applications.ferriscd.io crd/appprojects.ferriscd.io crd/applicationsets.ferriscd.io
kubectl create namespace ferriscd-system

ferriscd backup restore ferriscd-dr.yaml --dry-run   # expect: "would apply (dry run)" per object
ferriscd backup restore ferriscd-dr.yaml             # expect: "applied: <kind>/<ns>/<name>" per object
# recreate the credential Secrets from your secret store, then start FerrisCD and compare:
ferriscd app list --output table
```

`tests/integration/v2_0_upgrade_soak.rs` automates this story against `kind`
(`a_backup_bundle_round_trips_through_a_disaster_recovery_restore`): export, `--dry-run`, real
restore after losing the objects, an idempotent re-restore, and the missing-credential refusal.

---

## 9. Zero-Downtime Major-Version Upgrade (`v1.0` → `v2.0`)

A `v2.0` upgrade changes two things: the **CRD schemas** (additive only — `spec.source.oci`,
`spec.sources`, `AppProject.spec.syncWindows`/`policyRules`, plus the new
`applicationsets.ferriscd.io`) and the **control-plane image**. Follow the order; neither step is
destructive, but doing them in the wrong order invalidates objects.

### 9.1 Pre-flight

```bash
# 1. Drill it on a disposable cluster (the live suite performs exactly these steps).
make kind-up
cargo test -p ferriscd-cli --test v2_0_upgrade_soak -- --ignored

# 2. Take a DR bundle: the schema change is additive, but a pre-upgrade snapshot is free.
ferriscd backup export --output pre-v2.0-$(date -u +%Y%m%dT%H%M%SZ).yaml

# 3. Record the pre-upgrade state so a post-upgrade difference is attributable.
ferriscd app list --output table
kubectl -n <app-namespace> get pods -o custom-columns=\
  NAME:.metadata.name,UID:.metadata.uid,RESTARTS:.status.containerStatuses[0].restartCount
```

The two `#[ignore]`d tests in that file serialise themselves on a process-global mutex, so no
`--test-threads` flag is needed (and `make test-integration`, which runs
`cargo test --workspace -- --ignored`, passes none).

`make gate` proves the offline half of the same claim: `crates/ferriscd-crd/tests/schema_compat.rs`
diffs the frozen `v1.0` CRD manifests (`crates/ferriscd-crd/tests/fixtures/v1_0/`) against the
committed `v2.0` ones and fails on any removed field, narrowed enum or newly required property.

> **What the automated suite does *not* exercise: the Helm chart path.**
> `tests/integration/v2_0_upgrade_soak.rs` performs the steps a `helm upgrade` performs — CRDs via
> Server-Side Apply first, then the control-plane rollout — because this repository has no published
> `v1.0` image to pull and a live suite must not depend on a registry network. The chart itself is
> covered only by CI's static checks (`helm lint` for the default and `values-ha.yaml` profiles,
> `helm template` for its rendered objects, and a `diff` proving `deploy/helm/ferriscd/crds/*` equals
> `deploy/crds/*`). Nothing automated renders-and-installs the chart on a cluster, so the readiness
> probe wiring, `maxSurge`/`maxUnavailable`, RBAC and NetworkPolicy behaviour of §9.2 are a
> **reviewed-by-hand procedure**: run it on a disposable cluster (or a staging one) before a
> production major-version upgrade.

### 9.2 CRDs first, then the control plane

Helm never upgrades CRDs inside `crds/` on `helm upgrade`, so apply them explicitly **first**: an old
CRD with a new controller would reject `spec.sources` and `spec.source.oci`.

```bash
# 1. Server-Side Apply the v2.0 CRDs and wait for them to establish.
kubectl diff --server-side -f deploy/crds/          # review: additions only
kubectl apply --server-side -f deploy/crds/
kubectl wait --for=condition=Established --timeout=60s \
  crd/applications.ferriscd.io crd/appprojects.ferriscd.io crd/applicationsets.ferriscd.io

# 2. Upgrade the release (RollingUpdate with maxSurge=1 keeps one pod serving at all times).
helm upgrade ferriscd deploy/helm/ferriscd \
  -n ferriscd-system \
  -f deploy/helm/ferriscd/values-ha.yaml \
  --set image.tag=v2.0.0 --set web.image.tag=v2.0.0

# 3. Watch the rollout.
kubectl -n ferriscd-system rollout status deployment/ferriscd --timeout=300s
kubectl -n ferriscd-system get pods -w -l app.kubernetes.io/name=ferriscd
```

`/readyz` is the rollout gate (`T17.1`): a cold pod answers `503` with
`{"status":"not ready","reason":"waiting for initial control-plane readiness: …"}` until the
`Application` watches, the cluster-registry seed and the initial `ferriscd-rbac-cm` load complete,
and `200` afterwards. With a `/readyz` readiness probe, Kubernetes adds the new pod to the Service —
and only then terminates the old one — so a rollout cannot route traffic to an uninitialized
replica.

### 9.3 Verify zero disruption

```bash
# Managed workload pods: same uid, same age, restartCount still 0.
kubectl -n <app-namespace> get pods -o custom-columns=\
  NAME:.metadata.name,AGE:.metadata.creationTimestamp,RESTARTS:.status.containerStatuses[0].restartCount

# status.inventory intact, apps still Synced/Healthy.
ferriscd app list --output table
ferriscd app get <app-name> -n ferriscd-system

# No unexpected re-create: the managed objects' uids are unchanged.
kubectl -n <app-namespace> get configmaps,deployments -o custom-columns=\
  KIND:.kind,NAME:.metadata.name,UID:.metadata.uid
```

The live suite asserts exactly these: `0` managed-workload pod restarts, `0` re-created
`ConfigMap`/`Deployment` objects, unchanged `status.inventory` and `status.history` across a soak of
two full `requeueAfterSeconds` periods, the new instance's `503` → `200` readiness gate while the old
one kept answering `200`, and a queued sync operation consumed by the rolled instance afterwards.

### 9.4 If something goes wrong

1. **Image regression:** `helm rollback ferriscd -n ferriscd-system`. The CRDs stay as they are — every
   `v2.0` schema change is additive, and a `v1.0` controller ignores the new optional fields.
2. **An `Application` stops converging:** fix its spec (or restore the pre-upgrade bundle, §8). Do
   **not** delete the object: `ferriscd.io/tracking-id` ownership is what keeps the workloads on the
   cluster, and re-creating the CR would orphan them.
3. **Control plane cannot run at all:** restore the pre-upgrade bundle on the installed CRDs
   (`ferriscd backup restore pre-v2.0-*.yaml`); both schemas accept its objects.

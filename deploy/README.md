# FerrisCD deployment notes

This directory holds the manifests an operator applies **before** the controller can reconcile
anything:

| Path | What it is |
|---|---|
| `crds/applications.ferriscd.io.yaml` | `Application` CRD (`ferriscd.io/v1alpha1`) |
| `crds/appprojects.ferriscd.io.yaml` | `AppProject` CRD — the multi-tenancy boundary (`T12.1`) |
| `crds/applicationsets.ferriscd.io.yaml` | `ApplicationSet` CRD — opt-in fleet generation (`T19.3`, `--enable-applicationsets`) |
| `manifests/default-project.yaml` | the permissive single-tenant `default` project every `Application` falls back to |
| `kind-config.yaml` | local development cluster definition (`make kind-up`) |

Both CRDs must be installed. A cluster that does not serve `AppProject` cannot reconcile
anything: project lookups are **never** treated as permissive, and the failure names
`deploy/crds/appprojects.ferriscd.io.yaml` instead of pretending the project is missing
(finding M3).

---

## Controller `ClusterRole`

The controller authenticates as its own ServiceAccount. Everything below is required by the
code that ships today (Phases 06–12); the last block is only needed once you turn
Apps-in-any-namespace on.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ferriscd-controller
rules:
  # --- Application lifecycle (control-plane namespace) ------------------------------
  - apiGroups: ["ferriscd.io"]
    resources: ["applications"]
    verbs: ["get", "list", "watch", "patch"]
  - apiGroups: ["ferriscd.io"]
    resources: ["applications/status"]
    verbs: ["get", "patch", "update"]
  - apiGroups: ["ferriscd.io"]
    resources: ["applications/finalizers"]
    verbs: ["update"]

  # --- AppProject policy (read-only; `get` per reconcile, never a cluster-wide watch)
  - apiGroups: ["ferriscd.io"]
    resources: ["appprojects"]
    verbs: ["get"]

  # --- Kubernetes Events (`T15.2`) --------------------------------------------------
  # Rate-limited `Normal SyncSucceeded`, `Normal ResourcePruned` and `Warning SyncFailed`
  # events attached to each `Application` (`kubectl describe application`).
  - apiGroups: ["events.k8s.io"]
    resources: ["events"]
    verbs: ["create", "patch", "get", "list"]

  # --- The workloads the Applications declare (`T06`–`T08`) -------------------------
  # Enumerated on purpose. Do NOT write `apiGroups: ["*"] / resources: ["*"]` here: that also
  # grants `secrets` **cluster-wide**, which is precisely the grant the repository-credential
  # section below forbids. Enumerate the GroupKinds your Applications actually declare and
  # extend the list as you add kinds.
  #
  # With impersonation on (`T12.3`), the workload verbs are used *by the impersonated tenant
  # ServiceAccount*, not by this ClusterRole: the rules below therefore only have to cover the
  # Applications that keep the controller's identity (the control-plane ones). Grant each tenant
  # ServiceAccount its own, narrower `Role` in its destination namespace.
  - apiGroups: [""]
    resources:
      - configmaps
      - services
      - serviceaccounts
      - persistentvolumeclaims
      - namespaces         # only when a project whitelists `Namespace` (namespace pruning is opt-in)
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "networkpolicies"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["apiextensions.k8s.io"]
    resources: ["customresourcedefinitions"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]


  # --- Apps-in-any-namespace + ServiceAccount impersonation (`T12.2`, `T12.3`) ------
  # `impersonate` is what lets the controller act as a tenant's ServiceAccount. It must be
  # granted on `users` AND `groups`: Kubernetes authorizes groups, so a `RoleBinding` that
  # names `system:serviceaccounts:<ns>` only applies if the groups are impersonated too.
  - apiGroups: [""]
    resources: ["users", "groups"]
    verbs: ["impersonate"]
  # Impersonating `system:serviceaccount:<ns>:<name>` is additionally checked against
  # `serviceaccounts` in the *destination* namespace.
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["impersonate"]
```

> **`secrets` is deliberately absent from that `ClusterRole`.** A wildcard
> `apiGroups: ["*"] / resources: ["*"]` rule — the shape earlier drafts of this file shipped —
> grants `get`/`list` on **every `Secret` in the cluster**, which contradicts
> `ferriscd.io/secret-type=repository` being read from one namespace (below). If the manifests your
> Applications declare contain `Secret`s, use one of these instead, and never a cluster-wide
> `secrets` rule:
>
> 1. **Impersonated tenants (recommended).** Give each tenant `ServiceAccount` a namespaced `Role`
>    with `secrets` verbs in its *destination* namespace; the apply runs as that identity, so the
>    controller's own role never needs `secrets`.
> 2. **Control-plane Applications.** Bind a namespaced `Role` with `secrets` verbs in each
>    destination namespace the project allows, to the controller's `ServiceAccount` — never a
>    `ClusterRole` rule, and never `clusterRole`-wide `get`.

### Repository credential Secrets (`T12.4`) — namespaced, never cluster-wide

Git credentials (HTTPS tokens/basic auth and SSH deploy keys) live in `Secret`s labeled
`ferriscd.io/secret-type=repository` **in the control-plane namespace only**. The controller holds a
*namespaced* `Api<Secret>`, so every read is a label-filtered list inside that one namespace; it
can never observe a `Secret` anywhere else, and it never asks for cluster-wide `Secret` RBAC.

Grant exactly this, and nothing wider:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ferriscd-repository-credentials
  namespace: ferriscd-system          # the control-plane namespace, never another one
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    # `get`/`list` cover the scoped read the controller performs; `watch` is what a future
    # informer-based store would need and costs nothing to grant now.
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ferriscd-repository-credentials
  namespace: ferriscd-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ferriscd-repository-credentials
subjects:
  - kind: ServiceAccount
    name: ferriscd-controller
    namespace: ferriscd-system
```

Do **not** add `secrets` to the controller's `ClusterRole`, and do not bind this `Role` across
namespaces: a `Secret` a tenant writes in its own namespace must never become a credential FerrisCD
uses (that is the whole point of scoping it to `ferriscd-system`).

#### What a credential `Secret` looks like

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: repo-git-example-com
  namespace: ferriscd-system
  labels:
    ferriscd.io/secret-type: repository
stringData:
  url: https://git.example.com        # exact URL, or a prefix (longest prefix wins)
  username: ferriscd-bot              # optional (basic auth)
  token: ghp_…                        # or `password:`; `username` + `token` = basic auth w/ token
```

| Key | Meaning |
|---|---|
| `url` | repository URL or prefix. `https://` and `ssh://` only (SCP-style `git@host:org/repo` is accepted and normalized to `ssh://`). Plaintext `http://` is refused. |
| `username`, `password` | HTTPS basic auth. `username` + `token` is the GitHub/GitLab "user + PAT" form. |
| `token` | HTTPS bearer/PAT (sent as basic auth with the token as the user, which is what the hosts expect). |
| `sshPrivateKey`, `knownHosts` | SSH deploy key. The key **must be unencrypted** (no passphrase is read); `knownHosts` is required unless the controller explicitly allows missing host keys (test/dev only). |

Matching is predictable: the **whole normalized URL is lowercased — the path included** — one
trailing `.git` and trailing slashes are ignored, userinfo is dropped (so
`git@github.com:org/repo.git` and `ssh://github.com/org/repo` are the same repository), the default
port is ignored, an exact match beats any prefix, and a prefix only matches on a path boundary
(`https://git.example.com/org` does not match `https://git.example.com/organization/repo`).
Lowercasing the path is deliberate: Git hosting paths are conventionally case-insensitive, and it
means one `Secret` covers one repository even when a URL is copied with different casing. The cost
is documented rather than hidden — on a self-hosted server that *does* distinguish `/Org/Repo` from
`/org/repo`, both are treated as the same repository (and therefore use the same credential). A URL that matches nothing is cloned **anonymously**;
a `Secret` that cannot be used (no `url`, ambiguous `password`+`token`, an SSH key on an `https://`
URL, two `Secret`s claiming the same URL) is a **terminal** `Ready=False` error naming the `Secret`
— never a silent fallback.

Credential values never reach the logs or `Application.status`: the `Secret` name and the
credential *kind* are logged, the values are not, and repository URLs are quoted through the shared
redaction helper (`https://robot:***@host/...`).

### Remote clusters (`T13.1`) — Secret-registered, namespaced, TLS-verified

A cluster an operator registers with a `Secret` is a *destination*: an `Application` names it in
`spec.destination.cluster`, and the controller applies, diffs, prunes and cascades **over that
cluster's own client and API discovery**. `in-cluster` always means the control plane's own client
and needs no `Secret`.

Cluster `Secret`s are read from the control-plane namespace only, through a **namespaced**
`Api<Secret>` watch filtered by `ferriscd.io/secret-type=cluster` — the same rule the repository
credentials follow. Never grant `secrets` cluster-wide for this.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ferriscd-cluster-registry
  namespace: ferriscd-system          # the control-plane namespace, never another one
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
  # `T13.2`: the leader-election Lease lives in the same namespace.
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "create", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ferriscd-cluster-registry
  namespace: ferriscd-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ferriscd-cluster-registry
subjects:
  - kind: ServiceAccount
    name: ferriscd-controller
    namespace: ferriscd-system
```

#### What a cluster `Secret` looks like

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: workload-prod               # the cluster name `spec.destination.cluster` refers to
  namespace: ferriscd-system
  labels:
    ferriscd.io/secret-type: cluster
stringData:
  server: https://10.0.0.10:6443    # required unless a full `kubeconfig` is supplied
  ca.crt: |                         # optional: the CA the API server certificate must chain to
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  bearerToken: eyJhbGciOi…          # or: tls.crt + tls.key (client certificate), or kubeconfig
```

| Key | Meaning |
|---|---|
| `server` | absolute `https://` API server URL. Plaintext `http://` is refused unless the controller was started with the local-dev opt-in. |
| `ca.crt` | CA bundle (PEM). Optional for a publicly-trusted endpoint; parsed strictly, so a placeholder is rejected at seed time. |
| `bearerToken` | static bearer token. |
| `tls.crt`, `tls.key` | client certificate + **unencrypted** private key (PEM). |
| `kubeconfig` | a complete kubeconfig document. Mutually exclusive with the explicit keys. `exec`, `auth-provider`, `proxy-url`, `tokenFile` and every certificate *path* field are refused: whoever can write this `Secret` must not be able to make the controller run a binary or read a pod file. |
| `name` | optional cluster-name override (defaults to the `Secret`'s name). `in-cluster` is reserved and cannot be registered. |
| `insecureSkipTLSVerify` | `"true"` disables verification. Refused unless the controller runs with `--allow-insecure-cluster-tls` (local development only). |

Changing a `Secret` rebuilds that cluster's client (its connector and every cached impersonated
client are replaced); deleting it removes the cluster, and any `Application` still targeting it
fails **terminally** with `Ready=False, reason=InvalidSpec` naming the missing registration. A
`Secret` that becomes unusable (a rotated credential with a typo) invalidates the previous client
instead of keeping the revoked credential alive.

#### Credentials *on* the remote cluster

The controller authenticates to the remote cluster **as the `Secret`'s credential**, then
impersonates `spec.serviceAccountName` there exactly as it does in-cluster, with the remote
cluster's own connector (one connector per cluster, shared by every identity on it). The remote
credential therefore needs:

* the `impersonate` verbs (`users`, `groups`, `serviceaccounts`) the control plane's `ClusterRole`
  has, and
* the workload verbs the project's `destinations` allow (or, with impersonation, nothing beyond
  `impersonate` — the ServiceAccount's own RBAC bounds the deploy).

`Application.status` and the `ferriscd.io/finalizer` always stay on the **control plane**: the
remote credential is never asked to write a FerrisCD CR the remote cluster may not even serve.

If the cluster `Secret` is deleted while an `Application` with `ferriscd.io/cascade-delete: "true"`
is terminating, there is nothing left to delete with: the finalizer is **released with a warning**
(`reason=CleanupSkipped`) rather than wedging the object in `Terminating` (finding C5). Recreate the
`Secret` (with the same name and a working credential) and the cascade runs on the next reconcile if
the object has not been deleted yet.

`spec.destination.cluster` is still checked against `AppProject.spec.destinations` **before** the
registry is consulted, so a tenant cannot use an `Application` to probe which clusters exist.

### HA: `Lease` leader election (`T13.2`) — opt-in

By default the controller runs as a single replica: run exactly one. Two replicas without leader
election both reconcile the same objects (double applies, racing prunes).

`--leader-election` makes every replica an active/standby candidate over a
`coordination.k8s.io/v1` `Lease` (`ferriscd-controller-leader` in the control-plane namespace):

```text
ferriscd controller --leader-election   --leader-election-lease-name ferriscd-controller-leader   --leader-election-lease-duration-seconds 15   --leader-election-renew-interval-seconds 4
```

* Only the holder reconciles; a standby waits and takes over when the lease expires (a `SIGKILL`ed
  leader is replaced within `leaseDurationSeconds` + a retry interval).
* The renewal is an optimistic-concurrency write on `resourceVersion`, so a stale leader can never
  overwrite the current holder: it re-reads, sees a different holder, and stops.
* Losing the lease cancels reconciliation immediately (in-flight passes drain like a `SIGTERM`).
* On `SIGTERM` the leader **releases** the lease (holder cleared, duration 1 s), so the standby takes
  over at once instead of waiting out the full duration.
* `--leader-election-renew-interval-seconds` must be strictly less than a third of
  `--leader-election-lease-duration-seconds`, otherwise the controller refuses to start (a
  configuration that would make a healthy leader oscillate).
* **Control-plane nodes need NTP (or equivalent) time sync.** Lease expiry compares the leader's
  `renewTime` against local elapsed time, so a standby only takes over correctly while the replicas'
  clocks stay within a few seconds of each other — a large skew either delays failover or, worse,
  hands the lease to a standby while the old leader still believes it holds it. Keep the nodes on the
  same time source (`chrony`/`systemd-timesyncd`, or the cloud provider's clock service) and raise
  `--leader-election-lease-duration-seconds` above the skew you are prepared to tolerate.

The lease needs no extra `ClusterRole` rule: it is namespaced in `ferriscd-system`, so the
`ferriscd-cluster-registry` `Role` above covers it.

### Sharding: deterministic `Application` partitioning (`T13.3`) — opt-in

Leader election keeps every replica but one **idle**. At large scale that single active leader is the
bottleneck. `--shard-id`/`--total-shards` partition the `Application`s instead: replica `i` of `N`
reconciles only the objects whose

```text
shard = sha256(namespace, name) % total-shards
```

is `i` — computed locally from the object's own identity, so every replica agrees without a
coordinator and no restart ever reshuffles ownership.

```text
# three replicas, each with its own shard and its own leader Lease
ferriscd controller --leader-election --shard-id 0 --total-shards 3
ferriscd controller --leader-election --shard-id 1 --total-shards 3
ferriscd controller --leader-election --shard-id 2 --total-shards 3
```

`FERRISCD_SHARD_ID` and `FERRISCD_TOTAL_SHARDS` are read when the flags are absent, which is what a
`StatefulSet` needs (its pods already have a stable ordinal). The `apps.kubernetes.io/pod-index`
label is the ordinal as a string, which is exactly what the environment variable expects:

```yaml
kind: StatefulSet
spec:
  replicas: 3
  serviceName: ferriscd-controller
  podManagementPolicy: Parallel      # every shard should start at once, not one at a time
  template:
    spec:
      containers:
        - name: ferriscd
          command: ["ferriscd", "controller", "--leader-election"]
          env:
            - name: FERRISCD_SHARD_ID                # "0", "1", "2"
              valueFrom:
                fieldRef:
                  fieldPath: metadata.labels['apps.kubernetes.io/pod-index']
            - name: FERRISCD_TOTAL_SHARDS
              value: "3"
```

Rules the controller enforces at startup (it refuses to run otherwise):

* **Sharding reduces apply work, not watch load.** Every replica still lists/watches every
  `Application` it is configured to see and stores them (only the reconcile queue is filtered), so
  API-server list/watch traffic and memory scale with replica count, not with `1/N`. Size the API
  server and memory for the full object set per replica; use sharding to spread reconciliation and
  apply work, not to partition the watch.
* **Sharding requires `--leader-election`, and always uses a per-shard `Lease`**
  (`ferriscd-leader-shard-<id>`). Two replicas started with the same `--shard-id` would both reconcile
  that shard — the double apply the lease exists to prevent — so they compete for that shard's lease
  instead, and only one of them leads it.
* **`--shard-id` and `--total-shards` go together**, `--shard-id` must be `< --total-shards`, and
  `--total-shards` must be `>= 1`. A half-specified pair is an error, never a default: a default
  would silently put the whole fleet in one shard (or in a shard nobody owns).
* **`--leader-election-lease-name` is refused together with `--shard-id`.** One shared `Lease` would
  make exactly one replica a leader and leave every other shard unreconciled while its replicas stand
  by — a *silent* loss of coverage, which is why the combination cannot be configured rather than
  merely being discouraged.

Operational notes:

* Every replica must use the **same** `--total-shards`; shard indexes must be **unique**. Reusing an
  index costs a standby (safe, wasteful); changing `--total-shards` on one replica only costs
  *coverage* (the Applications that replica used to own are now owned by nobody), so the shard count
  belongs in the same place as the replica count — one templated value, not a per-pod knob.
* Sharding is a *capacity* decision, not a rebalancing algorithm. Changing `N` re-partitions every
  `Application` on the next watch event of every replica: that is safe (each object still has exactly
  one owner, and `ferriscd.io/tracking-id` ownership is unchanged) but it is a fleet-wide restart, and
  in-flight reconciles on a shrinking shard are drained like a rolling update.
* Shards do **not** partition `AppProject`s, cluster registrations or repository credentials: those
  stay shared, read-on-demand lookups in the control-plane namespace, so the RBAC above is unchanged
  (every per-shard `Lease` is namespaced in `ferriscd-system`, and the `leases` rule covers all of
  them).
* Nothing changes for the `Application`s themselves: each one is still reconciled, status-patched and
  finalized by exactly one owner, and a shard reads `status.inventory` written by a previous owner
  without special casing. A sharded replica also still *stores* every object its watches list (only
  the queue is filtered), so readiness and inventory reads do not depend on the shard count.
* Turning sharding on or off is a **stop-then-start**, never a rolling update: a sharded replica
  leads `ferriscd-leader-shard-<id>` while an unsharded one leads `ferriscd-controller-leader`, and
  neither `Lease` excludes the other, so overlapping replicas reconcile the same `Application`s
  twice (double applies, racing prunes). Scale the old configuration to zero (or release its lease)
  before starting the other. The same applies to changing `--total-shards`/`--shard-id` on a running
  fleet.

### Prometheus metrics (`T15.1`) — its **own** port, low cardinality

`ferriscd` serves `GET /metrics` on a **dedicated internal listener**. That listener is never on the API/webhook port:
`ferriscd server` refuses a `--metrics-addr` on the `--api-addr` port (any address), and the API router
(`/api/v1/*`, `/healthz`, `/readyz`, `/webhooks/*`) contains no metrics route at all: Prometheus
needs no bearer token, and a scraper's network has access to nothing else.

| Knob | Default | Notes |
|---|---|---|
| `--metrics-addr` | `0.0.0.0:9090` | `HOST:PORT`. `FERRISCD_METRICS_ADDR` is the env fallback (prefer it over the flag in a manifest). |
| `:0` | — | binds an ephemeral port and logs the real one (tests/local use). |
| path | `/metrics` | classic Prometheus text (`text/plain; version=0.0.4`). |

`0.0.0.0:9090` is the default because Prometheus scrapes the **pod IP**; a loopback default would
ship an endpoint nobody can scrape. The exposition holds application names and statuses only — no
`Secret` value, diff or token — and `--metrics-addr 127.0.0.1:9090` (or a `NetworkPolicy` allowing
port 9090 only from the monitoring namespace) narrows it if your platform requires that.

```yaml
# prometheus.yml (or a ServiceMonitor selecting the controller's pods)
scrape_configs:
  - job_name: ferriscd
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      # Publish a `metrics` container port (containerPort 9090) in the pod template, then keep the
      # pods that expose it.
      - source_labels: [__meta_kubernetes_pod_container_port_number]
        regex: "9090"
        action: keep
    metrics_path: /metrics
```

Exposed families — and nothing else:

| Family | Type | Labels |
|---|---|---|
| `ferriscd_reconcile_duration_seconds` | histogram | `result` = `success` \| `retryable` \| `terminal` |
| `ferriscd_reconcile_total` | counter | `result` (same three values) |
| `ferriscd_app_sync_status` | gauge | `app_namespace`, `app_name`, `status` = `Synced` \| `OutOfSync` \| `Unknown` |
| `ferriscd_app_health_status` | gauge | `app_namespace`, `app_name`, `status` = `Healthy` \| `Progressing` \| `Degraded` \| `Suspended` \| `Missing` \| `Unknown` |
| `ferriscd_git_fetch_duration_seconds` | histogram | *(none)* |
| `ferriscd_render_cache_total` | counter | `outcome` = `hit` \| `miss` |
| `ferriscd_active_reconciles` | gauge | *(none)* |
| `ferriscd_rbac_reload_total` | counter | `outcome` = `ok` \| `error` \| `deleted` |
| `ferriscd_rbac_watch_errors_total` | counter | *(none)* |
| `ferriscd_audit_events_total` | counter | `category` = `api.operation` \| `api.authz_denied` \| `webhook.delivery` \| `controller.impersonation` \| `cluster.registry`, `outcome` = `allowed` \| `denied` \| `accepted` \| `failed` |
| `ferriscd_audit_dropped_total` | counter | *(none)* — one per `try_send` drop, one per failed JSONL write/flush, one per event in a rejected/failed webhook batch, and one per timed-out sink flush (the exact backlog is unknown after the channel closes) |

Operational notes:

* **Cardinality is fixed by construction.** No `commit_sha`, `error_message`, repository URL or
  resource name is ever a label — the `result`/`status`/`outcome` values come from closed enums and
  the only free-form labels are the `Application`'s own `metadata.namespace`/`metadata.name`. Series
  therefore grow with the number of `Application`s, never with commits, failures, resources or
  scrapes. The two per-`Application` families exist **after a pass has observed that
  `Application`** (a status nobody observed is never invented); the other nine are exported from
  startup with zero values, so a "no data yet" alert does not fire on a fresh pod.
* **Prometheus scraping fails loudly if the listener dies.** The metrics server is an independent
  Tokio task, and its failure cancels the controller's own shutdown path instead of leaving a
  reconciling process with a dead endpoint.
* **Render-cache counters are the engine's**, bridged by delta: `ferriscd_render_cache_total` is
  `RenderCache::stats()`'s `hits`/`misses`, so it can never disagree with the cache.
* `--metrics-addr` reaches the controller through `ferriscd server` too (the controller flags are
  flattened into `ferriscd server`), so both entrypoints expose the same surface.

### OpenTelemetry OTLP tracing & Kubernetes Events (`T15.2`)

* **OpenTelemetry OTLP traces (opt-in):** set `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g.
  `http://otel-collector.monitoring:4318`) and optionally `OTEL_SERVICE_NAME` (default
  `ferriscd-controller`). When `OTEL_EXPORTER_OTLP_ENDPOINT` is unset or blank, zero OTLP exporter
  or background thread is constructed. Spans cover `reconcile`, `git_fetch`, `manifest_render`,
  `live_state_fetch`, `diff_evaluate`, and `sync_execute`, never carrying Secret payloads or raw
  credentials; any credentials embedded in an OTLP URL are redacted from logs and errors, and
  buffered spans flush on graceful shutdown.
* **Rate-limited Kubernetes Events (`events.k8s.io/v1`):** the controller emits
  `Normal SyncSucceeded` (on settled sync execution, not on no-op `SyncSkipped` passes),
  `Normal ResourcePruned` (summarizing pruned GKNN keys without secret data), and
  `Warning SyncFailed` (redacted and bounded to Kubernetes's 1 KiB note limit). Identical
  consecutive `Warning` reasons for the same `Application` are deduplicated within a 5-minute
  window in front of `kube::runtime::events::Recorder` so a failing app cannot spam `etcd`;
  publishing errors are logged as warnings and never fail reconciliation. Grant
  `apiGroups: ["events.k8s.io"], resources: ["events"], verbs: ["create", "patch", "get", "list"]` (included in
  the `ClusterRole` above).

### Ownership labels for the opt-in drift watcher (`T18.1`)

Under Model 1 a `DriftWatcher` (opt-in, `--enable-drift-watcher`) can only be *label*-scoped: the
Kubernetes API server cannot filter a watch on annotations. `--enable-drift-watcher`
(`FERRISCD_ENABLE_DRIFT_WATCHER`, default `false`) therefore also stamps two bounded top-level
labels onto every **non-hook** managed resource, alongside the existing
`ferriscd.io/tracking-id` annotation:

| Label | Value | Why |
|---|---|---|
| `ferriscd.io/managed-by` | `ferriscd` | the server-side selector (`ferriscd.io/managed-by=ferriscd`) so unmanaged objects never cross the wire |
| `ferriscd.io/app-hash` | 16 lowercase hex characters | first 16 hex chars (64 bits) of `SHA-256("<app-namespace>/<app-name>")` — identifies the owning `Application` without a 253-character name overflowing the **63-character** label-value limit, and without `ns-a/app` colliding with `ns-b/app` (Finding M5) |

Operational notes:

* **The env value is exactly `true` or `false`.** `FERRISCD_ENABLE_DRIFT_WATCHER` is parsed as a
  bool, not tested for truthiness: unset (or the flag absent) means **off**, and any other value —
  including the empty string and `1`/`yes`/`True` — is a **usage error** that stops the controller at
  startup instead of silently leaving the labels off. In the Helm chart there is no dedicated value;
  wire it through `server.extraArgs: ["--enable-drift-watcher"]` or
  `server.extraEnv: [{name: FERRISCD_ENABLE_DRIFT_WATCHER, value: "true"}]`, which
  `templates/deployment.yaml` passes straight to the `ferriscd` container.
* **Off by default, and additive when on.** With the flag off the apply body is unchanged (the
  annotation only). Turning it on adds the pair; turning it back off removes nothing from the
  desired body and the next sync's Server-Side Apply converges the two labels away — one no-op diff
  per resource, never a drift loop.
* **Never in an immutable selector.** The labels go on the object's own `metadata.labels` only.
  `spec.selector.matchLabels` and `spec.template.metadata.labels` are untouched: they are immutable
  on `Deployment`/`StatefulSet`/`DaemonSet`, so writing there would fail every later apply with
  `422 Immutable`.
* **Lifecycle hooks are never stamped.** A stamped hook would look prunable to the pruner even
  though its lifetime belongs to its `ferriscd.io/hook-delete-policy`.
* **No extra RBAC is needed for the labels themselves** — they ride on objects the controller
  already applies. (The metadata watch a future `DriftWatcher` runs needs
  `get`/`list`/`watch` on the resource kinds it watches; that is its own opt-in grant.)
* **Cluster lifecycle is broadcast internally.** `ClusterManager` publishes `Added`, `Rebuilt` and
  `Removed` events on a bounded (64) channel for `ferriscd.io/secret-type=cluster` secrets —
  including a cluster whose `Secret` vanished while the watch was reconnecting, which Kubernetes
  never reports as a delete. A subscriber that falls behind is told so (`Lagged`) and resynchronises
  against the registry's live name set; the registry never waits for a consumer.

### `ApplicationSet` controller (`T19.3`) — opt-in, namespaced grants

`--enable-applicationsets` (`FERRISCD_ENABLE_APPLICATIONSETS`, default `false`) starts an
independent loop that turns `ApplicationSet` objects (`ferriscd.io/v1alpha1`, `kubectl get appset`)
into ordinary `Application`s **in the `ApplicationSet`'s own namespace** — the control-plane
namespace — passing every one of them through the same `AppProject` policy as a hand-authored
`Application`.

Nothing is granted for it by default: the shipped Role in `deploy/manifests/rbac.yaml` keeps the
opt-in rules commented out, and the Helm chart gates them behind `rbac.applicationsets: false`. Add
exactly these three rules (control-plane namespace only) before turning the flag on:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ferriscd-applicationsets
  namespace: ferriscd-system
rules:
  # `patch` (not `update`): the finalizer is set and cleared with a merge patch on
  # `metadata.finalizers` of the ApplicationSet object itself. The `applicationsets/finalizers`
  # subresource is never used, so granting it would be a permission nothing needs.
  - apiGroups: ["ferriscd.io"]
    resources: ["applicationsets"]
    verbs: ["get", "list", "watch", "patch"]
  # `/status` is patched on every pass (`Ready`, `observedGeneration`, `generatedCount`).
  - apiGroups: ["ferriscd.io"]
    resources: ["applicationsets/status"]
    verbs: ["get", "patch", "update"]
  # Server-Side Apply on the generated Applications: `patch` for an existing object, `create`
  # for a new one. Never `update` (SSA does not use it).
  - apiGroups: ["ferriscd.io"]
    resources: ["applications"]
    verbs: ["get", "list", "watch", "patch", "create"]
```

**`delete` is a second, separate opt-in (`rbac.applicationsetPrune`).** The two verbs above are
everything a *non-destructive* `ApplicationSet` needs. Two features do delete generated
`Application`s, and each is opt-in per object: `spec.syncPolicy.prune: true` (drop the Applications
a generator no longer produces) and `spec.syncPolicy.preserveResourcesOnDeletion: false` (delete
them when the `ApplicationSet` itself is deleted). Add `delete` to the `applications` rule **only**
if some `ApplicationSet` sets one of them:

```yaml
  - apiGroups: ["ferriscd.io"]
    resources: ["applications"]
    verbs: ["get", "list", "watch", "patch", "create", "delete"]
```

With Helm, that is `rbac.applicationsets: true` plus `rbac.applicationsetPrune: true` (both default
`false`: the chart widens the `applications` grant — and only that rule — when the second is on).
The Kustomize manifest keeps the `delete`-bearing rule commented out for the same reason: it is a
namespace-wide grant, so it applies to *every* `ApplicationSet` in the control-plane namespace, not
just the one that opted in.

With Kustomize, patch the shipped Role instead of adding a second one:

```yaml
patches:
  - target:
      kind: Role
      name: ferriscd
    patch: |-
      - op: add
        path: /rules/-
        value:
          apiGroups: ["ferriscd.io"]
          resources: ["applicationsets"]
          verbs: ["get", "list", "watch", "patch"]
      - op: add
        path: /rules/-
        value:
          apiGroups: ["ferriscd.io"]
          resources: ["applicationsets/status"]
          verbs: ["get", "patch", "update"]
      - op: add
        path: /rules/-
        value:
          apiGroups: ["ferriscd.io"]
          resources: ["applications"]
          verbs: ["get", "list", "watch", "patch", "create"]
```

Operational notes:

* **The `clusters` generator never yields `in-cluster`.** The reserved pseudo-cluster is not a
  registration `Secret`, so it is not a generator parameter: an `ApplicationSet` that wants a
  control-plane `Application` writes it in the template instead of relying on a cluster match.
* **Deletion is non-destructive by default.** Deleting an `ApplicationSet` *orphans* the generated
  `Application`s (their `ownerReference` is dropped, the objects and their workloads stay) unless
  `spec.syncPolicy.preserveResourcesOnDeletion: false`. Pruning a stale generated `Application` is
  separately opt-in (`spec.syncPolicy.prune: true`).
* **Turning the flag off with `ApplicationSet`s in place wedges their deletion.** The controller
  adds `ferriscd.io/applicationset-cleanup` to every `ApplicationSet` it manages; if the feature is
  disabled afterwards, nothing runs that finalizer, so deleting an `ApplicationSet` leaves it
  `Terminating` and its generated `Application`s owned. Re-enable the flag (the finalizer then runs
  and orphans them) or remove the finalizer by hand
  (`kubectl patch applicationset <name> --type=merge -p '{"metadata":{"finalizers":null}}'`).
* **Changes are event-driven, not timer-driven.** A cluster registration appearing/changing/
  disappearing (`T18.1` broadcast) or a generated `Application` being created/edited/deleted
  re-runs the pass immediately; `spec.requeueAfterSeconds` (default 180) and the 10-minute re-list
  are backstops, not the reaction time.

### Multi-tenancy RBAC matrix

| Controller verb (`T12.2`/`T12.3`) | Why | Scope |
|---|---|---|
| `applications` `get`, `list`, `watch` | one `Controller`/watcher/store per `--application-namespaces` entry (a merged store would let one namespace's `InitDone` truncate the others) | one entry per tenant namespace; **cluster-wide** when the flag is `*` |
| `applications` `patch` | the rollback path removes `spec.syncPolicy.automated` and consumes `ferriscd.io/operation` (`T10.5`) | the tenant namespaces |
| `applications/status` `patch`, `update` | always-update-status: `/status` is patched on success **and** failure (trap T3) | the tenant namespaces |
| `applications/finalizers` `update` | the finalizer helper adds/removes `ferriscd.io/finalizer` **on the object it was handed**, which lives in the tenant namespace (`T12.2`) | the tenant namespaces |
| `applications` `get`, `patch` on a *deleting* object | a cascade cleanup re-reads the project and the tracked objects before deleting anything (finding H1) | the tenant namespaces |
| `appprojects` `get` | one scoped read per reconcile, from the control-plane namespace (`T12.1`) | the control-plane namespace |
| `users`, `groups` `impersonate` | `Impersonate-User` + the three `Impersonate-Group` headers (`T12.3`, finding H5) | cluster-scoped (impersonation is not namespaced) |
| `serviceaccounts` `impersonate` | Kubernetes checks the impersonated `system:serviceaccount:<ns>:<name>` against this resource | the destination namespaces |
| `secrets` `get`, `list`, `watch` | repository credential `Secret`s (`T12.4`); granted through a namespaced `Role`/`RoleBinding`, **never** a `ClusterRole` rule | the control-plane namespace only |
| workload verbs | the actual applies/diffs/prunes, now executed as the tenant's ServiceAccount | whatever the project's `destinations` allow |

Notes that matter operationally:

* **`system:masters` is never impersonated.** The group set is exactly
  `system:serviceaccounts`, `system:serviceaccounts:<destination namespace>` and
  `system:authenticated`, and the code refuses `system:masters` outright (trap T12). Granting
  the controller `impersonate` on `users`/`groups` lets it become *those* ServiceAccounts — so
  keep `AppProject.spec.allowedServiceAccounts` curated, and never allow `*` in a shared
  cluster.
* **A tenant `Application` without `spec.serviceAccountName` is refused** with
  `Ready=False, reason=PolicyViolation`; it is never deployed with the controller's identity.
* **The project allow-lists remain the boundary.** Impersonation narrows what a tenant *can* do;
  it does not authorize anything. An empty `spec.destinations`, `spec.sourceNamespaces`,
  `spec.allowedServiceAccounts`, or `spec.clusterResourceWhitelist` permits nothing
  (finding M2). Only `namespaceResourceWhitelist` is "empty means everything", matching Argo CD.
* **The `Application` object itself stays on the controller's identity** for `/status` and the
  finalizer: the tenant's ServiceAccount must not need RBAC on the `Application` CR (it usually
  only has RBAC in its destination namespace), while the controller must always be able to
  record what happened.
* **A cascade never runs as an unauthorized identity.** Deleting an `Application` with
  `ferriscd.io/cascade-delete: "true"` re-checks `AppProject.spec.allowedServiceAccounts` before
  the ServiceAccount is resolved (finding H1): a tenant that retargets `spec.serviceAccountName`
  and then deletes the object is refused, and nothing is deleted.
* **The tenant finalizer can wedge, on purpose.** If a tenant `Application` is deleted while it
  references a `ServiceAccount` the project no longer allows (or the `AppProject` itself is gone,
  or the `ServiceAccount` is refused as invalid), the reconcile fails with
  `Ready=False, reason=PolicyViolation` and the `ferriscd.io/finalizer` is **retained** — deleting
  with an identity no project authorized is the privilege escalation this phase exists to prevent,
  so the safe direction is to keep the object rather than to guess. The remedies are, in order:
  re-add the ServiceAccount to `spec.allowedServiceAccounts` (or recreate the project); set
  `spec.serviceAccountName` to an allowed account; or, to abandon the cascade entirely, annotate
  the object with `ferriscd.io/force-delete: "true"` — the finalizer is then released **without
  pruning**, and any managed objects must be removed by hand. `kubectl describe application` shows
  the reason and the offending name.
* **Remote clusters (`T13.1`)** need the same `impersonate` rules on their own credentials; each
  cluster has its own pool that builds one connector and reuses it for every ServiceAccount (no
  connector per reconcile, trap T12 / finding H5). At most 64 impersonated clients are cached per
  cluster (finding M2): the cache key is `(destination namespace, ServiceAccount)`, so it is
  bounded rather than tenant-controlled, and a miss rebuilds a middleware stack over the same
  connector.
* **Repository credentials are controller-side only.** They are read from `ferriscd-system` under
  the controller's own identity, *before* a clone, and are never copied into a tenant namespace,
  an `Application`, or a `status` field — so a tenant's RBAC on its destination namespaces never
  includes the token, and a tenant cannot read another tenant's credential.

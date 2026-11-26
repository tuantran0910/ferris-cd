# Lesson 16 — Packaging, Hardening, OpenAPI Codegen & Production GitOps

> Building a GitOps engine that passes unit tests is only half of `v1.0`. The other half is
> shipping it so a platform team can actually run it under Kubernetes's `restricted`
> PodSecurityStandard, inspect live diffs and resource topologies in a strictly typed Web UI, lock
> down egress against cloud metadata SSRF, and operate it through upgrades, outages, and failovers.
> Phase 16 completes `v1.0` with a TypeScript/React 19 dashboard generated directly from Rust
> OpenAPI 3.1 contracts (`T16.1`–`T16.4`), hardened non-root read-only containers (`T16.5`), a
> least-privilege Helm chart and Kustomize overlay (`T16.6`), and an operations runbook and release
> pipeline (`T16.7`).
>
> Code:
> * `apps/ferriscd-web/` · `docs/api/openapi.json`
> * `Dockerfile` · `apps/ferriscd-web/Dockerfile` · `apps/ferriscd-web/nginx.conf`
> * `deploy/helm/ferriscd/` · `deploy/manifests/`
> * `docs/operations/RUNBOOK.md` · `.github/workflows/release.yml`
>
> Verification status:
> * **Hermetic / offline CI:** Verified via `npm run generate-api && git diff --exit-code src/api/schema.d.ts`, `npm run typecheck && npm run test && npm run build`, `helm lint`, `helm template` + `kustomize build` security assertions in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), and YAML validation of [`.github/workflows/release.yml`](../../.github/workflows/release.yml).
> * **Live `kind` walkthrough:** Section 5 provides the exact reproducible `kind` commands against the real `Dockerfile`, `apps/ferriscd-web/Dockerfile`, and `deploy/helm/ferriscd` chart.

---

## 1. OpenAPI 3.1-Driven Rust-to-TypeScript Workflows (`T16.1`–`T16.4`)

Most full-stack infrastructure tools suffer from **schema drift**: a Rust backend renames a field
from `syncStatus` to `sync_status` or adds a `FieldConflict` enum variant, and the TypeScript UI
quietly renders `undefined` in production because hand-maintained `interface` files never noticed.

FerrisCD eliminates schema drift with a strict, one-way contract pipeline while keeping Cargo and
Node builds completely decoupled:

```text
Rust types (`crates/ferriscd-server/src/api.rs`, #[derive(utoipa::ToSchema)])
   │
   ▼  cargo run -p ferriscd-cli -- server openapi
Committed OpenAPI 3.1 contract (`docs/api/openapi.json`)
   │
   ▼  cd apps/ferriscd-web && npm run generate-api  (openapi-typescript)
Generated TypeScript definitions (`apps/ferriscd-web/src/api/schema.d.ts`)
   │
   ▼  createClient<paths>()  (openapi-fetch in apps/ferriscd-web/src/api/client.ts)
React 19 + TanStack Query v5 + React Flow UI (compile-time path, param & payload safety)
```

### Key architectural decisions in `apps/ferriscd-web`

1. **Zero Cargo-to-Vite coupling:** Cargo never shells out to `npm`, and Vite never invokes `cargo`.
   Instead, [`docs/api/openapi.json`](../api/openapi.json) is the frozen interface boundary checked
   on both sides:
   * Rust side: `ferriscd server openapi --check` fails if Rust handler/DTO changes diverge from
     `docs/api/openapi.json`.
   * Frontend side: CI runs `npm run generate-api && git diff --exit-code src/api/schema.d.ts`,
     followed by `npm run typecheck && npm run test && npm run build`.
2. **Typed `openapi-fetch` middleware (`apps/ferriscd-web/src/api/client.ts`):** Every API call
   (such as `raw.GET("/api/v1/applications/{namespace}/{name}/diff", ...)`) is statically checked
   against `paths` in `schema.d.ts`. Bearer tokens are injected in request middleware from
   memory/`sessionStorage` — **never** passed in URL query strings (which leak into Nginx access
   logs, browser history, and `Referer` headers) — and `401` responses trigger automatic session
   invalidation.
3. **Orthogonal UX invariants preserved in the UI:**
   * **Sync Status ≠ Health Status (`T16.2`):** The overview grid and detail pages render Sync
     (`Synced`, `OutOfSync`, `Unknown`) and Health (`Healthy`, `Progressing`, `Degraded`,
     `Suspended`, `Missing`, `Unknown`) as two distinct badges.
   * **Graph + Table dual view (`T16.3`):** The interactive `@xyflow/react` + `dagre` resource
     topology graph automatically pairs with a searchable Resource Table View so applications with
     100+ resources remain fast and navigable.
   * **Server-redacted diffs & RBAC-aware controls (`T16.4`):** The diff viewer renders the
     `DiffView` payload already redacted by `ferriscd-server` (`***REDACTED(...)***`), and action
     modals (Sync / Rollback) gracefully handle `403 Forbidden` for read-only identities and warn
     explicitly that Rollback pauses `spec.syncPolicy.automated`.

---

## 2. Hardened Non-Root Read-Only Containers & Finding C6 (`T16.5`)

### Why bare distroless breaks `gix` SSH transport (Finding C6)

A common container-hardening reflex for Rust binaries is `FROM gcr.io/distroless/static-debian12:nonroot`.
For FerrisCD, bare distroless fails on real production GitOps repositories for **three** concrete
reasons:

1. **`gix` delegates SSH transport to `ssh`:** While `gix` speaks HTTPS natively in Rust via
   `reqwest` + `rustls`, its SSH transport invokes the system `openssh-client` binary (`ssh`) using
   an ephemeral `0600` key file and strict `known_hosts` verification (`T02.3`). Without
   `openssh-client`, every `git@github.com:org/repo.git` or `ssh://` source fails.
2. **OpenSSH requires an `/etc/passwd` entry for UID `65532`:** Even when a container runs as
   `USER 65532:65532`, OpenSSH calls `getpwuid(geteuid())` at startup and aborts with
   `No user exists for uid 65532` if `/etc/passwd` lacks a matching record.
3. **External manifest renderers (`helm` v4 and `kustomize` v5):** FerrisCD invokes `helm` and
   `kustomize` inside `SandboxedCommand` (`env_clear()`, explicit `PATH`, bounded stdout/stderr,
   timeouts — Lesson 11).

### How [`Dockerfile`](../../Dockerfile) solves Finding C6 under `restricted` PodSecurityStandard

[`Dockerfile`](../../Dockerfile) uses a 3-stage multi-architecture build:

| Stage | Base | Responsibility |
|---|---|---|
| `builder` | `rust:1.100-slim-bookworm` | Compiles `ferriscd` (`cargo build --release --locked -p ferriscd-cli`) with cached third-party dependency layer and strips the binary |
| `tools` | `debian:bookworm-slim` | Downloads pinned `helm` (`v4.3.2`) and `kustomize` (`v5.8.3`) for `TARGETARCH` (`amd64`/`arm64`) and **verifies official SHA-256 digests** via `sha256sum -c` before installing |
| `runtime` | `debian:bookworm-slim` | Installs **only** `ca-certificates` and `openssh-client`; creates system user `ferriscd` (`UID/GID 65532`, home `/tmp`, shell `/usr/sbin/nologin`); copies `ferriscd`, `helm`, and `kustomize` as `root:root` `0755` |

All mutable runtime paths (`HOME`, `TMPDIR`, `XDG_*_HOME`, `HELM_*_HOME`, `--work-root /tmp/ferriscd-repos`)
point exclusively under `/tmp`, backed by a size-bounded Kubernetes `emptyDir` (`persistence.tmpSizeLimit: 1Gi`).
At image build time, the final `RUN` check executes as `USER 65532:65532` and asserts `getent passwd 65532`,
`ssh -V`, `helm version`, `kustomize version`, and `ferriscd --version`.

### Hardened static Web UI image ([`apps/ferriscd-web/Dockerfile`](../../apps/ferriscd-web/Dockerfile))

The dashboard ships as a separate minimal container (`node:24-alpine` -> `nginx/nginx-unprivileged:1.30-alpine`):

* Runs as non-root `UID/GID 65532` listening on unprivileged port `8080`.
* Sets `automountServiceAccountToken: false` in Kubernetes ([`deploy/helm/ferriscd/templates/web-deployment.yaml`](../../deploy/helm/ferriscd/templates/web-deployment.yaml)) — the static SPA never speaks to `kube-apiserver`.
* Directs Nginx `pid` and all temporary buffers to `/tmp/nginx/` (creating `/tmp/nginx` at startup
  so a freshly mounted Kubernetes `emptyDir` at `/tmp` works seamlessly with `readOnlyRootFilesystem: true`).
* Emits strict HTTP security headers (`Content-Security-Policy`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`) on every
  location block in [`apps/ferriscd-web/nginx.conf`](../../apps/ferriscd-web/nginx.conf) (because
  Nginx does **not** inherit parent `add_header` directives into child blocks that define their own
  `add_header`).

---

## 3. Kubernetes `NetworkPolicy` Egress Hardening & The Omitted `to:` Trap (`T16.6`)

A `NetworkPolicy` with `policyTypes: [Ingress, Egress]` flips a pod from allow-all to
**default-deny**. Writing egress rules cleanly for a GitOps controller has two subtle Kubernetes
traps that routinely weaken production clusters:

### Trap 1: Omitting `to:` disables IMDS (`169.254.169.254/32`) blocking

In Kubernetes `networking.k8s.io/v1`, an egress rule containing `ports:` **without** a `to:` field:

```yaml
# DANGEROUS: omitting `to:` allows TCP/443 to EVERY destination IP,
# including cloud metadata services (169.254.169.254/32)!
egress:
  - ports:
      - protocol: TCP
        port: 443
```

Because `NetworkPolicy` egress rules are **additive (logical OR)**, a single rule omitting `to:`
overrides every `except: [169.254.169.254/32]` exclusion elsewhere in the policy! Even though
FerrisCD blocks plaintext `http://` Git remotes and Kustomize remote URLs at the application layer,
defense-in-depth demands blocking `169.254.169.254/32` at the network layer as well.

[`deploy/helm/ferriscd/templates/networkpolicy.yaml`](../../deploy/helm/ferriscd/templates/networkpolicy.yaml)
and [`deploy/manifests/networkpolicy.yaml`](../../deploy/manifests/networkpolicy.yaml) therefore:

1. **Never omit `to:`** on any egress rule (enforced automatically by Ruby assertions in
   [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)).
2. Always include `except: ["169.254.169.254/32"]` whenever `cidr: 0.0.0.0/0` is used as a portable
   default across `kind`/EKS/GKE/AKS.
3. Expose explicit CIDR pin lists (`networkPolicy.egress.kubeApi.cidrs`,
   `networkPolicy.egress.gitHttps.cidrs`, `networkPolicy.egress.gitSsh.cidrs`) for hardened
   clusters.

### Trap 2: Port 443 overlap between `kubeApi` and `gitHttps`

Kubernetes API servers are commonly reached via ClusterIP `10.96.0.1:443` (pre-DNAT) or node IP
`:6443` (post-DNAT, depending on the CNI). Because `kubeApi.ports` defaults to `[443, 6443]`,
pinning `gitHttps.cidrs` alone while leaving `kubeApi.cidrs: []` still leaves TCP/443 open to
`0.0.0.0/0` (minus IMDS) through the `kubeApi` rule! In hardened production clusters, pin **both**
`networkPolicy.egress.kubeApi.cidrs` and `networkPolicy.egress.gitHttps.cidrs` (or restrict
`kubeApi.ports` to `[6443]` on post-DNAT CNIs).

---

## 4. Least-Privilege Helm & Kustomize Packaging (`T16.6`)

Both installation paths — the Helm chart ([`deploy/helm/ferriscd/`](../../deploy/helm/ferriscd/))
and the Kustomize overlay ([`deploy/manifests/`](../../deploy/manifests/)) — share strict security
invariants verified on every pull request in CI:

| Invariant | Default Setting | How CI Enforces It |
|---|---|---|
| No `*/*` wildcard RBAC | Enumerated workload GroupKinds in `rbac.workloadRules` | `ci.yml` aborts if any `ClusterRole` rule has `apiGroups: ["*"]` + `resources: ["*"]` |
| No cluster-wide `secrets` RBAC | `secrets` (`get/list/watch`) exists **only** in the control-plane namespace `Role` | `ci.yml` aborts if `secrets` appears in any `ClusterRole` |
| Opt-in `impersonate`, CRD writes, RBAC writes | `rbac.impersonation.enabled: false`, `rbac.manageCrds: false`, `rbac.manageRbacResources: false` | `ci.yml` aborts if default `ClusterRole` grants `impersonate`, `rbac.authorization.k8s.io`, or non-read CRD verbs |
| Default-deny REST API RBAC | `ferriscd-rbac-cm` renders `rules: []` until operator configures `rbacPolicy.rules` | `helm template` test verifies both empty default and explicit rule rendering |
| Automatic RBAC reload on Helm upgrade | `checksum/rbac-policy` pod template annotation triggers rolling restart when `ferriscd-rbac-cm` changes | Rendered by `templates/deployment.yaml` |
| CRD byte-for-byte sync | `deploy/crds/` == `deploy/helm/ferriscd/crds/` == `deploy/manifests/crds/` | `diff -u` gate in `ci.yml` + `ferriscd crd generate --check` in `make gate` |
| Sharding + custom Lease conflict guard | `sharding.enabled: true` forbids `leaderElection.leaseName` | `helm template` negative test in `ci.yml` asserts render failure |

---

## 5. Hands-On `kind` Experiment: Build, Harden & Deploy via Helm

This experiment builds both hardened images locally, loads them into a fresh `kind` cluster,
enforces Kubernetes `restricted` PodSecurity Admission on `ferriscd-system`, installs the production
Helm chart, and authenticates with `ferriscd login`.

> **Safety guard:** Always confirm `kubectl config current-context` starts with `kind-` before
> applying anything.

```bash
# 1. Start (or reuse) the local Kubernetes v1.35.8 kind cluster and verify context
make kind-up
kubectl config current-context | grep -q '^kind-'

# 2. Build both hardened non-root, read-only images locally
docker build -t ghcr.io/ferriscd/ferriscd:1.0.0 .
docker build -t ghcr.io/ferriscd/ferriscd-web:1.0.0 apps/ferriscd-web

# 3. Load both images directly into the kind node (no registry push needed)
kind load docker-image ghcr.io/ferriscd/ferriscd:1.0.0 --name ferriscd-dev
kind load docker-image ghcr.io/ferriscd/ferriscd-web:1.0.0 --name ferriscd-dev

# 4. Pre-create `ferriscd-system` with Kubernetes `restricted` PodSecurity Admission enforced
kubectl create namespace ferriscd-system --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace ferriscd-system \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

# 5. Install FerrisCD via the production Helm chart with an explicit admin RBAC grant
helm install ferriscd deploy/helm/ferriscd \
  -n ferriscd-system --create-namespace \
  --set 'rbacPolicy.rules[0].subject.kind=user' \
  --set 'rbacPolicy.rules[0].subject.name=system:serviceaccount:ferriscd-system:ferriscd-admin' \
  --set 'rbacPolicy.rules[0].project=*' \
  --set 'rbacPolicy.rules[0].actions[0]=admin'

# 6. Verify both Deployments roll out cleanly under `restricted` PSA and `readOnlyRootFilesystem: true`
kubectl -n ferriscd-system rollout status deployment/ferriscd
kubectl -n ferriscd-system rollout status deployment/ferriscd-web

# Confirm read-only rootfs and UID 65532 inside the running control-plane pod
kubectl -n ferriscd-system exec deploy/ferriscd -- sh -c \
  'id && getent passwd 65532 && touch /should-fail 2>&1 || true'

# 7. Mint a short-lived ServiceAccount token and authenticate with `ferriscd`
kubectl -n ferriscd-system create serviceaccount ferriscd-admin --dry-run=client -o yaml | kubectl apply -f -
kubectl -n ferriscd-system create token ferriscd-admin --duration=1h > /tmp/ferriscd-admin.token
chmod 0600 /tmp/ferriscd-admin.token

# Forward API (:8080) and Web UI (:5173 -> svc:80)
kubectl -n ferriscd-system port-forward svc/ferriscd 8080:8080 &
PF_API=$!
kubectl -n ferriscd-system port-forward svc/ferriscd-web 5173:80 &
PF_WEB=$!

# Verify health probes and CLI login via TokenReview
curl -sf http://127.0.0.1:8080/healthz && echo ""
cargo run -q -p ferriscd-cli -- login http://127.0.0.1:8080 --token-file /tmp/ferriscd-admin.token
cargo run -q -p ferriscd-cli -- project list
cargo run -q -p ferriscd-cli -- cluster list
cargo run -q -p ferriscd-cli -- app list

# Clean up local port-forwards and token file when finished
kill "$PF_API" "$PF_WEB"
rm -f /tmp/ferriscd-admin.token
```

### What to observe

1. `kubectl -n ferriscd-system exec deploy/ferriscd -- ...` prints `uid=65532(ferriscd)`, resolves
   `/etc/passwd` cleanly for OpenSSH, and fails `touch /should-fail` with `Read-only file system`.
2. `ferriscd-web` pods have **no** mounted ServiceAccount token (`automountServiceAccountToken: false`).
3. `ferriscd login` validates the projected Kubernetes token via `TokenReview` (`POST authentication.k8s.io/v1/tokenreviews`) and `ferriscd project list` enforces `ferriscd-rbac-cm`.

---

## 6. Operating GitOps in Production

Shipping `v1.0` shifts focus from "does it reconcile?" to Day-2 operational reliability:

* **High Availability:** Deploy with [`deploy/helm/ferriscd/values-ha.yaml`](../../deploy/helm/ferriscd/values-ha.yaml)
  (`replicaCount: 2`, `leaderElection.enabled: true`, `podDisruptionBudget.enabled: true`,
  anti-affinity + hostname topology spread). Keep control-plane node clocks NTP-synchronized.
* **CRD upgrades:** Helm intentionally does not overwrite `crds/` during `helm upgrade`. Always
  apply `deploy/crds/` via Server-Side Apply before running `helm upgrade`.
* **Day-2 runbook:** See [`docs/operations/RUNBOOK.md`](../operations/RUNBOOK.md) for copy-pasteable
  procedures covering stuck finalizers, SSA `409 FieldConflict` brownfield adoption, Rollback
  recovery, HA Lease failover & sharding stop-then-start migration, Prometheus/OTLP triage, and
  webhook/AuthN/RBAC diagnostics.
* **Automated `v1.0` releases:** Tagging `v*.*.*` triggers [`.github/workflows/release.yml`](../../.github/workflows/release.yml),
  building native multi-arch Rust binaries (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `aarch64-apple-darwin`), multi-arch GHCR container images (`linux/amd64,linux/arm64`) for both
  control-plane and web UI, and a packaged Helm chart with `SHA256SUMS.txt`.

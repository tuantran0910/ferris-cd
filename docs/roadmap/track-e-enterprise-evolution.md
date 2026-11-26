# Track E: Enterprise Evolution & Production Maturity (Phases 17–20)

> **Milestones:** `v1.1` (Phase 17) → `v1.2` (Phase 18) → `v1.3` (Phase 19) → `v2.0` (Phase 20)  
> **Scope:** 4 Phases · 18 Atomic Tasks (`T17.1`–`T20.5`) · 4 Phase Lessons (`docs/lessons/17-*`–`20-*`)  
> **Back to:** [ROADMAP.md](../ROADMAP.md) · [MASTER_PLAN.md](../MASTER_PLAN.md) · [post-v1-backlog.md](../design/post-v1-backlog.md) · [REVIEW_LOG.md](../REVIEW_LOG.md)

---

## Scope Guard & Architectural Continuity

FerrisCD `v1.0` (`Phases 01–16`, 83 atomic tasks) remains **strictly frozen and untouched** so `v1.0` packaging, Helm chart, and live `kind` verification ship cleanly without scope creep. **Track E** defines the post-`v1.0` enterprise evolution roadmap from `v1.1` through `v2.0`, closing concrete `v1.0` audit follow-ups first and then layering opt-in enterprise capabilities onto existing Rust seams and wire-compatible `ferriscd.io/v1alpha1` CRD schemas **without breaking upgrades or conversion webhooks**.

Every task in Track E MUST preserve all hard FerrisCD invariants (`AGENTS.md`):
- **Modular monolith (5 crates):** Keep `ferriscd-crd`, `ferriscd-engine`, `ferriscd-controller`, `ferriscd-server`, `ferriscd-cli` (no crate fragmentation).
- **`k8s-openapi` version-feature hygiene:** Never enable `k8s-openapi` version features (`v1_35`) in library crates (`ferriscd-crd`, `ferriscd-engine`).
- **Zero runtime panics & async hygiene:** No `unwrap()`/`expect()`/`panic!` in runtime code; run all blocking `gix`/OCI/archive/disk/crypto work inside `tokio::task::spawn_blocking`; never sleep/block reconcile workers (persist state and requeue).
- **GitOps & SSA safety:** Version-agnostic GKNN keys; crash-safe inventory `(prev \ pruned_ok) ∪ applied_ok`; `serverSideForce: false` default; Secret/credential redaction across `Debug`/`Display`/errors/logs/diffs/audit/notifications.

### Classification Legend

- **Priority Tiers:**
  - `Production Blocker` — Closes real `v1.0` operational, security, or supply-chain gaps required before tier-1 regulated production adoption.
  - `Essential Improvement` — High-leverage operator experience, governance, reliability, and disaster-recovery capabilities expected in production GitOps platforms.
  - `Strategic Capability` — Major opt-in platform features expanding FerrisCD's addressable enterprise use cases (real-time drift, OCI, OIDC, ApplicationSets, Notifications, Multi-Source, Policy-as-Code).
  - `Optional Enhancement` — Ecosystem-specific opt-in integrations for advanced progressive-delivery adopters.
- **Enterprise Workstreams (8):** `Core Product Capabilities` · `UI/UX & Design System` · `Architecture & Engineering Excellence` · `Security & Governance` · `Reliability & Performance` · `Enterprise Capabilities` · `Integrations & Extensibility` · `Developer & Operator Experience`.

---

## Phase 17: Production Hardening, Live Governance & Enterprise Web UI — *Milestone `v1.1`*

**Phase Goal:** Close all concrete Phase 14/15 review follow-ups (controller-backed `/readyz`, live-reloading YAML-budgeted RBAC, project-scoped clusters), add immutable compliance audit logging, deliver the missing enterprise Web UI surfaces (`Projects`, `Clusters`, `Events`, WCAG 2.2 AA accessibility, optional SSE), enforce `AppProject` sync windows, and lock down supply-chain security (`cargo-deny`, SBOM, SLSA, Cosign).  
**Knowledge Base Lesson (`docs/lessons/17-production-hardening-live-governance-and-supply-chain.md`):** Watch-backed Kubernetes readiness probes, atomic hot-reloading of security policies with fail-closed rollback, structured compliance audit trails, timezone-safe cron sync windows, and SLSA/Cosign release attestation.  
**Hands-On `kind` Experiment:** Deploy `v1.1` on `kind`, update `ferriscd-rbac-cm` live via `kubectl apply` and observe immediate `403 -> 200` authorization transition without pod restart; trigger a deny sync window on `AppProject/payments`, confirm automated sync defers cleanly while authorized manual override succeeds, and inspect the emitted JSON audit log trail.

---

### `T17.1` — Controller-Backed `/readyz` Probe & Live-Reloading Guarded RBAC

- **Priority & Workstream:** `Production Blocker` · `Architecture & Engineering Excellence` / `Security & Governance`
- **Problem Statement & User/Business Value:**
  - Today in `crates/ferriscd-server/src/api.rs:566` (`readyz`, `TODO(T15.x)`), `/readyz` is wired to `crate::state::ServingReadiness`, which unconditionally returns `200 OK` before `ApplicationControllers::wait_until_ready()`, the `ClusterManager` initial `Secret` seed, and the initial `ferriscd-rbac-cm` load complete — causing Kubernetes Services to route traffic to cold pods before control-plane watches and cluster/RBAC state have initialized. (Note: `KubeApplicationSource` queries Kubernetes via `Api::list` rather than an informer store, and no `AppProject` watch exists, so the stale `TODO(T15.x)` doc comment at `api.rs:566` must also be cleaned up.)
  - In `crates/ferriscd-server/src/state.rs`, `AppState.rbac` is a static `Arc<RbacPolicy>` loaded once at startup (`docs/REVIEW_LOG.md` line 203–204), forcing operators to restart control-plane pods on every RBAC policy change.
  - In `crates/ferriscd-server/src/rbac.rs`, `RbacPolicy::parse` calls bare `serde_saphyr::from_str(document)` rather than `ferriscd_engine::manifest::parse_document` (`crates/ferriscd-engine/src/manifest/yaml.rs`), bypassing YAML alias-replay/depth budgets and duplicate-key rejection.
  - In `crates/ferriscd-server/src/api.rs`, `list_clusters` ignores `_identity: Extension<AuthenticatedIdentity>`, exposing every registered cluster name to any authenticated tenant (`docs/REVIEW_LOG.md` line 204).
- **Detailed Requirements:**
  - **Functional:**
    - Implement `ControlPlaneReadiness` implementing `crate::state::Readiness`, returning `false` (`503 Service Unavailable` with secret-free reason) until `ApplicationControllers::wait_until_ready()`, the `ClusterManager` initial `Secret` seed, and the initial `ferriscd-rbac-cm` load have all completed `InitDone`.
    - Replace `AppState.rbac: Arc<RbacPolicy>` with a lock-free / `RwLock`-backed `RbacPolicyStore` updated live by a namespaced `Api<ConfigMap>` watch on `ferriscd-rbac-cm` in `ferriscd-system`.
    - Route `RbacPolicy::parse` through `ferriscd_engine::manifest::parse_document` so duplicate keys and billion-laughs alias bombs are rejected without quoting policy content in errors.
    - On live reload: if the updated `ferriscd-rbac-cm` fails validation, **retain the last known-good policy** (or remain deny-all if startup never succeeded), emit a `Warning` log + increment `ferriscd_rbac_reload_total{outcome="error"}`, and never silently widen access. If `ferriscd-rbac-cm` is deleted, immediately transition to `RbacPolicy::empty()` (default-deny).
    - Scope `GET /api/v1/clusters` (`list_clusters`) to the caller's visible `AppProject` destinations: an identity sees `in-cluster` or a remote cluster name only if at least one `AppProject` for which `actor.can_see(project)` allows that cluster (or `*` / unrestricted `PassThrough`).
  - **Non-Functional:**
    - Policy reads on the HTTP request hot path must be `O(1)` atomic snapshot clones with zero lock contention across concurrent requests.
    - Readiness probe evaluation must allocate zero heap memory on the steady-state `200 OK` path and answer in `< 1 ms`.
    - Zero secrets, user names, or group names may appear in `/readyz` bodies or `RbacPolicyError` messages.
- **Outputs:**
  - `crates/ferriscd-controller/src/readiness.rs` (watch barrier / `InitDone` tracker)
  - `crates/ferriscd-server/src/rbac.rs` (guarded `parse_document` + `RbacPolicyStore` + live watcher)
  - `crates/ferriscd-server/src/state.rs` & `crates/ferriscd-server/src/api.rs` (clean up stale `TODO(T15.x)` comment at `api.rs:566`, wire `ControlPlaneReadiness`, project-scoped `list_clusters`)
  - `crates/ferriscd-controller/src/metrics.rs` (`ferriscd_rbac_reload_total{outcome}`)
- **Verification & Acceptance Criteria:**
  - Unit tests proving: (1) `ControlPlaneReadiness` flips `503 -> 200` strictly after `ApplicationControllers::wait_until_ready()`, `ClusterManager` initial `Secret` seed, and initial `ferriscd-rbac-cm` load all signal `InitDone`; (2) `RbacPolicy::parse` rejects duplicate keys and billion-laughs alias bombs without echoing group/user names; (3) invalid live `ConfigMap` update retains last-good policy while `ConfigMap` deletion flips to default-deny; (4) `GET /api/v1/clusters` hides clusters belonging exclusively to another tenant's `AppProject`.
  - Live `kind` integration test confirming `/readyz` returns `503` before `InitDone`, `200` after, and editing `ferriscd-rbac-cm` takes effect within `<= 2 s` without restarting `ferriscd server`.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** Phase 14 (`T14.1`, `T14.3`, `T14.4`), Phase 15 (`T15.1`), Phase 16 (`T16.7`).
  - **Complexity:** Medium (4–6 hours).
  - **Risks/Trade-offs:** Retaining last-good policy on malformed edit prevents accidental full-cluster lockout from a YAML typo, while deleting the ConfigMap fails closed to default-deny; document both behaviors explicitly in `docs/operations/RUNBOOK.md`.
- **Trap Guard:** Never watch `ConfigMap` cluster-wide (strictly namespaced to `CONTROL_PLANE_NAMESPACE`); never revert `list_clusters` to leak cross-tenant cluster names or cluster counts.

---

### `T17.2` — Immutable Compliance Audit Trail & Security Telemetry

- **Priority & Workstream:** `Production Blocker` · `Security & Governance` / `Enterprise Capabilities`
- **Problem Statement & User/Business Value:**
  - Regulated enterprises (SOC 2, ISO 27001, PCI-DSS) require tamper-evident, structured attribution answering *who* triggered a sync/rollback, *which* webhook delivery matched an app, *who* received `403 Forbidden`, *which* ServiceAccount was impersonated during reconcile, and *when* remote cluster credentials were added/rotated/revoked.
  - Today `ferriscd-server` and `ferriscd-controller` emit human-readable `tracing::info!` lines without a stable machine-parseable audit schema, request correlation ID, or dedicated compliance sink.
- **Detailed Requirements:**
  - **Functional:**
    - Define a versioned `AuditEvent` schema (`schemaVersion: "ferriscd.io/audit/v1"`) carrying: `timestamp` (RFC 3339 UTC), `eventId` (UUIDv4), `requestId` (propagated via `X-Request-Id`), `category` (`api.operation`, `api.authz_denied`, `webhook.delivery`, `controller.impersonation`, `cluster.registry`), `actor` (`username`, `groups`, `tokenFingerprint` 12-hex — never raw tokens), `target` (`namespace`, `name`, `project`, `cluster`), `action`, `outcome` (`allowed`, `denied`, `accepted`, `failed`), and bounded `reason`.
    - Emit audit events from: `POST .../sync`, `POST .../rollback`, RBAC `403` denials (and auth `401` with fingerprint only), GitHub/GitLab webhook matches/rejections, controller `ImpersonationPool` resolutions, and `ClusterManager` `Added`/`Rebuilt`/`Removed` events.
    - Support pluggable `AuditSink` trait with two built-in sinks: structured JSON stream (`tracing` target `ferriscd::audit` for stdout/FluentBit/Vector collection, enabled by default) and optional append-only local JSONL file sink (`--audit-log-path`, rotated externally) or async batched HTTPS webhook sink (`--audit-webhook-url`, HTTPS-only with SSRF guard).
    - Expose low-cardinality Prometheus counter `ferriscd_audit_events_total{category, outcome}` and `ferriscd_audit_dropped_total`.
  - **Non-Functional:**
    - Audit emission on external sinks must be strictly non-blocking via a bounded channel (`try_send`, capacity `1_024`) so a slow SIEM endpoint can never stall API requests or reconciliation; drops increment `ferriscd_audit_dropped_total` and log a throttled warning.
    - Zero raw `Secret` values, bearer tokens, kubeconfigs, webhook secrets, or unredacted repo URLs may ever serialize into an `AuditEvent`.
- **Outputs:**
  - `crates/ferriscd-server/src/audit.rs` (`AuditEvent`, `AuditSink`, request-ID middleware)
  - `crates/ferriscd-controller/src/audit.rs` (impersonation & cluster-registry hooks)
  - `crates/ferriscd-controller/src/metrics.rs` (audit counters)
  - `deploy/helm/ferriscd/values.yaml` (optional audit sink configuration)
- **Verification & Acceptance Criteria:**
  - Unit tests verifying schema stability (JSON snapshot), secret/token redaction across all 5 event categories, `403` vs `404` audit attribution without leaking existence to the HTTP caller, and non-blocking drop behavior when a fake sink stalls.
  - HTTP integration tests (`tower::ServiceExt::oneshot`) confirming `sync`, `rollback`, `403` denial, and valid/invalid webhook deliveries each emit exactly one correlated `AuditEvent`.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T17.1`, Phase 14 (`T14.1`–`T14.4`), Phase 15 (`T15.1`).
  - **Complexity:** Medium (4–5 hours).
  - **Risks/Trade-offs:** Strict fail-closed audit blocking would allow a SIEM outage to halt production rollbacks; therefore external sinks are non-blocking with explicit drop metrics, while stdout structured JSON (`ferriscd::audit`) remains synchronous and lossless for Kubernetes log shippers.
- **Trap Guard:** Never log `Authorization` headers, raw JWTs, `Secret.data`, or `X-Gitlab-Token` in `AuditEvent`; never turn a `404` existence-hiding response into a `403` in the HTTP response body while auditing the underlying denial internally.

---

### `T17.3` — Enterprise Web UI: Projects, Clusters, Events & Accessibility

- **Priority & Workstream:** `Essential Improvement` · `UI/UX & Design System` / `Developer & Operator Experience`
- **Problem Statement & User/Business Value:**
  - In `apps/ferriscd-web/src/App.tsx` and `apps/ferriscd-web/src/components/Layout.tsx`, the `v1.0` Web UI only renders `ApplicationsPage` (`/`) and `ApplicationDetailPage` (`/applications/:namespace/:name`).
  - Although `ferriscd-server` already exposes `GET /api/v1/projects` and `GET /api/v1/clusters` (`crates/ferriscd-server/src/api.rs` lines 1252–1291), enterprise operators have no UI visibility into tenancy boundaries (`AppProject` allowlists, destinations, allowed ServiceAccounts), registered target clusters, or Kubernetes sync/failure Events (`crates/ferriscd-controller/src/events.rs`), nor keyboard-first navigation for incident response.
- **Detailed Requirements:**
  - **Functional:**
    - Add read-only `GET /api/v1/applications/{namespace}/{name}/events` endpoint in `ferriscd-server` (RBAC `Action::Get`, bounded to the latest 50 `events.k8s.io/v1` events for that `Application`, redacting notes via existing redactor) and regenerate `docs/api/openapi.json` + `apps/ferriscd-web/src/api/schema.d.ts`.
    - Build `ProjectsPage` (`/projects`) displaying project description, `sourceRepos`, `sourceNamespaces`, `destinations`, `allowedServiceAccounts`, and active sync windows (once `T17.4` lands), with search filtering and click-through to filtered Applications.
    - Build `ClustersPage` (`/clusters`) displaying `in-cluster` and project-visible remote clusters (`T17.1`) with application counts and health rollups derived from visible applications.
    - Add an **Events Timeline** tab inside `ApplicationDetailPage` displaying `Normal`/`Warning` Kubernetes events alongside `conditions` and `history`.
    - Add an accessible **Command Palette** (`Cmd+K` / `Ctrl+K`) for jumping to Applications, Projects, Clusters, and Diff/Graph tabs, plus full WCAG 2.2 AA keyboard navigation, focus traps in modals (`SyncModal`, `RollbackModal`), skip-to-content link, ARIA live regions for status updates, and verified contrast ratios (`>= 4.5:1`).
    - Add optional Server-Sent Events (`GET /api/v1/applications/stream`, RBAC-filtered, bounded per-connection buffer, automatic fallback to TanStack Query polling) to eliminate polling lag on active dashboards.
  - **Non-Functional:**
    - Zero new runtime dependencies that bloat the Vite bundle beyond `+50 KiB` gzipped; `npm run typecheck && npm run test && npm run build` must pass cleanly.
    - Frontend remains strictly decoupled from Cargo builds and driven exclusively by the generated OpenAPI TypeScript schema.
- **Outputs:**
  - `crates/ferriscd-server/src/api.rs` (`/events` and optional `/stream` SSE endpoints) + `docs/api/openapi.json`
  - `apps/ferriscd-web/src/pages/ProjectsPage.tsx`, `apps/ferriscd-web/src/pages/ClustersPage.tsx`
  - `apps/ferriscd-web/src/components/EventsTimeline.tsx`, `apps/ferriscd-web/src/components/CommandPalette.tsx`
  - `apps/ferriscd-web/src/App.tsx`, `apps/ferriscd-web/src/components/Layout.tsx`, `apps/ferriscd-web/src/pages/ApplicationDetailPage.tsx`
- **Verification & Acceptance Criteria:**
  - Vitest + Testing Library tests for `ProjectsPage`, `ClustersPage`, `EventsTimeline`, `CommandPalette` keyboard shortcuts, modal focus-trap/Escape handling, and `axe-core` automated WCAG 2.2 AA assertions with zero critical/serious violations.
  - `ferriscd-server` oneshot tests proving `/events` enforces `404`-if-unseen / `403`-if-visible RBAC and `/stream` never emits events for unauthorized projects and cleans up on client disconnect.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T17.1`, Phase 16 (`T16.1`–`T16.4`).
  - **Complexity:** Medium-High (5–6 hours).
  - **Risks/Trade-offs:** Long-lived SSE connections behind corporate reverse proxies can drop silently; therefore the UI implements bounded exponential reconnect with automatic fallback to `refetchInterval` polling.
- **Trap Guard:** Never leak unauthorized project events over SSE or `/events`; never fetch cluster-wide Events (always scope `Api::<k8s_openapi::api::events::v1::Event>::namespaced` by `app.namespace` and `field_selector("regarding.uid=...")`); never store bearer tokens in URL query params for SSE (`EventSource` cannot set headers — use `fetch()` streaming with `Authorization: Bearer` header!).

---

### `T17.4` — Sync Windows & Deployment Governance

- **Priority & Workstream:** `Essential Improvement` · `Enterprise Capabilities` / `Core Product Capabilities`
- **Problem Statement & User/Business Value:**
  - Enterprise change-management policies prohibit automated production deploys during peak revenue hours, weekends, or change freezes while still permitting break-glass manual overrides or drift visibility.
  - `AppProjectSpec` (`crates/ferriscd-crd/src/project.rs`) currently governs *where* and *what* an application may deploy, but not *when*.
- **Detailed Requirements:**
  - **Functional:**
    - Extend `AppProjectSpec` additively (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`) with `sync_windows: Vec<SyncWindow>`:
      - `kind: SyncWindowKind` (`Allow` | `Deny`)
      - `schedule: String` (standard 5-field cron expression)
      - `duration: String` (bounded Go/ISO duration e.g. `"2h"`, `"30m"`, capped at `7d`)
      - `time_zone: Option<String>` (IANA timezone via `jiff`, defaults to `"UTC"`)
      - `applications: Vec<String>`, `namespaces: Vec<String>`, `clusters: Vec<String>` (glob filters reusing `wildcard_matches`)
      - `manual_sync: bool` (defaults to `false`: whether manual `POST .../sync` may override a deny/outside-allow window)
    - Evaluate `SyncWindow`s deterministically in `crates/ferriscd-engine/src/policy/sync_windows.rs` (pure function taking `jiff::Timestamp`, no wall-clock calls inside engine):
      - Deny window active → block sync (unless `manual_sync: true` AND sync trigger is `Manual`).
      - One or more `Allow` windows configured and none active → block sync (same manual override rule).
      - When blocked, return `SkipReason::SyncWindowDenied` in `crates/ferriscd-engine/src/diff/decision.rs`, still report accurate drift (`OutOfSync`) and health, record a `Ready=True` condition with `reason=SyncWindowActive` and the next window transition time (never flipping `Ready=False` so blocked sync windows do not spuriously trigger `T19.4`'s `on-sync-failed` notification), and requeue cleanly for the window boundary.
    - Surface active/upcoming sync windows in `ProjectView` (`GET /api/v1/projects`), `ferriscd project list` (plus optionally adding `ferriscd project get` / `GET /api/v1/projects/{name}`), and `ProjectsPage` / `SyncModal` in `apps/ferriscd-web`.
  - **Non-Functional:**
    - Invalid cron expressions or unknown IANA timezones fail closed: reject at CRD validation and introduce `AppProjectSpec::validate` (in `crates/ferriscd-crd/src/project.rs`), and treat unparseable windows at runtime as deny-all with a clear `AppProject.status.conditions` error.
    - Zero breaking change to existing `v1alpha1` `AppProject` CRs (`syncWindows` optional, omitted when empty).
- **Outputs:**
  - `crates/ferriscd-crd/src/project.rs` + regenerated `deploy/crds/appprojects.ferriscd.io.yaml`
  - `crates/ferriscd-engine/src/policy/sync_windows.rs` & `crates/ferriscd-engine/src/diff/decision.rs`
  - `crates/ferriscd-server/src/api.rs`, `crates/ferriscd-cli/src/commands/platform.rs`, `apps/ferriscd-web/src/pages/ProjectsPage.tsx`
- **Verification & Acceptance Criteria:**
  - Pure unit tests (using injected `jiff::Timestamp`, zero sleeps) covering: allow-only windows, deny-overrides-allow precedence, DST spring-forward/fall-back transitions in `America/New_York`, glob matching on apps/namespaces/clusters, `manualSync: true` vs `false`, and fail-closed invalid schedules.
  - CRD round-trip test proving `v1.0` `AppProject` YAML fixtures deserialize identically; `ferriscd crd generate --check` passes.
  - Live `kind` test proving an active deny window blocks automated sync on Git push while preserving drift reporting, and resumes automatically once the window closes.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T17.3` (UI surfacing), Phase 12 (`T12.1`).
  - **Complexity:** Medium (4–5 hours).
  - **Risks/Trade-offs:** DST transitions can skip or duplicate local times (e.g., 02:30); leveraging `jiff` (already used by `k8s-openapi`/`kube` timestamps) handles IANA tzdb transitions cleanly without pulling in a second time stack.
- **Trap Guard:** A blocked sync window must **never** prune resources, clear `lastSyncedRevision`, or suppress drift detection (`GET .../diff` still computes live drift); never evaluate wall-clock `SystemTime::now()` inside pure engine functions (always pass `now: Timestamp`).

---

### `T17.5` — Supply-Chain Security & Continuous Dependency Governance

- **Priority & Workstream:** `Production Blocker` · `Security & Governance` / `Architecture & Engineering Excellence`
- **Problem Statement & User/Business Value:**
  - Enterprise security teams will not admit a cluster-admin-adjacent GitOps controller without automated vulnerability scanning, license compliance, SBOM artifacts, and cryptographic image provenance.
  - Today `.github/workflows/ci.yml` runs formatting, clippy, and tests, but has no `cargo-deny`/`cargo-audit` gate, no frontend `npm audit` policy, and `.github/workflows/release.yml` (from `T16.7`) does not yet attach CycloneDX SBOMs, SLSA Level 3 provenance, or keyless Cosign signatures.
- **Detailed Requirements:**
  - **Functional:**
    - Add `deny.toml` enforcing Rust crate license allowlist (Apache-2.0, MIT, BSD-2/3, ISC, MPL-2.0, Zlib, Unicode-3.0), banning yanked crates, flagging RUSTSEC advisories, and restricting untrusted registries/git sources.
    - Add a `security` job in `.github/workflows/ci.yml` running `cargo deny check` + `cargo audit` (and `npm audit --audit-level=high` for `apps/ferriscd-web`) on every PR and on a weekly scheduled cron workflow.
    - Extend `.github/workflows/release.yml` to:
      1. Generate CycloneDX SBOMs (`cargo-cyclonedx` + Syft container SBOM) attached to GitHub Releases.
      2. Sign published container images (`ferriscd` and `ferriscd-web`) by immutable digest using keyless Sigstore `cosign` (OIDC GitHub Actions identity) and attach SBOM attestations (`cosign attest`).
      3. Generate SLSA Level 3 build provenance attestations (`actions/attest-build-provenance`) for binaries, container digests, and Helm chart `.tgz` archives.
    - Document CVE triage SLAs (Critical `<= 48h`, High `<= 7d`), image verification commands (`cosign verify`), and Helm chart digest pinning in `SECURITY.md`.
    - Author `docs/lessons/17-production-hardening-live-governance-and-supply-chain.md` with the hands-on `kind` experiment.
  - **Non-Functional:**
    - CI security gate adds `< 90 s` to PR feedback using cached advisory DBs.
    - Pin all third-party GitHub Actions in `.github/workflows/*.yml` to full 40-char commit SHAs (never mutable `@v4` tags).
- **Outputs:**
  - `deny.toml`
  - `.github/workflows/ci.yml`, `.github/workflows/security-audit.yml`, `.github/workflows/release.yml`
  - `SECURITY.md` (verification & CVE SLA section)
  - `docs/lessons/17-production-hardening-live-governance-and-supply-chain.md`
- **Verification & Acceptance Criteria:**
  - `cargo deny check` and `cargo audit` pass cleanly with zero unacknowledged advisories or disallowed licenses.
  - Dry-run release workflow (or tag build on test registry) produces verifiable CycloneDX SBOM, `cosign verify` passes against the image digest, and `gh attestation verify` validates SLSA provenance.
  - Static check verifies zero unpinned `uses:` tags remain across `.github/workflows/`.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** Phase 16 (`T16.5`, `T16.6`, `T16.7`).
  - **Complexity:** Small-Medium (3–4 hours).
  - **Risks/Trade-offs:** Strict `cargo-audit` on PRs can occasionally block unrelated PRs when a new RUSTSEC drops; mitigate via an explicit, time-bounded `ignore` list in `deny.toml` requiring an expiry comment and linked tracking issue.
- **Trap Guard:** Never sign container images by mutable tag (`:v1.1.0`) — always sign by immutable `sha256:...` digest; never embed long-lived signing private keys in repo secrets when GitHub OIDC keyless Cosign is available.

---

## Phase 18: Near-Real-Time Drift Detection & OCI Artifact Sources — *Milestone `v1.2`*

**Phase Goal:** Deliver the two high-leverage GitOps engine extensions designed in [docs/design/post-v1-backlog.md](../design/post-v1-backlog.md): (1) an opt-in, trigger-only `PartialObjectMetadata` label-scoped `DriftWatcher` providing sub-second drift wakeups without cluster-wide body caches, and (2) wire-compatible OCI artifact sources (`spec.source.oci`) for Helm v4 charts and Kustomize/YAML bundles.  
**Knowledge Base Lesson (`docs/lessons/18-drift-watchers-and-oci-gitops-sources.md`):** Kubernetes `PartialObjectMetadata` watches, self-echo suppression for generation-less `ConfigMap`/`Secret` objects, additive CRD schema evolution with CEL mutual exclusion, and tar-slip/tar-bomb-proof OCI extraction.  
**Hands-On `kind` Experiment:** Enable `--enable-drift-watcher=true` on `kind`, run `kubectl edit configmap` on a `selfHeal: true` app and measure sub-3s self-heal without triggering an infinite loop; then push a Helm chart to a local OCI registry (`registry:2` on `kind`), deploy it via `spec.source.oci` pinned by digest, and verify zero Git mirror is required.

---

### `T18.1` — `ClusterManager` Lifecycle Broadcast & Hashed Ownership Labels

- **Priority & Workstream:** `Essential Improvement` · `Architecture & Engineering Excellence` / `Reliability & Performance`
- **Problem Statement & User/Business Value:**
  - Today `crates/ferriscd-engine/src/inventory/tracking.rs` (`stamp_tracking_id`) stamps only the annotation `ferriscd.io/tracking-id`, which Kubernetes watch label selectors cannot filter on. A naive `ferriscd.io/app=<name>` label violates Kubernetes's 63-char label limit and collides across namespaces under Apps-in-any-namespace (**Finding M5**, `docs/REVIEW_LOG.md`).
  - Meanwhile `crates/ferriscd-controller/src/cluster_manager.rs` returns `ClusterChange { Added, Rebuilt, Unchanged }` internally during `seed()`/`run()`, but exposes no event stream for downstream subsystems (like per-cluster `DriftWatcher`s or `ApplicationSet` Cluster generators) to react to dynamic cluster additions, credential rotations, or revocations.
- **Detailed Requirements:**
  - **Functional:**
    - Add an opt-in stamping flag (`stamp_drift_labels: bool`, controlled by `--enable-drift-watcher`, default `false` — or additive once opted in) to `stamp_tracking_id` in `crates/ferriscd-engine/src/inventory/tracking.rs` that stamps two top-level `metadata.labels` onto every non-hook managed resource:
      - `ferriscd.io/managed-by: ferriscd`
      - `ferriscd.io/app-hash: <16-hex-sha256>` where the hash is the first 16 lowercase hex chars of `SHA-256("<app-ns>/<app-name>")` computed via `ferriscd_engine::diff::sha256::digest`.
    - Add a `tokio::sync::broadcast::Sender<ClusterLifecycleEvent>` (`Added(String)`, `Rebuilt(String)`, `Removed(String)`) to `ClusterManager` (`crates/ferriscd-controller/src/cluster_manager.rs`), emitted consistently on both watch updates and `InitDone` re-list revocations (`P13-H2`), plus `ClusterManager::subscribe()`.
    - Ensure `ResourceDiff::compare` (`crates/ferriscd-engine/src/diff/`) compares stamped labels deterministically so toggling `--enable-drift-watcher` cleanly converges labels on the next sync without false drift loops.
  - **Non-Functional:**
    - Label hash computation must be pure, deterministic, and valid under RFC 1123 / Kubernetes 63-char label value constraints for all valid 253-char `Application` names and 63-char namespaces.
    - Broadcast channel must be bounded (e.g., `64`); slow subscribers handle `RecvError::Lagged` by resyncing against `ClusterManager::names()`.
- **Outputs:**
  - `crates/ferriscd-crd/src/annotations.rs` (label constants `LABEL_MANAGED_BY`, `LABEL_APP_HASH`)
  - `crates/ferriscd-engine/src/inventory/tracking.rs` (`app_hash`, additive label stamping)
  - `crates/ferriscd-controller/src/cluster_manager.rs` (`ClusterLifecycleEvent` + `subscribe()`)
- **Verification & Acceptance Criteria:**
  - Unit tests verifying: (1) 253-char app names produce exact 16-char lowercase hex `ferriscd.io/app-hash`; (2) `ns-a/app` and `ns-b/app` produce distinct hashes; (3) lifecycle hooks (`ferriscd.io/hook`) are never stamped; (4) `spec.selector.matchLabels` and `spec.template.metadata.labels` are **never** mutated; (5) `ClusterManager` broadcasts `Added`, `Rebuilt`, and `Removed` (including on `InitDone` omission).
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** Phase 06 (`T06.1`), Phase 13 (`T13.1`).
  - **Complexity:** Small-Medium (3–4 hours).
  - **Risks/Trade-offs:** A 64-bit hash has negligible collision probability (`~10^-15` at 10,000 apps), and because `DriftWatcher` is trigger-only, even a theoretical collision causes at most one harmless no-op reconcile verified by exact `ferriscd.io/tracking-id`.
- **Trap Guard:** **Never** stamp `ferriscd.io/managed-by` or `ferriscd.io/app-hash` into immutable `spec.selector.matchLabels` (which would break existing `Deployment`/`StatefulSet` SSA applies with `422 Immutable`); stamp top-level `metadata.labels` only.

---

### `T18.2` — `PartialObjectMetadata` Label-Scoped `DriftWatcher` with `SelfEchoCache`

- **Priority & Workstream:** `Strategic Capability` · `Reliability & Performance` / `Core Product Capabilities`
- **Problem Statement & User/Business Value:**
  - Under Model 1 (`v1.0`, ADR-004), out-of-band mutations (`kubectl edit`/`kubectl delete`) wait up to `spec.requeueAfterSeconds` (default `180s`) to self-heal. High-security or latency-sensitive teams want sub-3s drift detection without paying the memory or Secret-exposure cost of full-object cluster-wide informers.
- **Detailed Requirements:**
  - **Functional:**
    - Implement `DriftWatcher` behind opt-in `--enable-drift-watcher=false` (`FERRISCD_ENABLE_DRIFT_WATCHER=false`), watching active `(cluster, GVK)` pairs derived strictly from watched `Application.status.inventory` (resolved via `DiscoveryCache`, optionally restricted by `--drift-watcher-kinds`, capped at `MAX_DRIFT_WATCHES = 64` per cluster).
    - Use `kube::runtime::watcher::metadata_watcher` over `Api::<PartialObjectMetadata<DynamicObject>>::all_with(client, &api_resource)` filtered server-side by `labels("ferriscd.io/managed-by=ferriscd")` so zero `.spec`/`.status`/`Secret.data` bytes ever cross the wire.
    - Wire one bounded `mpsc::channel::<reflector::ObjectRef<Application>>(256)` per `NamespacedController` scope into `Controller::for_stream(stream, store).reconcile_on(ReceiverStream::new(drift_rx))` (`crates/ferriscd-controller/src/controller.rs`), using non-blocking `try_send` and filtering through `Sharding::owns(ns, name)` (`crates/ferriscd-controller/src/sharding.rs`).
    - Implement a bounded, TTL-expiring `SelfEchoCache` (`60s` TTL, `10_000` cap) populated by `SyncExecutor` from `Applier::apply`'s returned `metadata.resource_version` and confirmed prunes:
      - Generation-bearing kinds (`metadata.generation.is_some()`): ignore unchanged `(uid, generation)` events (filters `/status` chatter).
      - Generation-less kinds (`ConfigMap`, `Secret`): drop events whose `metadata.resource_version` matches `SelfEchoCache`; trigger immediately on any newer `resourceVersion` or non-self-pruned `WatchEvent::Deleted`.
    - Apply per-`Application` trailing debounce (`2s`, max-wait ceiling `5s`) to coalesce multi-resource bursts.
    - On `403 Forbidden`, `404 NotFound`, or `405 MethodNotAllowed`: log one structured `warn!`, increment `ferriscd_drift_watcher_fallback_total{reason}`, park the watcher on a `15m` cooldown, and fall back seamlessly to Model 1 periodic polling without marking any `Application` unhealthy.
    - Subscribe to `ClusterManager::subscribe()` (`T18.1`) to start/cancel remote-cluster watchers dynamically on cluster lifecycle events.
  - **Non-Functional:**
    - Memory overhead at 500 watched resources must remain `< 5 MiB` RSS (metadata-only objects discarded after hash lookup, no object cache retained).
    - Drift trigger latency from external `kubectl edit` to reconcile enqueue: `<= 2.5 s` (p95, dominated by the `2 s` debounce window).
- **Outputs:**
  - `crates/ferriscd-controller/src/drift_watcher.rs` (`DriftWatcher`, `SelfEchoCache`, trailing debouncer)
  - `crates/ferriscd-controller/src/controller.rs` (`reconcile_on` wiring), `crates/ferriscd-controller/src/sync.rs`, `crates/ferriscd-controller/src/sync_executor.rs` (echo recording), `crates/ferriscd-controller/src/metrics.rs`
- **Verification & Acceptance Criteria:**
  - Deterministic unit tests (mocked stream + injected clock, zero real sleeps) proving: (1) `ConfigMap`/`Secret` self-apply does NOT re-trigger while external RV bump DOES trigger; (2) status-only `Deployment` events (unchanged generation) are ignored; (3) `403 Forbidden` falls back cleanly and increments metric without panic or `Ready=False`; (4) shard filter drops triggers for non-owned apps; (5) burst of 50 events coalesces into 1 trigger.
  - Live `kind` E2E test confirming out-of-band `kubectl edit configmap` and `kubectl delete configmap` on a `selfHeal: true` app converge within `< 10 s` even when `requeueAfterSeconds: 600`.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T18.1`, Phase 13 (`T13.1`, `T13.3`), Phase 15 (`T15.1`).
  - **Complexity:** High (6 hours).
  - **Risks/Trade-offs:** Watching every GVK in a cluster would exhaust API server watch limits; bounding to active `status.inventory` GVKs + `MAX_DRIFT_WATCHES = 64` + opt-in flag keeps blast radius tight while preserving Model 1 as the authoritative fallback.
- **Trap Guard:** Never store or log full objects or `Secret.data`; never block the watch loop on a full `drift_rx` channel (`try_send` only); never omit `SelfEchoCache` for `ConfigMap`/`Secret` (without it, `selfHeal: true` enters an infinite apply/watch feedback loop).

---

### `T18.3` — Additive OCI Artifact Source (`spec.source.oci`) CRD & Safe Extraction

- **Priority & Workstream:** `Strategic Capability` · `Core Product Capabilities` / `Integrations & Extensibility`
- **Problem Statement & User/Business Value:**
  - Modern teams publish signed Helm v4 charts and Kustomize bundles directly to OCI registries (`ghcr.io`, ECR, GAR, Harbor) and want GitOps delivery without maintaining redundant Git mirror repositories.
  - As audited in `docs/design/post-v1-backlog.md` §3 & §6, `SourceSpec` (`crates/ferriscd-crd/src/application.rs`) can evolve additively to support `spec.source.oci` with **zero breaking changes** to stored `v1alpha1` CRs and no conversion webhook.
- **Detailed Requirements:**
  - **Functional:**
    - Evolve `SourceSpec` in `crates/ferriscd-crd/src/application.rs`: change `git: Option<GitSourceSpec>` and add `oci: Option<OciSourceSpec>` (`url`, `tag`, `digest`, `path`), both `#[serde(default, skip_serializing_if = "Option::is_none")]`.
    - Add OpenAPI v3 CEL `x-kubernetes-validations` rules on `SourceSpec` (`(has(self.git) && !has(self.oci)) || (!has(self.git) && has(self.oci))`) and `OciSourceSpec` (`has(self.tag) || has(self.digest)`), with 100% parity in `ApplicationSpec::validate(&self)` (`MissingSource`, `AmbiguousSource`, `InvalidOciUrl`, `InvalidOciDigest`).
    - Implement an object-safe `OciClient` trait (`resolve_digest` -> immutable `sha256:<64-hex>`, `fetch_artifact` -> read-only `RepoCheckout`) strictly inside `crates/ferriscd-engine/src/repo/` (keeping any third-party OCI client crate encapsulated inside `repo/`, matching the `gix` rule).
    - Support Helm chart (`application/vnd.cncf.helm.chart.content.v1.tar+gzip`) and generic/Flux bundle (`application/vnd.oci.image.layer.v1.tar+gzip`, `application/vnd.cncf.flux.content.v1.tar+gzip`) media types, including safe single-root Helm `.tgz` directory unwrapping so `path: ""` points cleanly at `Chart.yaml`.
    - Verify manifest and layer SHA-256 digests before extraction; enforce `WorktreeLimits` (`crates/ferriscd-engine/src/repo/sanitize.rs`) during streaming tar extraction (stopping tar bombs, absolute paths, `..` traversal, FIFOs/device nodes, escaping hardlinks) and run `sanitize_worktree` on the extracted root.
    - Extend `CredentialTemplate::from_secret` (`crates/ferriscd-controller/src/credentials.rs`) to accept `SCHEME_OCI = "oci"` on `ferriscd.io/secret-type=repository` Secrets (`username`/`password`/`token`/`.dockerconfigjson`), rejecting SSH fields on `oci://` templates.
  - **Non-Functional:**
    - All archive decompression, hashing, and filesystem extraction MUST execute inside `tokio::task::spawn_blocking`.
    - HTTPS-only registry transport by default (reject plaintext `http://` unless explicit local-dev flag is set for `kind` testing).
    - Existing `v1.0` Git `Application` YAML/JSON fixtures must round-trip byte-identically.
- **Outputs:**
  - `crates/ferriscd-crd/src/application.rs` + regenerated `deploy/crds/applications.ferriscd.io.yaml`
  - `crates/ferriscd-engine/src/repo/oci.rs` (`OciClient` trait, streaming safe tar extractor, digest verifier)
  - `crates/ferriscd-controller/src/credentials.rs` (`oci://` credential support)
- **Verification & Acceptance Criteria:**
  - Unit tests proving: (1) `v1.0` Git `Application` CRs deserialize/serialize byte-identically; (2) both-set and neither-set `(git, oci)` fail validation with exact errors; (3) mismatched digest, tar-slip (`../../etc/passwd`), symlink escape, device node, and 1 GiB compressed tar bomb are all rejected before reaching any renderer; (4) `oci://` credentials redact tokens in `Debug`/`Display`/errors.
  - `ferriscd crd generate --check` passes and confirms CEL rules are present in `deploy/crds/applications.ferriscd.io.yaml`.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** Phase 02 (`T02.5`), Phase 12 (`T12.4`), `T17.5` (license/audit check on OCI crate).
  - **Complexity:** High (5–6 hours).
  - **Risks/Trade-offs:** Helm OCI charts wrap files inside a `<chart-name>/` top-level directory while ORAS/Flux bundles often extract at root; explicit single-root unwrapping gated by `Chart.yaml` presence avoids breaking Kustomize bundles with subdirectories.
- **Trap Guard:** Never leak OCI crate types outside `crates/ferriscd-engine/src/repo/`; never trust the HTTP `Content-Length` header alone against gzip bombs (enforce streaming decompressed byte counter against `WorktreeLimits::max_bytes`); never allow `helm template` itself to make outbound OCI network calls (extract offline first, render strictly offline).

---

### `T18.4` — OCI Integration with Render Cache, `AppProject` Policy & Live `kind` Verification

- **Priority & Workstream:** `Essential Improvement` · `Core Product Capabilities` / `Developer & Operator Experience`
- **Problem Statement & User/Business Value:**
  - Fetching an OCI artifact is only useful once it flows seamlessly through FerrisCD's existing renderers (`PlainYaml`, `Kustomize`, `Helm`), collision-free `RenderCache`, `source_spec_hash` decision gate, `AppProject` tenancy boundaries, status/history views, CLI, and Web UI — and is proven end-to-end against a real OCI registry on `kind`.
- **Detailed Requirements:**
  - **Functional:**
    - Wire `OciClient` into `InventorySyncPipeline` (`crates/ferriscd-controller/src/sync.rs`) alongside `GitClient`, populating `RenderCacheKey` (`repo_url = oci.url`, `commit_sha = resolved_digest`, `source_path = oci.path`) in `crates/ferriscd-engine/src/manifest/cache.rs`.
    - Confirm `source_spec_hash` (`crates/ferriscd-engine/src/diff/decision.rs`) covers `spec.source.oci` (`tag`, `digest`, `path`), `SyncState.revision` / `lastSyncedRevision` records `sha256:<64-hex>`, and `SourceSummary` records the redacted `oci://` URL + tag/digest within the 20-entry `status.history` cap.
    - Verify `AppProjectPolicy::check_application` (`crates/ferriscd-engine/src/policy/app_project.rs`) enforces `spec.source.oci.url` against `AppProject.spec.sourceRepos` (e.g., `oci://ghcr.io/payments/*`) before any registry network call occurs.
    - Surface OCI source type, tag, and pinned digest in `SourceView` (`crates/ferriscd-server/src/api.rs`), `ferriscd app get`, and `apps/ferriscd-web` (`ApplicationDetailPage`).
    - Author `docs/lessons/18-drift-watchers-and-oci-gitops-sources.md` with the hands-on `kind` experiment.
  - **Non-Functional:**
    - Cached digest hits must execute zero OCI registry fetches and zero renderer subprocess invocations.
    - Prometheus metrics record `ferriscd_render_cache_total` and source-fetch duration with strictly bounded static labels (`source_kind="git|oci"`).
- **Outputs:**
  - `crates/ferriscd-controller/src/sync.rs`, `crates/ferriscd-engine/src/policy/app_project.rs`, `crates/ferriscd-server/src/api.rs`
  - `tests/integration/v1_2_oci_and_drift.rs` (live `kind` test with local OCI registry + `DriftWatcher`)
  - `docs/lessons/18-drift-watchers-and-oci-gitops-sources.md`
- **Verification & Acceptance Criteria:**
  - Unit tests verifying: unauthorized `oci://` URL rejected by `AppProjectPolicy` with zero `OciClient` calls; editing `oci.tag` or `oci.digest` changes `source_spec_hash` and triggers sync under `selfHeal: false`; rollback to a prior OCI history entry re-deploys the prior digest cleanly.
  - Live `kind` E2E test (`#[ignore]` + `kind-` context guard) pushing a real Helm v4 chart & Kustomize bundle to an in-cluster `registry:2`, reconciling via `spec.source.oci`, and confirming idempotent convergence + rollback.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T18.2`, `T18.3`.
  - **Complexity:** Medium (4–5 hours).
  - **Risks/Trade-offs:** Mutable OCI tags (e.g., `:latest` or `:1.x`) require periodic digest resolution against the registry; rely on lightweight OCI `HEAD /v2/.../manifests/<tag>` digest checks and skip layer downloads whenever the resolved `sha256` digest matches the local cache.
- **Trap Guard:** Enforce `AppProjectPolicy::check_application` **before** calling `OciClient::resolve_digest` (prevents unauthorized SSRF probes against internal registries via `Application.spec.source.oci.url`); keep `source_kind` Prometheus label strictly an enum (`git` | `oci`), never the registry hostname or digest.

---

## Phase 19: Enterprise SSO/OIDC, ApplicationSets & Notifications — *Milestone `v1.3`*

**Phase Goal:** Unlock full enterprise team workflows by adding standards-compliant OIDC/SSO authentication (web PKCE + CLI loopback), declarative fleet generation via the `ApplicationSet` CRD, and SSRF-hardened event-driven Slack/Teams/PagerDuty/Webhook notifications.  
**Knowledge Base Lesson (`docs/lessons/19-enterprise-sso-applicationsets-and-notifications.md`):** Hardened OIDC JWT/JWKS validation (defeating `alg: none`/`HS*` key confusion and `kid` DoS storms), PKCE `S256` in SPAs and CLIs, non-Turing-complete `ApplicationSet` fleet generation without tenancy bypasses, and SSRF-safe egress filtering.  
**Hands-On `kind` Experiment:** Deploy Dex as a local OIDC IdP on `kind`, log in via `ferriscd login --oidc` (or `--sso` alias) and Web UI SSO with group-mapped RBAC, generate 6 tenant `Application`s across 2 namespaces using an `ApplicationSet` `Matrix` (`clusters × git.directories`) generator, and observe signed webhook notifications fire on sync success and health degradation.

---

### `T19.1` — OIDC / SSO Authenticator in `ferriscd-server`

- **Priority & Workstream:** `Strategic Capability` · `Security & Governance` / `Enterprise Capabilities`
- **Problem Statement & User/Business Value:**
  - `v1.0` supports Kubernetes `TokenReview` (`crates/ferriscd-server/src/auth.rs`), which excels for CI `ServiceAccount` tokens but forces human operators to mint and paste raw Kubernetes bearer tokens. Enterprise organizations standardize on corporate IdPs (Okta, Entra ID, Keycloak, Dex, Google) with centralized group lifecycle and MFA.
- **Detailed Requirements:**
  - **Functional:**
    - Extend `AuthPolicy` (`crates/ferriscd-server/src/auth.rs`) with `AuthPolicy::Oidc` and `AuthPolicy::TokenReviewOrOidc` (keeping `AuthPolicy::TokenReview` as the default).
    - Implement `OidcTokenAuthenticator` and `CompositeTokenAuthenticator` behind the existing `TokenAuthenticator` trait (`authenticate(&self, token: &str) -> SeamFuture<'_, Option<AuthenticatedIdentity>>`) with zero changes to API handlers or `RbacPolicy`.
    - Discover `<issuer>/.well-known/openid-configuration` and `jwks_uri` over HTTPS (`rustls` + optional custom CA from `ferriscd.io/secret-type: oidc` Secret in `ferriscd-system`).
    - Enforce strict asymmetric algorithm allowlist (`RS256`, `ES256`, `ES384`, `EdDSA`) — **unconditionally rejecting `alg: none` and `HS*`**. Validate `iss` (exact), `aud` (contains `clientId`), `exp`, `nbf` (clock skew `<= 30s`), and non-empty `sub`.
    - Enforce mandatory non-empty `--oidc-username-prefix` (default `oidc:`) and `--oidc-groups-prefix` (default `oidc:`) so IdP claims can never spoof `system:masters` or `system:serviceaccount:*`.
    - Rate-limit on-demand JWKS refetches on unknown `kid` (at most once per `60s`) to prevent outbound DoS storms against the IdP.
    - Upgrade `IdentityCache` (`crates/ferriscd-server/src/auth.rs`) to support per-entry TTL clamping: `min(DEFAULT_IDENTITY_CACHE_TTL, jwt_exp - now)` so expired JWTs are never served from cache.
    - Add public discovery endpoint `GET /api/v1/auth/config` (`{ authMode, issuer, clientId, scopes, bffEnabled }`) to the `public` router group in `crates/ferriscd-server/src/api.rs`.
  - **Non-Functional:**
    - Local JWKS signature verification executes in `< 1 ms` per request with zero per-request outbound IdP calls; JWKS HTTP refresh runs asynchronously outside request lock paths.
    - All OIDC client secrets and signing keys are redacted in `Debug`/`Display`/errors; JWTs are logged only via 12-hex `token_fingerprint`.
- **Outputs:**
  - `crates/ferriscd-server/src/oidc.rs` (`OidcTokenAuthenticator`, `CompositeTokenAuthenticator`, JWKS cache)
  - `crates/ferriscd-server/src/auth.rs` (new `AuthPolicy` variants + per-entry `IdentityCache` TTL)
  - `crates/ferriscd-server/src/api.rs` (`GET /api/v1/auth/config` + updated `docs/api/openapi.json`)
- **Verification & Acceptance Criteria:**
  - Unit tests using ephemeral RSA/ECDSA/Ed25519 keys proving: (1) valid RS256/ES256/EdDSA JWTs map prefixed username & groups into `RbacPolicy`; (2) `alg: none`, `HS256` (signed with the public RSA key!), wrong `iss`, wrong `aud`, expired `exp`, and future `nbf` are all rejected with `401`; (3) 100 rapid requests with unknown `kid` trigger at most 1 JWKS fetch within 60s; (4) `IdentityCache` evicts a JWT immediately at `exp` even when `< 30s`; (5) `CompositeTokenAuthenticator` accepts both valid OIDC JWTs and valid `TokenReview` SA tokens.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T17.1`, `T17.2` (audit events carry `oidc:` actor attribution).
  - **Complexity:** High (5–6 hours).
  - **Risks/Trade-offs:** `TokenReviewOrOidc` must avoid calling Kubernetes `TokenReview` for every malformed token; inspect lightweight JWT structure/issuer hint first (without trusting unverified claims) or short-circuit on OIDC signature verification before falling through.
- **Trap Guard:** Reject `http://` issuers unless an explicit local-dev flag is passed; reject empty username/group prefixes at startup; never cache negative auth failures in `IdentityCache`.

---

### `T19.2` — Web UI PKCE (`S256`) SSO Flow & `ferriscd login --oidc` CLI Flow

- **Priority & Workstream:** `Essential Improvement` · `UI/UX & Design System` / `Developer & Operator Experience`
- **Problem Statement & User/Business Value:**
  - Server-side OIDC verification (`T19.1`) only delivers seamless human UX when both `apps/ferriscd-web` and the `ferriscd` CLI natively execute modern OAuth 2.1 Authorization Code + PKCE (`S256`) flows without requiring manual token copying or unsafe browser storage.
- **Detailed Requirements:**
  - **Functional:**
    - Update `apps/ferriscd-web` boot sequence to call `GET /api/v1/auth/config`:
      - `token-review`: render existing bearer-token sign-in screen.
      - `oidc` / `token-review-or-oidc`: render **"Sign in with SSO"** button launching Authorization Code + PKCE (`S256`) with cryptographically random `state`, `nonce`, and `code_verifier`, plus a collapsible ServiceAccount token fallback when `token-review-or-oidc` is enabled.
    - Support two secure browser session modes:
      1. **SPA In-Memory Mode (default):** Store the access/ID token strictly in React memory (`AuthContext` state — never `localStorage`/`sessionStorage`), clearing on tab close and surfacing a graceful session-expiry banner + one-click re-authenticate before expiry.
      2. **Optional BFF Cookie Mode (`--oidc-bff-enabled`):** Add `GET /api/v1/auth/login`, `GET /api/v1/auth/callback`, and `POST /api/v1/auth/logout` in `ferriscd-server` issuing an AEAD-encrypted `HttpOnly; Secure; SameSite=Lax` cookie (key from `ferriscd.io/secret-type: oidc` Secret) plus mandatory CSRF double-submit header validation on all mutating `POST` routes (`/sync`, `/rollback`, `/logout`).
    - Implement `ferriscd login <server-url> --oidc` (with `--sso` alias) in `crates/ferriscd-cli` using an ephemeral `127.0.0.1:<random-port>` loopback redirect server, opening the system browser (with headless URL printout fallback), completing PKCE `S256` exchange, and persisting the short-lived token in `~/.config/ferriscd/config.json` with `0600` permissions (also making CLI config read async/clean to close the `docs/REVIEW_LOG.md` line 204 follow-up).
  - **Non-Functional:**
    - `state` and `code_verifier` must use CSPRNG (`crypto.getRandomValues` in Web, `getrandom` in Rust) with `>= 256` bits of entropy.
    - Redirect URIs are validated against an exact configured allowlist (preventing open redirects).
- **Outputs:**
  - `crates/ferriscd-server/src/auth_bff.rs` (optional BFF routes + CSRF middleware)
  - `apps/ferriscd-web/src/auth/AuthContext.tsx`, `apps/ferriscd-web/src/auth/pkce.ts`, `apps/ferriscd-web/src/components/LoginScreen.tsx`
  - `crates/ferriscd-cli/src/commands/login.rs` (`--oidc` / `--sso` alias PKCE loopback flow)
- **Verification & Acceptance Criteria:**
  - Vitest tests proving: PKCE `S256` challenge matches RFC 7636 test vector; `state` mismatch aborts login cleanly; token never touches `localStorage` or `sessionStorage`; expired session renders re-auth prompt without losing current route context.
  - Server tests proving BFF mode rejects mutating `POST /sync` without matching CSRF header (`403`) and sets `HttpOnly; Secure; SameSite=Lax` attributes.
  - CLI integration test against a mock local OIDC server proving `ferriscd login --oidc` (and `--sso` alias) completes PKCE exchange and writes `0600` config file.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T19.1`.
  - **Complexity:** Medium-High (5–6 hours).
  - **Risks/Trade-offs:** In-memory SPA tokens lose session on hard browser refresh; offering optional BFF cookie mode solves hard-refresh ergonomics for high-security deployments without weakening XSS posture.
- **Trap Guard:** Never accept `plain` PKCE method (`S256` only); never put tokens or authorization `code`s in logs or error toasts; never omit CSRF protection when BFF cookies are enabled.

---

### `T19.3` — `ApplicationSet` CRD & Safe Generator Engine

- **Priority & Workstream:** `Strategic Capability` · `Enterprise Capabilities` / `Core Product Capabilities`
- **Problem Statement & User/Business Value:**
  - Platform teams managing dozens of microservices across dev/staging/prod clusters currently author repetitive `Application` YAML per `(service, cluster)` pair.
  - Shipping an additive `ApplicationSet` CRD (`ferriscd.io/v1alpha1`, designed in `docs/design/post-v1-backlog.md` §5.1) automates fleet templating while keeping `Application` a clean, single-destination primitive and preserving every multi-tenancy guardrail.
- **Detailed Requirements:**
  - **Functional:**
    - Define additive CRD `ApplicationSet` (`ferriscd.io/v1alpha1`, `shortname = "appset"`, `/status` subresource with `observedGeneration`, `conditions`, `generatedCount`) in `crates/ferriscd-crd/src/applicationset.rs` and export `deploy/crds/applicationsets.ferriscd.io.yaml`.
    - Run an independent, opt-in controller loop (`--enable-applicationsets=false` by default) supporting 4 generators:
      1. `list`: static array of key/value maps.
      2. `git` (`directories` glob & `files` YAML/JSON parsed via `parse_document` under YAML budgets, reusing `GitClient`, `RepoCache`, `sanitize_worktree`, `CredentialSource`).
      3. `clusters`: label selector over registered cluster Secrets (`ferriscd.io/secret-type=cluster`) via `ClusterManager`.
      4. `matrix`: Cartesian product of exactly two child generators with a hard output cap (`MAX_GENERATED_APPS = 200`, configurable ceiling) to block accidental fan-out bombs.
    - Render `spec.template` via strict flat `{{key}}` placeholder substitution with DNS-1123 sanitization — **no Turing-complete template engine or arbitrary code execution**.
    - Default `spec.syncPolicy.preserveResourcesOnDeletion` to `true` (mirroring Finding C5) so deleting an `ApplicationSet` or a transient Git error never mass-deletes live `Application`s unless explicitly opted in.
    - Create generated `Application`s strictly in the `ApplicationSet`'s own namespace with same-namespace `ownerReferences` and label `ferriscd.io/applicationset=<name>`; refuse to overwrite unmanaged or foreign-owned `Application`s (`Ready=False`).
    - Enforce `AppProjectPolicy` validation on every generated `Application` (including `sourceNamespaces`, `sourceRepos`, `destinations`, and `allowedServiceAccounts`) before applying.
  - **Non-Functional:**
    - Blocking Git/worktree evaluation runs inside `tokio::task::spawn_blocking`.
    - Generator evaluation on `matrix` of 200 apps completes in `< 500 ms` in memory with strictly deterministic ordering.
- **Outputs:**
  - `crates/ferriscd-crd/src/applicationset.rs` + `deploy/crds/applicationsets.ferriscd.io.yaml`
  - `crates/ferriscd-engine/src/applicationset/` (generators, flat template renderer, cap guard)
  - `crates/ferriscd-controller/src/applicationset_controller.rs`
  - `crates/ferriscd-server/src/api.rs` (`GET /api/v1/applicationsets` read view) & `apps/ferriscd-web` badge on generated apps
- **Verification & Acceptance Criteria:**
  - Unit tests verifying: all 4 generators (`list`, `git`, `clusters`, `matrix`); fan-out > `MAX_GENERATED_APPS` rejected with `Ready=False` and zero partial deletes; transient Git error preserves existing generated `Application`s; foreign/operator-owned `Application` conflict is refused; unauthorized `AppProject` target is rejected before create.
  - Live `kind` test generating 6 `Application`s via `Matrix(clusters × git.directories)`, verifying reconciliation, and confirming deleting the `ApplicationSet` preserves workloads by default.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T18.1` (`ClusterManager` lifecycle broadcast), Phase 12 (`T12.1`, `T12.2`).
  - **Complexity:** High (6 hours).
  - **Risks/Trade-offs:** A buggy `git.directories` glob or temporary branch rewrite could wipe a fleet if deletion cascaded by default; `preserveResourcesOnDeletion: true` + refusing prune on generator errors eliminates catastrophic fleet deletion.
- **Trap Guard:** Never allow `ApplicationSet` to generate `Application`s in a different namespace than itself (cross-namespace `ownerReferences` are invalid in Kubernetes and create privilege-escalation paths); never parse Git generator parameter files without `parse_document` budgets and `sanitize_worktree`.

---

### `T19.4` — Event-Driven Notifications Engine

- **Priority & Workstream:** `Strategic Capability` · `Integrations & Extensibility` / `Developer & Operator Experience`
- **Problem Statement & User/Business Value:**
  - Teams rely on immediate, actionable alerts in Slack, Microsoft Teams, PagerDuty, or internal automation webhooks when a production sync fails, health degrades, or a release succeeds — without polling the dashboard or modifying `ApplicationSpec`.
- **Detailed Requirements:**
  - **Functional:**
    - Opt-in exclusively via annotations (`notifications.ferriscd.io/subscribe.<trigger>.<service>: "<recipient>"`), which remain invisible to `TRACKED_ANNOTATIONS` in `crates/ferriscd-controller/src/predicate.rs` (zero spurious reconciles).
    - Attach an opt-in `NotificationObserver` (`--enable-notifications=false` by default) as a `StatusWriter` decorator hook around `ApiStatusWriter` (zero extra API server reads), firing edge-triggered notifications for: `on-sync-succeeded`, `on-sync-failed`, `on-health-degraded`, and debounced `on-out-of-sync`.
    - Load templates/triggers from `ConfigMap/ferriscd-notifications-cm` in `ferriscd-system` (parsed via `parse_document` under YAML budgets) and channel secrets/signing keys from `Secret`s labeled `ferriscd.io/secret-type: notifications` in `ferriscd-system`.
    - Ship built-in delivery adapters for: **Slack** (Incoming Webhook / Bot API), **Microsoft Teams** (Workflow webhook), **PagerDuty** (Events API v2), and **Generic Webhook** (with HMAC-SHA256 `X-FerrisCD-Signature-256` payload signing).
    - Deduplicate deliveries on `(app_ns, app_name, trigger, observed_generation, revision, health_status)` inside a bounded LRU cache + enforce per-application rate limiting (token bucket, e.g. `10 notifications / 5 min`).
    - Enforce strict **SSRF egress guard** on resolved destination IPs before every HTTP connect: require `https://`, resolve DNS and reject loopback (`127.0.0.0/8`, `::1`), RFC 1918 private ranges (unless operator-allowlisted via `--notifications-allow-private-cidrs`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), multicast, and **IPv4-mapped IPv6 addresses** (`::ffff:169.254.169.254`, `::ffff:127.0.0.1`), pinning the validated IP on connect to defeat DNS rebinding.
    - Redact all template context fields: expose only redacted `ApplicationStatus` (`sync`, `health`, `conditions`, `history`) and `redact_repo_url` — never raw `Secret` data or diffs.
  - **Non-Functional:**
    - Non-blocking bounded worker queue (`try_send`, capacity `512`), `5 s` per-request HTTP timeout, max `3` exponential-backoff retries; delivery failures increment `ferriscd_notifications_total{service, outcome}` and never delay reconciliation.
    - Author `docs/lessons/19-enterprise-sso-applicationsets-and-notifications.md`.
- **Outputs:**
  - `crates/ferriscd-controller/src/notifications/` (`observer.rs`, `ssrf.rs`, `adapters.rs`, `template.rs`)
  - `crates/ferriscd-controller/src/metrics.rs` (`ferriscd_notifications_total`)
  - `docs/lessons/19-enterprise-sso-applicationsets-and-notifications.md`
- **Verification & Acceptance Criteria:**
  - Unit tests proving: (1) adding/editing `notifications.ferriscd.io/*` produces an unchanged `predicate::composite_hash`; (2) SSRF guard blocks `http://`, `169.254.169.254`, `127.0.0.1`, `[::1]`, `[::ffff:169.254.169.254]`, `[::ffff:127.0.0.1]`, and redirects to blocked IPs; (3) repeated 180s requeues on an unchanged failure fire exactly 1 notification; (4) per-app rate limiter bounds bursts; (5) generic webhook HMAC signature validates and zero secret tokens leak into rendered payloads or logs.
  - Live `kind` test delivering signed notifications to an in-cluster test receiver pod on `on-sync-succeeded` and `on-health-degraded`.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** Phase 05 (`T05.2`), Phase 15 (`T15.1`, `T15.2`).
  - **Complexity:** Medium-High (5–6 hours).
  - **Risks/Trade-offs:** HTTP redirects (`302 -> http://169.254.169.254/...`) are a classic SSRF bypass; disable automatic HTTP redirects completely on the notification `reqwest`/`hyper` client.
- **Trap Guard:** Disable HTTP redirect following; check IPv4-mapped IPv6 (`IpAddr::to_canonical()` / `is_ipv4_mapped`) in addition to raw IPv4/IPv6 checks; never allow notification secrets inside `Application` annotations or `ConfigMap`s.

---

## Phase 20: Progressive Delivery, Policy-as-Code, Multi-Source & Disaster Recovery — *Milestone `v2.0`*

**Phase Goal:** Complete FerrisCD's evolution into a tier-1 enterprise GitOps platform with multi-source `Application`s (`spec.sources[]`), pre-sync Policy-as-Code gates (CEL + optional OPA/Rego), opt-in progressive delivery evaluators and metric-gated rollouts, safe backup/restore and zero-downtime upgrade verification, and 250-app / 2,500-resource sharded scale validation.  
**Knowledge Base Lesson (`docs/lessons/20-progressive-delivery-policy-and-fleet-scale.md`):** Deterministic multi-source rendering and revision tracking, pre-sync Policy-as-Code admission in GitOps engines, re-entrant metric-gated rollouts without blocking workers, secret-safe GitOps disaster recovery, and multi-shard scale engineering.  
**Hands-On `kind` Experiment:** Deploy a multi-source `Application` combining an OCI Helm chart with a separate Git values repository, block a non-compliant manifest (missing resource limits / privileged pod) with a CEL policy gate surfaced in `ferriscd app diff` and the Web UI, verify `ferriscd backup export` / `restore` into a clean namespace, and run the 250-app / 2,500-resource sharded benchmark.

---

### `T20.1` — Multi-Source `Application` (`spec.sources[]`) for Split Chart + Values Repos

- **Priority & Workstream:** `Strategic Capability` · `Core Product Capabilities` / `UI/UX & Design System`
- **Problem Statement & User/Business Value:**
  - A dominant enterprise Helm pattern separates upstream/platform Helm charts (often in an OCI registry or shared chart repo) from environment-specific `values.yaml` files living in a separate application Git repository. Single-source `spec.source` forces teams to vendor charts or write wrapper umbrella charts.
- **Detailed Requirements:**
  - **Functional:**
    - Extend `ApplicationSpec` (`crates/ferriscd-crd/src/application.rs`) additively by relaxing `ApplicationSpec.source` (`crates/ferriscd-crd/src/application.rs:102`) from `SourceSpec` to `Option<SourceSpec>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`, removing `"source"` from OpenAPI `spec.required`) and adding `sources: Vec<MultiSourceEntry>`, enforced as mutually exclusive via OpenAPI CEL `x-kubernetes-validations` + `ApplicationSpec::validate` (remaining 100% wire-compatible for all existing `v1.0` CRs stored in `etcd`).
    - Each `MultiSourceEntry` carries either `git` or `oci`, optional `renderer`, and optional `#[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")] pub ref_name: Option<String>` alias (e.g., `ref: values`), allowing another source's Helm `valueFiles` to reference `$values/envs/prod/values.yaml`.
    - Enforce `AppProjectPolicy::check_application` on **every** entry's repo/OCI URL before fetching any source.
    - Fetch all sources into isolated sanitized worktrees (`sanitize_worktree`), resolve `$ref/...` paths strictly jailed inside the referenced worktree (rejecting `..` traversal or unknown `$ref` aliases), and track deterministic per-source revisions in `status.sync.revisions: Vec<String>` and `status.history[].revisions: Vec<String>`.
    - Extend `RenderCacheKey` (`crates/ferriscd-engine/src/manifest/cache.rs`) to hash the length-prefixed canonical list of all `(source_url, resolved_revision, path, ref_alias)` tuples plus renderer config so cache keys stay collision-free.
    - Surface multi-source badges and per-source revisions in `ApplicationSummary`/`ApplicationDetailView` (`crates/ferriscd-server/src/api.rs`), CLI, and `apps/ferriscd-web`.
  - **Non-Functional:**
    - Cap `spec.sources.len() <= 16` (CRD validation) to bound checkout fan-out and status payload size within Kubernetes's 1.5 MiB `etcd` limit.
    - All checkouts/extractions execute inside `tokio::task::spawn_blocking`.
- **Outputs:**
  - `crates/ferriscd-crd/src/application.rs`, `crates/ferriscd-crd/src/status.rs` + regenerated `deploy/crds/applications.ferriscd.io.yaml`
  - `crates/ferriscd-engine/src/manifest/cache.rs`, `crates/ferriscd-engine/src/manifest/renderer.rs`, `crates/ferriscd-engine/src/policy/app_project.rs`
  - `crates/ferriscd-controller/src/sync.rs`, `crates/ferriscd-server/src/api.rs`, `apps/ferriscd-web/src/pages/ApplicationDetailPage.tsx`
- **Verification & Acceptance Criteria:**
  - Unit tests verifying: `$values/...` resolution succeeds inside the referenced repo and rejects `../` escapes or symlink escapes across worktrees; unauthorized second source URL is blocked by `AppProjectPolicy` before any clone; editing a value file in the secondary repo updates `status.sync.revisions` and triggers sync under `selfHeal: false`; `v1.0` single-source `Application` CRs round-trip unchanged.
  - Live `kind` test deploying a Helm chart from local OCI (`T18.3`) combined with `values.yaml` from a local Git repo.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T18.3`, `T18.4`.
  - **Complexity:** High (6 hours).
  - **Risks/Trade-offs:** Partial fetch failure on source 2 of 2 must fail the whole pass atomically and never apply half-rendered manifests or prune existing inventory.
- **Trap Guard:** Never copy referenced `$values` files into a shared writable directory without path canonicalization; never drop `status.sync.revision` compatibility for single-source apps; enforce `sources.len() <= 16` in both CEL and offline validation.

---

### `T20.2` — Pre-Sync Policy-as-Code Gate (CEL & Optional OPA/Rego)

- **Priority & Workstream:** `Strategic Capability` · `Security & Governance` / `Integrations & Extensibility`
- **Problem Statement & User/Business Value:**
  - `AppProject` allowlists restrict *kinds* and *namespaces*, but security teams also enforce fine-grained manifest invariants before anything touches a cluster (e.g., disallow `privileged: true`, require signed container registries, mandate cost-center labels, enforce `PodDisruptionBudget` on production Deployments) — and want violations visible immediately in `ferriscd app diff` and the Web UI, not only after cluster admission rejects an apply.
- **Detailed Requirements:**
  - **Functional:**
    - Implement a pure, offline `PolicyGate` engine in `crates/ferriscd-engine/src/policy/gate.rs` running immediately after Stage-2 scope normalization and **before** SSA apply (and during read-only `GET .../diff`).
    - Support built-in **CEL policy rules** (default engine, zero external process/network calls, compiled and cached with bounded AST/evaluation cost budget) configured via `ConfigMap/ferriscd-policies-cm` in `ferriscd-system` or additive `AppProject.spec.policyRules[]` (`name`, `enforcement: Enforce | Warn`, `matchKinds`, `expression`, `message`).
    - Support optional embedded **OPA/Rego** evaluation (feature-gated `opa-policy` using pure-Rust `regorus`, zero network/env/filesystem builtins enabled) for teams with existing Rego libraries.
    - Classify `Enforce` violations as a terminal pre-sync refusal (`PolicyGateViolation`) with zero mutating applies and zero prunes; classify `Warn` violations as non-blocking advisories surfaced in `Application.status.conditions`.
    - Surface structured `PolicyViolationView { rule, enforcement, resourceKey, message }` in `DiffView` (`GET /api/v1/applications/{ns}/{name}/diff`), exit code `3` in `ferriscd app diff` for CI gating, and a dedicated Policy Violations banner inside `apps/ferriscd-web/src/components/DiffViewer.tsx`.
  - **Non-Functional:**
    - Policy evaluation over 100 rendered resources must complete in `< 25 ms` with strict per-expression step/fuel limits to prevent CPU exhaustion from malformed policies.
    - Policy engine never receives unredacted `Secret.data` values (evaluate `Secret` metadata/type/keys only, or redact `.data` values prior to passing to CEL/Rego).
- **Outputs:**
  - `crates/ferriscd-crd/src/project.rs` (optional additive `policyRules`) + `deploy/crds/appprojects.ferriscd.io.yaml`
  - `crates/ferriscd-engine/src/policy/gate.rs`
  - `crates/ferriscd-controller/src/sync.rs`, `crates/ferriscd-server/src/api.rs` (`DiffView.policyViolations`), `crates/ferriscd-cli/src/commands/app.rs`, `apps/ferriscd-web/src/components/DiffViewer.tsx`
- **Verification & Acceptance Criteria:**
  - Unit tests proving: (1) `Enforce` violation blocks SSA apply with 0 mutating API calls and 0 prunes; (2) `Warn` violation permits apply and surfaces warning condition; (3) `Secret.data` plaintext is redacted before policy evaluation so a buggy policy message can never exfiltrate a secret; (4) `ferriscd app diff` exits with code `3` on `Enforce` violation; (5) invalid CEL expression fails closed (`Enforce` policies cannot silently degrade to allow).
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T17.5` (crate audit for CEL/Regorus), Phase 07 (`T07.1`–`T07.5`), Phase 14 (`T14.1`, `T14.5`).
  - **Complexity:** High (5–6 hours).
  - **Risks/Trade-offs:** Running arbitrary Rego builtins (`http.send`, `opa.runtime`) would reopen SSRF/secret exfiltration vectors; explicitly disable all I/O and env builtins in the Rego evaluator.
- **Trap Guard:** **Never** pass raw `Secret.data` or `Secret.stringData` into policy error messages or evaluation contexts; never fail open when a policy rule fails to compile.

---

### `T20.3` — Progressive Delivery Evaluators & Metric-Gated Rollouts

- **Priority & Workstream:** `Optional Enhancement` · `Integrations & Extensibility` / `Core Product Capabilities`
- **Problem Statement & User/Business Value:**
  - Organizations practicing canary or blue/green delivery rely on Gateway API `HTTPRoute`, Argo Rollouts (`argoproj.io/Rollout`), or Flagger (`flagger.app/Canary`), and want FerrisCD's sync waves to accurately reflect progressive rollout health and optionally gate promotion between waves on Prometheus SLO queries (error rate / p99 latency) with automatic abort on regression.
- **Detailed Requirements:**
  - **Functional:**
    - Register three pure, I/O-free `HealthEvaluator` implementations in `crates/ferriscd-engine/src/health/` (`(group, kind)` registry):
      1. `gateway.networking.k8s.io/HTTPRoute` (checks `Accepted=True` & `ResolvedRefs=True` parent conditions + `observedGeneration`).
      2. `argoproj.io/Rollout` (handles `Healthy`, `Progressing`, `Paused -> Suspended`, `Degraded`, stale `observedGeneration`).
      3. `flagger.app/Canary` (maps `Initialized`/`Succeeded -> Healthy`, `Progressing`/`Waiting`/`Promoting -> Progressing`, `Failed -> Degraded`).
    - Add opt-in metric-gated wave promotion (`Application.spec.syncPolicy.metricGates[]`: `afterWave`, `prometheusUrl` referenced via control-plane allowlisted `ConfigMap/ferriscd-metrics-providers-cm`, `query`, `successCondition`, `intervalSeconds`, `count`, `failureAction: Pause | Rollback`).
    - Implement metric-gate progression strictly inside the **re-entrant `OperationState` state machine** (`crates/ferriscd-crd/src/status.rs` + `crates/ferriscd-controller/src/sync.rs`): record `lastCheckedAt`, `consecutiveSuccesses`, and `gatePhase` in `OperationState`, issue one bounded-timeout (`5 s`) Prometheus query per pass, and requeue cleanly — **never sleeping in a reconcile worker**.
    - On gate failure with `failureAction: Rollback`, automatically trigger the existing safe rollback path (pinning prior history revision, pausing `automated` sync, and recording a `Warning` condition + audit/notification event).
  - **Non-Functional:**
    - Prometheus provider URLs must be configured exclusively by cluster admins in `ferriscd-system` (never arbitrary tenant-supplied URLs in `ApplicationSpec` — prevents SSRF).
    - Health evaluators remain 100% pure, deterministic, and zero-I/O.
- **Outputs:**
  - `crates/ferriscd-engine/src/health/progressive.rs` (`HTTPRoute`, `Rollout`, `Canary` evaluators)
  - `crates/ferriscd-crd/src/application.rs`, `crates/ferriscd-crd/src/status.rs` (additive `metricGates` + `OperationState` gate fields)
  - `crates/ferriscd-controller/src/metric_gate.rs`
- **Verification & Acceptance Criteria:**
  - Snapshot unit tests covering all status transitions and stale `observedGeneration` guards for `HTTPRoute`, `Rollout`, and `Canary`.
  - Re-entrant state-machine tests proving: (1) multi-sample gate (`count: 3`) requires 3 passes across requeues without blocking/sleeping; (2) surviving a simulated controller restart mid-gate resumes from persisted `OperationState`; (3) metric breach triggers `Pause` or safe `Rollback` deterministically; (4) tenant `Application` cannot specify an unallowlisted Prometheus endpoint.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** Phase 09 (`T09.1`–`T09.5`), Phase 10 (`T10.1`–`T10.5`), `T17.2`, `T19.4`.
  - **Complexity:** High (6 hours).
  - **Risks/Trade-offs:** Arbitrary PromQL execution can overload Prometheus; enforce a strict `5 s` query timeout, bounded query length, and admin-configured provider allowlist.
- **Trap Guard:** Never sleep inside a reconcile worker waiting for a canary bake window (`AGENTS.md` async hygiene); never let tenant `Application` manifests inject raw outbound URLs into the metric gate client (SSRF).

---

### `T20.4` — Disaster Recovery, Backup/Export & Zero-Downtime Upgrades

- **Priority & Workstream:** `Essential Improvement` · `Reliability & Performance` / `Developer & Operator Experience`
- **Problem Statement & User/Business Value:**
  - Production operators need a tested disaster-recovery workflow to back up and restore FerrisCD control-plane state (`AppProject`, `Application`, `ApplicationSet`, `ferriscd-rbac-cm`, `ferriscd-notifications-cm`) without accidentally leaking raw cluster/repository Secret plaintext into backup archives, plus proof that upgrading FerrisCD in-place from `v1.0` → `v2.0` causes zero workload disruption or accidental pruning.
- **Detailed Requirements:**
  - **Functional:**
    - Implement `ferriscd backup export [--output bundle.yaml]` and `ferriscd backup restore <bundle.yaml> [--dry-run]` in `crates/ferriscd-cli/src/commands/backup.rs`:
      - Exports `AppProject`, `Application`, `ApplicationSet`, and control-plane `ConfigMap`s (`ferriscd-rbac-cm`, `ferriscd-notifications-cm`, `ferriscd-policies-cm`), stripping live cluster-managed fields (`status`, `resourceVersion`, `uid`, `creationTimestamp`, `managedFields`, `generation`).
      - **Secret-safe by construction:** Never exports raw `Secret.data` for `ferriscd.io/secret-type={repository,cluster,oidc,notifications}`; instead emits a manifest inventory stub listing required Secret names, namespaces, labels, and expected keys (plus optional `--encrypt-secrets-with-age <pubkey>` future extension note) so restores prompt/verify secret presence before enabling reconciliation.
      - Restores in strict dependency order (`ConfigMap`s → `AppProject`s → `ApplicationSet`s → `Application`s) using SSA (`force: false`) with `--dry-run` preview.
    - Add a CRD backward-compatibility checker (`crates/ferriscd-crd/tests/schema_compat.rs`) comparing committed `v1.0` fixture CRs and OpenAPI schemas against `v2.0` CRDs to assert zero removed fields, zero narrowed enums, and zero newly required properties.
    - Build an automated `v1.0 -> v2.0` zero-downtime upgrade test (`tests/integration/v2_0_upgrade_soak.rs`) on `kind`: install `v1.0` Helm chart with 10 active workloads, run `helm upgrade` to `v2.0`, verify zero pod restarts on managed workloads, zero unintended prunes, intact `status.inventory`, and `/readyz` gating during rolling rollout.
    - Expand `docs/operations/RUNBOOK.md` with step-by-step DR recovery and major-version upgrade playbooks.
  - **Non-Functional:**
    - Backup export/restore must be deterministic (sorted by kind/namespace/name) so diffs in GitOps DR repos are clean.
    - Export parses/validates all YAML under `parse_document` budgets during restore.
- **Outputs:**
  - `crates/ferriscd-cli/src/commands/backup.rs`
  - `crates/ferriscd-crd/tests/schema_compat.rs`
  - `tests/integration/v2_0_upgrade_soak.rs`
  - `docs/operations/RUNBOOK.md` (DR & zero-downtime upgrade runbook)
- **Verification & Acceptance Criteria:**
  - Unit tests verifying: exported bundle contains zero `Secret.data` bytes, zero `resourceVersion`/`uid`/`status` fields, deterministic ordering, and restores cleanly in dependency order via `--dry-run` and real apply.
  - `schema_compat.rs` passes in `make gate`, proving 100% `v1.0` CR deserialization and validation parity.
  - Live `kind` upgrade test confirms `v1.0 -> v2.0` `helm upgrade` completes with **0** managed-workload restarts and **0** unintended deletes.
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** `T17.1`, `T18.3`, `T19.3`, `T20.1`, `T20.2`.
  - **Complexity:** Medium (4–5 hours).
  - **Risks/Trade-offs:** Restoring `Application`s before their `AppProject`s or `Secret`s exist causes transient `Ready=False` errors; strict dependency ordering + pre-flight check verifying all referenced `ferriscd.io/secret-type=*` Secrets exist (or `--allow-missing-secrets` flag) eliminates noisy restore storms.
- **Trap Guard:** **Never** serialize raw `Secret.data` into plaintext backup files; never strip `ferriscd.io/tracking-id` or alter GKNN keys during CRD upgrades (which would trigger mass orphan pruning!).

---

### `T20.5` — Enterprise Scale & Federation Readiness (`v2.0` Release Verification)

- **Priority & Workstream:** `Essential Improvement` · `Reliability & Performance` / `Enterprise Capabilities`
- **Problem Statement & User/Business Value:**
  - `T15.3` proved `v1.0` at 50 applications / 500 resources on a single replica. Enterprise platform teams run hundreds of applications across multiple clusters and HA sharded replicas — and need both empirical proof of horizontal scaling with `DriftWatcher` + `ApplicationSet` enabled and a fleet-wide executive health overview in the Web UI before adopting `v2.0`.
- **Detailed Requirements:**
  - **Functional:**
    - Extend `benchmarks/` with a 250-application / 2,500-resource sharded multi-replica benchmark harness (3 control-plane shards via `--total-shards 3` paired with `--shard-id <0|1|2>` and `--leader-election`, `ApplicationSet` generating the fleet, `DriftWatcher` enabled, and periodic Git commits + simulated out-of-band drift).
    - Measure and document in `docs/benchmarks/v2.0.md`: cold fleet convergence time, steady-state p50/p95/p99 reconcile latency, drift-detection latency, per-shard RSS memory over a 60-minute soak (confirming flat memory curve and zero FD leaks), and API `/api/v1/applications` p95 response latency.
    - Add a **Fleet Overview Dashboard** (`/overview` or summary bar on `apps/ferriscd-web`) aggregating cross-cluster health/sync KPIs, shard/cluster breakdown, policy-violation counts, and degraded-app triage queue (strictly scoped to the caller's RBAC-visible projects).
    - Author `docs/lessons/20-progressive-delivery-policy-and-fleet-scale.md`, update `docs/lessons/README.md` to cover all 20 lessons, and execute full `v2.0` release verification (`make gate`, frontend gate, `cargo deny check`, Helm lint/template, live `kind` upgrade + E2E suites).
  - **Non-Functional:**
    - Target SLOs on benchmark reference hardware: per-shard steady-state RSS `< 150 MiB` at 250 apps / 2,500 resources; steady-state p95 reconcile latency `< 1.5 s`; `0` panics, `0` dropped/corrupted inventory entries, `0` leaked file descriptors.
- **Outputs:**
  - `benchmarks/scale_250_sharded.sh` (or Rust harness) & `docs/benchmarks/v2.0.md`
  - `apps/ferriscd-web/src/pages/FleetOverviewPage.tsx`
  - `docs/lessons/20-progressive-delivery-policy-and-fleet-scale.md` & `docs/lessons/README.md`
- **Verification & Acceptance Criteria:**
  - 60-minute 250-app / 2,500-resource 3-shard soak test meets RSS, latency, and zero-leak targets with full raw metrics recorded in `docs/benchmarks/v2.0.md`.
  - Vitest tests verify `FleetOverviewPage` displays accurate RBAC-scoped rollups and zero cross-tenant leakage.
  - Complete `v2.0` release checklist passes: `make gate`, `npm run typecheck && npm run test && npm run build`, `cargo deny check`, `ferriscd crd generate --check`, and `kind` E2E + upgrade suites. **Milestone `v2.0` Complete.**
- **Dependencies, Complexity & Risks/Trade-offs:**
  - **Dependencies:** All Phase 17–20 tasks (`T17.1`–`T20.4`).
  - **Complexity:** Medium-High (5–6 hours).
  - **Risks/Trade-offs:** Running 2,500 live pods on a single developer `kind` node can starve the kubelet; benchmark harness should use lightweight `ConfigMap`/`Service` + scaled `Deployment` mixes (clearly documented in `docs/benchmarks/v2.0.md` hardware/workload profile) so measurements reflect controller/API-server scaling rather than container image pulls.
- **Trap Guard:** Ensure fleet overview metrics strictly filter by the caller's visible projects (never leak total cluster-wide app counts to restricted tenants); verify Prometheus cardinality stays strictly bounded at 250 apps / 2,500 resources (zero per-resource or per-commit metric series).

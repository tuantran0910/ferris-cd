# Track A: Walking Skeleton & Core Controller (Phases 01–06)

> **Milestones:** M0 Walking Skeleton (Phase 01) · `v0.1` Standalone Engine (Phase 03) · `v0.2` K8s-Native Controller (Phase 06)  
> **Back to:** [ROADMAP.md](file:///Users/tranngoctuan0910/Workspaces/PersonalRepo/ferris-cd/docs/ROADMAP.md) · [MASTER_PLAN.md](file:///Users/tranngoctuan0910/Workspaces/PersonalRepo/ferris-cd/docs/MASTER_PLAN.md)

---

## Phase 01: Workspace Scaffold, CI, ADRs & Walking Skeleton *(Milestone M0 — Week 1)*

**Phase Goal:** Establish the 4-crate Cargo workspace, automated quality gates, foundational ADRs, and a live `kind` SSA apply proof of concept in Week 1.  
**Knowledge Base Lesson (`docs/lessons/01-gitops-and-ssa-walking-skeleton.md`):** OpenGitOps theory, why Server-Side Apply replaces legacy client-side 3-way merge, and hands-on `kind` experiment inspecting `metadata.managedFields` after two applies.

### `T01.1` — Initialize 4-Crate Cargo Workspace & Lint Policy
- **Why:** Establish clean crate boundaries (`crd`, `engine`, `controller`, `cli`) and strict compiler/clippy rules before writing production code so technical debt and cyclic dependencies never accumulate.
- **Detailed Requirements:**
  - Create root `Cargo.toml` with `resolver = "2"`, `edition = "2024"`, and `[workspace.dependencies]` pinning `kube = "5.1"`, `k8s-openapi = { version = "0.29", features = ["schemars"] }` (without enabling a K8s version feature in library crates!), `schemars = "1"`, `tokio = "1"`, `serde = "1"`, `serde_json = "1"`, `thiserror = "2"`, `anyhow = "1"`, `tracing = "0.1"`.
  - Enable `k8s-openapi` version feature `v1_35` **only** in binary crates (`ferriscd-cli`, `ferriscd-controller` binary target) and dev/integration test crates.
  - Configure `[workspace.lints.clippy]` to deny `unwrap_used` and `expect_used` in library/runtime code (permitted in `#[cfg(test)]`).
  - Create `rust-toolchain.toml` pinning `1.99` with `rustfmt` and `clippy`.
- **Outputs:** Root `Cargo.toml`, `rust-toolchain.toml`, and compiling skeleton crates `crates/ferriscd-crd`, `crates/ferriscd-engine`, `crates/ferriscd-controller`, `crates/ferriscd-cli`.
- **Verification:** `cargo check --workspace --all-targets` exits 0 with zero warnings.
- **Trap Guard:** Do not create 13 crates upfront (Trap T14); do not enable `k8s-openapi/v1_35` in library crates (Finding H4).

### `T01.2` — Configure CI Pipeline & Local `kind` Dev Scripts
- **Why:** Catch formatting, clippy, and test regressions from commit #1 and provide a one-command reproducible Kubernetes v1.35 cluster for every downstream experiment and integration test.
- **Detailed Requirements:**
  - Create `.github/workflows/ci.yml` running `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` with Cargo caching.
  - Create a `Makefile` (or `justfile`) with targets: `fmt`, `lint`, `test`, `kind-up` (creates `ferriscd-dev` cluster), `kind-down`, `test-integration`.
  - Add `.gitignore` covering `/target`, `.env`, local scratch caches.
- **Outputs:** `.github/workflows/ci.yml`, `Makefile`, `.gitignore`, `deploy/kind-config.yaml`.
- **Verification:** `make lint && make test && make kind-up && kubectl cluster-info --context kind-ferriscd-dev` succeeds.
- **Trap Guard:** Pin `kind` node image to match `kubectl v1.35.x` so local and CI K8s API versions stay aligned.

### `T01.3` — Write Seed ADRs (0001–0003) & Basic YAML Example Fixtures
- **Why:** Document the three most load-bearing architectural decisions before implementation begins and provide realistic Kubernetes manifests to test against.
- **Detailed Requirements:**
  - Write concise 1-page ADRs: `0001-hybrid-ssa-architecture.md`, `0002-modular-monolith-workspace.md`, `0003-gknn-inventory-and-tracking-id.md`.
  - Create `examples/basic/` containing a `Namespace`, `ConfigMap`, `Deployment` (lightweight `nginx:alpine` or `pause` image), and `Service` (ClusterIP).
- **Outputs:** `docs/adr/0001-*.md`..`0003-*.md`, `examples/basic/*.yaml`.
- **Verification:** `kubectl apply --dry-run=client -f examples/basic/` validates cleanly.
- **Trap Guard:** Avoid `Service` of `type: LoadBalancer` in `kind` fixtures (no MetalLB means LoadBalancer stays pending forever — Finding M2).

### `T01.4` — Implement Minimal `ferriscd apply-file` Walking Skeleton
- **Why:** Prove the full Rust -> `kube 5.x` -> `Discovery` -> `DynamicObject` -> Server-Side Apply pipeline against live `kind` in Week 1 before building larger abstractions.
- **Detailed Requirements:**
  - Add a temporary/utility `apply-file <path> --namespace <ns>` subcommand in `ferriscd-cli`.
  - Read a single YAML manifest into `DynamicObject`, run `kube::Discovery::new(client).run()`, resolve `(ApiResource, ApiCapabilities)` matching `apiVersion` + `kind`.
  - Execute `Api::patch(name, &PatchParams::apply("ferriscd"), &Patch::Apply(&obj))` with `force: false`.
  - Print applied resource GKNN, `resourceVersion`, and active `managedFields` managers.
- **Outputs:** Working `ferriscd-cli/src/main.rs` + `apply-file` handler.
- **Verification:** Run `cargo run -p ferriscd-cli -- apply-file examples/basic/configmap.yaml --namespace default` twice against `kind`; second run succeeds with zero errors and `kubectl get cm -o yaml --show-managed-fields` shows `manager: ferriscd`.
- **Trap Guard:** Keep `force: false` by default so SSA conflict semantics are observed immediately (Trap T5).

### `T01.5` — Author Phase 01 Lesson & Experiment
- **Why:** Fulfill the dual-deliverable Knowledge Base goal while the fresh SSA mechanics are top of mind.
- **Detailed Requirements:**
  - Write `docs/lessons/01-gitops-and-ssa-walking-skeleton.md` covering OpenGitOps principles, CSA vs. SSA, `managedFields`, and a step-by-step `kind` experiment demonstrating a field conflict when `kubectl edit` modifies a field owned by `ferriscd`.
- **Outputs:** `docs/lessons/01-gitops-and-ssa-walking-skeleton.md`.
- **Verification:** Every command in the lesson runs cleanly against `kind-ferriscd-dev`.
- **Trap Guard:** Keep the lesson focused and empirical—cite real observed `managedFields` YAML from `kind`.

---

## Phase 02: Git Repository Engine

**Phase Goal:** Build a safe, concurrency-proof, pure-Rust Git acquisition engine behind a mockable `GitClient` trait, defending against worktree symlink escapes before any manifest is parsed.  
**Knowledge Base Lesson (`docs/lessons/02-git-internals-and-repo-caching.md`):** Git protocol v2, shallow packfiles, ref resolution vs. immutable commit SHAs, and worktree isolation under concurrent reconciles.

### `T02.1` — Define `GitClient` Trait, Domain Types & Error Classification
- **Why:** Decouple the entire GitOps engine from `gix` internals so unit/contract tests can swap in fast deterministic fakes and transport backends can evolve safely.
- **Detailed Requirements:**
  - Define `GitSource { repo_url, target_revision, path }`, `ResolvedRevision { commit_sha: String, requested_ref: String }`, `RepoCheckout { root_dir: PathBuf, commit_sha: String }`, and `RepoCredentials` (`Anonymous`, `HttpToken`, `HttpBasic`, `SshKey { private_key_pem, passphrase, known_hosts }`).
  - Implement custom `Debug` on `RepoCredentials` that prints `[REDACTED]` for all secret fields.
  - Define `RepoError` (`thiserror`) with `is_retryable(&self) -> bool` separating network/auth-timeout/5xx (retryable) from invalid URL/unknown revision/symlink escape (terminal).
  - Define async `GitClient` trait: `resolve_revision(&self, src, creds)` and `checkout(&self, src, sha, creds)`.
- **Outputs:** `crates/ferriscd-engine/src/repo/mod.rs`, `types.rs`, `error.rs`.
- **Verification:** Unit tests verifying `RepoCredentials` `Debug` output never leaks tokens/keys, URL validation rejects `file://` in production mode unless explicitly allowed for tests, and error classification truth table passes.
- **Trap Guard:** Never leak `gix` error or repo structs in public trait signatures.

### `T02.2` — Implement `GixGitClient` Core (Local & HTTPS Clone, Shallow Fetch, Ref Resolution)
- **Why:** Implement the core Git acquisition layer using pure-Rust `gix` without blocking Tokio async workers.
- **Detailed Requirements:**
  - Implement `GixGitClient` supporting `https://` (via `rustls`) and local paths (for tests).
  - Resolve branches (`refs/heads/*`), tags (`refs/tags/*`, including annotated tags peeled to commit OIDs), `HEAD`, and full 40-char commit SHAs into canonical 40-char hex `commit_sha`.
  - Support shallow fetch (`depth = 1`) for branch/tag tips with fallback fetch for specific commit SHAs.
  - Wrap all blocking `gix` disk/network operations inside `tokio::task::spawn_blocking`.
- **Outputs:** `crates/ferriscd-engine/src/repo/gix_client.rs`.
- **Verification:** Integration test initializing a temp bare Git repo with branches, lightweight/annotated tags, and multiple commits; verifies resolution and checkout of each ref type.
- **Trap Guard:** Never run `gix` I/O directly on Tokio worker threads; always peel annotated tags to their underlying commit SHA.

### `T02.3` — Add Per-Repo Concurrency Lock & Commit-Keyed Worktree Cache
- **Why:** Multiple `Application` CRs frequently point to the same monorepo at different paths or revisions; sharing a mutable working directory causes race conditions and corrupted checkouts.
- **Detailed Requirements:**
  - Maintain a bare mirror/object store per normalized `repo_url` protected by a per-repo async mutex (`DashMap<String, Arc<tokio::sync::Mutex<()>>>`).
  - Materialize immutable read-only worktrees keyed by `(repo_hash, commit_sha)` via atomic write-to-tempdir + rename so concurrent readers never observe partial checkouts.
  - Add bounded LRU/TTL garbage collection (`max_entries`, `max_age`) that skips worktrees currently held by an active checkout handle (RAII guard / refcount).
- **Outputs:** `crates/ferriscd-engine/src/repo/cache.rs`.
- **Verification:** Concurrency test spawning 16 simultaneous Tokio tasks fetching the same repo at 3 different commits—zero corruption, zero panics, cache hit verified on repeat checkout.
- **Trap Guard:** Never delete a cached commit directory while another reconcile task holds a handle to it.
- **Follow-up:** The persistent per-URL bare mirror/object store is tracked as `T02.7`; this task delivers the per-repo async lock and commit-keyed worktree cache only.

### `T02.4` — Implement HTTPS Token Auth & SSH Key Transport with `known_hosts`
- **Why:** Production GitOps repositories are private; SSH auth via `gix` spawns `/usr/bin/ssh` and requires strict host-key verification and safe temporary key handling.
- **Detailed Requirements:**
  - Wire HTTPS Basic/Bearer credentials into `gix` credential callbacks without embedding secrets in URLs or `.git/config`.
  - Wire SSH credentials by writing the private key to an ephemeral file (`0600` permissions) in a dedicated scratch directory, passing `GIT_SSH_COMMAND` with `-i <tmpkey> -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<known_hosts_file>`, and zeroizing/deleting the temp key file on drop (RAII `TempKeyGuard`).
  - Reject SSH connections when `known_hosts` is missing (unless an explicit insecure dev flag is enabled in tests).
- **Outputs:** `crates/ferriscd-engine/src/repo/auth.rs`.
- **Verification:** Unit tests verifying RAII temp key file creation (`0600` mode), deletion on drop/panic, and `GIT_SSH_COMMAND` quoting/escaping; integration test against local HTTPS/SSH fixture.
- **Trap Guard:** Fixes Finding C6 (`gix` SSH transport + `known_hosts` MITM defense + ephemeral `0600` keys).

### `T02.5` — Implement Worktree-Wide Symlink Sanitizer
- **Why:** Even if the Plain YAML parser checks paths, future renderers (`kustomize`, `helm`) run directly on the checked-out directory—a symlink like `values.yaml -> /var/run/secrets/kubernetes.io/serviceaccount/token` would otherwise exfiltrate cluster secrets.
- **Detailed Requirements:**
  - Immediately after materializing any checkout in `RepoCache` (before returning `RepoCheckout`), recursively walk the entire checkout tree.
  - Reject (fail checkout with terminal `RepoError::UnsafeSymlink`) any symlink whose canonical target escapes `root_dir` or points to an absolute path outside `root_dir`.
  - Enforce configurable limits on total worktree files and bytes to prevent checkout-bomb DoS.
- **Outputs:** `crates/ferriscd-engine/src/repo/sanitize.rs`.
- **Verification:** Unit tests creating a Git commit containing (a) valid intra-repo symlink, (b) symlink to `/etc/passwd`, (c) chained relative `../../` symlink escape—verifying (a) passes and (b)/(c) fail cleanly before returning `RepoCheckout`.
- **Trap Guard:** Neutralizes Finding C7 symlink escape across **all** renderers (Plain YAML, Kustomize, and Helm).

### `T02.6` — Build `FakeGitClient` Test Harness & Phase 02 Lesson
- **Why:** Every downstream phase (Phases 03–15) needs fast, zero-network deterministic Git fixtures simulating commits, rollbacks, and outages.
- **Detailed Requirements:**
  - Build `FakeGitClient` supporting programmatic commits (`add_commit(branch, files)`), switching refs, and injecting transient/terminal fetch failures.
  - Write `docs/lessons/02-git-internals-and-repo-caching.md` with an experiment demonstrating concurrent monorepo checkouts and symlink escape rejection.
- **Outputs:** `crates/ferriscd-engine/src/repo/fake.rs`, `docs/lessons/02-git-internals-and-repo-caching.md`.
- **Verification:** Unit tests verifying `FakeGitClient` revision switching and simulated outage injection.
- **Trap Guard:** Expose `FakeGitClient` under a `test-utils` Cargo feature so downstream crates (`ferriscd-controller`, `tests/integration`) can reuse it cleanly.

### `T02.7` — Persistent Per-URL Bare Mirror / Object Store *(Follow-up to `T02.3`)*
- **Why:** `RepoCache` serializes acquisition per normalized `repo_url` but delegates each materialization to a `GitClient` that re-fetches into a fresh temporary bare repository; monorepos resolving many commits re-download shared objects. A persistent per-URL bare mirror makes the per-repo lock pay off and cuts network/disk churn.
- **Detailed Requirements:**
  - Extend `GitClient`/`GixGitClient` so a checkout can be materialized from a persistent bare repository keyed by normalized `repo_url` under `work_root/mirrors/<repo_hash>`, while keeping `gix` types out of public trait signatures.
  - Initialize/fetch the mirror once per `(repo_url, credential generation)`; preserve the existing shallow-then-fallback behavior and annotated-tag peeling.
  - Serialize mirror updates under the existing per-repo async lock; never run blocking `gix` I/O on Tokio workers.
  - Define mirror reclamation (unused mirrors, size bounds) and keep the commit-keyed worktree cache crash-safe.
- **Outputs:** `crates/ferriscd-engine/src/repo/mirror.rs`, updates to `gix_client.rs`, `cache.rs`, and `GitClient` trait docs.
- **Verification:** Integration test resolving/checking out 3 commits from one repository performs exactly one network fetch, reuses the mirror, and preserves T02.2 ref/tag/fallback behavior; the T02.3 concurrency test still passes.
- **Trap Guard:** Do not leak `gix` repo structs through the `GitClient` abstraction; keep all blocking mirror I/O inside `spawn_blocking`; a failed mirror update must never delete a usable existing mirror.

---

## Phase 03: Manifest Engine (YAML 1.2 & Offline Normalization) — *Milestone `v0.1` Complete*

**Phase Goal:** Parse multi-document YAML 1.2 directories into validated, normalized Kubernetes objects with YAML-bomb protection, `v1/List` flattening, `Secret.stringData` conversion, and deliver the standalone `v0.1` `ferriscd apply` CLI.  
**Knowledge Base Lesson (`docs/lessons/03-kubernetes-manifests-yaml-and-normalization.md`):** YAML 1.2 vs 1.1 traps, `v1/List`, `Secret.stringData` write-only semantics, and offline vs. cluster-aware normalization.

### `T03.1` — Define Version-Agnostic `ResourceKey` (GKNN) & `DesiredResource`
- **Why:** Resource identity must survive Kubernetes API version upgrades (`networking.k8s.io/v1beta1` -> `v1`) without causing self-pruning.
- **Detailed Requirements:**
  - Define `ResourceKey { group: String, kind: String, namespace: Option<String>, name: String }` implementing `Eq`, `Hash`, `Ord` strictly over **GKNN** (omitting `version`!).
  - Define `GroupVersionKind { group: String, version: String, kind: String }` parsed cleanly from `apiVersion` (`"v1"` -> `group: "", version: "v1"`; `"apps/v1"` -> `group: "apps", version: "v1"`).
  - Define `DesiredResource { key: ResourceKey, gvk: GroupVersionKind, object: DynamicObject, source_file: String }` plus canonical GKNN string formatting (`<group>/<kind>/<ns>/<name>`).
- **Outputs:** `crates/ferriscd-engine/src/manifest/types.rs`.
- **Verification:** Unit tests proving `v1beta1` and `v1` of the same `Ingress` produce identical `ResourceKey` hashes and equality, while different groups/kinds/namespaces differ.
- **Trap Guard:** Fixes Finding C2 (API/CRD version upgrade self-pruning catastrophe).

### `T03.2` — Implement Multi-Document YAML 1.2 Parser (`serde-saphyr`) with Budgets & `v1/List` Flattening
- **Why:** Real Kubernetes manifests use multi-doc `---` streams, empty commented docs, `v1/List` wrappers, and untrusted YAML can carry billion-laughs anchor bombs.
- **Detailed Requirements:**
  - Parse YAML streams via `serde-saphyr::from_multiple` configured with strict parser **budgets** (max aliases, max depth, max nodes/bytes) and duplicate-key rejection.
  - Deserialize each document into `Option<serde_json::Value>`; silently skip `None` and `Value::Null` documents.
  - Recursively flatten any object whose `kind == "List"` (or `*List` with an `items` array) into individual child objects.
  - Validate every resulting object has non-empty `apiVersion`, `kind`, and either `metadata.name` OR (`metadata.generateName` allowed only when hook annotation `ferriscd.io/hook` is present).
  - Return clear errors including file path and 1-based document index.
- **Outputs:** `crates/ferriscd-engine/src/manifest/yaml.rs`.
- **Verification:** Fixture tests: multi-doc stream, trailing `---`, comment-only doc, `v1/List` with nested items, YAML-bomb (billion laughs) rejected by budget, duplicate key rejected, non-string map key error handling, YAML 1.2 `on`/`off`/`0123` preserved as strings.
- **Trap Guard:** Fixes Trap T13, Finding H2 (`v1/List` & `generateName`), and Finding M4 (`serde-saphyr` budgets).

### `T03.3` — Implement Safe Directory Walker for Manifest Paths
- **Why:** Collect all `.yaml`, `.yml`, and `.json` files under `spec.source.git.path` deterministically while verifying the target path stays jailed inside the checkout root.
- **Detailed Requirements:**
  - Canonicalize `checkout.root_dir.join(source.path)` and assert `starts_with(&checkout.root_dir)`.
  - Support both single-file and directory `path` targets (matching Argo CD behavior).
  - Sort discovered files deterministically by relative path; ignore hidden dot-directories (`.git/`) and non-manifest files; enforce max file count and total bytes read.
- **Outputs:** `crates/ferriscd-engine/src/manifest/loader.rs`.
- **Verification:** Unit tests for deterministic ordering, single-file vs directory paths, missing path error, and `../../` escape rejection.
- **Trap Guard:** Double-defense alongside `T02.5` worktree sanitizer (Trap T11).

### `T03.4` — Implement Offline Manifest Normalizer
- **Why:** Strip server-managed fields and convert write-only fields before diffing/applying—explicitly deferring `destination.namespace` injection to the cluster-aware stage (since offline code cannot know whether a custom CRD is cluster-scoped!).
- **Detailed Requirements:**
  - Strip top-level `.status` field from every desired object.
  - Strip server-owned metadata fields: `uid`, `resourceVersion`, `generation`, `creationTimestamp`, `managedFields`, `selfLink`.
  - For `v1/Secret`, convert any `stringData` entries into base64-encoded entries merged into `.data` (with `stringData` taking precedence over duplicate keys in `.data`, matching Kubernetes API server semantics) and remove `stringData`.
  - Detect and reject duplicate `ResourceKey`s within the same manifest set (with both source file names in the error).
- **Outputs:** `crates/ferriscd-engine/src/manifest/normalize.rs`.
- **Verification:** Unit tests covering `Secret.stringData` + `.data` merge precedence, `.status` stripping, server metadata removal, and duplicate GKNN detection.
- **Trap Guard:** Fixes Trap T4 (`Secret.stringData` phantom drift) and Finding H1 (never guess cluster vs namespaced scope offline!).

### `T03.5` — Implement Minimal Dependency Tier Sorter (Foundation for `v0.1` & `v0.2`)
- **Why:** Even in `v0.1` and `v0.2`, applying a multi-file repo containing a `Namespace` + `Deployment` fails flakily if filesystem order puts the `Deployment` first.
- **Detailed Requirements:**
  - Implement a minimal, deterministic 4-tier sort function: Tier 0 (`Namespace`), Tier 1 (`CustomResourceDefinition`), Tier 2 (`ServiceAccount`, `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`, `ConfigMap`, `Secret`), Tier 3 (everything else), with deterministic tie-breaking by `ResourceKey`.
  - Designed to be expanded cleanly into the full wave/hook graph in Phase 08/10.
- **Outputs:** `crates/ferriscd-engine/src/graph/mod.rs` (minimal tier sorter).
- **Verification:** Unit test feeding reversed manifests (`Deployment`, `Service`, `ConfigMap`, `CRD`, `Namespace`) and asserting exact deterministic output order.
- **Trap Guard:** Fixes Finding H9 (`v0.2` flaky multi-file apply ordering).

### `T03.6` — Wire Standalone `v0.1` CLI (`ferriscd apply`) & Phase 03 Lesson
- **Why:** Deliver the first end-to-end working GitOps milestone (`v0.1`) proving Git -> YAML 1.2 -> Normalizer -> Discovery-aware scope injection -> Ordered SSA Apply on `kind`.
- **Detailed Requirements:**
  - Implement `ferriscd apply --repo <url-or-path> --rev <ref> --path <dir> --namespace <ns>` in `ferriscd-cli`.
  - Resolve each object's `Scope` via `kube::Discovery`, inject `--namespace` only for `Scope::Namespaced` objects lacking a namespace, sort with minimal tier sorter, and SSA-apply (`Patch::Apply`, `force: false`).
  - Write `docs/lessons/03-kubernetes-manifests-yaml-and-normalization.md`.
- **Outputs:** `crates/ferriscd-cli/src/commands/apply.rs`, `tests/integration/v0_1_apply.rs`, `docs/lessons/03-kubernetes-manifests-yaml-and-normalization.md`.
- **Verification:** Live `kind` integration test applying `examples/basic` from a local Git repo; second run is idempotent; `Namespace` + `Deployment` + `Service` all live and Ready. **Milestone `v0.1` Complete.**
- **Trap Guard:** Validates cluster-scoped vs namespaced handling against real Kubernetes Discovery.

---

## Phase 04: Declarative CRDs (`Application` & `AppProject`)

**Phase Goal:** Define schema-validated Kubernetes CRDs (`ferriscd.io/v1alpha1`) with unrepresentable invalid states, compact GKNN inventory, `OperationState`, and `/status` subresources.  
**Knowledge Base Lesson (`docs/lessons/04-crd-design-openapi-and-etcd-limits.md`):** Designing Kubernetes APIs in Rust with `kube::CustomResource` + `schemars 1`, status subresources, printer columns, and `etcd` 1.5 MiB object limits.

### `T04.1` — Define `ApplicationSpec` with Type-Safe SyncPolicy & Multi-Tenancy Fields
- **Why:** Lock in a clean, forward-compatible CRD schema where invalid states (like `selfHeal: true` with `automated: false`) are impossible and future security/renderer fields don't require breaking schema migrations.
- **Detailed Requirements:**
  - Define `Application` (`#[derive(CustomResource, ...)]`, `group = "ferriscd.io"`, `version = "v1alpha1"`, `kind = "Application"`, `namespaced`, `status = "ApplicationStatus"`).
  - Model `SyncPolicy.automated: Option<AutomatedSyncPolicy> { prune: bool, self_heal: bool }`.
  - Include `project: String` (default `"default"`), `service_account_name: Option<String>`, structured `SourceSpec { git: GitSourceSpec, renderer: RendererSpec }`, `DestinationSpec { cluster: String, namespace: String }`, `SyncOptions` (`create_namespace`, `prune_last`, `prune_crds: false`, `prune_namespaces: false`, `server_side_force: false`, `apply_out_of_sync_only: true`, `takeover_field_managers`), `ignore_differences`, `requeue_after_seconds` (default 180), `revision_history_limit` (validated `1..=20`).
  - Document control annotations constants (`REFRESH`, `OPERATION`, `CASCADE_DELETE`, `FORCE_DELETE`, `TRACKING_ID`, `SYNC_WAVE`, `HOOK`, `HOOK_DELETE_POLICY`, `SYNC_OPTIONS`, `PRUNE`).
- **Outputs:** `crates/ferriscd-crd/src/application.rs`, `crates/ferriscd-crd/src/annotations.rs`.
- **Verification:** Unit tests for YAML serialization/deserialization, defaults, and schema generation validating `revisionHistoryLimit` bounds.
- **Trap Guard:** Makes invalid `automated`/`selfHeal` combinations unrepresentable; defines all control annotations in one canonical module (Fixes Finding C5 annotation omission).

### `T04.2` — Define `ApplicationStatus`, Compact GKNN Inventory & `OperationState`
- **Why:** Provide structured observability, crash-safe inventory persistence, and re-entrant multi-wave state without ever threatening Kubernetes's 1.5 MiB `etcd` object limit.
- **Detailed Requirements:**
  - Define `ApplicationStatus` with `observed_generation: Option<i64>`, `conditions: Vec<Condition>` (K8s `metav1.Condition`-compatible), `sync: Option<SyncState>` (including `revision`, `last_synced_revision`, `last_synced_spec_hash`, `last_synced_at`), `health: Option<HealthState>`, `inventory: Vec<InventoryEntry> { key: String, version: String }`, `operation_state: Option<OperationState>`, `history: Vec<RevisionHistoryEntry>`, and bounded per-resource status summary.
  - Add helper methods for standard `Ready` / `SyncError` condition transitions preserving `lastTransitionTime` when status is unchanged.
- **Outputs:** `crates/ferriscd-crd/src/status.rs`.
- **Verification:** Unit test generating an `ApplicationStatus` with 500 inventory entries and 20 history entries and asserting serialized JSON is <100 KB; condition transition tests verify `lastTransitionTime` stability.
- **Trap Guard:** Fixes Trap T9 (`etcd` size), Finding C2 (GKNN key + version hint), and Finding H7 (`last_synced_spec_hash`).

### `T04.3` — Define `AppProject` CRD with Explicit Allow-Lists & `sourceNamespaces`
- **Why:** Establish the multi-tenancy boundary schema early—including both `clusterResourceWhitelist` and `namespaceResourceWhitelist` plus `sourceNamespaces` for Phase 12's Apps-in-any-namespace.
- **Detailed Requirements:**
  - Define `AppProject` (`namespaced` in `ferriscd-system`) with `description`, `source_repos: Vec<String>`, `source_namespaces: Vec<String>` (default `["ferriscd-system"]`), `destinations: Vec<ProjectDestination> { cluster, namespace }`, `cluster_resource_whitelist: Vec<GroupKind>`, `namespace_resource_whitelist: Vec<GroupKind>`, `namespace_resource_blacklist: Vec<GroupKind>`, and `allowed_service_accounts: Vec<String>`.
  - Provide a canonical `default` `AppProject` manifest in `deploy/manifests/default-project.yaml` and define `PermissivePolicy` stub behavior for Phases 05–11.
- **Outputs:** `crates/ferriscd-crd/src/project.rs`, `deploy/manifests/default-project.yaml`.
- **Verification:** Unit tests for YAML round-trip and OpenAPI schema generation.
- **Trap Guard:** Fixes Finding M6 (adds `namespaceResourceWhitelist` + defines `default` project) and Finding C8 (`allowedServiceAccounts` + `sourceNamespaces`).

### `T04.4` — Build CRD YAML Generator, Printer Columns & Phase 04 Lesson
- **Why:** Generate deterministic, git-committed CRD YAML manifests with `kubectl get apps` printer columns and validate them against a live Kubernetes v1.35 API server.
- **Detailed Requirements:**
  - Add `ferriscd crd generate` command (or `xtask`) emitting `deploy/crds/applications.ferriscd.io.yaml` and `deploy/crds/appprojects.ferriscd.io.yaml`.
  - Configure `additionalPrinterColumns` on `Application`: `SYNC`, `HEALTH`, `REVISION`, `AGE`.
  - Write `docs/lessons/04-crd-design-openapi-and-etcd-limits.md` with a `kind` experiment verifying OpenAPI validation rejects malformed `Application` specs and `/status` updates do not bump `metadata.generation`.
- **Outputs:** `deploy/crds/*.yaml`, generator subcommand, `docs/lessons/04-crd-design-openapi-and-etcd-limits.md`.
- **Verification:** `kubectl apply --server-side -f deploy/crds/` succeeds on `kind`; invalid CR rejected with 422; `kubectl get apps` shows custom columns.
- **Trap Guard:** Verify generated CRD contains `subresources.status: {}` (Trap T2).

---

## Phase 05: Kubernetes-Native Controller Runtime

**Phase Goal:** Build the resilient `kube-rs` controller runtime with refreshable `DiscoveryCache`, composite watch predicates (zero missed deletions/operations, zero status loops), deadlock-safe finalizers, cluster-aware scope normalization, and always-update-status error handling.  
**Knowledge Base Lesson (`docs/lessons/05-kube-controller-runtime-predicates-and-finalizers.md`):** Reflectors, workqueues, why bare `predicates::generation` drops deletion/finalizer events, and safe finalizer patterns.

### `T05.1` — Implement `DiscoveryCache` with Explicit Invalidation & Refresh
- **Why:** Resolving dynamic GVKs per reconcile without caching hammers the API server, while caching forever breaks when a new CRD is installed mid-sync.
- **Detailed Requirements:**
  - Implement `DiscoveryCache` wrapping `Arc<tokio::sync::RwLock<CachedDiscovery>>` with configurable TTL (default 5 min) and `resolve(&Gvk) -> Result<(ApiResource, ApiCapabilities), DiscoveryError>`.
  - Expose `invalidate_and_refresh(&self)` (coalesced via singleflight/mutex so concurrent misses trigger one refresh, not 50) and `kube_version(&self) -> String` (for Phase 11 Helm `--kube-version`).
- **Outputs:** `crates/ferriscd-controller/src/discovery.rs`.
- **Verification:** Live `kind` integration test resolving `v1/ConfigMap`, `apps/v1/Deployment`, then installing a brand-new test CRD, calling `invalidate_and_refresh()`, and resolving the new CRD cleanly.
- **Trap Guard:** Required by CRD+CR single-sync (Trap T6) and Helm `--kube-version` (Finding H3).

### `T05.2` — Implement Composite Watch Predicate & `kube-rs` Controller Loop
- **Why:** Prevent infinite reconcile loops on `/status` patches *without* accidentally swallowing finalizer, deletion, or control-annotation updates.
- **Detailed Requirements:**
  - Build a custom watch predicate hashing `(metadata.generation, metadata.deletion_timestamp, metadata.finalizers, annotations[REFRESH, OPERATION, CASCADE_DELETE, FORCE_DELETE])`.
  - Wire `kube_runtime::Controller::new(apps_api, watcher::Config::default())` scoped to controller namespace (`ferriscd-system` by default) with bounded concurrency (`Config::default().concurrency(N)`).
  - Add `error_policy` computing exponential backoff for retryable errors and longer fixed backoff for terminal errors.
- **Outputs:** `crates/ferriscd-controller/src/predicate.rs`, `crates/ferriscd-controller/src/controller.rs`.
- **Verification:** Live `kind` integration test proving: (1) patching `/status` triggers **0** extra reconciles, (2) annotating `ferriscd.io/refresh` triggers immediately, (3) `kubectl delete app` triggers cleanup immediately.
- **Trap Guard:** Fixes Finding C4 (`predicates::generation` swallowing deletion/finalizer/operation events) and Trap T2.

### `T05.3` — Implement Finalizer Gate (with Escape Hatch) & Always-Update-Status Wrapper
- **Why:** Ensure every failure is surfaced visibly on `Application.status.conditions` and deleting an `Application` never wedges permanently in `Terminating`.
- **Detailed Requirements:**
  - Wrap reconcile in `kube_runtime::finalizer(&apps_api, "ferriscd.io/finalizer", app, ...)`.
  - In `Cleanup`: default to non-cascading orphan deletion unless `ferriscd.io/cascade-delete: "true"`. Treat `404`/`410`/`NoMatchesForKind` as already deleted. If `ferriscd.io/force-delete: "true"` or target cluster secret is missing, log/record warning and release finalizer.
  - Wrap `Apply` core pipeline so both `Ok(outcome)` and `Err(err)` execute `patch_status` (`Api::patch_status`) updating `observedGeneration` and `conditions` (`Ready=False, reason=...` on error) before returning.
- **Outputs:** `crates/ferriscd-controller/src/reconcile.rs`.
- **Verification:** Live `kind` test: (1) broken repo URL sets `Ready=False` with actionable message in `status.conditions`; (2) deleting `Application` cleanly removes finalizer; (3) `force-delete=true` releases finalizer even when cleanup hook simulates failure.
- **Trap Guard:** Fixes Trap T3 (silent failure) and Finding C5 (finalizer deadlock).

### `T05.4` — Implement Cluster-Aware Scope Normalizer
- **Why:** Correctly inject `spec.destination.namespace` onto namespaced resources while leaving cluster-scoped built-ins and custom CRDs untouched—fixing the offline-vs-online boundary.
- **Detailed Requirements:**
  - Implement `normalize_scopes(resources, destination_ns, &discovery, &in_bundle_crds)`:
    - Look up GVK scope in `DiscoveryCache`; if missing, inspect any `CustomResourceDefinition` in `resources` matching that group+kind (`spec.scope: Namespaced | Cluster`).
    - For `Scope::Namespaced`: if `metadata.namespace` is absent/empty, inject `destination_ns` and update `ResourceKey.namespace`.
    - For `Scope::Cluster`: if `metadata.namespace` is non-empty, return a clear validation error (or strip if explicitly configured); keep `ResourceKey.namespace = None`.
- **Outputs:** `crates/ferriscd-controller/src/scope.rs`.
- **Verification:** Unit + `kind` integration tests covering namespaced `Deployment` (gets default ns), namespaced `Deployment` with explicit ns (preserved), cluster-scoped `ClusterRole` (no ns injected), and in-bundle cluster-scoped CRD + CR.
- **Trap Guard:** Fixes Finding H1 (offline normalizer guessing cluster-scoped CRDs).

### `T05.5` — Add Graceful Shutdown, Structured Tracing & Phase 05 Lesson
- **Why:** Clean pod restarts in Kubernetes require draining active reconciles on `SIGTERM` instead of corrupting half-finished API sequences, and structured spans make debugging multi-app concurrency tractable.
- **Detailed Requirements:**
  - Wire `tokio::signal` (`SIGINT`/`SIGTERM`) into `Controller::graceful_shutdown_on` with configurable drain timeout.
  - Instrument reconcile with `tracing::info_span!("reconcile", app.namespace, app.name, app.generation)` and JSON/pretty log toggle (`FERRISCD_LOG_FORMAT`).
  - Write `docs/lessons/05-kube-controller-runtime-predicates-and-finalizers.md`.
- **Outputs:** Shutdown wiring in `crates/ferriscd-controller/src/lib.rs`, `docs/lessons/05-kube-controller-runtime-predicates-and-finalizers.md`.
- **Verification:** Send `SIGTERM` to running controller process during active reconcile; verify clean drain and exit code 0.
- **Trap Guard:** Never drop an active status-patch future abruptly on shutdown.

---

## Phase 06: Inventory & Live State Engine — *Milestone `v0.2` Complete*

**Phase Goal:** Track every resource owned by an `Application` using crash-safe GKNN inventory + `tracking-id` annotations, fetch true live state (`desired ∪ prev_inventory`), and complete the `v0.2` Kubernetes-native controller.  
**Knowledge Base Lesson (`docs/lessons/06-inventory-tracking-and-live-state.md`):** Why `desired`-only live fetching breaks pruning, GKNN vs. GVKNN version upgrades, and ownership tracking defense against cross-app hijacking.

### `T06.1` — Implement `ferriscd.io/tracking-id` Stamper & Ownership Classifier
- **Why:** Without an ownership marker on live Kubernetes objects, two `Application` CRs pointing at the same resource will fight infinitely and potentially prune each other's workloads.
- **Detailed Requirements:**
  - Format `tracking-id` as `<app-ns>/<app-name>:<group>/<kind>:<res-ns>/<res-name>` (version-agnostic!).
  - Stamp `ferriscd.io/tracking-id` onto `metadata.annotations` of every desired resource (excluding `PreSync`/`PostSync` hooks).
  - Implement `classify_ownership(live_obj, expected_tracking_id) -> Ownership { OwnedBySelf, Unmanaged, OwnedByForeign(String) }`.
- **Outputs:** `crates/ferriscd-engine/src/inventory/tracking.rs`.
- **Verification:** Unit tests for stamping, parsing, cluster-scoped formatting, and all 3 ownership states (including malformed annotation strings).
- **Trap Guard:** Fixes Trap T10 (cross-application hijacking) and keeps `tracking-id` consistent with version-agnostic GKNN (Finding C2).

### `T06.2` — Implement Crash-Safe GKNN Inventory Set Math
- **Why:** Partial apply failures and partial prune failures must never drop live cluster resources out of `status.inventory` (which would leak permanent orphans).
- **Detailed Requirements:**
  - Implement pure inventory algebra over `BTreeMap<ResourceKey, InventoryEntry>`:
    - `to_fetch(desired, prev_inventory) = desired_keys ∪ prev_inventory_keys`
    - `orphans(desired, prev_inventory) = prev_inventory_keys \ desired_keys`
    - `next_inventory(prev_inventory, applied_ok, pruned_ok) = (prev_inventory \ pruned_ok) ∪ applied_ok` (updating version hint for entries in `applied_ok`).
  - Serialize deterministically (sorted by `ResourceKey`) so `/status` patches don't churn on map iteration order.
- **Outputs:** `crates/ferriscd-engine/src/inventory/mod.rs`.
- **Verification:** Unit + property tests verifying: (1) failed apply of an existing resource **preserves** it in `next_inventory`, (2) failed prune of an orphan **preserves** it in `next_inventory`, (3) `v1beta1` -> `v1` upgrade updates version hint with 0 orphans produced, (4) output order is deterministic.
- **Trap Guard:** Fixes Finding C1 (inventory leak on partial apply failure), Finding C2 (version-upgrade self-prune), and Trap T8.

### `T06.3` — Implement Union Live State Fetcher (`ClusterStateReader`)
- **Why:** Query Kubernetes for the exact live state of all desired + previously managed resources with bounded concurrency and graceful handling of missing resources, missing namespaces, and uninstalled CRDs.
- **Detailed Requirements:**
  - Implement `ClusterStateReader::fetch_live(to_fetch, &discovery, &in_bundle_crds, &in_bundle_namespaces, create_namespace)` using `futures::stream::iter(...).buffer_unordered(16)`.
  - Classify each key into `LiveState`: `Present(DynamicObject, Ownership)`, `Missing`, `DeferredPendingCrd` (GVK absent from `Discovery` but defined by a CRD in `desired`), `DeferredPendingNamespace` (namespace `404` but `create_namespace` or `Namespace` manifest is in `desired`), or `OrphanGvkGone` (orphan's CRD was already deleted).
- **Outputs:** `crates/ferriscd-controller/src/live_state.rs`.
- **Verification:** Live `kind` integration test: apply 2 ConfigMaps, remove 1 from Git, confirm `ClusterStateReader` still fetches the removed ConfigMap via `status.inventory` and returns `Present(..., OwnedBySelf)`.
- **Trap Guard:** Fixes Trap T1 (`desired`-only fetch) and prepares clean inputs for Finding C3 (deferred dry-run).

### `T06.4` — Wire End-to-End `v0.2` Controller & Phase 06 Lesson
- **Why:** Deliver `v0.2`: a real, continuously reconciling Kubernetes controller driven by `Application` CRs on `kind`.
- **Detailed Requirements:**
  - Wire Phases 02–06 together in `ferriscd-controller`: Watch `Application` -> `Repo` -> `Manifest` -> `ScopeNormalizer` -> `ClusterStateReader` -> Ordered SSA Apply (basic `v0.2` sync, rejecting `OwnedByForeign`) -> Crash-safe Inventory + `/status` patch.
  - Add `ferriscd controller` subcommand to `ferriscd-cli`.
  - Write `docs/lessons/06-inventory-tracking-and-live-state.md`.
- **Outputs:** End-to-end `v0.2` controller runnable via `cargo run -p ferriscd-cli -- controller`, `tests/integration/v0_2_controller.rs`, `docs/lessons/06-inventory-tracking-and-live-state.md`.
- **Verification:** Live `kind` integration test: apply `Application` CR pointing at local Git repo -> workloads created, `status.sync.revision` and `status.inventory` populated -> push new Git commit -> controller reconciles update automatically. **Milestone `v0.2` Complete.**
- **Trap Guard:** Reject applying onto an existing resource whose `tracking-id` belongs to another `Application`.

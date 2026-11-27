# Lesson 17: Production Hardening, Live Governance & Software Supply-Chain Security

> **Milestone:** `v1.1` (Phase 17 · Track E)  
> **Tasks:** `T17.1` (Watch-Backed `/readyz`, Live RBAC Hot-Reload & Tenant-Scoped Clusters) · `T17.2` (Immutable Compliance Audit Trail & Security Telemetry) · `T17.3` (Enterprise Web UI & WCAG 2.2 AA) · `T17.4` (`AppProject.spec.syncWindows`) · `T17.5` (Supply-Chain Security & Continuous Dependency Governance)

Shipping `v1.0` proved that FerrisCD can reconcile 50 Applications / 500 resources with flat `~22 MiB` RSS and zero errors across a 30-minute soak. Turning a fast GitOps engine into a control plane that enterprise security and platform teams will admit into regulated production clusters requires a different class of engineering: **eliminating Day-2 operational blind spots, enforcing tamper-evident governance, and proving artifact provenance from commit to cluster**.

---

## 1. Watch-Backed `/readyz` & Zero-Downtime RBAC Hot-Reload (`T17.1`)

### Why a static `/readyz` breaks rolling upgrades
A liveness probe (`/healthz`) answers *"is the process wedged?"*; a readiness probe (`/readyz`) answers *"should Kubernetes route traffic to this pod?"*. Answering `200 OK` unconditionally at process start lets a newly rolled pod accept API calls before its controller watches, `ClusterManager` registry, and initial `ferriscd-rbac-cm` snapshot have finished their initial `Init` → `InitDone` list — producing spurious `404`s and `502`s during `helm upgrade --wait`.

FerrisCD coordinates startup with a lock-free three-gate barrier (`ControlPlaneReadiness` in `crates/ferriscd-controller/src/readiness.rs`) backed by three `AtomicBool` flags:

1. `controllers_ready`: flipped when `ApplicationControllers::wait_until_ready()` completes. In active/standby `--leader-election` mode a standby instead sets a distinct `standby_serving` gate once it observes a **healthy foreign leader**, and the gate is cleared when it acquires the lease — a leader always waits for its own controller `InitDone`, so a cold replica cannot accept traffic and `helm upgrade --wait` cannot deadlock.
2. `clusters_seeded`: flipped after the initial namespaced `Secret` list or the first bracketed `Init..InitDone` watch snapshot.
3. `rbac_loaded`: flipped after an authoritative initial API read of `ferriscd-rbac-cm` (including `404` missing or invalid YAML, which fail closed to deny-all) or after `watch_rbac_policy`'s first `InitDone`.

On the steady-state ready path, `GET /readyz` performs three `Acquire` atomic loads and returns a static `200 OK` JSON response (`{"status":"ready"}`) with **zero heap allocation**.

### Fail-Safe vs. Fail-Closed Live RBAC Transitions
Restarting every control-plane pod to rotate an RBAC rule is unacceptable in production. `watch_rbac_policy` watches `ferriscd-rbac-cm` strictly inside the control-plane namespace (`Api::namespaced` + `metadata.name=ferriscd-rbac-cm`, chained with `.default_backoff()`, never cluster-wide) and atomically swaps an `Arc<RbacPolicy>` inside `RbacPolicyStore`:

| `ferriscd-rbac-cm` Event | Active Policy Transition | Metric Increment |
|---|---|---|
| Valid YAML update (new `resourceVersion`) | Atomic swap to new policy | `ferriscd_rbac_reload_total{outcome="ok"}` |
| Unchanged `resourceVersion` (410 reconnect re-list) | No-op (deduplicated) | None |
| Malformed YAML, duplicate keys, alias bomb, or missing `policy.yaml` | **Retain last known-good policy** (fail-safe against operator typos) | `ferriscd_rbac_reload_total{outcome="error"}` (watch failures count on `ferriscd_rbac_watch_errors_total`) |
| `Delete` or omission from completed re-list (`Init` → `InitDone`) | **Fail closed** to `RbacPolicy::empty()` (default-deny) | `ferriscd_rbac_reload_total{outcome="deleted"}` |

Separately, `GET /api/v1/clusters` filters the cluster registry through the caller's visible `AppProject.spec.destinations` via `wildcard_matches`, closing cross-tenant cluster enumeration.

---

## 2. Immutable Compliance Audit Trail & Non-Blocking SIEM Sinks (`T17.2`)

Every regulated organization needs an authoritative answer to *"who triggered that sync/rollback, why was that request denied, which webhook fired, which ServiceAccount was impersonated, and when was a remote cluster credential rotated?"*

FerrisCD defines one versioned JSON contract (`schemaVersion: "ferriscd.io/audit/v1"`) shared across `ferriscd-controller` and `ferriscd-server` covering five low-cardinality categories (`api.operation`, `api.authz_denied`, `webhook.delivery`, `controller.impersonation`, `cluster.registry`) and four outcomes (`allowed`, `denied`, `accepted`, `failed`), correlated end-to-end by an outermost `X-Request-Id` middleware.

### Three Non-Negotiable Audit Invariants
1. **Never block production operations on a dead SIEM:** Stdout structured JSON (`tracing` target `ferriscd::audit`) is synchronous and lossless for Kubernetes log shippers (FluentBit/Vector). Optional external sinks (`--audit-log-path` JSONL file and `--audit-webhook-url` async batched HTTPS) enqueue via bounded `try_send` (`capacity = 1_024`) — if full, they drop immediately, increment `ferriscd_audit_dropped_total`, and emit a rate-limited warning.
2. **Defense-in-depth SSRF & URL redaction on webhook sinks:** `--audit-webhook-url` enforces `.https_only(true)`, `.no_proxy()`, `.redirect(Policy::none())`, rejects embedded URL credentials, strips query parameters/fragments in logs and `Debug`, and validates resolved IPs at DNS lookup time through `SsrfGuardedDnsResolver` (blocking loopback, link-local, AWS/GCP/Azure/Alibaba IPv4 & IPv6 IMDS `169.254.169.254` / `100.100.100.200` / `fd00:ec2::254`, IPv4-compatible IPv6, and NAT64 `64:ff9b::/96`).
3. **Preserve existence-hiding `404`s externally while auditing denials internally:** When an authenticated caller probes an `Application` in a project they have zero grants on, the HTTP response stays byte-identical to a nonexistent `Application` (`404 Not Found`), while the internal `AuditEvent` records `category: "api.authz_denied"` with the true target project.

---

## 3. Enterprise Governance & Supply-Chain Security (`T17.5`)

Because a GitOps controller holds write privileges across namespaces and clusters, its own build and dependency pipeline is a Tier-0 security boundary.

### Dependency & License Governance (`deny.toml` + `.cargo/audit.toml`)
* **`cargo deny check`** enforces an explicit OSI-compatible license allowlist (`Apache-2.0`, `MIT`, `BSD-2/3-Clause`, `ISC`, `MPL-2.0`, `Zlib`, `Unicode-3.0`, etc.), bans yanked crates, bans crates.io wildcard versions (`allow-wildcard-paths = true` with `publish = false` on private workspace crates), and restricts sources strictly to `crates.io`.
* **`cargo audit`** and **`npm audit --omit=dev --audit-level=high`** run on every PR (`.github/workflows/ci.yml`) and on a weekly Monday schedule (`.github/workflows/security-audit.yml`).
* **Time-bounded advisory exceptions:** When an advisory applies exclusively to an unused feature (for example, `RUSTSEC-2026-0600` affecting `kube-client`'s disabled `openssl-tls` connector while FerrisCD builds `rustls-tls` only), the ignore entry in `deny.toml` and `.cargo/audit.toml` MUST record the technical proof, expiry date, and tracking reference.

### Immutable CI Actions, CycloneDX SBOMs, Keyless Cosign & SLSA Level 3
1. **Zero mutable `@v4` tags in CI:** Every third-party `uses:` line across `.github/workflows/*.yml` is pinned to a full 40-character commit SHA and verified statically in CI on every PR.
2. **Sign by immutable digest, never mutable tag:** `.github/workflows/release.yml` signs `ghcr.io/<owner>/ferris-cd@sha256:...` and `ghcr.io/<owner>/ferris-cd-web@sha256:...` with keyless Sigstore `cosign` (GitHub OIDC identity — zero long-lived signing keys stored in repo secrets) and refuses to run if the reference does not contain `@sha256:`.
3. **CycloneDX SBOMs + SLSA Level 3 provenance:** Release builds emit both a Rust workspace CycloneDX SBOM (`cargo-cyclonedx`) and multi-arch container SBOMs (`anchore/sbom-action`), attach SBOM attestations via `cosign attest --type cyclonedx`, and publish SLSA Level 3 build provenance (`actions/attest-build-provenance`) for binary tarballs, Helm chart `.tgz` packages, and OCI image digests.

---

## 4. Hands-On Verification & `kind` Experiment

> **Safety Gate:** Always verify you are targeting a disposable `kind` cluster before running live commands:
> ```bash
> kubectl config current-context | grep -q '^kind-' || { echo "STOP: non-kind context!"; exit 1; }
> ```

### Part A — Verify Local Supply-Chain & Action-Pinning Gates (No Cluster Required)

```bash
# 1. Verify Rust licenses, advisories, bans, and sources against deny.toml
cargo deny check --hide-inclusion-graph

# 2. Verify production Web UI dependencies have zero High/Critical advisories
npm --prefix apps/ferriscd-web audit --omit=dev --audit-level=high

# 3. Verify the shared supply-chain policy (SHA pins, digest-only cosign, advisory expiry).
#    The exact script CI runs, so the documented check cannot drift from the enforced one.
ruby .github/scripts/check-supply-chain.rb
```

CycloneDX note: `cargo-cyclonedx 0.5.x` writes one BOM per crate next to its `Cargo.toml` and has no
workspace-aggregation mode — `--top-level` means "direct dependencies only" (17 of 366 components
here). The release job therefore generates the full graph for all five crates and merges them with
`.github/scripts/merge-cyclonedx.rb`.

### Part B — Live `kind` Experiment: `/readyz`, Live RBAC Reload & Audit Trail

```bash
# 1. Run the kind-guarded live readiness + live RBAC hot-reload E2E test (`<= 2 s` reload SLA)
cargo test -p ferriscd-cli --test v1_1_readiness_rbac -- --ignored --test-threads=1

# 2. Exercise the whole release supply-chain path without a tag: pushes <version>-dryrun images,
#    generates both image SBOMs, signs/attests by digest, then runs cosign verify in the job.
gh workflow run release.yml -f dry_run_version=0.0.0-dryrun -f sign_dry_run=true

# 3. Verify a released artifact's Sigstore signature & SLSA provenance (replace <VERSION> and <DIGEST>)
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github\.com/tuantran0910/ferris-cd/\.github/workflows/release\.yml@refs/tags/v" \
  "ghcr.io/tuantran0910/ferris-cd@sha256:<DIGEST>"

gh attestation verify "ferriscd-<VERSION>.tgz" --repo tuantran0910/ferris-cd
```

---

## Key Takeaways

- **Readiness is a state machine, not a constant:** Gating `/readyz` on controller watches, cluster registry seeding, and RBAC initialization eliminates upgrade-time `502`/`404` flashes while staying allocation-free in steady state.
- **Hot-reload safely, fail closed on absence:** Retain the last known-good RBAC policy on malformed edits so a syntax typo never locks out incident responders, yet transition immediately to default-deny if `ferriscd-rbac-cm` is deleted.
- **Audit asynchronously, verify cryptographically:** Keep audit sinks off the critical request path with bounded channels and explicit drop metrics, and anchor production deployments on SHA-pinned CI workflows, keyless digest signatures, CycloneDX SBOMs, and SLSA Level 3 provenance.

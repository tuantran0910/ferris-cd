# Security Policy & `v1.0` Threat Model

## Supported Versions

| Version | Supported |
|---|---|
| `1.1.x` (`v1.1`) | Supported (security fixes applied to `main` and tagged patch releases) |
| `1.0.x` (`v1.0`) | Supported (critical security backports) |
| `< 1.0.0` (pre-release) | Unsupported — upgrade to `v1.1` |

## Reporting a Vulnerability & CVE Triage SLAs

**Please do not report security vulnerabilities through public GitHub issues or pull requests.**

Use GitHub's **Private Vulnerability Reporting** ("Report a vulnerability" under the **Security** tab of `tuantran0910/ferris-cd`). Please include:

- A clear description of the vulnerability and its potential impact
- Minimal reproduction steps or proof-of-concept manifest/request
- Affected crate, container image, Helm value, or renderer configuration

### Remediation & Triage Targets (`T17.5`)

| Severity (CVSS v3.1 / RUSTSEC) | Initial Acknowledgement | Remediation / Patch Release Target |
|---|---|---|
| **Critical** (`9.0–10.0`) | `<= 24 hours` | `<= 48 hours` |
| **High** (`7.0–8.9`) | `<= 48 hours` | `<= 7 days` |
| **Medium / Low** (`< 7.0`) | `<= 72 hours` | Next scheduled minor/patch release (`<= 30 days`) |

The PR gate audits only **production** Web UI dependencies (`npm audit --omit=dev --audit-level=high`)
because the current dev toolchain (`vitest`/`tinypool`) carries open advisories that require a
breaking major upgrade (tracked in issue #51); the weekly `security-audit.yml` job reports the
full dependency tree, dev included, as a warning.

Temporary dependency advisory exceptions in [`deny.toml`](deny.toml) and [`.cargo/audit.toml`](.cargo/audit.toml) are permitted **only** when the vulnerable code path is demonstrably unreachable (e.g., disabled Cargo feature), and MUST carry a written technical justification, an explicit expiry date, and a tracking reference.

---

## Supply-Chain Verification & Artifact Provenance (`T17.5`)

Every tagged release (`vX.Y.Z`) published by [`.github/workflows/release.yml`](.github/workflows/release.yml) provides:

1. **Keyless Sigstore Cosign signatures** bound to the immutable `sha256:` image digest (never a mutable tag) using GitHub Actions OIDC identity.
2. **CycloneDX SBOMs** for both the Rust workspace (`ferriscd-<version>-workspace.cdx.json`) and both multi-arch OCI images (`ferriscd-<version>-image.cdx.json`, `ferriscd-web-<version>-image.cdx.json`), attested onto the image digests via `cosign attest`.
3. **SLSA Level 3 build provenance** attestations via `actions/attest-build-provenance` for release binary tarballs, Helm chart `.tgz` archives, and container image digests.
4. **Immutable CI supply chain:** Every third-party GitHub Action in `.github/workflows/` is pinned to a full 40-character commit SHA and enforced automatically on every PR.

### Verifying Container Image Signatures & SBOM Attestations

Always resolve and verify against the **immutable `sha256:` digest**, never a mutable tag.
The commands below require [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/),
the GitHub CLI (`gh attestation verify`), and [`crane`](https://github.com/google/go-containerregistry)
(or `docker buildx imagetools inspect`) to resolve the digest:

```bash
IMAGE="ghcr.io/tuantran0910/ferris-cd"
DIGEST="$(crane digest "${IMAGE}:1.1.0")"

# 1. Verify keyless Sigstore Cosign signature (GitHub Actions OIDC identity)
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github\.com/tuantran0910/ferris-cd/\.github/workflows/release\.yml@refs/tags/v" \
  "${IMAGE}@${DIGEST}"

# 2. Verify attached CycloneDX SBOM attestation
cosign verify-attestation \
  --type cyclonedx \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github\.com/tuantran0910/ferris-cd/\.github/workflows/release\.yml@refs/tags/v" \
  "${IMAGE}@${DIGEST}"
```

To exercise this path **without cutting a release**, dispatch the workflow with
`sign_dry_run=true`; it pushes `<version>-dryrun` images and runs the same `cosign verify` /
`cosign verify-attestation` checks inside the job:

```bash
gh workflow run release.yml -f dry_run_version=0.0.0-dryrun -f sign_dry_run=true
```

### Verifying SLSA Level 3 Provenance (Binaries, Helm Charts & Images)

```bash
# Verify a release binary archive or Helm chart `.tgz`
gh attestation verify ferriscd-1.1.0-x86_64-unknown-linux-gnu.tar.gz --repo tuantran0910/ferris-cd
gh attestation verify ferriscd-1.1.0.tgz --repo tuantran0910/ferris-cd

# Verify an OCI container image digest
gh attestation verify "oci://${IMAGE}@${DIGEST}" --repo tuantran0910/ferris-cd
```

### Pinning Immutable Digests in Helm Production Deployments

In production, pin immutable digests instead of mutable tags in your Helm values override:

```yaml
image:
  repository: ghcr.io/tuantran0910/ferris-cd
  tag: "1.1.0@sha256:<verified-control-plane-digest>"

web:
  image:
    repository: ghcr.io/tuantran0910/ferris-cd-web
    tag: "1.1.0@sha256:<verified-web-digest>"
```

---

## `v1.0` Security Architecture & Threat Model

FerrisCD operates as a high-trust Kubernetes control plane reconciling untrusted Git repositories.
Every stage of the pipeline applies defense-in-depth controls:

### 1. Untrusted Git Repositories & Manifest Rendering

| Threat | Mitigation |
|---|---|
| Symlink traversal reading pod files (`/var/run/secrets/...`, `/etc/...`) | Worktree-wide symlink sanitization (`crates/ferriscd-engine/src/repo/sanitize.rs`) runs across the **entire checked-out worktree** before any YAML parser or external renderer executes, rejecting symlinks escaping the checkout root and enforcing file-count (`100,000`) and byte (`512 MiB`) ceilings. |
| YAML alias/billion-laughs DoS | `serde-saphyr` parser budgets (`10,000` replayed events, depth `32`, `100` expansions per anchor) and plain-YAML loader limits (`10,000` files / `128 MiB`). |
| Malicious Kustomize remote bases / SSRF / env exfiltration | `SandboxedCommand` executes pinned, SHA-256-verified `kustomize` (`v5.8.3`) and `helm` (`v4.3.2`) binaries with `env_clear()`, explicit `PATH`, strict timeouts, and `20 MiB` stdout/stderr caps. Kustomize remote URLs and load restrictions outside the worktree are blocked; Helm CRDs are disabled unless `includeCRDs: true`. |
| Plaintext Git or unverified SSH MITM | Production policy rejects plaintext `http://` and `file://` repos (`--allow-local-repos` is opt-in for local dev only). SSH deploy keys use ephemeral `0600` files under `/tmp`, RAII zeroization, and mandatory `known_hosts` verification. |

### 2. Secret & Credential Hygiene

- **Diffs, Logs & Kubernetes Events:** All `Secret` `.data` and `.stringData` values are replaced
  with deterministic redacted placeholders (`***REDACTED(...)***`) before diffs are returned over
  the REST API, rendered in the CLI/Web UI, or emitted in logs/Events.
- **Credentials in memory & error paths:** `RepoCredentials`, `WebhookSecret`, `LoginArgs`,
  `ServerArgs`, and OTLP endpoints redact secrets in `Debug`, `Display`, and error chains.
  `TokenReview` caching is keyed by one-way token SHA-256 hashes (never raw bearer tokens).
- **Control-plane-scoped Secret RBAC:** Repository credentials (`ferriscd.io/secret-type=repository`)
  and remote-cluster registrations (`ferriscd.io/secret-type=cluster`) are read **only** from the
  control-plane namespace via a namespaced `Role`. `secrets` is **never** granted in the default
  `ClusterRole`, and remote-cluster kubeconfig Secrets reject `exec`, `auth-provider`, `proxy-url`,
  `tokenFile`, and filesystem certificate paths.

### 3. API Authentication, RBAC & Hardened Webhooks

- **Kubernetes `TokenReview` AuthN (`--auth-policy token-review` default):** Every `/api/v1/*`
  route requires `Authorization: Bearer <token>` validated against `authentication.k8s.io/v1`
  `TokenReview` with a 30-second positive-only cache. `/healthz` and `/readyz` are unauthenticated
  probes; `/metrics` is served on an isolated internal port (`:9090`).
- **Default-deny project RBAC (`ferriscd-rbac-cm`):** Ships with `rules: []` (refuses all
  authenticated callers until explicit grants are configured). Callers with zero grants on an
  `Application`'s project receive `404 Not Found` (preventing name enumeration), while read-only
  callers receive `403 Forbidden` on `sync`/`rollback`.
- **Hardened webhooks (`/api/v1/webhooks/{github,gitlab}`):** Enforces a `1 MiB`
  `DefaultBodyLimit` before parsing, constant-time (`subtle`) verification of `X-Hub-Signature-256`
  (GitHub HMAC-SHA256) with `X-GitHub-Delivery` bounded TTL replay deduplication (`10,000` entries
  / `15 min`), constant-time `X-Gitlab-Token` validation for GitLab, and per-repo debounce +
  jittered fan-out against monorepo thundering herds.

### 4. Multi-Tenancy & `ServiceAccount` Impersonation

- **`AppProject` boundary:** Every rendered resource's resolved namespace, cluster, GroupKind, and
  source repository is validated against its `AppProject` before dry-run or apply.
- **Confused-deputy defense:** Tenant `Application`s outside the control-plane namespace must
  declare `spec.serviceAccountName` listed in `AppProject.spec.allowedServiceAccounts` and are
  reconciled using `Impersonate-User` + `Impersonate-Group` headers (`system:masters` is
  unconditionally refused in code). Cascade deletes re-verify project policy before deleting
  anything.

### 5. Container Hardening, Mounted ServiceAccount Token & NetworkPolicy

- **Restricted PodSecurityStandard:** Both [`Dockerfile`](Dockerfile) (`ferriscd`) and
  [`apps/ferriscd-web/Dockerfile`](apps/ferriscd-web/Dockerfile) (`ferriscd-web`) run as non-root
  UID/GID `65532` with `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: ["ALL"]`, `seccompProfile.type: RuntimeDefault`, and a size-bounded
  `emptyDir` at `/tmp`.
- **Mounted ServiceAccount token note:**
  - **`ferriscd-web`** sets `automountServiceAccountToken: false` — the static SPA container never
    receives a Kubernetes API token and has zero cluster API access.
  - **`ferriscd` (controller + server)** sets `automountServiceAccountToken: true` (`serviceAccount.automount: true`)
    because the in-cluster controller and `TokenReview` middleware must authenticate to
    `kube-apiserver`. Operators should treat the control-plane namespace (`ferriscd-system`) as a
    privileged cluster boundary: restrict `kubectl exec`/pod-creation access to cluster admins,
    keep `rbac.manageCrds` / `rbac.manageRbacResources` / `rbac.impersonation.enabled` disabled
    unless needed, and never add cluster-wide `secrets` or `*/*` wildcards to the `ClusterRole`.
- **Default-deny `NetworkPolicy` + IMDS blocking:** Both Helm ([`deploy/helm/ferriscd/templates/networkpolicy.yaml`](deploy/helm/ferriscd/templates/networkpolicy.yaml))
  and Kustomize ([`deploy/manifests/networkpolicy.yaml`](deploy/manifests/networkpolicy.yaml))
  enforce `policyTypes: [Ingress, Egress]`. Every egress rule specifies an explicit `to:` peer
  (never omitted) and excludes cloud metadata IMDS `169.254.169.254/32` whenever `0.0.0.0/0` is
  used. In production, pin `networkPolicy.egress.kubeApi.cidrs`, `gitHttps.cidrs`, and
  `gitSsh.cidrs` to your cluster and Git infrastructure CIDRs.

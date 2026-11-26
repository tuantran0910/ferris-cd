# Security Policy & `v1.0` Threat Model

## Supported Versions

| Version | Supported |
|---|---|
| `1.0.x` (`v1.0`) | Supported (security fixes applied to `main` and tagged patch releases) |
| `< 1.0.0` (pre-release) | Unsupported — upgrade to `v1.0` |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues or pull requests.**

Use GitHub's **Private Vulnerability Reporting** ("Report a vulnerability" under the **Security** tab of `tuantran0910/ferris-cd`). Please include:

- A clear description of the vulnerability and its potential impact
- Minimal reproduction steps or proof-of-concept manifest/request
- Affected crate, container image, Helm value, or renderer configuration

We aim to acknowledge reports within **72 hours** and share a remediation plan and coordinated disclosure timeline after triage.

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

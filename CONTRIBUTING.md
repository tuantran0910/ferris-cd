# Contributing to FerrisCD

Thank you for your interest in contributing to **FerrisCD**! Every contribution—whether Rust engine code, Web UI components, Helm/Kustomize packaging, tests, ADRs, or Knowledge Base lessons—should uphold our safety, reliability, and clarity standards.

## Development Prerequisites

- **Rust:** `1.100.0` (Edition 2024, MSRV `1.99`) with `rustfmt` and `clippy` (pinned in [`rust-toolchain.toml`](rust-toolchain.toml))
- **Web Dashboard (`apps/ferriscd-web`):** Node.js `22+` and `npm`
- **Kubernetes local testing:** Docker, `kind` (`v0.33+`), `kubectl` (`v1.35+`)
- **Renderers & Packaging:** `helm` (`v4.3+`), `kustomize` (`v5.8+`), `ruby` (for CI YAML assertions)

## Engineering Invariants

Before submitting a PR, make sure your changes respect all invariants in [AGENTS.md](AGENTS.md) and [docs/MASTER_PLAN.md](docs/MASTER_PLAN.md):

1. **Modular monolith crate boundaries:** Keep the 5-crate Rust workspace (`ferriscd-crd`, `ferriscd-engine`, `ferriscd-controller`, `ferriscd-server`, `ferriscd-cli`) plus the decoupled `apps/ferriscd-web` frontend. Never couple Cargo builds to Vite/npm builds.
2. **`k8s-openapi` feature hygiene:** Enable `k8s-openapi` version features (`v1_35`) **only** in binary and integration-test crates—**never** in library crates (`ferriscd-crd`, `ferriscd-engine`).
3. **No panics in runtime code:** `unwrap()` and `expect()` are denied by Clippy outside `#[cfg(test)]`.
4. **Async hygiene:** Run blocking `gix`, disk, or blocking HTTP/OTLP shutdown work inside `tokio::task::spawn_blocking`. Never block a reconcile worker waiting for a wave or Job to complete.
5. **GitOps & SSA safety:** Key inventory strictly by version-agnostic GKNN, default `serverSideForce` to `false`, strip `.status` before apply, never prune on fetch/render failure, and redact `Secret` values and credentials everywhere.
6. **Safe `kind` testing:** Never run integration tests against a non-`kind` cluster (`kubectl config current-context` must start with `kind-`).

## Local Verification Gates

### 1. Rust Workspace Gate (mirrors `.github/workflows/ci.yml`)

```bash
# Full Rust gate: fmt-check, workspace clippy, engine test-utils clippy, CRD drift check, unit tests
make gate

# Fast inner-loop check (formatting + clippy only)
make gate-fast
```

If you modify CRD types in `crates/ferriscd-crd`, regenerate and sync all three CRD copies:

```bash
cargo run -p ferriscd-cli -- crd generate
cp deploy/crds/*.yaml deploy/helm/ferriscd/crds/
cp deploy/crds/*.yaml deploy/manifests/crds/
```

If you modify REST API types/routes in `crates/ferriscd-server`, regenerate the OpenAPI 3.1 contract and TypeScript types:

```bash
cargo run -p ferriscd-cli -- server openapi
(cd apps/ferriscd-web && npm run generate-api)
```

### 2. Web Dashboard Gate (`apps/ferriscd-web`)

```bash
cd apps/ferriscd-web
npm ci
npm run generate-api && git diff --exit-code src/api/schema.d.ts
npm run typecheck
npm run test
npm run build
```

### 3. Helm Chart & Kustomize Overlay Validation

```bash
helm lint deploy/helm/ferriscd
helm lint deploy/helm/ferriscd -f deploy/helm/ferriscd/values-ha.yaml
helm template ferriscd deploy/helm/ferriscd -n ferriscd-system > /dev/null
kustomize build deploy/manifests > /dev/null
```

### 4. Live `kind` Integration & Chaos Tests

```bash
make kind-up
kubectl config current-context | grep -q '^kind-'
make test-integration
```

For idempotency verification (running the full live suite twice back-to-back on the same `kind` cluster):

```bash
make test-integration-twice
```

## Commit Convention

All commit messages and Pull Request titles follow **[Conventional Commits 1.0.0](https://www.conventionalcommits.org/)** and are automatically validated locally (`.githooks/commit-msg`) and in CI ([`.github/workflows/commit-lint.yml`](.github/workflows/commit-lint.yml)).

### Format

```text
<type>(<scope>): <imperative summary>

[optional body explaining why]

[optional footer(s), e.g., Tasks: T16.7 / BREAKING CHANGE: ...]
```

### Allowed Types

| Type | When to use |
|---|---|
| `feat` | New user-facing or engine capability |
| `fix` | Bug fix or trap/regression fix |
| `docs` | Documentation, ADRs, roadmap, runbooks, or phase lessons |
| `refactor` | Code restructuring without behavior changes |
| `perf` | Performance or memory optimization |
| `test` | Adding or updating unit, integration, or chaos tests |
| `build` | Cargo dependencies, Dockerfiles, Helm/packaging changes |
| `ci` | GitHub Actions workflows, Makefile, lint/hook config |
| `chore` | Repository maintenance and housekeeping |
| `style` | Formatting-only changes (`cargo fmt`) |
| `revert` | Reverting a previous commit |

### Allowed Scopes

When a scope is provided, it **must** match one of the workspace crates or repository domains below. Do **not** put roadmap task IDs (`t16.7`, `phase-16`) in `<scope>`—place them in the commit body or PR description (e.g., `Tasks: T16.7`).

| Category | Allowed Scopes |
|---|---|
| Workspace & Crates | `workspace` (multi-crate/root), `crd`, `engine`, `controller`, `cli`, `server`, `web` |
| Infra & Docs | `deploy`, `examples`, `adr`, `lessons`, `docs`, `ci`, `deps`, `repo` |

### Subject Rules

- Use imperative present tense (`add`, `fix`, `strip`, not `added` or `adds`).
- Start with a lowercase word and omit any trailing period.
- Aim for ≤ 72 characters (hard CI limit: 100 characters).
- Mark breaking changes with `!` before `:` (e.g., `feat(crd)!: ...`) and/or a `BREAKING CHANGE:` footer.

### Examples

```text
feat(server): add TokenReview authentication middleware

Tasks: T14.3
```

```text
feat(web): add interactive React Flow resource topology graph
fix(engine): redact Secret.stringData before rendering dry-run diff
build(deploy): add default-deny NetworkPolicy and HA values overlay
docs(lessons): add Lesson 16 and Knowledge Base curriculum index
ci(repo): add multi-arch v1.0 release workflow
```

### Enable Local Commit Hook

Enable the repository's local `commit-msg` validator once per clone:

```bash
git config core.hooksPath .githooks
```

## Pull Request Workflow

1. Branch from `main` using `<type>/<short-kebab-description>` (e.g., `feat/release-pipeline`, `docs/operations-runbook`, `fix/imds-egress-rule`).
2. Keep pull requests small, atomic, and scoped to a single roadmap task or cohesive task pair (`TXX.Y`); stack PRs linearly when one depends on another.
3. Ensure your PR title follows the Conventional Commits format above (required for Squash & Merge).
4. Never bypass GPG signing (`--no-gpg-sign`) or git hooks (`--no-verify`).
5. Verify all relevant gates (`make gate`, `apps/ferriscd-web` checks, `helm lint`) pass before requesting review.

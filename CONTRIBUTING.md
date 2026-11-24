# Contributing to FerrisCD

Thank you for your interest in contributing to **FerrisCD**! Every contribution—whether code, tests, ADRs, or Knowledge Base lessons—should uphold our safety, reliability, and clarity standards.

## Development Prerequisites

- **Rust:** `1.99.0+` (Edition 2024) with `rustfmt` and `clippy` (pinned in `rust-toolchain.toml`)
- **Kubernetes local testing:** `docker`, `kind` (`v0.33+`), `kubectl` (`v1.35+`)
- **Renderers (Phase 11+):** `helm` (`v4.3+`), `kustomize` (`v5.8+`)

## Engineering Invariants

Before submitting a PR, make sure your changes respect all invariants in [AGENTS.md](AGENTS.md) and [docs/MASTER_PLAN.md](docs/MASTER_PLAN.md):

1. **Modular monolith crate boundaries:** Keep the 4->5 crate workspace (`ferriscd-crd`, `ferriscd-engine`, `ferriscd-controller`, `ferriscd-cli`, and `ferriscd-server` in Phase 14).
2. **`k8s-openapi` feature hygiene:** Enable `k8s-openapi` version features (`v1_35`) **only** in binary and integration-test crates—**never** in library crates (`ferriscd-crd`, `ferriscd-engine`).
3. **No panics in runtime code:** `unwrap()` and `expect()` are denied by Clippy outside `#[cfg(test)]`.
4. **GitOps & SSA safety:** Key inventory strictly by version-agnostic GKNN, default `serverSideForce` to `false`, strip `.status` before apply, and redact `Secret` values and credentials everywhere.
5. **Safe `kind` testing:** Never run integration tests against a non-`kind` cluster (`kubectl config current-context` must start with `kind-`).

## Local Verification Gate

Run the full quality gate before opening or updating a pull request:

```bash
make lint
make test
```

For tasks requiring live Kubernetes verification:

```bash
make kind-up
kubectl config current-context | grep -q '^kind-'
make test-integration
```

## Commit Convention

All commit messages and Pull Request titles follow **[Conventional Commits 1.0.0](https://www.conventionalcommits.org/)** and are automatically validated in CI (`.github/workflows/commit-lint.yml`).

### Format

```text
<type>(<scope>): <imperative summary>

[optional body explaining why]

[optional footer(s), e.g., BREAKING CHANGE: ...]
```

### Allowed Types

| Type | When to use |
|---|---|
| `feat` | New user-facing or engine capability |
| `fix` | Bug fix or trap/regression fix |
| `docs` | Documentation, ADRs, roadmap, or phase lessons |
| `refactor` | Code restructuring without behavior changes |
| `perf` | Performance or memory optimization |
| `test` | Adding or updating unit, integration, or chaos tests |
| `build` | Cargo dependencies, Dockerfiles, Helm/packaging changes |
| `ci` | GitHub Actions workflows, Makefile, lint/hook config |
| `chore` | Repository maintenance and housekeeping |
| `style` | Formatting-only changes (`cargo fmt`) |
| `revert` | Reverting a previous commit |

### Allowed Scopes

When a scope is provided, it **must** match one of the workspace crates or repository domains below (enforced locally and in CI). Do **not** put roadmap task IDs (`t02.1`, `phase-02`) in `<scope>`—place them in the commit body or PR description (e.g., `Tasks: T02.1`).

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
feat(engine): define GitClient trait and redacted RepoCredentials

Tasks: T02.1
```

```text
feat(workspace): configure shared lint policy and kind scripts
fix(engine): redact Secret.stringData before rendering dry-run diff
docs(adr): add ADR-0003 for GKNN inventory and tracking-id
ci(deps): bump actions/checkout from 4 to 5
```

### Enable Local Commit Hook

Enable the repository's local `commit-msg` validator once per clone:

```bash
git config core.hooksPath .githooks
```

## Pull Request Workflow

1. Branch from `main` using `<type>/<short-kebab-description>` (e.g., `feat/t02-1-git-client-trait`, `docs/t01-adrs-and-examples`, `chore/commit-convention`).
2. Keep pull requests small, atomic, and scoped to a single roadmap task or cohesive task pair (`TXX.Y`); stack PRs linearly when one depends on another.
3. Ensure your PR title follows the Conventional Commits format above (required for Squash & Merge).
4. Complete the checklist in the pull request template and verify GitHub Actions CI is green.

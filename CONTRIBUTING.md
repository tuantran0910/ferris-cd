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

## Pull Request Workflow

1. Branch from `main` using a descriptive branch name (e.g., `feat/t02-1-git-client-trait`, `docs/t01-adrs-and-examples`, `fix/ssa-namespace-mismatch`).
2. Keep pull requests small, atomic, and scoped to a single roadmap task or cohesive task pair (`TXX.Y`).
3. Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`, `refactor:`, `test:`).
4. Complete the checklist in the pull request template and ensure GitHub Actions CI is green.

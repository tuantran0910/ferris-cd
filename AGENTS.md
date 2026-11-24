# FerrisCD — Workspace Rules & Coordinator Protocol

FerrisCD is a Kubernetes-native GitOps Continuous Delivery platform written in Rust (`rustc 1.99+`, Edition 2024).

## Authoritative Project Docs
- Architecture, ADRs, CRD schema, and stack: `docs/MASTER_PLAN.md`
- Master roadmap & milestones: `docs/ROADMAP.md`
- Atomic task specifications (`T01.1`–`T16.8`): `docs/roadmap/track-{a-core,b-engine,c-enterprise,d-platform}.md`
- Trap & review audit log: `docs/REVIEW_LOG.md`

---

## Multi-Agent Workflow (Coordinator Model)

Project subagents are committed in `.commandcode/agents/` and load on the next turn:

| Agent | Role | Model / effort |
|---|---|---|
| `ferriscd-researcher` | Read-only API/library research (exact signatures, feature flags) | `deepseek/deepseek-v4.1-flash` / medium |
| `ferriscd-implementer` | Scoped implementation + tests, runs the gate | `deepseek/deepseek-v4.1-flash` / high |
| `ferriscd-fast-fix` | Applies a supplied review-findings list only | `deepseek/deepseek-v4.1-flash` / medium |
| `ferriscd-reviewer` | Read-only adversarial review | `deepseek/deepseek-v4.1-flash` / high |

**Model ids are exact.** `flash` = `deepseek/deepseek-v4.1-flash`; `pro` = `deepseek/deepseek-v4-pro`. Never put the aliases `"flash"`/`"pro"` in an agent `model:` field. Pass a one-off `model` override for high-risk tasks (the high-risk list below) when the Coordinator wants `pro`; the agent files pin `flash` for speed.

The **main agent is the Coordinator**. For any non-trivial roadmap task (`TXX.Y`), follow the `ferriscd-task-cycle` skill:

1. **Coordinator (Main Agent):** Owns roadmap state, cross-crate invariants, user alignment, short task briefs, and final acceptance. Handles trivial edits (<30 lines of glue/docs/typos) directly without subagents.
2. **Research:** Delegate to `ferriscd-researcher` only when a crate API (`kube 5.1`, `gix`, `serde-saphyr`, `utoipa`) or Kubernetes edge case is uncertain. Ask for exact signatures and flags, not tutorials.
3. **Implementer:** Delegate to `ferriscd-implementer` with a compact brief — task ID, spec path, outputs, Trap Guard, branch, and any research facts. The agent reads the spec itself, writes tests, runs `make gate`, and self-reviews. Do not paste the whole spec into the prompt.
   - Default `flash` for standard work. Override to `deepseek/deepseek-v4-pro` for high-risk / subtle tasks: `gix` cloning/locking/SSH (`T02.2–T02.5`), YAML budgets & normalizer (`T03.2`, `T03.4`), watch predicates/finalizers/`DiscoveryCache` (`T05.1–T05.4`), GKNN inventory & SSA dry-run diff/redaction (`T06.2`, `T07.1–T07.4`, `T08.3–T08.5`), re-entrant wave/hook state machine & rollback (`T10.1–T10.5`), renderer sandboxing/SSRF & multi-tenancy/impersonation (`T11.2–T11.3`, `T12.1–T12.3`), native Lease HA & webhook/RBAC security (`T13.2`, `T14.2–T14.4`).
   - If running two Implementers in parallel, use a git worktree or strictly disjoint crates/files.
4. **Gate:** Require `make gate` (fmt + clippy + test) green before review. Never review code that does not compile, lint, or pass tests.
5. **Reviewer:** Delegate to `ferriscd-reviewer`, read-only and fresh-context, scoped to the task diff plus untracked files. First pass is exhaustive; fix-round confirmations audit only the new hunks.
6. **Fix loop:** Use `ferriscd-fast-fix` for the exact Critical/High findings (plus explicitly approved Medium). Re-run `make gate`, then one confirmatory review pass. Escalate after 2 rounds.

Speed rules: batch independent research in parallel; never re-audit unchanged files; prefer `make gate` as the single gate command; keep per-task prompts short because the agent files carry the standing instructions.

---

## Hard FerrisCD Engineering Invariants (Never Violate)

### Rust & Workspace
- **Modular monolith (4→5 crates):** Keep `ferriscd-crd`, `ferriscd-engine`, `ferriscd-controller`, `ferriscd-cli` (and `ferriscd-server` in Phase 14). Do not fragment into extra crates.
- **`k8s-openapi` feature hygiene:** Pin `kube 5.1`, `k8s-openapi 0.29`, `schemars 1`. Enable `k8s-openapi` version feature (`v1_35`) **only** in binary and integration-test crates—**never** in library crates (`ferriscd-crd`, `ferriscd-engine`).
- **No panics in runtime code:** Never use `unwrap()` or `expect()` in library or controller code (tests only). Classify engine errors as retryable vs. terminal (`is_retryable()`).
- **Async hygiene:** Run blocking `gix` disk/network operations inside `tokio::task::spawn_blocking`. Never sleep/block a reconcile worker waiting for a wave/Job to finish (persist `operationState` and requeue).

### Kubernetes, SSA & GitOps Safety
- **Version-agnostic GKNN keys:** Key `ResourceKey` and `status.inventory` strictly on `Group + Kind + Namespace + Name` (store `version` only as a non-key hint) so API upgrades never self-prune.
- **Crash-safe inventory formula:** `next_inventory = (prev_inventory \ pruned_ok) ∪ applied_ok`.
- **Always-update-status & composite predicate:** Patch `/status` subresource on **both** `Ok` and `Err`. Never use bare `predicates::generation` (it swallows deletions/finalizers/annotations).
- **SSA defaults:** `serverSideForce` defaults to `false`; normalize `Secret.stringData` → base64 `.data`; strip `.status` before apply; skip dry-run for `DeferredPendingCrd` / `DeferredPendingNamespace`.
- **Prune safety:** Verify `ferriscd.io/tracking-id` immediately before delete. Never auto-prune `CustomResourceDefinition` or `Namespace` unless explicitly opted in.
- **Model 1 drift detection (`v1.0`):** On-demand scoped fetch (`desired ∪ prev_inventory`) on requeue/webhook/spec change; no background cluster-wide informers.

### Security & Testing
- **Secret hygiene:** Redact all `Secret` `.data`/`.stringData` values in diffs/logs; redact `RepoCredentials` in `Debug`/`Display`.
- **Untrusted repo defense:** Sanitize symlinks across the entire checked-out worktree before running any renderer; configure `serde-saphyr` parser budgets; block Kustomize remote URLs and clear subprocess env.
- **Safe `kind` testing:** Before running any live Kubernetes integration test, assert `kubectl config current-context` starts with `kind-`. Never touch a non-`kind` cluster.

---

## Git, Branch & Commit Convention (Strictly Enforced)

Every commit message and Pull Request title MUST follow **Conventional Commits 1.0.0** (enforced locally by `.githooks/commit-msg` and in CI by `.github/workflows/commit-lint.yml`):

- **Header format:** `<type>(<scope>): <summary>` (scope optional; append `!` before `:` for breaking changes).
- **Allowed `<type>`:** `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `style`, `revert`.
- **Allowed `<scope>` (strict allow-list — never use roadmap task IDs like `t01.1` or `phase-01`):**
  - Workspace & crates: `workspace`, `crd`, `engine`, `controller`, `cli`, `server`, `web` (use `workspace` for cross-crate changes)
  - Infra & docs: `deploy`, `examples`, `adr`, `lessons`, `docs`, `ci`, `deps`, `repo`
  - Reference roadmap task IDs in the commit body or PR description (e.g., `Tasks: T02.1`), not in `<scope>`.
- **Subject rules:** imperative present tense (`add`, not `added`/`adds`), lowercase first word, no trailing period, target ≤ 72 chars (hard CI limit: 100 chars).
- **PR & branch hygiene:**
  - Branch naming: `<type>/<short-kebab-description>` (e.g., `feat/git-client-trait`, `docs/seed-adrs-and-examples`, `ci/enforce-workspace-scopes`).
  - Keep PRs small, atomic, and stacked linearly when dependent; PR titles MUST obey the same Conventional Commits header rule so Squash & Merge preserves a clean `main` history.
  - Never bypass GPG signing (`--no-gpg-sign`) or git hooks (`--no-verify`).

---
name: ferriscd-task-cycle
description: >-
  Coordinator runbook for executing an atomic FerrisCD roadmap task (TXX.Y) using
  the Research -> Implementer -> Verify -> Adversarial Reviewer loop with cost-optimized
  model routing. Activate whenever starting or orchestrating a roadmap task.
---

# FerrisCD Task Execution Cycle

Use this procedure whenever implementing a task `TXX.Y` from `docs/roadmap/`.

## Step 1: Load Task Contract & Choose Model Tier
1. Read the exact task entry in `docs/roadmap/track-*.md` (`Why`, `Detailed Requirements`, `Outputs`, `Verification`, `Trap Guard`) and relevant sections of `docs/MASTER_PLAN.md`.
2. Decide if the task is **trivial** (<30 lines of glue/config/docs): if so, execute directly without subagents.
3. Otherwise select the Implementer model tier per `AGENTS.md`:
   - **`flash`** (default) for standard scaffolding, CRDs, pure types/sorters, health snapshots, CLI, metrics, Helm/Docker, standard React UI.
   - **`pro`** for concurrency/locking, `gix` internals/SSH, YAML budgets/normalizer, predicates/finalizers/`DiscoveryCache`, GKNN inventory, SSA dry-run diff/redaction, wave/hook `OperationState`, rollback, renderer sandboxing, `AppProject`/impersonation, Lease HA, webhooks/RBAC.

## Step 2: Optional Targeted Research (`Model: "flash"`)
Invoke the built-in `research` subagent **only** when a crate API signature (`kube 5.1`, `gix`, `serde-saphyr`, `utoipa`) or Kubernetes edge case is uncertain:
- Ask for exact API signatures, feature flags, and gotchas—not full tutorials.
- Keep output concise so it can be pasted directly into the Implementer brief.

## Step 3: Define & Launch Implementer (`EnableWriteTools: true`)
If `implementer` is not yet defined in this conversation, call `define_subagent`:
- `Name`: `"implementer"`
- `EnableWriteTools`: `true`
- `SystemPrompt`: Instruct it to strictly follow `AGENTS.md` invariants, implement only the scoped task `TXX.Y`, write thorough unit/integration tests, and run the full verification gate before reporting back.

Invoke `implementer` with:
- Exact task spec (`Why`, `Detailed Requirements`, `Outputs`, `Verification`, `Trap Guard`).
- Any Research findings from Step 2.
- Explicit pre-handoff gate requirement:
  1. `cargo fmt --check`
  2. `cargo clippy --workspace --all-targets -- -D warnings`
  3. `cargo test --workspace` (plus live `kind` test via `ferriscd-kind-test` skill if required by the task).
- If running multiple Implementers concurrently on disjoint tasks, set `Workspace: "share"` to avoid working-tree collisions.

## Step 4: Hard Pre-Review Gate
Confirm the Implementer reported passing output for `fmt`, `clippy`, and `test`.
- Never invoke the `pro` Reviewer on code that fails to compile, lint, or pass tests.
- If the gate failed, message the **same** Implementer via `send_message` to fix it first.

## Step 5: Adversarial Review (`EnableWriteTools: false`, `Model: "pro"`)
If `reviewer` is not yet defined in this conversation, call `define_subagent`:
- `Name`: `"reviewer"`
- `EnableWriteTools`: `false`
- `SystemPrompt`: Instruct it to read `.agents/skills/ferriscd-reviewer/SKILL.md` and perform a strict, read-only adversarial audit of the current `git diff` against the task spec, `Trap Guard`, and `AGENTS.md` invariants.

Invoke `reviewer` (`Model: "pro"`, `Role: "Adversarial Code Reviewer"`) with:
- Task ID `TXX.Y` and its full `Detailed Requirements`, `Verification`, and `Trap Guard`.
- List of changed files and the test commands that passed.

## Step 6: Review Loop & Completion
- **If `APPROVED` (zero Critical/High findings):** Accept the work, summarize results + exact verification commands to the user, and check if `TXX.Y` completes a Phase (if so, verify the Phase Lesson in `docs/lessons/` is written).
- **If `CHANGES REQUESTED`:** Forward the exact Critical/High findings to the **existing** Implementer via `send_message` (do not spawn a new Implementer). Once fixed and the verification gate re-passes, run one final Reviewer confirmation pass. Escalate to the user if unresolved after 2 review rounds.

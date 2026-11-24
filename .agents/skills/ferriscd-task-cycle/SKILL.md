---
name: ferriscd-task-cycle
description: >-
  Coordinator runbook for executing an atomic FerrisCD roadmap task (TXX.Y) using
  the Research -> Implementer -> Gate -> Adversarial Reviewer loop with project
  subagents in .commandcode/agents/. Activate whenever starting or orchestrating
  a roadmap task.
---

# FerrisCD Task Execution Cycle

Use this procedure for a task `TXX.Y` from `docs/roadmap/`. The standing
instructions live in `.commandcode/agents/`, so keep each per-task prompt short.

## Step 0: Pick the path
- **Trivial** (<30 lines of glue/config/docs/typos, no behavior change): do it
  directly; run `make gate` only if code changed.
- **Everything else:** run the subagent cycle below.

## Step 1: Load the contract (Coordinator)
Read the exact `TXX.Y` entry (`Why`, `Detailed Requirements`, `Outputs`,
`Verification`, `Trap Guard`) and the relevant `docs/MASTER_PLAN.md` section.
Write a compact brief: task ID, spec path, outputs, trap guard, branch, and any
binding decisions. Do **not** paste the whole spec into the subagent prompt.

## Step 2: Optional research (parallel, only if API is uncertain)
Delegate to **`ferriscd-researcher`** for exact `gix`/`kube`/`serde-saphyr`
signatures, feature flags, or Kubernetes edge cases. Ask for paste-ready facts,
not tutorials. Batch independent questions in one turn.

## Step 3: Implement
Delegate to **`ferriscd-implementer`** with the compact brief. The agent:
- reads `AGENTS.md` + the spec itself,
- writes production code and tests (proving Verification + Trap Guard),
- runs `make gate`,
- self-reviews the diff before reporting.

Run Implementers in parallel only on strictly disjoint crates/files (or git
worktrees). Override the model to `deepseek/deepseek-v4-pro` for the high-risk
list in `AGENTS.md`.

## Step 4: Hard gate (no review before this)
Require the Implementer's `make gate` output:
`cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`
+ `cargo test --workspace`. If it fails, send the failure back to the same role
(a fresh `ferriscd-fast-fix` run) — never to the Reviewer.

## Step 5: Adversarial review
Delegate to **`ferriscd-reviewer`** (read-only). Give it the task ID, spec path,
base branch, changed-file list, and the gate result. The agent independently
re-runs `make gate`, audits the diff + untracked files, and returns
`APPROVED` / `CHANGES REQUESTED` with severity + `file:line`.

First pass: exhaustive. Fix-round confirmation: **delta only** — new hunks and
files touched by the fixes.

## Step 6: Fix loop (max 2 rounds)
- `CHANGES REQUESTED` → delegate the exact Critical/High findings (plus any
  explicitly approved Medium) to **`ferriscd-fast-fix`**. It fixes only those,
  adds/tightens the matching tests, and re-runs `make gate`.
- Then one `ferriscd-reviewer` confirmation pass on the delta.
- Still blocked after 2 rounds → escalate to the user with the unresolved
  findings and options.

## Step 7: Complete
- `APPROVED` → summarize results and exact verification commands. If `TXX.Y`
  completes a phase, verify the phase lesson exists in `docs/lessons/`.
- Commit/PR only when asked. Use Conventional Commits with an allowed scope and
  put task IDs in the body (`Tasks: TXX.Y`).
- If a requirement is intentionally deferred, record it as a follow-up roadmap
  task *before* calling the task done.

## Speed rules
- Use `make gate` as the one gate command; don't run fmt/clippy/test separately.
- Review only the diff — never re-read unchanged files.
- Keep prompts short; the agent files carry the standing rules.
- Parallelize independent research; parallelize implementers only on disjoint files.
- Prefer `ferriscd-fast-fix` over a fresh full implementer for review fixes.
- Report gate counts verbatim; never claim green without the command output.

## Fallback
If a named agent is unavailable in the session, invoke `general` with that
agent file's body prepended to the brief, and keep the same gate/review contract.

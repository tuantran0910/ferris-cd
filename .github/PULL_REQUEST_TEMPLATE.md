## Summary
<!-- Briefly describe what this PR changes and why. -->

## Roadmap Task
<!-- Reference atomic task ID(s) from docs/roadmap/, e.g. T01.1, T01.2 -->
- Task ID(s):

## Changes
-

## Verification
<!-- List exact commands run and observed results. -->
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Live `kind-ferriscd-dev` verification (if applicable, with `^kind-` context guard)

## FerrisCD Invariants & Trap Guard Checklist
- [ ] No `k8s-openapi` version feature (`v1_35`) enabled in library crates (`ferriscd-crd`, `ferriscd-engine`)
- [ ] Zero `unwrap()` / `expect()` in runtime code
- [ ] SSA defaults remain safe (`force: false`), `.status` stripped before apply, secrets redacted
- [ ] Task-specific Trap Guard verified

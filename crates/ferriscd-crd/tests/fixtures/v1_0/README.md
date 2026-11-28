# Frozen `v1.0` contract fixtures (`T20.4`)

Provenance and refresh instructions for the frozen `v1.0` baseline used by the `v2.0`
backward-compatibility checker (`crates/ferriscd-crd/tests/schema_compat.rs`).

## What is frozen here

* `crds/` — the **exact** `deploy/crds/*.yaml` manifests as of the last `v1.0` commit
  (`56c12be`, the parent of the first Track E commit). They are what an existing `v1.0`
  installation has admitted into its API server, and they are what
  `crates/ferriscd-crd/tests/schema_compat.rs` diffs the current schema against and what
  `tests/integration/v2_0_upgrade_soak.rs` installs as its `v1.0` baseline.
* `resources/` — hand-written `v1.0`-shaped custom resources (`Application`, `AppProject`).
  They must keep deserializing, validating and round-tripping under the current types.

`v1.0` shipped no `ApplicationSet` CRD (it arrived in `T19.3`), so there is deliberately no
fixture for it: a brand-new CRD is additive by construction.

## How to refresh (only on a new baseline)

```text
git show 56c12be:deploy/crds/applications.ferriscd.io.yaml  > crds/applications.ferriscd.io.yaml
git show 56c12be:deploy/crds/appprojects.ferriscd.io.yaml   > crds/appprojects.ferriscd.io.yaml
```

Moving the baseline forward weakens the check, so it is a decision for a major-version bump —
never a fix for a failing `schema_compat` test.

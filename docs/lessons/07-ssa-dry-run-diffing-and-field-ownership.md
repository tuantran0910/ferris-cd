# Lesson 07 — SSA Dry-Run Diffing, `managedFields`, and Secret Redaction

> Phase 07 replaces the `v0.2` "apply the whole desired set on every reconcile" loop with a
> **diff-gated** one: every pass classifies the bundle with a Server-Side Apply
> `dryRun=All` PATCH, the pure engine decides whether anything may be applied
> (`automated` / `selfHeal` / source change / manual operation), and only the resources the diff
> calls `OutOfSync` or `Missing` are actually patched.
>
> Code references: `crates/ferriscd-controller/src/dry_run.rs` (the impure half: one
> `dryRun=All` PATCH per present resource), `crates/ferriscd-engine/src/diff/*` (compare,
> `ignoreDifferences`, redaction, the decision gate), and
> `crates/ferriscd-controller/src/{sync.rs,reconcile.rs}` (where the gate sits, and how the
> result reaches `Application.status`). The live `kind` experiment at the end is **not**
> executed by `make gate`; it is marked *pending* and must be run by hand. **`v0.3` is not
> declared complete until the `#[ignore]`d live test has run on `kind`** (§10) — hermetic tests
> cannot prove that the API server answers a dry-run the way the diffs assume.

---

## 1. Why "apply everything every pass" had to go

`v0.2` issued one `Patch::Apply` per desired resource per reconcile. It is *idempotent* (SSA
guarantees that) but it is not *cheap* nor *observable*:

| Problem | Consequence |
|---|---|
| every pass writes | `metadata.resourceVersion`/`managedFields` churn on 500 objects every 3 minutes; API-server write amplification |
| every pass writes | a `Patch` that changes nothing still runs the full admission/webhook chain, so a slow webhook slows every reconcile |
| no diff, no status | `status.sync.status` could only ever say "I applied N objects", never "live state differs from Git" |
| no policy gate | `automated: None` (manual-only) and `selfHeal: false` were indistinguishable from `selfHeal: true` |

The diff gate fixes all four: the observable cost of a reconcile becomes N *dry-run* PATCHes
(read-only), and a reconcile that has nothing to do writes exactly nothing to the workloads.

---

## 2. What `dryRun=All` actually means

`PATCH …?fieldManager=ferriscd&dryRun=All` with `Content-Type: application/apply-patch+yaml`
runs the **entire write path** and then throws the result away:

* mutating/validating admission webhooks run,
* defaulting runs (so `terminationMessagePath`, `imagePullPolicy`, `strategy` … are filled in),
* the API server computes the post-apply object (the *prediction*),
* `managedFields` conflict detection runs — a field owned by another manager still answers
  `409 Conflict`,
* **nothing is persisted**: `resourceVersion`, `uid`, `generation` and `managedFields` are
  unchanged. That is exactly what makes the live T07.5 test possible (§9.4).

Three consequences drive the implementation:

1. **The prediction is the right thing to compare against.** Comparing live against the raw
   YAML would report every defaulted field as drift forever. Comparing live against the
   *prediction* reports only fields that genuinely differ, because both sides went through the
   same defaulting and webhooks (`compare.rs`).
2. **A `409` is a classification, not a failure.** `dryRun=All` evaluates field ownership, so
   the "another field manager owns `spec.replicas`" case surfaces during the diff instead of
   during the apply. `dry_run.rs::parse_conflict_status` turns `Status.details.causes` (with a
   `message`-parsing fallback) into structured `FieldConflict { field, manager }` entries.
3. **`force` is not an option here.** `force: true` would silently take ownership of the
   conflicting field and the diff would report a clean `Synced` — hiding exactly what it exists
   to report (trap T5). `syncOptions.serverSideForce` is therefore logged and ignored in this
   milestone, for the dry-run *and* the apply, so the two always agree.

---

## 3. The desired-body contract: stamp first, then diff

The diff compares the **full documents** — `apiVersion`, `kind`, `metadata`, `spec`, … — not
`DynamicObject::data`. `data` excludes `metadata` and the type fields, so diffing it reported
every label/annotation edit as `Synced` (finding C1).

Because `metadata` participates, so does FerrisCD's own ownership marker,
`ferriscd.io/tracking-id`. Therefore:

> **The object handed to the dry-run must be the very stamped body the applier receives.**

Handing the evaluator a pre-stamp body predicts the *removal* of the annotation, so:

```text
pre-stamp diff:  live{annotations:{tracking-id}} vs predicted{annotations:{}}  -> OutOfSync
apply:           keeps the annotation                                          -> live unchanged
next pass:       same diff again                                               -> OutOfSync forever
```

The resource would be permanently `OutOfSync` and `selfHeal: true` would apply it on every
single reconcile — a self-inflicted hot loop. `InventorySyncPipeline::sync_apply` therefore
runs `stamp_ownership(..)` *before* the diff and passes the same `&resources` slice to the
evaluator and to the applier; the contract is documented on `DryRunEvaluator::evaluate` and on
`DryRunTarget::object`.

Deferred resources are diffed without an API call: `DeferredPendingCrd` /
`DeferredPendingNamespace` / `Missing` are all `Missing` ("create it"), because a commit that
creates a CRD and its CR together cannot dry-run the CR before the kind exists (finding C3).

---

## 4. `managedFields` and field ownership

Kubernetes tracks *which manager owns which field* in `metadata.managedFields`. SSA applies
**only the fields present in the request body**, and each of them becomes owned by
`fieldManager` (`ferriscd`). A field that another manager already owns and that this request
would change is a **conflict**:

```text
Apply of Deployment/payments/api failed: conflict with "kubectl-client-side-apply":
  .spec.replicas
```

FerrisCD's rules:

| Situation | FerrisCD |
|---|---|
| field owned by `ferriscd` | update it (it is ours) |
| field owned by nobody / never set | set it, we own it from now on |
| field owned by another manager | `409` → reported `OutOfSync` with `{field, manager}`; **never** forced by default |
| whole object owned by another `Application` (`tracking-id`) | `OwnershipConflict`: no dry-run, no apply, no prune (trap T10) |

Two traps live here:

* **Trap T5 — never `force: true` by default.** Forcing hides the conflict, steals the field
  from the HPA / kube-controller-manager, and the next write by the other controller starts a
  fight. `takeoverFieldManagers`-style, explicitly-opted-in forcing is `T08.4`.
* **Finding M4 — an ownership conflict is terminal, not drift.** If `DiffStatus::
  OwnershipConflict` counted as drift, `selfHeal: true` would execute on every reconcile
  forever and could never converge (the apply it authorizes cannot succeed). It is therefore
  excluded from `DiffSummary::has_drift()` while still keeping
  `status.sync.status = OutOfSync` and failing the reconcile once (terminal backoff,
  `REASON_OWNERSHIP_CONFLICT`).

`metadata.managedFields` itself is stripped before comparison: it is server bookkeeping, so a
manager rename would otherwise show up as drift.

---

## 5. What counts as drift

`compare.rs` canonicalizes both documents in this order (do not reorder — redaction must run
before anything can be recorded):

1. **redact** — `Secret` values and the `last-applied-configuration` annotation (§7),
2. **strip volatile** — `metadata.resourceVersion`, `uid`, `generation`, `creationTimestamp`,
   `managedFields`, and the top-level `.status`,
3. **remove `ignoreDifferences` pointers** on *both* sides,
4. **diff** into `Added` / `Removed` / `Modified` field changes (bounded to
   `MAX_FIELD_CHANGES = 100` per resource; the *verdict* is computed independently of the cap).

Everything else is compared, including `metadata.labels`/annotations and API-defaulted fields.

| `DiffStatus` | Meaning | Sync consequence |
|---|---|---|
| `Synced` | canonicalized live == prediction | nothing to do |
| `OutOfSync` | a field differs, or the dry-run answered `409` | apply |
| `Missing` | does not exist yet, or the dry-run was skipped because a CRD/namespace is pending | create |
| `Orphaned` | tracked in `status.inventory`, no longer in Git | prune (when allowed) |
| `OwnershipConflict` | the live object carries another `Application`'s `tracking-id` | fail once, never heal |

`DiffSummary` is **counts only** (`trap T9`: `Application.status` must stay small) and maps
onto `status.sync.status` through `DiffSummary::sync_status()`.

---

## 6. `ignoreDifferences`: RFC 6901 JSON Pointers

`Application.spec.ignoreDifferences` lists, per Group/Kind (optionally narrowed by
name/namespace), the JSON Pointers whose live/desired values must not be compared:

```yaml
spec:
  ignoreDifferences:
    - kind: Deployment
      jsonPointers:
        - /spec/replicas              # an HPA owns the replica count
    - group: ""                     # core group; omit to match any group
      kind: Secret
      name: registry-creds
      namespace: payments
      jsonPointers:
        - /data/password
```

Rules the implementation pins down (`ignore.rs`):

* Pointers are parsed with `jsonptr` (RFC 6901): `~0` escapes `~`, `~1` escapes `/`. A pointer
  is validated once at compile time, not per object.
* A pointer that does not resolve is a **no-op**, never an error: one typo in
  `ignoreDifferences` must not break every other resource. (`/spec/replicaz` on an object that has
  no such field is the canonical case: it *is* a valid pointer, it just resolves to nothing.)
* The pointer is removed from **both** sides, so the comparison stays symmetric and a resource
  whose only difference is ignored becomes `Synced` (and is therefore skipped by the apply).
* **A pointer that is not RFC 6901 at all is never applied — and never silent.** `PointerBuf`
  rejects only malformed pointers (a missing leading `/`, a bad `~` escape: `spec/replicaz` rather
  than `/spec/replicaz`). Those are collected (`IgnoreRuleSet::invalid_pointers`) and removed from
  neither side, and `sync_apply` surfaces them twice: one `tracing::warn!` per pointer carrying the
  `Application` namespace/name and the pointer itself (bounded to
  `MAX_LOGGED_INVALID_POINTERS = 8` lines per reconcile, so a spec full of typos cannot flood the
  log), **and** a count appended to the `Ready` condition message —
  `… ; 1 invalid ignoreDifferences pointer ignored` — because a warning that only exists in a log
  is invisible on the CR. A silently dropped typo is worse than an error: the operator believes a
  field is ignored while the diff keeps reporting it (finding H1).
* Field removal happens *before* the diff but *after* redaction, so an ignored `Secret` path is
  still redacted on the way through the code that could log it.

**Known limitation (documented, not hidden):** `ignoreDifferences.managedFieldsManagers` is
part of the CRD schema but the engine does not apply it yet; only `jsonPointers` are honoured.
Until it lands, "ignore whatever manager X owns" must be expressed as explicit pointers.

---

## 7. Secret redaction (trap T4)

A `dryRun=All` response is a **full object**, so for a `v1/Secret` it contains every base64
value. Without redaction, one `debug!` call or one `GET /diff` response leaks every credential
in the cluster.

* `.data` and `.stringData` values are replaced with
  `***REDACTED(sha256:<first-8-hex>)***`. The fingerprint keeps redacted diffs *useful*: an
  unchanged value produces the same placeholder on both sides (still `Synced`), a changed value
  produces a different one (`OutOfSync`) — and the plaintext never exists on either side.
  It is a diff fingerprint, **not** a password hash: it reveals "changed vs unchanged" plus a
  32-bit digest prefix and must never be used to verify a secret.
* `kubectl.kubernetes.io/last-applied-configuration` embeds a whole applied document — for a
  `Secret`, the base64 payload — so it is fingerprinted for **every** kind, not only for
  `Secret` (finding H1).
* `ResourceDiff::compare` is the **only** constructor that accepts raw payloads, and a
  `ResourceDiff`'s parts are crate-private, so no diff preview, log line, or API response can
  carry a raw secret value: redaction happens before the first change is recorded.
* `DryRunError::api` replaces the API server's message for `v1/Secret` keys with a fixed
  placeholder: a `400`/`422` for a Secret echoes the offending *value* ("illegal base64 data at
  input byte …"), and that message is logged and can reach `Application.status`.
* `Debug` for `DryRunTarget` / `DryRunOutcome::Predicted` deliberately omits the body.

---

## 8. Where the gate sits (`sync.rs`) and what it persists

```text
validate spec → reject createNamespace → resolve revision → checkout + load/parse (spawn_blocking)
  → tier sort → reject generateName/hooks → collect in-bundle CRDs → DiscoveryCache::ensure_fresh
  → normalize_scopes + duplicate check
  → stamp_tracking_id                                    ← before the diff (contract, §3)
  → empty-desired guard
  → plan_fetch(desired ∪ prev_inventory) → ClusterStateReader::fetch_live   (16 concurrent GETs)
  → reject OwnedByForeign                                (terminal, no dry-run, no apply; trap T10)
  → DryRunEvaluator::evaluate(stamped desired, orphans, live, ignoreDifferences)
  → DiffSummary + source_spec_hash(spec.source, spec.destination)
  → should_sync(app, resolved_sha, spec_hash, summary, manual_op)          (pure, T07.4)
  → apply ONLY the keys the diff calls OutOfSync/Missing (applyOutOfSyncOnly, default true)
  → prune (only when the gate executed, and only with automated.prune)
  → next_inventory(prev, confirmed, pruned) + status.sync
```

The decision table (`ferriscd_engine::diff::decision`):

| `syncPolicy.automated` | `selfHeal` | Executes when |
|---|---|---|
| absent | — | never automatic (`Skip(AutomatedDisabled)`); a manual operation still syncs |
| present | `false` | `(commit_sha, source_spec_hash)` differs from `status.sync.lastSynced*` |
| present | `true` | source changed, **or** any `OutOfSync`/`Missing`, **or** (`prune` and any orphan) |
| any | any | a manual operation: `ferriscd.io/operation` present and non-blank |

`source_spec_hash` is `sha256(canonical_json(spec.source, spec.destination))` (finding H7).
Without it, `selfHeal: false` compared only the commit SHA, so editing
`spec.source.git.path` — a different directory in the *same* commit — never synced until
somebody pushed. The hash is persisted as `status.sync.lastSyncedSpecHash` next to
`lastSyncedRevision`, and both markers are written by the same successful pass (a pass that
did not refresh them reports `None`, and `reconcile::merge_sync_state` keeps the previous
values instead of clearing them).

Status mapping (`build_outcome`):

| Outcome | `status.sync.status` | `lastSynced*` | `Ready` reason |
|---|---|---|---|
| `Execute`, nothing pending | `Synced` | all three written | `SyncSucceeded` |
| `Execute`, something pending on a CRD/namespace | `OutOfSync` (from the summary) | not advanced | `PendingDependencies` (requeue 10 s) |
| `Skip(...)` | from the diff summary (orphans excluded when `prune: false`, see below) | untouched | `SyncSkipped` |
| `OwnershipConflict` | `OutOfSync` | untouched | `OwnershipConflict` (`Ready=False`, terminal) |

Notes that matter:

* **A `Skip` still updates the status.** That is the whole point of `selfHeal: false`: the
  operator sees `OutOfSync` without the controller touching the cluster.
* **`prune` decides how an orphan maps onto `status.sync.status`, and both pass kinds agree.**
  `DiffSummary::sync_status()` (the engine) reports `OutOfSync` for an orphan, which is right when
  `automated.prune` is **enabled**: the orphan is a prune that is still due. With `prune: false`
  nothing will ever delete that object, so `build_outcome` maps the summary through
  `sync_status_without_orphans` (drift and ownership conflicts still count) and reports the
  retained orphan in the `Ready` message (`N orphan(s) retained`). Both the executing pass and the
  `Skip` pass that follows it therefore report `Synced` for a Git-removed-but-tracked resource
  (finding H2, the T06 contract); the count of retained orphans is the diff's orphan count on the
  `prune: false` path, because the prune pass is a pure no-op there and used to report zero.
* **A pass that executed and left nothing pending reports `Synced`, even when a prune-disabled
  orphan remains.** The orphan is reported in the `Ready` message (`N orphan(s) retained`),
  not by pinning `sync.status` to `OutOfSync` forever; the T06 live contract asserts exactly
  that for a Git-removed-but-tracked resource with `prune: false`.
* **A `Synced` resource is diff-verified**, so it is recorded in `status.inventory` even on a
  skipped pass — otherwise a wiped `status.inventory` would leak it as an untracked orphan
  (finding C1; `v0.2` self-healed this only because it re-applied everything).
* **`fetched` and `applied` are different sets.** `status.inventory` is
  `next_inventory(prev, applied_ok ∪ synced_ok, pruned_ok)`, and a mid-sync failure still
  persists the partial inventory (`ReconcileError::PartialSync`).
* **`ferriscd.io/refresh` is not a sync request**; it only asks for an immediate reconcile and
  the gate still decides. `ferriscd.io/operation` is, and it bypasses every policy. Until
  `T10.x` persists/clears `status.operationState`, a *stale* operation annotation keeps
  requesting manual syncs — which can only cause an extra idempotent apply, never a missed one.
* **A manual-only (`automated: None`) `Application` is not free.** It applies nothing, but every
  requeue still issues **one `dryRun=All` PATCH per *present* resource** — that is how drift is
  reported on the CR. Only the mutating calls are zero. Likewise, `prune: true` combined with
  `selfHeal: false` only prunes on a revision/spec-hash change: the diff gate skips on an
  unchanged source, and a skip issues no deletes (so an orphan shows up as `OutOfSync` until the
  next source change or manual operation).

The zero-write invariant is observable at the `Applier` seam: `InventorySyncPipeline::
mutating_applies()` counts issued SSA applies (dry-runs are not counted), so "a second
reconcile of an already-synced `Application` issues **0** mutating `Patch` calls" is asserted
hermetically over the fake cluster and live over `resourceVersion` (§9.4).

### Known limitations (Phase 07, tracked — do not hide)

* **A dry-run `409` cannot be acted on yet.** `dryRun=All` surfaces the field conflict as a
  *classification*: the resource is reported `OutOfSync` with `FieldConflict { field, manager }`,
  and `selfHeal: true` then executes and applies it — which the API server answers with a real
  `409` again, this time as a *retryable apply error* (`ReconcileError::Api`, backoff, no status
  change in the affected field). The diff is therefore honest (it names the manager) but not
  actionable: there is no "do it anyway" path until `syncOptions.takeoverFieldManagers`
  (`T08.4`), and the transient self-heal churn is the price of not forcing (trap T5).
* **`FieldConflict` is not surfaced in `Application.status` yet.** The conflicts are computed,
  redacted and bounded (`MAX_FIELD_CONFLICTS`), and they reach the log and the in-process diff
  result, but no `status` field is allocated for them (that is `T08.4`). Until then the operator
  sees `OutOfSync` plus the log line, not `{field, manager}` on the CR.
* **`ignoreDifferences.managedFieldsManagers`** is accepted by the CRD but not consulted (§6):
  only `jsonPointers` are honoured.

---

## 9. Manual `kind` walkthrough — **PENDING (not yet executed)**

Everything below must be run by hand against `kind-ferriscd-dev`. **No output is recorded in
this repository yet**, and nothing here is asserted by CI. Do not treat any expected value
below as a measurement: they are the assertions to *check*, not results.

```bash
# 0. cluster + CRDs + control-plane namespace
make kind-up
kubectl apply -f deploy/crds
kubectl create namespace ferriscd-system --dry-run=client -o yaml | kubectl apply -f -

# 1. a fixture repo with a Namespace and one ConfigMap
export DEMO=$(mktemp -d); mkdir -p "$DEMO/repo" && cd "$DEMO/repo"
cat > namespace.yaml <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: ferriscd-demo
EOF
cat > cm.yaml <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo
data:
  key: value
EOF
git init --initial-branch=main . && git add . \
  && git -c user.name=demo -c user.email=demo@example.com commit -m seed
git rev-parse HEAD   # note this SHA: it must never change in §9.1-§9.3
cd -

# 2. run the controller (local repos are opt-in)
cargo run -p ferriscd-cli -- controller --allow-local-repos --namespace ferriscd-system
```

### 9.1 `automated: None` — report drift, never apply

```bash
kubectl apply -f - <<EOF
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata: { name: demo, namespace: ferriscd-system }
spec:
  source: { git: { repoURL: $DEMO/repo, targetRevision: main, path: . } }
  destination: { cluster: in-cluster, namespace: ferriscd-demo }
  requeueAfterSeconds: 15
EOF
```

Expected (verify, do not assume):

* `kubectl get cm -n ferriscd-demo` → **`No resources found`**: nothing was applied, not even
  the `Namespace`.
* `status.conditions[?(@.type=="Ready")]` → `status=True, reason=SyncSkipped`, message
  beginning `no sync performed: automated sync is disabled;`.
* `status.sync.status` → `OutOfSync`; `status.sync.lastSyncedRevision` → **empty**;
  `status.inventory` → `[]`.

### 9.2 `selfHeal: false` — source-change-only sync

```bash
kubectl patch application demo -n ferriscd-system --type=merge \
  -p '{"spec":{"syncPolicy":{"automated":{"prune":false,"selfHeal":false}}}}'
```

The policy change is not part of `source_spec_hash`, and there is no `lastSyncedRevision` yet,
so the source counts as changed: the first pass after this patch **does** sync.

* `status.sync.status` → `Synced`, `lastSyncedRevision` = the SHA from §1,
  `lastSyncedSpecHash` = a 64-hex digest, `lastSyncedAt` set.
* `kubectl get cm demo -n ferriscd-demo -o yaml` → `data.key: value` **and**
  `metadata.annotations.ferriscd\.io/tracking-id: ferriscd-system/demo:/ConfigMap:ferriscd-demo/demo`.

Now create drift by hand and confirm nothing is written:

```bash
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.metadata.resourceVersion}{"\n"}' > /tmp/rv1
kubectl patch cm demo -n ferriscd-demo --type=merge -p '{"data":{"key":"tampered"}}'
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.metadata.resourceVersion}{"\n"}' > /tmp/rv2   # changed by *us*
# wait at least two reconciles, then:
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.data.key}{"\n"}'        # expect: tampered (not healed)
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.metadata.resourceVersion}{"\n"}'  # expect: same as /tmp/rv2
kubectl get application demo -n ferriscd-system \
  -o jsonpath='{.status.sync.status}{" "}{.status.conditions[?(@.type=="Ready")].reason}{"\n"}'
#   expect: OutOfSync SyncSkipped
```

Finally prove finding H7 — a *spec* edit that produces no new commit must still sync:

```bash
# 1. add a second directory to the same repository and commit it (this one *does* move the SHA,
#    so it is picked up normally and records the new SHA + the spec hash of path ".")
mkdir -p "$DEMO/repo/other"
sed 's/name: demo/name: demo-other/' "$DEMO/repo/cm.yaml" > "$DEMO/repo/other/cm.yaml"
cd "$DEMO/repo" && git add other \
  && git -c user.name=demo -c user.email=demo@example.com commit -m other
git rev-parse HEAD                        # -> this becomes status.sync.lastSyncedRevision
cd -
kubectl get application demo -n ferriscd-system \
  -o jsonpath='{.status.sync.lastSyncedRevision}{"\n"}'

# 2. now change only spec.source.git.path — no new commit, so the SHA cannot change
kubectl patch application demo -n ferriscd-system --type=merge \
  -p '{"spec":{"source":{"git":{"path":"other"}}}}'
kubectl get application demo -n ferriscd-system \
  -o jsonpath='{.status.sync.revision}{" "}{.status.sync.lastSyncedRevision}{"\n"}'
#   expect: the SAME sha on both sides, and:
kubectl get application demo -n ferriscd-system \
  -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}{"\n"}'
#   expect: … (sourceChanged)     <- found by lastSyncedSpecHash, not by the revision
#           (the one desired resource is already Synced, so "applied 0 of 1" is correct here;
#            `demo`/the Namespace are now orphans and, with prune off, are reported as retained)
kubectl get cm demo-other -n ferriscd-demo     # the newly desired resource exists
```

Without `lastSyncedSpecHash` this patch is invisible: `selfHeal: false` would compare only the
commit SHA, decide "unchanged", and never sync until somebody pushed.

### 9.3 `selfHeal: true` — drift is corrected

```bash
kubectl patch application demo -n ferriscd-system --type=merge \
  -p '{"spec":{"syncPolicy":{"automated":{"prune":false,"selfHeal":true}}}}'
kubectl patch cm demo -n ferriscd-demo --type=merge -p '{"data":{"key":"tampered-again"}}'
# wait one reconcile cycle:
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.data.key}{"\n"}'   # expect: value (healed)
kubectl get application demo -n ferriscd-system \
  -o jsonpath='{.status.sync.status}{" "}{.status.conditions[?(@.type=="Ready")].message}{"\n"}'
#   expect: Synced  applied 1 of 2 resource(s) … (driftDetected)
```

The `applied 1 of 2` is the `applyOutOfSyncOnly` trap guard in the field: the Namespace was
`Synced` and was **not** re-patched.

Also inspect what ownership looks like on a managed object (this is the `managedFields` half of
the lesson — the manager must be `ferriscd`, and `spec`/`data` fields must be owned by it):

```bash
kubectl get cm demo -n ferriscd-demo -o jsonpath='{range .metadata.managedFields[*]}{.manager}{" "}{.operation}{"\n"}{end}'
#   expect: ferriscd Apply
```

### 9.4 The T07.5 assertion: an already-synced Application performs 0 mutating `Patch` calls

`dryRun=All` does not persist anything, so a reconcile that applies nothing cannot change
`metadata.resourceVersion`. That is the live observation:

```bash
kubectl get ns ferriscd-demo -o jsonpath='{.metadata.resourceVersion}{"\n"}'
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.metadata.resourceVersion}{"\n"}'
# force one full pass that is guaranteed to start *after* this snapshot: requeueAfterSeconds is
# not part of source_spec_hash, so the gate must skip
kubectl patch application demo -n ferriscd-system --type=merge -p '{"spec":{"requeueAfterSeconds":16}}'
kubectl get application demo -n ferriscd-system \
  -o jsonpath='{.metadata.generation}{" "}{.status.observedGeneration}{"\n"}'   # expect: equal
kubectl get application demo -n ferriscd-system \
  -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}{"\n"}'           # expect: SyncSkipped
kubectl get ns ferriscd-demo -o jsonpath='{.metadata.resourceVersion}{"\n"}'    # expect: UNCHANGED
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.metadata.resourceVersion}{"\n"}'  # expect: UNCHANGED
```

Then the control leg (otherwise "unchanged" proves nothing — this is the same observation
detecting a write):

```bash
kubectl patch cm demo -n ferriscd-demo --type=merge -p '{"data":{"key":"drifted"}}'
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.data.key}{"\n"}'   # eventually: value (healed)
kubectl get cm demo -n ferriscd-demo -o jsonpath='{.metadata.resourceVersion}{"\n"}'  # CHANGED
```

### 9.5 cleanup

```bash
kubectl delete application demo -n ferriscd-system
kubectl delete namespace ferriscd-demo
make kind-down
```

**Status:** pending manual execution. Replace this paragraph with the observed
`managedFields`, `status.sync` and `resourceVersion` output — and with every *surprise* — once
the walkthrough has actually run on `kind-ferriscd-dev`.

---

## 10. What is verified automatically

```bash
make gate                # fmt + clippy + unit/integration tests (no cluster)
make test-integration    # the #[ignore]d live tests (requires kind-up)
```

Hermetic coverage (no cluster, no network):

* **Engine** (`crates/ferriscd-engine/src/diff/`): the full `should_sync` truth table
  (`automated: None` / `selfHeal: false` / `selfHeal: true` × drift/orphans × source change);
  `source_spec_hash` determinism, coverage of every `spec.source`/`spec.destination` field and
  an independently computed digest; canonical JSON key ordering; `ignoreDifferences` RFC 6901
  escaping, missing-pointer no-ops, symmetric removal; `Secret` redaction (values, the
  `last-applied-configuration` annotation, no plaintext in `Debug`/`Display`/serialization);
  `DiffSummary` counting and `sync_status()`; ownership conflicts excluded from drift.
* **Evaluation** (`dry_run.rs`): classification per `LiveState`, no dry-run for
  `Missing`/deferred/foreign objects, `409` parsing from `details.causes` and from `message`,
  bounded `MAX_FIELD_CONFLICTS`, `force` propagation, `Secret` server-message redaction,
  bounded concurrency (16), deterministic key ordering.
* **Wiring** (`sync.rs`): the stamped slice is what gets diffed; an already-synced
  `Application` + `selfHeal: true` ⇒ **0** applies while dry-runs still happen; drift +
  `selfHeal: true` ⇒ only the drifted resource; `selfHeal: false` + unchanged
  `(revision, spec hash)` ⇒ `Skip(SelfHealDisabled)` with `OutOfSync` and 0 applies; a
  `spec.source.git.path` edit with an unchanged SHA ⇒ `Execute(SourceChanged)` + apply; a
  manual operation annotation overrides `automated: None`; `applyOutOfSyncOnly: false` re-applies
  synced resources; an ownership conflict applies nothing, dry-runs nothing, reports
  `OutOfSync`, and is terminal (no loop); the pure `apply_selection` trap guard;
  an invalid `ignoreDifferences` pointer is counted in the `Ready` message while a valid one is
  honoured (H1); a `Skip` pass with `prune: false` reports `Synced` + `N orphan(s) retained`,
  with `prune: true` reports `OutOfSync` and deletes nothing, and an executing pass with
  `prune: false` reports `Synced` + the count (H2).
* **Error classification** (`reconcile.rs`): `OwnershipConflict` is terminal; a `DryRunError`
  is classified like an API error — `0`/`408`/`409`/`425`/`429`/`5xx` retryable,
  `403`/`404`/`422`, unserved kind and serialization failures terminal (M2).
* **Status** (`reconcile.rs`): `lastSyncedRevision`/`lastSyncedSpecHash`/`lastSyncedAt` are
  written together by a successful pass and preserved by a pass that did not refresh them;
  `SyncSkipped`/`PendingDependencies`/`OwnershipConflict` reasons; the failure path persists the
  partial inventory and the `OutOfSync` status.

Live coverage (`tests/integration/v0_2_controller.rs`, `#[ignore]`d, `kind-` context guarded):
the T06 legs (union fetch, removed-but-tracked resource, prune) plus the T07.5 leg of §9.4 —
record the managed objects' `resourceVersion`, force a post-snapshot reconcile via
`metadata.generation`, assert the versions did not move, then hand-edit the ConfigMap and
assert self-heal *does* move them.

# Lesson 03: Kubernetes Manifests, YAML 1.2, and Offline Normalization

> **Phase:** 03 — Manifest Engine (YAML 1.2 & Offline Normalization)
> **Related ADRs:** [ADR-0003: GKNN Inventory & Tracking Id](../adr/0003-gknn-inventory-and-tracking-id.md) · *ADR-0006 (`serde-saphyr` YAML 1.2 + budgets, planned)*
> **Code Walkthrough:** [`manifest/types.rs`](../../crates/ferriscd-engine/src/manifest/types.rs) · [`manifest/yaml.rs`](../../crates/ferriscd-engine/src/manifest/yaml.rs) · [`manifest/loader.rs`](../../crates/ferriscd-engine/src/manifest/loader.rs) · [`manifest/normalize.rs`](../../crates/ferriscd-engine/src/manifest/normalize.rs) · [`graph/mod.rs`](../../crates/ferriscd-engine/src/graph/mod.rs) · [`commands/apply.rs`](../../crates/ferriscd-cli/src/commands/apply.rs)

---

## 1. The Pipeline in One Paragraph

`ferriscd apply` turns a Git checkout into ordered Server-Side Apply calls:

```text
checkout.root_dir + source.path
        │  loader::load          (canonicalize, jail to root, deterministic sort, limits)
        ▼
Vec<ManifestFile>
        │  yaml::parse_file      (multi-doc YAML 1.2, budgets, v1/List flatten, validate)
        ▼
Vec<DesiredResource>            (ResourceKey = GKNN, version-agnostic)
        │  normalize::normalize  (strip .status + server metadata, Secret.stringData→.data, dedup GKNN)
        ▼
Vec<DesiredResource>
        │  graph::sort_by_tier   (Namespace → CRD → RBAC/Config/Secret → everything else)
        ▼
Discovery scope resolution → inject --namespace only on namespaced objects lacking one → SSA Patch::Apply (force: false)
```

Every stage is a pure, unit-tested function; the only I/O is file reads (loader), YAML text (parser), and the final Kubernetes API calls.

---

## 2. YAML 1.2 vs 1.1: The Traps That Bite Real Manifests

YAML 1.1 (the old `yes/no/on/off` boolean schema and base-8 octals) is still what many "YAML" parsers implement. `serde-saphyr` is a YAML **1.2** parser, and FerrisCD configures it to match the YAML 1.2 core schema:

```rust
serde_saphyr::options! {
    duplicate_keys: DuplicateKeyPolicy::Error,
    strict_booleans: true,                // reject yes/no/on/off as booleans
    leading_zero_numbers_as_strings: true, // 0123 stays "0123", not octal 83
    // ... alias-replay limits, budget
}
```

The three concrete traps and how the parser handles them:

| Input | YAML 1.1 naive | FerrisCD (YAML 1.2) |
|---|---|---|
| `on: on` | `on → true` (boolean) | `on → "on"` (string) |
| `oct: 0123` | `0123 → 83` (octal) | `0123 → "0123"` (string) |
| duplicate key | last-wins (silent) | **error** with file + document index |

That last row matters more than the first two. A GitOps engine that silently "last-wins" a duplicated `metadata.name` or `replicas` key will deploy something different from what the author reviewed. FerrisCD rejects duplicates up front (`manifest::yaml::tests::duplicate_yaml_key_is_rejected_with_document_index`).

Non-string map keys (`1: value`, `true: value`) are not silently dropped: `serde_json::Value` requires string keys, so `serde-saphyr` preserves the key's original spelling (`1` → `"1"`, `true` → `"true"`). The behavior is deterministic and covered by `manifest::yaml::tests::non_string_map_keys_are_coerced_to_their_string_spelling`.

---

## 3. Multi-Document Streams, `v1/List`, and Null Documents

Real Kubernetes manifests are multi-document streams:

```yaml
# a comment-only document (skipped)
---
apiVersion: v1
kind: ConfigMap
metadata: { name: a }
---
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    metadata: { name: b }
  - apiVersion: apps/v1
    kind: DeploymentList
    items:
      - apiVersion: apps/v1
        kind: Deployment
        metadata: { name: c }
---
```

The parser:

1. **Splits documents** on column-0 `---` markers (trailing `---` and comment-only/`null`/`~` documents are skipped).
2. **Flattens recursively**: any object whose `kind == "List"`, or whose `kind` ends in `"List"` and has an `items` array, is replaced by its items. Nested lists work because flattening recurses.
3. **Validates** every resulting object: non-empty `apiVersion`, `kind`, and `metadata.name` — with `metadata.generateName` allowed **only** when the `ferriscd.io/hook` annotation is present.

Why flatten `v1/List` and typed `*List`? `kubectl get ... -o yaml` frequently wraps a set of objects in a `List`, and the Kubernetes API accepts a `List` but SSA cannot address an individual item inside it. Flattening turns "one wrapper object" into "N addressable objects", which is the only shape the apply/diff/inventory stages understand.

A design note worth calling out: `serde_saphyr::from_multiple` silently drops null/empty documents, which makes an accurate **1-based document index** impossible for a stream that mixes real and empty documents. The parser therefore runs the public whole-stream budget check (`check_yaml_budget`) and then splits/parses documents itself so errors can say *"`apps/base.yaml`: document 2: kind must be present…"*. The splitter only treats a column-0 `---` followed by whitespace/comment/end-of-line as a marker; block-scalar content is always indented, so it can never be mistaken for one.

Inline marker content is preserved, not dropped: for `--- {apiVersion: v1, kind: ConfigMap, metadata: {name: inline}}` only the three-character `---` token is stripped and the remainder (` {apiVersion: ...}`) is parsed as the document body. A `kind: List` (or typed `*List`) without an `items` array is a **clear error**, never a silent drop or a confusing "missing metadata.name" failure.

---

## 4. Budgets: The Billion-Laughs Defense

YAML aliases/anchors make exponential expansion ("billion laughs") possible:

```yaml
a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
# ... 9^9 leaf scalars from a handful of lines
```

FerrisCD enforces two independent layers:

- **Whole-stream `Budget`** (`check_yaml_budget`): `max_aliases`, `max_anchors`, `max_depth`, `max_nodes`, `max_events`, `max_total_scalar_bytes`, `max_documents`, `max_merge_keys`.
- **Alias-replay limits** in `Options::alias_limits`: `max_total_replayed_events`, `max_replay_stack_depth`, `max_alias_expansions_per_anchor`. These are what actually stop exponential *replay* during deserialization.

The bomb above is rejected (terminal, non-retryable) by `manifest::yaml::tests::billion_laughs_alias_bomb_is_rejected_by_budget`. The exact budget numbers live as constants at the top of [`manifest/yaml.rs`](../../crates/ferriscd-engine/src/manifest/yaml.rs) and are deliberately tightened below `serde-saphyr`'s permissive defaults (e.g. `max_aliases = 100`, `max_depth = 32`, `max_nodes = 50_000`).

> **API note:** `serde-saphyr 2.2`'s `Budget` has no single "max bytes" knob for `&str` input (`max_reader_input_bytes` applies only to reader-based entry points; string input is already in memory). The byte-level protection for `&str` manifests is therefore the **loader's** total-byte budget plus `max_total_scalar_bytes`/`max_nodes` on the parse. This is the closest supported protection, documented here rather than inventing a knob.

---

## 5. `Secret.stringData` Is Write-Only

`v1/Secret` has two overlapping fields:

- `data`: base64-encoded values (what the API server *stores and returns*).
- `stringData`: plaintext values (convenience; the API server encodes them into `data` on write and **never returns** them).

If an engine diffs the *desired* `stringData` (plaintext) against the *live* `data` (base64), every reconcile reports phantom drift forever. That is finding **T4**. The offline normalizer therefore converts eagerly:

```text
stringData: { password: "s3cret" }   →   data: { password: base64("s3cret") }
```

Rules (matching API-server semantics, `manifest::normalize::tests::string_data_wins_and_is_base64_encoded_then_removed`):

- `stringData` **wins** over a same-named `.data` entry.
- encoded values are standard base64 (`base64::engine::general_purpose::STANDARD`);
- `stringData` is removed after the merge;
- the conversion happens **offline**, before any diff/apply.

`base64` was already in the lockfile via `gix`/`k8s-openapi`, so it was added as a workspace dependency edge rather than a new external crate.

---

## 6. Offline vs. Cluster-Aware Normalization

The offline normalizer strips:

- top-level `.status`,
- server-managed metadata: `uid`, `resourceVersion`, `generation`, `creationTimestamp`, `managedFields`, `selfLink`.

It deliberately does **not** inject `destination.namespace`. That is the offline/cluster-aware boundary (finding **H1**): offline code cannot know whether a *custom* CRD is cluster-scoped or namespaced, so guessing would put a namespace on a cluster-scoped CR or fail to add one to a namespaced CR. Namespace injection is deferred to the cluster-aware stage (`kube::Discovery` scope resolution), which the standalone CLI performs right before apply:

```rust
// Scope::Namespaced + no metadata.namespace  -> inject --namespace
// Scope::Namespaced + explicit namespace     -> leave it
// Scope::Cluster                             -> never touch
```

The function (`commands::apply::inject_namespace`) is unit-tested for all three cases, and updates both the object and its `ResourceKey.namespace` in lockstep.

Duplicate detection runs on the version-agnostic GKNN key (`group/kind/namespace/name`) and names **both** source files in the error, so an operator can find the collision immediately instead of debugging a mysterious last-write. It runs **twice** in `ferriscd apply`: once after offline normalization, and once again after namespace injection, because injecting `--namespace` into one object can make it collide with a sibling that already declared that namespace.

> **v0.1 limitation — in-bundle CRD + CR:** `kube::Discovery` is run **once**, before any apply call, so a `CustomResourceDefinition` and a `CustomResource` (CR) that both live in the same bundle cannot resolve in the same pass: the CR's GVK is not discoverable until the CRD is actually created on the cluster. This milestone applies such bundles by first applying the CRD, then requires a **separate** run (or a future phase's deferred/re-discovery stage) to apply the CR. Do not rely on a single `v0.1` `ferriscd apply` invocation to bootstrap a CRD and its CRs together.

---

## 7. Version-Agnostic Identity and Deterministic Ordering

`ResourceKey` is `group + kind + namespace + name` — **no version**. Two manifests that differ only by `networking.k8s.io/v1beta1` → `networking.k8s.io/v1` therefore have the *same* identity (finding **C2**). The version is carried on `GroupVersionKind` as a non-key hint, so an API upgrade never self-prunes a previously managed object.

Apply order is a 4-tier deterministic sort (`graph::sort_by_tier`):

| Tier | Kinds |
|---|---|
| 0 | `Namespace` |
| 1 | `CustomResourceDefinition` |
| 2 | `ServiceAccount`, `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`, `ConfigMap`, `Secret` |
| 3 | everything else |

Ties break by `ResourceKey` (`Ord` is derived), so the same input always produces the same order — no filesystem-order flakiness when a `Deployment` happens to sort before its `Namespace` in a directory listing. The function is intentionally minimal and is the seed for the full sync-wave/hook graph in Phase 08/10.

---

## 8. Live Verification (Manual / Pending)

The live `kind` experiment is **not yet executed** in this pass (no live `kind` execution during implementation). It is captured as an `#[ignore]`d integration test at [`tests/integration/v0_1_apply.rs`](../../tests/integration/v0_1_apply.rs), compiled by the `ferriscd-cli` test target.

The test's first statement is the safety gate required by AGENTS.md:

```rust
let context = current_kube_context();
assert!(context.starts_with("kind-"), "refusing to touch non-kind cluster '{context}'");
```

Manual verification steps (run on a `kind` cluster, never a real one):

```bash
make kind-up
make test-integration
# or, targeting the single live test:
cargo test -p ferriscd-cli --test v0_1_apply -- --ignored --nocapture
```

Expected result once executed: `ferriscd apply` against a local Git repo creates a `Namespace` + `ConfigMap`, the second run is an idempotent SSA no-op, and both runs print `applied: /Namespace/ferriscd-demo/ferriscd-demo` and `applied: /ConfigMap/ferriscd-demo/demo-config`.

> **Status:** **pending manual verification.** All offline stages are covered by unit tests; the live `kind` path remains to be observed when a cluster is available.

---

## 9. Invariants to Carry Forward

| Invariant | Where | Failure it prevents |
|---|---|---|
| YAML 1.2 scalars (`on`/`off`/`0123`) stay strings | `strict_booleans`, `leading_zero_numbers_as_strings` | boolean/octal surprise in ConfigMap values |
| Duplicate YAML keys are terminal errors | `DuplicateKeyPolicy::Error` | silently deploying the "wrong" value |
| `v1/List`/`*List` flattened recursively | `yaml::flatten_into` | unaddressable wrapper objects in apply/diff/inventory |
| Budgets + alias-replay limits always on | `strict_budget`, `parse_options` | billion-laughs DoS |
| `Secret.stringData` → base64 `.data`, removed | `normalize::normalize_secret` | phantom drift (T4) |
| No namespace injection offline | normalizer leaves namespace alone | guessing scope of a custom CRD (H1) |
| GKNN identity omits version | `ResourceKey` | API-upgrade self-pruning (C2) |
| Deterministic tier order + `ResourceKey` tie-break | `graph::sort_by_tier` | filesystem-order apply flakiness (H9) |
| File + 1-based document index in every parse error | `ManifestError::YamlParse`/`Validation` | undebuggable "bad YAML somewhere" |
| Live tests gate on `kind-` context first | `tests/integration/v0_1_apply.rs` | touching a non-`kind` cluster |

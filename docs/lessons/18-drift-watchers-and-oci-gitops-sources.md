# Lesson 18: Drift Watchers & OCI Artifact Sources

> **Milestone:** `v1.2` (Phase 18 · Track E)  
> **Tasks:** `T18.1` (`ClusterManager` lifecycle broadcast & `ferriscd.io/app-hash` labels) · `T18.2` (Opt-in
> `PartialObjectMetadata` `DriftWatcher` with `SelfEchoCache` & `403` fallback) · `T18.3` (Additive
> `spec.source.oci` CRD with CEL mutual exclusion & tar-safe extraction) · `T18.4` (Render-cache/
> `AppProject` integration & live OCI `kind` verification)

`v1.1` made FerrisCD a control plane a regulated platform team will admit: readiness is a state machine,
RBAC hot-reloads, and every privileged action is audited. Two gaps remained, and both are about *where
desired state comes from* and *how fast reality is noticed*:

1. **Model 1 drift detection is on-demand.** `v1.0` re-reads `desired ∪ status.inventory` only when a
   requeue, a webhook, or a spec change asks for it — so a `600 s` requeue means an out-of-band
   `kubectl edit` can survive up to ten minutes. Kubernetes events are the only sub-second signal
   available, and consuming them naively means a cluster-wide informer per kind (O(fleet) memory,
   O(cluster) watch pressure).
2. **Every source was Git.** Helm charts and Kustomize bundles are already published as OCI artifacts
   (`helm push`, ORAS, Flux), and teams that ship that way should not be forced to keep a Git mirror
   just to satisfy the reconciler.

Phase 18 closes both without weakening a single safety rail: an **opt-in, label-scoped metadata
watcher** that only *triggers* reconciles, and an **additive `spec.source.oci`** that flows through the
same renderers, `RenderCache`, `source_spec_hash` gate, `AppProject` policy, `/status` history, CLI and
Web UI as `spec.source.git`.

---

## 1. Near-Real-Time Drift Detection Without Cluster-Wide Informers (`T18.1`, `T18.2`)

### 1.1 A bounded identity: `ferriscd.io/app-hash`

A watcher must answer *"which `Application` owns this object?"* from metadata alone. Deriving that from
the object's name is impossible (resource names are unrelated), and listing every `Application` on every
event is O(fleet) work per event. `T18.1` therefore stamps a **second label** next to
`ferriscd.io/managed-by`:

```
ferriscd.io/app-hash = <first 16 lowercase hex of SHA-256("<namespace>/<name>")>
```

| Property | Why it matters |
|---|---|
| Always 16 `[0-9a-f]` characters | Valid under Kubernetes' 63-character label-value limit for *any* `Application` name (up to 253) and namespace |
| Digest of `"<ns>/<name>"`, not of the name | `ns-a/app` and `ns-b/app` never collide (Finding M5: a bare `ferriscd.io/app: <name>` label collides across namespaces) |
| 64 bits, not 128 | `PartialObjectMetadata` must stay small; a theoretical collision costs **one no-op reconcile**, because exact ownership is still verified against `ferriscd.io/tracking-id` immediately before any apply/prune |
| A fixed two-key label set | No label key is ever derived from a name, namespace, cluster, or repository URL, so the label surface cannot grow with the fleet |

### 1.2 The watch plan is derived, never configured

`DriftWatcher` (`crates/ferriscd-controller/src/drift_watcher.rs`) computes its watch set from
`status.inventory` of the `Application`s it already stores — the same GKNN inventory the pruner trusts —
so it watches exactly the kinds FerrisCD actually manages:

```text
ClusterManager broadcast ──► watch plan (cluster × GroupKind from inventory) ──► PartialObjectMetadata watch
        ▲                                                                                    │
        └──────────────── WATCH_REFRESH_INTERVAL (30 s) tick ◄───────────────────────────────┘
```

| Bound | Value | Consequence |
|---|---|---|
| `MAX_DRIFT_WATCHES` | `64` | One watch per `(cluster, GroupKind)`; beyond it the plan is logged and truncated, never unbounded |
| `WATCH_REFRESH_INTERVAL` | `30 s` | A kind that enters an inventory is watched within one tick (see §3.4 — this is an E2E-test prerequisite, not a detail) |
| `DRIFT_DEBOUNCE` / `DRIFT_MAX_DEBOUNCE` | `2 s` / `5 s` | One `kubectl apply -f` touching thirty objects collapses into one trigger per `Application` |
| `DRIFT_TRIGGER_CAPACITY` | `256` | A burst drops triggers under back-pressure instead of growing the queue |
| `FALLBACK_COOLDOWN` | `15 min` | A kind the API server refuses (`403` on `PartialObjectMetadata`) parks instead of retrying per refresh |

The watches are `watcher::metadata` over `PartialObjectMetadata`, filtered by
`ferriscd.io/managed-by=ferriscd` and requested with `resourceVersion=0` semantics — no object bodies,
no decoders, no per-object memory. A slow subscriber that lags the `ClusterManager` lifecycle broadcast
resynchronises from the authoritative `names()` snapshot rather than replaying events.

### 1.3 `SelfEchoCache`: suppressing our own writes

A metadata watch cannot distinguish "the user changed this object" from "**we** changed this object a
millisecond ago", and every apply would otherwise feed back into a reconcile loop. `SelfEchoCache` is
the one place that answers it, keyed by `(cluster, GKNN)`:

| Observation | Suppressed? | Why |
|---|---|---|
| `Modify` of a generation-bearing kind, same `(uid, generation)` | **Yes** (`UnchangedGeneration`) | Only `/status` moved — the controller's own post-apply status patch |
| `Modify` of a generation-less kind, same `resourceVersion` | **Yes** (`Write`) | `ConfigMap`-class kinds have no generation, so the version is the only evidence available |
| `Delete` with a matching `resourceVersion` | **No** | Finding C1: a delete event repeats the object's *last written* version, so a matching version proves nothing — an external `kubectl delete` of an object we just applied carries exactly that version |
| `Delete` after a prune **marker** was recorded | **Yes** (`Prune`), marker consumed | Only a marker proves FerrisCD issued the delete; making it one-shot (Finding M-2) means a re-create cannot leave a durable marker behind |
| Any event older than `SELF_ECHO_TTL` (`60 s`) | **No** | The entry expires; the baseline of a long-lived `/status` churner is refreshed instead (Finding M3) |

The cache is LRU-by-recency capped (`SELF_ECHO_CAPACITY = 10 000`) and swept every `256` writes, so a
fleet larger than the cap degrades to "an echo may cost one extra reconcile", never to unbounded memory.

### 1.4 What a trigger does — and does not do

A drift hit enqueues exactly one `ObjectRef<Application>` through the **same** store, queue, concurrency
limit, backoff and sharding filter as every watch event. It is a *trigger*, never an authority:
`ferriscd.io/tracking-id` still gates every apply and prune, so a stale or colliding trigger can only
waste a pass. Observability is three low-cardinality series:

| Metric | Type | Labels |
|---|---|---|
| `ferriscd_drift_watcher_active_watches` | gauge | — (sampled once per refresh; a parked watch is never counted) |
| `ferriscd_drift_watcher_triggers_total` | counter | `reason` (`debounced`/`coalesced`/…) |
| `ferriscd_drift_watcher_fallback_total` | counter | `reason` (`forbidden`/`unavailable`/…) |

---

## 2. OCI Artifact Sources as a First-Class Source (`T18.3`)

### 2.1 Additive CRD, not a new kind

`spec.source.oci` is an **additional arm** beside `spec.source.git`, so a `v1.0` Git manifest round-trips
byte-identically and every consumer (`status`, `history`, CLI, API, UI) keeps its shape:

```yaml
spec:
  source:
    oci:
      url: oci://ghcr.io/payments/charts        # registry + repository, never a tag
      tag: "1.4.2"                              # mutable pointer, resolved to a digest
      digest: sha256:9f2c…                      # immutable pin, verified when both are set
      path: ""                                  # sub-directory inside the extracted artifact
    renderer:
      helm: {}
```

`repo_url()`/`source_path()`/`requested_revision()` collapse the two arms onto one accessor set, so the
`RenderCacheKey` (`repo_url`, `commit_sha`, `source_path`), `source_spec_hash`, `SourceSummary` and the
`SourceView` DTO never branch on the source kind. An OCI history entry therefore records
`revision: "sha256:<64-hex>"` and `sourceSummary.targetRevision: "<tag>"` — the digest proves *what* ran,
the tag explains *why*.

### 2.2 The CEL rule that no cluster could install

The mutual exclusion (`exactly one of git, oci`) and the "an OCI reference must be immutable" invariant are
injected as `x-kubernetes-validations` on the typed CRD, so the API server's `422` and the offline
`ApplicationSpec::validate()` verdict agree:

```text
spec.source       (has(self.git) && self.git != null && !(has(self.oci) && self.oci != null))
                  || (!(has(self.git) && self.git != null) && has(self.oci) && self.oci != null)
spec.source.oci   self.?tag.hasValue() || self.?digest.hasValue()
```

The second rule **must not** be written `has(self.tag) && self.tag != null`. `tag`/`digest` are
`nullable: true` **strings**, so CEL types `self.tag` as `string` and `string != null` is a *static*
error:

```text
compilation failed: ERROR: <input>:1:28: found no matching overload for '_!=_' applied to '(string, null)'
```

The API server then refuses the **whole CRD** — so `applications.ferriscd.io` could not be installed on
any cluster at all, and every live suite that runs `kubectl apply -f deploy/crds` failed before it
touched an `Application`. Optional chaining (`self.?field`, `.hasValue()`, Kubernetes `>= 1.29`) is the
null-aware spelling with correct static types; `Field::Absent`/`Null`/`Set` parity with
`OciSourceSpec::validate` is asserted over the full 3×3 grid, and a regression guard now fails the build
if a `!= null` comparison ever reappears on a scalar arm. The object-typed arms of the `spec.source`
rule are unaffected: a nullable *object* is compared as a map, not as a scalar.

### 2.3 Fetch is a verified, bounded, offline pipeline

`repo::oci` and `repo::registry` own the whole path, and **no OCI or `reqwest` type escapes `repo/`**:

1. **Validate the reference** (`OciSource::validate`): `oci://`/`https://` only under the production
   policy, no embedded userinfo, `sha256:<64 lowercase hex>` digests, tags bounded to 128 characters.
2. **Resolve** with a `HEAD /v2/<repo>/manifests/<ref>`, verifying a pinned digest when both are set; a
   moved tag that no longer matches the pin is `OciDigestMismatch`, never a silent re-pin.
3. **Fetch the blob through a streaming byte counter** — `Content-Length` is never the authority, so a
   registry cannot make the controller buffer an arbitrarily large body, and the declared layer `size` is
   checked against `WorktreeLimits` *before* the first byte.
4. **Verify, then extract**: the manifest's digest is checked before it is interpreted, the layer's
   SHA-256 while it is streamed into `<work-root>/<scratch>/layer.tar.gz` (written **once** — the
   extractor consumes that same file and re-verifies it, instead of spooling a second copy), and only
   then is the gzip stream read by an in-house tar parser that
   accepts **only** regular files and directories — tar-slip (`../../etc/passwd`), absolute paths,
   symlinks, hard links, device nodes, and a 1 GiB compressed bomb are all rejected before any renderer
   sees a single file, followed by the same worktree-wide symlink sanitizer Git checkouts get.
5. **Unwrap one chart root** only when the layer media type is
   `application/vnd.cncf.helm.chart.content.v1.tar+gzip` and the extraction root holds exactly one
   directory containing `Chart.yaml` — because `helm package` wraps the chart in `<name>/` while
   ORAS/Flux bundles extract at the root.
6. **Render strictly offline**: `helm template` never sees the registry; the artifact is already on disk.

The blocking half (hash, gunzip, tar, filesystem, sanitizer) runs in `tokio::task::spawn_blocking`;
only the network half is `async`. Redirects are not followed at all — carrying an `Authorization` header
to a host the operator never configured is worse than failing.

---

## 3. Wiring It Into the Reconcile Path (`T18.4`)

### 3.1 Where the two sources converge

`InventorySyncPipeline` treats an OCI source as *the same* pass as a Git one, in this order:

| Step | OCI behaviour |
|---|---|
| `AppProjectPolicy::check_application` | **Before** any registry call, matched against `spec.source.oci.url` — otherwise an `Application` would become an SSRF probe into internal registries |
| Effective source | A rollback pin replaces **both** `tag` and `digest`, so a rolled-back pass can never re-resolve a moved tag |
| Rule 1: pinned digest + warm `RenderCache` | Serve the rendered bundle; **zero** registry round trips, **zero** renderer subprocesses |
| Rule 2: `tag` **and** `digest`, cold cache | One `HEAD` to confirm the tag still points at the pin (a moved tag is a terminal `OciDigestMismatch`, not a silently dropped tag); then rule 1 for the requeue |
| Rule 3: tag only → digest | One `HEAD`; if the resolved digest is already rendered, serve the cache (still zero downloads) |
| Rule 4: miss | Download, verify, extract, render — into the same `RenderCache`, keyed `(oci.url, digest, oci.path, kubeVersion)` |
| `source_spec_hash` | Covers `oci.url`, `oci.tag`, `oci.digest`, `oci.path`, so editing the pin re-syncs under `selfHeal: false` even when the resolved digest has not moved |
| Metrics | `ferriscd_source_fetch_duration_seconds{source_kind="git"\|"oci"}` — a **closed enum label**; a registry host, repository, tag or digest would be unbounded and attacker-influenced. `record_git_fetch` *is* the `git` observation (it forwards), so the Git path calls it exactly once |

Credentials come from the same `ferriscd.io/secret-type=repository` `Secret`s, resolved *after* the policy
check and redacted in `Debug`/`Display`/errors, and a `401` `WWW-Authenticate: Bearer` challenge is
answered with **one** bounded token request whose plaintext realm is refused unless the local-development
opt-in is set. Three details of that exchange are worth knowing before debugging a `403`:

* **Every** challenge in the header is parsed, and `Bearer` wins over `Basic` (a registry that offers
  both wants the token exchange; `Basic` there is a compatibility scheme).
* The token cache is keyed `(realm, service, scope)` — *not* the request URL. Two tags, or a manifest
  and a blob of the same repository, share one minted token, and both caches (tokens, remembered
  realms) are bounded at 64 / 16 entries and cleared when full.
* The realm's **host** must be the registry's own authority (or named in
  `RegistryOciClientConfig::token_service_hosts`; Docker Hub's `auth.docker.io` is the one built-in
  exception). A registry that advertises its token service on some other host is refused *before* the
  `Secret`'s credential is sent, because that is the one place a hostile registry can exfiltrate it.
  Redirects (`301`/`302`/`303`/`307`/`308`) are refused outright for the same reason — the `Location`
  is not followed and not echoed.

Registry round trips are bounded by a 10 s connect timeout and a 60 s per-request timeout
(`RegistryOciClientConfig::with_timeouts`), so a hung registry costs one reconcile attempt rather than a
pinned worker.

### 3.2 The one production knob: `--allow-local-repos`

`OciUrlPolicy::Production` builds the client with `reqwest::https_only(true)`, so a plaintext registry is
impossible *by construction*. A `kind` demo needs `registry:2` on `http://127.0.0.1:<port>`, which is
exactly what `--allow-local-repos` opts into (with a startup `warn!`). The same flag relaxes the Git URL
policy, so a production deployment simply does not pass it.

### 3.3 Surfacing the source without breaking clients

`SourceView` gained `sourceType` (`"git"`/`"oci"`) plus **optional** `tag`/`digest` that are omitted when
absent (`skip_serializing_if`), so an existing client sees the payload it saw before. `ferriscd app get`
prints `[oci]` and an `OCI digest` row, and the Web UI's source panel switches the "Repository" row to
"Registry" and renders the tag and the pinned digest as **separate** rows — collapsing them into one
"Target Revision" string would hide the pin behind a mutable tag.

### 3.4 Live verification is where the CRD bugs are found

The `kind` E2E (`tests/integration/v1_2_oci_and_drift.rs`) pushes a real Helm chart and a real Kustomize
bundle to an in-cluster `registry:2`, forwards it to the host, and drives one `Application` through
digest convergence, an idempotent second pass, a drift heal and a rollback. Three lessons only a live
cluster teaches:

1. **A CRD is validated by the API server, not by `serde`.** The CEL rule of §2.2 compiled in Rust, passed
   `crd generate --check`, and was rejected by Kubernetes. `deploy/crds` is now regression-guarded by the
   shape that is *installable*, not by the shape that is *parseable*.
2. **A tar fixture is part of the contract.** macOS `bsdtar` defaults to PAX and emits
   `PaxHeader/<name>` extended headers (plus AppleDouble `._<name>` files); the extractor correctly refuses
   any entry type other than plain file/directory. `tar --format=ustar` is what `helm package` (Go's
   `archive/tar`) produces, and it is what the fixture must produce too — the alternative is a "flaky
   bundle" that is really a fixture bug.
3. **A metadata watch only sees changes *after* it starts.** The watcher derives its plan from
   `status.inventory` and re-plans on a `30 s` tick, so a drift patch issued before the `ConfigMap` stream
   is streaming is simply never observed. The E2E therefore waits on
   `ferriscd_drift_watcher_active_watches >= 1` before mutating anything out of band — the same
   prerequisite `T18.2`'s own suite documents.

---

## 4. Hands-On `kind` Experiment

> **Safety Gate:** Always verify you are targeting a disposable `kind` cluster before running live
> commands:
> ```bash
> kubectl config current-context | grep -q '^kind-' || { echo "STOP: non-kind context!"; exit 1; }
> ```

### Part A — Hermetic proofs (no cluster required)

```bash
# 1. The CRD is deterministic, and the injected CEL rules are installable
cargo run -q -p ferriscd-cli -- crd generate --check
K8S_OPENAPI_ENABLED_VERSION=1.35 cargo test -p ferriscd-crd

# 2. Registry transport, tar-safety and digest verification (in-memory artifacts, real extraction)
K8S_OPENAPI_ENABLED_VERSION=1.35 \
  cargo test -p ferriscd-engine --features test-utils repo::

# 3. Render-cache keys, spec-hash gating, AppProject policy and rollback (fake clients, real pipeline)
cargo test -p ferriscd-controller -- sync::
cargo test -p ferriscd-controller -- policy::
```

### Part B — Live OCI registry + DriftWatcher on `kind`

```bash
# 1. A disposable cluster, and the one image the experiment needs (pre-loading makes it offline-safe)
make kind-up
kind load docker-image registry:2 --name ferriscd-dev

# 2. The whole experiment: in-cluster registry:2, a Helm chart OCI artifact and a Kustomize bundle pushed
#    over the registry v2 API, digest-pinned convergence, an idempotent second pass, a drift heal inside
#    30 s with requeueAfterSeconds: 600, then a rollback to the prior digest.
cargo test -p ferriscd-cli --test v1_2_oci_and_drift -- --ignored --test-threads=1

# 3. Watch the pieces by hand while it runs (the test's namespaces are ferriscd-oci-e2e / -target)
kubectl -n ferriscd-oci-e2e get application ledger -o jsonpath='{.status.sync.revision}{"\n"}'
kubectl -n ferriscd-oci-target get configmap ledger-settings -o jsonpath='{.data.version}{"\n"}'
kubectl -n ferriscd-oci-target annotate configmap ledger-settings debug=1   # heals in ~2-10 s
```

What to look for in the output: a `status.sync.revision` that is always
`sha256:<64-hex>` (never `1.0.0`), `ferriscd_source_fetch_duration_seconds_count{source_kind="git"}` pinned
at `0`, a healed `kubectl annotate` within seconds despite the `600 s` requeue, and a
`spec.syncPolicy.automated` that is **gone** after the rollback (the documented rail that stops self-heal
from overwriting a rollback).

---

## Key Takeaways

- **Trigger from metadata, verify with ownership.** A label-scoped `PartialObjectMetadata` watch gets
  sub-second notification for O(managed kinds) memory instead of a cluster-wide informer, and
  `tracking-id` still gates every write — so a stale or colliding trigger can only cost a pass.
- **Echo suppression is about provenance, not equality.** Suppress by `(uid, generation)`/`resourceVersion`
  for writes, but never suppress a *deletion* on a matching version: a delete repeats the last written
  version, so only a prune marker proves the delete was ours.
- **Publish a stable, bounded identity.** `SHA-256("<namespace>/<name>")[:16]` is label-legal for any name,
  namespace-unique, and cheap enough that a collision is a no-op reconcile.
- **An OCI source is a source, not a pipeline.** Reusing `repo_url`/`source_path`/`requested_revision`,
  `RenderCacheKey`, `source_spec_hash`, `AppProject` policy and `SourceSummary` means OCI inherits every
  safety rail Git has — including "policy before network".
- **`crd generate --check` is not a CRD test.** CEL is type-checked by the API server: `string != null`
  on a `nullable: true` scalar silently makes the CRD uninstallable everywhere. Live suites find that;
  unit tests never will.
- **Digest in, digest out.** `status.sync.revision`, the render-cache key, the rollback pin and the
  `source_kind` metric all speak in immutable digests; a tag is only ever an input to resolution.

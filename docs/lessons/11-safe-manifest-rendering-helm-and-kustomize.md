# Lesson 11 — Safe Manifest Rendering (Kustomize v5 & Helm v4)

> Phase 11 stops treating "the repository" as data and starts executing tools over it. That is the
> moment a GitOps controller becomes an attack surface: `kustomize` downloads remote bases, `helm`
> evaluates chart templates with cluster-shaped capabilities, and both inherit the controller's
> process environment. This lesson is about making that boundary explicit and boring.
>
> Code: `crates/ferriscd-engine/src/manifest/{renderer,exec,kustomize,helm,cache}.rs`,
> `examples/kustomize/`, `examples/helm/`.
> Hermetic coverage: `cargo test -p ferriscd-engine --lib manifest` (fake renderer binaries, no
> external tools). Live coverage: `tests/integration/v0_4_renderers.rs` (`#[ignore]`d, `kind-`
> guarded) — **not executed here** (see §9).

---

## 1. Rendering is a trust boundary, not a formatting step

A manifest renderer takes *attacker-controlled input* (a Git repository) and produces *objects the
controller will apply with its own credentials*. Three failure classes follow, and none of them are
YAML bugs:

1. **Egress.** `kustomize` can fetch `https://…` bases and `helm --values` accepts URLs. A malicious
   repository can turn rendering into an SSRF proxy: cloud metadata
   (`http://169.254.169.254/…`), in-cluster services, or a private Git host that `AppProject`
   never authorized (Finding C7).
2. **Environment.** A child process inherits everything the controller has: a mounted service
   account token, `KUBECONFIG`, cloud credentials, proxy settings that point at a real network.
3. **Resource exhaustion.** A chart that template-loops or a kustomization that expands can produce
   unbounded stdout or run forever; a rendering step must not be able to OOM the controller.

Everything in this phase is a response to one of those three.

## 2. One funnel: renderers emit text, Phase 03/04 owns semantics

The `ManifestRenderer` trait deliberately has a weak contract:

```rust
fn render<'a>(&'a self, ctx: &'a RenderContext) -> RenderFuture<'a, Vec<ManifestFile>>;
```

`ManifestFile` is `{ source_file, contents }` — *raw text*, possibly with a synthetic label such as
`kustomize:overlays/prod` or `helm:.`. A renderer may not parse, normalize, or interpret Kubernetes
objects. `render_desired` then runs the exact same pipeline a plain-YAML bundle goes through:

```text
renderer output ─► yaml::parse_file (budgets, v1/List flattening, apiVersion/kind validation)
                ─► normalize::normalize (strip .status/metadata, Secret.stringData → base64 .data,
                                         duplicate GKNN rejection)
                ─► Vec<DesiredResource>
```

Why this shape:

- **No renderer can skip a safety step.** `v1/List` flattening, `stringData` conversion, and
  duplicate-GKNN detection are properties of the *pipeline*, not of each renderer (Trap Guard for
  T11.1). A test renders the same bundle three ways (plain YAML, fake kustomize, fake helm) and
  asserts byte-identical normalized identities, including the base64 `stringData` value and the
  stripped `.status`/`uid`.
- **Adding a renderer (OCI, Jsonnet, …) touches one file.** The controller, sync planner, diff
  engine, and inventory never learn a new type.
- **Errors stay uniform.** `kustomize:overlays/prod: document 2: apiVersion is required` is the same
  error shape a plain manifest produces, with the renderer named in the path.

### Auto-detection is a fixed precedence, not a guess

```text
Chart.yaml                                 → helm
kustomization.yaml | kustomization.yml | Kustomization → kustomize
otherwise                                  → plainYaml
```

A single manifest *file* is always plain YAML (neither tool can render one). Explicit
`spec.source.renderer.{plainYaml,kustomize,helm}` bypasses detection entirely — and that is
observable: `renderer::tests::explicit_selection_overrides_auto_detection` asserts detection says
Kustomize for a directory while an explicit `plainYaml` request runs the raw loader over it
(including the `kustomization.yaml` file, which then fails validation rather than being silently
skipped).

Detection touches the filesystem (a `stat` per marker), so it runs inside
`tokio::task::spawn_blocking`; the async helpers in `renderer.rs` never block a Tokio worker.

## 3. The sandbox: `SandboxedCommand`

`manifest/exec.rs` is the only place FerrisCD executes an external binary. It is a
`tokio::process::Command` builder with opinions:

| Concern | Implementation |
|---|---|
| Environment | `env_clear()`, then **only** `PATH`, scratch `HOME`/`TMPDIR`/`TMP`/`XDG_*`, and dead proxies |
| Program lookup | an absolute path is used as-is; a bare name is resolved against the *parent* `PATH` (the child's cleared env cannot influence which binary runs); **a relative path is rejected** |
| Egress | `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (+ lowercase) = `http://127.0.0.1:0`, `NO_PROXY`=`""` |
| Runtime | hard deadline (default 60 s, reported in **milliseconds**); `kill_on_drop(true)` so a cancelled reconcile kills the child |
| Output | both pipes drained by reader tasks that abort at the cap (default 20 MiB per stream) |
| Shell | none — arguments are `OsStr` values handed to `execve` |

Details that matter in review:

- **The waiter owns the child.** A spawned task awaits `child.wait()`; on timeout or output-cap
  breach we `abort()` it, which drops the `Child`, and `kill_on_drop` sends `SIGKILL`. That is why
  the timeout path cannot leak a process even if the render future is dropped mid-flight.
- **The output cap is enforced while reading, not after.** A reader stops at the cap and returns
  `OutputLimit`, the select loop kills the child immediately. Buffering first and checking later
  would defeat the point.
- **Program paths are not trusted.** `./kustomize`, `bin/helm`, and `../x` are rejected with
  `ExecError::ProgramRelativePath`, because a relative program resolves against the *child's*
  working directory — the checkout the repository controls. A repository-shipped `./kustomize`
  must never be the thing the controller executes.
- **Bounded is not redacted.** Reported stderr is capped at the same 20 MiB and only 4 KiB of it is
  quoted in an error, but it is **not** scrubbed: `helm`/`kustomize` diagnostics quote chart and
  kustomization source, which a repository can fill with credential-shaped strings. Treat
  `SandboxedOutput::stderr` and `ExecError::Failed { stderr }` as untrusted text; never log them
  unredacted and never copy them into a user-facing status field.
- **`Debug` is redacted.** `SandboxedCommand` prints its program, argument count, and *flag names*
  only: a Helm argv can carry `--set password=…`. The `--set`/`--set-string` pairs come from the
  repository; they must never appear in a log line. `SandboxedOutput` prints byte counts instead of
  the captured text, because its `stdout` is the rendered bundle and can already contain a `Secret`.

Security tests (`exec::tests`) prove: a sleeping child is killed at the deadline (and the runner
still works afterwards), unbounded stdout *and* stderr abort at the cap, the child's environment is
exactly the allow-list (so *any* parent variable — including credentials — is invisible), the
controller `PATH`/`HOME` are not inherited, proxies are poisoned, `$(id)`/backticks/spaces pass
through as literal argument bytes, and a repository-provided relative `./kustomize` is refused
without being executed (the identical script does run when named by absolute path, so the
assertion is not vacuous).

### What the sandbox does **not** do

The child still runs as the controller's uid with the controller's filesystem view. Killing
in-process egress by proxy variables is defense in depth, not a network namespace: a binary that
opens a raw socket ignores them. Real isolation is a deployment concern (Phase 16): run renderers in
a dedicated pod with `automountServiceAccountToken: false`, a `readOnlyRootFilesystem`, and a
`NetworkPolicy` that denies egress. Documented as a residual risk in `exec.rs` and here.

## 4. Kustomize: `--load-restrictor` is *not* an SSRF defense

The roadmap trap is precise and easy to get wrong: `--load-restrictor=LoadRestrictionsRootOnly`
constrains **local file loads**. It says nothing about

```yaml
resources:
  - https://raw.githubusercontent.com/attacker/repo/main/base
  - git::https://example.com/repo.git//base?ref=v1
```

which kustomize happily downloads. So FerrisCD parses the kustomization graph **before spawning
anything** (`kustomize::guard_kustomization_tree`) and rejects:

- remote URLs, `git::`, `git@…`, `github.com/…`-style shorthands, protocol-relative `//host`, and
  absolute host paths in `resources`, `bases`, `components`, `patches`, `patchesStrategicMerge`,
  `patchesJson6902`, `configurations`, `crds`, `generators`, `transformers`;
- `configMapGenerator`/`secretGenerator` `files`/`envs`/`env` paths (including `key=path` form);
- references that canonicalize outside the checkout (`../../../outside`) — reported as an escape,
  not a typo;
- `helmCharts` (it needs `--enable-helm`, which is never passed);
- glob references (`resources: [patches/*.yaml]`), because expansion cannot be validated before the
  build runs;
- reference chains deeper than 16 kustomizations or touching more than 256 (cycle/bomb bound).

Crucially the guard **recurses into referenced local sub-kustomizations**: a local `resources:
[../../base]` is a legitimate monorepo pattern, but that `base` may itself pull a remote component.
`kustomize::tests::remote_references_in_a_nested_sub_kustomization_are_rejected` proves the nested
case fails before the fake binary is invoked *once* (`invocations() == 0`).

The invocation itself is pinned:

```text
kustomize build <checkout path> --load-restrictor=LoadRestrictionsRootOnly
```

No `--enable-exec`, no `--enable-alpha-plugins`, no `--enable-helm`, never
`LoadRestrictionsNone` — asserted on the recorded argv, not just in prose.

### Two-phase build: `namePrefix`/`nameSuffix`/`images` without mutating the checkout

The cached worktree is immutable (`T02.3`): a renderer must not write into it, and `kustomize edit`
would. But `RootOnly` also refuses a resource *file* outside the kustomization directory, so a
scratch overlay cannot simply point back at the checkout. Real probe (kustomize v5.8.3):

```text
$ kustomize build <scratch>/badroot --load-restrictor=LoadRestrictionsRootOnly
Error: accumulating resources: … security; file '<scratch>/rendered.yaml' is not in or below
'<scratch>/badroot' …
```

The working design is therefore two phases:

1. `kustomize build <checkout>/overlays/prod --load-restrictor=LoadRestrictionsRootOnly` — read-only,
   repository untouched.
2. If transforms are configured, the phase-1 text is written to
   `<scratch>/overlay/rendered.yaml` and a generated `<scratch>/overlay/kustomization.yaml` applies
   them:

```json
{"apiVersion":"kustomize.config.k8s.io/v1beta1","images":[{"name":"nginx","newName":"registry.example.com/nginx","newTag":"1.28-alpine"}],"kind":"Kustomization","namePrefix":"prod-","resources":["rendered.yaml"]}
```

   (JSON is a YAML 1.2 subset, so `serde_json` provides escaping: a `namePrefix` containing `: ` or
   newlines cannot inject YAML structure. `images` entries are converted from the CRD's
   `name=newName:tag` string form into v5's structured object form — v5 *rejects* the bare string,
   which the example above shows as a real error.)

Note the phase-2 semantics: reference rewrites only apply to resources that are in the bundle.
`namePrefix` renaming a `ConfigMap` that lives outside the bundle will not rewrite a `configMapRef`
to it. That is a documented limitation, not an accident of the implementation.

## 5. Helm: offline template, opt-in CRDs, argv safety

`helm template` renders locally — it never contacts a cluster — so `.Capabilities` must come from
the destination cluster's discovered version:

```text
helm template <release> <chart> --namespace <dest_ns> --kube-version <major.minor[.patch]> --no-hooks
```

- **`--include-crds` is opt-in (Finding H3).** Pruning a CRD deletes every custom resource of that
  type, so FerrisCD never manages `crds/` unless `spec.source.renderer.helm.includeCRDs: true`.
  The test asserts the *rendered output* (not the argv): with the default, the bundle has no
  `CustomResourceDefinition`; with `include_crds: true` it does, and it still normalizes cleanly.
- **`--kube-version` is mandatory.** An empty discovered version is a `RendererRejected` render
  error, not "pass no flag": without it Helm silently substitutes the version it was compiled
  against, so the same commit would render differently on a controller image upgrade and the cache
  key (`cluster_kube_version`) would be lying. The controller refreshes discovery before rendering,
  which is why `UNKNOWN_KUBE_VERSION` (`"unknown"`) fails the version validation instead of
  reaching the subprocess.
- **Chart hooks never enter the bundle (`--no-hooks`).** `helm template` would inline
  `helm.sh/hook*` resources into the rendered stream, where the pipeline would treat them as
  ordinary objects: a hook `Job` applied on every sync, diffed against the tracked inventory, and
  deleted by a prune — while the `PreSync`/`PostSync` ordering it exists for was never honoured.
  Lifecycle hooks are Phase 10/12 work, so the flag is unconditional and the test proves the
  hook-bearing fake (`helm_hook_conditional`) emits its `Job` *without* the flag and produces no
  `Job` through the renderer.
- **Value paths are jailed (Trap T11).** `valueFiles` are resolved relative to
  `spec.source.git.path`, canonicalized, and must stay inside the checkout. `../../secret.yaml` is
  rejected with an `UnsafeReference` error that quotes the reference but never the file's contents;
  `https://…/values.yaml` is rejected too, because Helm accepts URLs for `--values`.
- **Inline values never touch argv.** They are written to `<scratch>/values.yaml` and passed with
  `--values`. A test asserts a `password: hunter2` inline value leaves no trace in argv.
- **Release name and namespace are validated first.** `helm template` parses its positional
  arguments, so an `Application` named `--post-renderer=/tmp/evil.sh` would become a *flag*. Release
  names must be lowercase alphanumerics/`-`/`.` (≤53), namespaces must be DNS-1123 labels, and the
  kube version must be `major.minor[.patch]`. Rejected before spawning (`invocations() == 0`).
- **`--set`/`--set-string` are separate `OsStr` args.** No shell, so `;`, quotes, `$(…)` are data.

`helm template` also emits a leading `---` and `# Source:` comments; Phase 03 already handles both.

## 6. The render cache: a commit SHA is not a cache key (Finding M1)

Rendered output depends on the commit **and** on everything the renderer was told:

```text
SHA-256(repo_url, commit_sha, source_path, app_namespace, app_name,
        destination_namespace, cluster_kube_version, canonical_renderer_config)
```

- **Monorepo:** two `Application`s at the same commit with different `path`s must not share a result,
  or one tenant deploys the other's manifests.
- **Helm:** `.Release.Name` and `.Release.Namespace` are rendered into the output; a
  destination-namespace-blind key would ship `payments` objects into `billing`.
- **`.Capabilities.KubeVersion`:** a cluster upgrade legitimately changes the rendered output, so the
  kube version is part of the key.

Correctness details that the tests pin:

- **Unambiguous encoding.** Every field is length-prefixed (`11:apps/prod;`) before hashing, so a
  `path` containing `;`/`:` cannot forge two fields.
- **`SHA-256` is local.** `sha2` is not in the workspace lock file, so the ~70-line FIPS 180-4
  implementation lives in `cache.rs` and is pinned to the NIST vectors (`""`, `"abc"`, the 56-byte
  two-block message, and the 1,000,000-`a` multi-block vector —
  `cdc76e5c…12cd0`). Comparing the implementation against itself would pass for any hash.
- **Failures are never cached**, and a context with an **empty `commit_sha` bypasses the cache** —
  an unresolved revision cannot distinguish commits.
- **The output is tier-sorted** (`sort_by_tier`) on both the render and the cache path, so the
  controller never re-sorts and the two paths cannot disagree about apply order.
- **Counters** (`hits`/`misses`/`entries`/`capacity`, plus `hit_rate()`) exist for Phase 15 metrics;
  they are incremented on the same critical section as the lookup.
- **Redacted `Debug`, twice over.** `RenderCacheKey` prints `https://robot:***@host/repo.git` — and
  a *bare* userinfo (`https://ghp_…@host`) as `https://***@host`, because there the "username" is
  the token. The renderer configuration is printed as `renderer_config_digest` (a SHA-256 hex
  string), never as its canonical pre-image, which embeds inline Helm values and `--set` pairs
  verbatim; the pre-image (`renderer_config`, `canonical_input`) is private. `RenderCache`,
  `CacheState`, `CacheEntry`, and `SandboxedOutput` print counts and sizes, never cached objects or
  captured stdout.

The cache is a bounded LRU (`DEFAULT_CACHE_CAPACITY = 128`, `capacity = 0` disables it) over
`Arc<Vec<DesiredResource>>`, so a hit hands back shared, already-normalized objects without cloning.

Evidence (fake binary invocation counter, so this is not an assumption):

- `repeat_render_hits_the_cache_and_spawns_no_subprocess`: 4 renders, `invocations() == 1`,
  `hits == 3`, `misses == 1`.
- `monorepo_apps_at_the_same_commit_do_not_contaminate_each_other`: the fake emits
  `<target>/manifest.yaml`, so each app can only get its own content; `invocations() == 2`,
  `entries == 2`.
- `destination_namespace_changes_the_key_and_the_rendered_output`: the fake models
  `.Release.Namespace` from `--namespace`; `payments` and `billing` never cross over.
- `cache_key_debug_hides_inline_values_and_the_renderer_pre_image`: `format!("{:?}", key)` contains
  neither `hunter2` nor the repository token, and still distinguishes two renderer configurations.
- The controller tests `a_kustomize_application_renders_through_the_cr` /
  `a_helm_application_renders_with_the_discovered_kube_version` render a *committed kustomization /
  chart* through the `Application` CR with a fake binary and assert one invocation for two
  reconciles (the cache is wired into the controller, not just the engine).

## 7. Verification performed

Every transcript below was executed on the branch this lesson describes (`kustomize v5.8.3`,
`helm v4.3.2`), so the counts and object names are reproducible rather than illustrative.

Hermetic (part of `make gate`):

```text
$ K8S_OPENAPI_ENABLED_VERSION=1.35 cargo test -p ferriscd-engine --lib manifest
test result: ok. 113 passed; 0 failed; 1 ignored; 0 measured; 253 filtered out; finished in 0.32s
```

The single ignored case is the real-binary example render below; it needs `kustomize`/`helm` on
`PATH`, so `make gate` must not depend on it.

```
$ K8S_OPENAPI_ENABLED_VERSION=1.35 cargo test -p ferriscd-engine --lib -- --ignored examples
test manifest::renderer::tests::committed_examples_render_with_the_real_binaries ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 366 filtered out; finished in 0.24s
```

That test renders the committed `examples/kustomize/overlays/prod` (including the scratch
`namePrefix`/`images` overlay) and `examples/helm` (with `values-prod.yaml` + inline
`replicaCount: 2`) through the real binaries and asserts parsed `DesiredResource`s.

Same tools, by hand — the phase-1 build of the committed kustomize example:

```text
$ kustomize build examples/kustomize/overlays/prod --load-restrictor=LoadRestrictionsRootOnly \
    | grep -E '^(kind:|  name:|  replicas:)'
kind: Namespace
  name: ferriscd-render
kind: ConfigMap
  name: render-config
kind: Service
  name: render-app
kind: Deployment
  name: render-app
  replicas: 3
```

The overlay patch's `replicas: 3` is applied, and the objects still carry their base names
(`render-app`, `render-config`) — the prefix/suffix transforms are *not* applied by this build.

The phase-2 scratch overlay (phase-1 text written to `<scratch>/overlay/rendered.yaml` plus the
generated kustomization with `namePrefix: prod-` and
`images: [{name: nginx, newName: registry.example.com/nginx, newTag: 1.28-alpine}]`):

```text
$ kustomize build <scratch>/overlay --load-restrictor=LoadRestrictionsRootOnly \
    | grep -E '^(kind:|  name:|  replicas:|        image:)'
kind: Namespace
  name: ferriscd-render
kind: ConfigMap
  name: prod-render-config
kind: Service
  name: prod-render-app
kind: Deployment
  name: prod-render-app
  replicas: 3
        image: registry.example.com/nginx:1.28-alpine
```

`prod-render-app` / `prod-render-config` in `ferriscd-render` is what the prefix transform produces
from the committed example; the `Namespace` keeps its own name. The `configMapRef` inside the
Deployment is rewritten to `prod-render-config` because that ConfigMap is in the built bundle
(§4's limitation is about references to objects that are *not*).

Helm CRD opt-in, same chart, same version:

```text
$ helm template refd examples/helm --namespace ferriscd-render-helm --kube-version 1.35.0 --no-hooks
kind: ConfigMap
  name: refd-config
kind: Service
  name: refd
kind: Deployment
  name: refd

$ helm template refd examples/helm --namespace ferriscd-render-helm --kube-version 1.35.0 --no-hooks --include-crds
kind: CustomResourceDefinition
  name: widgets.example.com
kind: ConfigMap
  name: refd-config
kind: Service
  name: refd
kind: Deployment
  name: refd
```

(Labels and the rest of each object are elided by the `grep`; the object *set* is the whole claim.)

## 8. Why `findings` (C7, H3, M1) are structural, not careful coding

| Finding | Structural fix |
|---|---|
| C7 (env/SSRF) | Single sandboxed executor; no shell; guard runs before spawn; dead proxies; relative programs rejected |
| H3 (CRDs) | `include_crds` defaults to `false`; the flag is only *conditionally* pushed |
| M1 (cache collision) | Key is the full tuple; length-prefixed encoding; empty SHA bypasses caching |
| H1 (secret leakage) | The renderer pre-image is a private field; `Debug` prints `renderer_config_digest` |
| M4 (hook drift) | `--no-hooks` is unconditional, so no hook resource can reach the inventory |

Reviewers should look for the opposite pattern: a new call site of `std::process::Command` or
`tokio::process::Command` outside `manifest/exec.rs`, a renderer that constructs
`DesiredResource` directly, a cache lookup that ignores a render parameter, or a `Debug` impl that
formats a `RendererConfig`/`SandboxedOutput` field directly.

## 9. Manual `kind` acceptance — **PENDING (not executed)**

The live tests exist and are wired
(`tests/integration/v0_4_renderers.rs` + `crates/ferriscd-engine/tests/v0_4_renderers.rs` shim),
both `#[ignore]`d and both asserting `kubectl config current-context` starts with `kind-` before
touching anything:

| Test | Asserts |
|---|---|
| `kustomize_example_overlay_renders_and_applies_on_kind` | the example overlay renders (replicas 3 from the patch), `namePrefix`/`images` work through the scratch overlay, the bundle applies, `Deployment`/`Service`/`ConfigMap`/`Namespace` exist |
| `helm_example_renders_with_values_and_omits_crds_on_kind` | `values-prod.yaml` + inline `replicaCount: 2` reach the rendered object, `crds/` stays out by default, `includeCRDs: true` renders it |

They were **not run** as part of this work (no `kind` cluster was created), so treat their live
cluster behaviour as unverified until `make kind-up && cargo test -p ferriscd-engine --test
v0_4_renderers -- --ignored` has been executed and recorded here.

## 10. Limitations at the end of Phase 11

- **The controller renders, but only the `in-cluster` anonymous path.**
  `InventorySyncPipeline::fetch_desired` builds a `RenderContext::for_application(...)` (commit SHA,
  `Application` namespace/name, destination namespace, discovered cluster version, loader budgets)
  and calls `RenderPipeline::render`, so `spec.source.renderer` is honoured end to end. What is
  still Phase 12/13 is everything around it: `AppProject` policy, repository credentials, and
  remote `destination.cluster`s. The `v0.1` CLI (`ferriscd apply`) keeps its own plain-YAML step.
- **The render cache is per-process and has no explicit invalidation.** Entries fall out by LRU
  pressure only; the key includes the commit SHA, so a new revision is a new entry. There is no
  "renderer upgraded, drop the cache" signal beyond a controller restart (see the version note
  below).
- **`v1alpha1` does not expose every engine knob.** Kustomize `namePrefix`/`nameSuffix`, Helm inline
  `values`, and `--set`/`--set-string` are implemented in the engine and reachable through
  `RendererConfig`, but the CRD only carries `kustomizationPath`, `images`, `releaseName`,
  `valueFiles`, and `includeCRDs` today. `RendererConfig::from_crd` is the single extension point;
  `RendererBinaries` (the binary override) is operator/test configuration, not CRD surface.
- **Glob references are unsupported** in kustomizations (validated-before-spawn beats convenient).
- **Phase-2 transforms cannot rewrite references to objects outside the built bundle.**
- **Renderer version is not in the cache key.** Two different `kustomize` versions would share a key;
  the binary is pinned by the container image, and the cache is per-process.
- **Sub-kustomization resource *files* are not content-scanned**: the guard validates path/URL
  provenance, not that a local patch file only contains safe fields (a patch is applied to the
  renderer's own output and cannot fetch anything).
- **Only unpacked chart directories are supported** (`Chart.yaml` must be present); `.tgz` chart
  archives are not opened by the renderer.
- **Renderer stderr is untrusted text.** It is bounded, not redacted (§3); nothing scrubs a
  credential a chart chose to print.

## Further reading

- `kustomize` `Loader`/`RestrictionRootOnly` implementation and the `git`/`http` `KustomizeSource`
  downloaders — the reason the guard exists is that these are *allowed* by the flag.
- Helm's `--include-crds`, `--kube-version`, and `--values` (URL) semantics, plus CRD install/prune
  asymmetry (`helm install` installs `crds/`, `helm upgrade` does not).
- FIPS 180-4 §5/§6 for the SHA-256 padding and compression used by the cache key.
- OWASP SSRF prevention cheat sheet: allow-lists beat blocklists — which is why FerrisCD blocks
  *remote references entirely* instead of trying to enumerate metadata IPs.

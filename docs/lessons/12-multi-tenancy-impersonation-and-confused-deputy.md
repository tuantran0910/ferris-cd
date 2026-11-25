# Lesson 12 — Multi-Tenancy, Impersonation, and the Confused Deputy

> Phase 12 is the phase where FerrisCD stops being a single-tenant tool and starts holding *other
> people's* permissions. Everything here follows from one sentence: **a GitOps controller is a
> confused deputy by construction** — it acts with its own cluster-wide credentials on input
> (a Git repository) that somebody else controls. Nothing in this phase makes that deputy smarter;
> it makes the set of actions it can be tricked into doing small, explicit, and auditable.
>
> Code: `crates/ferriscd-engine/src/policy/app_project.rs`,
> `crates/ferriscd-controller/src/{impersonation,project,credentials}.rs`,
> `crates/ferriscd-controller/src/sync.rs`.
> Hermetic coverage: `cargo test -p ferriscd-engine --lib policy`,
> `cargo test -p ferriscd-controller --lib` (policy ordering, impersonation headers, credential
> matching, `FakeGitClient::credential_log`). Live coverage:
> `tests/integration/v0_5_multi_tenancy.rs` and `tests/integration/v0_5_repo_credentials.rs`
> (`#[ignore]`d, `kind-` guarded) — **not executed here** (see §8).

---

## 1. The confused deputy, precisely

The classic formulation: a privileged program is asked by a less-privileged party to perform an
action, and it performs it *with its own authority*. The deputy is not malicious; it cannot tell
whose interest it is serving.

In Argo CD / FerrisCD the shape is exact:

| Actor | Can do | Wants |
|---|---|---|
| Tenant (writes an `Application` in a namespace it owns) | create/modify one CR | deploy arbitrary manifests into `kube-system`, create a `ClusterRoleBinding`, read another tenant's `Secret` |
| Controller (the deputy) | everything on the `ClusterRole` — `*/*` in the single-tenant shape | reconcile whatever the CR says |
| Git repository (attacker-controlled input) | contain any YAML | *become* cluster-admin once the deputy applies it |

Three separate holes follow, and Phase 12 closes each one with a different mechanism because they
are different problems:

1. **Authorization** — "may this `Application` ask for this at all?" → `AppProject` (§4).
2. **Identity** — "as *whom* does the deputy act?" → ServiceAccount impersonation (§2–§3).
3. **Secrets** — "which credentials may the deputy pick up, and from where?" → scoped credential
   `Secret`s (§6).

The failure mode to avoid at all costs is the *implicit* one: a controller that silently falls back
to its own identity, its own namespace, or its own default project whenever a check is inconvenient.
Every fallback in this phase is a hard, terminal error instead, because a fallback that helps a
misconfigured tenant also helps a malicious one.

## 2. `Impersonate-User` alone breaks every group-based `RoleBinding` (Finding H5)

Kubernetes authorization is `(user, verb, resource, namespace)`, but the *policy* almost never names
users. Operators bind **groups**:

```yaml
kind: RoleBinding
metadata: { name: tenant-deployer, namespace: tenant-a }
roleRef: { kind: Role, name: configmap-writer }
subjects:
  - kind: Group
    name: system:serviceaccounts:tenant-a   # every ServiceAccount in tenant-a
```

A kubelet puts three groups in a ServiceAccount's token: `system:serviceaccounts`,
`system:serviceaccounts:<ns>` and `system:authenticated`. If the controller sends only
`Impersonate-User: system:serviceaccount:tenant-a:deployer`, the impersonated request belongs to
**no groups at all** — so the binding above stops applying, the tenant's deploy fails with a
mysterious `403`, and the natural "fix" an operator reaches for is to grant the user directly or,
worse, to stop impersonating. That is how a security control gets removed for being inconvenient.

So the header set is fixed and generated, never assembled from CR input:

| Header | Value |
|---|---|
| `Impersonate-User` | `system:serviceaccount:<destination namespace>:<serviceAccountName>` |
| `Impersonate-Group` | `system:serviceaccounts` |
| `Impersonate-Group` | `system:serviceaccounts:<destination namespace>` |
| `Impersonate-Group` | `system:authenticated` |

Two details that look pedantic and are not:

* **The ServiceAccount resolves in `spec.destination.namespace`, never in the `Application`'s own
  namespace** (ADR-007). A tenant `Application` in `team-a` that deploys into `payments` acts as
  `system:serviceaccount:payments:<name>` — exactly the account its workloads will run as, which is
  the only account whose RBAC the operator has actually reasoned about.
* **`system:masters` is never injectable.** It bypasses authorization entirely; `Impersonation::new`
  refuses it and the ServiceAccount constructor cannot produce it, because the group set is derived
  from the namespace rather than supplied. The only groups a request can ever carry are the three
  above.

The `tower` layer that injects the headers runs *innermost* (immediately above the transport) and
**replaces** any pre-existing `Impersonate-*` header, so neither a kubeconfig `headers:` entry nor a
later middleware can rewrite the identity the controller decided on.

## 3. One connector, not one client per reconcile

The naive implementation builds a `kube::Client` for the impersonated identity inside the reconcile
loop. Each one owns a TLS connector — a certificate store, a socket pool, and file descriptors — and
a controller reconciling a thousand `Application`s every 180 s leaks a thousand connection pools.

`ImpersonationPool` builds **one** `hyper_util::client::legacy::Client` (one TLS connector, one
connection pool) from the controller's own `kube::Config`, and every impersonated client is a
`kube` middleware stack over a *clone of that handle*. The pool caches one client per distinct
identity, and `builds() == cached()` is asserted however often `client()` is called — that is the
test seam which makes "no connector per reconcile" a property rather than a hope.

Two consequences worth stating:

* The pool is created **eagerly** at startup. A broken TLS configuration is a startup failure, not a
  reconcile that fails forever.
* A proxied `kube::Config` is refused rather than silently un-proxied: an impersonated request that
  quietly bypasses the operator's proxy is a different security posture than the one they configured.
* The impersonated stack is assembled by hand, so it **intentionally omits** `kube`'s own
  `tower_http::trace::TraceLayer`. Adding `tower-http` as a direct dependency for observability
  alone was not worth it, and the omitted span is the one field that would quote a request URL for
  *tenant* traffic; the pipeline's own spans (`reconcile`, per-resource apply/prune/hook logs) still
  cover what an operator needs. The layer also strips any foreign `Impersonate-Uid` /
  `Impersonate-Extra-*` header, so a kubeconfig `headers:` entry cannot select a different principal
  alongside the ServiceAccount the controller chose.

## 4. `AppProject` is defense in depth, not a duplicate of RBAC

RBAC answers "may *this identity* perform this verb on this resource in this namespace?". It cannot
answer "may this `Application` declare this resource at all?", because the attacker's usual move is
to make the deputy perform a legitimate action in an *unintended* place. The bypasses are trivial:

* `spec.destination.namespace: payments` with a committed manifest that hardcodes
  `metadata.namespace: kube-system`;
* a committed `ClusterRoleBinding` (namespaced `destination` says nothing about cluster-scoped
  kinds);
* a `source.git.repoUrl` that is not the repository the operator authorized.

Hence two checks at two different times, and both are required:

**Before rendering** (`check_application`) — the `Application` is refused before the repository is
cloned, before a `dryRun=All` PATCH, before an apply or a prune. A denial costs the cluster nothing:

1. the `Application`'s own namespace is in `spec.sourceNamespaces`;
2. `spec.source.git.repoUrl` matches `spec.sourceRepos`;
3. `(destination.cluster, destination.namespace)` matches `spec.destinations`;
4. `spec.serviceAccountName`, if set, is in `spec.allowedServiceAccounts`.

**After Stage-2 scope normalization** (`check_resources`) — on **every** rendered resource, using its
*actual* scope rather than the declared one:

1. a namespaced resource's real `metadata.namespace` is allowed by `spec.destinations`;
2. a cluster-scoped `(group, kind)` is in `clusterResourceWhitelist`;
3. a namespaced `(group, kind)` is allowed by `namespaceResourceWhitelist` (when non-empty) and not
   in `namespaceResourceBlacklist`.

Order matters: scope normalization is what turns "declared namespaced, hardcodes `kube-system`" into
an effective namespace, so the post-normalization check is the only one that can see what will
actually be applied. Hooks are covered by the same pass — a `PreSync` `Job` is created imperatively
but it is still a rendered resource.

The "empty means what?" question is a security decision, not a convenience:

| Field | Empty means |
|---|---|
| `sourceRepos`, `sourceNamespaces`, `destinations`, `clusterResourceWhitelist`, `allowedServiceAccounts` | **nothing is permitted** |
| `namespaceResourceWhitelist` | everything is permitted (matches Argo CD) |

An operator who writes half a project gets a project that denies, not one that allows. Only
`namespaceResourceWhitelist` keeps the familiar "absent = unrestricted" reading, because the
blacklist exists for the narrower case.

`AppProject` is *defense in depth*, so it never replaces RBAC: impersonation narrows what a tenant
*can* do, the project decides what it *may ask for*, and the API server still has the final say. The
live test asserts exactly that layering — its project deliberately allows `kube-system` and
`ClusterRole` so the `403` it observes can only come from the impersonated ServiceAccount's own RBAC.

## 5. Apps-in-any-namespace is opt-in, and has a mandatory price

`--application-namespaces` defaults to the control-plane namespace. Widening it is a deliberate
operator act with a mandatory precondition per `Application`:

* `spec.serviceAccountName` must be non-empty. A tenant `Application` without one is refused with
  `Ready=False, reason=PolicyViolation` — never deployed silently as the controller (§1's implicit
  fallback, which is the whole trap).
* the project must list the tenant namespace in `spec.sourceNamespaces` **and** the ServiceAccount in
  `spec.allowedServiceAccounts`;
* the finalizer and `/status` patches follow the object (`team-a`), while workload traffic follows
  the impersonated identity — the tenant's ServiceAccount usually has no RBAC on the `Application`
  CR, and the controller must always be able to record what happened.

**One `Controller` per watched namespace, and why that is not a style choice.** Kube has no "watch
these N namespaces" API, so the obvious implementation is N namespaced watchers multiplexed into one
stream and one `reflector::store()`. That is a trap: a store has exactly **one** writer, and a
watcher emits `Init`/`InitApply`/`InitDone` on every (re)connect — `InitDone` *swaps* the writer's
buffer into the store, i.e. it replaces the whole content. With more than one namespace the last
`InitDone` truncates the others, the objects vanish from the store, and the controller discards
their reconciles as `ObjectNotFound`. Nothing logs an error; the other tenants simply stop being
reconciled, intermittently, under watch churn. So each scope gets its own `Controller`, its own
store, its own reader and its own reconnect backoff, and readiness is declared only when **every**
scope has completed its first list (`ApplicationControllers::wait_until_ready`). The regression test
feeds two scopes a scripted `Init`/`InitDone` and asserts that one scope's restart cannot remove the
other's objects.

## 6. Repository credentials: scope, matching, and the refusal to downgrade

`T12.4` adds a third kind of secret to the deputy: Git credentials. The design is three decisions
and one refusal.

**Scope.** Credential `Secret`s are labeled `ferriscd.io/secret-type=repository` and read **only**
from the control-plane namespace. `SecretCredentialStore` holds an `Api<Secret>` built with
`Api::namespaced`, so the request path is `/api/v1/namespaces/ferriscd-system/secrets` — there is no
cluster-wide `Secret` read in the code to grant RBAC for. A `Secret` a tenant writes in its own
namespace is therefore not "filtered out"; it is unreachable. The controller's `ClusterRole` gets no
`secrets` rule at all; a namespaced `Role` + `RoleBinding` grants `get`/`list`/`watch` in that one
namespace (`deploy/README.md`).

**Matching.** A credential carries a `url` and matches `spec.source.git.repoUrl` through one
normalization function: scheme and host lowercased, one trailing `.git` and trailing slashes removed,
the default port removed, userinfo dropped on **both** sides (so `git@github.com:org/repo.git` and
`ssh://github.com/org/repo` are the same repository), then exact match first and longest prefix
second — and a prefix only matches on a **path boundary**, so `https://git.example.com/org` matches
`https://git.example.com/org/repo` but never `https://git.example.com/organization/repo` or
`https://git.example.com.evil/repo`. A host-only template matches every repository on that host: one
`Secret` per Git server instead of one per repository.

Two rules keep matching boring rather than clever:

* **No match is `Anonymous`.** Public repositories keep working, and "no credential configured" is not
  an error.
* **An unusable `Secret` is terminal.** No `url`, ambiguous `password` + `token`, an SSH key on an
  `https://` URL, or two `Secret`s claiming the same `url` produce `Ready=False` naming the `Secret`,
  its namespace, and the offending keys. Silently choosing one of two credentials makes "which token
  does this Application use?" unanswerable — which is precisely the audit question an incident asks.

**Hygiene.** The `Secret` name, its namespace, and the credential *kind* (`http-basic`, `ssh-key`, …)
are logged; the values are not, and `RepoCredentials`' `Debug`/`Display` redact them at the type
level. Repository URLs — including the one inside a credential `Secret` — are quoted through the
shared `redact_repo_url` helper before any log line or `/status` message, because a Git remote
routinely embeds a personal access token.

**Plaintext HTTP is refused; the harness gap is the missing server, not the certificate.** Two
different things were easy to conflate, so they are separated here:

* **Plaintext `http://` is a security boundary, and it holds.** Three layers refuse it
  independently:
  1. `validate_repo_url` accepts only `https://`, `ssh://` and SCP-style SSH remotes (plus
     `file://` under the test/local policy): a plaintext `http://` remote never reaches a
     transport.
  2. `isolated_open_options` pins `protocol.http.allow=never` on every mirror, even under the
     permissive URL policy.
  3. `gix`'s HTTP transport refuses to put credentials on the wire in clear text
     (`AuthenticationRefused`), short of a workspace-wide `http-client-insecure-credentials`
     feature that would weaken **production** builds.

  This is pinned by `a_plaintext_http_remote_never_reaches_a_transport` and stays as it is.
* **An HTTPS loopback fixture is not blocked by trust.** A throwaway certificate can be trusted by
  this stack through the platform trust store (`SSL_CERT_FILE` for the `rustls`/`reqwest`
  transport). `gix`'s per-request TLS knobs (`http.sslVerify`/`http.sslCAInfo`) are only honoured
  by the `curl` backend, which is why the trust has to come from the environment rather than from
  repository config — an ergonomics point, not a blocker.
  What is actually missing is an **HTTPS Git server in the harness**: nothing in this repository
  serves an authenticated Git smart-HTTP endpoint, and adding one (TLS listener, `git
  http-backend`, per-request basic auth) is test infrastructure of its own. It is therefore
  recorded as an explicit follow-up (§8/§9) rather than replaced by a weaker assertion.

So the credential path is verified in two honest halves today: mapping + matching hermetically
(`credentials.rs`), and "the resolved credentials really reach the Git client" through
`FakeGitClient::credential_log` (`sync.rs`), plus the Kubernetes + pipeline + log/status hygiene end
to end in the `#[ignore]`d live test.

## 7. Verification performed

Hermetic (no cluster, no network, no external tools):

```text
cargo test -p ferriscd-engine --lib policy          # AppProject allow-lists, wildcards, empty-means-nothing
cargo test -p ferriscd-controller --lib              # ordering, headers, pool reuse, credential matching
cargo test --workspace                               # the full gate (`make gate`)
```

What those tests actually assert (not just "it runs"):

| Claim | Where it is pinned |
|---|---|
| `Impersonate-User` + exactly three `Impersonate-Group` values (Finding H5) | `impersonation::a_service_account_produces_exactly_the_four_impersonation_headers` |
| `system:masters` can never be impersonated (trap T12) | `impersonation::system_masters_is_never_impersonated` |
| one connector, one client per identity, cached | `impersonation::the_pool_reuses_one_connector_for_every_identity` |
| a foreign `Impersonate-*` header is replaced, not appended | `impersonation::the_layer_injects_the_identity_and_replaces_a_foreign_one` |
| policy runs **before** the clone/diff/apply, and again per rendered resource | `sync::*` policy-ordering tests; `policy::app_project` exhaustive cases |
| a hardcoded `metadata.namespace: kube-system` is rejected | `policy::app_project` (`check_resources` after normalization) |
| an unauthorized `ClusterRole` is rejected | same |
| credential matching: exact, longest prefix, boundary, `.git`/slash/case/default-port, SCP-style | `credentials::*` (matching section) |
| credential mapping: token, password, `username`+`password`, `username`+`token`, SSH key + `knownHosts` | `credentials::https_secrets_map_to_basic_and_token_credentials`, `…ssh_secrets_map_to_key_credentials…` |
| no match ⇒ `Anonymous`; unusable `Secret` ⇒ terminal error naming the `Secret` | `credentials::no_match_is_anonymous_not_an_error`, `…ambiguous_or_incomplete_secrets…` |
| the store is namespaced + label-filtered (recorded request URI) | `credentials::the_store_lists_only_the_labeled_secrets_of_the_control_plane_namespace` |
| resolved credentials really reach the Git client | `sync::resolved_repository_credentials_reach_the_git_client` (`FakeGitClient::credential_log`) |
| a malformed credential stops the pass before the clone | `sync::an_unusable_credential_secret_is_terminal_and_clones_nothing` |
| plaintext `http://` never reaches a transport | `repo::gix_client::a_plaintext_http_remote_never_reaches_a_transport` |
| nothing secret in `Debug`/`Display`/errors | `credentials::no_debug_display_or_error_output_contains_secret_material` |
| one controller, one store and one reconnect backoff per watched namespace; an `Init` in one scope cannot truncate another | `controller::one_controller_and_one_store_per_watched_namespace`, `controller::an_init_of_one_scope_cannot_remove_another_scopes_objects`, `controller::every_scope_reconciles_the_applications_it_watches` |
| the cascade re-checks `allowedServiceAccounts` **before** resolving the identity, and retains the finalizer on denial | `sync::a_cascade_with_an_unauthorized_service_account_retains_the_finalizer` |
| the cascade deletes as the tenant's ServiceAccount, not the controller | `sync::a_cascade_deletes_as_the_impersonated_service_account` |
| ordering is policy → identity (`identities()` is empty on a denial) | `sync::a_service_account_outside_allowed_service_accounts_is_rejected` |
| the impersonated-client cache is bounded and evicts the oldest identity | `impersonation::the_identity_cache_is_bounded_and_evicts_the_oldest_entry` |
| a foreign `Impersonate-Uid`/`Impersonate-Extra-*` is stripped, not passed through | `impersonation::the_layer_injects_the_identity_and_replaces_a_foreign_one` |
| a credential error is `reason=InvalidSpec`, not a generic sync error | `reconcile::failure_reasons_are_specific_and_actionable` |
| `deploy/README.md` never grants a cluster-wide wildcard or cluster-wide `secrets`, and documents the finalizer wedge | `tests/deploy_docs.rs` |

## 8. Live `kind` acceptance — **PENDING (not executed)**

`tests/integration/v0_5_multi_tenancy.rs` and `tests/integration/v0_5_repo_credentials.rs` are
`#[ignore]`d and `kind-` guarded; they have **not** been executed in this environment, so no output is
recorded here. What they are written to prove:

1. a tenant `Application` without `serviceAccountName` is refused (`PolicyViolation`) and deploys
   nothing;
2. with an authorized project and ServiceAccount, the sync is `Synced`, the finalizer lands in the
   tenant namespace, and a **group** `RoleBinding` (`system:serviceaccounts:tenant-a`) is satisfied —
   which only happens if `Impersonate-Group` is sent;
3. the API server refuses a `ConfigMap` into `kube-system` and a `ClusterRole` with `403` naming
   `system:serviceaccount:tenant-a:deployer` (the project deliberately allows both, so the denial can
   only come from impersonation);
4. a `ferriscd.io/secret-type=repository` `Secret` in `ferriscd-system` is read (real API, real label
   selector), matched to the `Application`'s URL, and the credential is resolved and handed to the Git
   client — observable in the logs by `Secret` *name*, never by value — while the same `Secret` in the
   tenant namespace is invisible and an unlabeled one is ignored;
5. a malformed `Secret` is a terminal `Ready=False` that names the `Secret`, and no credential value
   appears in the logs or in `/status`;
6. an `Application` whose URL matches no `Secret` still syncs anonymously (`Synced`).

Run them with `make kind-up && cargo test -p ferriscd-controller --test v0_5_multi_tenancy --test
v0_5_repo_credentials -- --ignored`.

> **Follow-up (not done in Phase 12):** the token-protected **local HTTPS Git fixture** the roadmap
> asks for. The certificate is not the obstacle (§6) — an HTTPS Git server in the harness is. It
> needs a TLS listener serving `git http-backend` with per-request basic auth, reached by pointing
> `SSL_CERT_FILE` at its CA, so the live test can prove the token reached the wire instead of
> relying on a real private repository.

**Optional manual check of the authenticated-clone path** (needs an outbound network, which is why it
is not part of the suite): create a credential `Secret` whose `url` is a real private repository and
whose `token` is a *deliberately invalid* value, then reconcile an `Application` that uses it. The
clone must fail with an authentication error (proving the credential reached the wire) instead of
succeeding anonymously (which would mean the store never matched), and neither the token nor the
user name may appear in the controller logs or in `kubectl describe application`. Repeat with a valid
token to see the same `Application` reach `Synced`.

## 9. Limitations at the end of Phase 12

- **Credential `Secret`s are fetched per resolve.** One label-filtered list per `Application` per
  reconcile, not a shared informer. That is deliberate (no cluster-wide informer, no cached
  credential outliving a revoked `Secret` by an outage), with an API-server cost that Phase 15
  metrics will make visible.
- **Only repository credentials are implemented.** SSH `knownHosts` must be provided per `Secret`
  (the controller never trusts an unknown host key); passphrase-protected keys are refused rather
  than prompting; client-certificate Git auth is not supported.
- **`Secret` rotation is picked up on the next resolve**, because nothing is cached — no restart
  needed, but also no push notification.
- **Impersonation pools are per cluster.** Remote clusters (`T13.1`) will each own a pool — and
  therefore their own single connector and their own bounded client cache.
- **`AppProject` cannot express "this repository but only this path"**; `sourceRepos` is URL-granular.
  Per-path authorization is a Phase 13+ design question.
- **The tenant's ServiceAccount must exist**; the controller never creates it, and a missing one
  surfaces as the API server's `403`, not as a policy error.
- **`spec.destination.cluster` is `in-cluster` only** in this milestone, so cross-cluster
  impersonation RBAC is documented but not exercised (`T13.1`/`T13.4`).
- **The roadmap's token-protected local Git HTTP fixture is not implemented** (§6/§8). Plaintext
  `http://` is refused on purpose and must stay refused; over TLS the remaining gap is that the
  harness has **no HTTPS Git server**, not that a certificate could not be trusted. Tracked as the
  explicit follow-up in §8.
- **The impersonation cache is capped at 64 clients, with FIFO eviction.** The cache key
  (`(destination namespace, ServiceAccount)`) is tenant-influenced, so an unbounded cache was a
  tenant-controlled memory (and `tower::buffer` task) growth vector; a miss rebuilds one
  middleware stack over the same shared connector and logs the eviction.
- **A cascade cleanup can wedge a tenant `Application` in `Terminating`.** `cleanup_inner`
  re-checks `AppProject.spec.allowedServiceAccounts` before resolving the identity (a tenant could
  otherwise retarget `spec.serviceAccountName` and delete its way out with an unauthorized
  identity), so an `Application` left pointing at a now-unallowed ServiceAccount — or at a project
  that was deleted — fails with `Ready=False, reason=PolicyViolation` and **keeps** the finalizer.
  The `ferriscd.io/force-delete: "true"` annotation releases it without pruning; the operator then
  removes the managed objects by hand. Documented in `deploy/README.md` too.

## Further reading

- Kubernetes `Impersonate-User`/`Impersonate-Group` docs and the `impersonate` verb matrix
  (`users`, `groups`, `serviceaccounts`, `uids`).
- The Kubernetes "Authenticating" reference for the exact group set a ServiceAccount token carries.
- Argo CD's `AppProject` semantics (`sourceRepos`, `destinations`, `clusterResourceWhitelist`,
  `namespaceResourceWhitelist`, `namespaceResourceBlacklist`) — including the "empty means
  everything" divergence for the namespace whitelist.
- CVE-2022-31036 / the Argo CD `AppProject`-bypass advisories: real-world instances of the
  "destination namespace is not the resource's namespace" hole this phase closes.
- `gix-transport`'s `add_basic_auth_if_present` (the clear-text credential refusal) and
  `SchemePermission` (the `protocol.<name>.allow` model) — the two upstream mechanisms §6 relies on.

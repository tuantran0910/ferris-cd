# Lesson 14 — Control-Plane API, Webhooks, TokenReview & Project RBAC

> Phase 14 turns FerrisCD from "a controller you `kubectl apply` into" into a platform: an HTTP API
> other programs can drive, webhooks that make `git push` a sync trigger, and the two authorization
> questions every control plane eventually has to answer — **who is this?** and **what may they
> touch?**. The interesting part is not the handlers. It is that the same process now serves a
> network-facing surface, so every request has to be authenticated, authorized, bounded, and unable
> to leak the `Secret`s the controller already knows about.
>
> Code: `crates/ferriscd-server/src/{api,auth,rbac,webhooks,openapi,state,kube}.rs`,
> `crates/ferriscd-cli/src/{client,output,commands/{login,app,platform}}.rs`.
>
> Hermetic coverage: `cargo test -p ferriscd-server` (`auth`, `rbac`, `api`, `webhooks`, `openapi`,
> `kube`) and `cargo test -p ferriscd-cli --bin ferriscd` (client, renderers, exit codes, a fake
> server on `127.0.0.1:0`).
> Live coverage: `tests/integration/v0_9_api_webhooks.rs` and
> `tests/integration/v1_0_control_plane_auth.rs` (`#[ignore]`d, `kind-` guarded) — **not executed
> here** (see §8).

---

## 1. Why the API lives in the controller process

`Application.status` never stores rendered YAML or a diff (ADR-001). So `GET .../diff` cannot be
served by a stateless "read the CR and answer" process: it has to clone the repository (or reuse the
cache), render it, read the destination cluster, and run an SSA dry-run. A second process would need
its own `RepoCache`, renderer cache, `ClusterManager`, `DiscoveryCache` and `DiffEngine` — i.e. every
cache the controller spent five phases building, duplicated and permanently out of sync (finding C9),
plus Redis to share state, which `v1.0` does not have.

So `ferriscd-server` is a **library** that `ferriscd server` embeds next to the controller:

```text
                    ┌──────────────── ferriscd process ────────────────┐
  git ──► RepoCache │  controller loop ──► ReconcileContext::pipeline  │
                    │        ▲                        │               │
  k8s ◄── ClusterManager ─────┼────────────────────────┘               │
                    │        │ SyncPipeline::diff (read-only)          │
  HTTP ──► axum ────┴────────┴── handlers ──► state seams              │
                    └───────────────────────────────────────────────────┘
```

Two consequences worth naming:

* **An API answer cannot disagree with the next reconcile**, because it *is* the reconcile's
  read-only prefix.
* **Everything is testable without a cluster.** Every collaborator is a trait in `state.rs`
  (`ApplicationSource`, `DiffSource`, `OperationWriter`, …), so the router — auth, RBAC, body limits,
  webhook verification, DTO mapping — is driven in-process with `tower::ServiceExt::oneshot` and
  fakes. That is what makes the security tests in §7 hermetic.

The API also never *does* anything to a workload: `POST .../sync` patches one annotation
(`ferriscd.io/operation`) that the controller consumes. The API is a request recorder, not a second
control loop.

## 2. Authentication: `TokenReview`, and why the cache is the hard part

FerrisCD issues no credentials. Kubernetes already does — every workload has a `ServiceAccount`, and
`authentication.k8s.io/v1` will tell you whether a bearer token is valid *right now*, including
audience binding, expiry, and a `ServiceAccount` that has since been deleted. Validating a JWT
locally would need the cluster's signing key and would keep accepting a revoked identity until the
token expired.

```text
client ── Authorization: Bearer <token> ──► axum
                                             │ sha256(token) ──► positive cache (30 s, bounded)
                                             │ miss
                                             ├─► POST tokenreviews.authentication.k8s.io/v1
                                             │      status.authenticated == true ?
                                             ├─► AuthenticatedIdentity { username, groups }
                                             └─► 401 (no token, bad token, or API server unreachable)
```

The mechanism is one API call; everything subtle is in the surrounding decisions.

| Decision | Why it is that way |
|---|---|
| Only **positive** reviews are cached | A negative result is what an attacker controls. Caching "this token is bad" lets a hostile caller fill the cache and evict real identities, and it changes nothing for the attacker. It would, however, break the legitimate case: a token Kubernetes *just* started accepting (a freshly projected `ServiceAccount` token) must work on the first try, not after a 30 s window. |
| The cache key is `SHA-256(token)` | A heap dump of the API process then holds no usable credential, and neither a log line nor a `Debug` rendering can print one. `fingerprint_label()` (12 hex chars) is the only handle that ever reaches a log. |
| TTL = 30 s | A projected `ServiceAccount` token lives an hour and is rotated; 30 s bounds staleness to something far below rotation, while turning a 1 rps dashboard poll into one etcd write per identity per 30 s. |
| Capacity-bound, evict expired then oldest | An `etcd` client that doubles as a `TokenReview` amplifier is a denial of service against the API server. The map is bounded so the API's memory is not a function of the cluster's identity count. |
| Every failure is `401` | Fail closed. An unreachable API server, a missing `create tokenreviews` RBAC grant, an oversized header: all "you are not authenticated". The *reason* goes to the log, keyed by fingerprint. |
| The `401` body never explains | "No token", "expired token" and "token exists but is not a `ServiceAccount`" are three different answers an attacker would love to have. A legitimate caller only needs to know to re-run `ferriscd login`. |
| Route groups, not per-handler checks | The layer is installed on the protected `Router` **before** the groups are merged, so a route added later cannot escape it. `/healthz`, `/readyz` and `/api/v1/webhooks/*` are separate groups: a kubelet probe has no credential and a Git server has a shared secret, not a bearer token. |

`AuthPolicy` makes the choice explicit and typed (`--auth-policy`/`FERRISCD_AUTH_POLICY`):

* `token-review` — the default, described above.
* `deny-all` — lockdown: every protected request is refused without parsing a token or calling the
  API server. Useful during an incident; it cannot accidentally authenticate anyone.
* `pass-through` — the **development escape hatch**: anonymous identity, no authentication. It is
  only defensible on a loopback bind, which is why `exposes_unauthenticated_api(addr, policy)` exists
  and both the binary and `serve_listener` log a warning for that combination. The default bind is
  loopback (`127.0.0.1:8080`), so the shipped configuration is authenticated *and* unreachable from
  the cluster network.

The `ServiceAccount` the control plane runs as needs exactly one extra permission:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ferriscd-token-review
rules:
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
```

Without it every review fails, and because the middleware fails closed, **every** protected request
answers `401` while `/healthz` still says the server is healthy. That is the right failure mode
(never "open because misconfigured"), but it is worth knowing before it happens to you.

## 3. Authorization: project-scoped RBAC, and never leaking existence

`TokenReview` answers *who*. It says nothing about *what*, and in a multi-tenant GitOps control plane
"what" is a project boundary: `Application.spec.project` names an `AppProject`, and an `AppProject`
is the tenant.

The policy is one `ConfigMap` (`ferriscd-rbac-cm`, key `policy.yaml`, in the control-plane
namespace):

```yaml
rules:
  - subject: { kind: group, name: platform-admins }
    project: "*"
    actions: [admin]
  - subject: { kind: group, name: payments-team }
    project: payments
    actions: [get, diff]
  - subject: { kind: user, name: system:serviceaccount:ferriscd-system:ci }
    project: payments
    actions: [get, diff, sync]
```

| Term | Meaning |
|---|---|
| `subject.kind` | `user` matches `AuthenticatedIdentity.username`; `group` matches one of `groups` |
| `subject.name` | exact name, or `*` for every user/group |
| `project` | an `AppProject` name, or `*` |
| `actions` | `get`, `diff`, `sync`, `rollback`; `admin` implies all four |

Design decisions that matter more than the YAML:

* **Default-deny, everywhere.** No rules, no matching rule, an unparseable document, a missing
  `ConfigMap`, an unreadable `ConfigMap`: all authorize nothing. `load_rbac_policy` returns the empty
  policy on error (`fallback_to_deny_all`), the server keeps serving probes and webhooks, and every
  authenticated request is refused. A broken policy is a loud outage, never a quiet opening.
* **Rules union.** A group can grant `get`/`diff` and a narrower group `sync`; an identity holds the
  union of its matches. `admin` folds into every action so a rule cannot grant "admin except sync".
* **An unknown action is a parse error**, not a silent no-op: `actions: [read]` would otherwise
  create a rule that looks real and grants nothing.
* **The policy is a startup snapshot.** Authorization happens on every request; an `etcd` read per
  request would make the API's own policy a denial-of-service vector. The trade-off is documented as
  a limitation (§9): change the `ConfigMap`, restart the server.

### The existence-leak rule

"Never leak the existence of unauthorized applications" is easy to state and easy to get wrong,
because the authorization decision needs the object (its project) and the object read is exactly what
reveals existence. The rule FerrisCD implements is one sentence:

> **`403` is only ever returned to an identity that can already see the object.**

```text
grant = policy.grants(identity, app.spec.project)

grant is empty            → 404  (byte-identical to a nonexistent application)
grant exists, action off  → 403  (the caller can already read it: they know it exists)
grant.allows(action)      → proceed
```

So a read-only identity gets an honest `403` on `sync` (it can read the application, so the refusal
reveals nothing), while a tenant with no grant at all gets `404` for a tenant-B application **and**
for a name that does not exist — same status, same body, same shape. That holds for reads, diffs
*and* mutations: trying to `sync` a foreign application is a `404`, not a `403`.

Lists cannot answer `404`, so they are **filtered** instead: an application in a project the caller
holds nothing in is simply absent from `GET /api/v1/applications` (and a project is absent from
`GET /api/v1/projects`), exactly as if the control plane did not manage it. The response never
reports how many were filtered.

`GET /api/v1/clusters` and `/api/v1/openapi.json` are not project-scoped (a cluster name and the API
contract are not tenant data), so they only require authentication.

## 4. Webhooks: two different schemes, one hardened path

A webhook is an unauthenticated internet-facing endpoint that makes the control plane talk to a Git
remote. GitHub and GitLab are **not interchangeable** here, and treating them as "a secret in a
header" weakens whichever one is checked second (finding H8):

| Layer | Attack it stops |
|---|---|
| `DefaultBodyLimit::max(1 MiB)` installed on the whole router before any parsing | memory exhaustion from a huge body (`413`, not a parse) |
| `X-Hub-Signature-256` HMAC-SHA256 over the raw body, constant-time | forged deliveries — GitHub authenticates the *content* |
| `X-Gitlab-Token` shared secret, constant-time (compared as digests) | forged deliveries — GitLab has no HMAC, so the token authenticates the *caller* and says nothing about the body |
| bounded `X-GitHub-Delivery` replay cache (10 000 ids / 15 min) | replay storms and GitHub's own retries double-syncing |
| per-repository debounce (2 s) + jittered fan-out | a monorepo push matching 50 `Application`s becoming 50 simultaneous reconciles |

Ordering is part of the defence: authenticate **before** touching the replay cache (an
unauthenticated caller must not be able to burn a legitimate delivery id), and deduplicate **before**
parsing (a replay costs one map lookup, not a JSON parse and a cluster read).

A webhook never applies anything. It patches `ferriscd.io/refresh` on the matched `Application`s;
the composite watch predicate turns that into a reconcile, and the diff gate, the `AppProject` checks
and the wave plan all still run in the controller.

## 5. One OpenAPI document, three consumers

`utoipa` generates the contract from the handler annotations, and the same bytes are:

1. served at `GET /api/v1/openapi.json`,
2. committed to `docs/api/openapi.json` by `ferriscd server openapi` (`make gate` runs the CRD check;
   a unit test fails when the committed file drifts), and
3. consumed by `T16.1`'s `openapi-typescript` codegen for the web UI.

The document declares the security scheme per operation, so the generated TypeScript client sends a
bearer token to `/api/v1/*` and none to `/healthz` — the contract, not a convention. Adding the
`403` responses in `T14.4` changed the generated document, which is precisely why it is committed and
checked: a security-relevant contract change is visible in review as a diff.

## 6. Hands-on: signed webhooks, `TokenReview`, RBAC, and the CLI

> Every command below uses **fake** credentials. The `Secret`s, tokens and repository URLs in this
> lesson are throwaway strings; nothing here is a real credential.

### 6.1 A signed GitHub delivery with `curl`

The HMAC is computed exactly as GitHub does it: `sha256=<hex>` over the raw body, keyed by the shared
secret.

```bash
# The cluster (kind) and the server, with a throwaway 32-byte webhook secret.
export KIND_CLUSTER=ferriscd-dev
kind get clusters | grep -qx "$KIND_CLUSTER" || kind create cluster --config deploy/kind-config.yaml
kubectl config use-context "kind-$KIND_CLUSTER"
kubectl apply -f deploy/crds/

export FERRISCD_GITHUB_WEBHOOK_SECRET='fake-webhook-secret-not-a-real-credential'
ferriscd server \
  --api-addr 127.0.0.1:8080 \
  --namespace ferriscd-system \
  --github-webhook-secret "$FERRISCD_GITHUB_WEBHOOK_SECRET" &

# A payload with a deliverable `push`, a fresh delivery id, and no secret material.
BODY='{"ref":"refs/heads/main","after":"8f3a1c2","repository":{"html_url":"https://github.com/example/payment-service","clone_url":"https://github.com/example/payment-service.git","default_branch":"main"}}'
DELIVERY="$(uuidgen)"
SIGNATURE="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$FERRISCD_GITHUB_WEBHOOK_SECRET" -r | cut -d' ' -f1)"

curl -sS -i -X POST http://127.0.0.1:8080/api/v1/webhooks/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-GitHub-Delivery: $DELIVERY" \
  -H "X-Hub-Signature-256: $SIGNATURE" \
  --data-binary "$BODY"
# 200 {"status":"accepted","matched":1,"reference":"refs/heads/main",...}

# The same delivery again: accepted, but nothing is scheduled twice.
curl -sS -X POST http://127.0.0.1:8080/api/v1/webhooks/github \
  -H "Content-Type: application/json" -H "X-GitHub-Event: push" \
  -H "X-GitHub-Delivery: $DELIVERY" -H "X-Hub-Signature-256: $SIGNATURE" \
  --data-binary "$BODY"
# 200 {"status":"duplicate",...}

# A tampered body with the old signature: 401, and no reconcile.
curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/api/v1/webhooks/github \
  -H "Content-Type: application/json" -H "X-GitHub-Event: push" \
  -H "X-GitHub-Delivery: $DELIVERY-tampered" -H "X-Hub-Signature-256: $SIGNATURE" \
  --data-binary "$BODY "
# 401
```

Watch the effect without polling the API: `kubectl get application -n ferriscd-system -o
jsonpath='{.items[*].status.sync.lastSyncedRevision}'` moves to the pushed commit, and the webhook
path never touches it — the annotation does.

### 6.2 `TokenReview` + RBAC + the CLI

```bash
# A throwaway identity, and the policy that lets it *read* one project and nothing else.
kubectl create namespace ferriscd-auth-demo
kubectl create serviceaccount cli-demo -n ferriscd-auth-demo

kubectl apply -f - <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: ferriscd-rbac-cm
  namespace: ferriscd-system
data:
  policy.yaml: |
    rules:
      - subject: { kind: group, name: system:serviceaccounts:ferriscd-auth-demo }
        project: payments
        actions: [get, diff]
YAML

# Restart `ferriscd server` so it loads the policy (it is a startup snapshot).
kubectl create token cli-demo -n ferriscd-auth-demo --duration 1h > /tmp/fake-demo-token

# The CLI stores the token in ~/.config/ferriscd/config.json with mode 0600.
ferriscd login http://127.0.0.1:8080 --token-file /tmp/fake-demo-token
stat -c '%a %n' ~/.config/ferriscd/config.json          # 600 …/config.json

ferriscd app list                                       # only project `payments` appears
ferriscd app diff payments-api                          # redacted; exit 2 when there is drift
ferriscd app sync payments-api                          # 403 + "ferriscd-rbac-cm" hint, exit 1

# No token at all: 401 before any handler runs.
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/api/v1/applications   # 401
# A token Kubernetes does not know: also 401, with the same body.
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Authorization: Bearer definitely-not-a-token' http://127.0.0.1:8080/api/v1/applications  # 401
```

The interesting observation is that `ferriscd app get tenant-b-api` answers **`404`**, not `403`:
the identity holds no grant on `tenant-b`, so the application is indistinguishable from one that does
not exist. The same identity gets an honest `403` only where it can already read.

## 7. Verification performed (hermetic)

`T14.3` (`crates/ferriscd-server/tests/auth_rbac.rs`):

* missing token → `401` on every protected route, with `WWW-Authenticate: Bearer`; a protected `POST`
  is `401` before its body is decoded;
* invalid token → `401`, body identical to the missing-token answer, credential never echoed; a
  malformed header (`Basic …`, `Bearer ` with no credential) is refused **without** a `TokenReview`;
* a valid identity from the fake `TokenReview` → `200`, and the *groups* are what the RBAC policy
  matched (a token with no groups sees nothing);
* cache behaviour, counted: five requests with one token cost **one** review; a second token costs its
  own; a rejected token is reviewed on **every** attempt (negatives are not cached); a zero-TTL cache
  reviews every request; TTL expiry is driven on a paused clock, not a sleep;
* a `TokenReview` that errors → `401` (fail closed), and the backend message is logged, not published;
* route separation: `/healthz`, `/readyz` and a signed webhook answer `200` in the *same* state where
  `/api/v1/applications` answers `401`.

`T14.4` (same file):

* read-only identity: `get` `200`, `diff` `200` (and the diff carries
  `***REDACTED(sha256:…)***`, never a `Secret` value), `sync` `403`, `rollback` `403`, and **no**
  `ferriscd.io/operation` write happened;
* tenant-A's list contains only tenant-A's application; `get`, `diff` and `sync` on tenant-B's
  application all answer `404` with the same body a nonexistent name gets; the project list is
  filtered the same way;
* group matching: the same username with no groups sees nothing;
* `admin` can list everything and sync/roll back anything;
* a malformed policy (through `fallback_to_deny_all`) denies every authenticated caller while
  `/healthz` stays `200`;
* a scoped grant on one project does not leak into another.

`T14.5` (`crates/ferriscd-cli/src/…` unit tests + the fake server in `commands/test_server.rs`):

* the client calls exactly the documented endpoints, always with `Authorization: Bearer …`;
* `app diff` exits `2` on drift and `0` when in sync; `sync --prune` forwards the flag and reports the
  server's `422`; `sync`/`rollback` send exactly `{}` / `{"id":7}`;
* `--watch` settles on the operation's terminal phase and returns on the **first** poll (no fixed
  sleep anywhere in the suite);
* error mapping: `401` → "run `ferriscd login`", `403` → the `ferriscd-rbac-cm` hint, `404` → the
  server's message, `422` → the server's explanation, a malformed body → a decode error, a dead port
  → a transport error; the token appears in none of them;
* the stored credential is `0600` in a `0700` directory, re-tightened on rewrite, and never rendered
  by `Debug`.

`cargo test -p ferriscd-server` and `cargo test -p ferriscd-cli --bin ferriscd` are green in
`make gate`; the rendered OpenAPI document matches `docs/api/openapi.json` byte for byte.

## 8. Live `kind` acceptance — **PENDING (not executed)**

The two ignored suites were **not** run while writing this lesson (no cluster was available in the
authoring environment). The commands below are the acceptance procedure:

```bash
make kind-up

# T14.2: a signed GitHub push really syncs the pushed commit (webhook is the only trigger).
cargo test -p ferriscd-server --test v0_9_api_webhooks -- --ignored --test-threads=1

# T14.3 + T14.4 + T14.5: TokenReview, project RBAC and the CLI, end to end.
cargo test -p ferriscd-cli --test v1_0_control_plane_auth -- --ignored --test-threads=1
```

`v1_0_control_plane_auth` creates a scratch namespace, a `ServiceAccount`, a `ferriscd-rbac-cm` and
two applications (one visible, one not), mints a token with `kubectl create token`, starts the real
`ferriscd server` on a free loopback port, and then:

1. `ferriscd login` succeeds and leaves a `0600` credential file;
2. `ferriscd app list --output json` contains the granted application and never the token;
3. `ferriscd app sync` is refused with the RBAC hint (exit `1`);
4. a bogus `FERRISCD_TOKEN` is `401` with the "run `ferriscd login`" message;
5. `app get` on a foreign and on a nonexistent application both report "not found".

Both suites assert `kubectl config current-context` starts with `kind-` before touching anything, and
both clean up after themselves.

## 9. Limitations at the end of Phase 14

* **The RBAC policy is loaded once, at startup.** A `ConfigMap` edit needs a restart. Reloading it
  would need either a watch (a new informer, which ADR-004 forbids for drift) or a TTL cache with its
  own failure semantics; neither belongs in the same task as the policy itself.
* **Authorization happens after the object read.** The project is a field of the `Application`, so
  there is nothing to authorize before reading it. The existence leak is closed by the `404` rule,
  not by avoiding the read — and a caller can therefore still make the server do a scoped cluster
  read for a name it may not see.
* **No response-time side channel is defended against.** A `404` for an unauthorized application
  costs a read and a `404` for a nonexistent one costs a read too, but they are not constant-time.
* **`TokenReview` is an etcd write.** The 30 s cache bounds it per identity; a genuinely hostile
  authenticated caller still costs one review per 30 s, and an unauthenticated flood costs nothing
  (no token, no review).
* **`--auth-policy pass-through` exists.** It is the documented development escape and it logs a
  warning off loopback, but it is still one flag away from an unauthenticated API. A future release
  could gate it behind a build feature; `v1.0` documents it instead.
* **`POST .../sync` cannot prune, pin a revision, or dry-run.** Those are `spec` fields or `GET
  .../diff` in `v1.0`; the server answers `422` for a body asking otherwise rather than silently
  ignoring it.
* **No OIDC/SSO.** `T14.3` deliberately picks one mechanism (finding H9); OIDC is post-`v1.0`
  backlog (`T16.8`).
* **The webhook fan-out is per-process.** Two replicas each debounce and each patch the annotation;
  the patch is idempotent and the controller coalesces, but the debounce window is not shared.

## Further reading

* Kubernetes `TokenReview` API: <https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/>
* Projected `ServiceAccount` tokens and bound audiences: <https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection>
* GitHub webhook signature validation: <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>
* GitLab webhook secret tokens: <https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#validate-payloads-by-using-a-secret-token>
* OpenAPI 3.1: <https://spec.openapis.org/oas/v3.1.0>
* `utoipa`: <https://docs.rs/utoipa>
* `axum` middleware and `route_layer`: <https://docs.rs/axum/latest/axum/middleware/index.html>
* Argo CD's project RBAC (the model this borrows from): <https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/>

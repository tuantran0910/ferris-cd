# Lesson 19 — Enterprise SSO, `ApplicationSet`s and Event-Driven Notifications

**Phase 19 (`v1.1`) knowledge base.** This chapter covers the notifications engine (`T19.4`). The SSO
(`T19.1`/`T19.2`) and `ApplicationSet` (`T19.3`) sections of this phase land in their own tasks; the
`kind` experiment below is the one `T19.4` ships.

---

## 1. Why notifications are a *status writer* and not a controller

Every GitOps notification feature has to answer one question: *what event do I subscribe to?* The
tempting answers are all wrong in the same way:

| Design | What breaks |
|---|---|
| A second `Application` watch | doubles the API-server load and re-derives state that a reconcile already computed |
| A polling loop over `/status` | adds latency, wakes the API server for nothing, and pages on the poll, not on the change |
| Notify whenever the status *is* `Degraded` | pages on every 180 s requeue of a persistently failing app (alert fatigue, then alert blindness) |

FerrisCD already writes every status through one seam — the `StatusWriter` decorator chain
(`ApiStatusWriter` → `MetricsStatusWriter`, `T15.1`) — under the always-update-status contract
(trap T3): `Ok` **and** `Err` passes both persist `/status`. So the notification observer
(`crates/ferriscd-controller/src/notifications/observer.rs`) is just another decorator:

```text
reconcile pass ──► StatusWriter::patch(status)
                      ├─► ApiStatusWriter            (the real patch)
                      ├─► NotificationObserver       (this chapter)
                      └─► MetricsStatusWriter        (T15.1)
```

That gives three properties for free:

* **Zero extra API reads.** The observer sees the exact `ApplicationStatus` the pass persisted,
  together with the `Application` it belongs to — no re-fetch, no informer.
* **No notification for a write that did not happen.** The decorator notifies only *after*
  `inner.patch(..)` returned `Ok`; a rejected patch describes a world that never existed.
* **No coupling to the reconcile logic.** No pipeline, CLI flag or CRD field changes shape.

## 2. Edge triggering, deduplication and the debounce

Three gates, in this order, decide whether a delivery happens:

1. **Edge detection** (`on-sync-succeeded`, `on-sync-failed`, `on-health-degraded`): a trigger fires
   on a *transition* (`synced` ← not-synced, `Ready=False` ← not-`False`, `Degraded` ← not-`Degraded`),
   never on a state. A revision change counts as a transition, so "revision `feedface` failed" is a
   new alert even if the previous revision also failed.
2. **Debounce for `on-out-of-sync`.** A sync that is about to run *always* passes through
   `OutOfSync`; firing immediately would alert on every legitimate sync. The trigger fires only when
   the drift survives the debounce (60 s by default, `ConfigMap`-tunable up to 1 h), and only once
   per `(generation, revision, health)`.
3. **Deduplication** on the roadmap's key `(app_ns, app_name, trigger, observed_generation,
   revision, health_status)` in a bounded LRU (4096 keys). It suppresses a re-observed state even when
   the edge table no longer has it (evicted entry, `forget_app`, a second observer). A key is recorded
   only once a delivery was actually **queued**, so an event the token bucket suppressed is retryable
   instead of lost.

Both tables are in memory, so a **process restart loses them**. The consequence is bounded and
deliberate: after a restart a persistently failing `Application` delivers at most one notification per
subscribed trigger (the first reconcile looks like a fresh edge), and PagerDuty's `dedup_key` — which
*is* this key — collapses that repeat server-side.

Then a **per-`Application` token bucket** (`10 notifications / 5 min`) bounds a flapping app, and the
queue (`try_send`, capacity 512) bounds the whole subsystem: a full queue drops the notification,
counts it (`outcome="dropped"`) and logs a warning, because an alert must never apply backpressure to
a reconcile loop.

### 2.1 Reserve, then refund (and roll back the edge)

The token bucket is consumed **before** `try_send`, because two workers racing for the same token is
exactly what the bucket exists to stop. That ordering has one failure mode worth naming: a full queue
would spend a token on an alert that was then *dropped*, and a burst of 512 drops would empty a
tenant's bucket and rate-limit (`outcome="suppressed"`) the one real page that follows — the alert the
budget exists to protect. So the token is a **reservation**: `try_send` returning `Err` (or the
delivery being deduplicated / rate limited) gives it back.

The same pass treats the *observation* the same way. The new observation is computed against a
snapshot of the previous one and committed only when at least one delivery was enqueued; otherwise it
is rolled back. With the state committed first, one rate-limited `on-sync-failed` would mean the
failure is never announced, because "we already saw `Ready=False`" is now permanent state. Two
deliberate exceptions: the `on-out-of-sync` debounce timer keeps running (it is a clock, not an edge —
resetting it would re-arm a 60 s wait every 180 s and never fire), and a write that fires several
triggers where only some are enqueued advances the whole observation (the documented limit of the
snapshot/restore approach).

Every table is bounded and `forget_app` releases a deleted `Application`'s entries — the same
cardinality discipline as `T15.1`'s metrics.

## 3. Configuration: annotations for opt-in, `ConfigMap` for text, `Secret`s for destinations

| Surface | Holds | Trap |
|---|---|---|
| `Application` annotation `notifications.ferriscd.io/subscribe.<trigger>.<service>: <recipient>` | *who* is notified | the key is deliberately **not** in `CONTROL_ANNOTATIONS`, so subscribing emits no reconcile (`composite_hash` is unchanged — asserted) |
| `ConfigMap/ferriscd-notifications-cm` (key `notifications.yaml`) | message templates, `on-out-of-sync` debounce | parsed through `ferriscd_engine::manifest::parse_document` (duplicate keys, alias bombs, budgets); an unusable document falls back to the built-in templates, because templates only choose *words* |
| `Secret`s labelled `ferriscd.io/secret-type=notifications` | `url`, `service`, `signingKey`, `routingKey`, `token`, `channel` | never in an annotation and never in a `ConfigMap`; a namespaced `Api<Secret>` means no code path can read a `Secret` from a tenant namespace |

Templates are **not** a template engine. A placeholder is either one of twelve allow-listed keys or the
document is refused at load time:

```yaml
templates:
  on-sync-failed:
    title: "Sync failed: {{app.name}}"
    body: "{{app.namespace}}/{{app.name}} failed at {{app.revision}}: {{app.message}}"
triggers:
  on-out-of-sync:
    debounceSeconds: 120
```

The context built for the template is a closed struct
(`notifications/template.rs::NotificationContext`): the redacted sync/health/condition facts, the
redacted repository URL, and the trigger/service/recipient. A template cannot reach a `Secret`, a
diff, or a rendered manifest because the renderer never sees one.

### 3.1 The context is narrower than the roadmap's list

The roadmap describes the redacted context as `sync`, `health`, `conditions` and `history`.
`conditions` and `history` are **not** exposed, deliberately:

* `conditions` duplicates what the four scalar keys already carry (`app.syncStatus`,
  `app.healthStatus`, `app.message` = the bounded `Ready` message, `app.observedGeneration`), and a
  per-condition array in a payload is a payload the receiver has to parse before it can act;
* `history` is the deployment history — unbounded in principle, operator-visible, and the one field
  on `ApplicationStatus` a template would most like to iterate over. Exposing it turns "render some
  words" into "expose the workload's deployment log to whoever can write an annotation", for no
  alerting value: the useful fact (`app.revision`) is a single key.

The twelve keys are allow-listed at `ConfigMap` load time, so "a template cannot reach a `Secret`" is a
property of the type, not of a reviewer's attention.

### 3.2 Tenancy is default-open, and says so at startup

`--notifications-allowed-namespaces` unset means *any* reconciled namespace may subscribe, and may
name *any* channel `Secret` in the control-plane namespace. That default is kept for compatibility (a
new flag must not silence an existing `Application`), but the dangerous combination — notifications
enabled, `Application` scope wider than the control plane, no allowlist — emits one `tracing::warn!`
before the first reconcile, naming both namespaces. The predicate is pure
(`open_tenant_allowlist_warning`), so an operator can also see the answer in a test instead of a log.

## 4. The SSRF guard is the interesting part

A notification destination is attacker-*influenced*: whoever can write an `Application` annotation
chooses the recipient, and the recipient's `Secret` holds a URL. Naively posting to that URL hands the
controller pod's network identity — cloud metadata credentials included — to a tenant. Four layers,
each independently sufficient for the common bypass:

1. **Static validation** (`notifications/ssrf.rs`): `https://` only; `user:pass@` refused; `localhost`,
   `*.localhost` and `metadata`/`metadata.google.internal` refused; a literal IP is classified before
   any DNS work.
2. **Address classification on the canonical form.** `::ffff:169.254.169.254` and `::169.254.169.254`
   are judged as `169.254.169.254`, and NAT64 (`64:ff9b::a9fe:a9fe`) is judged by its embedded IPv4
   address. Loopback, link-local/IMDS, multicast, broadcast, unspecified and `fd00:ec2::254` are
   always refused.
3. **Resolution-time re-check** (`resolve_and_validate`): every address DNS returns is classified
   immediately before the connect, so a name that resolves to a metadata address right now is refused
   even if it resolved to a public one when the `Secret` was written.
4. **Pinning at connect** (`GuardedResolver`, a `reqwest::dns::Resolve`): the pooled client only opens
   connections to addresses the policy approved. That is what defeats **DNS rebinding** — the name
   cannot resolve benignly for the pre-flight check and evilly a millisecond later.

`--notifications-allow-private-cidrs` exists because internal receivers usually live on RFC 1918
addresses. It unlocks **only** the `PrivateNetwork` class: loopback, link-local/IMDS and multicast stay
refused even when an allowlisted CIDR covers them, and `/0` is rejected at parse time instead of
silently disabling the guard.

**Redirects are never followed.** `302 → http://169.254.169.254/...` is the classic bypass; the
production client is built with `reqwest::redirect::Policy::none()` *and* the worker treats every 3xx as
a hard failure, so neither half has to be trusted alone.

### 4.1 Internal receivers: `--notifications-ca-file`, never "skip verification"

The common enterprise blocker is not the SSRF guard, it is **TLS**: an internal receiver
(`https://notifications.internal.corp/hook`) is signed by the platform's own CA, which the
controller's trust store has never heard of. The tempting escape hatch — a `--insecure-skip-verify`
flag — would delete the only thing that makes `https://` meaningful for a tenant-influenced
destination, and it would do it globally, for every channel.

`--notifications-ca-file <path>` (or `FERRISCD_NOTIFICATIONS_CA_FILE`) is the narrow alternative:

* the file is a PEM bundle, read **once at startup** (async: a blocking read on a runtime worker is
  exactly what the async-hygiene rule forbids), and every certificate in it is **added** to the
  client's roots via `reqwest`'s `add_root_certificate` — the platform trust store stays in force, so
  a public destination keeps working unchanged;
* nothing else changes: still `https://` only, still no redirects, still the pinned SSRF resolver,
  still hostname/IP verification (the `IP SAN` is checked, which is why this test's leaf carries one);
* a missing, empty or non-PEM file is a **startup** error. The alternative — starting successfully and
  then failing TLS on the first real page — is the worst possible failure mode for an alerting path;
* the private address still needs `--notifications-allow-private-cidrs`: trust and reachability are
  two different decisions, and an operator has to make both.

## 5. Delivery: bounded, retried, and observable

* `5 s` per request, at most `3` attempts with exponential backoff (`500 ms`, `1 s`).
* Every **delivery** ends in `ferriscd_notifications_total{service, outcome}` with a fixed label set
  (`slack|teams|pagerduty|webhook` × `delivered|failed|dropped|suppressed`): no status code, no error
  string, no URL ever becomes a label. One delivery is one outcome, however many of its attempts
  failed — the counter answers "did the page land?", not "how many TCP connections were tried".
* Slack has two shapes from one adapter: an Incoming Webhook `url` (`{"text": ...}`), or the Bot API
  (`url: https://slack.com/api/chat.postMessage` plus `token` and `channel` — the token rides in the
  `Authorization` header, never in the body a receiver logs).
* Generic webhooks are signed: `X-FerrisCD-Signature-256: sha256=<hex HMAC-SHA256>`, computed over the
  exact bytes posted, with `X-FerrisCD-Trigger` and `X-FerrisCD-Delivery` (the dedup key) alongside.
  PagerDuty gets the same dedup key as its `dedup_key`, so it collapses a repeat even after a
  controller restart.
* Secrets never reach a payload or a log: the channel `Debug` prints `scheme://host/<redacted>`
  (Slack/Teams keep their token in the URL **path**, so stripping only the query string is not enough),
  and `reqwest` errors are logged through `without_url()`.

## 6. Hands-on `kind` experiment

1. Enable the feature and allowlist the kind service CIDR:

   ```bash
   ferriscd controller --enable-notifications \
     --notifications-allow-private-cidrs 10.96.0.0/12
   ```

2. Create a channel `Secret` (the only place a URL may live):

   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: payments-oncall
     namespace: ferriscd-system
     labels:
       ferriscd.io/secret-type: notifications
   type: Opaque
   stringData:
     service: webhook
     url: https://ferriscd-notifications-receiver.ferriscd-system.svc/hook
     signingKey: change-me
   ```

3. Opt one `Application` in — this is the *only* change to the `Application`, and it triggers no
   reconcile:

   ```bash
   kubectl annotate application demo-app -n ferriscd-system \
     notifications.ferriscd.io/subscribe.on-sync-succeeded.webhook=payments-oncall \
     notifications.ferriscd.io/subscribe.on-health-degraded.webhook=payments-oncall
   ```

4. Break the deployment (`kubectl set image ...=nginx:does-not-exist`) and watch exactly **one**
   `on-health-degraded` delivery; leave it broken for ten requeues (30 minutes) and confirm **no**
   additional deliveries. Recovery produces one `on-sync-succeeded`.
5. Prove the guard: point the `Secret`'s `url` at `http://169.254.169.254/latest/meta-data/` and watch
   `ferriscd_notifications_total{service="webhook",outcome="failed"}` climb while the receiver sees
   nothing. Repeat with `https://169.254.169.254/...` and `https://[::ffff:169.254.169.254]/...`.
6. Verify a signature on the receiver: recompute `sha256=<hex>` with HMAC-SHA256 over the raw body and
   compare it with `X-FerrisCD-Signature-256`.
7. If the receiver is HTTPS signed by a private CA, add `--notifications-ca-file /etc/ferriscd/notif-ca.pem`
   (a PEM bundle) instead of weakening anything: the CA is *added* to the client's roots, the IP/host
   check and the SSRF guard stay on, and the destination still needs its CIDR allowlisted.

Two `#[ignore]`d live tests cover this chapter (both assert a `kind-*` context first):

* `crates/ferriscd-controller/src/notifications/mod.rs` — steps 2–5's configuration half against the
  real API (`ConfigMap` parsing, `Secret` resolution, the egress policy).
* `tests/integration/v0_5_notifications.rs` (target `ferriscd-cli`, `cargo test -p ferriscd-cli --test
  v0_5_notifications -- --ignored`; the two tests take a process-global mutex, so `--test-threads`
  does not matter and `make test-integration`'s default thread count is safe) — the full acceptance: an
  **in-test HTTPS
  receiver** on the host's LAN address, its own throwaway CA and an `IP SAN` leaf, the real controller
  binary started with `--enable-notifications --notifications-ca-file --notifications-allow-private-cidrs
  <lan>/32`, one `on-sync-succeeded` and one `on-health-degraded` delivery driven through a local Git
  failure/recovery, each signature recomputed independently from the raw bytes. The host's LAN address
  must be **private** (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`): the negative control proves
  "no `--notifications-allow-private-cidrs` ⇒ refused", which is only a statement about the flag when
  the guard would otherwise demand it, so the suite asserts the classification and refuses to run on a
  public address.

### 6.1 What the live acceptance can and cannot prove

**The receiver is on the host, not in a pod (recorded narrowing).** The roadmap asks for an in-cluster
receiver pod. The suite instead binds an HTTPS server on this host's non-loopback LAN address and runs
the controller as a **host process**, because the two properties the roadmap sentence is really after
are both client-side and both observable this way: an operator-supplied PEM CA is *added to* the
client's roots (a trust extension, not a verification bypass), and "can I reach this address at all" is
a **separate** decision from "do I trust it", taken by the CIDR allowlist. What the suite does not
cover, and says so: the in-cluster network path (a `Service`/`EndpointSlice`-routed `https://…svc/hook`
destination) and a receiver pod's own identity.

**The second test is a negative control, and it is what makes "required" measurable.**
`notifications_require_the_ca_file_and_the_private_cidr_allowlist` runs the same receiver, the same
`Application` and the same flags **minus exactly one prerequisite** per phase, and each phase proves
three things:

| Phase | Metric (scraped from the process's own `/metrics`) | Receiver | Log |
|---|---|---|---|
| no `--notifications-ca-file` | `webhook,outcome="failed"` ≥ 1, `delivered` = 0 | connection **accepted**, zero deliveries (the handshake is what failed) | `the notification delivery failed`, no egress-guard refusal |
| no `--notifications-allow-private-cidrs` | same | **no** new connection at all (refused before the connect) | the egress-guard refusal, no transport failure |

Both phases would otherwise look identical — `outcome="failed"` and an empty receiver — so the
connection counter and the two log strings are the observables that keep the test from passing for the
wrong reason. The metric itself is read over a `TcpStream` from the address parsed out of the
controller's own `metrics listener ready` line (`--metrics-addr 127.0.0.1:0` means the kernel picks the
port), which is also why the parser has a hermetic unit test: the same log carries a
`metrics_addr=Some("127.0.0.1:0")` startup field, and the pretty log format colours the field names.

**The CA fixture needs a portable `openssl` invocation.** `-addext` only exists in OpenSSL 1.1.1+ and is
absent from the stock macOS LibreSSL, so the CA is generated from a config file (`-config` with a
`[v3_ca]` section: `basicConstraints=critical,CA:TRUE`, `keyUsage=critical,keyCertSign,cRLSign`). The
leaf keeps an **IP SAN** so IP/hostname verification stays switched on — otherwise the test would only
prove that an untrusted certificate is refused.

**No scratch directories are left behind.** Every controller child gets its own `TMPDIR` *and* an
explicit `--work-root` inside it, and both tests assert that `--work-root`'s `ferriscd-repos` exists and
that `<TMPDIR>/ferriscd-repos` (the default the flag replaces) does not.

## 7. Takeaways

* Observability belongs on an existing seam, not in a second watch: the `StatusWriter` decorator
  pattern made "notify exactly once per real change" a pure-function problem.
* Edge detection without deduplication is not enough (a restart is an edge), and deduplication without
  edge detection is not enough (a flap is a new key every time). You need both, plus a debounce for the
  state every sync passes through.
* For egress to a user-chosen URL, classify the **canonical** address, re-check at resolution time, pin
  the address in the connection pool, refuse redirects, and make the operator allowlist unable to
  unlock metadata. Any one of those alone is a known bypass.
* A URL is a credential: `redact_audit_url` strips the query, but Slack/Teams tokens live in the path —
  redact the path too.
* **"Required" is a claim you have to measure.** Two flags that are both required for one delivery
  produce exactly the same evidence when either is missing (`outcome="failed"`, an empty receiver), so a
  positive test alone cannot tell "the CA is required" from "the allowlist is required" from "nothing
  ran". The negative control asserts what each phase should *not* look like — a transport failure vs. a
  refusal before any connection — and reads the process's own metric so an assertion can never pass by
  observing a controller that never reconciled anything.

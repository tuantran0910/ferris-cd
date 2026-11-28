//! Live `v0.5` acceptance for event-driven notifications (`T19.4`, finding **P19-H1**).
//!
//! # What only a real cluster can prove
//!
//! The hermetic unit tests pin every *decision* (edge detection, deduplication, rate limiting,
//! templates, payloads, the SSRF guard). They cannot prove the two things an operator actually cares
//! about:
//!
//! 1. **A real `Application` lifecycle produces exactly one delivery per trigger**, through the real
//!    `StatusWriter` decorator, the real `/status` patches, the real `Secret` resolution and the real
//!    HTTPS client — `on-sync-succeeded` when the sync recovers, `on-health-degraded` when the
//!    workload's health degrades.
//! 2. **The `--notifications-ca-file` escape hatch is a *trust* extension, not a verification
//!    bypass.** The receiver below is an in-test HTTPS server whose certificate is signed by a
//!    throwaway CA and carries an **IP SAN for the host's non-loopback LAN address**. Nothing in the
//!    platform trust store vouches for it: the controller can only deliver if the operator-supplied
//!    PEM CA is really added to the client's roots, over `https://` only, to an address that is
//!    unlocked by `--notifications-allow-private-cidrs` (a `/32`), with HMAC-SHA256 signing intact.
//! 3. **Both prerequisites are *required*, and neither substitutes for the other.** The second test
//!    (the negative control) runs the same receiver, the same `Application` and the same flags
//!    **minus exactly one prerequisite** each time: without the CA file the TCP connection is made and
//!    the TLS handshake is refused; without the CIDR allowlist not a single connection is opened. In
//!    both phases `ferriscd_notifications_total{service="webhook",outcome="failed"}` is the only
//!    thing that moves and the receiver records **zero** deliveries.
//!
//! # Safety gate
//!
//! Like every live test in this directory, it asserts `kubectl config current-context` starts with
//! `kind-` before touching anything, and it is `#[ignore]`d so `make gate` never needs a cluster.
//!
//! ```text
//! make kind-up
//! kubectl apply -f deploy/crds
//! cargo test -p ferriscd-cli --test v0_5_notifications -- --ignored --nocapture
//! ```
//!
//! # Prerequisites
//!
//! * a `kind-*` context with the FerrisCD CRDs installed (the test applies `deploy/crds` itself);
//! * the `openssl` CLI (the test CA and the IP-SAN leaf are generated with it — a Rust certificate
//!   stack is not otherwise a dependency of this workspace). The CA comes from a **config file**
//!   (`-config` + `[v3_ca]` extensions), not from `-addext`, which only exists in OpenSSL 1.1.1+ and
//!   is absent from the stock macOS LibreSSL: the same command line therefore works on both;
//! * a non-loopback, **private** IPv4 address on this host that the controller process can reach,
//!   which is where the receiver binds. The test fails loudly if it cannot determine one.
//!
//!   Private is a prerequisite, not a preference: the negative control's second phase proves "no
//!   `--notifications-allow-private-cidrs` ⇒ refused" by pointing the controller at the receiver
//!   **without** the allowlist, and only an address the egress guard classifies as private is
//!   refused for that reason. A public address (a cloud host with a directly-routed public IP) is
//!   reachable without the flag, so the phase would then assert something it never tested. The
//!   accepted ranges are the ones `EgressPolicy` gates behind the allowlist — `10.0.0.0/8`,
//!   `172.16.0.0/12`, `192.168.0.0/16` and the RFC 6598 `100.64.0.0/10` (an IPv6 ULA would be the
//!   same case, but this suite's receiver is IPv4-only). Put the host on such a network and re-run;
//!   `non_loopback_ipv4` refuses to start the test otherwise.
//!
//! # No sleeps, bounded waits
//!
//! Every wait is a bounded poll (`wait_until`) with a deadline and a named condition — the controller
//! is asynchronous, so "wait for the cluster to converge" is unavoidable, but no assertion depends on
//! a fixed sleep being long enough, and a miss fails with the observed status in the message.
//!
//! # Serial by construction, not by command line
//!
//! A controller started here watches every `Application` in the control-plane namespace, exactly like
//! the production one, so the two live tests in this file must not run at the same time: each would
//! observe (and its cleanup would delete) the other's fixtures. "Run serially" is therefore **not** a
//! note telling the operator to pass `--test-threads=1` — `make test-integration` runs
//! `cargo test --workspace -- --ignored`, which uses the default thread count. Both tests take the
//! process-global `LIVE_SUITE` mutex as their first statement, so they are serial under any
//! `--test-threads`, and a `--test-threads=4` run is equivalent to `--test-threads=1`.

// Test-only shell-out/TLS helpers are allowed to panic: this file is compiled as a test target and
// never ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Control-plane namespace the controller watches.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// `Application` name (unique, so a parallel run of another live test cannot collide).
const APPLICATION_NAME: &str = "notifications-live-demo";
/// Namespace the fixture `Deployment` is applied into.
const TARGET_NAMESPACE: &str = "ferriscd-notifications-live";
/// The channel `Secret` (`ferriscd.io/secret-type: notifications`).
const CHANNEL_SECRET: &str = "notifications-live-channel";
/// The HMAC key the receiver verifies against; it must never appear in a payload or a log.
const SIGNING_KEY: &str = "t19-4-live-signing-key-do-not-leak";
/// Image tag that cannot be pulled: the `Deployment` never becomes available.
const BAD_IMAGE: &str = "nginx:definitely-not-a-real-tag";
/// Short progress deadline so `Degraded` is reachable inside a test (`600 s` by default).
const PROGRESS_DEADLINE_SECONDS: u32 = 20;
/// How long one convergence step may take.
const CONVERGENCE_DEADLINE: Duration = Duration::from_secs(360);
/// `Application` the negative control uses (per-test, so the two live tests cannot collide).
const NEGATIVE_APPLICATION_NAME: &str = "notifications-live-negative-control";
/// Channel `Secret` the negative control uses.
const NEGATIVE_CHANNEL_SECRET: &str = "notifications-live-negative-channel";
/// Namespace the negative control's fixture `ConfigMap` is applied into.
const NEGATIVE_TARGET_NAMESPACE: &str = "ferriscd-notifications-negative";
/// The `outcome="failed"` counter of the generic webhook channel (what a refused delivery leaves).
const WEBHOOK_FAILED_SERIES: &str =
    r#"ferriscd_notifications_total{service="webhook",outcome="failed"}"#;
/// The `outcome="delivered"` counter, which the negative control must never see move.
const WEBHOOK_DELIVERED_SERIES: &str =
    r#"ferriscd_notifications_total{service="webhook",outcome="delivered"}"#;
/// Path the receiver serves, and the query token that must never be logged.
///
/// The destination URL is the one field a channel `Secret` can carry a credential in, and a webhook
/// token is routinely in the **path** or the **query string** (Slack keeps it in the path). Sending
/// the token here turns "the URL is never logged" from a comment into an assertion: the controller's
/// complete log must not contain it, while the receiver must still see it on the wire.
const RECEIVER_PATH: &str = "/hook";
/// The query token of the receiver URL (see [`RECEIVER_PATH`]).
const URL_QUERY_TOKEN: &str = "t19-4-live-query-token-never-logged";
/// Upper bound on the bytes the receiver will buffer while looking for the end of a request head.
///
/// A test receiver must not be an unbounded sink: without a cap, a peer (or a regression that sends
/// an endless header block) grows this buffer until the process dies. `16 KiB` is far above the
/// largest head this suite sends and far below anything that would matter.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Serialises the two live tests **in this process**.
///
/// Both of them start a controller that watches every `Application` in the control-plane namespace,
/// so running them at the same time would make each one observe the other's fixtures — and
/// `ClusterCleanup` would delete them underneath it. `cargo test -- --ignored` (what
/// `make test-integration` runs) uses the default thread count, so the "run serially" note in the
/// module docs has to be enforced here rather than in the command line.
static LIVE_SUITE: Mutex<()> = Mutex::new(());

/// Takes the process-global live-suite lock.
fn live_suite() -> std::sync::MutexGuard<'static, ()> {
    acquire(&LIVE_SUITE)
}

/// Locks `lock`, recovering from a poisoning panic.
///
/// A panic *while holding* it poisons the mutex; the other live test must still run (and report its
/// own result) rather than fail on a `PoisonError` it cannot do anything about, and `()` carries no
/// state that a panic could leave half-written, so recovering is sound. Taking the `&'static`
/// argument (instead of reading the global directly) is what lets a test prove the recovery without
/// poisoning the real lock.
fn acquire(lock: &'static Mutex<()>) -> std::sync::MutexGuard<'static, ()> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The receiver's URL: `https://<lan ip>:<port>/hook?token=<URL_QUERY_TOKEN>`.
fn receiver_url(lan_ip: Ipv4Addr, port: u16) -> String {
    format!("https://{lan_ip}:{port}{RECEIVER_PATH}?token={URL_QUERY_TOKEN}")
}

#[test]
#[ignore = "requires a live kind cluster (make kind-up) and the openssl CLI"]
fn notifications_deliver_once_per_trigger_to_a_private_ca_receiver() {
    // First statement, before even the context check: the other live test in this file starts a
    // controller that watches the same namespace, so this is the serialisation point.
    let _live = live_suite();
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "ABORT: refusing to touch non-kind cluster context {context:?}"
    );

    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    // Best-effort cleanup even when an assertion below panics (the fixtures are cluster objects and
    // a controller child process).
    let _cluster_cleanup = ClusterCleanup::new(APPLICATION_NAME, CHANNEL_SECRET, TARGET_NAMESPACE);

    // ------------------------------------------------------------------
    // 1. The receiver: HTTPS, private CA, IP SAN for this host's LAN IP
    // ------------------------------------------------------------------
    let lan_ip = non_loopback_ipv4();
    let tls_dir = tempfile::tempdir().expect("create the TLS fixture directory");
    let tls = generate_tls_material(tls_dir.path(), lan_ip);
    let receiver = TlsReceiver::start(lan_ip, &tls);

    // ------------------------------------------------------------------
    // 2. The channel Secret: a URL only a CA-file-supplied trust root can reach
    // ------------------------------------------------------------------
    let channel_url = receiver_url(lan_ip, receiver.port());
    apply_channel_secret(CHANNEL_SECRET, &channel_url);

    // ------------------------------------------------------------------
    // 3. The Application: subscribed to exactly the two triggers this test drives
    // ------------------------------------------------------------------
    let fixture = tempfile::tempdir().expect("create the git fixture directory");
    let repo = fixture.path().join("repo");
    std::fs::create_dir_all(&repo).expect("create the fixture repository");
    write_broken_fixture_and_commit(&repo);
    apply_application(
        APPLICATION_NAME,
        CHANNEL_SECRET,
        TARGET_NAMESPACE,
        &repo.display().to_string(),
    );

    // ------------------------------------------------------------------
    // 4. The controller: the real binary, the real flags
    // ------------------------------------------------------------------
    let log_dir = tempfile::tempdir().expect("create the log directory");
    let log_path = log_dir.path().join("controller.log");
    // Finding P19-M3: the controller's Git scratch root defaults to `<system temp dir>/ferriscd-repos`,
    // which a test run would leave behind on the developer's machine forever. The process gets its
    // own `TMPDIR` *and* an explicit `--work-root` inside it, so the assertion below can prove both
    // that the flag was honoured and that nothing landed in the default location.
    let scratch_dir = tempfile::tempdir().expect("create the controller scratch directory");
    let work_root = scratch_dir.path().join("work");
    let controller = ControllerProcess::start(
        NotificationFlags {
            ca_pem: Some(&tls.ca_pem),
            allow_private: Some(lan_ip),
            metrics_addr: "127.0.0.1:0",
        },
        &log_path,
        &work_root,
        scratch_dir.path(),
    );

    // The failure pass: `Ready=False`, which is the trigger this test does *not* subscribe to.
    //
    // A render failure is classified **terminal**, so the next pass of an unfixed `Application` is
    // `TERMINAL_DELAY` (600 s) away — deliberately, so an unfixable `Application` stops churning the
    // work queue. See `poke_reconcile` for how the recovery below stays inside the test's budget.
    wait_until(
        APPLICATION_NAME,
        CONVERGENCE_DEADLINE,
        "the broken fixture to fail the sync (Ready=False)",
        || ready_status(APPLICATION_NAME).as_deref() == Some("False"),
    );
    assert!(
        receiver.deliveries().is_empty(),
        "an unsubscribed trigger must not deliver: {:?}",
        receiver.summary()
    );

    // ------------------------------------------------------------------
    // 5. Recovery: a valid commit, then `on-sync-succeeded`
    // ------------------------------------------------------------------
    write_bad_image_fixture_and_commit(&repo);
    // The recovering commit does not change the `Application` (only the repository's `main`), and the
    // failed pass scheduled the next one 600 s out, so the watcher has to be woken: this is a real
    // spec edit, which is exactly what an operator fixing a broken `Application` would produce.
    poke_reconcile(APPLICATION_NAME);
    wait_until(
        APPLICATION_NAME,
        CONVERGENCE_DEADLINE,
        "the Application to report Synced after the fix",
        || status_jsonpath(APPLICATION_NAME, "{.status.sync.status}") == "Synced",
    );
    wait_until(
        APPLICATION_NAME,
        CONVERGENCE_DEADLINE,
        "the on-sync-succeeded delivery",
        || trigger_count(&receiver, "on-sync-succeeded") == 1,
    );

    // ------------------------------------------------------------------
    // 6. Health degrades: `on-health-degraded`
    // ------------------------------------------------------------------
    wait_until(
        APPLICATION_NAME,
        CONVERGENCE_DEADLINE,
        "the Application to report Degraded health for the unpullable image",
        || health_status(APPLICATION_NAME).as_deref() == Some("Degraded"),
    );
    wait_until(
        APPLICATION_NAME,
        CONVERGENCE_DEADLINE,
        "the on-health-degraded delivery",
        || trigger_count(&receiver, "on-health-degraded") == 1,
    );

    // ------------------------------------------------------------------
    // 7. Exactly one delivery per trigger, signed, and nothing else
    // ------------------------------------------------------------------
    // A grace window in which a duplicate would have to arrive (the controller requeues every 2 s,
    // so several further passes happen inside it). Polling, not a fixed sleep: the condition is
    // "still exactly two, one per trigger".
    let stable_until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < stable_until {
        let deliveries = receiver.deliveries();
        assert_eq!(
            deliveries.len(),
            2,
            "exactly one delivery per subscribed trigger, got: {:?}",
            receiver.summary()
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    let deliveries = receiver.deliveries();
    assert_eq!(deliveries.len(), 2, "{:?}", receiver.summary());
    assert_eq!(
        trigger_count(&receiver, "on-sync-succeeded"),
        1,
        "{:?}",
        receiver.summary()
    );
    assert_eq!(
        trigger_count(&receiver, "on-health-degraded"),
        1,
        "{:?}",
        receiver.summary()
    );

    for delivery in &deliveries {
        let trigger = delivery.header("x-ferriscd-trigger").unwrap_or_default();
        // The request target, verbatim: the receiver's path **and** its query string, because the
        // query token is the credential the log assertions below prove is never printed.
        let target = delivery
            .request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default();
        assert_eq!(
            target,
            format!("{RECEIVER_PATH}?token={URL_QUERY_TOKEN}"),
            "the destination URL's path and query are what was posted to: {}",
            delivery.request_line
        );
        // The signature is recomputed here from the raw bytes: this is the verification an operator
        // implements, not a comparison against FerrisCD's own implementation.
        let expected = format!(
            "sha256={}",
            hmac_sha256_hex(SIGNING_KEY.as_bytes(), delivery.body.as_bytes())
        );
        let signature = delivery
            .header("x-ferriscd-signature-256")
            .unwrap_or_default()
            .to_owned();
        assert_eq!(
            signature, expected,
            "the HMAC-SHA256 signature of the {trigger} delivery must verify"
        );
        assert!(
            !delivery.body.contains(SIGNING_KEY),
            "the signing key must never reach a payload: {}",
            delivery.body
        );
        assert!(
            delivery
                .header("x-ferriscd-delivery")
                .is_some_and(|key| !key.is_empty()),
            "the deduplication key travels with the delivery so a receiver can collapse repeats"
        );
        // The payload is the redacted status, not a raw diff or secret.
        let body: serde_json::Value = serde_json::from_str(&delivery.body).expect("a JSON body");
        assert_eq!(
            body["app"]["name"].as_str(),
            Some(APPLICATION_NAME),
            "{}",
            delivery.body
        );
    }

    // The controller's own logs never carry the key or the URL's query string. The child is
    // stopped first, so this is the **complete** log of the run and not a "so far" sample.
    drop(controller);
    let logs = std::fs::read_to_string(&log_path).expect("the controller log must be readable");
    assert!(
        logs.contains("event-driven notifications enabled"),
        "the log must actually contain the controller's notification startup line, otherwise the \
         secret assertion below is vacuous: {logs}"
    );
    assert!(
        !logs.contains(SIGNING_KEY),
        "the signing key must never reach the controller log: {logs}"
    );
    // The URL's query string is a credential-shaped part of the `Secret` and is redacted everywhere
    // the destination is printed, so the complete log must not contain it either.
    assert!(
        !logs.contains(URL_QUERY_TOKEN),
        "the destination URL's query string must never reach the controller log: {logs}"
    );

    // Finding P19-M3: the Git scratch root really is where `--work-root` pointed, and the default
    // `<system temp dir>/ferriscd-repos` was never created by this run.
    assert!(
        work_root.join("ferriscd-repos").is_dir(),
        "--work-root must be honoured (expected {} to exist)",
        work_root.join("ferriscd-repos").display()
    );
    assert!(
        !scratch_dir.path().join("ferriscd-repos").exists(),
        "a test run must not leave {} behind (that is the default the flag replaces)",
        scratch_dir.path().join("ferriscd-repos").display()
    );
}

// ---------------------------------------------------------------------------
// The negative control: each prerequisite is *required*
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a live kind cluster (make kind-up) and the openssl CLI"]
fn notifications_require_the_ca_file_and_the_private_cidr_allowlist() {
    // First statement, before even the context check: this test shares the control-plane namespace
    // with the test above, so it must never run at the same time as it.
    let _live = live_suite();
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "ABORT: refusing to touch non-kind cluster context {context:?}"
    );

    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    let _cluster_cleanup = ClusterCleanup::new(
        NEGATIVE_APPLICATION_NAME,
        NEGATIVE_CHANNEL_SECRET,
        NEGATIVE_TARGET_NAMESPACE,
    );

    // ------------------------------------------------------------------
    // The same receiver and channel shape as the positive test, under its
    // own names so the two tests cannot collide
    // ------------------------------------------------------------------
    let lan_ip = non_loopback_ipv4();
    let tls_dir = tempfile::tempdir().expect("create the TLS fixture directory");
    let tls = generate_tls_material(tls_dir.path(), lan_ip);
    let receiver = TlsReceiver::start(lan_ip, &tls);
    let channel_url = receiver_url(lan_ip, receiver.port());
    apply_channel_secret(NEGATIVE_CHANNEL_SECRET, &channel_url);

    // A fixture that *does* sync: the only trigger it can produce is `on-sync-succeeded`, so a
    // delivery failing here cannot be confused with a fixture that never got that far.
    let fixture = tempfile::tempdir().expect("create the git fixture directory");
    let repo = fixture.path().join("repo");
    write_healthy_fixture_and_commit(&repo);
    apply_application(
        NEGATIVE_APPLICATION_NAME,
        NEGATIVE_CHANNEL_SECRET,
        NEGATIVE_TARGET_NAMESPACE,
        &repo.display().to_string(),
    );

    // ------------------------------------------------------------------
    // Phase 1: everything but `--notifications-ca-file`
    // ------------------------------------------------------------------
    let mut without_ca = Phase::start(NotificationFlags {
        ca_pem: None,
        allow_private: Some(lan_ip),
        metrics_addr: "127.0.0.1:0",
    });
    // The trigger has to exist before "no delivery" means anything: `Synced` is what fires
    // `on-sync-succeeded` (the one trigger this control subscribes to), and this controller is the
    // only thing reconciling the fixture, so the status cannot appear without it.
    wait_until(
        NEGATIVE_APPLICATION_NAME,
        CONVERGENCE_DEADLINE,
        "the healthy fixture to report Synced (the trigger the control relies on)",
        || status_jsonpath(NEGATIVE_APPLICATION_NAME, "{.status.sync.status}") == "Synced",
    );
    let scraped = wait_for_a_failed_delivery(without_ca.metrics_addr);
    // Every series is pre-populated at `0` (a fixed label set), so "nothing was delivered" is a
    // sampled `0`, not an absent series.
    assert_eq!(
        prometheus_sample(&scraped, WEBHOOK_DELIVERED_SERIES).unwrap_or(0.0),
        0.0,
        "without the CA file nothing may be delivered, but a delivery was recorded as delivered: \
         {scraped}"
    );
    // The receiver was reached and the handshake was refused: this is *only* about trust, not about
    // reachability, and it is what makes the phase's `outcome="failed"` meaningful.
    assert!(
        receiver.connections() > 0,
        "without --notifications-ca-file the client must still reach the receiver (the CIDR is \
         allowlisted) and fail the TLS handshake; it never connected at all"
    );
    assert!(
        receiver.deliveries().is_empty(),
        "an unverifiable certificate must not produce a delivery: {:?}",
        receiver.summary()
    );
    let logs = without_ca.stop();
    assert!(
        logs.contains("event-driven notifications enabled"),
        "the log must contain the notifications startup line, otherwise the assertions below are \
         vacuous: {logs}"
    );
    assert!(
        logs.contains("the notification delivery failed"),
        "the CA-file-less run must fail in the transport (TLS), not before it: {logs}"
    );
    assert!(
        !logs.contains("refused by the SSRF egress guard"),
        "the destination is allowlisted, so the egress guard must not be what refused it: {logs}"
    );
    assert!(
        !logs.contains(URL_QUERY_TOKEN),
        "the destination URL's query string must never reach the controller log, not even on a \
         failed delivery: {logs}"
    );
    without_ca.assert_no_scratch_leftover();

    // ------------------------------------------------------------------
    // Phase 2: everything but `--notifications-allow-private-cidrs`
    // ------------------------------------------------------------------
    let before = receiver.connections();
    let mut without_allowlist = Phase::start(NotificationFlags {
        ca_pem: Some(&tls.ca_pem),
        allow_private: None,
        metrics_addr: "127.0.0.1:0",
    });
    let scraped = wait_for_a_failed_delivery(without_allowlist.metrics_addr);
    assert_eq!(
        prometheus_sample(&scraped, WEBHOOK_DELIVERED_SERIES).unwrap_or(0.0),
        0.0,
        "the SSRF guard must refuse this destination before it can be delivered: {scraped}"
    );
    // The guard runs *before* the connect: a trusted certificate for a private address that is not
    // allowlisted must never even open a socket to it.
    let after = receiver.connections();
    assert_eq!(
        after,
        before,
        "the SSRF guard must refuse a non-allowlisted private address before any connection is made \
         (the receiver accepted {} new connection(s))",
        after.saturating_sub(before)
    );
    assert!(
        receiver.deliveries().is_empty(),
        "a refused destination must not produce a delivery: {:?}",
        receiver.summary()
    );
    let logs = without_allowlist.stop();
    assert!(
        logs.contains("refused by the SSRF egress guard"),
        "the allowlist-less run must be refused by the egress guard: {logs}"
    );
    assert!(
        !logs.contains("the notification delivery failed"),
        "the CA file is configured, so the failure must be the egress guard and not the TLS \
         transport: {logs}"
    );
    assert!(
        !logs.contains(SIGNING_KEY),
        "the signing key must never reach the controller log: {logs}"
    );
    assert!(
        !logs.contains(URL_QUERY_TOKEN),
        "the destination URL's query string must never reach the controller log: {logs}"
    );
    without_allowlist.assert_no_scratch_leftover();
}

// ---------------------------------------------------------------------------
// The receiver: a one-thread HTTPS server with a private CA
// ---------------------------------------------------------------------------

/// One recorded request.
#[derive(Debug, Clone)]
struct Received {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Received {
    /// A header value, looked up case-insensitively (HTTP header names are case-insensitive).
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The PEM/DER material `openssl` produced for this test.
struct TlsMaterial {
    /// The CA certificate in PEM (what `--notifications-ca-file` receives).
    ca_pem: PathBuf,
    /// The leaf certificate in DER (what the in-test TLS server presents).
    server_der: PathBuf,
    /// The leaf private key in DER (PKCS#8).
    server_key_der: PathBuf,
}

/// An in-test HTTPS receiver: rustls over a blocking socket on the host's LAN address.
struct TlsReceiver {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    /// How many TCP connections were **accepted**, whether or not they produced a request.
    ///
    /// This is what separates "the client reached us and the TLS handshake was refused" (a missing
    /// CA file) from "the client never connected at all" (the SSRF guard refused the destination):
    /// both end in `outcome="failed"` and zero deliveries, so the counter is the only observable that
    /// tells the two negative-control phases apart.
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    address: Ipv4Addr,
}

impl TlsReceiver {
    /// Binds `ip:0` and serves HTTPS until the receiver is dropped.
    fn start(ip: Ipv4Addr, tls: &TlsMaterial) -> Self {
        ferriscd_controller::impersonation::ensure_crypto_provider();
        let listener = TcpListener::bind((ip, 0)).expect("the receiver must bind the LAN address");
        let port = listener
            .local_addr()
            .expect("the bound address is readable")
            .port();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    std::fs::read(&tls.server_der).expect("read the leaf certificate"),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        std::fs::read(&tls.server_key_der).expect("read the leaf key"),
                    ),
                ),
            )
            .expect("the TLS server configuration must build");
        let config = Arc::new(config);
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let recorded = received.clone();
        let stopping = stop.clone();
        let accepted = connections.clone();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = stream else { break };
                accepted.fetch_add(1, Ordering::Relaxed);
                record_one_connection(stream, &config, &recorded);
            }
        });
        Self {
            port,
            received,
            connections,
            stop,
            handle: Some(handle),
            address: ip,
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn deliveries(&self) -> Vec<Received> {
        self.received.lock().expect("receiver lock").clone()
    }

    /// How many TCP connections this receiver has accepted so far.
    fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    fn summary(&self) -> Vec<String> {
        self.deliveries()
            .iter()
            .map(|delivery| {
                delivery
                    .header("x-ferriscd-trigger")
                    .unwrap_or("<no trigger header>")
                    .to_owned()
            })
            .collect()
    }
}

impl Drop for TlsReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake the blocking `accept` so the thread can observe the flag and exit.
        let _ = TcpStream::connect((self.address, self.port));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Performs the TLS handshake, reads one HTTP request, records it, and answers `200 OK`.
fn record_one_connection(
    stream: TcpStream,
    config: &Arc<rustls::ServerConfig>,
    received: &Arc<Mutex<Vec<Received>>>,
) {
    // Bounded so a half-open connection can never wedge the receiver thread.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let connection = match rustls::ServerConnection::new(config.clone()) {
        Ok(connection) => connection,
        Err(err) => {
            eprintln!("notifications receiver: TLS setup failed: {err}");
            return;
        }
    };
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 2048];
    let header_end = loop {
        if let Some(position) = find_subslice(&buffer, b"\r\n\r\n") {
            break position;
        }
        // Capped, so an endless header block cannot grow this buffer without bound: the receiver is
        // a test fixture and must not be the thing that exhausts memory.
        if buffer.len() > MAX_HEADER_BYTES {
            eprintln!(
                "notifications receiver: request head exceeded {MAX_HEADER_BYTES} bytes; dropping \
                 the connection"
            );
            return;
        }
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0_usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        }
        headers.push((name, value));
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
        }
    }
    received.lock().expect("receiver lock").push(Received {
        request_line,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    let response = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
    let _ = tls.write_all(response.as_bytes());
    let _ = tls.flush();
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// HMAC-SHA256 (`RFC 2104`) over `message`, rendered as lowercase hex.
///
/// Implemented here from the workspace's SHA-256 primitive on purpose: the point of the assertion is
/// that an independent implementation of the published algorithm agrees with the header FerrisCD
/// sent, not that two copies of FerrisCD's own helper agree.
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_BYTES: usize = 64;
    let mut key_block = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        key_block[..32].copy_from_slice(&ferriscd_engine::diff::sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK_BYTES + message.len());
    inner.extend(key_block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let inner = ferriscd_engine::diff::sha256::digest(&inner);
    let mut outer = Vec::with_capacity(BLOCK_BYTES + inner.len());
    outer.extend(key_block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&inner);
    ferriscd_engine::diff::sha256::digest(&outer)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// TLS material (openssl)
// ---------------------------------------------------------------------------

/// Generates a throwaway CA and a leaf with an **IP SAN** for `ip`.
///
/// `openssl` is used instead of a Rust certificate crate because generating certificates is a
/// test-only concern and this workspace does not (and should not) depend on one.
///
/// The CA's extensions come from a **config file** (`-config`, `[v3_ca]`), not from `-addext`: the
/// flag only exists in OpenSSL 1.1.1+, while the `openssl` on a stock macOS (LibreSSL) does not know
/// it, and a live test that only runs on one TLS toolkit is a test nobody else can run.
fn generate_tls_material(dir: &Path, ip: Ipv4Addr) -> TlsMaterial {
    let ca_pem = dir.join("ca.pem");
    let ca_key = dir.join("ca.key");
    let ca_config = dir.join("ca.cnf");
    let server_key = dir.join("server.key");
    let server_csr = dir.join("server.csr");
    let server_pem = dir.join("server.pem");
    let server_der = dir.join("server.der");
    let server_key_der = dir.join("server-key.der");
    let extensions = dir.join("leaf-extensions.cnf");

    // `x509_extensions` is the OpenSSL / LibreSSL spelling for "the extensions of the certificate
    // `req -x509` self-signs". `prompt = no` + a DN section keeps the subject in one place instead of
    // splitting it between `-subj` and the file.
    std::fs::write(
        &ca_config,
        "[req]\n\
         default_md = sha256\n\
         prompt = no\n\
         distinguished_name = ca_distinguished_name\n\
         x509_extensions = v3_ca\n\
         \n\
         [ca_distinguished_name]\n\
         CN = ferriscd-t19-4-live-ca\n\
         \n\
         [v3_ca]\n\
         basicConstraints = critical,CA:TRUE\n\
         keyUsage = critical,keyCertSign,cRLSign\n\
         subjectKeyIdentifier = hash\n",
    )
    .expect("write the CA config file");
    openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &ca_key.display().to_string(),
            "-out",
            &ca_pem.display().to_string(),
            "-days",
            "2",
            "-config",
            &ca_config.display().to_string(),
        ],
    );
    openssl(
        dir,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &server_key.display().to_string(),
            "-out",
            &server_csr.display().to_string(),
            "-subj",
            &format!("/CN={ip}"),
        ],
    );
    std::fs::write(
        &extensions,
        format!(
            "basicConstraints=critical,CA:FALSE\n\
             keyUsage=critical,digitalSignature,keyEncipherment\n\
             extendedKeyUsage=serverAuth\n\
             subjectAltName=IP:{ip}\n"
        ),
    )
    .expect("write the leaf extension file");
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            &server_csr.display().to_string(),
            "-CA",
            &ca_pem.display().to_string(),
            "-CAkey",
            &ca_key.display().to_string(),
            "-CAcreateserial",
            "-out",
            &server_pem.display().to_string(),
            "-days",
            "2",
            "-extfile",
            &extensions.display().to_string(),
        ],
    );
    openssl(
        dir,
        &[
            "x509",
            "-in",
            &server_pem.display().to_string(),
            "-outform",
            "DER",
            "-out",
            &server_der.display().to_string(),
        ],
    );
    openssl(
        dir,
        &[
            "pkey",
            "-in",
            &server_key.display().to_string(),
            "-outform",
            "DER",
            "-out",
            &server_key_der.display().to_string(),
        ],
    );

    // The leaf really does carry the IP SAN, otherwise the whole test would only prove that an
    // untrusted certificate is refused.
    let printed = openssl_stdout(
        dir,
        &[
            "x509",
            "-in",
            &server_pem.display().to_string(),
            "-noout",
            "-ext",
            "subjectAltName",
        ],
    );
    assert!(
        printed.contains(&format!("IP Address:{ip}")),
        "the leaf certificate must carry an IP SAN for {ip}: {printed}"
    );

    TlsMaterial {
        ca_pem,
        server_der,
        server_key_der,
    }
}

fn openssl(dir: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("the openssl CLI must be installed (see the module docs)");
    assert!(
        output.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn openssl_stdout(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("the openssl CLI must be installed (see the module docs)");
    assert!(
        output.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// Metrics: the evidence that a delivery was attempted and failed
// ---------------------------------------------------------------------------

/// Waits for the controller's "metrics listener ready" line and returns the address it bound.
///
/// `--metrics-addr 127.0.0.1:0` means the kernel picks the port, so the log line is the only place
/// the real address exists. Bounded poll (the child needs a moment to get that far), never a fixed
/// sleep.
fn metrics_addr_from_log(log_path: &Path) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(logs) = std::fs::read_to_string(log_path)
            && let Some(addr) = parse_metrics_addr(&logs)
        {
            return addr;
        }
        assert!(
            Instant::now() < deadline,
            "the controller never logged a metrics listener address in {}; the child's last {} log \
             lines were:\n{}",
            log_path.display(),
            LOG_TAIL_LINES,
            log_tail(log_path, LOG_TAIL_LINES)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// How many lines of a child's log a failure message carries.
const LOG_TAIL_LINES: usize = 40;

/// The last `max_lines` lines of `path`, for a failure message that would otherwise only say
/// "timed out" — the reason (a flag the binary refused, a bind that failed) is in the child's log and
/// not in the assertion.
///
/// Best effort: an unreadable log becomes the message, never a second panic that hides the first.
fn log_tail(path: &Path, max_lines: usize) -> String {
    match std::fs::read_to_string(path) {
        Ok(logs) => {
            let lines: Vec<&str> = logs.lines().collect();
            let start = lines.len().saturating_sub(max_lines);
            if lines.is_empty() {
                "<the child logged nothing>".to_owned()
            } else {
                lines[start..].join("\n")
            }
        }
        Err(err) => format!("<the child's log is unreadable: {err}>"),
    }
}

/// The `addr=…` of the **listener** line, or `None` while it has not been logged yet.
///
/// The startup line carries `metrics_addr=Some("127.0.0.1:…)` (the flag as it was given, `:0` and
/// all), so the message is matched first and the address is taken from that line only.
fn parse_metrics_addr(logs: &str) -> Option<SocketAddr> {
    logs.lines()
        .map(strip_ansi)
        .filter(|line| line.contains("metrics listener ready"))
        .find_map(|line| {
            let addr = line.split("addr=").nth(1)?.split_whitespace().next()?;
            addr.parse().ok()
        })
}

/// Removes ANSI escape sequences (`ESC [ … final`) from an already-formatted log line.
///
/// The controller's default log format is `pretty`, which colours the field names; those sequences
/// sit between `addr` and `=`, so a log line cannot be searched for `addr=` until they are gone.
/// Plain (uncoloured) lines pass through unchanged.
fn strip_ansi(line: &str) -> String {
    let mut cleaned = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            cleaned.push(ch);
            continue;
        }
        // `ESC` `[` <parameter bytes> <final byte in `@`..=`~`>. The introducer itself is in that
        // range, so it is excluded explicitly.
        for next in chars.by_ref() {
            if next != '[' && ('@'..='~').contains(&next) {
                break;
            }
        }
    }
    cleaned
}

/// Scrapes `/metrics` over a plain `TcpStream` and returns the response body.
///
/// The listener is bound to loopback by the test itself, so a full HTTP client (and another
/// dependency) would buy nothing: the request is one line and the response is read to `EOF` because
/// the request asks for `connection: close`.
fn scrape_metrics(addr: SocketAddr) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n\r\n",
        path = ferriscd_controller::metrics::METRICS_PATH
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(match response.split_once("\r\n\r\n") {
        Some((_head, body)) => body.to_owned(),
        None => response,
    })
}

/// Polls `/metrics` until the webhook channel has a **failed** delivery recorded, and returns what
/// was scraped.
///
/// `outcome="failed"` is the metric-level proof that the controller really tried to deliver: without
/// it, "the receiver saw nothing" would also be satisfied by a controller that never reconciled.
fn wait_for_a_failed_delivery(addr: SocketAddr) -> String {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if let Ok(body) = scrape_metrics(addr)
            && prometheus_sample(&body, WEBHOOK_FAILED_SERIES).is_some_and(|count| count > 0.0)
        {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "no failed webhook delivery was recorded on {addr} within the budget"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// One sample of an **exact** Prometheus series, or `None` when the series was not encoded.
///
/// The line has to start with the full series (labels included) followed by a space, so a series
/// that merely shares a prefix cannot be mistaken for it.
fn prometheus_sample(encoded: &str, series: &str) -> Option<f64> {
    encoded.lines().find_map(|line| {
        let rest = line.strip_prefix(series)?;
        rest.strip_prefix(' ')?.trim().parse().ok()
    })
}

/// This host's non-loopback IPv4 address, discovered without a DNS lookup or an extra dependency.
///
/// `UdpSocket::connect` only selects a route (no packet is sent), and `local_addr` then reports the
/// interface address the kernel would use.
///
/// The address has to be **private** as well as non-loopback, and that is asserted rather than
/// assumed: the negative control's second phase proves "no `--notifications-allow-private-cidrs` ⇒
/// refused" by pointing the controller at this address *without* the allowlist, so a public address
/// would make the premise false (the guard would admit it and the phase would fail for a reason that
/// has nothing to do with the flag). See the module's # Prerequisites.
fn non_loopback_ipv4() -> Ipv4Addr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind a probe socket");
    socket
        .connect("192.0.2.1:9")
        .expect("a route to the documentation network is required to discover the LAN address");
    let address = match socket
        .local_addr()
        .expect("the probe socket has a local address")
        .ip()
    {
        IpAddr::V4(address) if !address.is_loopback() && !address.is_unspecified() => address,
        other => panic!(
            "the notification receiver needs a non-loopback IPv4 address on this host, got {other}"
        ),
    };
    assert!(
        requires_private_allowlist(address),
        "the notification receiver needs a **private** IPv4 address, but this host's route to the \
         outside picked {address}, which the egress guard admits without \
         --notifications-allow-private-cidrs. Phase 2 of the negative control proves that a \
         non-allowlisted address is refused, which is only true inside the ranges the guard gates: \
         10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 (an IPv6 ULA would be the same \
         case, but this receiver is IPv4-only). Put the host on a private network, or run the suite \
         where the LAN address is private, and re-run."
    );
    address
}

/// Whether the egress guard classifies `address` as private — i.e. reachable only through
/// `--notifications-allow-private-cidrs`.
///
/// The guard's own classifier is used instead of a local range list: the premise the live test
/// depends on is "the guard would demand the allowlist for this address", and only the guard's
/// answer makes that true by construction.
fn requires_private_allowlist(address: Ipv4Addr) -> bool {
    matches!(
        ferriscd_controller::notifications::ssrf::classify(IpAddr::V4(address)),
        Some(ferriscd_controller::notifications::ssrf::BlockReason::PrivateNetwork)
    )
}

// ---------------------------------------------------------------------------
// The controller process and the Kubernetes fixtures
// ---------------------------------------------------------------------------

/// The notification flags one controller run is started with.
///
/// A struct instead of a long argument list so the negative control below reads as "the same run,
/// minus exactly one prerequisite".
#[derive(Debug, Clone, Copy)]
struct NotificationFlags<'a> {
    /// The `--notifications-ca-file` value, or `None` to prove the CA is *required*.
    ca_pem: Option<&'a Path>,
    /// Whether the receiver's host address is allowlisted through
    /// `--notifications-allow-private-cidrs`, or `None` to prove the allowlist is *required*.
    allow_private: Option<Ipv4Addr>,
    /// The `--metrics-addr` to bind (`/metrics` is scraped by the negative control).
    metrics_addr: &'a str,
}

/// Runs `ferriscd controller` with the notification flags for the duration of the test.
struct ControllerProcess {
    child: Child,
}

impl ControllerProcess {
    fn start(
        flags: NotificationFlags<'_>,
        log_path: &Path,
        work_root: &Path,
        tmpdir: &Path,
    ) -> Self {
        let log = std::fs::File::create(log_path).expect("create the controller log");
        let stderr = log.try_clone().expect("clone the controller log handle");
        let mut command = Command::new(env!("CARGO_BIN_EXE_ferriscd"));
        command.args([
            "controller",
            "--namespace",
            CONTROL_NAMESPACE,
            // The fixture repository is local, which the production URL policy refuses.
            "--allow-local-repos",
            "--metrics-addr",
            flags.metrics_addr,
            "--enable-notifications",
            // Finding P19-M3: an explicit scratch root, so the run cannot leave
            // `<system temp dir>/ferriscd-repos` behind on the host.
            "--work-root",
        ]);
        command.arg(work_root);
        if let Some(lan_ip) = flags.allow_private {
            // The receiver is on this host's private LAN address: unlock exactly that /32.
            command.args([
                "--notifications-allow-private-cidrs",
                &format!("{lan_ip}/32"),
            ]);
        }
        if let Some(ca_pem) = flags.ca_pem {
            command.arg("--notifications-ca-file").arg(ca_pem);
        }
        let child = command
            .env("RUST_LOG", "info")
            // The child's own `TMPDIR`, so a regression to the default work root is observable
            // inside the test's temporary directory instead of on the developer's machine.
            .env("TMPDIR", tmpdir)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("the ferriscd binary must start");
        Self { child }
    }

    /// Kills and reaps the child.
    ///
    /// Explicit (as well as idempotent via `Drop`) because a negative-control phase has to stop the
    /// run before it can read the **complete** log, and because a killed child returns errors that
    /// must not be fatal here.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ControllerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One controller run of the negative control: the child, the address it really bound for
/// `/metrics`, and the scratch root its Git checkouts landed in.
///
/// A struct rather than a long argument list so a phase reads as "the positive test's run, minus
/// exactly one flag".
struct Phase {
    controller: Option<ControllerProcess>,
    log: PathBuf,
    metrics_addr: SocketAddr,
    /// The child's `TMPDIR` (finding P19-M3): the default scratch root would land inside it.
    scratch: tempfile::TempDir,
    /// The `--work-root` the child was given.
    work_root: PathBuf,
}

impl Phase {
    fn start(flags: NotificationFlags<'_>) -> Self {
        let scratch = tempfile::tempdir().expect("create the controller scratch directory");
        let log = scratch.path().join("controller.log");
        let work_root = scratch.path().join("work");
        let controller = ControllerProcess::start(flags, &log, &work_root, scratch.path());
        let metrics_addr = metrics_addr_from_log(&log);
        Self {
            controller: Some(controller),
            log,
            metrics_addr,
            scratch,
            work_root,
        }
    }

    /// Stops the child and returns the **complete** log of the run.
    fn stop(&mut self) -> String {
        if let Some(mut controller) = self.controller.take() {
            controller.stop();
        }
        std::fs::read_to_string(&self.log).expect("the controller log must be readable")
    }

    /// Finding P19-M3: the run's Git scratch root is the one `--work-root` named, and the default
    /// `<system temp dir>/ferriscd-repos` was never created inside the child's own `TMPDIR`.
    fn assert_no_scratch_leftover(&self) {
        assert!(
            self.work_root.join("ferriscd-repos").is_dir(),
            "--work-root must be honoured (expected {} to exist)",
            self.work_root.join("ferriscd-repos").display()
        );
        assert!(
            !self.scratch.path().join("ferriscd-repos").exists(),
            "a test run must not leave {} behind (that is the default the flag replaces)",
            self.scratch.path().join("ferriscd-repos").display()
        );
    }
}

/// Deletes one test's cluster objects, even when an assertion panics.
///
/// The names are per-test so the two `#[ignore]`d tests in this file cannot collide when `cargo
/// test -- --ignored` runs them on several threads.
struct ClusterCleanup {
    application: &'static str,
    secret: &'static str,
    target_namespace: &'static str,
}

impl ClusterCleanup {
    fn new(
        application: &'static str,
        secret: &'static str,
        target_namespace: &'static str,
    ) -> Self {
        Self {
            application,
            secret,
            target_namespace,
        }
    }
}

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        // The controller adds `ferriscd.io/finalizer` to an `Application` and the child process is
        // already gone by the time this runs (it is declared after this guard, so it drops first), so
        // a bare delete would block on the finalizer until the timeout and leave the object
        // `Terminating` for the next run. Strip it first, exactly like the other live suites.
        let _ = kubectl(&[
            "patch",
            "application",
            self.application,
            "-n",
            CONTROL_NAMESPACE,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":[]}}"#,
        ]);
        let _ = kubectl(&[
            "delete",
            "application",
            self.application,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
            "--timeout=60s",
        ]);
        let _ = kubectl(&[
            "delete",
            "secret",
            self.secret,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
        ]);
        // Blocking delete: a namespace left `Terminating` would race the next run's create.
        let _ = kubectl(&[
            "delete",
            "namespace",
            self.target_namespace,
            "--ignore-not-found=true",
            "--timeout=120s",
        ]);
    }
}

/// Wakes the reconcile loop with a real `spec` edit (`requeueAfterSeconds` `n -> n + 1`).
///
/// A repository commit is invisible to the `Application` watch, and the failed pass above is
/// terminal (`TERMINAL_DELAY` = 600 s), so without a spec edit the recovery would only be observed
/// ten minutes later. Bumping the requeue interval is the one spec change that cannot alter what the
/// pass does — it is a scheduling knob — so the only difference it can make is "reconcile now".
fn poke_reconcile(application: &str) {
    let current: u32 = status_jsonpath(application, "{.spec.requeueAfterSeconds}")
        .parse()
        .unwrap_or(2);
    let patch = format!(
        r#"{{"spec":{{"requeueAfterSeconds":{}}}}}"#,
        current.saturating_add(1).min(60)
    );
    let output = kubectl(&[
        "patch",
        "application",
        application,
        "-n",
        CONTROL_NAMESPACE,
        "--type=merge",
        "-p",
        &patch,
    ]);
    assert!(
        output.status.success(),
        "poking the Application to reconcile immediately failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The channel `Secret` — the only place a destination URL (and its HMAC key) may live.
fn apply_channel_secret(name: &str, url: &str) {
    let _ = kubectl(&[
        "delete",
        "secret",
        name,
        "-n",
        CONTROL_NAMESPACE,
        "--ignore-not-found=true",
    ]);
    let manifest = format!(
        "apiVersion: v1\n\
         kind: Secret\n\
         metadata:\n\
         \x20 name: {name}\n\
         \x20 namespace: {CONTROL_NAMESPACE}\n\
         \x20 labels:\n\
         \x20   ferriscd.io/secret-type: notifications\n\
         type: Opaque\n\
         stringData:\n\
         \x20 service: webhook\n\
         \x20 url: {url}\n\
         \x20 signingKey: {SIGNING_KEY}\n"
    );
    apply_manifest(&manifest);
}

/// The `Application`: opt-in through annotations only, fast requeue so recovery is quick.
fn apply_application(name: &str, secret: &str, target_namespace: &str, repo_path: &str) {
    let manifest = format!(
        "apiVersion: ferriscd.io/v1alpha1\n\
         kind: Application\n\
         metadata:\n\
         \x20 name: {name}\n\
         \x20 namespace: {CONTROL_NAMESPACE}\n\
         \x20 annotations:\n\
         \x20   notifications.ferriscd.io/subscribe.on-sync-succeeded.webhook: {secret}\n\
         \x20   notifications.ferriscd.io/subscribe.on-health-degraded.webhook: {secret}\n\
         spec:\n\
         \x20 project: default\n\
         \x20 source:\n\
         \x20   git:\n\
         \x20     repoURL: {repo_path}\n\
         \x20     targetRevision: main\n\
         \x20     path: .\n\
         \x20 destination:\n\
         \x20   cluster: in-cluster\n\
         \x20   namespace: {target_namespace}\n\
         \x20 syncPolicy:\n\
         \x20   automated:\n\
         \x20     prune: false\n\
         \x20     selfHeal: true\n\
         \x20 requeueAfterSeconds: 2\n"
    );
    apply_manifest(&manifest);
}

/// Commit 1: manifests the renderer refuses, so the first pass is `Ready=False`.
fn write_broken_fixture_and_commit(repo: &Path) {
    std::fs::write(
        repo.join("broken.yaml"),
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: [unclosed\n",
    )
    .expect("write the broken fixture");
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["add", "."]);
    git_commit(repo, "a manifest the renderer must refuse");
}

/// Commit 2: a valid bundle whose `Deployment` can never become available (health degrades).
fn write_bad_image_fixture_and_commit(repo: &Path) {
    std::fs::remove_file(repo.join("broken.yaml")).expect("remove the broken fixture");
    // The `Namespace` is part of the bundle: the controller applies it first
    // (`DeferredPendingNamespace`), so the `Deployment` in the same commit can land.
    std::fs::write(
        repo.join("namespace.yaml"),
        format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {TARGET_NAMESPACE}\n"),
    )
    .expect("write the namespace fixture");
    std::fs::write(
        repo.join("deployment.yaml"),
        format!(
            "apiVersion: apps/v1\n\
             kind: Deployment\n\
             metadata:\n\
             \x20 name: web\n\
             \x20 namespace: {TARGET_NAMESPACE}\n\
             spec:\n\
             \x20 replicas: 1\n\
             \x20 progressDeadlineSeconds: {PROGRESS_DEADLINE_SECONDS}\n\
             \x20 selector:\n\
             \x20   matchLabels:\n\
             \x20     app: web\n\
             \x20 template:\n\
             \x20   metadata:\n\
             \x20     labels:\n\
             \x20       app: web\n\
             \x20   spec:\n\
             \x20     containers:\n\
             \x20       - name: web\n\
             \x20         image: {BAD_IMAGE}\n"
        ),
    )
    .expect("write the deployment fixture");
    git(repo, &["add", "--all"]);
    git_commit(repo, "a deployment whose image cannot be pulled");
}

/// The negative control's only commit: a bundle the controller applies cleanly.
///
/// The `Application` reaches `Synced` (which is what fires `on-sync-succeeded`, the trigger the
/// control subscribes to) and its only object is a `ConfigMap`, so the workload cannot degrade: a
/// failed delivery in this test can therefore only be the delivery itself, never "a different event
/// fired".
fn write_healthy_fixture_and_commit(repo: &Path) {
    std::fs::create_dir_all(repo).expect("create the fixture repository");
    // The `Namespace` is part of the bundle: the controller applies it first
    // (`DeferredPendingNamespace`), so the `ConfigMap` in the same commit can land.
    std::fs::write(
        repo.join("namespace.yaml"),
        format!(
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {NEGATIVE_TARGET_NAMESPACE}\n"
        ),
    )
    .expect("write the namespace fixture");
    std::fs::write(
        repo.join("configmap.yaml"),
        format!(
            "apiVersion: v1\n\
             kind: ConfigMap\n\
             metadata:\n\
             \x20 name: healthy\n\
             \x20 namespace: {NEGATIVE_TARGET_NAMESPACE}\n\
             data:\n\
             \x20 key: value\n"
        ),
    )
    .expect("write the configmap fixture");
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["add", "."]);
    git_commit(repo, "a bundle the controller applies cleanly");
}

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git must run");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_commit(repo: &Path, message: &str) {
    git(
        repo,
        &[
            "-c",
            "user.name=FerrisCD Test",
            "-c",
            "user.email=ferriscd@example.com",
            "commit",
            "-m",
            message,
        ],
    );
}

fn install_crds() {
    let crds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/crds");
    let output = kubectl(&["apply", "-f", &crds.display().to_string()]);
    assert!(
        output.status.success(),
        "kubectl apply -f deploy/crds failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ensure_default_project() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/manifests/default-project.yaml");
    let output = kubectl(&["apply", "-f", &manifest.display().to_string()]);
    assert!(
        output.status.success(),
        "kubectl apply -f deploy/manifests/default-project.yaml failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ensure_namespace(namespace: &str) {
    let manifest = format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n");
    apply_manifest(&manifest);
}

fn apply_manifest(manifest: &str) {
    let output = kubectl_with_stdin(&["apply", "-f", "-"], manifest);
    assert!(
        output.status.success(),
        "applying a fixture manifest failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn current_kube_context() -> String {
    let output = kubectl(&["config", "current-context"]);
    assert!(
        output.status.success(),
        "kubectl config current-context failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn ready_status(application: &str) -> Option<String> {
    optional_jsonpath(
        application,
        "{.status.conditions[?(@.type==\"Ready\")].status}",
    )
}

fn health_status(application: &str) -> Option<String> {
    optional_jsonpath(application, "{.status.health.status}")
}

/// One `jsonpath` value of the fixture `Application`, or `None` when it is not there yet.
fn optional_jsonpath(application: &str, path: &str) -> Option<String> {
    let output = kubectl(&[
        "get",
        "application",
        application,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        &format!("jsonpath={path}"),
    ]);
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn status_jsonpath(application: &str, path: &str) -> String {
    optional_jsonpath(application, path).unwrap_or_default()
}

fn kubectl(args: &[&str]) -> Output {
    Command::new("kubectl")
        .args(args)
        .output()
        .expect("kubectl must run")
}

fn kubectl_with_stdin(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new("kubectl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kubectl must start");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())
        .expect("write the manifest to kubectl stdin");
    child.wait_with_output().expect("kubectl must finish")
}

/// Polls `condition` until it holds or `budget` elapses (bounded; never a fixed sleep as a
/// synchronisation primitive).
fn wait_until(application: &str, budget: Duration, what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + budget;
    loop {
        if condition() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for {what}; Application status was: {}",
            status_jsonpath(application, "{.status}")
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// How many deliveries carried `trigger` in their `X-FerrisCD-Trigger` header.
fn trigger_count(receiver: &TlsReceiver, trigger: &str) -> usize {
    receiver
        .deliveries()
        .iter()
        .filter(|delivery| delivery.header("x-ferriscd-trigger") == Some(trigger))
        .count()
}

// ---------------------------------------------------------------------------
// The parsers and invariants the two `#[ignore]`d tests above depend on
// ---------------------------------------------------------------------------

// These run in `make gate` (no cluster needed). They are the places where a live test could
// otherwise pass or fail for the wrong reason: a log line read with the wrong address, a metrics
// series matched too loosely, an address that does not make phase 2's premise true, and two live
// tests that run concurrently unless the process-global lock actually excludes.

#[test]
fn the_live_suite_guard_is_exclusive_across_threads() {
    // What the second live test hits while the first one holds the guard: it blocks instead of
    // running, whatever `--test-threads` says. `try_lock` from another thread is the non-blocking
    // proof of that (a blocking `lock` here would deadlock the test).
    let held = live_suite();
    let blocked = std::thread::spawn(|| LIVE_SUITE.try_lock().is_err())
        .join()
        .expect("the probe thread must not panic");
    assert!(
        blocked,
        "the live-suite lock must already be held by this test, otherwise the two live tests could \
         share the control-plane namespace"
    );
    drop(held);
    // And it is reusable once released, which is what lets the second live test run at all.
    drop(acquire(&LIVE_SUITE));
}

#[test]
fn a_poisoned_live_suite_lock_still_lets_the_other_test_run() {
    // A leaked, locally-poisoned mutex has the same shape as `LIVE_SUITE` and proves the same
    // recovery, without poisoning the real lock for the rest of the process.
    let poisoned: &'static Mutex<()> = Box::leak(Box::new(Mutex::new(())));
    let _ = std::thread::spawn(move || {
        let _guard = poisoned.lock().expect("acquired before the panic");
        panic!("intentional: the poisoning proof");
    })
    .join();
    assert!(
        poisoned.lock().is_err(),
        "the probe thread must have left the mutex poisoned"
    );
    // A live test that already panicked must not turn the other live test into a `PoisonError`
    // failure: it takes the lock, recovers, and reports its own result.
    drop(acquire(poisoned));
}

#[test]
fn the_receiver_address_predicate_matches_the_ranges_the_guard_gates() {
    // The ranges phase 2 of the negative control depends on: private addresses are refused without
    // `--notifications-allow-private-cidrs`, so an allowlisted run needs the flag.
    for private in [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(172, 31, 255, 254),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 127, 255, 254),
    ] {
        assert!(
            requires_private_allowlist(private),
            "{private} is gated behind --notifications-allow-private-cidrs"
        );
    }
    // A public address is *not* refused for being private, which is exactly why the live test cannot
    // use one: phase 2 would then fail for a reason unrelated to the missing allowlist.
    for public in [
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(172, 32, 0, 1),
        Ipv4Addr::new(100, 128, 0, 1),
    ] {
        assert!(
            !requires_private_allowlist(public),
            "{public} is a public address: it cannot make \"no allowlist ⇒ refused\" true"
        );
    }
}

#[test]
fn the_log_tail_is_bounded_and_names_an_empty_or_missing_log() {
    let dir = tempfile::tempdir().expect("create the log-tail directory");
    let path = dir.path().join("controller.log");
    std::fs::write(&path, "one\ntwo\nthree\nfour\n").expect("write the log fixture");
    assert_eq!(log_tail(&path, 2), "three\nfour");
    assert_eq!(
        log_tail(&path, 99),
        "one\ntwo\nthree\nfour",
        "a tail larger than the log is the whole log, never a panic"
    );
    std::fs::write(&path, "").expect("truncate the log fixture");
    assert_eq!(log_tail(&path, 5), "<the child logged nothing>");
    let missing = dir.path().join("absent.log");
    assert!(
        log_tail(&missing, 5).starts_with("<the child's log is unreadable:"),
        "a missing log must not panic inside the failure message that reports it"
    );
}

#[test]
fn the_metrics_address_parser_reads_the_listener_line_and_survives_ansi_colour() {
    // Byte-for-byte the shape the controller writes: `pretty` format, ANSI-coloured field names, and
    // a startup line *before* it whose `metrics_addr=Some("127.0.0.1:1")` is the flag, not the port
    // the kernel picked.
    let startup = "\u{1b}[2m2026-11-28T02:46:51.484600Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \
                   \u{1b}[2mferriscd_controller\u{1b}[0m\u{1b}[2m:\u{1b}[0m ferriscd-controller \
                   starting \u{1b}[3mmetrics_addr\u{1b}[0m\u{1b}[2m=\u{1b}[0mSome(\"127.0.0.1:1\")";
    let listener = "\u{1b}[2m2026-11-28T02:46:51.509517Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \
                    \u{1b}[2mferriscd_controller::metrics\u{1b}[0m\u{1b}[2m:\u{1b}[0m metrics \
                    listener ready (low-cardinality Prometheus exposition on its own port) \
                    \u{1b}[3maddr\u{1b}[0m\u{1b}[2m=\u{1b}[0m127.0.0.1:61733 \
                    \u{1b}[3mpath\u{1b}[0m\u{1b}[2m=\u{1b}[0m\"/metrics\"";
    let logs = format!("{startup}\n{listener}\n");
    assert_eq!(
        parse_metrics_addr(&logs),
        Some(SocketAddr::from(([127, 0, 0, 1], 61733))),
        "the listener's real port must be read, not the `:0` the flag was given, and ANSI colour \
         must not hide the field"
    );

    // The same line once the listener has not been logged yet: the address must not be invented from
    // the startup flag (that would send every scrape to port `1`).
    assert_eq!(parse_metrics_addr(&format!("{startup}\n")), None);
    assert_eq!(parse_metrics_addr(""), None);
    // Plain, uncoloured logs parse too.
    assert_eq!(
        parse_metrics_addr(
            "INFO ferriscd_controller::metrics: metrics listener ready (x) addr=10.0.0.7:9090 path=\"/metrics\""
        ),
        Some(SocketAddr::from(([10, 0, 0, 7], 9090)))
    );
}

#[test]
fn the_prometheus_parser_requires_the_whole_series() {
    let encoded = "\
# HELP ferriscd_notifications_total Notifications by service and outcome
# TYPE ferriscd_notifications_total counter
ferriscd_notifications_total{service=\"webhook\",outcome=\"failed\"} 3
ferriscd_notifications_total{service=\"webhook\",outcome=\"delivered\"} 0
ferriscd_notifications_total{service=\"slack\",outcome=\"failed\"} 7
";
    assert_eq!(prometheus_sample(encoded, WEBHOOK_FAILED_SERIES), Some(3.0));
    assert_eq!(
        prometheus_sample(encoded, WEBHOOK_DELIVERED_SERIES),
        Some(0.0)
    );
    assert_eq!(
        prometheus_sample(
            encoded,
            r#"ferriscd_notifications_total{service="webhook"}"#
        ),
        None,
        "a series with fewer labels must not match a longer one"
    );
    assert_eq!(
        prometheus_sample(encoded, r#"ferriscd_notifications_total"#),
        None,
        "the bare metric name must not match any labelled series"
    );
}

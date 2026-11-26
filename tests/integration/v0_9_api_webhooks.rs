//! Live `v0.9` control-plane API test: a signed GitHub push webhook really wakes the controller and
//! the `Application` syncs the new commit (`T14.2` verification bullet: "live `kind` test proving
//! push webhook triggers reconcile").
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. The test starts by asserting that
//! `kubectl config current-context` begins with `kind-` (the same guard `make test-integration`
//! applies) and is marked `#[ignore]`, so `cargo test` never runs it accidentally. Invoke it with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-server --test v0_9_api_webhooks -- --ignored --test-threads=1
//! ```
//!
//! # Shape of the test
//!
//! The test body is synchronous and owns a Tokio runtime explicitly: the `kubectl`/`git` shell-outs
//! and the bounded polling are plain blocking calls on the *test* thread, while the controller loop
//! and the API listener are tasks on the runtime, which keeps running between `block_on` calls. No
//! blocking call therefore sits on an async worker.
//!
//! # What this pins (and what the hermetic tests cannot)
//!
//! The in-process suite (`crates/ferriscd-server/tests/api.rs`) already proves the HMAC check, the
//! delivery-id replay cache, the 1 MiB cap and the per-repository debounce against a fake sink. What
//! it cannot prove is that the **production wiring** turns a delivery into a reconcile: this test
//! runs the real [`ferriscd_controller::ControlPlane`] (real `RepoCache`, renderer, `ClusterManager`,
//! `DiscoveryCache`, SSA applier and status writer) with the real `axum` listener in front of it,
//! posts an `X-Hub-Signature-256`-signed `push` event carrying `X-GitHub-Delivery` over a real
//! socket, and asserts:
//!
//! 1. the delivery is `accepted` with `matched: 1`;
//! 2. `ferriscd.io/refresh` is written on the `Application` (the real `ApiRefreshSink` patches the
//!    real object) inside the webhook budget;
//! 3. `status.sync.lastSyncedRevision` moves from the first commit to the pushed one, and the
//!    `ConfigMap` really contains the pushed value — with `spec.requeueAfterSeconds: 600`, so **the
//!    webhook is the only thing that could have done it** (a periodic requeue cannot be mistaken for
//!    the push).
//!
//! # What is deliberately *not* asserted, and why
//!
//! * **GitHub's own signature.** The delivery is signed by this test with the shared secret, using
//!   the same RFC 2104 HMAC-SHA256 the handler verifies (`ferriscd_server::webhooks::hmac_sha256`),
//!   so the handler's verification is exercised end to end. Whether *GitHub* computes that header is
//!   not observable from a local cluster: it would need a public endpoint and a GitHub App, which no
//!   suite in this repository can own. The hermetic suite covers the negative cases (a tampered
//!   body, another key, a replayed delivery id) instead.
//! * **"`< 2 s`" end to end.** The roadmap's `T14.2` bullet says `<2s`, which is the *webhook budget*
//!   — the 2 s per-repository debounce FerrisCD controls. The observable end-to-end time also
//!   contains a `git` fetch of the pushed commit, a render, an SSA apply and a `/status` patch, which
//!   depend on the machine and on `kind`'s API server. So the assertions are bounded budgets
//!   ([`REFRESH_BUDGET`] for the annotation, [`SYNC_BUDGET`] for the new revision) and the measured
//!   latency is printed, instead of a hard-coded two seconds that would be flaky on a laptop while
//!   testing `kind` rather than FerrisCD.
//!
//! Every wait is a bounded poll on real elapsed time, never a fixed sleep: a slow machine still
//! passes and a broken webhook path fails loudly instead of hanging.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target and never
// ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use ferriscd_controller::RunOptions;
use ferriscd_server::AuthPolicy;
use ferriscd_server::webhooks::{self, WebhookConfig, WebhookSecret};

/// Control-plane namespace the controller watches.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// `Application` name.
const APPLICATION_NAME: &str = "api-webhook";
/// Namespace the `Application` deploys into.
const TARGET_NAMESPACE: &str = "ferriscd-api-webhook";
/// The GitHub HMAC secret the API server is configured with (and the test signs with).
const WEBHOOK_SECRET: &str = "live-t14-2-webhook-secret";
/// Per-repository debounce the API server is started with (the production default).
const DEBOUNCE: Duration = Duration::from_secs(2);
/// Budget for `ferriscd.io/refresh` to appear after the delivery was accepted.
///
/// The delivery is `accepted` immediately; the debounce window (`DEBOUNCE`) then closes and the
/// fan-out patches the annotation, with at most `DEFAULT_MAX_JITTER` (500 ms) of jitter. The budget
/// is deliberately far above that: the assertion is "the debounce happened, it was not minutes", and
/// a tight bound would only measure the CI machine.
const REFRESH_BUDGET: Duration = Duration::from_secs(30);
/// Budget for the pushed commit to reach `status.sync.lastSyncedRevision`.
///
/// A full pass over a local fixture repository: `git` fetch, render, SSA apply, `/status` patch.
const SYNC_BUDGET: Duration = Duration::from_secs(180);

/// `T14.2`: a signed GitHub push syncs the pushed commit, with no periodic requeue to hide behind.
#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn a_signed_github_push_syncs_the_pushed_commit() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_namespace(TARGET_NAMESPACE);
    ensure_default_project();
    let _cluster_cleanup = ClusterCleanup;

    // --- the fixture repository --------------------------------------------------------------
    let fixture = tempfile::tempdir().expect("create the git fixture directory");
    let repo = fixture.path().to_path_buf();
    write(&repo, "configmap.yaml", &configmap("v1"));
    git_init(&repo);
    let first_commit = git_head(&repo);

    // --- the real control plane + the real API listener ---------------------------------------
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a Tokio runtime");
    let (addr, stop, api, controller) = runtime.block_on(async {
        // `prepare` is the same constructor `ferriscd server` uses: one client, one `RepoCache`, one
        // renderer cache, one `ClusterManager`, one pipeline, shared by the reconcile loop and the
        // API (finding C9).
        let options = RunOptions {
            namespace: Some(CONTROL_NAMESPACE.to_owned()),
            // The fixture is a local path, which the production URL policy rejects.
            allow_local_repos: true,
            ..RunOptions::default()
        };
        let plane = ferriscd_controller::prepare(options)
            .await
            .expect("the control plane must start against the kind cluster");
        let state = ferriscd_server::kube::app_state(&plane, webhook_config())
            .with_auth(AuthPolicy::PassThrough);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("the bound address");
        let stop = tokio_util::sync::CancellationToken::new();
        let api_stop = stop.clone();
        let api = tokio::spawn(async move {
            ferriscd_server::serve_listener(listener, state, api_stop.cancelled_owned()).await
        });
        let controller_stop = stop.clone();
        let controller = tokio::spawn(async move { plane.run_until(controller_stop).await });
        (addr, stop, api, controller)
    });

    // --- the Application ----------------------------------------------------------------------
    apply_application(&repo);
    assert!(
        wait_until(Duration::from_secs(120), "the first commit to sync", || {
            status_jsonpath("{.status.sync.lastSyncedRevision}") == first_commit
        }),
        "the first commit never reached status.sync.lastSyncedRevision: {}",
        status_jsonpath("{.status}")
    );

    // --- push a new commit, then deliver the webhook ------------------------------------------
    write(&repo, "configmap.yaml", &configmap("v2"));
    git_commit(&repo, "second commit");
    let pushed = git_head(&repo);
    assert_ne!(
        pushed, first_commit,
        "the fixture must produce a new commit for the webhook to pick up"
    );
    // Nothing but a webhook may reconcile inside `SYNC_BUDGET`: a short periodic requeue would make
    // this test vacuously green.
    assert_eq!(
        status_jsonpath("{.spec.requeueAfterSeconds}"),
        "600",
        "a short requeue would make this test vacuous"
    );

    let delivered = Instant::now();
    let body = push_body(&repo);
    let headers = [
        (
            webhooks::GITHUB_SIGNATURE_HEADER,
            github_signature(WEBHOOK_SECRET, &body),
        ),
        (
            webhooks::GITHUB_DELIVERY_HEADER,
            format!("live-delivery-{:x}", std::process::id()),
        ),
        (webhooks::GITHUB_EVENT_HEADER, "push".to_owned()),
        ("content-type", "application/json".to_owned()),
    ];
    let (status, response) = runtime.block_on(post_webhook(
        addr,
        "/api/v1/webhooks/github",
        &headers,
        &body,
    ));
    assert_eq!(status, 200, "the delivery was refused: {response}");
    assert!(
        response.contains("\"accepted\""),
        "the delivery was not accepted: {response}"
    );
    assert!(
        response.contains("\"matched\":1"),
        "the push must match the Application: {response}"
    );

    // 1. The real `ApiRefreshSink` writes `ferriscd.io/refresh` on the real object.
    assert!(
        wait_until(REFRESH_BUDGET, "ferriscd.io/refresh", || {
            !status_jsonpath("{.metadata.annotations.ferriscd\\.io/refresh}").is_empty()
        }),
        "no ferriscd.io/refresh annotation appeared after the delivery: {}",
        status_jsonpath("{.metadata.annotations}")
    );
    let refreshed_after = delivered.elapsed();
    println!("ferriscd.io/refresh appeared {refreshed_after:?} after the delivery");

    // 2. The pushed commit reaches `/status` — the reconcile the webhook asked for.
    assert!(
        wait_until(SYNC_BUDGET, "the pushed commit to sync", || {
            status_jsonpath("{.status.sync.lastSyncedRevision}") == pushed
        }),
        "the pushed commit {pushed} never synced; status was: {}",
        status_jsonpath("{.status}")
    );
    let synced_after = delivered.elapsed();
    println!(
        "status.sync.lastSyncedRevision moved to {pushed} {synced_after:?} after the delivery"
    );
    assert!(
        refreshed_after <= REFRESH_BUDGET,
        "the refresh annotation took {refreshed_after:?}, beyond the {REFRESH_BUDGET:?} budget"
    );
    assert_eq!(
        status_jsonpath("{.status.sync.revision}"),
        pushed,
        "status.sync.revision must be the pushed commit: {}",
        status_jsonpath("{.status.sync}")
    );

    // 3. The sync really deployed the pushed manifest, not just the revision marker.
    assert!(
        wait_until(Duration::from_secs(60), "the ConfigMap to carry v2", || {
            configmap_version().as_deref() == Some("v2")
        }),
        "the ConfigMap did not reach v2: {:?}",
        kubectl_jsonpath(&[
            "get",
            "configmap",
            "settings",
            "-n",
            TARGET_NAMESPACE,
            "-o",
            "jsonpath={.data}",
        ])
    );

    // --- shutdown: one decision drains both halves --------------------------------------------
    stop.cancel();
    let (served, reconciled) = runtime.block_on(async {
        (
            api.await.expect("the API task must not panic"),
            controller
                .await
                .expect("the controller task must not panic"),
        )
    });
    served.expect("the API server must stop cleanly");
    reconciled.expect("the controller must stop cleanly");
}

/// Deletes what the test created, so a second run starts from its own state.
struct ClusterCleanup;

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        let _ = kubectl(&[
            "delete",
            "application",
            APPLICATION_NAME,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
            "--wait=false",
        ]);
        let _ = kubectl(&[
            "patch",
            "application",
            APPLICATION_NAME,
            "-n",
            CONTROL_NAMESPACE,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":null}}"#,
        ]);
        let _ = kubectl(&[
            "delete",
            "namespace",
            TARGET_NAMESPACE,
            "--ignore-not-found=true",
            // Blocking delete: a namespace left `Terminating` races the next run (`Forbidden`).
            "--timeout=120s",
        ]);
    }
}

// ---------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------

fn configmap(version: &str) -> String {
    format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  version: {version}\n"
    )
}

/// The pushed `ConfigMap`'s value, as the destination cluster has it.
fn configmap_version() -> Option<String> {
    kubectl_jsonpath(&[
        "get",
        "configmap",
        "settings",
        "-n",
        TARGET_NAMESPACE,
        "-o",
        "jsonpath={.data.version}",
    ])
}

fn write(root: &Path, name: &str, contents: &str) {
    std::fs::write(root.join(name), contents)
        .unwrap_or_else(|error| panic!("write {name}: {error}"));
}

fn git_init(cwd: &Path) {
    git(cwd, &["init", "--initial-branch=main"]);
    git_commit(cwd, "seed manifests");
}

fn git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git must run");
    assert!(
        output.status.success(),
        "git {args:?} failed (cwd={}): stdout={}, stderr={}",
        cwd.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_commit(cwd: &Path, message: &str) {
    git(cwd, &["add", "--all"]);
    git(
        cwd,
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

/// The full SHA `HEAD` points at, which is what `status.sync.revision` records.
fn git_head(cwd: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .output()
        .expect("git must run");
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// The GitHub `push` payload, with the fixture path as the repository URL.
///
/// The controller clones a local path here (`--allow-local-repos`), so the repository *identity* it
/// computes is that path; the payload reports the same path, which is what makes the delivery match.
/// `default_branch: main` is what the `Application`'s `targetRevision: main` tracks.
fn push_body(repo: &Path) -> Vec<u8> {
    let url = repo.display().to_string();
    serde_json::json!({
        "ref": "refs/heads/main",
        "after": "0000000000000000000000000000000000000000",
        "repository": {
            "html_url": url,
            "clone_url": url,
            "ssh_url": url,
            "git_url": url,
            "default_branch": "main",
        },
    })
    .to_string()
    .into_bytes()
}

fn github_signature(secret: &str, body: &[u8]) -> String {
    let digest = webhooks::hmac_sha256(secret.as_bytes(), body);
    let mut signature = String::from("sha256=");
    for byte in digest {
        signature.push_str(&format!("{byte:02x}"));
    }
    signature
}

fn webhook_config() -> WebhookConfig {
    WebhookConfig {
        github_secret: Some(WebhookSecret::new(WEBHOOK_SECRET).expect("a non-empty secret")),
        debounce: DEBOUNCE,
        ..WebhookConfig::default()
    }
}

/// A minimal HTTP/1.1 POST, so the test needs no HTTP client dependency.
async fn post_webhook(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the API listener accepts connections");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the request headers");
    stream
        .write_all(body)
        .await
        .expect("write the request body");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read the response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .expect("a status line");
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

// ---------------------------------------------------------------------
// kubectl helpers
// ---------------------------------------------------------------------

fn current_kube_context() -> String {
    let output = Command::new("kubectl")
        .args(["config", "current-context"])
        .output()
        .expect("kubectl config current-context must run");
    assert!(
        output.status.success(),
        "kubectl config current-context failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn kubectl(args: &[&str]) -> Output {
    Command::new("kubectl")
        .args(args)
        .output()
        .expect("kubectl must run")
}

fn kubectl_stdin(args: &[&str], stdin: &str) -> Output {
    use std::io::Write as _;

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
        .expect("write the manifest to kubectl's stdin");
    child.wait_with_output().expect("kubectl must finish")
}

/// Installs the committed `Application` CRD (idempotent).
fn install_crds() {
    let crds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/crds");
    let output = kubectl(&["apply", "-f", &crds.display().to_string()]);
    assert!(
        output.status.success(),
        "kubectl apply -f deploy/crds failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies the shipped `default` `AppProject` (a missing project is a terminal denial).
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
    let output = kubectl_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "creating namespace {namespace} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies the `Application`, with a requeue long enough that only the webhook can sync inside the
/// test's budget.
fn apply_application(repo: &Path) {
    let manifest = format!(
        "apiVersion: ferriscd.io/v1alpha1\n\
         kind: Application\n\
         metadata:\n\
         \x20 name: {APPLICATION_NAME}\n\
         \x20 namespace: {CONTROL_NAMESPACE}\n\
         spec:\n\
         \x20 source:\n\
         \x20   git:\n\
         \x20     repoURL: {}\n\
         \x20     targetRevision: main\n\
         \x20     path: .\n\
         \x20 destination:\n\
         \x20   cluster: in-cluster\n\
         \x20   namespace: {TARGET_NAMESPACE}\n\
         \x20 syncPolicy:\n\
         \x20   automated:\n\
         \x20     prune: false\n\
         \x20     selfHeal: true\n\
         \x20 requeueAfterSeconds: 600\n",
        repo.display()
    );
    let output = kubectl_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "applying the Application failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn status_jsonpath(template: &str) -> String {
    let output = kubectl(&[
        "get",
        "application",
        APPLICATION_NAME,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        &format!("jsonpath={template}"),
    ]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Runs `kubectl` and returns its trimmed stdout, or `None` on failure or an empty value.
fn kubectl_jsonpath(args: &[&str]) -> Option<String> {
    let output = kubectl(args);
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
}

/// Polls `condition` until it holds or `budget` elapses; `false` on timeout.
///
/// Blocking on purpose: the caller is the test thread (see "Shape of the test"), so the runtime's
/// workers keep driving the controller and the listener while we poll.
fn wait_until(budget: Duration, what: &str, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            eprintln!("timed out after {budget:?} waiting for {what}");
            return false;
        }
        sleep(Duration::from_secs(1));
    }
}

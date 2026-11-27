//! Live `v1.1` control-plane test: watch-backed `/readyz`, live `ferriscd-rbac-cm` hot-reload
//! (`<= 2 s` without pod restart), malformed-update retention, and fail-closed deletion (`T17.1`).
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. It asserts that `kubectl config
//! current-context` begins with `kind-` before doing anything, and it is `#[ignore]`d so `cargo test`
//! never runs it. Invoke it with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v1_1_readiness_rbac -- --ignored --test-threads=1
//! ```
//!
//! Every wait is a bounded poll, never a fixed sleep, and the child process is killed on every exit
//! path (a `Drop` guard), so a failing assertion cannot leak a server.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target and never
// ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Dedicated scratch namespace hosting the test's `ServiceAccount`, `AppProject`, `Application`,
/// and `ferriscd-rbac-cm` so `ferriscd-system` is never modified.
const NAMESPACE: &str = "ferriscd-rbac-reload-e2e";
const SERVICE_ACCOUNT: &str = "rbac-reload-e2e";
const PROJECT: &str = "payments";
const APPLICATION: &str = "payments-api";

/// How long `ferriscd server` may take to reach `/readyz == 200` on startup.
const STARTUP_BUDGET: Duration = Duration::from_secs(120);
/// `T17.1` SLA: live edits and deletions of `ferriscd-rbac-cm` must take effect in `<= 2 s`.
const LIVE_RELOAD_SLA: Duration = Duration::from_secs(2);

/// `T17.1`: `/readyz` flips to `200` after startup `InitDone`, live `ferriscd-rbac-cm` edits apply
/// in `<= 2 s` without restarting `ferriscd server`, malformed edits retain last known-good, and
/// deleting `ferriscd-rbac-cm` fails closed in `<= 2 s`.
#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn readyz_and_live_rbac_reload_work_end_to_end() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    install_crds();
    create_namespace();
    let _cleanup = ClusterCleanup;

    create_service_account();
    apply_rbac_policy(&format!(
        r#"rules:
  - subject:
      kind: group
      name: system:serviceaccounts:{NAMESPACE}
    project: {PROJECT}
    actions: [get, diff]
"#
    ));
    create_project_and_application();
    let token = mint_token();
    assert!(!token.trim().is_empty(), "kubectl must mint a token");

    let address = free_address();
    let metrics_address = free_address();
    let mut server = ServerProcess::start(address, metrics_address);

    // --- 1. /readyz flips 503 -> 200 once all three startup gates complete ----------------------
    let ready_body = wait_for_ready(address);
    assert!(
        ready_body.contains(r#""status":"ready""#),
        "expected ready payload, got: {ready_body}"
    );

    let app_path = format!("/api/v1/applications/{NAMESPACE}/{APPLICATION}");
    let sync_path = format!("{app_path}/sync");

    // Initial read-only policy: GET is 200, POST .../sync is 403.
    let (get_status, _) = http_request(address, "GET", &app_path, Some(token.trim()), None)
        .expect("GET application must complete");
    assert_eq!(get_status, 200, "read-only identity must read the app");

    let (sync_status, _) =
        http_request(address, "POST", &sync_path, Some(token.trim()), Some("{}"))
            .expect("POST sync must complete");
    assert_eq!(sync_status, 403, "read-only identity must be denied sync");

    // --- 2. Live RBAC grant takes effect in <= 2 s without restarting the server ----------------
    apply_rbac_policy(&format!(
        r#"rules:
  - subject:
      kind: group
      name: system:serviceaccounts:{NAMESPACE}
    project: {PROJECT}
    actions: [get, diff, sync]
"#
    ));
    let reload_start = Instant::now();
    let mut granted = false;
    while reload_start.elapsed() <= LIVE_RELOAD_SLA {
        if let Some((202, _)) =
            http_request(address, "POST", &sync_path, Some(token.trim()), Some("{}"))
        {
            granted = true;
            break;
        }
        sleep(Duration::from_millis(50));
    }
    assert!(
        granted,
        "live ferriscd-rbac-cm grant did not flip POST .../sync from 403 to 202 within {LIVE_RELOAD_SLA:?}"
    );

    // --- 3. Malformed RBAC update retains last known-good policy --------------------------------
    apply_rbac_policy("rules: [unterminated");
    // Wait for the watch to *observe and reject* the malformed update (outcome="error" metric)
    // instead of sleeping: only then does the retained grant prove the fail-safe path ran.
    let rejection_deadline = Instant::now() + Duration::from_secs(10);
    let mut rejection_observed = false;
    while Instant::now() < rejection_deadline {
        if rbac_reload_errors(metrics_address) >= 1 {
            rejection_observed = true;
            break;
        }
        sleep(Duration::from_millis(50));
    }
    assert!(
        rejection_observed,
        "the malformed update was never rejected (ferriscd_rbac_reload_total{{outcome=\"error\"}} stayed 0)"
    );
    let (retained_status, _) = http_request(address, "GET", &app_path, Some(token.trim()), None)
        .expect("GET after malformed update must complete");
    assert_eq!(
        retained_status, 200,
        "malformed RBAC update must retain last known-good policy"
    );

    // --- 4. Deleting ferriscd-rbac-cm fails closed (404 existence-hiding deny) in <= 2 s --------
    kubectl(&["-n", NAMESPACE, "delete", "configmap", "ferriscd-rbac-cm"]);
    let delete_start = Instant::now();
    let mut failed_closed = false;
    while delete_start.elapsed() <= LIVE_RELOAD_SLA {
        if let Some((404, _)) = http_request(address, "GET", &app_path, Some(token.trim()), None) {
            failed_closed = true;
            break;
        }
        sleep(Duration::from_millis(50));
    }
    assert!(
        failed_closed,
        "deleting ferriscd-rbac-cm did not fail closed (404) within {LIVE_RELOAD_SLA:?}"
    );

    server.stop();
}

// ---------------------------------------------------------------------------
// Server child process & raw HTTP helpers
// ---------------------------------------------------------------------------

struct ServerProcess {
    child: Child,
}

impl ServerProcess {
    fn start(address: SocketAddr, metrics_address: SocketAddr) -> Self {
        let binary = env!("CARGO_BIN_EXE_ferriscd");
        let child = Command::new(binary)
            .args([
                "server",
                "--api-addr",
                &address.to_string(),
                "--metrics-addr",
                &metrics_address.to_string(),
                "--namespace",
                NAMESPACE,
                "--auth-policy",
                "token-review",
                "--github-webhook-secret",
                "rbac-reload-e2e-secret",
                "--webhook-debounce-seconds",
                "0",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the ferriscd binary must start");
        Self { child }
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("an address");
    drop(listener);
    address
}

fn wait_for_ready(address: SocketAddr) -> String {
    let deadline = Instant::now() + STARTUP_BUDGET;
    let mut first_response = true;
    while Instant::now() < deadline {
        if let Some((status, body)) = http_request(address, "GET", "/readyz", None, None) {
            // The spec requires proof of the `503` phase, not only the final `200`.
            if first_response {
                assert_eq!(
                    status, 503,
                    "the first /readyz response must be 503 before InitDone, got {status}: {body}"
                );
                assert!(
                    body.contains("application watch"),
                    "the 503 must name the pending controller gate, got: {body}"
                );
                first_response = false;
            }
            if status == 200 {
                return body;
            }
        }
        // Before the first response, poll fast enough to catch the narrow pre-InitDone window.
        sleep(Duration::from_millis(if first_response { 5 } else { 100 }));
    }
    panic!("the API server did not reach /readyz == 200 within {STARTUP_BUDGET:?}");
}

/// Sums `ferriscd_rbac_reload_total{outcome="error"}` from the metrics endpoint (`0` when the
/// listener is not up yet).
fn rbac_reload_errors(metrics_address: SocketAddr) -> u64 {
    let Some((200, body)) = http_request(metrics_address, "GET", "/metrics", None, None) else {
        return 0;
    };
    body.lines()
        .filter(|line| line.starts_with("ferriscd_rbac_reload_total{"))
        .filter(|line| line.contains("outcome=\"error\""))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

fn http_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    bearer_token: Option<&str>,
    json_body: Option<&str>,
) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(address).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(token) = bearer_token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(body) = json_body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("\r\n");
        request.push_str(body);
    } else {
        request.push_str("\r\n");
    }

    stream.write_all(request.as_bytes()).ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    let text = String::from_utf8_lossy(&response);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())?;
    let body = text
        .split_once("\r\n\r\n")
        .map_or_else(String::new, |(_, body)| body.to_owned());
    Some((status, body))
}

// ---------------------------------------------------------------------------
// Cluster fixtures (kubectl)
// ---------------------------------------------------------------------------

struct ClusterCleanup;

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        let _ = kubectl(&[
            "-n",
            NAMESPACE,
            "patch",
            "application",
            APPLICATION,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":null}}"#,
        ]);
        let _ = kubectl(&[
            "delete",
            "namespace",
            NAMESPACE,
            "--ignore-not-found",
            "--wait=false",
        ]);
    }
}

fn current_kube_context() -> String {
    let output = kubectl(&["config", "current-context"]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn install_crds() {
    let directory = workspace_root().join("deploy/crds");
    for entry in std::fs::read_dir(&directory).expect("deploy/crds must exist") {
        let path = entry.expect("a CRD file").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            kubectl(&["apply", "-f", &path.to_string_lossy()]);
        }
    }
}

fn create_namespace() {
    kubectl(&["create", "namespace", NAMESPACE]);
}

fn create_service_account() {
    let manifest = format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: {SERVICE_ACCOUNT}
  namespace: {NAMESPACE}
"#
    );
    kubectl_with_stdin(&["apply", "-f", "-"], Some(&manifest));
}

fn apply_rbac_policy(policy_yaml: &str) {
    let indented = policy_yaml
        .lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let manifest = format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: ferriscd-rbac-cm
  namespace: {NAMESPACE}
data:
  policy.yaml: |
{indented}
"#
    );
    kubectl_with_stdin(&["apply", "-f", "-"], Some(&manifest));
}

fn create_project_and_application() {
    let manifest = format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {PROJECT}
  namespace: {NAMESPACE}
spec:
  description: "payments (v1.1 live rbac reload e2e)"
  sourceRepos: ["*"]
  sourceNamespaces: ["{NAMESPACE}"]
  destinations:
    - cluster: in-cluster
      namespace: "*"
  allowedServiceAccounts: ["*"]
---
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {APPLICATION}
  namespace: {NAMESPACE}
spec:
  project: {PROJECT}
  source:
    git:
      repoURL: https://github.com/example/payments.git
      targetRevision: main
      path: deploy
    renderer:
      plainYaml: {{}}
  destination:
    cluster: in-cluster
    namespace: {NAMESPACE}
  syncPolicy:
    automated: {{}}
  requeueAfterSeconds: 600
"#
    );
    kubectl_with_stdin(&["apply", "-f", "-"], Some(&manifest));
}

fn mint_token() -> String {
    let output = kubectl(&[
        "create",
        "token",
        SERVICE_ACCOUNT,
        "-n",
        NAMESPACE,
        "--duration",
        "1h",
    ]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

fn kubectl(args: &[&str]) -> Output {
    kubectl_with_stdin(args, None)
}

fn kubectl_with_stdin(args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new("kubectl");
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn().expect("kubectl must be installed");
    if let Some(manifest) = stdin {
        child
            .stdin
            .as_mut()
            .expect("a stdin pipe")
            .write_all(manifest.as_bytes())
            .expect("the manifest is written");
    }
    let output = child.wait_with_output().expect("kubectl output");
    let tolerated = args.first() == Some(&"create") && args.get(1) == Some(&"namespace");
    assert!(
        output.status.success() || tolerated,
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

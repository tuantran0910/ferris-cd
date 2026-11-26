//! Live `v1.0` control-plane test: Kubernetes `TokenReview` AuthN + project RBAC + the `ferriscd` CLI
//! (`T14.3`, `T14.4`, `T14.5` verification bullets "live `kind` test" / "end-to-end CLI tests").
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. It asserts that `kubectl config
//! current-context` begins with `kind-` before doing anything, and it is `#[ignore]`d so `cargo test`
//! never runs it. Invoke it with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v1_0_control_plane_auth -- --ignored --test-threads=1
//! ```
//!
//! # What it proves that the hermetic suite cannot
//!
//! The in-process tests (`crates/ferriscd-server/tests/auth_rbac.rs`) substitute the `TokenReview`
//! call. Here nothing is substituted:
//!
//! 1. a real `ServiceAccount` token minted by `kubectl create token` is accepted by the cluster's
//!    own `authentication.k8s.io/v1` `TokenReview` through the API server `ferriscd server` started;
//! 2. the identity's Kubernetes groups are what the `ferriscd-rbac-cm` policy matches, so a
//!    read-only group can list and read a `payments` application but is refused (`403`) on `sync`;
//! 3. `ferriscd login` stores the token in a `0600` file and `ferriscd app list` reads through the
//!    API — i.e. the whole `T14.5` command surface works against a real server;
//! 4. a bogus token is `401` and an invisible application is `404`, end to end.
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

/// Namespace that hosts this test's `ServiceAccount`, `Application`, and RBAC `ConfigMap`.
///
/// `ferriscd server` reads `ferriscd-rbac-cm` from its own `--namespace`, so pointing the whole test
/// at a scratch namespace keeps the developer's `ferriscd-system` untouched.
const NAMESPACE: &str = "ferriscd-auth-e2e";
/// The `ServiceAccount` whose token is minted and reviewed.
const SERVICE_ACCOUNT: &str = "cli-e2e";
/// The `AppProject` the application belongs to.
const PROJECT: &str = "payments";
/// The `Application` the CLI should see.
const APPLICATION: &str = "payments-api";

/// How long the API server may take to answer `/healthz`.
const STARTUP_BUDGET: Duration = Duration::from_secs(120);
/// How long one `ferriscd` invocation may take.
const COMMAND_BUDGET: Duration = Duration::from_secs(120);

/// `T14.3`+`T14.4`+`T14.5`: `TokenReview` AuthN, project RBAC and the CLI, end to end on `kind`.
#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn token_review_rbac_and_the_cli_work_end_to_end() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    install_crds();
    ensure_default_project();
    create_namespace();
    let _cleanup = ClusterCleanup;

    create_service_account();
    create_rbac_configmap();
    create_application();
    let token = mint_token();
    assert!(!token.trim().is_empty(), "kubectl must mint a token");

    let address = free_address();
    let mut server = ServerProcess::start(address);
    wait_for_healthy(address);

    // --- `ferriscd login` stores the credential in a 0600 file ---------------------------------
    let directory = tempfile::tempdir().expect("a scratch directory");
    let config = directory.path().join("config.json");
    let login = run_cli(
        &[
            "login",
            &format!("http://{address}"),
            "--token",
            token.trim(),
        ],
        &config,
        None,
    );
    assert!(
        login.status.success(),
        "login failed: {}\n{}",
        String::from_utf8_lossy(&login.stdout),
        String::from_utf8_lossy(&login.stderr)
    );
    let stored = std::fs::read_to_string(&config).expect("the credential file exists");
    assert!(stored.contains("serverUrl"), "{stored}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&config)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the stored token must be private");
    }

    // --- `ferriscd app list` sees the application the RBAC policy grants see --------------------
    let list = run_cli(&["app", "list", "--output", "json"], &config, None);
    assert!(
        list.status.success(),
        "app list failed: {}\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        stdout.contains(APPLICATION),
        "the granted project's application must be listed: {stdout}"
    );
    assert!(
        !stdout.contains(token.trim()),
        "the CLI must never print the token: {stdout}"
    );

    // --- a read-only identity is refused on sync (403) ------------------------------------------
    let sync = run_cli(
        &["app", "sync", "-n", NAMESPACE, APPLICATION],
        &config,
        None,
    );
    assert!(
        !sync.status.success(),
        "a read-only identity must not be able to sync"
    );
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(
        stderr.contains("ferriscd-rbac-cm") || stderr.contains("not permitted"),
        "the refusal must explain the missing grant: {stderr}"
    );

    // --- a bogus token is 401 -------------------------------------------------------------------
    let bogus = run_cli(
        &["app", "list"],
        &config,
        Some("definitely-not-a-kubernetes-token"),
    );
    assert!(
        !bogus.status.success(),
        "a bogus token must not be accepted"
    );
    assert!(
        String::from_utf8_lossy(&bogus.stderr).contains("ferriscd login"),
        "a 401 must tell the user to log in: {}",
        String::from_utf8_lossy(&bogus.stderr)
    );

    // --- an invisible application is 404, exactly like a missing one ----------------------------
    for name in ["tenant-b-api", "does-not-exist"] {
        let get = run_cli(&["app", "get", "-n", NAMESPACE, name], &config, None);
        assert!(!get.status.success(), "{name} must not be readable");
        assert!(
            String::from_utf8_lossy(&get.stderr).contains("not found"),
            "{name} must answer not-found: {}",
            String::from_utf8_lossy(&get.stderr)
        );
    }

    server.stop();
}

// ---------------------------------------------------------------------------
// The API server child process
// ---------------------------------------------------------------------------

/// `ferriscd server`, killed when the test ends (however it ends).
struct ServerProcess {
    child: Child,
}

impl ServerProcess {
    fn start(address: SocketAddr) -> Self {
        let binary = env!("CARGO_BIN_EXE_ferriscd");
        let child = Command::new(binary)
            .args([
                "server",
                "--api-addr",
                &address.to_string(),
                "--metrics-addr",
                "127.0.0.1:0",
                "--namespace",
                NAMESPACE,
                "--auth-policy",
                "token-review",
                // A throwaway webhook secret: the webhook endpoints must be configured for the
                // server to accept deliveries, and this test never sends one.
                "--github-webhook-secret",
                "cli-e2e-webhook-secret",
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

/// A loopback address that is free right now.
///
/// Binding and immediately dropping a listener is the only portable way to ask the kernel; the window
/// between the drop and the server's own bind is a race this test accepts (and the health poll would
/// fail loudly if the port were taken by something else).
fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("an address");
    drop(listener);
    address
}

/// Polls `GET /healthz` until the server answers `200`, or panics after [`STARTUP_BUDGET`].
///
/// A raw TCP request keeps this test free of an HTTP client dependency; `/healthz` is public, which
/// is also what proves the probe split (`T14.3`) on a real socket.
fn wait_for_healthy(address: SocketAddr) {
    let deadline = Instant::now() + STARTUP_BUDGET;
    while Instant::now() < deadline {
        if http_status(address, "/healthz") == Some(200) {
            return;
        }
        sleep(Duration::from_millis(200));
    }
    panic!("the API server did not become healthy within {STARTUP_BUDGET:?}");
}

/// One HTTP/1.1 `GET`, returning the status code when the exchange completed.
fn http_status(address: SocketAddr, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(address).ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    let text = String::from_utf8_lossy(&response);
    text.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
}

// ---------------------------------------------------------------------------
// CLI invocations
// ---------------------------------------------------------------------------

/// Runs the `ferriscd` binary with an isolated config file and a bounded wait.
fn run_cli(args: &[&str], config: &Path, token_override: Option<&str>) -> Output {
    let binary = env!("CARGO_BIN_EXE_ferriscd");
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("FERRISCD_CONFIG", config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(token) = token_override {
        command.env("FERRISCD_TOKEN", token);
    } else {
        command.env_remove("FERRISCD_TOKEN");
    }
    command.env_remove("FERRISCD_SERVER");
    let mut child = command.spawn().expect("the ferriscd binary must run");
    let deadline = Instant::now() + COMMAND_BUDGET;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().expect("the CLI output"),
            Ok(None) => sleep(Duration::from_millis(100)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("cannot wait for the CLI: {error}");
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("a ferriscd invocation did not finish within {COMMAND_BUDGET:?}");
}

// ---------------------------------------------------------------------------
// Cluster fixtures (kubectl)
// ---------------------------------------------------------------------------

/// Deletes the namespace this test created, whatever state the API server left it in.
struct ClusterCleanup;

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        // Strip any finalizer attached by the test server before deleting the namespace, since
        // `ServerProcess` is dropped before `ClusterCleanup` and no controller remains to release
        // `ferriscd.io/finalizer`.
        for app in [APPLICATION, "tenant-b-api"] {
            let _ = kubectl(&[
                "-n",
                NAMESPACE,
                "patch",
                "application",
                app,
                "--type=merge",
                "-p",
                r#"{"metadata":{"finalizers":null}}"#,
            ]);
        }
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

/// The `default` `AppProject` the controller requires for `spec.project: default` applications.
fn ensure_default_project() {
    let manifest = workspace_root().join("deploy/manifests/default-project.yaml");
    kubectl(&["apply", "-f", &manifest.to_string_lossy()]);
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

/// The RBAC policy: this namespace's `ServiceAccount`s may *read* the `payments` project only.
fn create_rbac_configmap() {
    let manifest = format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: ferriscd-rbac-cm
  namespace: {NAMESPACE}
data:
  policy.yaml: |
    rules:
      - subject:
          kind: group
          name: system:serviceaccounts:{NAMESPACE}
        project: {PROJECT}
        actions: [get, diff]
"#
    );
    kubectl_with_stdin(&["apply", "-f", "-"], Some(&manifest));
}

/// An `Application` in `payments`, and one in a project the token may not see.
fn create_application() {
    let manifest = format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {PROJECT}
  namespace: ferriscd-system
spec:
  description: "payments (v1.0 auth e2e)"
  sourceRepos: ["*"]
  sourceNamespaces: ["{NAMESPACE}"]
  destinations:
    - cluster: in-cluster
      namespace: "*"
  allowedServiceAccounts: ["*"]
---
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: tenant-b
  namespace: ferriscd-system
spec:
  description: "another tenant (v1.0 auth e2e)"
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
---
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: tenant-b-api
  namespace: {NAMESPACE}
spec:
  project: tenant-b
  source:
    git:
      repoURL: https://github.com/example/tenant-b.git
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

/// A short-lived token for [`SERVICE_ACCOUNT`], minted by the cluster's own token API.
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

/// Runs `kubectl` with no stdin, asserting success.
fn kubectl(args: &[&str]) -> Output {
    kubectl_with_stdin(args, None)
}

/// Runs `kubectl`, asserting success (or tolerating an already-existing object for `create`).
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
    // `create namespace` fails when it already exists; every other failure is the test's problem.
    let tolerated = args.first() == Some(&"create");
    assert!(
        output.status.success() || tolerated,
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

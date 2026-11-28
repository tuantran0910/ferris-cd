//! A fake `ferriscd-server` for the CLI tests (`T14.5`).
//!
//! Unit tests inside the binary crate cannot spawn a cluster, so the client is pointed at a real
//! `axum` listener on `127.0.0.1:0` that answers canned payloads and records every request. That
//! keeps the tests honest: the request line, the `Authorization` header and the JSON body are
//! produced by the real `reqwest` client, and the responses are parsed back into the server's own
//! DTOs. There is no sleep anywhere — the listener is bound before the test's first call and shut
//! down when the guard is dropped.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

/// One request the fake server received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// HTTP method.
    pub method: String,
    /// Path only (`/api/v1/applications/...`).
    pub path: String,
    /// The `Authorization` header, if one was sent.
    pub authorization: Option<String>,
    /// The request body, if any.
    pub body: Option<String>,
}

/// What the fake server answers for one `METHOD /path`.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A JSON body with a status.
    Json(StatusCode, Value),
    /// A raw body (for a malformed payload) with a status.
    Raw(StatusCode, String),
}

/// The canned routes, keyed by `"METHOD /path"`.
#[derive(Debug, Clone, Default)]
pub struct Routes {
    replies: HashMap<String, Reply>,
}

impl Routes {
    /// An empty route table (every request answers `404 NotFound`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers `METHOD /path` with `reply`.
    #[must_use]
    pub fn with(mut self, method: &str, path: &str, reply: Reply) -> Self {
        self.replies
            .insert(format!("{} {path}", method.to_uppercase()), reply);
        self
    }

    /// Answers a `GET`.
    #[must_use]
    pub fn get_json(self, path: &str, status: StatusCode, body: Value) -> Self {
        self.with("GET", path, Reply::Json(status, body))
    }

    /// Answers a `POST`.
    #[must_use]
    pub fn post_json(self, path: &str, status: StatusCode, body: Value) -> Self {
        self.with("POST", path, Reply::Json(status, body))
    }
}

/// The state the fake server shares with its test.
#[derive(Clone)]
struct Shared {
    routes: Routes,
    recorded: Arc<Mutex<Vec<Recorded>>>,
}

/// A running fake server. Dropping it stops the listener.
pub struct FakeServer {
    base_url: String,
    recorded: Arc<Mutex<Vec<Recorded>>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl FakeServer {
    /// Starts the server on a free loopback port and returns it with its base URL.
    pub async fn start(routes: Routes) -> Self {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let shared = Shared {
            routes,
            recorded: Arc::clone(&recorded),
        };
        let app = axum::Router::new().fallback(handle).with_state(shared);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free loopback port");
        let address = listener.local_addr().expect("the bound address");
        let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await;
        });
        Self {
            base_url: format!("http://{address}"),
            recorded,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    /// The base URL to hand to [`crate::client::Client::connect`].
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Every request received so far, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<Recorded> {
        self.recorded.lock().expect("test state").clone()
    }

    /// The paths received so far, in order.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        self.recorded()
            .into_iter()
            .map(|recorded| recorded.path)
            .collect()
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Records one request and answers from the route table.
async fn handle(State(shared): State<Shared>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let authorization = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = axum::body::to_bytes(request.into_body(), 1 << 20)
        .await
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    shared.recorded.lock().expect("test state").push(Recorded {
        method: method_label(&method).to_owned(),
        path: path.clone(),
        authorization,
        body,
    });

    let key = format!("{} {path}", method_label(&method));
    match shared.routes.replies.get(&key) {
        Some(Reply::Json(status, value)) => (*status, axum::Json(value.clone())).into_response(),
        Some(Reply::Raw(status, raw)) => (*status, raw.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": {
                    "code": "NotFound",
                    "message": format!("the fake server has no route for {key}"),
                }
            })),
        )
            .into_response(),
    }
}

/// The method as the route table spells it.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::client::{Client, ClientError};
    use crate::commands::app::{
        self, AppArgs, AppCommand, ConnectionArgs, DiffArgs, EXIT_OK, EXIT_OUT_OF_SYNC, GetArgs,
        ListArgs, RollbackArgs, SyncArgs, TargetArgs,
    };
    use crate::commands::platform::{
        self, ClusterArgs, ClusterCommand, ProjectArgs, ProjectCommand, sync_windows_cell,
    };
    use crate::output::OutputFormat;

    const APPLICATION: &str = r#"{
        "namespace": "ferriscd-system",
        "name": "payments-api",
        "project": "payments",
        "source": {
            "repoUrl": "https://github.com/example/payments.git",
            "path": "deploy",
            "targetRevision": "main",
            "renderer": "plainYaml"
        },
        "destination": {"cluster": "in-cluster", "namespace": "payments"},
        "sync": {
            "status": "Synced",
            "revision": "8f3a1c2",
            "lastSyncedRevision": "8f3a1c2"
        },
        "health": {"status": "Healthy"},
        "conditions": [],
        "resourceCount": 2
    }"#;

    fn application() -> Value {
        serde_json::from_str(APPLICATION).expect("a valid ApplicationSummary")
    }

    fn diff_body(clean: bool) -> Value {
        let (status, out_of_sync) = if clean {
            ("synced", 0)
        } else {
            ("outOfSync", 1)
        };
        serde_json::json!({
            "revision": "8f3a1c2",
            "desired": 1,
            "wouldSync": !clean,
            "summary": {
                "total": 1,
                "synced": if clean { 1 } else { 0 },
                "outOfSync": out_of_sync,
                "missing": 0,
                "orphaned": 0,
                "ownershipConflicts": 0,
                "fieldConflicts": 0
            },
            "resources": if clean {
                serde_json::json!([])
            } else {
                serde_json::json!([{
                    "key": "/Secret/payments/db",
                    "status": status,
                    "changes": [{
                        "path": "/data/password",
                        "kind": "modified",
                        "live": "***REDACTED(sha256:0123456789ab)***",
                        "predicted": "***REDACTED(sha256:ba9876543210)***"
                    }],
                    "conflicts": [],
                    "truncated": false
                }])
            }
        })
    }

    fn connection(server: &str) -> ConnectionArgs {
        ConnectionArgs {
            server_url: Some(server.to_owned()),
            // A fake token: the tests assert it is sent, never that it is valid.
            token: Some("fake-cli-test-token".to_owned()),
        }
    }

    fn list_args() -> ListArgs {
        ListArgs {
            output: OutputFormat::Json,
            color: crate::output::ColorChoice::Never,
        }
    }

    fn target(name: &str) -> TargetArgs {
        TargetArgs {
            name: name.to_owned(),
            namespace: None,
        }
    }

    #[tokio::test]
    async fn the_client_calls_the_documented_endpoints_with_the_bearer_token() {
        let server = FakeServer::start(
            Routes::new()
                .get_json(
                    "/api/v1/applications",
                    StatusCode::OK,
                    serde_json::json!({"items": [application()]}),
                )
                .get_json(
                    "/api/v1/applications/ferriscd-system/payments-api",
                    StatusCode::OK,
                    serde_json::json!({"application": application(), "history": []}),
                )
                .get_json(
                    "/api/v1/applications/ferriscd-system/payments-api/diff",
                    StatusCode::OK,
                    diff_body(false),
                )
                .get_json(
                    "/api/v1/projects",
                    StatusCode::OK,
                    serde_json::json!({"items": []}),
                )
                .get_json(
                    "/api/v1/clusters",
                    StatusCode::OK,
                    serde_json::json!({"items": [{"name": "in-cluster", "inCluster": true}]}),
                ),
        )
        .await;
        let client = Client::connect(Some(server.base_url()), Some("fake-cli-test-token"))
            .expect("a client");

        let list = client.list_applications().await.expect("the list");
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].name, "payments-api");
        assert_eq!(list.items[0].project, "payments");
        client
            .get_application("ferriscd-system", "payments-api")
            .await
            .expect("the detail");
        let diff = client
            .diff("ferriscd-system", "payments-api")
            .await
            .expect("the diff");
        assert_eq!(diff.summary.out_of_sync, 1);
        client.list_projects().await.expect("the projects");
        client.list_clusters().await.expect("the clusters");

        assert_eq!(
            server.paths(),
            vec![
                "/api/v1/applications".to_owned(),
                "/api/v1/applications/ferriscd-system/payments-api".to_owned(),
                "/api/v1/applications/ferriscd-system/payments-api/diff".to_owned(),
                "/api/v1/projects".to_owned(),
                "/api/v1/clusters".to_owned(),
            ]
        );
        for recorded in server.recorded() {
            assert_eq!(
                recorded.authorization.as_deref(),
                Some("Bearer fake-cli-test-token"),
                "every request is authenticated ({} {})",
                recorded.method,
                recorded.path
            );
        }
    }

    /// **`T14.5` verification (exit codes):** `app diff` exits `2` when there is drift and `0` when
    /// there is none — the CI contract.
    #[tokio::test]
    async fn app_diff_exits_two_for_drift_and_zero_when_in_sync() {
        for (clean, expected) in [(false, EXIT_OUT_OF_SYNC), (true, EXIT_OK)] {
            let server = FakeServer::start(Routes::new().get_json(
                "/api/v1/applications/ferriscd-system/payments-api/diff",
                StatusCode::OK,
                diff_body(clean),
            ))
            .await;
            let args = AppArgs {
                connection: connection(server.base_url()),
                command: AppCommand::Diff(DiffArgs {
                    target: target("payments-api"),
                    output: OutputFormat::Json,
                    color: crate::output::ColorChoice::Never,
                }),
            };
            assert_eq!(
                app::run(args).await.expect("the diff runs"),
                expected,
                "clean={clean}"
            );
            assert_eq!(
                server.paths(),
                vec!["/api/v1/applications/ferriscd-system/payments-api/diff".to_owned()]
            );
        }
    }

    /// `app sync --prune` forwards the flag, and a `422` from the server is reported with the
    /// server's own explanation (v1.0 cannot prune through the API).
    #[tokio::test]
    async fn app_sync_forwards_prune_and_reports_the_servers_refusal() {
        let server = FakeServer::start(Routes::new().post_json(
            "/api/v1/applications/ferriscd-system/payments-api/sync",
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({"error": {
                "code": "Unprocessable",
                "message": "this server cannot honour prune yet",
            }}),
        ))
        .await;
        let args = AppArgs {
            connection: connection(server.base_url()),
            command: AppCommand::Sync(SyncArgs {
                target: target("payments-api"),
                prune: true,
                watch: false,
                timeout: 1,
            }),
        };
        let error = app::run(args).await.expect_err("a 422 is an error");
        assert!(
            error.to_string().contains("cannot honour prune"),
            "the server's explanation must reach the user: {error}"
        );
        let recorded = server.recorded();
        assert_eq!(recorded.len(), 1);
        let body: Value =
            serde_json::from_str(recorded[0].body.as_deref().expect("a body")).expect("valid JSON");
        assert_eq!(body, serde_json::json!({"prune": true}));
    }

    /// `app sync` and `app rollback` send exactly the documented bodies, and a plain sync is `{}`.
    #[tokio::test]
    async fn app_sync_and_rollback_send_the_documented_bodies() {
        let operation = serde_json::json!({
            "status": "accepted",
            "operation": "sync",
            "namespace": "ferriscd-system",
            "name": "payments-api",
            "request": "{\"sync\":{}}",
        });
        let server = FakeServer::start(
            Routes::new()
                .post_json(
                    "/api/v1/applications/ferriscd-system/payments-api/sync",
                    StatusCode::ACCEPTED,
                    operation.clone(),
                )
                .post_json(
                    "/api/v1/applications/ferriscd-system/payments-api/rollback",
                    StatusCode::ACCEPTED,
                    serde_json::json!({
                        "status": "accepted",
                        "operation": "rollback",
                        "namespace": "ferriscd-system",
                        "name": "payments-api",
                        "request": "{\"rollback\":{\"id\":7}}",
                    }),
                ),
        )
        .await;
        let sync = AppArgs {
            connection: connection(server.base_url()),
            command: AppCommand::Sync(SyncArgs {
                target: target("ferriscd-system/payments-api"),
                prune: false,
                watch: false,
                timeout: 1,
            }),
        };
        assert_eq!(app::run(sync).await.expect("the sync"), EXIT_OK);

        let rollback = AppArgs {
            connection: connection(server.base_url()),
            command: AppCommand::Rollback(RollbackArgs {
                target: target("payments-api"),
                history_id: 7,
            }),
        };
        assert_eq!(app::run(rollback).await.expect("the rollback"), EXIT_OK);

        let recorded = server.recorded();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].method, "POST");
        let body: Value =
            serde_json::from_str(recorded[0].body.as_deref().expect("a body")).expect("valid JSON");
        assert_eq!(
            body,
            serde_json::json!({}),
            "a plain sync sends an empty object"
        );
        let body: Value =
            serde_json::from_str(recorded[1].body.as_deref().expect("a body")).expect("valid JSON");
        assert_eq!(body, serde_json::json!({"id": 7}));
    }

    /// `T17.4`: `ferriscd project list` renders each sync window with the state the server
    /// evaluated it in — "blocked" is invisible otherwise.
    #[tokio::test]
    async fn project_list_shows_sync_windows_with_their_live_state() {
        let server = FakeServer::start(Routes::new().get_json(
            "/api/v1/projects",
            StatusCode::OK,
            serde_json::json!({"items": [
                {
                    "name": "governed",
                    "sourceRepos": ["*"],
                    "destinations": ["in-cluster/payments"],
                    "syncWindows": [
                        {
                            "kind": "deny",
                            "schedule": "0 9-17 * * MON-FRI",
                            "duration": "8h",
                            "timeZone": "America/New_York",
                            "manualSync": false,
                            "active": true,
                            "startsAt": "2027-01-15T14:00:00Z",
                            "endsAt": "2027-01-15T22:00:00Z",
                            "nextStart": "2027-01-18T14:00:00Z"
                        },
                        {
                            "kind": "allow",
                            "schedule": "0 2 * * SAT",
                            "duration": "2h",
                            "timeZone": "UTC",
                            "manualSync": true,
                            "active": false,
                            "nextStart": "2027-01-16T02:00:00Z"
                        }
                    ],
                    "nextSyncWindowTransition": "2027-01-15T22:00:00Z"
                },
                {"name": "ungoverned", "sourceRepos": ["*"], "destinations": ["in-cluster/*"]}
            ]}),
        ))
        .await;

        let projects = Client::connect(Some(server.base_url()), Some("fake-cli-test-token"))
            .expect("a client")
            .list_projects()
            .await
            .expect("the project list");
        let governed = &projects.items[0];
        assert_eq!(governed.sync_windows.len(), 2);
        assert!(governed.sync_windows[0].active);
        assert_eq!(
            governed.next_sync_window_transition.as_deref(),
            Some("2027-01-15T22:00:00Z")
        );
        assert!(
            projects.items[1].sync_windows.is_empty(),
            "a project without windows must not grow an empty list (the field stays omitted)"
        );

        // The table cell says what the window does *and* what it is doing right now.
        let cell = sync_windows_cell(&governed.sync_windows);
        assert!(
            cell.contains(
                "deny 0 9-17 * * MON-FRI America/New_York active until 2027-01-15T22:00:00Z"
            ),
            "{cell}"
        );
        assert!(
            cell.contains("allow 0 2 * * SAT UTC next 2027-01-16T02:00:00Z, manual sync allowed"),
            "{cell}"
        );
        assert_eq!(sync_windows_cell(&[]), "<none>");

        // An unparseable entry is reported, never hidden (the project is deny-all while it is
        // broken).
        let broken = ferriscd_server::api::ProjectSyncWindowView {
            kind: "deny".to_owned(),
            schedule: "every weekday".to_owned(),
            duration: "2h".to_owned(),
            time_zone: "UTC".to_owned(),
            applications: Vec::new(),
            namespaces: Vec::new(),
            clusters: Vec::new(),
            manual_sync: false,
            active: false,
            starts_at: None,
            ends_at: None,
            next_start: None,
            error: Some("not a cron expression".to_owned()),
        };
        let cell = sync_windows_cell(std::slice::from_ref(&broken));
        assert!(cell.contains("invalid (not a cron expression)"), "{cell}");

        // And the table command itself still exits cleanly.
        let args = ProjectArgs {
            connection: connection(server.base_url()),
            command: ProjectCommand::List(platform::ListArgs {
                output: OutputFormat::Table,
            }),
        };
        assert_eq!(
            platform::run_project(args).await.expect("the table"),
            EXIT_OK
        );
        assert_eq!(
            server.paths(),
            vec!["/api/v1/projects".to_owned(), "/api/v1/projects".to_owned()],
            "the table render costs exactly one more `GET /api/v1/projects`"
        );
    }

    /// `app list`, `app get`, `app history`, `project list` and `cluster list` all succeed against
    /// the fake server and never request an endpoint the OpenAPI document does not declare.
    #[tokio::test]
    async fn every_read_command_uses_a_documented_endpoint() {
        let server = FakeServer::start(
            Routes::new()
                .get_json(
                    "/api/v1/applications",
                    StatusCode::OK,
                    serde_json::json!({"items": [application()]}),
                )
                .get_json(
                    "/api/v1/applications/ferriscd-system/payments-api",
                    StatusCode::OK,
                    serde_json::json!({
                        "application": application(),
                        "history": [{"id": 7, "revision": "8f3a1c2", "deployedAt": "2027-01-15T10:30:00Z"}],
                        "operation": {
                            "phase": "Succeeded",
                            "currentWave": 1,
                            "startedAt": "2027-01-15T10:30:00Z"
                        }
                    }),
                )
                .get_json(
                    "/api/v1/projects",
                    StatusCode::OK,
                    serde_json::json!({"items": [{
                        "name": "payments",
                        "description": "payments team",
                        "destinations": ["in-cluster/payments"],
                        "sourceRepos": ["https://github.com/example/payments.git"]
                    }]}),
                )
                .get_json(
                    "/api/v1/clusters",
                    StatusCode::OK,
                    serde_json::json!({"items": [{"name": "in-cluster", "inCluster": true}]}),
                ),
        )
        .await;

        for command in [
            AppCommand::List(list_args()),
            AppCommand::Get(GetArgs {
                target: target("payments-api"),
                output: OutputFormat::Json,
            }),
            AppCommand::History(app::HistoryArgs {
                target: target("payments-api"),
                output: OutputFormat::Json,
            }),
        ] {
            let args = AppArgs {
                connection: connection(server.base_url()),
                command,
            };
            assert_eq!(app::run(args).await.expect("the read command"), EXIT_OK);
        }

        for command in [ProjectCommand::List(platform::ListArgs {
            output: OutputFormat::Json,
        })] {
            let args = ProjectArgs {
                connection: connection(server.base_url()),
                command,
            };
            assert_eq!(
                platform::run_project(args).await.expect("project list"),
                EXIT_OK
            );
        }
        let args = ClusterArgs {
            connection: connection(server.base_url()),
            command: ClusterCommand::List(platform::ListArgs {
                output: OutputFormat::Json,
            }),
        };
        assert_eq!(
            platform::run_cluster(args).await.expect("cluster list"),
            EXIT_OK
        );

        let documented = [
            "/api/v1/applications",
            "/api/v1/applications/ferriscd-system/payments-api",
            "/api/v1/projects",
            "/api/v1/clusters",
        ];
        for path in server.paths() {
            assert!(
                documented.contains(&path.as_str()),
                "the CLI called an endpoint outside the documented set: {path}"
            );
        }
    }

    /// **`T14.5` verification (error handling + redaction):** a `401` tells the user to log in, a
    /// `404` says the application is not there *or not visible* (`T14.4`), and neither message ever
    /// carries the token.
    #[tokio::test]
    async fn a_refused_request_is_explained_without_leaking_the_token() {
        let unauthorized = FakeServer::start(Routes::new().get_json(
            "/api/v1/applications",
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": {
                "code": "Unauthorized",
                "message": "a valid Kubernetes bearer token is required",
            }}),
        ))
        .await;
        let client = Client::connect(Some(unauthorized.base_url()), Some("expired-token-value"))
            .expect("a client");
        let error = client
            .list_applications()
            .await
            .expect_err("a 401 is an error");
        assert!(
            matches!(error, ClientError::Unauthenticated { .. }),
            "{error:?}"
        );
        let rendered = error.to_string();
        assert!(rendered.contains("ferriscd login"), "{rendered}");
        assert!(
            !rendered.contains("expired-token-value"),
            "the token must never appear in an error: {rendered}"
        );

        let not_found = FakeServer::start(Routes::new().get_json(
            "/api/v1/applications/ferriscd-system/tenant-b-api",
            StatusCode::NOT_FOUND,
            serde_json::json!({"error": {
                "code": "NotFound",
                "message": "Application ferriscd-system/tenant-b-api not found",
            }}),
        ))
        .await;
        let args = AppArgs {
            connection: connection(not_found.base_url()),
            command: AppCommand::Get(GetArgs {
                target: target("tenant-b-api"),
                output: OutputFormat::Json,
            }),
        };
        let error = app::run(args).await.expect_err("a 404 is an error");
        assert!(
            error.to_string().contains("not found"),
            "the server's message is reported: {error}"
        );

        // A `403` is the one refusal that names the action, and it points at the RBAC ConfigMap.
        let forbidden = FakeServer::start(Routes::new().post_json(
            "/api/v1/applications/ferriscd-system/payments-api/sync",
            StatusCode::FORBIDDEN,
            serde_json::json!({"error": {
                "code": "Forbidden",
                "message": "not permitted to sync Application ferriscd-system/payments-api",
            }}),
        ))
        .await;
        let args = AppArgs {
            connection: connection(forbidden.base_url()),
            command: AppCommand::Sync(SyncArgs {
                target: target("payments-api"),
                prune: false,
                watch: false,
                timeout: 1,
            }),
        };
        let error = app::run(args).await.expect_err("a 403 is an error");
        let rendered = error.to_string();
        assert!(rendered.contains("ferriscd-rbac-cm"), "{rendered}");
        assert!(rendered.contains("not permitted to sync"), "{rendered}");
    }

    /// A malformed body from the server is reported as such instead of panicking, and an unreachable
    /// server is a transport error (exit `1`, never a hang: `reqwest` is bounded by the test's
    /// runtime, and the CLI reports the failure).
    #[tokio::test]
    async fn a_malformed_body_and_a_dead_server_are_plain_errors() {
        let malformed = FakeServer::start(Routes::new().with(
            "GET",
            "/api/v1/applications",
            Reply::Raw(StatusCode::OK, "{not json".to_owned()),
        ))
        .await;
        let client = Client::connect(Some(malformed.base_url()), Some("token")).expect("a client");
        let error = client
            .list_applications()
            .await
            .expect_err("a malformed body is an error");
        assert!(matches!(error, ClientError::Decode { .. }), "{error:?}");

        // A port nobody listens on: `127.0.0.1:1` is refused immediately by the kernel.
        let client = Client::connect(Some("http://127.0.0.1:1"), Some("token")).expect("a client");
        let error = client
            .list_applications()
            .await
            .expect_err("a dead server is an error");
        assert!(matches!(error, ClientError::Transport { .. }), "{error:?}");
    }

    /// `--watch` polls until the operation settles; the first poll happens before any sleep, so a
    /// controller that has already finished is reported without waiting.
    #[tokio::test]
    async fn watching_a_settled_sync_returns_success_without_waiting() {
        let server = FakeServer::start(Routes::new().get_json(
            "/api/v1/applications/ferriscd-system/payments-api",
            StatusCode::OK,
            serde_json::json!({
                "application": application(),
                "history": [],
                "operation": {
                    "phase": "Succeeded",
                    "currentWave": 0,
                    "startedAt": "2027-01-15T10:30:00Z"
                }
            }),
        ))
        .await;
        let client = Client::connect(Some(server.base_url()), Some("fake-cli-test-token"))
            .expect("a client");
        // A long timeout and a long interval: success must come from the first poll, not the clock.
        let code = app::watch_for_tests(
            &client,
            "ferriscd-system",
            "payments-api",
            Duration::from_secs(3_600),
            Duration::from_secs(3_600),
        )
        .await
        .expect("the watch completes");
        assert_eq!(code, EXIT_OK);
        assert_eq!(server.paths().len(), 1, "one poll, no extra requests");
    }
}

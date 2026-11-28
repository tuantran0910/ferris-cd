//! `ferriscd login` tests (`T14.5`, `T19.2`).
//!
//! The SSO half drives the **real** flow against a mock IdP served from an `axum` router on an
//! ephemeral loopback port: no external network, and no sleeps — the flow's `on_authorize_url` hook
//! fires only after the loopback listener is bound, so the test can play the browser immediately.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser as _;
use serde_json::{Value, json};

use super::*;

// ---------------------------------------------------------------------------
// The bearer-token half
// ---------------------------------------------------------------------------

fn args(token: Option<&str>, token_file: Option<&std::path::Path>) -> LoginArgs {
    LoginArgs {
        server_url: "https://ferriscd.example.com".to_owned(),
        token: token.map(ToOwned::to_owned),
        token_file: token_file.map(ToOwned::to_owned),
        no_verify: false,
        oidc: false,
        no_browser: false,
        login_timeout_seconds: DEFAULT_LOGIN_TIMEOUT.as_secs(),
        oidc_insecure_http: false,
    }
}

/// `read_token` over the parsed arguments.
fn read(args: &LoginArgs) -> Result<String> {
    read_token(args.token.as_deref(), args.token_file.as_deref())
}

#[test]
fn a_token_from_a_flag_or_a_file_is_trimmed_and_required() {
    assert_eq!(read(&args(Some(" abc\n"), None)).expect("a token"), "abc");
    assert!(read(&args(Some("   "), None)).is_err(), "empty is refused");
    assert!(read(&args(None, None)).is_err(), "missing is refused");

    let directory = tempfile::tempdir().expect("a scratch directory");
    let path = directory.path().join("token");
    std::fs::write(&path, "from-a-file\n").expect("write");
    assert_eq!(
        read(&args(None, Some(&path))).expect("a token"),
        "from-a-file"
    );

    std::fs::write(&path, "  \n").expect("write");
    assert!(
        read(&args(None, Some(&path))).is_err(),
        "an empty file is refused"
    );
    assert!(
        read(&args(None, Some(&directory.path().join("nope")))).is_err(),
        "an unreadable file is refused"
    );
}

/// `LoginArgs` holds a credential: its `Debug` must never print it.
#[test]
fn the_parsed_arguments_never_print_the_token() {
    let rendered = format!("{:?}", args(Some("super-secret-token"), None));
    assert!(!rendered.contains("super-secret-token"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(
        rendered.contains("https://ferriscd.example.com"),
        "{rendered}"
    );
}

// ---------------------------------------------------------------------------
// Argument parsing: `--oidc` and the `--sso` alias
// ---------------------------------------------------------------------------

#[derive(clap::Parser)]
struct LoginCli {
    #[command(flatten)]
    login: LoginArgs,
}

fn parse_login(argv: &[&str]) -> Result<LoginArgs, clap::Error> {
    LoginCli::try_parse_from(argv).map(|cli| cli.login)
}

#[test]
fn the_sso_alias_and_the_oidc_flag_are_equivalent() {
    for flag in ["--oidc", "--sso"] {
        let parsed = parse_login(&["login", "https://ferriscd.example.com", flag])
            .unwrap_or_else(|error| panic!("{flag} must parse: {error}"));
        assert!(parsed.oidc, "{flag} must request the SSO flow");
        assert!(parsed.token.is_none());
    }
    // The headless and local-IdP switches are only meaningful with the SSO flow.
    assert!(
        parse_login(&["login", "https://ferriscd.example.com", "--no-browser"]).is_err(),
        "--no-browser without --oidc is refused rather than ignored"
    );
    assert!(
        parse_login(&[
            "login",
            "https://ferriscd.example.com",
            "--oidc",
            "--token",
            "abc"
        ])
        .is_err(),
        "--token and --oidc are mutually exclusive"
    );
    let parsed = parse_login(&[
        "login",
        "https://ferriscd.example.com",
        "--sso",
        "--no-browser",
        "--oidc-insecure-http",
        "--login-timeout-seconds",
        "30",
    ])
    .expect("the headless SSO flags parse");
    assert!(parsed.oidc);
    assert!(parsed.no_browser);
    assert!(parsed.oidc_insecure_http);
    assert_eq!(parsed.login_timeout_seconds, 30);
}

// ---------------------------------------------------------------------------
// A mock IdP + server
// ---------------------------------------------------------------------------

/// What the mock IdP saw, and how it must answer the verification call.
#[derive(Debug, Default)]
struct Recorded {
    token_requests: Mutex<Vec<std::collections::HashMap<String, String>>>,
    clusters_requests: std::sync::atomic::AtomicUsize,
    refuse_clusters: std::sync::atomic::AtomicBool,
}

impl Recorded {
    fn token_requests(&self) -> Vec<std::collections::HashMap<String, String>> {
        self.token_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// How many `GET /api/v1/clusters` verification calls arrived.
    fn clusters_requests(&self) -> usize {
        self.clusters_requests
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Makes the mock server answer the verification call with `401`, as a wrong `aud`/`iss` would.
    fn refuse_clusters(&self) {
        self.refuse_clusters
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The verification endpoint the SSO login calls once the token is minted.
async fn mock_clusters(State(recorded): State<Arc<Recorded>>) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    recorded
        .clusters_requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if recorded
        .refuse_clusters
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"code": "Unauthorized", "message": "the token was rejected"}})),
        )
            .into_response();
    }
    Json(json!({"items": []})).into_response()
}

/// Starts a mock IdP serving `GET /api/v1/auth/config`, the discovery document and `POST /token`.
///
/// One server plays both roles (the FerrisCD API and the IdP) so the test needs a single ephemeral
/// port; the URLs are still the real ones a deployment would use.
async fn start_mock_idp() -> (SocketAddr, Arc<Recorded>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral loopback port");
    let address = listener.local_addr().expect("the bound address");
    let base_url = format!("http://127.0.0.1:{}", address.port());
    let recorded = Arc::new(Recorded {
        token_requests: Mutex::new(Vec::new()),
        ..Recorded::default()
    });

    let app = Router::new()
        .route(
            "/api/v1/auth/config",
            get({
                let base_url = base_url.clone();
                move || async move {
                    Json(json!({
                        "authMode": "oidc",
                        "issuer": base_url,
                        "clientId": "ferriscd-cli",
                        "scopes": ["openid", "profile", "email"],
                        "bffEnabled": false,
                    }))
                }
            }),
        )
        .route(
            "/.well-known/openid-configuration",
            get({
                let base_url = base_url.clone();
                move || async move {
                    Json(json!({
                        "issuer": base_url,
                        "authorization_endpoint": format!("{base_url}/authorize"),
                        "token_endpoint": format!("{base_url}/token"),
                    }))
                }
            }),
        )
        .route(
            "/authorize",
            get(|uri: axum::http::Uri| async move { format!("{uri}") }),
        )
        .route("/token", post(mock_token))
        .route("/api/v1/clusters", get(mock_clusters))
        .with_state(recorded.clone());

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (address, recorded, handle)
}

/// Parses an `application/x-www-form-urlencoded` body into a map.
///
/// Hand-rolled because the CLI's `axum` dev-dependency deliberately enables only the features a test
/// router needs (no `form`).
fn parse_form(body: &str) -> std::collections::HashMap<String, String> {
    let url = reqwest::Url::parse(&format!("https://form.invalid/?{body}"));
    let mut form = std::collections::HashMap::new();
    if let Ok(url) = url {
        for (key, value) in url.query_pairs() {
            form.insert(key.into_owned(), value.into_owned());
        }
    }
    form
}

async fn mock_token(State(recorded): State<Arc<Recorded>>, body: String) -> Json<Value> {
    let form = parse_form(&body);
    recorded
        .token_requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(form);
    Json(json!({
        "access_token": "cli-access-token-value",
        "token_type": "Bearer",
        "expires_in": 600,
    }))
}

// ---------------------------------------------------------------------------
// The SSO flow end to end
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sso_flow_completes_pkce_and_stores_a_0600_credential() {
    let (address, recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let directory = tempfile::tempdir().expect("a scratch directory");
    let config_path = directory.path().join("config.json");

    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let flow = tokio::spawn({
        let server_url = server_url.clone();
        async move {
            oidc_flow(OidcFlowOptions {
                server_url,
                open_browser: false,
                timeout: std::time::Duration::from_secs(10),
                allow_insecure_http: true,
                on_authorize_url: Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            })
            .await
        }
    });

    // The hook fires only after the loopback listener is bound, so this cannot race.
    let authorize = authorize_rx
        .recv()
        .await
        .expect("the flow publishes its authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute authorization URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| panic!("the authorization URL carries {key}: {authorize}"))
    };
    let redirect_uri = parameter("redirect_uri");
    let state = parameter("state");
    let challenge = parameter("code_challenge");
    assert_eq!(parameter("code_challenge_method"), "S256");
    assert_eq!(parameter("response_type"), "code");
    assert_eq!(parameter("client_id"), "ferriscd-cli");
    assert!(
        redirect_uri.starts_with("http://127.0.0.1:"),
        "the redirect URI is an ephemeral loopback port: {redirect_uri}"
    );
    assert!(redirect_uri.ends_with("/callback"), "{redirect_uri}");
    assert_eq!(
        challenge.len(),
        43,
        "an S256 challenge is 32 bytes base64url"
    );
    // No client secret is ever sent, and no token is in the URL.
    assert!(!authorize.contains("client_secret"), "{authorize}");
    assert!(!authorize.contains("access_token"), "{authorize}");

    // Play the browser.
    let callback = format!("{redirect_uri}?code=the-authorization-code&state={state}");
    let page = reqwest::get(&callback)
        .await
        .expect("the loopback listener answers");
    assert_eq!(page.status(), reqwest::StatusCode::OK);
    assert!(page.text().await.expect("a body").contains("signed in"));

    let token = flow
        .await
        .expect("the flow task did not panic")
        .expect("the SSO flow completes");
    assert_eq!(token, "cli-access-token-value");

    // The exchange carried the verifier whose S256 challenge the browser was given.
    let requests = recorded.token_requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    assert_eq!(
        request.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        request.get("code").map(String::as_str),
        Some("the-authorization-code")
    );
    assert_eq!(
        request.get("redirect_uri").map(String::as_str),
        Some(redirect_uri.as_str())
    );
    assert_eq!(
        request.get("client_id").map(String::as_str),
        Some("ferriscd-cli")
    );
    assert!(
        !request.contains_key("client_secret"),
        "a public client sends no secret: {request:?}"
    );
    let verifier = request.get("code_verifier").expect("a PKCE verifier");
    assert_eq!(
        ferriscd_server::s256_challenge(verifier),
        challenge,
        "the verifier matches the challenge the IdP saw"
    );

    // The credential persists with mode 0600 and reads back.
    store_at(&config_path, &server_url, token)
        .await
        .expect("the credential is stored");
    let stored = crate::client::StoredConfig::load_from(&config_path).expect("the credential");
    assert_eq!(stored.server_url, server_url);
    assert_eq!(stored.token, "cli-access-token-value");
    assert_mode_0600(&config_path);
}

/// The whole `ferriscd login --sso` command path: parse, discover, PKCE, loopback callback, exchange,
/// and the `0600` credential write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sso_alias_command_completes_the_flow_and_writes_a_0600_config() {
    let (address, recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let directory = tempfile::tempdir().expect("a scratch directory");
    let config_path = directory.path().join("config.json");

    let args = parse_login(&[
        "login",
        &server_url,
        "--sso",
        "--no-browser",
        "--oidc-insecure-http",
    ])
    .expect("the --sso alias parses");
    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let command = tokio::spawn({
        let config_path = config_path.clone();
        async move {
            run_oidc_with(
                &args,
                &config_path,
                Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            )
            .await
        }
    });

    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .expect("the authorization URL parameter")
    };
    let callback = format!(
        "{}?code=the-code&state={}",
        parameter("redirect_uri"),
        parameter("state")
    );
    reqwest::get(&callback)
        .await
        .expect("the loopback listener answers")
        .error_for_status()
        .expect("the browser page is a success");

    command
        .await
        .expect("the login task did not panic")
        .expect("`ferriscd login --sso` completes");

    let stored =
        crate::client::StoredConfig::load_from(&config_path).expect("the credential is stored");
    assert_eq!(stored.server_url, server_url);
    assert_eq!(stored.token, "cli-access-token-value");
    assert_mode_0600(&config_path);
    // One exchange, with the verifier whose challenge the IdP saw.
    let requests = recorded.token_requests();
    assert_eq!(requests.len(), 1);
    let verifier = requests[0].get("code_verifier").expect("a verifier");
    assert_eq!(
        ferriscd_server::s256_challenge(verifier),
        parameter("code_challenge")
    );
}

/// A forged callback is refused, nothing is exchanged, and it cannot complete the login on its own:
/// the flow only ends when the real callback arrives (or the timeout expires), never because somebody
/// guessed the loopback port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callback_with_the_wrong_state_stores_nothing_and_does_not_complete_the_login() {
    let (address, recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let flow = tokio::spawn({
        let server_url = server_url.clone();
        async move {
            oidc_flow(OidcFlowOptions {
                server_url,
                open_browser: false,
                // Short, so the "the forged callback did not finish it" half needs no real wait.
                timeout: std::time::Duration::from_millis(400),
                allow_insecure_http: true,
                on_authorize_url: Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            })
            .await
        }
    });
    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let redirect_uri = url
        .query_pairs()
        .find(|(name, _)| name == "redirect_uri")
        .map(|(_, value)| value.into_owned())
        .expect("a redirect URI");

    // A forged callback (someone else's state) is refused…
    let forged = reqwest::get(format!(
        "{redirect_uri}?code=stolen&state=not-the-issued-state"
    ))
    .await
    .expect("the loopback listener answers");
    assert_eq!(forged.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(
        !flow.is_finished(),
        "a refused callback must not end the sign-in"
    );

    // …and it never finishes the login: only the real callback can, so the flow times out instead.
    let error = flow
        .await
        .expect("the flow task did not panic")
        .expect_err("a forged callback cannot complete the login");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("no browser callback arrived"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("stolen"),
        "the code is never echoed: {rendered}"
    );
    assert!(recorded.token_requests().is_empty(), "no exchange happened");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_without_oidc_refuses_the_sso_flow_with_a_useful_message() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral loopback port");
    let address = listener.local_addr().expect("the bound address");
    let app = Router::new().route(
        "/api/v1/auth/config",
        get(|| async {
            Json(json!({
                "authMode": "token-review",
                "scopes": [],
                "bffEnabled": false,
            }))
        }),
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let error = oidc_flow(OidcFlowOptions {
        server_url: format!("http://127.0.0.1:{}", address.port()),
        open_browser: false,
        timeout: std::time::Duration::from_secs(5),
        allow_insecure_http: true,
        on_authorize_url: None,
    })
    .await
    .expect_err("a token-review server has no SSO");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("token-review"), "{rendered}");
    assert!(
        rendered.contains("--token-file"),
        "it suggests the fallback: {rendered}"
    );
    server.abort();
}

#[cfg(unix)]
fn assert_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = std::fs::metadata(path)
        .expect("the credential file exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the credential must be private to its owner");
}

#[cfg(not(unix))]
fn assert_mode_0600(_path: &Path) {}

// ---------------------------------------------------------------------------
// The loopback listener: a forged callback does not end the sign-in
// ---------------------------------------------------------------------------

/// **`T19.2` review finding: the first callback with the wrong `state` aborted the whole login.**
///
/// The loopback listener is reachable by anything on the machine, so a forged (or stale, or
/// cross-site) `GET /callback?state=…` used to kill a sign-in that was about to succeed. It is now
/// answered `400` and the listener keeps waiting; the *real* callback then completes the flow, and the
/// forged code is never exchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_callback_is_refused_and_the_login_keeps_waiting_for_the_real_one() {
    let (address, recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let flow = tokio::spawn({
        let server_url = server_url.clone();
        async move {
            oidc_flow(OidcFlowOptions {
                server_url,
                open_browser: false,
                timeout: std::time::Duration::from_secs(10),
                allow_insecure_http: true,
                on_authorize_url: Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            })
            .await
        }
    });
    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .expect("the authorization URL parameter")
    };
    let redirect_uri = parameter("redirect_uri");
    let state = parameter("state");

    // 1. Somebody else's callback, with a code this process must never exchange.
    let forged = reqwest::get(format!("{redirect_uri}?code=stolen-code&state=not-issued"))
        .await
        .expect("the loopback listener answers a forged request");
    assert_eq!(forged.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(
        !flow.is_finished(),
        "a forged callback must not end the sign-in"
    );
    assert!(
        recorded.token_requests().is_empty(),
        "nothing was exchanged"
    );

    // 2. The browser's real callback.
    let real = reqwest::get(format!("{redirect_uri}?code=the-code&state={state}"))
        .await
        .expect("the loopback listener answers the real request");
    assert_eq!(real.status(), reqwest::StatusCode::OK);
    assert!(real.text().await.expect("a body").contains("signed in"));

    let token = flow
        .await
        .expect("the flow task did not panic")
        .expect("the real callback completes the login");
    assert_eq!(token, "cli-access-token-value");
    let requests = recorded.token_requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(
        requests[0].get("code").map(String::as_str),
        Some("the-code"),
        "only the real authorization code was ever exchanged"
    );
}

/// A callback without a `state`/`code`, and a non-`GET` request, are answered with the right status —
/// and the listener keeps waiting for the real callback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_loopback_requests_are_answered_with_their_own_status_and_do_not_abort() {
    let (address, _recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let flow = tokio::spawn({
        let server_url = server_url.clone();
        async move {
            oidc_flow(OidcFlowOptions {
                server_url,
                open_browser: false,
                timeout: std::time::Duration::from_secs(10),
                allow_insecure_http: true,
                on_authorize_url: Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            })
            .await
        }
    });
    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .expect("the authorization URL parameter")
    };
    let redirect_uri = parameter("redirect_uri");

    // A POST is not a callback: the status line must say `Method Not Allowed`, not "Bad Request".
    let http = reqwest::Client::new();
    let posted = http
        .post(&redirect_uri)
        .body("")
        .send()
        .await
        .expect("the listener answers");
    assert_eq!(posted.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);

    // A GET with no query at all: refused, and the flow still runs.
    let bare = http
        .get(&redirect_uri)
        .send()
        .await
        .expect("the listener answers");
    assert_eq!(bare.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(
        !flow.is_finished(),
        "a malformed request must not end the sign-in"
    );

    // Finish it so the task does not outlive the test.
    let real = http
        .get(format!(
            "{redirect_uri}?code=the-code&state={}",
            parameter("state")
        ))
        .send()
        .await
        .expect("the listener answers");
    assert_eq!(real.status(), reqwest::StatusCode::OK);
    flow.await
        .expect("the flow task did not panic")
        .expect("the login completes");
}

/// **`T19.2` round-3 finding: an oversized loopback request aborted the whole sign-in.**
///
/// The listener reads one bounded request head (`MAX_CALLBACK_BYTES`). A head past that ceiling is
/// unparseable — not a verdict about the sign-in — so it is now answered `431` and the flow keeps
/// waiting, exactly like a forged `state` is answered `400`. A machine-local process (or a broken
/// client) can therefore not kill a sign-in that is still about to succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_callback_head_is_answered_431_and_the_login_keeps_waiting() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (address, _recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let flow = tokio::spawn({
        let server_url = server_url.clone();
        async move {
            oidc_flow(OidcFlowOptions {
                server_url,
                open_browser: false,
                timeout: std::time::Duration::from_secs(10),
                allow_insecure_http: true,
                on_authorize_url: Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            })
            .await
        }
    });
    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .expect("the authorization URL parameter")
    };
    let redirect_uri = reqwest::Url::parse(&parameter("redirect_uri")).expect("an absolute URL");
    let loopback = redirect_uri
        .socket_addrs(|| None)
        .expect("the loopback address")
        .into_iter()
        .next()
        .expect("one address");

    // A request head far past the documented ceiling, with no terminator: the listener has to give up
    // on the *request*, not on the sign-in.
    let stream = tokio::net::TcpStream::connect(loopback)
        .await
        .expect("the loopback listener accepts");
    let oversized = format!(
        "GET {}?code=the-code&state={} HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
        redirect_uri.path(),
        parameter("state"),
        "a".repeat(MAX_CALLBACK_BYTES * 2)
    );
    // Written from its own task: the listener stops reading once the ceiling is passed, so a fully
    // synchronous write could block on a socket the other side already abandoned.
    let (mut reader, mut writer) = stream.into_split();
    tokio::spawn(async move {
        let _ = writer.write_all(oversized.as_bytes()).await;
    });
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_to_end(&mut response),
    )
    .await
    .expect("the listener answers the oversized request");
    let response = String::from_utf8_lossy(&response).into_owned();
    assert!(
        response.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
        "{response}"
    );
    assert!(
        !flow.is_finished(),
        "an oversized request must not end the sign-in"
    );

    // The real callback still completes it.
    let real = reqwest::get(format!(
        "{redirect_uri}?code=the-code&state={}",
        parameter("state")
    ))
    .await
    .expect("the listener answers the real request");
    assert_eq!(real.status(), reqwest::StatusCode::OK);
    let token = flow
        .await
        .expect("the flow task did not panic")
        .expect("the login completes");
    assert_eq!(token, "cli-access-token-value");
}

// ---------------------------------------------------------------------------
// The loopback listener: an `error=` aborts only when it carries the issued `state`
// ---------------------------------------------------------------------------

/// Starts `oidc_flow` against the mock IdP and returns the loopback `redirect_uri`, the `state` it
/// issued, and the flow task (the mock IdP keeps running detached for the duration of the test).
async fn start_loopback_flow() -> (String, String, tokio::task::JoinHandle<Result<String>>) {
    let (address, _recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let flow = tokio::spawn({
        let server_url = server_url.clone();
        async move {
            oidc_flow(OidcFlowOptions {
                server_url,
                open_browser: false,
                timeout: std::time::Duration::from_secs(10),
                allow_insecure_http: true,
                on_authorize_url: Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            })
            .await
        }
    });
    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .expect("the authorization URL parameter")
    };
    (parameter("redirect_uri"), parameter("state"), flow)
}

/// **`T19.2` final-round finding: one forged `GET /callback?error=…` aborted the whole sign-in.**
///
/// An `error` is the IdP's answer only when it echoes the `state` this process issued (RFC 6749
/// §4.1.2.1). A request without a `state`, or with somebody else's, is answered `400` and the listener
/// keeps waiting — so a local process cannot kill an operator's sign-in with one request, and the real
/// callback still completes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_error_callback_is_refused_and_the_login_keeps_waiting() {
    let (redirect_uri, state, flow) = start_loopback_flow().await;
    let http = reqwest::Client::new();

    for forged in [
        format!("{redirect_uri}?error=access_denied"),
        format!("{redirect_uri}?error=access_denied&state=not-the-issued-state"),
        // A wrong `state` is refused before the `error` is read, whichever order the parameters
        // arrive in.
        format!("{redirect_uri}?state=not-the-issued-state&error=server_error"),
    ] {
        let page = http
            .get(&forged)
            .send()
            .await
            .expect("the loopback listener answers a forged request");
        assert_eq!(page.status(), reqwest::StatusCode::BAD_REQUEST, "{forged}");
        assert!(
            !flow.is_finished(),
            "a forged `error` must not end the sign-in: {forged}"
        );
    }

    // The browser's real callback still completes the flow.
    let real = http
        .get(format!("{redirect_uri}?code=the-code&state={state}"))
        .send()
        .await
        .expect("the loopback listener answers the real request");
    assert_eq!(real.status(), reqwest::StatusCode::OK);
    let token = flow
        .await
        .expect("the flow task did not panic")
        .expect("the real callback completes the login");
    assert_eq!(token, "cli-access-token-value");
}

/// An `error` that *does* carry the issued `state` is genuinely the IdP's: it ends the sign-in with a
/// message naming the (plain, short) code, and nothing is exchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idp_error_with_the_issued_state_ends_the_sign_in() {
    let (redirect_uri, state, flow) = start_loopback_flow().await;

    let page = reqwest::get(format!("{redirect_uri}?error=access_denied&state={state}"))
        .await
        .expect("the loopback listener answers");
    assert_eq!(page.status(), reqwest::StatusCode::BAD_REQUEST);

    let error = flow
        .await
        .expect("the flow task did not panic")
        .expect_err("an IdP error ends the sign-in");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("refused the sign-in"), "{rendered}");
    assert!(rendered.contains("access_denied"), "{rendered}");
}

/// **`T19.2` final-round finding: the decoded `error` value was interpolated into the terminal.**
///
/// The query is percent-decoded, so an `error` can carry newlines, ANSI escapes or a forged
/// "stored the credential" line. Only a plain `[A-Za-z0-9_-.]` code of at most
/// [`MAX_ECHOED_ERROR_CODE_CHARS`] characters is echoed; anything else is omitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_sequence_in_an_error_is_never_echoed() {
    // A code shaped like an ANSI erase-line + a fake success line, plus a bell.
    let hostile = "\u{1b}[2K\rstored the credential\u{7}";
    let (redirect_uri, state, flow) = start_loopback_flow().await;
    let mut callback = reqwest::Url::parse(&redirect_uri).expect("an absolute loopback URL");
    callback
        .query_pairs_mut()
        .append_pair("error", hostile)
        .append_pair("state", &state);
    let page = reqwest::get(callback.as_str())
        .await
        .expect("the loopback listener answers");
    assert_eq!(page.status(), reqwest::StatusCode::BAD_REQUEST);

    let error = flow
        .await
        .expect("the flow task did not panic")
        .expect_err("a matching-state error ends the sign-in");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("refused the sign-in"), "{rendered}");
    for forbidden in ["\u{1b}", "\u{7}", "[2K", "stored the credential"] {
        assert!(
            !rendered.contains(forbidden),
            "the hostile value must not be echoed ({forbidden:?}): {rendered}"
        );
    }

    // An over-long value is a payload, not an error code: it is dropped rather than printed.
    let (redirect_uri, state, flow) = start_loopback_flow().await;
    let overlong = "a".repeat(MAX_ECHOED_ERROR_CODE_CHARS + 1);
    let mut callback = reqwest::Url::parse(&redirect_uri).expect("an absolute loopback URL");
    callback
        .query_pairs_mut()
        .append_pair("error", &overlong)
        .append_pair("state", &state);
    let page = reqwest::get(callback.as_str())
        .await
        .expect("the loopback listener answers");
    assert_eq!(page.status(), reqwest::StatusCode::BAD_REQUEST);
    let error = flow
        .await
        .expect("the flow task did not panic")
        .expect_err("a matching-state error ends the sign-in");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("refused the sign-in"), "{rendered}");
    assert!(
        !rendered.contains(&overlong),
        "an over-long value is not echoed: {rendered}"
    );
}

/// The echo clamp itself, without a socket: only plain, short tokens pass.
#[test]
fn the_echoed_error_code_is_clamped_to_a_plain_short_token() {
    assert_eq!(echoable_error_code("access_denied"), Some("access_denied"));
    assert_eq!(
        echoable_error_code("invalid-request.v2"),
        Some("invalid-request.v2")
    );
    assert_eq!(echoable_error_code(""), None, "an empty code says nothing");
    assert_eq!(echoable_error_code("a\u{1b}[2K"), None, "an ANSI escape");
    assert_eq!(echoable_error_code("two words"), None, "not a token");
    assert_eq!(echoable_error_code("é"), None, "non-ASCII");
    assert_eq!(echoable_error_code("a\nb"), None, "a newline");
    let longest = "a".repeat(MAX_ECHOED_ERROR_CODE_CHARS);
    assert_eq!(echoable_error_code(&longest), Some(longest.as_str()));
    assert_eq!(echoable_error_code(&format!("{longest}a")), None);
}

// ---------------------------------------------------------------------------
// Bounded, timed-out HTTP (the login path must not hang or over-allocate)
// ---------------------------------------------------------------------------

/// Starts a listener that accepts connections and then never answers.
async fn start_silent_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral loopback port");
    let address = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _peer)) = listener.accept().await {
            // Hold the connection open, answer nothing.
            held.push(stream);
        }
    });
    address
}

/// **`T19.2` review finding: the login's HTTP calls had no timeouts.**
///
/// A discovery endpoint that accepts the connection and then says nothing used to hang
/// `ferriscd login --oidc` until the operator gave up. The client now carries a total and a connect
/// timeout; the test injects a 50 ms total timeout against exactly that server, so the assertion is
/// about the timeout being enforced rather than about the production value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discovery_endpoint_that_never_answers_times_out() {
    let address = start_silent_server().await;
    let issuer = format!("http://127.0.0.1:{}", address.port());
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        discover_with(&issuer, true, std::time::Duration::from_millis(50)),
    )
    .await
    .expect("the client must give up on its own");
    let error = outcome.expect_err("a silent endpoint cannot produce a discovery document");
    let rendered = format!("{error:#}").to_lowercase();
    assert!(
        rendered.contains("timed out") || rendered.contains("timeout"),
        "the failure must name the timeout: {rendered}"
    );
}

/// **`T19.2` review finding: the login's HTTP calls read unbounded bodies.**
///
/// A discovery document (or token response) larger than [`MAX_HTTP_BODY_BYTES`] is refused instead of
/// being buffered into memory — the ceiling is checked against the declared length *and* while the
/// body streams in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_reply_is_refused_instead_of_buffered() {
    // A well-formed, `Transfer-Encoding: chunked` reply with no declared length: the streaming
    // ceiling is what must catch it, exactly like a discovery document that never ends.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral loopback port");
    let address = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        // Read the request head first: answering before it arrives (and then closing) makes the kernel
        // reset the connection and the client reports a transport error instead of the size ceiling.
        let mut head = Vec::new();
        let mut scratch = [0_u8; 1024];
        loop {
            match stream.read(&mut scratch).await {
                Ok(0) => return,
                Ok(read) => head.extend_from_slice(&scratch[..read]),
                Err(_) => return,
            }
            if head.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        if stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .is_err()
        {
            return;
        }
        let chunk = "a".repeat(8 * 1024);
        let chunks = MAX_HTTP_BODY_BYTES / chunk.len() + 4;
        for _ in 0..chunks {
            let framed = format!("{:x}\r\n{chunk}\r\n", chunk.len());
            if stream.write_all(framed.as_bytes()).await.is_err() {
                // The client hung up at the ceiling: that is the behaviour under test.
                return;
            }
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    });
    let issuer = format!("http://127.0.0.1:{}", address.port());
    let error = discover_with(&issuer, true, std::time::Duration::from_secs(5))
        .await
        .expect_err("an oversized document is refused");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&MAX_HTTP_BODY_BYTES.to_string()),
        "the error names the ceiling: {rendered}"
    );
    assert!(
        rendered.contains("larger than"),
        "the error is about the size, not a proxy failure: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// The minted token is verified against the server (finding: `--oidc` never verified)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sso_flow_verifies_the_minted_token_against_the_server() {
    let (address, recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let directory = tempfile::tempdir().expect("a scratch directory");
    let config_path = directory.path().join("config.json");

    let args = parse_login(&[
        "login",
        &server_url,
        "--oidc",
        "--no-browser",
        "--oidc-insecure-http",
    ])
    .expect("--oidc parses without --no-verify");
    assert!(!args.no_verify);

    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let command = tokio::spawn({
        let config_path = config_path.clone();
        async move {
            run_oidc_with(
                &args,
                &config_path,
                Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            )
            .await
        }
    });
    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .expect("the authorization URL parameter")
    };
    reqwest::get(format!(
        "{}?code=the-code&state={}",
        parameter("redirect_uri"),
        parameter("state")
    ))
    .await
    .expect("the loopback listener answers")
    .error_for_status()
    .expect("the browser page is a success");

    command
        .await
        .expect("the login task did not panic")
        .expect("the verified login completes");
    assert_eq!(
        recorded.clusters_requests(),
        1,
        "the minted token was checked with GET /api/v1/clusters before it was stored"
    );
    let stored =
        crate::client::StoredConfig::load_from(&config_path).expect("the credential is stored");
    assert_eq!(stored.token, "cli-access-token-value");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_the_server_refuses_is_never_stored() {
    let (address, recorded, _server) = start_mock_idp().await;
    recorded.refuse_clusters();
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let directory = tempfile::tempdir().expect("a scratch directory");
    let config_path = directory.path().join("config.json");

    let args = parse_login(&[
        "login",
        &server_url,
        "--sso",
        "--no-browser",
        "--oidc-insecure-http",
    ])
    .expect("the SSO flags parse");
    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let command = tokio::spawn({
        let config_path = config_path.clone();
        async move {
            run_oidc_with(
                &args,
                &config_path,
                Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            )
            .await
        }
    });
    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .expect("the authorization URL parameter")
    };
    reqwest::get(format!(
        "{}?code=the-code&state={}",
        parameter("redirect_uri"),
        parameter("state")
    ))
    .await
    .expect("the loopback listener answers")
    .error_for_status()
    .expect("the browser page is a success");

    let error = command
        .await
        .expect("the login task did not panic")
        .expect_err("a token the server refuses must fail the login");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("refused the SSO token"), "{rendered}");
    assert!(
        !rendered.contains("cli-access-token-value"),
        "the token is never echoed: {rendered}"
    );
    assert!(
        crate::client::StoredConfig::load_from(&config_path).is_err(),
        "nothing was written for a refused token"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_verify_skips_the_server_check() {
    let (address, recorded, _server) = start_mock_idp().await;
    let server_url = format!("http://127.0.0.1:{}", address.port());
    let directory = tempfile::tempdir().expect("a scratch directory");
    let config_path = directory.path().join("config.json");

    let args = parse_login(&[
        "login",
        &server_url,
        "--oidc",
        "--no-browser",
        "--no-verify",
        "--oidc-insecure-http",
    ])
    .expect("--oidc and --no-verify are no longer in conflict");
    assert!(args.no_verify);
    let (authorize_tx, mut authorize_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let command = tokio::spawn({
        let config_path = config_path.clone();
        async move {
            run_oidc_with(
                &args,
                &config_path,
                Some(Box::new(move |url: &str| {
                    let _ = authorize_tx.send(url.to_owned());
                })),
            )
            .await
        }
    });
    let authorize = authorize_rx.recv().await.expect("the authorization URL");
    let url = reqwest::Url::parse(&authorize).expect("an absolute URL");
    let parameter = |key: &str| {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .expect("the authorization URL parameter")
    };
    reqwest::get(format!(
        "{}?code=the-code&state={}",
        parameter("redirect_uri"),
        parameter("state")
    ))
    .await
    .expect("the loopback listener answers")
    .error_for_status()
    .expect("the browser page is a success");

    command
        .await
        .expect("the login task did not panic")
        .expect("--no-verify stores without a server check");
    assert_eq!(
        recorded.clusters_requests(),
        0,
        "--no-verify must not reach the clusters endpoint"
    );
    let stored =
        crate::client::StoredConfig::load_from(&config_path).expect("the credential is stored");
    assert_eq!(stored.token, "cli-access-token-value");
}

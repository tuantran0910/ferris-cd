//! `ferriscd login` — store a server URL and a credential (`T14.5`, `T19.2`).
//!
//! Two credentials are supported:
//!
//! * a **Kubernetes bearer token** (`--token`, `--token-file`, `$FERRISCD_TOKEN`, or a prompt at
//!   `$FERRISCD_TOKEN`), verified against the server before it is stored;
//! * **SSO** (`--oidc`, alias `--sso`), which runs an OAuth 2.1 Authorization Code + PKCE (`S256`)
//!   flow against the IdP the server advertises on `GET /api/v1/auth/config`.
//!
//! Either way the credential goes to `~/.config/ferriscd/config.json` with mode `0600` (or
//! `$FERRISCD_CONFIG`), never to a dotfile the shell sources, never to a URL parameter, and never to
//! the terminal echo: the token is not printed, not put in `argv` and not in an error message.
//!
//! The SSO flow is the RFC 8252 "native app" shape, which is what makes it safe without a client
//! secret:
//!
//! 1. bind an ephemeral `127.0.0.1:<random-port>` listener **before** anything is sent to the IdP;
//! 2. generate a 32-byte `state`, a 32-byte `nonce` and a 32-byte PKCE verifier from the OS CSPRNG
//!    (`getrandom`, via `ring`);
//! 3. print the authorization URL and open the system browser (a headless host simply follows the
//!    printed URL);
//! 4. wait — bounded by `--login-timeout-seconds` — for one `GET /callback?code=…&state=…` on the
//!    loopback listener, and refuse it when the `state` is not the one this process issued;
//! 5. exchange the code for an access token with the verifier, and store the token `0600`.
//!
//! Nothing on this path logs a code, a verifier or a token: the browser sees `state` and the S256
//! challenge (both public), and the terminal sees the server URL and the account's outcome.
//!
//! Two limits worth stating:
//!
//! * **The ID token's `nonce` is not verified here.** The `nonce` is generated and sent so the
//!   authorization request is a complete Authorization Code request, but this process has no reason to
//!   *trust* an ID token: it stores the **access token**, and every later request hands that to the
//!   server, which verifies `iss`/`aud`/`exp`/`nbf`/signature against the IdP's JWKS (`T19.1`).
//!   Parsing an ID token this client cannot verify would add ceremony, not security.
//! * **Every HTTP call is bounded.** The discovery document, the token endpoint and
//!   `GET /api/v1/auth/config` are fetched with a connect timeout, a total timeout, no redirect
//!   following and a [`MAX_HTTP_BODY_BYTES`] ceiling, mirroring `ferriscd_server::auth_bff`: a hostile
//!   or broken endpoint must not be able to hang the login or make it allocate without limit.
//! * **The minted token is verified against the server** (unless `--no-verify`), exactly like a
//!   pasted one: an SSO flow that "succeeds" against an IdP but produces a token the server refuses
//!   would otherwise write an unusable credential into `config.json`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Args;

use crate::client::{Client, StoredConfig, TOKEN_ENV, config_path, normalize_server_url};

/// How long the SSO flow waits for the browser callback by default.
pub const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// The largest callback request line + headers the loopback listener will read.
const MAX_CALLBACK_BYTES: usize = 16 * 1024;

/// The largest discovery / token endpoint response this client reads.
///
/// Mirrors `ferriscd_server::auth_bff::MAX_HTTP_BODY_BYTES`: both are JSON documents with a bounded
/// number of fields, so anything larger is a broken or hostile endpoint rather than a big answer.
const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;

/// How long one OIDC HTTP call may take in total (discovery, token exchange).
///
/// A login that hangs forever is worse than one that fails: the operator is left watching a
/// "waiting for the browser" prompt with no way to know the IdP never answered.
pub const OIDC_HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// How long establishing the TLS/TCP connection may take, separately from the total.
pub const OIDC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A hook the flow calls with the authorization URL once the loopback listener is bound.
///
/// Production passes `None`; the tests use it to play the browser deterministically (no sleeping to
/// wait for a port).
pub type AuthorizeUrlHook = Box<dyn Fn(&str) + Send + Sync>;

/// Arguments for `ferriscd login`.
///
/// `Debug` is written by hand: `token` is a credential and a derived `Debug` would print it the first
/// time anybody logged the parsed arguments.
#[derive(Args)]
pub struct LoginArgs {
    /// Base URL of `ferriscd-server` (for example https://ferriscd.example.com).
    #[arg(value_name = "SERVER_URL")]
    pub server_url: String,

    /// Kubernetes bearer token (a `ServiceAccount` token); prefer `--token-file` or
    /// `$FERRISCD_TOKEN` so it stays out of `ps` and your shell history.
    #[arg(
        long = "token",
        value_name = "TOKEN",
        env = "FERRISCD_TOKEN",
        hide_env_values = true,
        conflicts_with = "token_file"
    )]
    pub token: Option<String>,

    /// Read the token from a file (`kubectl create token ... > token`), where it is not visible in
    /// the process table.
    #[arg(long = "token-file", value_name = "PATH", conflicts_with = "token")]
    pub token_file: Option<PathBuf>,

    /// Do not check the token against the server before storing it.
    ///
    /// Applies to `--oidc` as well: the SSO access token is verified with `GET /api/v1/clusters`
    /// unless this flag is passed.
    #[arg(long = "no-verify")]
    pub no_verify: bool,

    /// Sign in with SSO (OIDC Authorization Code + PKCE `S256`) instead of pasting a token.
    ///
    /// Uses an ephemeral `127.0.0.1` loopback redirect and never sends a client secret. The access
    /// token the IdP mints is verified against the server before it is stored (see `--no-verify`).
    #[arg(long = "oidc", alias = "sso", conflicts_with_all = ["token", "token_file"])]
    pub oidc: bool,

    /// Do not try to launch a browser; print the authorization URL and wait for the callback
    /// (headless hosts, containers, remote sessions).
    #[arg(long = "no-browser", requires = "oidc")]
    pub no_browser: bool,

    /// How long to wait for the browser callback, in seconds.
    #[arg(
        long = "login-timeout-seconds",
        value_name = "SECONDS",
        default_value_t = DEFAULT_LOGIN_TIMEOUT.as_secs(),
        requires = "oidc"
    )]
    pub login_timeout_seconds: u64,

    /// Trust a plain-`http://` OIDC issuer (a local IdP on `kind`).
    ///
    /// Development only: in production the issuer must be `https://`.
    #[arg(long = "oidc-insecure-http", requires = "oidc")]
    pub oidc_insecure_http: bool,
}

impl std::fmt::Debug for LoginArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginArgs")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("token_file", &self.token_file)
            .field("no_verify", &self.no_verify)
            .field("oidc", &self.oidc)
            .field("no_browser", &self.no_browser)
            .field("login_timeout_seconds", &self.login_timeout_seconds)
            .field("oidc_insecure_http", &self.oidc_insecure_http)
            .finish()
    }
}

/// Executes `ferriscd login`.
///
/// # Errors
///
/// Fails when no credential is supplied, the URL is not absolute http(s), the server refuses the
/// token (unless `--no-verify`), the SSO flow is refused or times out, or the configuration cannot be
/// written.
pub async fn run(args: LoginArgs) -> Result<()> {
    if args.oidc {
        return run_oidc(&args).await;
    }
    // Reading the token file and writing the credential are blocking disk operations; they run on
    // the blocking pool so the command never stalls an async worker (AGENTS.md async hygiene), even
    // though a CLI process would rarely notice.
    let token = tokio::task::spawn_blocking({
        let token = args.token.clone();
        let token_file = args.token_file.clone();
        move || read_token(token.as_deref(), token_file.as_deref())
    })
    .await
    .context("reading the token panicked")??;
    let server_url = normalize_server_url(&args.server_url).context(
        "the server URL is not usable: pass an absolute http(s) URL, e.g. https://ferriscd.example.com",
    )?;

    if !args.no_verify {
        let client =
            Client::new(&server_url, token.clone()).context("cannot build the API client")?;
        let clusters = client
            .list_clusters()
            .await
            .context("the server refused the token, so nothing was stored")?;
        println!(
            "authenticated against {} ({} cluster(s) visible)",
            client.base_url(),
            clusters.items.len()
        );
    }

    store(&server_url, token).await
}

/// The `--oidc`/`--sso` half of `run`.
async fn run_oidc(args: &LoginArgs) -> Result<()> {
    let path = config_path()?;
    run_oidc_with(args, &path, None).await
}

/// [`run_oidc`] over an explicit credential path and (test-only) authorization-URL hook.
///
/// Split out so a test can drive the **whole** `ferriscd login --sso --no-browser` path — discovery,
/// PKCE, loopback callback, code exchange and the `0600` write — without touching the process
/// environment or a real browser.
async fn run_oidc_with(
    args: &LoginArgs,
    config_path: &Path,
    on_authorize_url: Option<AuthorizeUrlHook>,
) -> Result<()> {
    let server_url = normalize_server_url(&args.server_url).context(
        "the server URL is not usable: pass an absolute http(s) URL, e.g. https://ferriscd.example.com",
    )?;
    let token = oidc_flow(OidcFlowOptions {
        server_url: server_url.clone(),
        open_browser: !args.no_browser,
        timeout: Duration::from_secs(args.login_timeout_seconds.max(1)),
        allow_insecure_http: args.oidc_insecure_http,
        on_authorize_url,
    })
    .await?;
    // The IdP authenticated the operator; whether *this server* accepts the token it minted is a
    // second, independent question (`--auth-policy oidc` verifies the JWT locally, and an `aud`/`iss`
    // mismatch is exactly the mistake a local Dex setup makes). Verify it the same way a pasted token
    // is verified, so `config.json` never holds a credential the server refuses.
    if !args.no_verify {
        let client =
            Client::new(&server_url, token.clone()).context("cannot build the API client")?;
        let clusters = client
            .list_clusters()
            .await
            .context("the server refused the SSO token, so nothing was stored")?;
        println!(
            "authenticated against {} ({} cluster(s) visible)",
            client.base_url(),
            clusters.items.len()
        );
    }
    store_at(config_path, &server_url, token).await?;
    println!(
        "stored the credential for {server_url} in {}",
        config_path.display()
    );
    println!("next: `ferriscd app list`");
    Ok(())
}

/// Writes the credential `0600` at the resolved path and prints only non-secret facts.
async fn store(server_url: &str, token: String) -> Result<()> {
    let path = config_path()?;
    store_at(&path, server_url, token).await?;
    println!(
        "stored the credential for {server_url} in {}",
        path.display()
    );
    println!("next: `ferriscd app list`");
    Ok(())
}

/// Writes `StoredConfig` to `path` (mode `0600`), on the blocking pool.
///
/// Split out so the SSO flow's persistence is testable without the process environment: the test
/// points `path` at a temporary directory and asserts the mode.
async fn store_at(path: &Path, server_url: &str, token: String) -> Result<()> {
    let stored = StoredConfig {
        server_url: server_url.to_owned(),
        token,
    };
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || stored.save_to(&path))
        .await
        .context("storing the credential panicked")??;
    Ok(())
}

/// The token, from the flag, `$FERRISCD_TOKEN`, or a file.
///
/// # Errors
///
/// [`crate::client::ClientError::MissingToken`] when none is supplied, and a read failure for an
/// unreadable `--token-file`.
fn read_token(token: Option<&str>, token_file: Option<&Path>) -> Result<String> {
    if let Some(token) = token {
        let token = token.trim();
        anyhow::ensure!(!token.is_empty(), "the supplied token is empty");
        return Ok(token.to_owned());
    }
    if let Some(path) = token_file {
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read the token file {}", path.display()))?;
        let token = token.trim();
        anyhow::ensure!(
            !token.is_empty(),
            "the token file {} is empty",
            path.display()
        );
        return Ok(token.to_owned());
    }
    Err(crate::client::ClientError::MissingToken).context(format!(
        "no token was supplied; `ferriscd login` reads --token, --token-file or ${TOKEN_ENV}"
    ))
}

// ---------------------------------------------------------------------------
// The SSO flow (T19.2)
// ---------------------------------------------------------------------------

/// The endpoints the flow needs from the IdP's discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcEndpoints {
    /// Where the browser authenticates.
    pub authorization_endpoint: String,
    /// Where this process exchanges the code.
    pub token_endpoint: String,
}

/// Everything one `ferriscd login --oidc` run needs.
///
/// `on_authorize_url` is the seam the tests use: the flow calls it with the authorization URL *after*
/// the loopback listener is bound, so a test can play the browser without sleeping.
pub struct OidcFlowOptions {
    /// The `ferriscd-server` base URL (already normalized).
    pub server_url: String,
    /// Whether to try launching a browser (always printed either way).
    pub open_browser: bool,
    /// How long to wait for the loopback callback.
    pub timeout: Duration,
    /// Whether a plain-`http` issuer is trusted.
    pub allow_insecure_http: bool,
    /// Test hook: called with the authorization URL **after** the loopback listener is bound.
    pub on_authorize_url: Option<AuthorizeUrlHook>,
}

/// Runs the Authorization Code + PKCE (`S256`) flow and returns the access token.
///
/// The token is returned rather than stored so the caller (and a test) can decide where it goes; the
/// only thing this function prints is the authorization URL and a "waiting" line.
///
/// # Errors
///
/// Fails when the server advertises no OIDC configuration, the discovery document is unusable, the
/// loopback listener cannot bind, the callback state does not match, the IdP refuses the exchange, or
/// the wait exceeds `timeout`.
pub async fn oidc_flow(options: OidcFlowOptions) -> Result<String> {
    use ferriscd_server::auth_bff::{PkcePair, authorize_url, random_urlsafe_token};

    let config = crate::client::fetch_auth_config(&options.server_url)
        .await
        .context("cannot read GET /api/v1/auth/config from the server")?;
    let Some(issuer) = config.issuer.clone() else {
        anyhow::bail!(
            "the server does not advertise an OIDC issuer (authMode {:?}), so `--oidc` cannot be \
             used; run `ferriscd login {url} --token-file <path>` instead",
            config.auth_mode,
            url = options.server_url
        );
    };
    let Some(client_id) = config.client_id.clone() else {
        anyhow::bail!("the server advertises an OIDC issuer but no client id");
    };
    let endpoints = discover(&issuer, options.allow_insecure_http).await?;

    // Bind before anything is sent to the IdP: the redirect URI has to name the real port, and a
    // browser that comes back early must find a listener already waiting.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("cannot bind the loopback callback listener on 127.0.0.1")?;
    let address = listener
        .local_addr()
        .context("cannot read the loopback listener address")?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", address.port());

    let pkce = PkcePair::generate().context("the OS CSPRNG refused to generate a PKCE verifier")?;
    let state = random_urlsafe_token().context("the OS CSPRNG refused to generate a state")?;
    let nonce = random_urlsafe_token().context("the OS CSPRNG refused to generate a nonce")?;
    let authorize = authorize_url(
        &endpoints.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &config.scopes,
        &state,
        &nonce,
        &pkce.challenge,
    )
    .context("cannot build the authorization URL")?;

    println!(
        "opening the browser to sign in to {server} (redirect {redirect})",
        server = options.server_url,
        redirect = redirect_uri
    );
    println!("if nothing opens, visit: {authorize}");
    if options.open_browser {
        // Spawning a browser is blocking; the failure is not fatal (a headless host has no browser,
        // and the URL above is enough).
        let _ = tokio::task::spawn_blocking({
            let url = authorize.clone();
            move || open_browser(&url)
        })
        .await;
    }
    if let Some(callback) = options.on_authorize_url.as_ref() {
        callback(&authorize);
    }

    let code = tokio::time::timeout(options.timeout, await_callback(listener, &state))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "no browser callback arrived within {}s; run `ferriscd login --oidc` again",
                options.timeout.as_secs()
            )
        })??;

    let token = exchange_code(
        &endpoints.token_endpoint,
        &client_id,
        &code,
        &pkce.verifier,
        &redirect_uri,
        options.allow_insecure_http,
    )
    .await?;
    println!("signed in via SSO (the access token is never printed)");
    Ok(token)
}

/// Fetches and validates `<issuer>/.well-known/openid-configuration`.
async fn discover(issuer: &str, allow_insecure_http: bool) -> Result<OidcEndpoints> {
    discover_with(issuer, allow_insecure_http, OIDC_HTTP_TIMEOUT).await
}

/// [`discover`] with an explicit total timeout (the seam a test uses to prove it is enforced).
async fn discover_with(
    issuer: &str,
    allow_insecure_http: bool,
    timeout: Duration,
) -> Result<OidcEndpoints> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let parsed = reqwest::Url::parse(&url).context("the issuer is not an absolute URL")?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_insecure_http => {}
        _ => anyhow::bail!(
            "the issuer {issuer} is not https; a local IdP needs --oidc-insecure-http (development \
             only)"
        ),
    }
    let http = http_client_with(timeout, OIDC_CONNECT_TIMEOUT.min(timeout))?;
    let response = http
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("cannot fetch {url}"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "the identity provider answered HTTP {} for {url}",
        response.status().as_u16()
    );
    let document: serde_json::Value = read_bounded_json(response, &url).await?;
    let document_issuer = document
        .get("issuer")
        .and_then(serde_json::Value::as_str)
        .context("the discovery document has no `issuer`")?;
    anyhow::ensure!(
        document_issuer.trim_end_matches('/') == issuer.trim_end_matches('/'),
        "the discovery document's issuer does not match the server's configured issuer"
    );
    let endpoint = |key: &str| -> Result<String> {
        let value = document
            .get(key)
            .and_then(serde_json::Value::as_str)
            .with_context(|| format!("the discovery document has no `{key}`"))?;
        let parsed = reqwest::Url::parse(value)
            .with_context(|| format!("`{key}` is not an absolute URL"))?;
        match parsed.scheme() {
            "https" => {}
            "http" if allow_insecure_http => {}
            _ => anyhow::bail!("`{key}` must be an https URL"),
        }
        Ok(value.to_owned())
    };
    Ok(OidcEndpoints {
        authorization_endpoint: endpoint("authorization_endpoint")?,
        token_endpoint: endpoint("token_endpoint")?,
    })
}

/// Waits for exactly one **valid** callback and returns the authorization code.
///
/// The `state` is compared here, before the code is used: a mismatch is a refusal, not a warning, and
/// the code is never exchanged. A refused request does **not** end the login, though — the loopback
/// listener is open to the whole machine, so anything can connect to it (a scanner, another local
/// process, a stale browser tab replaying an old callback). Answering the first bad request with a
/// fatal error meant a *single* forged `GET /callback?state=…` could abort an operator's sign-in; the
/// forged request is answered `400` and the listener keeps waiting for the real one (bounded by
/// `--login-timeout-seconds`). A request head larger than [`MAX_CALLBACK_BYTES`] is answered `431` for
/// the same reason — it is unparseable, not a verdict about the sign-in.
///
/// An IdP-side `error=` **is** terminal, but only when it carries the `state` this process issued:
/// RFC 6749 §4.1.2.1 requires `state` on an error response, and without that check a local process
/// could abort the sign-in by sending one forged `GET /callback?error=…`. An `error` with a missing or
/// different `state` is answered `400` and the listener keeps waiting. The code itself is echoed only
/// when it is a short, plain `[A-Za-z0-9_-.]` token ([`echoable_error_code`]): it is attacker-influenced
/// output headed for a terminal, so an ANSI/control sequence must never reach it.
async fn await_callback(listener: tokio::net::TcpListener, expected_state: &str) -> Result<String> {
    use tokio::io::AsyncReadExt as _;

    loop {
        let (mut stream, _peer) = listener
            .accept()
            .await
            .context("the loopback listener failed")?;
        let mut buffer = Vec::with_capacity(1024);
        let mut chunk = [0_u8; 1024];
        // Read until the request head is complete; the body (there is none for a GET) is ignored.
        let mut oversized = false;
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .context("reading the browser callback failed")?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > MAX_CALLBACK_BYTES {
                oversized = true;
                break;
            }
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        if oversized {
            // A head bigger than any callback a browser sends is a request this listener cannot
            // parse, not a verdict about the sign-in: answer `431` and keep waiting, for the same
            // reason a forged `state` is answered `400` rather than aborting (see the item docs).
            let _ = respond(&mut stream, 431, "request header too large").await;
            continue;
        }
        let request = String::from_utf8_lossy(&buffer);
        let Some(request_line) = request.lines().next() else {
            continue;
        };
        let mut parts = request_line.split_whitespace();
        let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
            // A browser may open a speculative connection (`/favicon.ico`); keep waiting.
            let _ = respond(&mut stream, 400, "bad request").await;
            continue;
        };
        if method != "GET" {
            let _ = respond(&mut stream, 405, "method not allowed").await;
            continue;
        }
        let Some(query) = target.split_once('?').map(|(_, query)| query) else {
            let _ = respond(&mut stream, 404, "not found").await;
            continue;
        };
        let params: Vec<(String, String)> =
            reqwest::Url::parse(&format!("http://127.0.0.1/?{query}"))
                .map(|url| {
                    url.query_pairs()
                        .map(|(key, value)| (key.into_owned(), value.into_owned()))
                        .collect()
                })
                .unwrap_or_default();
        let get = |name: &str| {
            params
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };

        let state = get("state");
        if let Some(error) = get("error") {
            // An `error` is only this sign-in's IdP answer when it echoes the `state` we issued
            // (RFC 6749 §4.1.2.1). Anything else is a forged request from the same machine, and
            // aborting on it would hand any local process a one-request kill switch — so it is
            // answered `400` and the listener keeps waiting, exactly like a wrong `state` below.
            if state.as_deref() != Some(expected_state) {
                let _ = respond(&mut stream, 400, "unexpected callback").await;
                continue;
            }
            let _ = respond(&mut stream, 400, "sign-in failed").await;
            return Err(match echoable_error_code(&error) {
                Some(code) => {
                    anyhow::anyhow!("the identity provider refused the sign-in (error {code})")
                }
                // Not a plain, short error code: print nothing rather than hand a control sequence
                // (or a wall of text) to the terminal.
                None => anyhow::anyhow!("the identity provider refused the sign-in"),
            });
        }
        let Some(state) = state else {
            // Not this process's callback (or a truncated request): refuse it, keep waiting.
            let _ = respond(&mut stream, 400, "missing state").await;
            continue;
        };
        if state != expected_state {
            // A cross-site, forged or replayed callback: refuse it and keep waiting for the real one.
            let _ = respond(&mut stream, 400, "state mismatch").await;
            continue;
        }
        let Some(code) = get("code") else {
            let _ = respond(&mut stream, 400, "missing code").await;
            continue;
        };
        let _ = respond(
            &mut stream,
            200,
            "signed in to FerrisCD — you can close this tab and return to the terminal",
        )
        .await;
        return Ok(code);
    }
}

/// The longest `error` value this client will repeat on the terminal.
///
/// The real codes are short (`access_denied`); anything past this is not an error code but a payload,
/// and there is no reason to print it.
const MAX_ECHOED_ERROR_CODE_CHARS: usize = 64;

/// The IdP's `error` code, if it is safe to write to a terminal.
///
/// The callback query is percent-decoded before it gets here, so the value can hold any byte an
/// attacker chose — newlines, ANSI escapes, a fake "stored the credential" line. Only plain
/// `[A-Za-z0-9_-.]` tokens of at most [`MAX_ECHOED_ERROR_CODE_CHARS`] are echoed; anything else is
/// dropped, and the operator still sees the real code on the IdP's own page.
fn echoable_error_code(error: &str) -> Option<&str> {
    let printable = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
    (!error.is_empty()
        && error.chars().count() <= MAX_ECHOED_ERROR_CODE_CHARS
        && error.chars().all(printable))
    .then_some(error)
}

/// Writes a tiny HTML page to the browser and closes the connection.
async fn respond(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    message: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>FerrisCD</title>\
         <body style=\"font-family:system-ui;padding:2rem\"><h1>FerrisCD</h1><p>{message}</p>"
    );
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        reason_phrase(status),
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// The reason phrase for one of the loopback listener's statuses.
///
/// Spelled out rather than defaulted to `Bad Request`: a `405 Method Not Allowed` answered with the
/// reason phrase "Bad Request" is a lie in the one place an operator debugs by hand (visiting the
/// callback URL directly), and an unknown status must not borrow another status's words either.
const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Unknown",
    }
}

/// Exchanges the code for an access token (public client: no secret, PKCE verifier instead).
async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    allow_insecure_http: bool,
) -> Result<String> {
    let parsed = reqwest::Url::parse(token_endpoint).context("the token endpoint is not a URL")?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_insecure_http => {}
        _ => anyhow::bail!("the token endpoint must be an https URL"),
    }
    // `application/x-www-form-urlencoded` via `Url`'s own percent encoder: the verifier may contain
    // `-`/`_` and the code may contain `+`/`/`.
    let mut form =
        reqwest::Url::parse("https://form.invalid/").context("cannot build the token request")?;
    {
        let mut query = form.query_pairs_mut();
        query.append_pair("grant_type", "authorization_code");
        query.append_pair("code", code);
        query.append_pair("code_verifier", verifier);
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("client_id", client_id);
    }
    let body = form.query().unwrap_or_default().to_owned();
    let response = http_client_with(OIDC_HTTP_TIMEOUT, OIDC_CONNECT_TIMEOUT)?
        .post(token_endpoint)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(body)
        .send()
        .await
        .context("the token endpoint could not be reached")?;
    let status = response.status();
    if !status.is_success() {
        // The body is not quoted: an IdP error document can echo the code or the verifier.
        anyhow::bail!(
            "the identity provider refused the authorization code exchange (HTTP {})",
            status.as_u16()
        );
    }
    let document: serde_json::Value = read_bounded_json(response, "the token endpoint").await?;
    let token = document
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned();
    anyhow::ensure!(
        !token.is_empty(),
        "the identity provider returned no access token"
    );
    Ok(token)
}

/// The `reqwest` client every OIDC call uses: process TLS provider, bounded timeouts, no redirects.
///
/// The timeouts are parameters rather than constants so a test can prove they are actually enforced
/// (the production call sites always pass [`OIDC_HTTP_TIMEOUT`] / [`OIDC_CONNECT_TIMEOUT`]). No
/// redirect following, like `ferriscd_server::auth_bff`: a discovery document that answers `302` to
/// another host is not a document this client should chase.
fn http_client_with(timeout: Duration, connect_timeout: Duration) -> Result<reqwest::Client> {
    ferriscd_controller::impersonation::ensure_crypto_provider();
    reqwest::Client::builder()
        .user_agent(concat!("ferriscd/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("cannot build the HTTP client")
}

/// Reads a JSON response body of at most [`MAX_HTTP_BODY_BYTES`].
///
/// The body is read chunk by chunk and abandoned at the ceiling: `.json()` would happily buffer
/// whatever the endpoint sends (the discovery and token endpoints are attacker-influenced in a
/// misconfigured deployment).
async fn read_bounded_json(
    mut response: reqwest::Response,
    what: &str,
) -> Result<serde_json::Value> {
    if let Some(declared) = response.content_length()
        && declared > MAX_HTTP_BODY_BYTES as u64
    {
        anyhow::bail!("{what} announced a reply larger than {MAX_HTTP_BODY_BYTES} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("reading the reply from {what} failed"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_HTTP_BODY_BYTES {
            anyhow::bail!("the reply from {what} is larger than {MAX_HTTP_BODY_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).with_context(|| format!("{what} did not answer with JSON"))
}

/// Opens `url` in the system browser. Returns whether a launch command was started.
///
/// Blocking (it spawns a process); the caller runs it on the blocking pool. A failure is expected on a
/// headless host and is only reported, never fatal — the URL is printed either way.
fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let (program, args) = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let (program, args) = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let (program, args) = ("xdg-open", vec![url]);

    match std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => true,
        Err(error) => {
            eprintln!("could not launch a browser ({error}); use the URL printed above");
            false
        }
    }
}

#[cfg(test)]
mod tests;

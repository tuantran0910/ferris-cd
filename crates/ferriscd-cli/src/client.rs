//! The `ferriscd` API client (`T14.5`).
//!
//! One-thin-wrapper-per-endpoint over `reqwest`, talking to `ferriscd-server`'s documented REST API
//! (`docs/api/openapi.json`). Two rules shape this module:
//!
//! * **The server owns the payload.** Every method returns `ferriscd_server::api`'s own DTO, so the
//!   CLI cannot invent a shape the OpenAPI contract does not declare — and, in particular, cannot
//!   re-derive or un-redact a diff: the `Secret` redaction happens in the engine, before the bytes
//!   leave the server, and the CLI only renders what it was given.
//! * **The token is a credential.** It is stored in `~/.config/ferriscd/config.json` with mode
//!   `0600`, sent only in an `Authorization` header, and never rendered: [`Connection`] and
//!   [`Client`] both write their own `Debug`, [`ClientError`] never quotes it, and no code path
//!   prints a request header.
//!
//! Exit codes are not this module's business; it returns typed results and
//! [`ClientError`]s, and `main` maps them onto `0`/`1`/`2`.

use std::path::{Path, PathBuf};

use ferriscd_server::api::{
    ApplicationDetailView, ApplicationListView, ClusterListView, DiffView, OperationResponse,
    ProjectListView,
};
use ferriscd_server::error::ApiErrorBody;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Overrides the location of `config.json` (tests and CI use it).
pub const CONFIG_ENV: &str = "FERRISCD_CONFIG";

/// Overrides the stored server URL.
pub const SERVER_ENV: &str = "FERRISCD_SERVER";

/// Overrides the stored bearer token (the CI-friendly way: never on the command line).
pub const TOKEN_ENV: &str = "FERRISCD_TOKEN";

/// Name of the control-plane namespace, used when a name is given without one.
pub const DEFAULT_NAMESPACE: &str = ferriscd_crd::CONTROL_PLANE_NAMESPACE;

/// Directory (under `$XDG_CONFIG_HOME` or `~/.config`) that holds `config.json`.
const CONFIG_DIR: &str = "ferriscd";

/// File name of the stored credential.
const CONFIG_FILE: &str = "config.json";

/// Everything that can go wrong on the client side.
///
/// No variant, and no `Display`, ever contains the bearer token or a response body: a credential
/// pasted into an error message ends up in shell history, a CI log, and a bug report.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// There is no stored configuration and none was supplied.
    #[error(
        "not logged in: no credential at {path}. Run `ferriscd login <server-url> --token <token>` \
         (or set {TOKEN_ENV})"
    )]
    NotLoggedIn {
        /// Where the CLI looked.
        path: PathBuf,
    },

    /// Neither `$XDG_CONFIG_HOME` nor `$HOME` is set, so the config path cannot be computed.
    #[error("cannot locate the configuration directory: neither $XDG_CONFIG_HOME nor $HOME is set")]
    NoHome,

    /// The stored configuration exists but cannot be used.
    #[error("the stored configuration at {path} is unusable: {reason}")]
    Config {
        /// The file that was read.
        path: PathBuf,
        /// What is wrong with it (never its contents).
        reason: String,
    },

    /// The configuration could not be written.
    #[error("the configuration at {path} could not be written: {source}")]
    ConfigWrite {
        /// The file that was to be written.
        path: PathBuf,
        /// The I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The server URL is not an absolute `http`/`https` URL.
    #[error(
        "`{url}` is not a usable server URL: expected an absolute http:// or https:// URL (for \
         example https://ferriscd.example.com or http://127.0.0.1:8080)"
    )]
    InvalidUrl {
        /// What was given.
        url: String,
    },

    /// No token was supplied on `login`.
    #[error(
        "no token was supplied: pass --token <token>, --token-file <path>, or set {TOKEN_ENV} \
         (a Kubernetes ServiceAccount token, e.g. `kubectl create token <sa> -n <namespace>`)"
    )]
    MissingToken,

    /// The request never completed (DNS, TCP, TLS, timeout).
    #[error("{method} {url} failed: {message}")]
    Transport {
        /// HTTP method.
        method: String,
        /// The absolute URL that was attempted (never a header).
        url: String,
        /// The transport's explanation.
        message: String,
    },

    /// The server answered `401`: the token is missing, expired, or not accepted.
    #[error(
        "{method} {url} was not authenticated ({code}): {message}. Run `ferriscd login \
         <server-url> --token <token>` with a fresh Kubernetes token"
    )]
    Unauthenticated {
        /// HTTP method.
        method: String,
        /// The URL that was refused.
        url: String,
        /// The server's stable error code.
        code: String,
        /// The server's explanation (bounded, secret-free).
        message: String,
    },

    /// The server answered `403`: the token is valid but not authorized for this project.
    #[error(
        "{method} {url} is not permitted ({code}): {message}. Ask a cluster administrator for an \
         `AppProject` grant in `{RBAC_CONFIGMAP_HINT}`"
    )]
    Forbidden {
        /// HTTP method.
        method: String,
        /// The URL that was refused.
        url: String,
        /// The server's stable error code.
        code: String,
        /// The server's explanation (bounded, secret-free).
        message: String,
    },

    /// Any other non-2xx answer.
    #[error("{method} {url} failed with HTTP {status} ({code}): {message}")]
    Api {
        /// HTTP method.
        method: String,
        /// The URL that failed.
        url: String,
        /// The HTTP status code.
        status: u16,
        /// The server's stable error code (`NotFound`, `Conflict`, ...).
        code: String,
        /// The server's explanation (bounded, secret-free).
        message: String,
    },

    /// The response was not the JSON this CLI understands.
    #[error("{method} {url} answered with a body the CLI cannot read: {message}")]
    Decode {
        /// HTTP method.
        method: String,
        /// The URL that answered.
        url: String,
        /// The decoding failure.
        message: String,
    },
}

/// The `ConfigMap` an operator grants project access in, for the `403` hint.
const RBAC_CONFIGMAP_HINT: &str = "ferriscd-rbac-cm";

/// Where the credential lives and what it is.
///
/// `Debug` renders the URL and `token: <redacted>`: this type is logged at most once per command, and
/// a `{:?}` in a panic message must not publish the credential.
#[derive(Clone, PartialEq, Eq)]
pub struct Connection {
    /// Base URL of the API server (no trailing slash).
    pub server_url: String,
    /// Bearer token (a Kubernetes `ServiceAccount` token).
    pub token: String,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("server_url", &self.server_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Connection {
    /// Resolves the connection from explicit values, then environment overrides, then the file.
    ///
    /// `server`/`token` are the command's own flags (`--server-url`, `--token`); `None` means "not
    /// given here", which is when `FERRISCD_SERVER`/`FERRISCD_TOKEN` and finally
    /// `config.json` are consulted.
    /// Every `ferriscd` command runs inside the async runtime, so the `config.json` read happens on
    /// the blocking pool rather than on an executor thread (the `docs/REVIEW_LOG.md` §`v1.0`
    /// follow-up, closed by `T19.2`).
    ///
    /// # Errors
    ///
    /// [`ClientError::NotLoggedIn`] when nothing is stored, [`ClientError::Config`] when the stored
    /// file is unusable, [`ClientError::InvalidUrl`] for a URL that is not absolute http(s).
    pub async fn resolve_async(
        server: Option<&str>,
        token: Option<&str>,
    ) -> Result<Self, ClientError> {
        let stored = if server.is_none() || token.is_none() {
            StoredConfig::load_if_present_async().await?
        } else {
            None
        };
        Self::resolve_from(server, token, stored)
    }

    /// The shared resolution order, over an already-read (or absent) stored configuration.
    fn resolve_from(
        server: Option<&str>,
        token: Option<&str>,
        stored: Option<StoredConfig>,
    ) -> Result<Self, ClientError> {
        let server_url = server
            .map(ToOwned::to_owned)
            .or_else(|| std::env::var(SERVER_ENV).ok().filter(|url| !url.is_empty()))
            .or_else(|| stored.as_ref().map(|stored| stored.server_url.clone()))
            .ok_or_else(|| ClientError::NotLoggedIn {
                path: config_path().unwrap_or_else(|_| PathBuf::from("config.json")),
            })?;
        let token = token
            .map(ToOwned::to_owned)
            .or_else(|| {
                std::env::var(TOKEN_ENV)
                    .ok()
                    .filter(|token| !token.is_empty())
            })
            .or_else(|| stored.as_ref().map(|stored| stored.token.clone()))
            .ok_or(ClientError::MissingToken)?;
        Ok(Self {
            server_url: normalize_server_url(&server_url)?,
            token: trim_token(token),
        })
    }

    /// The connection a `login` is about to store (tests build one directly).
    #[must_use]
    #[cfg(test)]
    pub fn new(server_url: &str, token: &str) -> Self {
        Self {
            server_url: server_url.to_owned(),
            token: token.to_owned(),
        }
    }
}

/// Normalizes a server URL: absolute `http`/`https`, no trailing slash.
///
/// # Errors
///
/// [`ClientError::InvalidUrl`] for anything else (a bare host, a `file://` URL, a relative path): a
/// CLI that silently guesses `http://` would send a bearer token to an attacker-chosen host.
pub fn normalize_server_url(url: &str) -> Result<String, ClientError> {
    let url = url.trim();
    let parsed = reqwest::Url::parse(url).map_err(|_| ClientError::InvalidUrl {
        url: redact_userinfo(url),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(ClientError::InvalidUrl {
            url: redact_userinfo(url),
        });
    }
    Ok(url.trim_end_matches('/').to_owned())
}

/// Strips `user:password@` from a URL before it is quoted in an error.
///
/// A pasted URL can carry credentials (`https://oauth2:<token>@…`); the rejection message is the one
/// place the CLI would otherwise echo them, into a terminal and a CI log.
fn redact_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let (authority_end, suffix) = match rest.find(['/', '?', '#']) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    match authority_end.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://***@{host}{suffix}"),
        None => url.to_owned(),
    }
}

/// Trims whitespace/newlines from a token (`kubectl create token` output is usually piped through a
/// file or an env var, which adds a trailing newline).
fn trim_token(token: String) -> String {
    token.trim().to_owned()
}

/// The stored credential file (`~/.config/ferriscd/config.json`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredConfig {
    /// Base URL of the API server.
    pub server_url: String,
    /// Bearer token.
    pub token: String,
}

impl StoredConfig {
    /// Reads the configuration at `path`.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotLoggedIn`] when the file does not exist, [`ClientError::Config`] when it is
    /// not the documented JSON.
    pub fn load_from(path: &Path) -> Result<Self, ClientError> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(ClientError::NotLoggedIn {
                    path: path.to_path_buf(),
                });
            }
            Err(err) => {
                return Err(ClientError::Config {
                    path: path.to_path_buf(),
                    reason: err.to_string(),
                });
            }
        };
        let stored: Self = serde_json::from_str(&raw).map_err(|err| ClientError::Config {
            path: path.to_path_buf(),
            reason: format!(
                "not the documented JSON (line {}, column {})",
                err.line(),
                err.column()
            ),
        })?;
        Ok(stored)
    }

    /// Reads the configuration at the resolved path on the blocking pool, or `Ok(None)` when it does
    /// not exist.
    ///
    /// # Errors
    ///
    /// [`ClientError::Config`] when the file exists but is unusable, or when the blocking read panics.
    pub async fn load_if_present_async() -> Result<Option<Self>, ClientError> {
        let path = config_path()?;
        let report = path.clone();
        match tokio::task::spawn_blocking(move || Self::read_or_absent(&path)).await {
            Ok(result) => result,
            Err(_) => Err(ClientError::Config {
                path: report,
                reason: "the configuration read panicked".to_owned(),
            }),
        }
    }

    /// [`Self::load_from`] over a known path, mapping "no such file" to `Ok(None)`.
    fn read_or_absent(path: &Path) -> Result<Option<Self>, ClientError> {
        match Self::load_from(path) {
            Ok(stored) => Ok(Some(stored)),
            Err(ClientError::NotLoggedIn { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Writes the configuration to `path` with mode `0600` (`0700` for the directory).
    ///
    /// # Errors
    ///
    /// [`ClientError::ConfigWrite`] when the directory or the file cannot be created.
    pub fn save_to(&self, path: &Path) -> Result<(), ClientError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| ClientError::ConfigWrite {
                path: path.to_path_buf(),
                source,
            })?;
            restrict_permissions(parent, 0o700).map_err(|source| ClientError::ConfigWrite {
                path: path.to_path_buf(),
                source,
            })?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|err| ClientError::Config {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
        write_private(path, &format!("{json}\n")).map_err(|source| ClientError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Writes `contents` to `path` with mode `0600` from the first byte.
///
/// The mode is set at `create` time (not after the write) so the credential is never briefly
/// world-readable, and it is re-applied afterwards to fix a pre-existing file with a wider mode.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    file.write_all(contents.as_bytes())?;
    file.flush()?;
    drop(file);
    restrict_permissions(path, 0o600)
}

/// Restricts `path` to `mode` (a no-op off unix).
#[cfg(unix)]
fn restrict_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// The configuration path: `$FERRISCD_CONFIG`, else `$XDG_CONFIG_HOME/ferriscd/config.json`, else
/// `$HOME/.config/ferriscd/config.json`.
///
/// # Errors
///
/// [`ClientError::NoHome`] when no home directory can be determined.
pub fn config_path() -> Result<PathBuf, ClientError> {
    resolve_config_path(
        std::env::var_os(CONFIG_ENV).as_deref(),
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// The pure half of [`config_path`], so the precedence is testable without touching the environment.
///
/// # Errors
///
/// [`ClientError::NoHome`] when none of the three sources yields a path.
pub fn resolve_config_path(
    explicit: Option<&std::ffi::OsStr>,
    xdg_config_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, ClientError> {
    if let Some(explicit) = explicit.filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(explicit));
    }
    if let Some(xdg) = xdg_config_home.filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(xdg).join(CONFIG_DIR).join(CONFIG_FILE));
    }
    let Some(home) = home.filter(|path| !path.is_empty()) else {
        return Err(ClientError::NoHome);
    };
    Ok(PathBuf::from(home)
        .join(".config")
        .join(CONFIG_DIR)
        .join(CONFIG_FILE))
}

/// A client for one `ferriscd-server`, holding one credential.
pub struct Client {
    base: reqwest::Url,
    token: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Builds a client for `server_url` authenticating as `token`.
    ///
    /// # Errors
    ///
    /// [`ClientError::InvalidUrl`] for a non-http(s) URL and [`ClientError::Transport`] when the
    /// underlying `reqwest` client cannot be built.
    pub fn new(server_url: &str, token: impl Into<String>) -> Result<Self, ClientError> {
        // Both `kube` (ring) and `gix`'s `reqwest` (aws-lc-rs) are linked into this binary; install
        // the controller's process-level provider so a TLS connection cannot fail (or panic) on an
        // ambiguous provider choice.
        ferriscd_controller::impersonation::ensure_crypto_provider();
        let normalized = normalize_server_url(server_url)?;
        // The base always ends in `/` so a relative `join` cannot drop a path prefix.
        let base = reqwest::Url::parse(&format!("{normalized}/"))
            .map_err(|_| ClientError::InvalidUrl { url: normalized })?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("ferriscd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| ClientError::Transport {
                method: "CLIENT".to_owned(),
                url: base.to_string(),
                message: err.to_string(),
            })?;
        Ok(Self {
            base,
            token: trim_token(token.into()),
            http,
        })
    }

    /// Builds a client from the command's flags, the environment, or the stored configuration.
    ///
    /// The stored-credential read happens on the blocking pool (`T19.2`), so this is safe to call from
    /// any subcommand's async body.
    ///
    /// # Errors
    ///
    /// See [`Connection::resolve_async`] and [`Self::new`].
    pub async fn connect_async(
        server: Option<&str>,
        token: Option<&str>,
    ) -> Result<Self, ClientError> {
        let connection = Connection::resolve_async(server, token).await?;
        Self::from_connection(connection)
    }

    /// Builds the client from a resolved [`Connection`] (with the plain-HTTP warning).
    fn from_connection(connection: Connection) -> Result<Self, ClientError> {
        if connection.server_url.starts_with("http://") && !is_loopback(&connection.server_url) {
            eprintln!(
                "warning: {} is plain HTTP, so the bearer token is sent in clear text; use https:// \
                 for anything but a local port-forward",
                connection.server_url
            );
        }
        Self::new(&connection.server_url, connection.token)
    }

    /// The base URL this client talks to (no credential).
    #[must_use]
    pub fn base_url(&self) -> &str {
        self.base.as_str().trim_end_matches('/')
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let url = self.url(path)?;
        let response = self
            .http
            .get(url.clone())
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| transport("GET", &url, &err))?;
        decode("GET", &url, response).await
    }

    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ClientError> {
        let url = self.url(path)?;
        let response = self
            .http
            .post(url.clone())
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(body)
            .send()
            .await
            .map_err(|err| transport("POST", &url, &err))?;
        decode("POST", &url, response).await
    }

    fn url(&self, path: &str) -> Result<String, ClientError> {
        let joined = self.base.join(path).map_err(|_| ClientError::InvalidUrl {
            url: format!("{}{path}", self.base),
        })?;
        Ok(joined.to_string())
    }

    /// `GET /api/v1/applications` — every `Application` the caller may see.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`]. A `403`/`404` cannot occur here: the server filters the list.
    pub async fn list_applications(&self) -> Result<ApplicationListView, ClientError> {
        self.get("api/v1/applications").await
    }

    /// `GET /api/v1/applications/{namespace}/{name}`.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`]; `404` also covers "exists but not visible to you" (`T14.4`).
    pub async fn get_application(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<ApplicationDetailView, ClientError> {
        self.get(&format!("api/v1/applications/{}/{name}", encode(namespace)))
            .await
    }

    /// `GET /api/v1/applications/{namespace}/{name}/diff`.
    ///
    /// The payload is already `Secret`-redacted by the server: this method hands it through
    /// untouched, which is what makes "the CLI never prints a raw `Secret`" true by construction
    /// rather than by careful rendering.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`].
    pub async fn diff(&self, namespace: &str, name: &str) -> Result<DiffView, ClientError> {
        self.get(&format!(
            "api/v1/applications/{}/{name}/diff",
            encode(namespace)
        ))
        .await
    }

    /// `POST /api/v1/applications/{namespace}/{name}/sync`.
    ///
    /// `prune` is forwarded verbatim: `v1.0` servers answer `422` for it (pruning is a spec field),
    /// and silently dropping the flag would report a sync that did not prune anything.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`], including the server's `422` for a body it cannot honour.
    pub async fn sync(
        &self,
        namespace: &str,
        name: &str,
        prune: bool,
    ) -> Result<OperationResponse, ClientError> {
        let body = if prune {
            serde_json::json!({ "prune": true })
        } else {
            serde_json::json!({})
        };
        self.post(
            &format!("api/v1/applications/{}/{name}/sync", encode(namespace)),
            &body,
        )
        .await
    }

    /// `POST /api/v1/applications/{namespace}/{name}/rollback`.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`], including the server's `422` for an unknown history id.
    pub async fn rollback(
        &self,
        namespace: &str,
        name: &str,
        id: i64,
    ) -> Result<OperationResponse, ClientError> {
        let body = serde_json::json!({ "id": id });
        self.post(
            &format!("api/v1/applications/{}/{name}/rollback", encode(namespace)),
            &body,
        )
        .await
    }

    /// `GET /api/v1/projects` — the `AppProject`s the caller may see.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`].
    pub async fn list_projects(&self) -> Result<ProjectListView, ClientError> {
        self.get("api/v1/projects").await
    }

    /// `GET /api/v1/clusters`.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`].
    pub async fn list_clusters(&self) -> Result<ClusterListView, ClientError> {
        self.get("api/v1/clusters").await
    }
}

/// The largest `GET /api/v1/auth/config` body the CLI reads.
///
/// The document is a handful of short strings, so anything larger is a broken or hostile endpoint:
/// the same reasoning (and the same ceiling) as `ferriscd_server::auth_bff::MAX_HTTP_BODY_BYTES`.
pub const MAX_AUTH_CONFIG_BODY_BYTES: usize = 64 * 1024;

/// `GET /api/v1/auth/config` with **no credential** (`T19.1`, consumed by `T19.2`).
///
/// The document is public by design — it is how a client learns which sign-in method the server
/// wants — so this deliberately does not build a [`Client`] (which demands a token).
///
/// It is also the first call `ferriscd login --oidc` makes, so it carries a total and a connect
/// timeout, follows no redirects and reads at most [`MAX_AUTH_CONFIG_BODY_BYTES`]: a login must not
/// hang on a wedged server, nor be made to buffer an unbounded body before it has authenticated
/// anything.
///
/// # Errors
///
/// [`ClientError::InvalidUrl`] for an unusable server URL and the usual transport/status errors.
pub async fn fetch_auth_config(
    server_url: &str,
) -> Result<ferriscd_server::api::AuthConfigView, ClientError> {
    fetch_auth_config_with(server_url, AUTH_CONFIG_TIMEOUT).await
}

/// The total timeout for [`fetch_auth_config`].
pub const AUTH_CONFIG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The connect timeout for [`fetch_auth_config`].
pub const AUTH_CONFIG_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// [`fetch_auth_config`] with an explicit total timeout (the seam a test uses to prove it is
/// enforced).
///
/// # Errors
///
/// As [`fetch_auth_config`].
pub async fn fetch_auth_config_with(
    server_url: &str,
    timeout: std::time::Duration,
) -> Result<ferriscd_server::api::AuthConfigView, ClientError> {
    ferriscd_controller::impersonation::ensure_crypto_provider();
    let normalized = normalize_server_url(server_url)?;
    let url = format!("{normalized}/api/v1/auth/config");
    let http = reqwest::Client::builder()
        .user_agent(concat!("ferriscd/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .connect_timeout(AUTH_CONFIG_CONNECT_TIMEOUT.min(timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| ClientError::Transport {
            method: "CLIENT".to_owned(),
            url: url.clone(),
            message: error.to_string(),
        })?;
    let response = http
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| transport("GET", &url, &error))?;
    decode_bounded("GET", &url, response, Some(MAX_AUTH_CONFIG_BODY_BYTES)).await
}

/// Reads `response` into memory, refusing more than `limit` bytes.
async fn read_bounded(response: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    if let Some(declared) = response.content_length()
        && declared > limit as u64
    {
        return Err(format!(
            "the reply announced {declared} bytes, more than the {limit} byte limit"
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(format!("the reply is larger than the {limit} byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Whether `url` points at loopback (`127.0.0.0/8`, `::1`, `localhost`).
fn is_loopback(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    match parsed.host_str() {
        Some("localhost") => true,
        // `host_str` keeps the brackets of an IPv6 literal (`[::1]`); `str::parse` wants them gone.
        Some(host) => match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
            Ok(address) => address.is_loopback(),
            Err(_) => false,
        },
        None => false,
    }
}

/// Percent-encodes one path segment (a namespace is an RFC 1123 label, but never assume).
fn encode(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

/// Maps a `reqwest` transport failure, never including a header (the token).
fn transport(method: &str, url: &str, error: &reqwest::Error) -> ClientError {
    let message = if error.is_timeout() {
        "the request timed out".to_owned()
    } else if error.is_connect() {
        "connection failed".to_owned()
    } else {
        error.to_string()
    };
    ClientError::Transport {
        method: method.to_owned(),
        url: url.to_owned(),
        message,
    }
}

/// Reads a response, mapping the server's `{"error":{"code","message"}}` shape onto [`ClientError`].
async fn decode<T: DeserializeOwned>(
    method: &str,
    url: &str,
    response: reqwest::Response,
) -> Result<T, ClientError> {
    decode_bounded(method, url, response, None).await
}

/// [`decode`] with an optional body ceiling, checked against the declared length *and* while the body
/// streams in (a hostile endpoint can omit `Content-Length`).
async fn decode_bounded<T: DeserializeOwned>(
    method: &str,
    url: &str,
    mut response: reqwest::Response,
    limit: Option<usize>,
) -> Result<T, ClientError> {
    let status = response.status();
    // One code path: an absent limit is `usize::MAX`, which the streaming reader treats as "no
    // ceiling worth mentioning".
    let bytes = read_bounded(&mut response, limit.unwrap_or(usize::MAX))
        .await
        .map_err(|message| ClientError::Decode {
            method: method.to_owned(),
            url: url.to_owned(),
            message,
        })?;
    if !status.is_success() {
        // The API's own error body is bounded and secret-free (`ApiError::message`), and a client
        // cannot do better than repeat it. Anything else is summarised by its status code only.
        let (code, message) = match serde_json::from_slice::<ApiErrorBody>(&bytes) {
            Ok(body) => (body.error.code, body.error.message),
            Err(_) => (
                "UnexpectedResponse".to_owned(),
                "the server did not answer with the documented error shape".to_owned(),
            ),
        };
        return Err(match status.as_u16() {
            401 => ClientError::Unauthenticated {
                method: method.to_owned(),
                url: url.to_owned(),
                code,
                message,
            },
            403 => ClientError::Forbidden {
                method: method.to_owned(),
                url: url.to_owned(),
                code,
                message,
            },
            status_code => ClientError::Api {
                method: method.to_owned(),
                url: url.to_owned(),
                status: status_code,
                code,
                message,
            },
        });
    }
    serde_json::from_slice(&bytes).map_err(|err| ClientError::Decode {
        method: method.to_owned(),
        url: url.to_owned(),
        message: format!(
            "not the documented JSON (line {}, column {})",
            err.line(),
            err.column()
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn a_server_url_must_be_absolute_http_or_https() {
        for accepted in [
            "https://ferriscd.example.com",
            "http://127.0.0.1:8080",
            "http://localhost:8080/",
            "https://example.com/ferriscd/",
        ] {
            let normalized = normalize_server_url(accepted).expect("a usable URL");
            assert!(!normalized.ends_with('/'), "{normalized}");
            assert!(normalized.starts_with("http"), "{normalized}");
        }
        for rejected in [
            "ferriscd.example.com",
            "127.0.0.1:8080",
            "/api/v1",
            "file:///etc/passwd",
            "ftp://example.com",
            "",
        ] {
            let error = normalize_server_url(rejected).expect_err("must be refused");
            assert!(
                matches!(error, ClientError::InvalidUrl { .. }),
                "{rejected:?} produced {error:?}"
            );
            // The rejected URL is quoted back (it is what the operator typed) — but nothing secret.
            assert!(!error.to_string().is_empty());
        }
    }

    /// A rejected URL is echoed back — because it is what the operator typed — but never with the
    /// credential fragment a pasted `https://user:token@host` URL carries.
    #[test]
    fn a_rejected_url_never_quotes_the_credential_it_carries() {
        let error = normalize_server_url("ftp://oauth2:ghp_averysecrettoken@example.com/x")
            .expect_err("ftp is refused");
        let rendered = error.to_string();
        assert!(rendered.contains("ftp://***@example.com/x"), "{rendered}");
        assert!(!rendered.contains("ghp_averysecrettoken"), "{rendered}");
        assert!(!rendered.contains("oauth2"), "{rendered}");

        // A URL with no userinfo is unchanged, and a bare host has nothing to redact.
        assert_eq!(
            redact_userinfo("https://example.com/x"),
            "https://example.com/x"
        );
        assert_eq!(redact_userinfo("not-a-url"), "not-a-url");
        assert_eq!(
            redact_userinfo("https://user:pass@example.com"),
            "https://***@example.com"
        );
    }

    #[test]
    fn the_config_path_precedence_is_explicit_then_xdg_then_home() {
        let explicit = resolve_config_path(
            Some(OsStr::new("/tmp/ferriscd.json")),
            Some(OsStr::new("/xdg")),
            Some(OsStr::new("/home/tester")),
        )
        .expect("an explicit path");
        assert_eq!(explicit, PathBuf::from("/tmp/ferriscd.json"));

        let xdg = resolve_config_path(
            None,
            Some(OsStr::new("/xdg")),
            Some(OsStr::new("/home/tester")),
        )
        .expect("an xdg path");
        assert_eq!(xdg, PathBuf::from("/xdg/ferriscd/config.json"));

        let home =
            resolve_config_path(None, None, Some(OsStr::new("/home/tester"))).expect("a home path");
        assert_eq!(
            home,
            PathBuf::from("/home/tester/.config/ferriscd/config.json")
        );

        assert!(matches!(
            resolve_config_path(None, None, None),
            Err(ClientError::NoHome)
        ));
        // An empty override is ignored rather than producing a relative path.
        assert_eq!(
            resolve_config_path(Some(OsStr::new("")), None, Some(OsStr::new("/home/tester")))
                .expect("a home path"),
            PathBuf::from("/home/tester/.config/ferriscd/config.json")
        );
    }

    /// **`T14.5`:** the stored token lives in a `0600` file (and `0700` directory), and reloading it
    /// round-trips. A credential readable by other local users is a leak this test refuses to allow.
    #[cfg(unix)]
    #[test]
    fn the_stored_credential_is_private_and_round_trips() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a scratch directory");
        let path = directory.path().join("ferriscd").join("config.json");
        let stored = StoredConfig {
            server_url: "https://ferriscd.example.com".to_owned(),
            token: "super-secret-token".to_owned(),
        };
        stored.save_to(&path).expect("the config is written");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the token file must not be readable by others");
        let directory_mode = std::fs::metadata(path.parent().expect("a parent"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            directory_mode, 0o700,
            "the config directory must be private"
        );

        // A pre-existing file with a wider mode is tightened rather than left readable.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        stored.save_to(&path).expect("the config is rewritten");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        assert_eq!(
            StoredConfig::load_from(&path).expect("the config loads"),
            stored
        );

        // A missing file is "not logged in", not a crash.
        let missing = StoredConfig::load_from(&directory.path().join("nope.json"))
            .expect_err("a missing config is an error");
        assert!(matches!(missing, ClientError::NotLoggedIn { .. }));

        // A corrupt file is reported without printing its contents.
        std::fs::write(&path, "{\"token\":").expect("write");
        let corrupt =
            StoredConfig::load_from(&path).expect_err("a corrupt config must be reported");
        let rendered = corrupt.to_string();
        assert!(rendered.contains("not the documented JSON"), "{rendered}");
    }

    /// Nothing that renders a connection or a client may print the token.
    #[test]
    fn a_connection_never_renders_its_token() {
        let connection = Connection::new("https://ferriscd.example.com", "super-secret-token");
        assert!(!format!("{connection:?}").contains("super-secret-token"));
        assert_eq!(connection.server_url, "https://ferriscd.example.com");

        let client =
            Client::new("https://ferriscd.example.com", "super-secret-token").expect("a client");
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
        assert_eq!(client.base_url(), "https://ferriscd.example.com");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_token_is_trimmed_and_a_path_segment_is_encoded() {
        assert_eq!(trim_token(" abc\n".to_owned()), "abc");
        assert_eq!(encode("ferriscd-system"), "ferriscd-system");
        assert_eq!(encode("a/b c"), "a%2Fb%20c");
    }

    #[test]
    fn loopback_is_recognized_so_the_http_warning_is_accurate() {
        assert!(is_loopback("http://127.0.0.1:8080"));
        assert!(is_loopback("http://localhost:8080"));
        assert!(is_loopback("http://[::1]:8080"));
        assert!(!is_loopback("http://10.0.0.7:8080"));
        assert!(!is_loopback("https://ferriscd.example.com"));
    }

    /// `Connection::resolve_async` prefers the explicit values over everything else, and reports "not
    /// logged in" (never a panic) when nothing is available.
    #[tokio::test]
    async fn an_explicit_connection_never_needs_a_stored_file() {
        let connection = Connection::resolve_async(
            Some("https://ferriscd.example.com/"),
            Some("token-from-flag"),
        )
        .await
        .expect("explicit values are enough");
        assert_eq!(connection.server_url, "https://ferriscd.example.com");
        assert_eq!(connection.token, "token-from-flag");

        // Only a token, no URL: no stored file in this (empty) environment means "not logged in".
        // `FERRISCD_SERVER` may be set by the caller's shell, so the assertion accepts either the
        // stored/env path or the documented error — but never a panic or a half-built connection.
        match Connection::resolve_async(None, Some("token")).await {
            Ok(connection) => assert!(!connection.server_url.is_empty()),
            Err(error) => assert!(
                matches!(error, ClientError::NotLoggedIn { .. }),
                "{error:?}"
            ),
        }
    }
}

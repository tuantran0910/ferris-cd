//! The live OCI registry client (`T18.4`): the transport behind [`OciClient`].
//!
//! [`FakeOciClient`](super::FakeOciClient) proves the *seam*; this is the implementation that
//! actually talks to `ghcr.io`, ECR, GAR, Harbor, or a `registry:2` running on `kind`. Everything a
//! registry client can get wrong is decided here, and none of it is delegated to a third-party OCI
//! crate — `reqwest` is a plain HTTP client, and the distribution protocol (manifest fetch, blob
//! fetch, token challenge) is written out where a reviewer can read it.
//!
//! ## Transport: HTTPS only, and bounded
//!
//! * Under the production policy the [`reqwest::Client`] is built with `https_only(true)`, so a
//!   plaintext request is impossible **by construction** rather than by remembering to check the
//!   scheme at each call site. Plaintext is reachable only through the explicit local-development
//!   opt-in ([`OciUrlPolicy::AllowLocal`], `--allow-local-repos`), which is what a `kind`-hosted
//!   `registry:2` needs.
//! * Connect and request timeouts bound every round trip ([`DEFAULT_CONNECT_TIMEOUT`], 10 s, and
//!   [`DEFAULT_REQUEST_TIMEOUT`], 60 s, both overridable through
//!   [`RegistryOciClientConfig::with_timeouts`]), so one unresponsive registry cannot pin a
//!   reconcile worker for ever.
//! * Manifests, token documents, and layer blobs are read through a **streaming byte counter**
//!   ([`RegistryOciClient::read_bounded`] and the layer download). A registry cannot make the
//!   controller buffer an arbitrarily large body, and `Content-Length` is never the authority: the
//!   declared `size` is checked against the budget up front, and the counter stops the stream.
//! * Redirects are **not** followed at all. A `301`/`302`/`303`/`307`/`308` is a terminal
//!   [`RepoError::RegistryRedirectRefused`] naming the cause: following it would mean deciding
//!   whether to carry the `Authorization` header to a host the operator never configured.
//!   `registry:2`, GHCR, Harbor and Docker Hub answer blob `GET`s directly; registries that always
//!   redirect (ECR/GAR) need a proxy until this is revisited.
//!
//! ## Authentication
//!
//! `.dockerconfigjson` and `ferriscd.io/secret-type=repository` `Secret`s are already mapped onto
//! [`RepoCredentials`] by the controller (`T12.4`/`T18.3`), so this module only has to *present*
//! them:
//!
//! * a request starts with the credential the `Secret` carried (`Basic`, or `Bearer` for a token);
//! * a `401` carrying a `WWW-Authenticate` challenge is answered with **one** bounded token request
//!   against the advertised realm, and the original request is retried **once**;
//! * **every** challenge in the header is parsed (a registry may advertise `Negotiate` *and*
//!   `Bearer` in one line), and the first `Bearer` — else `Basic` — is answered;
//! * a plaintext realm is refused unless the local-development opt-in is set, and the realm's
//!   **authority must be the registry's own** (finding M5): the token endpoint is the one place a
//!   registry can send us to a *different* host with the credential in hand, so a split token
//!   service has to be named explicitly in
//!   [`RegistryOciClientConfig::token_service_hosts`]. Docker Hub is the single documented
//!   exception ([`WELL_KNOWN_TOKEN_HOSTS`]);
//! * tokens are cached per `(realm, service, scope)` — not per request URL — so the manifest `HEAD`,
//!   the manifest `GET` and the blob `GET` of one pass share one minted token (finding M4). Both
//!   caches are bounded ([`MAX_CACHED_TOKENS`], [`MAX_CACHED_REALMS`]) and a refused token is
//!   dropped and re-minted exactly once, so an expired token costs one extra round trip, never a
//!   loop and never unbounded memory.
//!
//! ## Blocking work
//!
//! Hash verification, gunzip, tar reading, filesystem extraction, and the work-root `mkdir` all run
//! inside [`tokio::task::spawn_blocking`]; the network half is `async` and the blob is written with
//! [`tokio::fs`], so no blocking call runs on a Tokio worker.
//!
//! The blob is written **once**: the download streams into `<scratch>/layer.tar.gz` while hashing
//! it, and extraction consumes that same file ([`extract_spooled_layer`]) instead of re-spooling
//! it into a second temporary file (finding M3).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use futures::StreamExt as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

use super::error::RepoError;
use super::oci::{
    ARCHIVE_OVERHEAD_BYTES, DIGEST_PREFIX, FLUX_BUNDLE_MEDIA_TYPE, HELM_CHART_MEDIA_TYPE,
    MAX_MANIFEST_BYTES, OCI_IMAGE_LAYER_MEDIA_TYPE, OciClient, OciDescriptor, OciFuture,
    OciManifest, OciSource, OciUrlPolicy, ResolvedDigest, extract_spooled_layer,
    is_supported_layer_media_type, sha256_digest, validate_digest,
};
use super::sanitize::WorktreeLimits;
use super::types::{RepoCheckout, RepoCredentials, redact_oci_url_credentials};

/// Default TCP/TLS connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for one registry round trip (including the streamed body).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest number of minted bearer tokens the client retains (finding M-nits: bounded cache).
///
/// One token per `(realm, service, scope)`; a controller that pulls from a handful of registries
/// needs a handful of entries, so this is generous. Reaching the cap clears the cache rather than
/// growing without bound — re-minting a token costs one round trip, never correctness.
pub const MAX_CACHED_TOKENS: usize = 64;

/// Largest number of remembered `registry origin -> token service` mappings.
pub const MAX_CACHED_REALMS: usize = 16;

/// Registry authorities whose token service is legitimately hosted somewhere else.
///
/// `registry-1.docker.io` advertises `https://auth.docker.io/token`; this is the only such pair
/// FerrisCD ships knowledge of. Any other split token service has to be named by the operator in
/// [`RegistryOciClientConfig::token_service_hosts`].
const WELL_KNOWN_TOKEN_HOSTS: [(&str, &str); 1] = [("registry-1.docker.io", "auth.docker.io")];

/// `User-Agent` sent on every request (registries log it, and an operator needs to see it).
pub const USER_AGENT: &str = concat!("ferriscd/", env!("CARGO_PKG_VERSION"));

/// Accepted manifest media types, in preference order.
///
/// The Docker spelling is included because `registry:2` (and every mirror in front of it) answers
/// with it, and its document shape is the one [`OciManifest`] parses.
const MANIFEST_ACCEPT: &str = concat!(
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.docker.distribution.manifest.v2+json",
);

/// Header a registry reports the canonical manifest digest in.
const DIGEST_HEADER: &str = "docker-content-digest";

/// `WWW-Authenticate` header (the authentication challenge).
const CHALLENGE_HEADER: &str = "www-authenticate";

/// Configuration of a [`RegistryOciClient`].
///
/// `Debug` is derived: it holds no credential. The registry credentials travel per call through
/// [`OciClient`]'s arguments, exactly like the Git client's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryOciClientConfig {
    /// Which `spec.source.oci.url` schemes are accepted (`Production` = HTTPS only).
    pub url_policy: OciUrlPolicy,
    /// Budgets enforced while extracting a layer (charged against the decompressed stream).
    pub limits: WorktreeLimits,
    /// Directory the per-fetch scratch trees are created in (`--work-root`).
    ///
    /// The same root backs the Git mirrors/worktrees (`RepoCache`), so a deployment that already
    /// sized its `emptyDir` for Git also holds OCI extractions. An extraction is removed with its
    /// [`RepoCheckout`], so this directory only ever holds the checkouts currently in use.
    pub work_root: PathBuf,
    /// Timeout for the TCP/TLS connect.
    pub connect_timeout: Duration,
    /// Timeout for one request (including the streamed body).
    pub request_timeout: Duration,
    /// Additional hosts (as `host` or `host:port`) that may host this registry's **token service**.
    ///
    /// Empty by default, which means "the registry's own authority only": the `WWW-Authenticate`
    /// realm is registry-controlled, and the token request is exactly where the `Secret`'s
    /// credential would be handed to a host of the registry's choosing (finding M5). Docker Hub is
    /// allowed out of the box ([`WELL_KNOWN_TOKEN_HOSTS`]); a split token service anywhere else —
    /// a corporate proxy, an ECR/GAR endpoint fronted by a different authority — has to be named
    /// here by the operator who owns both ends.
    pub token_service_hosts: Vec<String>,
}

impl Default for RegistryOciClientConfig {
    fn default() -> Self {
        Self {
            url_policy: OciUrlPolicy::Production,
            limits: WorktreeLimits::default(),
            work_root: std::env::temp_dir(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            token_service_hosts: Vec::new(),
        }
    }
}

impl RegistryOciClientConfig {
    /// Configuration rooted at `work_root` with the production URL policy and default budgets.
    #[must_use]
    pub fn new(work_root: impl Into<PathBuf>) -> Self {
        Self {
            work_root: work_root.into(),
            ..Self::default()
        }
    }

    /// Selects the URL/transport policy (`Production` is HTTPS-only).
    #[must_use]
    pub fn with_url_policy(mut self, url_policy: OciUrlPolicy) -> Self {
        self.url_policy = url_policy;
        self
    }

    /// Sets the extraction budgets.
    #[must_use]
    pub fn with_worktree_limits(mut self, limits: WorktreeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the connect and request timeouts.
    #[must_use]
    pub fn with_timeouts(mut self, connect: Duration, request: Duration) -> Self {
        self.connect_timeout = connect;
        self.request_timeout = request;
        self
    }

    /// Names the hosts (as `host` or `host:port`) that may host this registry's token service.
    ///
    /// See [`Self::token_service_hosts`]; the registry's own authority is always allowed.
    #[must_use]
    pub fn with_token_service_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.token_service_hosts = hosts.into_iter().map(Into::into).collect();
        self
    }
}

/// The token service one registry advertised, remembered per request origin.
///
/// Remembered so the *next* request can look its token up without first paying a `401`: the realm
/// is only ever learned from a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenRealm {
    realm: String,
    service: Option<String>,
}

/// Cache key of one minted bearer token: the token service, its optional `service` name, and the
/// requested `scope`.
///
/// Deliberately **not** the request URL (finding M4): a manifest `HEAD`, a manifest `GET` and a blob
/// `GET` are three URLs for one repository scope, and keying on the URL minted three tokens per
/// pass. The realm is part of the key so a token minted by one registry can never be presented to
/// another that advertises the identical scope string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TokenKey {
    realm: String,
    service: Option<String>,
    scope: String,
}

/// The live [`OciClient`]: a bounded registry transport with digest verification.
pub struct RegistryOciClient {
    config: RegistryOciClientConfig,
    http: reqwest::Client,
    /// Minted bearer tokens, keyed by [`TokenKey`] (`<realm>|<service>|<scope>`), at most
    /// [`MAX_CACHED_TOKENS`] entries.
    ///
    /// A token is an opaque credential, so the cache is never printed: [`std::fmt::Debug`] reports
    /// only how many entries it holds.
    tokens: Mutex<HashMap<TokenKey, String>>,
    /// The token service each registry origin advertised, at most [`MAX_CACHED_REALMS`] entries.
    realms: Mutex<HashMap<String, TokenRealm>>,
}

impl std::fmt::Debug for RegistryOciClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cached = self.tokens.try_lock().map(|tokens| tokens.len()).ok();
        let realms = self.realms.try_lock().map(|realms| realms.len()).ok();
        f.debug_struct("RegistryOciClient")
            .field("config", &self.config)
            .field("cached_tokens", &cached)
            .field("cached_realms", &realms)
            .finish_non_exhaustive()
    }
}

impl RegistryOciClient {
    /// Builds the client from `config`.
    ///
    /// # Errors
    ///
    /// [`RepoError::RepositoryError`] when the HTTP client cannot be built (an unusable TLS
    /// configuration, in practice). Nothing touches the filesystem: the work root is created
    /// lazily, inside the blocking half of the first [`OciClient::fetch_artifact`].
    pub fn new(config: RegistryOciClientConfig) -> Result<Self, RepoError> {
        // Two crypto providers are linked in this workspace (`ring` via `kube`, `aws-lc-rs` via
        // `gix`'s reqwest), and `rustls` refuses to guess between them — so the process-level
        // provider is pinned to `ring`, exactly like the controller's impersonation pool does.
        // Losing the race means another thread installed it first, which is just as good.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            // Production is HTTPS-only *structurally*: with `https_only` set, reqwest refuses a
            // plaintext URL even if a caller somehow built one.
            .https_only(config.url_policy == OciUrlPolicy::Production)
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            // Never follow a redirect: see the module docs (an `Authorization` header must not be
            // carried to a host the operator never configured).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| RepoError::RepositoryError {
                message: format!("failed to build the OCI registry HTTP client: {error}"),
            })?;

        Ok(Self {
            config,
            http,
            tokens: Mutex::new(HashMap::new()),
            realms: Mutex::new(HashMap::new()),
        })
    }

    /// The configuration this client was built with.
    #[must_use]
    pub fn config(&self) -> &RegistryOciClientConfig {
        &self.config
    }

    /// The HTTP base URL and repository path of a validated reference.
    fn endpoint(&self, src: &OciSource) -> Result<RegistryEndpoint, RepoError> {
        let endpoint = RegistryEndpoint::parse(&src.url)?;
        if endpoint.plaintext && self.config.url_policy == OciUrlPolicy::Production {
            // `OciSource::validate` already refuses this; keeping the check here means a future
            // caller that forgets to validate still cannot dial a plaintext registry.
            return Err(RepoError::InvalidUrl {
                url: redact_oci_url_credentials(&src.url),
                reason: "plaintext http:// registries are disallowed under the production policy"
                    .to_owned(),
            });
        }
        Ok(endpoint)
    }

    /// Resolves `src` into an immutable manifest digest, verifying a pinned digest when present.
    async fn resolve(
        &self,
        src: &OciSource,
        creds: &RepoCredentials,
    ) -> Result<ResolvedDigest, RepoError> {
        src.validate(self.config.url_policy)?;
        let endpoint = self.endpoint(src)?;
        let requested_ref = src
            .requested_reference()
            .ok_or_else(|| RepoError::InvalidSource {
                reason: "spec.source.oci must set a tag or a digest".to_owned(),
            })?
            .to_owned();
        let url = endpoint.manifest_url(&requested_ref);

        let response = self
            .send(
                reqwest::Method::HEAD,
                &endpoint,
                &url,
                Some(MANIFEST_ACCEPT),
                creds,
            )
            .await?;
        let status = response.status().as_u16();
        let resolved = match status {
            200 => match header_digest(&response) {
                Some(digest) => digest,
                // A registry is allowed to omit `Docker-Content-Digest`; the digest is then the
                // hash of the manifest body, which is what `fetch_artifact` verifies anyway.
                None => {
                    let manifest = self.get_manifest(&endpoint, &requested_ref, creds).await?;
                    sha256_digest(&manifest)
                }
            },
            _ => {
                return Err(manifest_status_error(status, &endpoint, &requested_ref));
            }
        };
        validate_digest(&resolved)?;
        if let Some(pinned) = src.digest.as_deref()
            && pinned != resolved
        {
            return Err(RepoError::OciDigestMismatch {
                expected: pinned.to_owned(),
                actual: resolved,
            });
        }
        Ok(ResolvedDigest {
            manifest_digest: resolved,
            requested_ref,
        })
    }

    /// Fetches (and verifies) the manifest for `reference`.
    async fn get_manifest(
        &self,
        endpoint: &RegistryEndpoint,
        reference: &str,
        creds: &RepoCredentials,
    ) -> Result<Vec<u8>, RepoError> {
        let url = endpoint.manifest_url(reference);
        let response = self
            .send(
                reqwest::Method::GET,
                endpoint,
                &url,
                Some(MANIFEST_ACCEPT),
                creds,
            )
            .await?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(manifest_status_error(status, endpoint, reference));
        }
        self.read_bounded(response, MAX_MANIFEST_BYTES, "the OCI manifest")
            .await
    }

    /// Reads `response`'s body into memory, refusing more than `cap` bytes.
    ///
    /// A declared `Content-Length` above the cap is refused before a byte is read, and the streamed
    /// counter catches a body that lies about (or omits) its length.
    async fn read_bounded(
        &self,
        response: reqwest::Response,
        cap: usize,
        what: &str,
    ) -> Result<Vec<u8>, RepoError> {
        if let Some(declared) = response.content_length()
            && declared > cap as u64
        {
            return Err(RepoError::OciInvalidArtifact {
                reason: format!(
                    "{what} declares {declared} bytes, which exceeds the {cap}-byte limit"
                ),
            });
        }
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| transport_error(&error))?;
            if body.len().saturating_add(chunk.len()) > cap {
                return Err(RepoError::OciInvalidArtifact {
                    reason: format!("{what} exceeds the {cap}-byte limit"),
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Sends one request, answering a single authentication challenge if the registry asks for one.
    ///
    /// At most **one** challenge round trip: a registry that keeps answering `401` cannot make this
    /// loop. Two properties are load-bearing here and are why the cached-token lookup happens before
    /// the request rather than after:
    ///
    /// * the cache key is `(realm, service, scope)`, so every URL of one repository scope reuses one
    ///   minted token (finding M4);
    /// * the realm is only learned from a challenge, so the `origin -> realm` mapping is remembered
    ///   separately to make that lookup possible without a probe.
    async fn send(
        &self,
        method: reqwest::Method,
        endpoint: &RegistryEndpoint,
        url: &str,
        accept: Option<&str>,
        creds: &RepoCredentials,
    ) -> Result<reqwest::Response, RepoError> {
        if matches!(creds, RepoCredentials::SshKey { .. }) {
            // `T18.3`: the credential store refuses SSH material on an `oci://` template, so this
            // can only be a caller that bypassed the store. Refusing beats sending nothing and
            // reporting a confusing 401.
            return Err(RepoError::AuthFailed {
                reason: "SSH credentials cannot authenticate an OCI registry".to_owned(),
            });
        }
        let base = self.base_authorization(creds);
        let scope = endpoint.pull_scope();
        let cached_key = self.remembered_realm(&endpoint.base).map(|realm| TokenKey {
            realm: realm.realm,
            service: realm.service,
            scope: scope.clone(),
        });
        let cached = cached_key.as_ref().and_then(|key| self.cached_token(key));
        // The cache holds the bare token; the header is `Bearer <token>`, exactly as the retry below
        // sends it. (Sending the token without its scheme is how a "cached" credential gets refused
        // and re-minted on every single call.)
        let cached_authorization = cached.as_deref().map(|token| format!("Bearer {token}"));

        let response = self
            .execute(
                method.clone(),
                url,
                accept,
                cached_authorization.as_deref().or(base.as_deref()),
            )
            .await?;
        if response.status().as_u16() != 401 {
            return Ok(response);
        }

        // A cached token that was refused is dropped first, so an expired token costs one extra
        // request and not a permanent failure.
        if let Some(key) = &cached_key {
            self.forget_token(key);
        }
        let header = challenge_header(&response);
        let Some(header) = header else {
            return Err(RepoError::AuthFailed {
                reason: format!(
                    "registry {} answered 401 without a WWW-Authenticate challenge",
                    redact_oci_url_credentials(url)
                ),
            });
        };
        // Every challenge in the header is parsed: a registry is allowed to advertise several
        // schemes at once, and "the first one was `Negotiate`" is not a reason to give up on the
        // `Bearer` challenge beside it.
        let challenges = parse_challenges(&header);
        let authorization = match select_challenge(&challenges) {
            Some(Challenge::Basic) => match &base {
                Some(base) => base.clone(),
                None => {
                    return Err(RepoError::AuthFailed {
                        reason: format!(
                            "registry {} requires basic authentication but no credential Secret \
                             matched the reference",
                            redact_oci_url_credentials(url)
                        ),
                    });
                }
            },
            Some(Challenge::Bearer {
                realm,
                service,
                scope: advertised,
            }) => {
                if !self.token_host_allowed(&endpoint.base, realm) {
                    return Err(RepoError::AuthFailed {
                        reason: format!(
                            "registry {} advertises its token service at {}, which is not the \
                             registry's own authority; refusing to send registry credentials to a \
                             host the operator did not configure (allow it explicitly with \
                             `RegistryOciClientConfig::with_token_service_hosts`)",
                            redact_oci_url_credentials(&endpoint.base),
                            authority_of(realm).unwrap_or(realm),
                        ),
                    });
                }
                let scope = advertised.clone().unwrap_or_else(|| scope.clone());
                let key = TokenKey {
                    realm: realm.clone(),
                    service: service.clone(),
                    scope: scope.clone(),
                };
                // A token may already be cached under the scope the *challenge* advertised (the
                // requested scope is a hint, and the registry is free to answer with another).
                let token = match self.cached_token(&key) {
                    Some(token) => token,
                    None => {
                        let token = self
                            .fetch_token(realm, service.as_deref(), &scope, creds)
                            .await?;
                        self.remember_token(key, &token);
                        token
                    }
                };
                self.remember_realm(
                    &endpoint.base,
                    TokenRealm {
                        realm: realm.clone(),
                        service: service.clone(),
                    },
                );
                format!("Bearer {token}")
            }
            None => {
                return Err(RepoError::AuthFailed {
                    reason: format!(
                        "registry {} answered 401 with an unsupported WWW-Authenticate challenge",
                        redact_oci_url_credentials(url)
                    ),
                });
            }
        };
        self.execute(method, url, accept, Some(&authorization))
            .await
    }

    /// Issues one HTTP request with an optional `Authorization` value.
    async fn execute(
        &self,
        method: reqwest::Method,
        url: &str,
        accept: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<reqwest::Response, RepoError> {
        let mut request = self.http.request(method, url);
        if let Some(accept) = accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }
        if let Some(authorization) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, authorization);
        }
        request
            .send()
            .await
            .map_err(|error| transport_error(&error))
    }

    /// The `Authorization` value the `Secret` itself provides, if any.
    fn base_authorization(&self, creds: &RepoCredentials) -> Option<String> {
        match creds {
            RepoCredentials::Anonymous | RepoCredentials::SshKey { .. } => None,
            RepoCredentials::HttpToken { token } => Some(format!("Bearer {token}")),
            RepoCredentials::HttpBasic { username, password } => {
                use base64::Engine as _;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                Some(format!("Basic {encoded}"))
            }
        }
    }

    /// Mints (or refreshes) a bearer token from the advertised realm.
    ///
    /// The realm is registry-controlled, so it is held to the same transport policy as the registry
    /// itself — HTTPS unless the local-development opt-in is set — and its **host** is checked
    /// against the registry authority before this is ever called
    /// ([`Self::token_host_allowed`]). The answer is size-capped and parsed for
    /// `token`/`access_token` only — every other field is ignored and never logged.
    async fn fetch_token(
        &self,
        realm: &str,
        service: Option<&str>,
        scope: &str,
        creds: &RepoCredentials,
    ) -> Result<String, RepoError> {
        if !realm_transport_allowed(realm, self.config.url_policy) {
            return Err(RepoError::AuthFailed {
                reason: format!(
                    "the registry's token realm {} is not HTTPS; refusing to send registry \
                     credentials over a plaintext connection",
                    redact_oci_url_credentials(realm)
                ),
            });
        }

        let mut url = if realm.contains('?') {
            format!("{realm}&")
        } else {
            format!("{realm}?")
        };
        if let Some(service) = service {
            url.push_str(&format!("service={}&", urlencode(service)));
        }
        url.push_str(&format!("scope={}", urlencode(scope)));
        let request = self.http.get(url);
        // Only a basic credential can authenticate the token endpoint itself. A token credential is
        // presented as a bearer token (registries that mint tokens from a PAT accept it there).
        let request = match creds {
            RepoCredentials::HttpBasic { username, password } => {
                request.basic_auth(username, Some(password))
            }
            RepoCredentials::HttpToken { token } => request.bearer_auth(token),
            RepoCredentials::Anonymous | RepoCredentials::SshKey { .. } => request,
        };
        let response = request
            .send()
            .await
            .map_err(|error| transport_error(&error))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(RepoError::AuthFailed {
                reason: format!(
                    "the registry's token service {} answered HTTP {status}",
                    redact_oci_url_credentials(realm)
                ),
            });
        }
        let body = self
            .read_bounded(response, MAX_MANIFEST_BYTES, "the OCI token document")
            .await?;
        let document: TokenDocument =
            serde_json::from_slice(&body).map_err(|_error| RepoError::AuthFailed {
                reason: format!(
                    "the registry's token service {} did not answer a JSON token document",
                    redact_oci_url_credentials(realm)
                ),
            })?;
        document
            .token
            .or(document.access_token)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| RepoError::AuthFailed {
                reason: format!(
                    "the registry's token service {} answered no `token`/`access_token`",
                    redact_oci_url_credentials(realm)
                ),
            })
    }

    /// Whether `realm` may receive this client's registry credential on behalf of `origin`.
    ///
    /// The transport policy is checked here too, so a realm is only ever dialled when *both* the
    /// scheme and the host are acceptable. The host rule is the finding-M5 fix: the realm is chosen
    /// by the registry, and answering it with the `Secret`'s credential is precisely how a
    /// compromised or hostile registry exfiltrates that credential. Allowed:
    ///
    /// 1. the registry's own authority (the common case: GHCR, Harbor, `registry:2`);
    /// 2. a host the operator named in [`RegistryOciClientConfig::token_service_hosts`];
    /// 3. the built-in pairs in [`WELL_KNOWN_TOKEN_HOSTS`] (Docker Hub).
    fn token_host_allowed(&self, origin: &str, realm: &str) -> bool {
        if !realm_transport_allowed(realm, self.config.url_policy) {
            return false;
        }
        let Some(origin_authority) = authority_of(origin) else {
            return false;
        };
        let Some(realm_authority) = authority_of(realm) else {
            return false;
        };
        if realm_authority.eq_ignore_ascii_case(origin_authority) {
            return true;
        }
        if self
            .config
            .token_service_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(realm_authority))
        {
            return true;
        }
        let origin_host = host_of(origin_authority);
        let realm_host = host_of(realm_authority);
        WELL_KNOWN_TOKEN_HOSTS.iter().any(|(registry, token)| {
            registry.eq_ignore_ascii_case(origin_host) && token.eq_ignore_ascii_case(realm_host)
        })
    }

    /// The minted token cached for `key`, if any.
    fn cached_token(&self, key: &TokenKey) -> Option<String> {
        self.tokens
            .lock()
            .ok()
            .and_then(|tokens| tokens.get(key).cloned())
    }

    /// Caches `token` under `key`, dropping the whole cache when it is full.
    ///
    /// Clearing (rather than evicting one entry) keeps the cache bounded without an LRU's
    /// bookkeeping: every entry is recoverable by one extra token request.
    fn remember_token(&self, key: TokenKey, token: &str) {
        if let Ok(mut tokens) = self.tokens.lock() {
            if tokens.len() >= MAX_CACHED_TOKENS && !tokens.contains_key(&key) {
                tokens.clear();
            }
            tokens.insert(key, token.to_owned());
        }
    }

    /// Drops the token cached for `key` (a refused token is re-minted exactly once).
    fn forget_token(&self, key: &TokenKey) {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.remove(key);
        }
    }

    /// The token service `origin` advertised the last time it challenged us.
    fn remembered_realm(&self, origin: &str) -> Option<TokenRealm> {
        self.realms
            .lock()
            .ok()
            .and_then(|realms| realms.get(origin).cloned())
    }

    /// Remembers which token service `origin` uses, so the next request can reuse its token.
    fn remember_realm(&self, origin: &str, realm: TokenRealm) {
        if let Ok(mut realms) = self.realms.lock() {
            if realms.len() >= MAX_CACHED_REALMS && !realms.contains_key(origin) {
                realms.clear();
            }
            realms.insert(origin.to_owned(), realm);
        }
    }

    /// Streams the layer blob for `layer` into `spool`, bounded by the extraction budget.
    ///
    /// The bytes are hashed **as they are streamed** and compared against the manifest descriptor
    /// before this returns, so a hostile or broken registry is refused here rather than after a
    /// second pass over the file. The digest check is repeated by
    /// [`extract_spooled_layer`](super::oci::extract_spooled_layer) — this is the fast failure, that
    /// one is the invariant.
    async fn download_layer(
        &self,
        endpoint: &RegistryEndpoint,
        layer: &OciDescriptor,
        spool: &Path,
        creds: &RepoCredentials,
    ) -> Result<u64, RepoError> {
        let budget = self
            .config
            .limits
            .max_bytes
            .saturating_add(ARCHIVE_OVERHEAD_BYTES);
        if let Some(declared) = layer.size
            && declared > budget
        {
            // Refused before a byte crosses the wire: a manifest that declares a 10 GiB layer is not
            // something the budget could ever hold, so downloading it would only be a denial of
            // service against ourselves.
            return Err(RepoError::CheckoutLimitExceeded {
                reason: format!(
                    "the OCI layer declares {declared} bytes, which exceeds the {budget}-byte \
                     compressed budget"
                ),
            });
        }

        let url = endpoint.blob_url(&layer.digest);
        let response = self
            .send(reqwest::Method::GET, endpoint, &url, None, creds)
            .await?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(status_error(
                status,
                &url,
                format!("fetching the blob {}", endpoint.blob_path(&layer.digest)),
            ));
        }

        let mut file = tokio::fs::File::create(spool)
            .await
            .map_err(|source| RepoError::Io {
                context: "creating the OCI layer spool file".to_owned(),
                source,
            })?;
        let mut hasher = Sha256::new();
        let mut stream = response.bytes_stream();
        let mut written = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| transport_error(&error))?;
            written = written.saturating_add(chunk.len() as u64);
            if written > budget {
                return Err(RepoError::CheckoutLimitExceeded {
                    reason: format!(
                        "the OCI layer exceeds the {budget}-byte compressed budget while streaming"
                    ),
                });
            }
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|source| RepoError::Io {
                    context: "spooling the OCI layer".to_owned(),
                    source,
                })?;
        }
        file.flush().await.map_err(|source| RepoError::Io {
            context: "flushing the OCI layer spool".to_owned(),
            source,
        })?;

        let actual = format!("{DIGEST_PREFIX}{:x}", hasher.finalize());
        if actual != layer.digest {
            return Err(RepoError::OciDigestMismatch {
                expected: layer.digest.clone(),
                actual,
            });
        }
        if let Some(declared) = layer.size
            && declared != written
        {
            return Err(RepoError::OciInvalidArtifact {
                reason: format!(
                    "the layer descriptor declares {declared} bytes but the registry served \
                     {written}"
                ),
            });
        }
        Ok(written)
    }
}

impl OciClient for RegistryOciClient {
    fn resolve_digest<'a>(
        &'a self,
        src: &'a OciSource,
        creds: &'a RepoCredentials,
    ) -> OciFuture<'a, ResolvedDigest> {
        Box::pin(self.resolve(src, creds))
    }

    /// Fetches the artifact, verifying the manifest **and** the layer digest before extraction.
    ///
    /// # Limitations
    ///
    /// A `301`/`302`/`303`/`307`/`308` from the registry is a terminal
    /// [`RepoError::RegistryRedirectRefused`]: FerrisCD does not follow registry redirects, because
    /// doing so would mean carrying the `Authorization` header to a CDN host the operator never
    /// configured. `registry:2`, GHCR, Harbor and Docker Hub answer blob `GET`s directly;
    /// registries that always redirect (ECR/GAR) need a proxy until this is revisited.
    fn fetch_artifact<'a>(
        &'a self,
        src: &'a OciSource,
        digest: &'a str,
        creds: &'a RepoCredentials,
    ) -> OciFuture<'a, RepoCheckout> {
        Box::pin(async move {
            src.validate(self.config.url_policy)?;
            validate_digest(digest)?;
            let endpoint = self.endpoint(src)?;
            let reference = src
                .requested_reference()
                .ok_or_else(|| RepoError::InvalidSource {
                    reason: "spec.source.oci must set a tag or a digest".to_owned(),
                })?
                .to_owned();
            // The manifest is fetched by the *resolved* digest when the reference already is one,
            // and by tag otherwise: a registry serves a manifest by digest immutably, so asking for
            // the digest we pinned is what makes the verification below meaningful.
            let manifest_reference = if reference.starts_with("sha256:") {
                reference.clone()
            } else {
                digest.to_owned()
            };
            let manifest = self
                .get_manifest(&endpoint, &manifest_reference, creds)
                .await?;
            // Verified before it is interpreted: the digest is the identity the cache keys on, and a
            // body that does not hash to it is not the artifact the `Application` asked for.
            if sha256_digest(&manifest) != digest {
                return Err(RepoError::OciDigestMismatch {
                    expected: digest.to_owned(),
                    actual: sha256_digest(&manifest),
                });
            }
            let parsed = OciManifest::parse(&manifest)?;
            let layer = parsed.single_layer()?.clone();
            if !is_supported_layer_media_type(&layer.media_type) {
                return Err(RepoError::OciUnsupportedMediaType {
                    media_type: layer.media_type,
                });
            }

            let work_root = self.config.work_root.clone();
            let scratch = tokio::task::spawn_blocking(move || {
                std::fs::create_dir_all(&work_root).map_err(|source| RepoError::Io {
                    context: format!("creating the OCI work root {}", work_root.display()),
                    source,
                })?;
                tempfile::Builder::new()
                    .prefix("ferriscd-oci-")
                    .tempdir_in(&work_root)
                    .map_err(|source| RepoError::Io {
                        context: "creating an OCI extraction root".to_owned(),
                        source,
                    })
            })
            .await
            .map_err(|error| RepoError::TaskCancelled {
                message: format!("OCI scratch-directory worker failed: {error}"),
            })??;

            let spool = scratch.path().join("layer.tar.gz");
            self.download_layer(&endpoint, &layer, &spool, creds)
                .await?;

            // The blob is on disk now, so extraction consumes *that* file (finding M3): the bytes
            // are written once, inside the work root, and `extract_spooled_layer` re-verifies the
            // digest while it reads them before decompressing anything.
            let limits = self.config.limits;
            let expected = digest.to_owned();
            let dest = scratch.path().join("artifact");
            let descriptor = layer.clone();
            let root = tokio::task::spawn_blocking(move || {
                extract_spooled_layer(&spool, &descriptor, &dest, &limits)
            })
            .await
            .map_err(|error| RepoError::TaskCancelled {
                message: format!("OCI extraction worker failed: {error}"),
            })??;

            let lease: std::sync::Arc<dyn std::any::Any + Send + Sync> =
                std::sync::Arc::new(scratch);
            Ok(RepoCheckout::with_lease(root, expected, lease))
        })
    }
}

/// HTTP base URL and repository path of one registry reference.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryEndpoint {
    /// `https://host[:port]` (or `http://…` under the local-development opt-in).
    base: String,
    /// `<repository>` — the path after the registry authority.
    repository: String,
    /// Whether the transport is plaintext.
    plaintext: bool,
}

impl RegistryEndpoint {
    /// Splits a reference whose shape [`OciSource::validate`] has already accepted.
    fn parse(url: &str) -> Result<Self, RepoError> {
        let invalid = |reason: &str| RepoError::InvalidUrl {
            url: redact_oci_url_credentials(url),
            reason: reason.to_owned(),
        };
        let (scheme, rest) = url.split_once("://").ok_or_else(|| {
            invalid("registry URL must be absolute, e.g. oci://ghcr.io/org/chart")
        })?;
        let (authority, repository) = rest
            .split_once('/')
            .ok_or_else(|| invalid("registry URL must be oci://<registry>/<repository>"))?;
        if authority.is_empty() || repository.is_empty() {
            return Err(invalid(
                "registry URL must be oci://<registry>/<repository>",
            ));
        }
        let scheme = scheme.to_ascii_lowercase();
        let (transport, plaintext) = match scheme.as_str() {
            // `oci://` is the GitOps spelling of "this registry over HTTPS".
            "oci" | "https" => ("https", false),
            "http" => ("http", true),
            other => {
                return Err(invalid(&format!(
                    "unsupported registry URL scheme '{other}'"
                )));
            }
        };
        Ok(Self {
            base: format!("{transport}://{authority}"),
            repository: repository.to_owned(),
            plaintext,
        })
    }

    /// `GET`/`HEAD` URL of one manifest.
    fn manifest_url(&self, reference: &str) -> String {
        format!("{}/v2/{}/manifests/{reference}", self.base, self.repository)
    }

    /// `GET` URL of one blob.
    fn blob_url(&self, digest: &str) -> String {
        format!("{}/v2/{}/blobs/{digest}", self.base, self.repository)
    }

    /// Path of one blob, for error messages (never the full URL: the registry host is not a secret,
    /// but the message is built from the endpoint so it stays stable and greppable).
    fn blob_path(&self, digest: &str) -> String {
        format!("/v2/{}/blobs/{digest}", self.repository)
    }

    /// Token scope this client needs: read-only pull on this repository.
    fn pull_scope(&self) -> String {
        format!("repository:{}:pull", self.repository)
    }
}

/// One `WWW-Authenticate` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Challenge {
    /// `Bearer realm="…", service="…", scope="…"`.
    Bearer {
        realm: String,
        service: Option<String>,
        scope: Option<String>,
    },
    /// `Basic realm="…"`.
    Basic,
}

/// Parses a `WWW-Authenticate` header value into **every** challenge it carries.
///
/// A registry is allowed to advertise several schemes in one header
/// (`Bearer realm="…",service="…",Basic realm="Registry"`), and answering "unsupported" because the
/// *first* scheme was e.g. `Negotiate` would fail a registry that also offers `Bearer`. Unsupported
/// schemes and unusable `Bearer` challenges (no `realm`) are dropped here; [`select_challenge`]
/// decides which of the parsed challenges is answered.
fn parse_challenges(header: &str) -> Vec<Challenge> {
    let mut parsed: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for (token, value) in challenge_items(header) {
        match value {
            // A bare token starts a new challenge: `Bearer`, `Basic`, `Negotiate`, …
            None => parsed.push((token, Vec::new())),
            // `key=value` belongs to the challenge it follows.
            Some(value) => {
                if let Some((_scheme, params)) = parsed.last_mut() {
                    params.push((token.to_ascii_lowercase(), value));
                }
            }
        }
    }
    parsed
        .into_iter()
        .filter_map(
            |(scheme, params)| match scheme.to_ascii_lowercase().as_str() {
                "basic" => Some(Challenge::Basic),
                "bearer" => {
                    let mut realm = None;
                    let mut service = None;
                    let mut scope = None;
                    for (key, value) in params {
                        match key.as_str() {
                            "realm" => realm = Some(value),
                            "service" => service = Some(value),
                            "scope" => scope = Some(value),
                            _ => {}
                        }
                    }
                    Some(Challenge::Bearer {
                        realm: realm?,
                        service,
                        scope,
                    })
                }
                _ => None,
            },
        )
        .collect()
}

/// Picks the challenge this client answers: the first `Bearer`, else `Basic`.
///
/// `Basic` is the fallback rather than the default because a registry that offers both wants the
/// token exchange: `Basic` there is a compatibility scheme, not the credential the `Secret` should
/// be sent as on every request.
fn select_challenge(challenges: &[Challenge]) -> Option<&Challenge> {
    challenges
        .iter()
        .find(|challenge| matches!(challenge, Challenge::Bearer { .. }))
        .or_else(|| {
            challenges
                .iter()
                .find(|challenge| matches!(challenge, Challenge::Basic))
        })
}

/// Splits a challenge header into `(token, Some(value))` parameters and `(scheme, None)` markers,
/// honouring quoted values (which may legitimately contain commas).
fn challenge_items(header: &str) -> Vec<(String, Option<String>)> {
    let mut items = Vec::new();
    let mut chars = header.chars().peekable();
    loop {
        // Skip separators and whitespace between items.
        while chars
            .peek()
            .is_some_and(|c| c.is_whitespace() || *c == ',' || *c == ';')
        {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut token = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() || c == ',' {
                break;
            }
            token.push(c);
            chars.next();
        }
        if chars.peek() != Some(&'=') {
            // A bare token (a challenge scheme). `token` may be empty when the header starts with a
            // separator run; skip those rather than pushing an empty marker.
            if !token.is_empty() {
                items.push((token, None));
            }
            continue;
        }
        // Consume '=' and read the value: quoted (with backslash escapes) or bare.
        chars.next();
        let value = if chars.peek() == Some(&'"') {
            chars.next();
            let mut value = String::new();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(escaped) = chars.next() {
                        value.push(escaped);
                    }
                    continue;
                }
                if c == '"' {
                    break;
                }
                value.push(c);
            }
            value
        } else {
            let mut value = String::new();
            while let Some(&c) = chars.peek() {
                if c == ',' || c.is_whitespace() {
                    break;
                }
                value.push(c);
                chars.next();
            }
            value
        };
        items.push((token, Some(value)));
    }
    items
}

/// Every `WWW-Authenticate` header value on `response`, joined the way RFC 9110 allows.
fn challenge_header(response: &reqwest::Response) -> Option<String> {
    let values: Vec<String> = response
        .headers()
        .get_all(CHALLENGE_HEADER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// Wire shape of the token documents registries return.
#[derive(Deserialize)]
struct TokenDocument {
    #[serde(default)]
    token: Option<String>,
    #[serde(default, rename = "access_token")]
    access_token: Option<String>,
}

/// A non-`200` manifest response, classified.
fn manifest_status_error(status: u16, endpoint: &RegistryEndpoint, reference: &str) -> RepoError {
    if status == 404 {
        return RepoError::RevisionNotFound {
            revision: format!("{}/{}:{reference}", endpoint.base, endpoint.repository),
        };
    }
    status_error(
        status,
        &endpoint.manifest_url(reference),
        format!("fetching the manifest of {}", endpoint.repository),
    )
}

/// Classifies a non-2xx status the registry answered with.
///
/// A redirect is its own terminal error (finding: name the cause instead of reporting a generic
/// `4xx`), `401`/`403` are an authentication problem (terminal: the `Secret` is wrong or the token
/// expired in a way one refresh could not fix), and everything else keeps
/// [`RepoError::RemoteServerError`]'s own retry classification — retryable exactly for
/// `408`/`429`/`5xx`, terminal for the other `4xx` (a wrong repository name, say).
///
/// `url` is the request that was redirected, **redacted**: the `Location` header is deliberately
/// not echoed, because the redirect target is registry-controlled and an unverified URL does not
/// belong in `Application.status`.
fn status_error(status: u16, url: &str, message: String) -> RepoError {
    match status {
        301 | 302 | 303 | 307 | 308 => RepoError::RegistryRedirectRefused {
            status,
            url: redact_oci_url_credentials(url),
        },
        401 | 403 => RepoError::AuthFailed {
            reason: format!("the registry answered HTTP {status} while {message}"),
        },
        other => RepoError::RemoteServerError {
            status: Some(other),
            message,
        },
    }
}

/// Percent-encodes `value` for use in a query string (RFC 3986 unreserved characters are kept).
///
/// The token request is the one place a registry-controlled string (`service`, `scope`) becomes a
/// URL component, so it is encoded rather than interpolated — the crate's `reqwest` build does not
/// enable the `query` feature, and hand-rolling the two-line escape keeps it that way.
fn urlencode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

/// Whether a token realm may be dialled with registry credentials under `policy`.
///
/// The realm is chosen by the registry, so this is the one place a registry could redirect the
/// credential to a host of its choosing. HTTPS is required, and plaintext is reachable only through
/// the local-development opt-in (`kind`'s `registry:2` mints no tokens, but a test double might).
/// The **host** half of that decision is [`RegistryOciClient::token_host_allowed`], which calls this
/// first.
fn realm_transport_allowed(realm: &str, policy: OciUrlPolicy) -> bool {
    let Some((scheme, _rest)) = realm.split_once("://") else {
        return false;
    };
    match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http" => policy == OciUrlPolicy::AllowLocal,
        _ => false,
    }
}

/// The `host[:port]` authority of an absolute URL, with any userinfo stripped.
///
/// `None` for a relative or unusable reference — which is what a caller comparing authorities needs
/// to treat as "not allowed", never as "no authority to check".
fn authority_of(url: &str) -> Option<&str> {
    let (_scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return None;
    }
    // The **last** `@` is the userinfo/host boundary: a password may contain an unescaped `@`.
    Some(match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    })
}

/// The host part of an authority: `host:port` → `host`, `[v6]:port` → `[v6]`.
fn host_of(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority
            .split_once(']')
            .map_or(authority, |(host, _port)| &authority[..host.len() + 1]);
    }
    authority
        .split_once(':')
        .map_or(authority, |(host, _port)| host)
}

/// Maps a transport failure onto the engine's retry classification.
fn transport_error(error: &reqwest::Error) -> RepoError {
    if error.is_timeout() {
        return RepoError::Timeout {
            message: format!("registry request timed out: {error}"),
        };
    }
    if error.is_redirect() {
        // The client sets `redirect::Policy::none()`, so a 3xx surfaces as a response, not here;
        // this branch exists so a future policy change cannot silently become "follow the CDN".
        return RepoError::OciInvalidArtifact {
            reason: "the registry answered with a redirect, which FerrisCD does not follow"
                .to_owned(),
        };
    }
    RepoError::Network {
        message: format!("registry transport error: {error}"),
    }
}

/// Reads a `sha256:<64-hex>` value out of the `Docker-Content-Digest` header.
fn header_digest(response: &reqwest::Response) -> Option<String> {
    let value = response
        .headers()
        .get(DIGEST_HEADER)
        .and_then(|value| value.to_str().ok())?
        .trim();
    validate_digest(value).ok()?;
    Some(value.to_owned())
}

/// Media types a `spec.source.oci` layer may declare, for `Debug`/documentation purposes.
#[must_use]
pub fn supported_media_types() -> [&'static str; 3] {
    [
        HELM_CHART_MEDIA_TYPE,
        OCI_IMAGE_LAYER_MEDIA_TYPE,
        FLUX_BUNDLE_MEDIA_TYPE,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    // ---------------------------------------------------------------------
    // A scripted HTTP/1.1 registry (no network, no sleeps)
    // ---------------------------------------------------------------------

    /// One canned response.
    struct Response {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    }

    impl Response {
        fn new(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: Vec::new(),
            }
        }

        fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
            self.headers.push((name, value.into()));
            self
        }

        fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
            self.body = body.into();
            self
        }
    }

    /// A request the scripted registry observed.
    #[derive(Debug, Clone)]
    struct Observed {
        method: String,
        target: String,
        authorization: Option<String>,
    }

    /// A `Connection: close` HTTP server whose answers come from a closure.
    ///
    /// One connection per request keeps the scripted protocol obvious (and mirrors what a registry
    /// behind a load balancer may do anyway), so a test asserts on a request *sequence* rather than
    /// on socket reuse.
    struct TestRegistry {
        address: SocketAddr,
        observed: Arc<Mutex<Vec<Observed>>>,
        shutdown: Arc<Mutex<bool>>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TestRegistry {
        fn start<F>(handler: F) -> Self
        where
            F: Fn(&Observed, SocketAddr) -> Response + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
            listener
                .set_nonblocking(true)
                .expect("a non-blocking listener");
            let address = listener.local_addr().expect("a bound address");
            let observed = Arc::new(Mutex::new(Vec::new()));
            let shutdown = Arc::new(Mutex::new(false));
            let recorded = Arc::clone(&observed);
            let stopping = Arc::clone(&shutdown);
            let handle = std::thread::spawn(move || {
                while !*stopping.lock().expect("the shutdown flag") {
                    match listener.accept() {
                        Ok((stream, _peer)) => serve_one(stream, address, &handler, &recorded),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::yield_now();
                        }
                        Err(_) => return,
                    }
                }
            });
            Self {
                address,
                observed,
                shutdown,
                handle: Some(handle),
            }
        }

        /// A plaintext reference to `repository` on this server.
        fn url(&self, scheme: &str, repository: &str) -> String {
            format!("{scheme}://{}/{repository}", self.address)
        }

        fn observed(&self) -> Vec<Observed> {
            self.observed.lock().expect("the observed requests").clone()
        }

        fn targets(&self) -> Vec<String> {
            self.observed()
                .into_iter()
                .map(|request| request.target)
                .collect()
        }
    }

    impl Drop for TestRegistry {
        fn drop(&mut self) {
            if let Ok(mut stopping) = self.shutdown.lock() {
                *stopping = true;
            }
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn serve_one<F>(
        mut stream: TcpStream,
        address: SocketAddr,
        handler: &F,
        observed: &Mutex<Vec<Observed>>,
    ) where
        F: Fn(&Observed, SocketAddr) -> Response,
    {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        // A client that stops reading mid-body (which is exactly what the byte-counter tests do) must
        // not wedge the accept loop: the write is bounded too. It is deliberately short — the client
        // closes the connection only when its own pool is dropped, so a patient server would make
        // `Drop` wait for that instead of failing the write it can never complete.
        let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
        // The listener is non-blocking so the accept loop can observe `shutdown`; on some platforms
        // (BSD/macOS) the accepted socket inherits that flag, so it is cleared explicitly before the
        // request is read — otherwise `read_line` would spuriously return `WouldBlock`.
        let _ = stream.set_nonblocking(false);
        let mut reader = BufReader::new(stream.try_clone().expect("a cloned stream"));
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let target = parts.next().unwrap_or_default().to_owned();
        let mut authorization = None;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("authorization")
            {
                authorization = Some(value.trim().to_owned());
            }
        }
        let request = Observed {
            method,
            target,
            authorization,
        };
        if let Ok(mut requests) = observed.lock() {
            requests.push(request.clone());
        }
        let response = handler(&request, address);
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            response.status,
            status_text(response.status),
            response.body.len()
        );
        for (name, value) in &response.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&response.body);
        let _ = stream.flush();
    }

    fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            302 => "Found",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Status",
        }
    }

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    const BODY: &str = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n";
    const HEX_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A minimal ustar record for one regular file (`0` typeflag).
    fn tar_with(name: &str, content: &[u8]) -> Vec<u8> {
        fn octal(value: u64, width: usize) -> String {
            let digits = format!("{value:o}");
            format!("{}{}\0", "0".repeat(width - 1 - digits.len()), digits)
        }
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(octal(0o644, 8).as_bytes());
        header[108..116].copy_from_slice(octal(0, 8).as_bytes());
        header[116..124].copy_from_slice(octal(0, 8).as_bytes());
        header[124..136].copy_from_slice(octal(content.len() as u64, 12).as_bytes());
        header[136..148].copy_from_slice(octal(0, 12).as_bytes());
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{:06o}\0 ", checksum).as_bytes());
        let mut archive = header;
        archive.extend_from_slice(content);
        let padding = (512 - content.len() % 512) % 512;
        archive.extend(std::iter::repeat_n(0u8, padding));
        archive
    }

    /// A gzip-compressed tar layer holding `files` (the archive ends with one zero-block pair).
    fn gzipped_layer(files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, content) in files {
            tar.extend(tar_with(name, content.as_bytes()));
        }
        tar.extend(std::iter::repeat_n(0u8, 1024));
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).expect("gzip the fixture layer");
        encoder.finish().expect("finish the fixture layer")
    }

    fn manifest_for(media_type: &str, layer: &[u8]) -> Vec<u8> {
        format!(
            concat!(
                r#"{{"schemaVersion":2,"#,
                r#""mediaType":"application/vnd.oci.image.manifest.v1+json","#,
                r#""layers":[{{"mediaType":"{media_type}","digest":"{digest}","size":{size}}}]}}"#
            ),
            media_type = media_type,
            digest = sha256_digest(layer),
            size = layer.len(),
        )
        .into_bytes()
    }

    fn client(policy: OciUrlPolicy, work_root: &Path) -> RegistryOciClient {
        RegistryOciClient::new(
            RegistryOciClientConfig::new(work_root)
                .with_url_policy(policy)
                .with_timeouts(Duration::from_secs(5), Duration::from_secs(10)),
        )
        .expect("build the registry client")
    }

    fn source(url: &str, tag: Option<&str>, digest: Option<&str>, path: &str) -> OciSource {
        OciSource::new(url, tag.map(str::to_owned), digest.map(str::to_owned), path)
    }

    /// Total regular-file bytes under `path` (recursively), for "how many copies are on disk" tests.
    fn directory_bytes(path: &Path) -> u64 {
        let mut total = 0u64;
        let mut pending = vec![path.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("a readable directory") {
                let entry = entry.expect("a directory entry");
                let metadata = entry.metadata().expect("entry metadata");
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else {
                    total = total.saturating_add(metadata.len());
                }
            }
        }
        total
    }

    // ---------------------------------------------------------------------
    // Reference parsing & transport policy
    // ---------------------------------------------------------------------

    #[test]
    fn an_oci_reference_maps_onto_https_and_keeps_the_repository_path() {
        let endpoint = RegistryEndpoint::parse("oci://ghcr.io/payments/charts/api").expect("parse");
        assert_eq!(endpoint.base, "https://ghcr.io");
        assert!(!endpoint.plaintext);
        assert_eq!(endpoint.repository, "payments/charts/api");
        assert_eq!(
            endpoint.manifest_url("1.4.2"),
            "https://ghcr.io/v2/payments/charts/api/manifests/1.4.2"
        );
        assert_eq!(
            endpoint.blob_url(&format!("sha256:{HEX_A}")),
            format!("https://ghcr.io/v2/payments/charts/api/blobs/sha256:{HEX_A}")
        );
        assert_eq!(endpoint.pull_scope(), "repository:payments/charts/api:pull");

        let plaintext = RegistryEndpoint::parse("http://127.0.0.1:5000/charts").expect("parse");
        assert!(plaintext.plaintext);
        assert_eq!(plaintext.base, "http://127.0.0.1:5000");

        // `https://` and `oci://` are the same transport, spelled differently.
        let https = RegistryEndpoint::parse("https://ghcr.io/org/chart").expect("parse");
        assert_eq!(https.base, "https://ghcr.io");
        assert!(!https.plaintext);
    }

    #[test]
    fn an_unsupported_scheme_or_shape_is_rejected_without_echoing_the_token() {
        for url in [
            "ftp://ghcr.io/org/chart",
            "ghcr.io/org/chart",
            "oci://ghcr.io",
            "ghcr-token@ghcr.io/org/chart",
        ] {
            let error = RegistryEndpoint::parse(url).expect_err("must be rejected");
            assert!(
                matches!(error, RepoError::InvalidUrl { .. }),
                "unexpected variant for {url:?}: {error:?}"
            );
            assert!(!error.to_string().contains("ghcr-token"), "{error}");
        }
    }

    #[test]
    fn a_token_realm_is_held_to_the_transport_policy() {
        assert!(realm_transport_allowed(
            "https://auth.example.com/token",
            OciUrlPolicy::Production
        ));
        assert!(!realm_transport_allowed(
            "http://auth.example.com/token",
            OciUrlPolicy::Production
        ));
        assert!(realm_transport_allowed(
            "http://127.0.0.1:5000/token",
            OciUrlPolicy::AllowLocal
        ));
        for unusable in ["auth.example.com/token", "file:///etc/passwd", ""] {
            assert!(
                !realm_transport_allowed(unusable, OciUrlPolicy::AllowLocal),
                "{unusable:?} must never be dialled"
            );
        }
    }

    /// **Trap guard (`T18.3`/`T18.4`).** A plaintext registry is unreachable under the production
    /// policy — refused by validation *and* structurally by the `https_only` HTTP client.
    #[tokio::test]
    async fn a_plaintext_registry_is_refused_under_the_production_policy() {
        let registry = TestRegistry::start(|_request, _address| Response::new(200));
        let work = tempfile::tempdir().expect("work root");
        let url = registry.url("http", "charts");

        let production = client(OciUrlPolicy::Production, work.path());
        let error = production
            .resolve_digest(
                &source(&url, Some("1.0.0"), None, ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("plaintext must be refused");
        assert!(
            matches!(error, RepoError::InvalidUrl { .. }),
            "unexpected variant: {error:?}"
        );
        assert!(!error.is_retryable());
        assert!(
            registry.observed().is_empty(),
            "no request may reach a plaintext registry under the production policy"
        );

        // The same reference is usable with the explicit local-development opt-in: the client really
        // dials the (plaintext) registry, issuing the HEAD and — because the fixture answers no
        // `Docker-Content-Digest` — the manifest-body fallback.
        let local = client(OciUrlPolicy::AllowLocal, work.path());
        local
            .resolve_digest(
                &source(&url, Some("1.0.0"), None, ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect("the local-development policy dials the registry");
        assert_eq!(
            registry.targets(),
            vec![
                "/v2/charts/manifests/1.0.0".to_owned(),
                "/v2/charts/manifests/1.0.0".to_owned()
            ],
            "the local client issues a HEAD and then falls back to a GET"
        );
    }

    #[tokio::test]
    async fn ssh_credentials_are_refused_before_any_request() {
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let credentials = RepoCredentials::SshKey {
            private_key_pem: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n".to_owned(),
            passphrase: None,
            known_hosts: None,
        };
        let error = client
            .resolve_digest(
                &source("oci://ghcr.io/org/chart", Some("1"), None, ""),
                &credentials,
            )
            .await
            .expect_err("SSH credentials cannot authenticate a registry");
        assert!(matches!(error, RepoError::AuthFailed { .. }), "{error:?}");
        assert!(!format!("{error:?}").contains("SECRET"), "{error:?}");
        assert!(!format!("{error:?}").contains("BEGIN"), "{error:?}");
    }

    // ---------------------------------------------------------------------
    // Digest resolution
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn resolve_uses_the_docker_content_digest_header_without_fetching_the_body() {
        let registry = TestRegistry::start(|_request, _address| {
            Response::new(200).header("Docker-Content-Digest", format!("sha256:{HEX_A}"))
        });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");

        let resolved = client
            .resolve_digest(
                &source(&url, Some("1.4.2"), None, ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect("resolve");
        assert_eq!(resolved.manifest_digest, format!("sha256:{HEX_A}"));
        assert_eq!(resolved.requested_ref, "1.4.2");

        let requests = registry.observed();
        assert_eq!(
            requests.len(),
            1,
            "one HEAD, no manifest body: {requests:?}"
        );
        assert_eq!(requests[0].method, "HEAD");
        assert_eq!(requests[0].target, "/v2/charts/manifests/1.4.2");
    }

    #[tokio::test]
    async fn resolve_falls_back_to_hashing_the_manifest_when_the_header_is_absent() {
        let layer = gzipped_layer(&[("configmap.yaml", BODY)]);
        let manifest = manifest_for(OCI_IMAGE_LAYER_MEDIA_TYPE, &layer);
        let expected = sha256_digest(&manifest);
        let registry = TestRegistry::start(move |request, _address| {
            if request.method == "HEAD" {
                Response::new(200)
            } else {
                Response::new(200).body(manifest.clone())
            }
        });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");

        let resolved = client
            .resolve_digest(
                &source(&url, Some("main"), None, ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect("resolve");
        assert_eq!(resolved.manifest_digest, expected);
        let methods: Vec<String> = registry
            .observed()
            .into_iter()
            .map(|request| request.method)
            .collect();
        assert_eq!(methods, vec!["HEAD".to_owned(), "GET".to_owned()]);
    }

    /// A moved tag can never be mistaken for the pinned artifact: the resolved digest is compared
    /// against `spec.source.oci.digest`, and a mismatch is terminal.
    #[tokio::test]
    async fn a_moved_tag_that_no_longer_matches_the_pinned_digest_is_terminal() {
        let registry = TestRegistry::start(|_request, _address| {
            Response::new(200).header("Docker-Content-Digest", format!("sha256:{HEX_A}"))
        });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");

        let error = client
            .resolve_digest(
                &source(&url, Some("1.4.2"), Some(&format!("sha256:{HEX_B}")), ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("a moved tag must be refused");
        assert!(
            matches!(error, RepoError::OciDigestMismatch { .. }),
            "unexpected variant: {error:?}"
        );
        assert!(!error.is_retryable());

        // The pin that *does* match resolves cleanly.
        let resolved = client
            .resolve_digest(
                &source(&url, Some("1.4.2"), Some(&format!("sha256:{HEX_A}")), ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect("a matching pin resolves");
        assert_eq!(resolved.manifest_digest, format!("sha256:{HEX_A}"));
    }

    #[tokio::test]
    async fn a_missing_manifest_is_a_terminal_revision_not_found() {
        let registry = TestRegistry::start(|_request, _address| {
            Response::new(404).body(b"not found".to_vec())
        });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");
        let error = client
            .resolve_digest(
                &source(&url, Some("9.9.9"), None, ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("404");
        assert!(
            matches!(error, RepoError::RevisionNotFound { .. }),
            "unexpected variant: {error:?}"
        );
        assert!(!error.is_retryable());
        assert!(error.to_string().contains("9.9.9"), "{error}");
    }

    // ---------------------------------------------------------------------
    // Authentication
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn a_bearer_challenge_mints_one_token_and_retries_once() {
        let server = TestRegistry::start(move |request, address| {
            if request.target.starts_with("/token") {
                assert_eq!(
                    request.authorization.as_deref(),
                    Some("Basic dXNlcjpwYXNz"),
                    "the token request carries the Secret's basic credential"
                );
                assert!(
                    request.target.contains("scope=repository%3Acharts%3Apull")
                        || request.target.contains("scope=repository:charts:pull"),
                    "the token request asks for a pull scope: {}",
                    request.target
                );
                return Response::new(200).body(br#"{"access_token":"minted-token"}"#.to_vec());
            }
            match request.authorization.as_deref() {
                Some("Bearer minted-token") => {
                    Response::new(200).header("Docker-Content-Digest", format!("sha256:{HEX_A}"))
                }
                _ => Response::new(401).header(
                    "WWW-Authenticate",
                    format!(
                        "Bearer realm=\"http://{address}/token\",service=\"registry\",\
                         scope=\"repository:charts:pull\""
                    ),
                ),
            }
        });

        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = server.url("http", "charts");
        let credentials = RepoCredentials::HttpBasic {
            username: "user".to_owned(),
            password: "pass".to_owned(),
        };

        let resolved = client
            .resolve_digest(&source(&url, Some("1.0.0"), None, ""), &credentials)
            .await
            .expect("the challenge is answered");
        assert_eq!(resolved.manifest_digest, format!("sha256:{HEX_A}"));

        let observed = server.observed();
        let methods: Vec<&str> = observed
            .iter()
            .map(|request| request.method.as_str())
            .collect();
        assert_eq!(
            methods,
            vec!["HEAD", "GET", "HEAD"],
            "one challenge, one token, one retry: {observed:?}"
        );
        assert!(observed[1].target.starts_with("/token"), "{observed:?}");
        assert_eq!(
            observed[2].authorization.as_deref(),
            Some("Bearer minted-token")
        );

        // A second resolve reuses the cached token: no second token request.
        let again = client
            .resolve_digest(&source(&url, Some("1.0.0"), None, ""), &credentials)
            .await
            .expect("the cached token is reused");
        assert_eq!(again.manifest_digest, format!("sha256:{HEX_A}"));
        assert_eq!(
            server
                .targets()
                .iter()
                .filter(|target| target.starts_with("/token"))
                .count(),
            1,
            "the token is minted once and cached: {:?}",
            server.targets()
        );
    }

    #[tokio::test]
    async fn a_401_without_a_challenge_is_terminal() {
        let registry = TestRegistry::start(|_request, _address| Response::new(401));
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");
        let error = client
            .resolve_digest(
                &source(&url, Some("1"), None, ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("401 without a challenge");
        assert!(matches!(error, RepoError::AuthFailed { .. }), "{error:?}");
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn a_basic_challenge_is_answered_with_the_secret_credential() {
        let registry =
            TestRegistry::start(|request, _address| match request.authorization.as_deref() {
                Some("Basic dXNlcjpwYXNz") => {
                    Response::new(200).header("Docker-Content-Digest", format!("sha256:{HEX_A}"))
                }
                _ => Response::new(401).header("WWW-Authenticate", "Basic realm=\"Registry\""),
            });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");
        let credentials = RepoCredentials::HttpBasic {
            username: "user".to_owned(),
            password: "pass".to_owned(),
        };
        let resolved = client
            .resolve_digest(&source(&url, Some("1"), None, ""), &credentials)
            .await
            .expect("basic authentication");
        assert_eq!(resolved.manifest_digest, format!("sha256:{HEX_A}"));

        // Anonymous cannot satisfy a basic challenge: a clear AuthFailed, never a silent miss.
        let error = client
            .resolve_digest(
                &source(&url, Some("1"), None, ""),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("no credential");
        assert!(matches!(error, RepoError::AuthFailed { .. }), "{error:?}");
        assert!(!error.to_string().contains("pass"), "{error}");
    }

    /// **Finding M4.** The token cache is keyed on `(realm, service, scope)`, so a second request
    /// that needs the same scope — a different tag, or the blob of the same repository — reuses the
    /// minted token instead of minting another one.
    ///
    /// The counter is on the *token endpoint*, not on the cache: a URL-keyed cache (the bug) also
    /// "has" a cache, it just misses on every new URL and mints one token per request.
    #[tokio::test]
    async fn one_token_is_minted_per_scope_not_per_request_url() {
        let minted = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&minted);
        let server = TestRegistry::start(move |request, address| {
            if request.target.starts_with("/token") {
                *counter.lock().expect("the mint counter") += 1;
                return Response::new(200).body(br#"{"token":"minted-token"}"#.to_vec());
            }
            if request.authorization.as_deref() == Some("Bearer minted-token") {
                return Response::new(200)
                    .header("Docker-Content-Digest", format!("sha256:{HEX_A}"));
            }
            Response::new(401).header(
                "WWW-Authenticate",
                format!(
                    "Bearer realm=\"http://{address}/token\",service=\"registry\",\
                     scope=\"repository:charts:pull\""
                ),
            )
        });

        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = server.url("http", "charts");
        let credentials = RepoCredentials::HttpBasic {
            username: "user".to_owned(),
            password: "pass".to_owned(),
        };

        // Two *different* request URLs, one scope: the second must not mint.
        client
            .resolve_digest(&source(&url, Some("1.0.0"), None, ""), &credentials)
            .await
            .expect("the first resolve mints one token");
        client
            .resolve_digest(&source(&url, Some("2.0.0"), None, ""), &credentials)
            .await
            .expect("the second resolve reuses it");

        let tokens = server
            .targets()
            .into_iter()
            .filter(|target| target.starts_with("/token"))
            .count();
        assert_eq!(
            tokens,
            1,
            "one mint per scope, not one per request URL: {:?}",
            server.targets()
        );
        assert_eq!(*minted.lock().expect("the mint counter"), 1);
        let requests = server.observed();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.authorization.as_deref() == Some("Bearer minted-token"))
                .count(),
            2,
            "the cached token is presented on both requests rather than triggering a challenge: \
             {requests:?}"
        );
    }

    /// **Finding M4.** A token minted by one registry is never presented to another that happens to
    /// advertise the identical `repository:charts:pull` scope string.
    #[tokio::test]
    async fn tokens_are_never_shared_between_registries_with_the_same_scope() {
        fn registry(token: &'static str) -> TestRegistry {
            TestRegistry::start(move |request, address| {
                if request.target.starts_with("/token") {
                    return Response::new(200).body(format!(r#"{{"token":"{token}"}}"#));
                }
                if request.authorization.as_deref() == Some(&format!("Bearer {token}")) {
                    return Response::new(200)
                        .header("Docker-Content-Digest", format!("sha256:{HEX_A}"));
                }
                Response::new(401).header(
                    "WWW-Authenticate",
                    format!(
                        "Bearer realm=\"http://{address}/token\",scope=\"repository:charts:pull\""
                    ),
                )
            })
        }

        let first = registry("first-token");
        let second = registry("second-token");
        let work = tempfile::tempdir().expect("work root");
        // One client, two registries: the cache is per client, so the keys must keep them apart.
        let client = client(OciUrlPolicy::AllowLocal, work.path());

        for registry in [&first, &second] {
            let url = registry.url("http", "charts");
            client
                .resolve_digest(
                    &source(&url, Some("1.0.0"), None, ""),
                    &RepoCredentials::Anonymous,
                )
                .await
                .expect("each registry mints its own token");
        }
        assert_eq!(
            first
                .observed()
                .iter()
                .filter(|request| request.authorization.as_deref() == Some("Bearer first-token"))
                .count(),
            1,
            "{:?}",
            first.observed()
        );
        assert_eq!(
            second
                .observed()
                .iter()
                .filter(|request| request.authorization.as_deref() == Some("Bearer second-token"))
                .count(),
            1,
            "{:?}",
            second.observed()
        );
        // Neither registry ever saw the other's token.
        assert!(
            first
                .observed()
                .iter()
                .all(|request| request.authorization.as_deref() != Some("Bearer second-token")),
            "the first registry saw the second's token: {:?}",
            first.observed()
        );
        assert!(
            second
                .observed()
                .iter()
                .all(|request| request.authorization.as_deref() != Some("Bearer first-token")),
            "the second registry saw the first's token: {:?}",
            second.observed()
        );
    }

    /// **Finding M5.** A registry may advertise its token service anywhere; the `Secret`'s
    /// credential must not be handed to a host the operator did not configure.
    ///
    /// The second server stands in for the attacker's host: it must see **zero** requests, which is
    /// what "refused before the credential is sent" means. Then the same arrangement is allowed
    /// explicitly, and the request really does reach it — so the refusal above is about the host
    /// rule, not about a credential that could never have worked.
    #[tokio::test]
    async fn a_token_realm_on_another_host_is_refused_before_the_credential_is_sent() {
        // The host the wrong realm points at. It mints a token if anyone ever asks.
        let elsewhere = TestRegistry::start(|_request, _address| {
            Response::new(200).body(br#"{"token":"other"}"#.to_vec())
        });
        let elsewhere_address = elsewhere.address;
        let registry = TestRegistry::start(move |request, _address| {
            if request.authorization.as_deref() == Some("Bearer other") {
                return Response::new(200)
                    .header("Docker-Content-Digest", format!("sha256:{HEX_A}"));
            }
            Response::new(401).header(
                "WWW-Authenticate",
                format!("Bearer realm=\"http://{elsewhere_address}/token\",scope=\"repository:charts:pull\""),
            )
        });

        let work = tempfile::tempdir().expect("work root");
        let credentials = RepoCredentials::HttpBasic {
            username: "robot".to_owned(),
            password: "s3cr3t".to_owned(),
        };
        let url = registry.url("http", "charts");

        let strict = client(OciUrlPolicy::AllowLocal, work.path());
        let error = strict
            .resolve_digest(&source(&url, Some("1.0.0"), None, ""), &credentials)
            .await
            .expect_err("a token service on another authority must be refused");
        assert!(matches!(error, RepoError::AuthFailed { .. }), "{error:?}");
        assert!(!error.is_retryable(), "the realm is terminal, not a retry");
        let message = error.to_string();
        assert!(
            message.contains("token service") && message.contains("with_token_service_hosts"),
            "the refusal names the cause and the escape hatch: {message}"
        );
        assert!(
            !message.contains("s3cr3t"),
            "the refusal must not leak the credential: {message}"
        );
        assert!(
            elsewhere.observed().is_empty(),
            "the credential must never be sent to the advertised host: {:?}",
            elsewhere.observed()
        );

        // The documented escape hatch: name the extra token service and the same flow works.
        let permissive = RegistryOciClient::new(
            RegistryOciClientConfig::new(work.path())
                .with_url_policy(OciUrlPolicy::AllowLocal)
                .with_token_service_hosts([elsewhere_address.to_string()])
                .with_timeouts(Duration::from_secs(5), Duration::from_secs(10)),
        )
        .expect("client");
        let resolved = permissive
            .resolve_digest(&source(&url, Some("1.0.0"), None, ""), &credentials)
            .await
            .expect("an allow-listed token service is used");
        assert_eq!(resolved.manifest_digest, format!("sha256:{HEX_A}"));
        let token_requests = elsewhere.observed();
        assert_eq!(
            token_requests.len(),
            1,
            "the allow-listed host received exactly one token request: {token_requests:?}"
        );
        assert!(
            token_requests[0].authorization.is_some(),
            "the allow-listed host is the one the credential is for: {token_requests:?}"
        );
    }

    /// Both caches stay bounded: a controller that sees many realms or scopes cannot grow them
    /// without limit.
    #[test]
    fn the_token_caches_are_bounded() {
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        for index in 0..(MAX_CACHED_TOKENS * 2 + 5) {
            client.remember_token(
                TokenKey {
                    realm: format!("https://auth{index}.example.com/token"),
                    service: None,
                    scope: "repository:charts:pull".to_owned(),
                },
                "token",
            );
            client.remember_realm(
                &format!("https://registry{index}.example.com"),
                TokenRealm {
                    realm: format!("https://auth{index}.example.com/token"),
                    service: None,
                },
            );
        }
        let tokens = client.tokens.lock().expect("the token cache").len();
        let realms = client.realms.lock().expect("the realm cache").len();
        assert!(
            tokens <= MAX_CACHED_TOKENS,
            "{tokens} tokens exceed the {MAX_CACHED_TOKENS} cap"
        );
        assert!(
            realms <= MAX_CACHED_REALMS,
            "{realms} realms exceed the {MAX_CACHED_REALMS} cap"
        );
        // Bounded and still usable: the newest entry is the one that survived.
        assert!(
            client
                .cached_token(&TokenKey {
                    realm: format!(
                        "https://auth{}.example.com/token",
                        MAX_CACHED_TOKENS * 2 + 4
                    ),
                    service: None,
                    scope: "repository:charts:pull".to_owned(),
                })
                .is_some(),
            "the most recently minted token is cached"
        );
        assert!(!format!("{client:?}").contains("token\""), "{client:?}");
    }

    // ---------------------------------------------------------------------
    // Artifact fetch
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn fetch_verifies_the_manifest_and_layer_digests_and_extracts_the_artifact() {
        let layer = gzipped_layer(&[("configmap.yaml", BODY)]);
        let manifest = manifest_for(OCI_IMAGE_LAYER_MEDIA_TYPE, &layer);
        let digest = sha256_digest(&manifest);
        let blob_path = format!("/v2/charts/blobs/{}", sha256_digest(&layer));
        let served_manifest = manifest.clone();
        let served_layer = layer.clone();
        let registry = TestRegistry::start(move |request, _address| {
            if request.target.contains("/manifests/") {
                Response::new(200).body(served_manifest.clone())
            } else if request.target == blob_path {
                Response::new(200).body(served_layer.clone())
            } else {
                Response::new(404)
            }
        });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");

        let checkout = client
            .fetch_artifact(
                &source(&url, Some("1.0.0"), None, ""),
                &digest,
                &RepoCredentials::Anonymous,
            )
            .await
            .expect("fetch");
        assert_eq!(checkout.commit_sha(), digest);
        let extracted = checkout.root_dir().join("configmap.yaml");
        assert!(extracted.is_file(), "the layer must be extracted");
        assert_eq!(
            std::fs::read_to_string(&extracted).expect("read the extracted file"),
            BODY
        );
        assert!(
            checkout.root_dir().starts_with(work.path()),
            "an extraction lives under the configured work root"
        );
        assert_eq!(
            registry.observed().len(),
            2,
            "one manifest GET and one blob GET: {:?}",
            registry.targets()
        );
    }

    /// **Finding M3.** The blob is written **once**, inside the work root: the download streams it
    /// to `<scratch>/layer.tar.gz`, and extraction consumes that same file.
    ///
    /// The check is byte accounting on the scratch directory, because that is what "spooled twice"
    /// costs: with a second copy the directory would hold two blobs' worth of compressed bytes. The
    /// entry set is asserted too, so a stray copy under any name fails here.
    #[tokio::test]
    async fn the_layer_blob_is_written_once_inside_the_work_root() {
        let layer = gzipped_layer(&[("configmap.yaml", BODY)]);
        let manifest = manifest_for(OCI_IMAGE_LAYER_MEDIA_TYPE, &layer);
        let digest = sha256_digest(&manifest);
        let blob_path = format!("/v2/charts/blobs/{}", sha256_digest(&layer));
        let served_manifest = manifest.clone();
        let served_layer = layer.clone();
        let registry = TestRegistry::start(move |request, _address| {
            if request.target.contains("/manifests/") {
                Response::new(200).body(served_manifest.clone())
            } else if request.target == blob_path {
                Response::new(200).body(served_layer.clone())
            } else {
                Response::new(404)
            }
        });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");

        let checkout = client
            .fetch_artifact(
                &source(&url, Some("1.0.0"), None, ""),
                &digest,
                &RepoCredentials::Anonymous,
            )
            .await
            .expect("fetch");

        let artifact = checkout.root_dir().to_path_buf();
        let scratch = artifact.parent().expect("the extraction scratch directory");
        assert!(
            scratch.starts_with(work.path()),
            "the scratch tree lives under the configured work root: {}",
            scratch.display()
        );
        let mut entries: Vec<String> = std::fs::read_dir(scratch)
            .expect("the scratch directory is readable")
            .map(|entry| {
                entry
                    .expect("a scratch entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec!["artifact".to_owned(), "layer.tar.gz".to_owned()],
            "exactly one spool and one extracted tree"
        );

        let spool = scratch.join("layer.tar.gz");
        assert_eq!(
            std::fs::metadata(&spool).expect("the spool metadata").len(),
            layer.len() as u64,
            "the spool is the downloaded blob, not a re-spooled copy of something else"
        );
        assert!(artifact.is_dir(), "the artifact tree is beside the spool");

        let extracted = directory_bytes(&artifact);
        assert_eq!(
            directory_bytes(scratch),
            layer.len() as u64 + extracted,
            "the work root holds the compressed blob once plus the extracted tree — never two \
             copies of the blob"
        );
    }

    /// **Finding M3 (verification order).** A registry that serves bytes other than the manifest's
    /// layer is refused **during the download**, before anything is decompressed, and terminally.
    #[tokio::test]
    async fn a_blob_that_does_not_match_the_manifest_digest_is_refused_during_the_download() {
        let layer = gzipped_layer(&[("configmap.yaml", BODY)]);
        let manifest = manifest_for(OCI_IMAGE_LAYER_MEDIA_TYPE, &layer);
        let digest = sha256_digest(&manifest);
        // The registry answers the blob request with a *different* (still valid gzip) layer.
        let tampered = gzipped_layer(&[("configmap.yaml", "apiVersion: v1\nkind: Secret\n")]);
        let tampered_digest = sha256_digest(&tampered);
        let served_manifest = manifest.clone();
        let served_tampered = tampered.clone();
        let registry = TestRegistry::start(move |request, _address| {
            if request.target.contains("/manifests/") {
                Response::new(200).body(served_manifest.clone())
            } else {
                Response::new(200).body(served_tampered.clone())
            }
        });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");

        let error = client
            .fetch_artifact(
                &source(&url, Some("1.0.0"), None, ""),
                &digest,
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("a blob that is not the declared layer is refused");
        assert!(
            matches!(
                error,
                RepoError::OciDigestMismatch { ref actual, .. } if *actual == tampered_digest
            ),
            "unexpected variant: {error:?}"
        );
        assert!(!error.is_retryable());
        assert!(
            registry
                .targets()
                .iter()
                .filter(|target| target.contains("/blobs/"))
                .count()
                == 1,
            "the blob is fetched once, not once per verification: {:?}",
            registry.targets()
        );
        // Nothing was extracted and nothing was left behind: the scratch tree is removed with the
        // failed fetch, so the work root is empty again.
        assert!(
            std::fs::read_dir(work.path())
                .expect("the work root is readable")
                .next()
                .is_none(),
            "a refused blob leaves no extraction behind"
        );
    }

    #[tokio::test]
    async fn a_manifest_that_does_not_hash_to_the_pinned_digest_is_refused_before_extraction() {
        let layer = gzipped_layer(&[("configmap.yaml", BODY)]);
        let manifest = manifest_for(OCI_IMAGE_LAYER_MEDIA_TYPE, &layer);
        let served = manifest.clone();
        let registry =
            TestRegistry::start(move |_request, _address| Response::new(200).body(served.clone()));
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");

        let error = client
            .fetch_artifact(
                &source(&url, Some("1.0.0"), None, ""),
                &format!("sha256:{HEX_A}"),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("a mismatched manifest must be refused");
        assert!(
            matches!(error, RepoError::OciDigestMismatch { .. }),
            "unexpected variant: {error:?}"
        );
        assert!(
            registry
                .targets()
                .iter()
                .all(|target| !target.contains("/blobs/")),
            "no layer may be downloaded before the manifest is verified"
        );
    }

    #[tokio::test]
    async fn a_layer_that_declares_more_than_the_budget_is_refused_before_downloading() {
        let layer = gzipped_layer(&[("configmap.yaml", BODY)]);
        // Declares a 4 GiB layer without serving one byte of it.
        let manifest = format!(
            concat!(
                r#"{{"schemaVersion":2,"#,
                r#""mediaType":"application/vnd.oci.image.manifest.v1+json","#,
                r#""layers":[{{"mediaType":"{media_type}","digest":"{digest}","size":4294967296}}]}}"#
            ),
            media_type = OCI_IMAGE_LAYER_MEDIA_TYPE,
            digest = sha256_digest(&layer),
        )
        .into_bytes();
        let digest = sha256_digest(&manifest);
        let served = manifest.clone();
        let served_layer = layer.clone();
        let registry = TestRegistry::start(move |request, _address| {
            if request.target.contains("/manifests/") {
                Response::new(200).body(served.clone())
            } else {
                Response::new(200).body(served_layer.clone())
            }
        });
        let work = tempfile::tempdir().expect("work root");
        let client = RegistryOciClient::new(
            RegistryOciClientConfig::new(work.path())
                .with_url_policy(OciUrlPolicy::AllowLocal)
                .with_worktree_limits(WorktreeLimits::default().with_max_bytes(64 * 1024 * 1024))
                .with_timeouts(Duration::from_secs(5), Duration::from_secs(10)),
        )
        .expect("client");
        let url = registry.url("http", "charts");

        let error = client
            .fetch_artifact(
                &source(&url, Some("1.0.0"), None, ""),
                &digest,
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("an oversized layer must be refused");
        assert!(
            matches!(error, RepoError::CheckoutLimitExceeded { .. }),
            "unexpected variant: {error:?}"
        );
        assert!(
            registry
                .targets()
                .iter()
                .all(|target| !target.contains("/blobs/")),
            "no byte of an oversized layer may be downloaded"
        );
    }

    #[tokio::test]
    async fn a_streamed_body_beyond_the_manifest_cap_is_refused() {
        let registry = TestRegistry::start(|_request, _address| {
            Response::new(200).body(vec![b'x'; MAX_MANIFEST_BYTES + 1])
        });
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");
        let error = client
            .fetch_artifact(
                &source(&url, Some("1"), None, ""),
                &format!("sha256:{HEX_A}"),
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("an oversized manifest must be refused");
        assert!(
            matches!(error, RepoError::OciInvalidArtifact { .. }),
            "unexpected variant: {error:?}"
        );
    }

    #[tokio::test]
    async fn an_unsupported_layer_media_type_is_refused_before_extraction() {
        let layer = gzipped_layer(&[("configmap.yaml", BODY)]);
        let manifest = manifest_for("application/vnd.example.unknown", &layer);
        let digest = sha256_digest(&manifest);
        let served = manifest.clone();
        let registry =
            TestRegistry::start(move |_request, _address| Response::new(200).body(served.clone()));
        let work = tempfile::tempdir().expect("work root");
        let client = client(OciUrlPolicy::AllowLocal, work.path());
        let url = registry.url("http", "charts");
        let error = client
            .fetch_artifact(
                &source(&url, Some("1"), None, ""),
                &digest,
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("an unknown media type must be refused");
        assert!(
            matches!(error, RepoError::OciUnsupportedMediaType { .. }),
            "unexpected variant: {error:?}"
        );
        assert!(
            registry
                .targets()
                .iter()
                .all(|target| !target.contains("/blobs/")),
            "an unsupported layer is never downloaded"
        );
    }

    /// A registry that answers with a redirect is not followed: the `Authorization` header must not
    /// be carried to a host the operator never configured.
    ///
    /// Every redirect status maps onto the dedicated terminal error, which names the cause, and the
    /// `Location` is never echoed (it is registry-controlled, and `Application.status` is not a good
    /// place for an unverified URL).
    #[tokio::test]
    async fn every_redirect_status_is_refused_with_a_dedicated_terminal_error() {
        for status in [301_u16, 302, 303, 307, 308] {
            let registry = TestRegistry::start(move |_request, _address| {
                Response::new(status).header("Location", "https://cdn.example.com/blob")
            });
            let work = tempfile::tempdir().expect("work root");
            let client = client(OciUrlPolicy::AllowLocal, work.path());
            let url = registry.url("http", "charts");
            let error = client
                .resolve_digest(
                    &source(&url, Some("1"), None, ""),
                    &RepoCredentials::Anonymous,
                )
                .await
                .expect_err("a redirect is refused");
            assert!(
                matches!(error, RepoError::RegistryRedirectRefused { status: got, .. } if got == status),
                "unexpected variant for HTTP {status}: {error:?}"
            );
            assert!(!error.is_retryable(), "a redirect is terminal, not a retry");
            let message = error.to_string();
            assert!(
                message.contains(&format!("HTTP {status} redirect")),
                "the message names the redirect cause: {message}"
            );
            assert!(
                !message.contains("cdn.example.com"),
                "the redirect target is not echoed as if it had been followed: {message}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Challenge parsing
    // ---------------------------------------------------------------------

    #[test]
    fn the_www_authenticate_parser_reads_every_challenge_in_the_header() {
        assert_eq!(
            parse_challenges(
                r#"Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:org/repo:pull""#
            ),
            vec![Challenge::Bearer {
                realm: "https://auth.example.com/token".to_owned(),
                service: Some("registry.example.com".to_owned()),
                scope: Some("repository:org/repo:pull".to_owned()),
            }]
        );
        // Unquoted values, extra whitespace, and an unknown parameter.
        assert_eq!(
            parse_challenges("Bearer realm=https://a/token,foo=bar,service=registry"),
            vec![Challenge::Bearer {
                realm: "https://a/token".to_owned(),
                service: Some("registry".to_owned()),
                scope: None,
            }]
        );
        assert_eq!(
            parse_challenges(r#"Basic realm="Registry""#),
            vec![Challenge::Basic]
        );
        // A header may advertise several schemes at once. Both are parsed, so a registry whose
        // *first* challenge is one this client cannot answer is still usable — that is the whole
        // point of parsing past the first one.
        let multi = r#"Negotiate, Bearer realm="https://auth.example.com/token",service="registry.example.com", Basic realm="Registry""#;
        assert_eq!(
            parse_challenges(multi),
            vec![
                Challenge::Bearer {
                    realm: "https://auth.example.com/token".to_owned(),
                    service: Some("registry.example.com".to_owned()),
                    scope: None,
                },
                Challenge::Basic,
            ],
            "the unsupported `Negotiate` scheme is dropped, not treated as fatal"
        );
        // Selection prefers `Bearer` even when `Basic` comes first, and falls back to `Basic`.
        assert!(matches!(
            select_challenge(&parse_challenges(
                r#"Basic realm="Registry", Bearer realm="https://a/token""#
            )),
            Some(Challenge::Bearer { .. })
        ));
        assert_eq!(
            select_challenge(&parse_challenges(r#"Basic realm="Registry""#)),
            Some(&Challenge::Basic)
        );
        // A quoted value that contains a comma must not be split mid-value.
        assert_eq!(
            parse_challenges(r#"Bearer realm="https://a/token",scope="repository:a,b:pull""#),
            vec![Challenge::Bearer {
                realm: "https://a/token".to_owned(),
                service: None,
                scope: Some("repository:a,b:pull".to_owned()),
            }]
        );
        // No realm: not something this client can use, so it is dropped rather than guessed at.
        assert!(parse_challenges("Bearer service=registry").is_empty());
        assert!(parse_challenges("Negotiate").is_empty());
        assert!(parse_challenges("").is_empty());
        assert_eq!(select_challenge(&[]), None);
    }

    #[test]
    fn supported_media_types_match_the_extractor() {
        for media_type in supported_media_types() {
            assert!(
                is_supported_layer_media_type(media_type),
                "{media_type} must be accepted by the extractor too"
            );
        }
    }
}

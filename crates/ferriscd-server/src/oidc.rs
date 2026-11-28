//! OIDC / SSO bearer authentication (`T19.1`).
//!
//! `T14.3` authenticates every protected request with a Kubernetes `TokenReview`
//! ([`crate::auth::AuthPolicy::TokenReview`]), which is exactly right for a CI `ServiceAccount` and
//! exactly wrong for a human operator: it forces them to mint and paste a raw cluster token, and it
//! knows nothing about the corporate IdP's group lifecycle or MFA. This module adds the second
//! mechanism the `v1.x` roadmap promised — local validation of an OIDC JWT against the IdP's
//! published JWKS — behind the **existing** [`TokenAuthenticator`] seam, so no API handler and no
//! `RbacPolicy` rule changes: an identity is still "a username plus Kubernetes groups".
//!
//! ```text
//! Authorization: Bearer <jwt>
//!         │
//!         ▼
//!  parse (bounded)  ──► unverified `iss` routing hint ("is this ours to judge?")
//!         │
//!         ▼
//!  alg allow-list  ──► RS256 | ES256 | ES384 | EdDSA   (never `none`, never `HS*`)
//!         │
//!         ▼
//!  JWKS cache      ──► local signature verification; one rate-limited refresh per unknown `kid`
//!         │
//!         ▼
//!  claims          ──► iss (exact), aud (contains clientId), exp/nbf (±30 s), non-empty `sub`
//!         │
//!         ▼
//!  oidc:<sub> + oidc:<group>…  ──► AuthenticatedIdentity ──► RbacPolicy (unchanged)
//! ```
//!
//! # The four things that make this safe
//!
//! 1. **An algorithm allow-list, checked before any key is used.** `alg: none` (the classic "no
//!    signature" forgery) and `HS*` (the key-confusion attack: sign with the *public* RSA key as the
//!    HMAC secret) are refused by name, not by failing a verification — a signature check that is
//!    never reached cannot be bypassed. Every key is also matched to the `kty` its `alg` requires, so
//!    an RSA key can never be fed an ECDSA signature.
//! 2. **The identity namespace belongs to the IdP only through a mandatory prefix.** `sub` becomes
//!    `oidc:<sub>` and every claim group becomes `oidc:<group>`, so a malicious IdP claim of
//!    `system:masters` or `system:serviceaccount:kube-system:admin` can never become a Kubernetes
//!    group: it becomes the harmless `oidc:system:masters`. An empty prefix is refused at startup.
//! 3. **No per-request network I/O.** Signature verification is local (one `ring` call); the JWKS is
//!    fetched once, cached, and re-fetched **at most once per 60 s** on an unknown `kid`, so a flood
//!    of tokens with random `kid`s cannot be turned into an outbound DoS storm against the IdP (and
//!    a slow IdP can never stall a request: the refresh happens outside the cache lock). A caller
//!    that arrives while a refresh is already in flight **waits for that refresh** (single-flight,
//!    finding `M1`) instead of being refused, so a cold-start or rotation burst costs one fetch and
//!    one answer for every caller.
//! 4. **Expired credentials are never served from cache.** [`OidcOutcome::Accepted`] carries
//!    `exp - now`, which
//!    [`IdentityCache::insert_with_ttl`](crate::auth::IdentityCache::insert_with_ttl) clamps against
//!    the 30 s default: a JWT with 5 s left is cached for 5 s, not 30.
//!
//! # Secrets
//!
//! There is no client secret here (`T19.2`'s PKCE/BFF flow needs one): a verified JWT's claims are
//! public and the config holds an issuer, a client id, scopes and an optional CA bundle. The token
//! itself is never stored, never logged and never formatted — it reaches a log line only as the
//! 12-hex [`fingerprint_label`] of its SHA-256, exactly like a `TokenReview` token.
//!
//! The claims that *do* become an identity are screened, not trusted: a `sub` or a group carrying a
//! control character is refused (finding `M3`), so an IdP — or an attacker who can get one claim
//! into a token — cannot use a newline or an ANSI escape to forge a log line or an audit record.
//!
//! # For embedders
//!
//! [`HttpsJwksSource`] builds a `rustls` client, so **a process that links both `ring` and
//! `aws-lc-rs` must call [`ensure_crypto_provider`](ferriscd_controller::impersonation::ensure_crypto_provider)
//! once, before the first client is built.** `ferriscd` does it at startup; a library embedder that
//! skips it panics inside `rustls` at the first TLS handshake instead of failing here.
//!
//! # Fail closed, and when to fall through
//!
//! [`OidcTokenAuthenticator`] fails closed for every failure, and distinguishes the two kinds: a
//! token *it judged* and refused is `Ok(None)` (a `401`), while a key set that could not be
//! refreshed at all — an IdP outage, finding `M2` — is `Err(crate::error::ApiError::Backend)`, which the
//! middleware logs and audits as a backend failure rather than as an attacker's token.
//! [`CompositeTokenAuthenticator`] (`--auth-policy token-review-or-oidc`) consults OIDC **first**
//! and calls the `TokenReview` fallback only when the token is not one of ours at all
//! ([`NotApplicable`]) — a token that carries this server's issuer but a bad signature, a wrong
//! audience or an expired `exp` is *refused*, never forwarded to the API server, so a hostile
//! caller cannot turn malformed OIDC tokens into etcd writes. A key-source failure is never
//! forwarded either: an API server is not a second opinion on our own IdP.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use futures::StreamExt as _;
use futures::future::BoxFuture;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;

use crate::auth::{
    AuthenticatedCredential, AuthenticatedIdentity, TokenAuthenticator, fingerprint_label,
    token_fingerprint,
};
use crate::error::ApiError;
use crate::state::SeamFuture;

// ---------------------------------------------------------------------------
// Limits and defaults
// ---------------------------------------------------------------------------

/// The username prefix a verified `sub` is mapped through (`--oidc-username-prefix`).
///
/// Mandatory and non-empty: without it, an IdP claim of `system:masters` would *be* the Kubernetes
/// group `system:masters`.
pub const DEFAULT_USERNAME_PREFIX: &str = "oidc:";

/// The groups prefix every claim group is mapped through (`--oidc-groups-prefix`).
pub const DEFAULT_GROUPS_PREFIX: &str = "oidc:";

/// The scopes the Web UI/CLI ask the IdP for (`--oidc-scopes`).
///
/// Published by `GET /api/v1/auth/config` so the SPA sends exactly what the server expects; the
/// server itself never uses a scope (it only verifies the resulting token).
pub const DEFAULT_SCOPES: [&str; 3] = ["openid", "profile", "email"];

/// The largest tolerated clock skew when checking `exp`/`nbf` (`T19.1`: "clock skew `<= 30s`").
///
/// A hard ceiling, not a default: a larger value is refused at startup because it would extend every
/// expired token's life for that much longer.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// The default tolerated clock skew (`<= 30s`).
pub const DEFAULT_CLOCK_SKEW: Duration = MAX_CLOCK_SKEW;

/// How often an unknown `kid` may trigger an on-demand JWKS refetch.
///
/// The `T19.1` trap guard: at most one outbound fetch per 60 s per server instance, so a caller
/// sending 100 tokens with 100 random `kid`s costs the IdP **one** request.
pub const DEFAULT_JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// The timeout of one discovery/JWKS HTTP request (connect **and** total).
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest JWKS document the server will read.
pub const MAX_JWKS_BYTES: usize = 512 * 1024;

/// The largest discovery document the server will read.
pub const MAX_DISCOVERY_BYTES: usize = 64 * 1024;

/// The largest number of keys a JWKS may contribute.
///
/// A hostile or misconfigured IdP must not be able to make one request walk ten thousand public keys
/// (that would be a cheap CPU denial of service on every authenticated request).
pub const MAX_JWKS_KEYS: usize = 64;

/// The largest number of candidates one token may be verified against.
pub const MAX_KEY_CANDIDATES: usize = 8;

/// The largest number of claim groups mapped onto an identity.
pub const MAX_CLAIMED_GROUPS: usize = 256;

/// The largest accepted `sub` length (a Kubernetes subject name stays far below this).
pub const MAX_SUBJECT_CHARS: usize = 256;

/// The largest accepted group name length.
pub const MAX_GROUP_CHARS: usize = 256;

/// The largest single JOSE segment (header, payload or signature) the decoder will touch.
const MAX_JOSE_PART_CHARS: usize = 4096;

/// The largest transport-error description a log line may carry.
const MAX_ERROR_CHARS: usize = 200;

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

/// The **only** JOSE signature algorithms this server accepts.
///
/// Deliberately an enum: there is no `Name` variant for `none` and none for `HS256`, so "is this
/// algorithm allowed?" cannot be answered by a string comparison somebody later relaxes — an
/// unknown `alg` parses to `None` and is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JoseAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 (every Okta/Keycloak/Entra/Dex default).
    Rs256,
    /// ECDSA over P-256 with SHA-256 (raw `r || s` signature).
    Es256,
    /// ECDSA over P-384 with SHA-384 (raw `r || s` signature).
    Es384,
    /// EdDSA over Ed25519.
    EdDsa,
}

impl JoseAlgorithm {
    /// Every accepted algorithm, in a stable order.
    pub const ALLOWED: [Self; 4] = [Self::Rs256, Self::Es256, Self::Es384, Self::EdDsa];

    /// Parses a JOSE `alg` value, or `None` for anything outside [`Self::ALLOWED`].
    ///
    /// `none`, `HS256`/`HS384`/`HS512` (symmetric key confusion), the `PS*` RSA-PSS family and the
    /// deprecated `ES256K` all answer `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            "ES384" => Some(Self::Es384),
            "EdDSA" => Some(Self::EdDsa),
            _ => None,
        }
    }

    /// The JOSE spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
        }
    }

    /// The key type (`kty`) this algorithm requires.
    #[must_use]
    pub const fn key_type(self) -> JwkKeyType {
        match self {
            Self::Rs256 => JwkKeyType::Rsa,
            Self::Es256 | Self::Es384 => JwkKeyType::EllipticCurve,
            Self::EdDsa => JwkKeyType::OctetKeyPair,
        }
    }

    /// The curve this algorithm requires (`None` for RSA).
    #[must_use]
    pub const fn curve(self) -> Option<JoseCurve> {
        match self {
            Self::Rs256 => None,
            Self::Es256 => Some(JoseCurve::P256),
            Self::Es384 => Some(JoseCurve::P384),
            Self::EdDsa => Some(JoseCurve::Ed25519),
        }
    }
}

/// A JWK `kty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwkKeyType {
    /// `RSA`: `n` and `e`.
    Rsa,
    /// `EC`: `crv` + `x` + `y`.
    EllipticCurve,
    /// `OKP`: `crv` (`Ed25519`) + `x`.
    OctetKeyPair,
}

/// A JWK `crv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoseCurve {
    /// NIST P-256 (`ES256`).
    P256,
    /// NIST P-384 (`ES384`).
    P384,
    /// Ed25519 (`EdDSA`).
    Ed25519,
}

impl JoseCurve {
    /// Parses a JWK `crv` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "P-256" => Some(Self::P256),
            "P-384" => Some(Self::P384),
            "Ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }

    /// The coordinate (or raw key) width in bytes.
    #[must_use]
    pub const fn coordinate_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::Ed25519 => 32,
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Everything the authenticator needs, and nothing secret.
///
/// Built by the binary from `--oidc-*` flags (`crates/ferriscd-cli/src/commands/server.rs`) and
/// **validated** by [`Self::validate`] — which [`OidcTokenAuthenticator::new`] calls again, so a
/// library embedder cannot construct an authenticator with an empty prefix either.
#[derive(Clone)]
pub struct OidcConfig {
    /// The IdP issuer, exactly as it appears in the `iss` claim (trailing `/` trimmed by validation).
    pub issuer: String,
    /// The OAuth client id this server is registered as; the token's `aud` must contain it.
    pub client_id: String,
    /// The mandatory username prefix (`oidc:`).
    pub username_prefix: String,
    /// The mandatory groups prefix (`oidc:`).
    pub groups_prefix: String,
    /// The scopes `GET /api/v1/auth/config` advertises.
    pub scopes: Vec<String>,
    /// The claim carrying group names (`groups`).
    pub groups_claim: String,
    /// The tolerated clock skew for `exp`/`nbf`; at most [`MAX_CLOCK_SKEW`].
    pub clock_skew: Duration,
    /// The minimum interval between two JWKS fetches.
    pub jwks_min_refresh_interval: Duration,
    /// The connect/total timeout of one discovery or JWKS request.
    pub http_timeout: Duration,
    /// Whether a plain-`http://` issuer is tolerated (a local development IdP only).
    pub allow_insecure_http: bool,
    /// An optional PEM CA bundle to trust the IdP with, from the `ferriscd.io/secret-type: oidc`
    /// `Secret` (`ca.crt`).
    pub ca_pem: Option<Vec<u8>>,
}

impl std::fmt::Debug for OidcConfig {
    /// Prints the configuration an operator needs to debug a failed login and **never** the CA
    /// bundle's bytes: the bundle is public material, but a `{:?}` that dumps a PEM into a log line
    /// is noise nobody can read.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("username_prefix", &self.username_prefix)
            .field("groups_prefix", &self.groups_prefix)
            .field("scopes", &self.scopes)
            .field("groups_claim", &self.groups_claim)
            .field("clock_skew", &self.clock_skew)
            .field("jwks_min_refresh_interval", &self.jwks_min_refresh_interval)
            .field("http_timeout", &self.http_timeout)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .field(
                "ca_pem",
                &self
                    .ca_pem
                    .as_ref()
                    .map(|pem| format!("<{} PEM bytes>", pem.len())),
            )
            .finish()
    }
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            username_prefix: DEFAULT_USERNAME_PREFIX.to_owned(),
            groups_prefix: DEFAULT_GROUPS_PREFIX.to_owned(),
            scopes: DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
            groups_claim: "groups".to_owned(),
            clock_skew: DEFAULT_CLOCK_SKEW,
            jwks_min_refresh_interval: DEFAULT_JWKS_MIN_REFRESH_INTERVAL,
            http_timeout: DEFAULT_HTTP_TIMEOUT,
            allow_insecure_http: false,
            ca_pem: None,
        }
    }
}

impl OidcConfig {
    /// A configuration for `issuer` and `client_id`, with the safe defaults.
    #[must_use]
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            ..Self::default()
        }
    }

    /// Replaces the mandatory username prefix.
    #[must_use]
    pub fn with_username_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.username_prefix = prefix.into();
        self
    }

    /// Replaces the mandatory groups prefix.
    #[must_use]
    pub fn with_groups_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.groups_prefix = prefix.into();
        self
    }

    /// Replaces the advertised scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Replaces the group claim name.
    #[must_use]
    pub fn with_groups_claim(mut self, claim: impl Into<String>) -> Self {
        self.groups_claim = claim.into();
        self
    }

    /// Replaces the tolerated clock skew (refused above [`MAX_CLOCK_SKEW`]).
    #[must_use]
    pub fn with_clock_skew(mut self, skew: Duration) -> Self {
        self.clock_skew = skew;
        self
    }

    /// Replaces the JWKS refresh interval.
    #[must_use]
    pub fn with_jwks_min_refresh_interval(mut self, interval: Duration) -> Self {
        self.jwks_min_refresh_interval = interval;
        self
    }

    /// Replaces the discovery/JWKS HTTP timeout.
    #[must_use]
    pub fn with_http_timeout(mut self, timeout: Duration) -> Self {
        self.http_timeout = timeout;
        self
    }

    /// Allows a plain-`http://` issuer (a local development IdP on `kind`, nothing else).
    #[must_use]
    pub fn with_allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Trusts the IdP through the PEM `ca_pem` bundle instead of only the system roots.
    #[must_use]
    pub fn with_ca_pem(mut self, ca_pem: Option<Vec<u8>>) -> Self {
        self.ca_pem = ca_pem;
        self
    }

    /// Validates and normalizes the configuration.
    ///
    /// # Errors
    ///
    /// [`OidcConfigError`] for an unusable issuer, an empty client id, an empty (or Kubernetes
    /// `system:`) identity prefix, an empty scope list, an over-large clock skew or a zero duration.
    /// The messages never quote a value: a rejected configuration is reported by *which* flag is
    /// wrong, so a log line cannot echo an operator's secret-adjacent input.
    pub fn validate(mut self) -> Result<Self, OidcConfigError> {
        self.issuer = self.issuer.trim().trim_end_matches('/').to_owned();
        validate_issuer(&self.issuer, self.allow_insecure_http)?;

        self.client_id = self.client_id.trim().to_owned();
        if self.client_id.is_empty() {
            return Err(OidcConfigError::EmptyClientId);
        }
        if self.client_id.chars().any(char::is_whitespace) {
            return Err(OidcConfigError::MalformedClientId);
        }

        validate_prefix(&self.username_prefix, "username")?;
        validate_prefix(&self.groups_prefix, "groups")?;

        self.groups_claim = self.groups_claim.trim().to_owned();
        if self.groups_claim.is_empty() {
            return Err(OidcConfigError::EmptyGroupsClaim);
        }

        if self.scopes.is_empty() {
            return Err(OidcConfigError::EmptyScopes);
        }
        for scope in &mut self.scopes {
            *scope = scope.trim().to_owned();
            if scope.is_empty() || scope.chars().any(|c| c.is_whitespace() || c == ',') {
                return Err(OidcConfigError::MalformedScope);
            }
        }

        if self.clock_skew > MAX_CLOCK_SKEW {
            return Err(OidcConfigError::ClockSkewTooLarge);
        }
        if self.jwks_min_refresh_interval.is_zero() {
            return Err(OidcConfigError::ZeroRefreshInterval);
        }
        if self.http_timeout.is_zero() {
            return Err(OidcConfigError::ZeroHttpTimeout);
        }
        Ok(self)
    }
}

/// Validates an issuer URL: absolute, `https://` (unless explicitly allowed), and unambiguous.
fn validate_issuer(issuer: &str, allow_insecure_http: bool) -> Result<(), OidcConfigError> {
    if issuer.is_empty() {
        return Err(OidcConfigError::EmptyIssuer);
    }
    let Ok(url) = reqwest::Url::parse(issuer) else {
        return Err(OidcConfigError::IssuerNotAbsolute);
    };
    match url.scheme() {
        "https" => {}
        // The trap guard: `http://` is refused unless the operator passed the local-dev flag.
        "http" if allow_insecure_http => {}
        "http" => return Err(OidcConfigError::InsecureIssuer),
        _ => return Err(OidcConfigError::IssuerNotAbsolute),
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OidcConfigError::IssuerCarriesAmbiguity);
    }
    Ok(())
}

/// Validates one mandatory identity prefix.
fn validate_prefix(prefix: &str, which: &'static str) -> Result<(), OidcConfigError> {
    if prefix.trim().is_empty() {
        return Err(match which {
            "groups" => OidcConfigError::EmptyGroupsPrefix,
            _ => OidcConfigError::EmptyUsernamePrefix,
        });
    }
    if prefix.chars().any(|c| c.is_whitespace() || c.is_control()) || prefix.contains(',') {
        return Err(OidcConfigError::MalformedPrefix { which });
    }
    // A prefix of `system:` (or `system:anything`) would hand the IdP the cluster-local identity
    // namespace back, which is precisely what the prefix exists to prevent.
    if prefix.starts_with("system:") {
        return Err(OidcConfigError::ReservedPrefix { which });
    }
    Ok(())
}

/// Why an [`OidcConfig`] was refused.
///
/// Every message names the flag and the rule, never the operator's value: `--oidc-issuer` may be an
/// internal hostname and a rejected configuration is logged at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OidcConfigError {
    /// No `--oidc-issuer`.
    #[error("--oidc-issuer must not be empty")]
    EmptyIssuer,
    /// The issuer is not an absolute `https://` URL.
    #[error("--oidc-issuer must be an absolute https URL")]
    IssuerNotAbsolute,
    /// The issuer uses `http://`.
    #[error(
        "--oidc-issuer uses `http://`; only a local development IdP may do that, and it requires \
         --oidc-insecure-http"
    )]
    InsecureIssuer,
    /// The issuer carries userinfo, a query, or a fragment.
    #[error("--oidc-issuer must not carry a username, password, query string or fragment")]
    IssuerCarriesAmbiguity,
    /// No `--oidc-client-id`.
    #[error("--oidc-client-id must not be empty")]
    EmptyClientId,
    /// The client id contains whitespace.
    #[error("--oidc-client-id must not contain whitespace")]
    MalformedClientId,
    /// No `--oidc-username-prefix`.
    #[error(
        "--oidc-username-prefix must not be empty: an unprefixed IdP subject could impersonate a \
         Kubernetes user"
    )]
    EmptyUsernamePrefix,
    /// No `--oidc-groups-prefix`.
    #[error(
        "--oidc-groups-prefix must not be empty: an unprefixed IdP group could impersonate \
         `system:masters` or a `system:serviceaccount:*` identity"
    )]
    EmptyGroupsPrefix,
    /// The prefix carries a delimiter that would let one claim become two groups.
    #[error("--oidc-{which}-prefix must not contain whitespace, a control character or a comma")]
    MalformedPrefix {
        /// `username` or `groups`.
        which: &'static str,
    },
    /// The prefix reuses the Kubernetes identity namespace.
    #[error(
        "--oidc-{which}-prefix must not start with `system:`: that is the Kubernetes identity \
         namespace the prefix exists to keep the IdP out of"
    )]
    ReservedPrefix {
        /// `username` or `groups`.
        which: &'static str,
    },
    /// No group claim name.
    #[error("--oidc-groups-claim must not be empty")]
    EmptyGroupsClaim,
    /// No `--oidc-scopes`.
    #[error("--oidc-scopes must list at least one scope")]
    EmptyScopes,
    /// A scope is empty or malformed.
    #[error("--oidc-scopes entries must be non-empty and must not contain whitespace or a comma")]
    MalformedScope,
    /// A clock skew above the hard ceiling.
    #[error("--oidc-clock-skew must not exceed 30s")]
    ClockSkewTooLarge,
    /// A zero JWKS refresh interval.
    #[error("--oidc-jwks-min-refresh-interval must be greater than zero")]
    ZeroRefreshInterval,
    /// A zero HTTP timeout.
    #[error("--oidc-http-timeout must be greater than zero")]
    ZeroHttpTimeout,
    /// The configured CA bundle is not a PEM certificate.
    #[error("the OIDC CA bundle is not a PEM certificate")]
    InvalidCa,
    /// The HTTP client could not be built (an unusable TLS provider, for instance).
    #[error("the OIDC HTTP client could not be built")]
    InvalidHttpClient,
}

// ---------------------------------------------------------------------------
// JWKs
// ---------------------------------------------------------------------------

/// The decoded public half of one JWK.
#[derive(Clone, PartialEq, Eq)]
pub enum JwkKey {
    /// An RSA public key: modulus and exponent, big-endian without leading zeros.
    Rsa {
        /// `n`.
        n: Vec<u8>,
        /// `e`.
        e: Vec<u8>,
    },
    /// An elliptic-curve public key: affine coordinates.
    EllipticCurve {
        /// `crv`.
        curve: JoseCurve,
        /// `x`.
        x: Vec<u8>,
        /// `y`.
        y: Vec<u8>,
    },
    /// An Ed25519 public key.
    Ed25519 {
        /// `x`: the raw 32-byte public key.
        x: Vec<u8>,
    },
}

impl std::fmt::Debug for JwkKey {
    /// Public keys are not secret, but printing 256 bytes of modulus into a log line is noise: the
    /// identities of the material are what a log needs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa { n, e } => f
                .debug_struct("Rsa")
                .field("modulus_bytes", &n.len())
                .field("exponent_bytes", &e.len())
                .finish(),
            Self::EllipticCurve { curve, x, y } => f
                .debug_struct("EllipticCurve")
                .field("curve", curve)
                .field("x_bytes", &x.len())
                .field("y_bytes", &y.len())
                .finish(),
            Self::Ed25519 { x } => f
                .debug_struct("Ed25519")
                .field("x_bytes", &x.len())
                .finish(),
        }
    }
}

impl JwkKey {
    /// The `kty` this material belongs to.
    #[must_use]
    pub const fn key_type(&self) -> JwkKeyType {
        match self {
            Self::Rsa { .. } => JwkKeyType::Rsa,
            Self::EllipticCurve { .. } => JwkKeyType::EllipticCurve,
            Self::Ed25519 { .. } => JwkKeyType::OctetKeyPair,
        }
    }
}

/// One public key from the IdP's JWKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    /// `kid`, when the IdP published one.
    pub kid: Option<String>,
    /// `alg`, when the IdP pinned one. A token whose `alg` differs is never verified with this key.
    pub algorithm: Option<JoseAlgorithm>,
    /// The decoded public material.
    pub key: JwkKey,
}

impl Jwk {
    /// Whether this key may be used to verify a `kid`/`alg` pair.
    ///
    /// Three things must line up: the key type the algorithm requires, the curve the algorithm
    /// requires, and — when the IdP pinned `alg` on the key — that exact algorithm. That last check
    /// is what stops one published key from being reused across algorithm families.
    #[must_use]
    pub fn is_candidate(&self, kid: Option<&str>, algorithm: JoseAlgorithm) -> bool {
        if let Some(kid) = kid
            && self.kid.as_deref() != Some(kid)
        {
            return false;
        }
        if self.algorithm.is_some_and(|pinned| pinned != algorithm) {
            return false;
        }
        if self.key.key_type() != algorithm.key_type() {
            return false;
        }
        match (&self.key, algorithm.curve()) {
            (JwkKey::Rsa { .. }, None) => true,
            (JwkKey::EllipticCurve { curve, .. }, Some(expected)) => *curve == expected,
            (JwkKey::Ed25519 { .. }, Some(JoseCurve::Ed25519)) => true,
            _ => false,
        }
    }

    /// Verifies `signature` over `message`.
    ///
    /// Every branch checks the signature **length** the JOSE encoding mandates before calling
    /// `ring`, so a malformed (or truncated) signature is a clean `false` rather than an error path a
    /// caller might treat differently.
    #[must_use]
    pub fn verify(&self, algorithm: JoseAlgorithm, message: &[u8], signature: &[u8]) -> bool {
        // The algorithm/key pairing is re-checked here, not just in `is_candidate`: `verify` is the
        // one function that touches the crypto, and it must be safe to call on its own.
        if !self.is_candidate(None, algorithm) {
            return false;
        }
        match (&self.key, algorithm) {
            (JwkKey::Rsa { n, e }, JoseAlgorithm::Rs256) => {
                if n.is_empty() || e.is_empty() || signature.len() > n.len() {
                    return false;
                }
                RsaPublicKeyComponents {
                    n: n.as_slice(),
                    e: e.as_slice(),
                }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok()
            }
            (
                JwkKey::EllipticCurve { curve, x, y },
                JoseAlgorithm::Es256 | JoseAlgorithm::Es384,
            ) => {
                let coordinate_len = curve.coordinate_len();
                if x.len() != coordinate_len
                    || y.len() != coordinate_len
                    || signature.len() != 2 * coordinate_len
                {
                    return false;
                }
                let Some(point) = uncompressed_point(x, y) else {
                    return false;
                };
                let verification: &'static dyn signature::VerificationAlgorithm = match curve {
                    JoseCurve::P256 => &signature::ECDSA_P256_SHA256_FIXED,
                    JoseCurve::P384 => &signature::ECDSA_P384_SHA384_FIXED,
                    JoseCurve::Ed25519 => return false,
                };
                UnparsedPublicKey::new(verification, point)
                    .verify(message, signature)
                    .is_ok()
            }
            (JwkKey::Ed25519 { x }, JoseAlgorithm::EdDsa) => {
                if x.len() != JoseCurve::Ed25519.coordinate_len() || signature.len() != 64 {
                    return false;
                }
                UnparsedPublicKey::new(&signature::ED25519, x.as_slice())
                    .verify(message, signature)
                    .is_ok()
            }
            _ => false,
        }
    }
}

/// The SEC1 uncompressed point encoding `ring` expects: `0x04 || x || y`.
fn uncompressed_point(x: &[u8], y: &[u8]) -> Option<Vec<u8>> {
    if x.len() != y.len() || x.is_empty() {
        return None;
    }
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    Some(point)
}

/// The IdP's published key set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Builds a set from already-decoded keys (tests and embedders).
    #[must_use]
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }

    /// How many usable keys the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set holds no usable key at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The usable keys.
    #[must_use]
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// Whether any key in the set could verify a `kid`/`alg` pair.
    #[must_use]
    pub fn has_candidate(&self, kid: Option<&str>, algorithm: JoseAlgorithm) -> bool {
        self.keys.iter().any(|key| key.is_candidate(kid, algorithm))
    }

    /// The (bounded) candidates for a `kid`/`alg` pair.
    #[must_use]
    pub fn candidates(&self, kid: Option<&str>, algorithm: JoseAlgorithm) -> Vec<&Jwk> {
        self.keys
            .iter()
            .filter(|key| key.is_candidate(kid, algorithm))
            .take(MAX_KEY_CANDIDATES)
            .collect()
    }

    /// Parses a JWKS document.
    ///
    /// Keys are filtered, never trusted: a key whose `use`/`key_ops`/`alg`/`kty`/`crv` is not a
    /// signing key this server can verify with is **skipped** (a JWKS legitimately carries encryption
    /// keys and symmetric secrets). A document with no usable key is an error, so a broken IdP
    /// publication fails loudly instead of producing an empty cache that silently rejects everybody.
    ///
    /// # Errors
    ///
    /// [`OidcError::InvalidJwks`] when the document is not a JWKS object, and
    /// [`OidcError::NoUsableKeys`] when nothing in it can verify a signature.
    pub fn parse_json(document: &[u8]) -> Result<Self, OidcError> {
        let raw: RawJwkSet = serde_json::from_slice(document)
            .map_err(|_| OidcError::InvalidJwks("the document is not a JWKS object"))?;
        // Usability is decided **before** the key budget is spent: a JWKS is allowed to carry
        // encryption keys and symmetric secrets, and taking the first `MAX_JWKS_KEYS` entries
        // verbatim would let an IdP that publishes 64 of those ahead of its signing key make the
        // whole set unusable (`NoUsableKeys` for a perfectly good document).
        let keys: Vec<Jwk> = raw
            .keys
            .iter()
            .filter_map(usable_jwk)
            .take(MAX_JWKS_KEYS)
            .collect();
        if keys.is_empty() {
            return Err(OidcError::NoUsableKeys);
        }
        Ok(Self { keys })
    }
}

/// The `serde` mirror of a JWKS document.
#[derive(Debug, Deserialize)]
struct RawJwkSet {
    #[serde(default)]
    keys: Vec<RawJwk>,
}

/// The `serde` mirror of one JWK. Every member is optional so a key of any type parses; the filter
/// that decides whether it is usable lives in [`usable_jwk`].
#[derive(Debug, Deserialize)]
struct RawJwk {
    #[serde(default)]
    kty: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    intended_use: Option<String>,
    #[serde(default)]
    key_ops: Option<Vec<String>>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

/// Turns one raw JWK into a usable signing key, or `None`.
///
/// This is the allow-list for key material: `oct` (a symmetric secret, i.e. the other half of an
/// `HS256` key-confusion attack), `use: enc`, a key restricted to `encrypt`, an `alg` outside
/// [`JoseAlgorithm::ALLOWED`] and any malformed coordinate are all dropped here.
fn usable_jwk(entry: &RawJwk) -> Option<Jwk> {
    if entry
        .intended_use
        .as_deref()
        .is_some_and(|value| value != "sig")
    {
        return None;
    }
    if let Some(operations) = entry.key_ops.as_deref()
        && !operations.iter().any(|operation| operation == "verify")
    {
        return None;
    }
    let algorithm = match entry.alg.as_deref() {
        None => None,
        // A key that advertises an algorithm this server does not accept is not a candidate for it.
        Some(value) => Some(JoseAlgorithm::parse(value)?),
    };
    let kid = entry
        .kid
        .as_deref()
        .map(str::trim)
        .filter(|kid| !kid.is_empty() && kid.chars().count() <= MAX_SUBJECT_CHARS)
        .map(ToOwned::to_owned);
    let key = match entry.kty.as_deref()? {
        "RSA" => {
            let n = decode_base64url(entry.n.as_deref()?)?;
            let e = decode_base64url(entry.e.as_deref()?)?;
            // 2048 bits is the smallest RS256 key `ring` will verify; a 8 KiB modulus is a
            // resource-exhaustion attempt, not a key.
            if n.len() < 256 || n.len() > 1024 || e.is_empty() || e.len() > 8 {
                return None;
            }
            JwkKey::Rsa { n, e }
        }
        "EC" => {
            let curve = JoseCurve::parse(entry.crv.as_deref()?)?;
            if curve == JoseCurve::Ed25519 {
                return None;
            }
            let x = decode_base64url(entry.x.as_deref()?)?;
            let y = decode_base64url(entry.y.as_deref()?)?;
            if x.len() != curve.coordinate_len() || y.len() != curve.coordinate_len() {
                return None;
            }
            JwkKey::EllipticCurve { curve, x, y }
        }
        "OKP" => {
            let curve = JoseCurve::parse(entry.crv.as_deref()?)?;
            if curve != JoseCurve::Ed25519 {
                return None;
            }
            let x = decode_base64url(entry.x.as_deref()?)?;
            if x.len() != JoseCurve::Ed25519.coordinate_len() {
                return None;
            }
            JwkKey::Ed25519 { x }
        }
        _ => return None,
    };
    Some(Jwk {
        kid,
        algorithm,
        key,
    })
}

/// Decodes one base64url JOSE segment (padding tolerated, nothing else).
fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() > MAX_JOSE_PART_CHARS {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why the IdP's documents could not be turned into a key set.
///
/// The transport strings are bounded and single-line; they can name the issuer (validated to carry
/// no credentials, no query and no fragment) but never a token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OidcError {
    /// The discovery document could not be fetched.
    #[error("the OIDC discovery document could not be fetched: {0}")]
    Discovery(String),
    /// The JWKS document could not be fetched.
    #[error("the OIDC JWKS could not be fetched: {0}")]
    Jwks(String),
    /// The discovery document is not usable.
    #[error("the OIDC discovery document is not usable: {0}")]
    InvalidDiscovery(&'static str),
    /// The JWKS document is not usable.
    #[error("the OIDC JWKS document is not usable: {0}")]
    InvalidJwks(&'static str),
    /// The document holds no key this server can verify a signature with.
    #[error("the OIDC key set holds no usable signing key")]
    NoUsableKeys,
    /// The refresh was rate limited.
    #[error("an OIDC key-set refresh was refused: at most one per {0:?}")]
    RefreshRateLimited(Duration),
    /// A zero refresh interval, which would disable the "at most one fetch per 60 s" trap guard.
    #[error("the OIDC key-set refresh interval must be longer than zero")]
    ZeroRefreshInterval,
    /// No key set is cached and none can be fetched right now: every token is unverifiable, so this
    /// is an outage (finding `M2`), not a verdict about the caller's credential.
    #[error("no OIDC key set is cached and the refresh is rate limited: at most one per {0:?}")]
    KeySetUnavailable(Duration),
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

/// Where a [`JwkSet`] comes from.
///
/// The production implementation is [`HttpsJwksSource`] (discovery + JWKS over HTTPS); a test
/// substitutes a table, which is what makes every claim below — one fetch per 60 s, key rotation, no
/// per-request network I/O — assertable without an IdP and without a socket.
pub trait JwksSource: Send + Sync + 'static {
    /// Fetches the current key set.
    fn fetch(&self) -> BoxFuture<'static, Result<JwkSet, OidcError>>;
}

/// The bounded, rate-limited JWKS cache.
///
/// One successful fetch is shared by every in-flight request; a refresh is started **outside** the
/// lock, so a slow or hanging IdP can never stall an authenticated request or another refresh. The
/// lock is only ever held for a map swap (`std::sync::Mutex` around plain data, never across an
/// `await`).
///
/// The rate limit bounds how often the IdP is asked; **single-flight** bounds how many callers one
/// refresh answers (finding `M1`). A caller that arrives while a fetch is already in flight awaits
/// that fetch's result instead of being told "rate limited" — otherwise the first burst after a
/// cold start (or after a key rotation) would answer `401` to every caller but the leader, for a
/// token that is perfectly valid.
///
/// The rate-limit timestamp is still recorded **before** the fetch, and the in-flight slot is
/// cleared by a drop guard, so the cache is cancellation-safe: a request dropped mid-fetch (a
/// disconnect, a client timeout) leaves the timestamp behind — never a "refresh in progress" flag
/// that would wedge the cache until the process restarts.
pub struct JwksCache {
    source: Arc<dyn JwksSource>,
    min_refresh_interval: Duration,
    /// Shared with each in-flight [`FlightGuard`], which clears the slot when the leading fetch is
    /// dropped without finishing.
    state: Arc<Mutex<JwksState>>,
    fetch_attempts: AtomicUsize,
}

#[derive(Default)]
struct JwksState {
    keys: Option<Arc<JwkSet>>,
    last_attempt: Option<tokio::time::Instant>,
    /// The fetch concurrent callers should await, when one is in progress.
    in_flight: Option<Arc<Flight>>,
}

impl std::fmt::Debug for JwksCache {
    /// Renders counts only (never a key, never a token).
    ///
    /// The cache's own mutex **is** taken here, for the duration of the `{:?}`: the lock is only
    /// ever held for a map swap and never across an `await`, so that cannot deadlock, but a caller
    /// that formats this type while holding its own view of the same data would be asking for a
    /// lock it cannot get. Nothing in this crate does that; the caveat is recorded because `Debug`
    /// is written by hand and a future field could change it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lock();
        f.debug_struct("JwksCache")
            .field("min_refresh_interval", &self.min_refresh_interval)
            .field("keys", &state.keys.as_ref().map(|keys| keys.len()))
            .field("refresh_in_flight", &state.in_flight.is_some())
            .field(
                "fetch_attempts",
                &self.fetch_attempts.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// The outcome of one shared key-set fetch.
type FlightOutcome = Result<Arc<JwkSet>, OidcError>;

/// A fetch in flight, which every concurrent caller shares instead of starting its own (finding
/// `M1`).
///
/// The leader publishes the outcome once; followers await it. Nothing here does I/O: the leader's
/// future is *not* stored (only its result channel is), which is what keeps a cancelled request
/// from leaving a fetch nobody drives behind — see [`FlightGuard`].
struct Flight {
    outcome: tokio::sync::watch::Sender<Option<FlightOutcome>>,
}

impl Flight {
    fn new() -> Self {
        let (outcome, _receiver) = tokio::sync::watch::channel(None);
        Self { outcome }
    }

    /// A handle that resolves when the leading fetch publishes its outcome.
    fn follower(&self) -> tokio::sync::watch::Receiver<Option<FlightOutcome>> {
        self.outcome.subscribe()
    }

    /// Hands the outcome to every current follower. A failed send just means they all went away.
    fn publish(&self, outcome: &FlightOutcome) {
        let _ = self.outcome.send(Some(outcome.clone()));
    }
}

/// Clears the in-flight slot when the leading fetch is dropped without finishing.
///
/// A dropped request (a disconnect, a client timeout) must not leave a flight behind that every
/// later caller waits on forever: the rate-limit stamp already keeps that from becoming a fetch
/// storm, and this keeps it from becoming a wedge. Followers observe the dropped sender and answer
/// with what the cache already holds.
struct FlightGuard {
    state: Arc<Mutex<JwksState>>,
    flight: Arc<Flight>,
    settled: bool,
}

impl FlightGuard {
    /// Records that the fetch finished (or failed) normally, so the drop guard does nothing: the
    /// leader has already cleared the slot while holding the lock.
    fn settle(&mut self) {
        self.settled = true;
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        clear_in_flight(&mut state, &self.flight);
    }
}

/// Clears `state.in_flight` when it is still `flight` (a newer leader is never clobbered).
fn clear_in_flight(state: &mut JwksState, flight: &Arc<Flight>) {
    if state
        .in_flight
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, flight))
    {
        state.in_flight = None;
    }
}

impl JwksCache {
    /// Builds a cache over `source`, refetching at most once per `min_refresh_interval`.
    ///
    /// # Errors
    ///
    /// [`OidcError::ZeroRefreshInterval`] when `min_refresh_interval` is zero. Finding `N5`: the
    /// `T19.1` trap guard ("at most one outbound fetch per 60 s") lives in this cache, so a zero
    /// interval would let an **embedder** — anything that builds the cache without going through
    /// [`OidcConfig::validate`] — turn a 100-token burst with 100 random `kid`s into 100 requests to
    /// the IdP. The guard is not optional, so the constructor refuses rather than silently
    /// substituting a default (a substitution would hide the misconfiguration).
    pub fn new(
        source: Arc<dyn JwksSource>,
        min_refresh_interval: Duration,
    ) -> Result<Self, OidcError> {
        if min_refresh_interval.is_zero() {
            return Err(OidcError::ZeroRefreshInterval);
        }
        Ok(Self {
            source,
            min_refresh_interval,
            state: Arc::new(Mutex::new(JwksState::default())),
            fetch_attempts: AtomicUsize::new(0),
        })
    }

    /// How many fetches this cache has **started** (the metric the rate-limit guard is asserted on).
    #[must_use]
    pub fn fetch_attempts(&self) -> usize {
        self.fetch_attempts.load(Ordering::Relaxed)
    }

    /// The currently cached key set, without touching the network.
    #[must_use]
    pub fn cached(&self) -> Option<Arc<JwkSet>> {
        self.lock().keys.as_ref().map(Arc::clone)
    }

    /// Eagerly fetches the key set (the binary calls this at startup, so the first login does not pay
    /// for the round trip).
    ///
    /// # Errors
    ///
    /// Whatever the source reported: a failed warm-up is a warning, not a startup failure, because
    /// the cache retries on demand.
    pub async fn warm_up(&self) -> Result<(), OidcError> {
        match self.refresh().await {
            Ok(keys) => {
                tracing::info!(
                    usable_keys = keys.len(),
                    "fetched the OIDC key set; bearer tokens are now verified locally"
                );
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "the OIDC key set could not be fetched; the first authenticated request will retry"
                );
                Err(error)
            }
        }
    }

    /// Fetches the key set now, subject to the rate limit.
    ///
    /// A caller that finds a fetch already in flight waits for **that** fetch instead of being
    /// refused (finding `M1`), so a burst of concurrent requests produces exactly one outbound
    /// request and one answer for all of them.
    ///
    /// # Errors
    ///
    /// [`OidcError::RefreshRateLimited`] when the last attempt is younger than the interval and no
    /// fetch is in flight, and whatever the source reported. A failed — or abandoned — attempt still
    /// counts as an attempt, so a broken IdP is polled at the same bounded rate as a healthy one.
    pub async fn refresh(&self) -> Result<Arc<JwkSet>, OidcError> {
        let now = tokio::time::Instant::now();
        // Which side of the flight this caller is on, decided under the lock and acted on outside
        // it: the fetch is the slow, remote part and must never hold the lock.
        enum Role {
            Lead(Arc<Flight>),
            Follow(tokio::sync::watch::Receiver<Option<FlightOutcome>>),
        }
        let role = {
            let mut state = self.lock();
            if let Some(flight) = state.in_flight.as_ref().map(Arc::clone) {
                Role::Follow(flight.follower())
            } else if let Some(last) = state.last_attempt
                && now.duration_since(last) < self.min_refresh_interval
            {
                return Err(OidcError::RefreshRateLimited(self.min_refresh_interval));
            } else {
                // Claimed before the fetch, and never rolled back: an abandoned fetch must still
                // count, or a hostile caller could cancel its way into a fetch storm.
                state.last_attempt = Some(now);
                self.fetch_attempts.fetch_add(1, Ordering::Relaxed);
                let flight = Arc::new(Flight::new());
                state.in_flight = Some(Arc::clone(&flight));
                Role::Lead(flight)
            }
        };
        match role {
            Role::Lead(flight) => self.lead(flight).await,
            Role::Follow(mut follower) => {
                loop {
                    // Explicit `*` deref: this clones the published outcome, not the borrowed guard.
                    let published = (*follower.borrow_and_update()).clone();
                    if let Some(outcome) = published {
                        return outcome;
                    }
                    if follower.changed().await.is_err() {
                        // The leading fetch was dropped without an answer (its request was
                        // cancelled). Fail closed on what the cache already holds rather than
                        // waiting for a fetch nobody is driving any more.
                        return self
                            .cached()
                            .ok_or(OidcError::RefreshRateLimited(self.min_refresh_interval));
                    }
                }
            }
        }
    }

    /// Performs `flight`'s fetch and publishes its outcome to every follower.
    async fn lead(&self, flight: Arc<Flight>) -> Result<Arc<JwkSet>, OidcError> {
        let mut guard = FlightGuard {
            state: Arc::clone(&self.state),
            flight: Arc::clone(&flight),
            settled: false,
        };
        let outcome = self.source.fetch().await.map(Arc::new);
        {
            let mut state = self.lock();
            if let Ok(keys) = &outcome {
                state.keys = Some(Arc::clone(keys));
            }
            clear_in_flight(&mut state, &flight);
        }
        guard.settle();
        flight.publish(&outcome);
        outcome
    }

    /// The cached key set when it can verify `kid`/`alg`, otherwise a refreshed one.
    ///
    /// `Ok(None)` means "no key **for this token**": the key set is there, but nothing in it matches
    /// this `kid`/`alg` — a forged or rotated-away key, which the caller turns into the ordinary
    /// `401`. **No** negative authentication result is ever cached.
    ///
    /// # Errors
    ///
    /// A transport/parse failure of a fetch that was actually attempted, and
    /// [`OidcError::KeySetUnavailable`] when the cache holds no key set at all and cannot fetch one
    /// right now. The distinction is finding `M2`: with an empty cache *every* token is
    /// unverifiable, which is an IdP outage (retryable), not a verdict about the caller's
    /// credential.
    pub async fn keys_for(
        &self,
        kid: Option<&str>,
        algorithm: JoseAlgorithm,
    ) -> Result<Option<Arc<JwkSet>>, OidcError> {
        if let Some(keys) = self.cached()
            && keys.has_candidate(kid, algorithm)
        {
            return Ok(Some(keys));
        }
        match self.refresh().await {
            Ok(keys) => Ok(keys.has_candidate(kid, algorithm).then_some(keys)),
            // "Not now" is not an error *when there is a key set to answer from*: the caller refuses
            // the token with the ordinary `401`. With nothing cached at all there is no answer to
            // give, and pretending otherwise would report an outage as an attacker's token.
            Err(OidcError::RefreshRateLimited(interval)) => match self.cached() {
                Some(keys) => Ok(keys.has_candidate(kid, algorithm).then_some(keys)),
                None => Err(OidcError::KeySetUnavailable(interval)),
            },
            Err(error) => Err(error),
        }
    }

    fn lock(&self) -> MutexGuard<'_, JwksState> {
        // A poisoned cache still has to answer: the worst case is one extra fetch.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// ---------------------------------------------------------------------------
// The production key source: discovery + JWKS over HTTPS
// ---------------------------------------------------------------------------

/// The subset of `<issuer>/.well-known/openid-configuration` this server consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryDocument {
    /// The document's own `issuer` (must equal the configured issuer, exactly).
    pub issuer: String,
    /// Where the key set is published.
    pub jwks_uri: String,
}

/// The production [`JwksSource`]: OIDC discovery followed by the JWKS fetch.
///
/// HTTPS only (unless the local-dev flag allowed `http://`), a bounded timeout, no redirect following
/// (an `https://` URL that redirects to `http://` must not be honoured), a bounded response body, and
/// an optional extra CA bundle. Both documents are fetched at most once per cache refresh: the
/// discovery document is memoized here because it only changes when the IdP is re-installed.
pub struct HttpsJwksSource {
    issuer: String,
    allow_insecure_http: bool,
    client: reqwest::Client,
    discovery: Arc<Mutex<Option<DiscoveryDocument>>>,
}

impl std::fmt::Debug for HttpsJwksSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let memoized = self
            .discovery
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false);
        f.debug_struct("HttpsJwksSource")
            .field("issuer", &self.issuer)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .field("discovery_cached", &memoized)
            .finish()
    }
}

impl HttpsJwksSource {
    /// Builds the client for a validated configuration.
    ///
    /// A process that links both `ring` and `aws-lc-rs` **must** install a process-level `rustls`
    /// provider first — [`ensure_crypto_provider`](ferriscd_controller::impersonation::ensure_crypto_provider),
    /// which `ferriscd` calls at startup. An embedder that skips it panics inside `rustls` at the
    /// first handshake; this constructor cannot detect the condition for it.
    ///
    /// # Errors
    ///
    /// [`OidcConfigError::InvalidCa`] when the CA bundle is not a PEM certificate,
    /// [`OidcConfigError::InvalidHttpClient`] when the TLS client cannot be built.
    pub fn new(config: &OidcConfig) -> Result<Self, OidcConfigError> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.http_timeout)
            .connect_timeout(config.http_timeout)
            .https_only(!config.allow_insecure_http)
            // No redirects: a JWKS fetch must not be steerable to another host, and following one
            // would defeat the https-only rule above.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("ferriscd-server/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = config.ca_pem.as_deref() {
            let certificates = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|_| OidcConfigError::InvalidCa)?;
            if certificates.is_empty() {
                return Err(OidcConfigError::InvalidCa);
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder
            .build()
            .map_err(|_| OidcConfigError::InvalidHttpClient)?;
        Ok(Self {
            issuer: config.issuer.clone(),
            allow_insecure_http: config.allow_insecure_http,
            client,
            discovery: Arc::new(Mutex::new(None)),
        })
    }

    /// The issuer this source reads from.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

impl JwksSource for HttpsJwksSource {
    fn fetch(&self) -> BoxFuture<'static, Result<JwkSet, OidcError>> {
        let client = self.client.clone();
        let issuer = self.issuer.clone();
        let allow_insecure_http = self.allow_insecure_http;
        let slot = Arc::clone(&self.discovery);
        Box::pin(async move {
            let memoized = {
                let guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
                guard.clone()
            };
            let discovery = match memoized {
                Some(document) => document,
                None => {
                    let document = fetch_discovery(&client, &issuer, allow_insecure_http).await?;
                    let mut guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
                    *guard = Some(document.clone());
                    document
                }
            };
            let document = fetch_json(&client, &discovery.jwks_uri, MAX_JWKS_BYTES)
                .await
                .map_err(OidcError::Jwks)?;
            JwkSet::parse_json(&document)
        })
    }
}

/// Fetches and validates `<issuer>/.well-known/openid-configuration`.
async fn fetch_discovery(
    client: &reqwest::Client,
    issuer: &str,
    allow_insecure_http: bool,
) -> Result<DiscoveryDocument, OidcError> {
    let url = format!("{issuer}/.well-known/openid-configuration");
    let document = fetch_json(client, &url, MAX_DISCOVERY_BYTES)
        .await
        .map_err(OidcError::Discovery)?;
    validate_discovery(&document, issuer, allow_insecure_http)
}

/// Validates a discovery document against the configured issuer.
///
/// Split out from the fetch so the rules are a pure function with a test: the document's `issuer` must
/// match exactly ([OpenID Connect Discovery 1.0 §4.3](https://openid.net/specs/openid-connect-discovery-1_0.html)
/// requires it, and skipping it lets a hostile document point at another key set), and `jwks_uri` must
/// be HTTPS (unless the local-dev flag), credential-free and fragment-free.
fn validate_discovery(
    document: &[u8],
    issuer: &str,
    allow_insecure_http: bool,
) -> Result<DiscoveryDocument, OidcError> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        issuer: Option<String>,
        #[serde(default)]
        jwks_uri: Option<String>,
    }
    let raw: Raw = serde_json::from_slice(document).map_err(|_| {
        OidcError::InvalidDiscovery("the response is not a JSON object with `issuer`/`jwks_uri`")
    })?;
    let document_issuer = raw
        .issuer
        .ok_or(OidcError::InvalidDiscovery("the document has no `issuer`"))?;
    if document_issuer.trim_end_matches('/') != issuer {
        return Err(OidcError::InvalidDiscovery(
            "the document's `issuer` does not match the configured issuer",
        ));
    }
    let jwks_uri = raw.jwks_uri.ok_or(OidcError::InvalidDiscovery(
        "the document has no `jwks_uri`",
    ))?;
    let url = reqwest::Url::parse(&jwks_uri)
        .map_err(|_| OidcError::InvalidDiscovery("`jwks_uri` is not an absolute URL"))?;
    match url.scheme() {
        "https" => {}
        "http" if allow_insecure_http => {}
        _ => {
            return Err(OidcError::InvalidDiscovery(
                "`jwks_uri` must be an https URL",
            ));
        }
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(OidcError::InvalidDiscovery(
            "`jwks_uri` must not carry credentials or a fragment",
        ));
    }
    Ok(DiscoveryDocument {
        issuer: document_issuer,
        jwks_uri,
    })
}

/// Reads one JSON document with a hard size bound.
///
/// `bytes()` would allocate whatever the peer sends (and a chunked response declares no length), so
/// the body is assembled from a byte stream that stops at `cap`.
async fn fetch_json(client: &reqwest::Client, url: &str, cap: usize) -> Result<Vec<u8>, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| transport_error(&error))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "the identity provider answered HTTP {}",
            status.as_u16()
        ));
    }
    if let Some(declared) = response.content_length()
        && declared > cap as u64
    {
        return Err(format!(
            "the response declares {declared} bytes, over the {cap}-byte bound"
        ));
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| transport_error(&error))?;
        if body.len() + chunk.len() > cap {
            return Err(format!("the response exceeds the {cap}-byte bound"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// A bounded, single-line transport description (never a response body, never a token).
fn transport_error(error: &reqwest::Error) -> String {
    let text: String = error
        .to_string()
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_ERROR_CHARS)
        .collect();
    if error.is_timeout() {
        format!("timed out: {text}")
    } else {
        text
    }
}

// ---------------------------------------------------------------------------
// Token verification
// ---------------------------------------------------------------------------

/// Why a token was not evaluated at all.
///
/// [`CompositeTokenAuthenticator`] falls through to its `TokenReview` fallback for exactly these two:
/// the token is not this server's to judge. Everything else is a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotApplicable {
    /// Not a three-segment JWT (an opaque or non-JOSE credential).
    NotAJwt,
    /// A JWT whose (unverified) `iss` is somebody else's — a Kubernetes `ServiceAccount` token, for
    /// instance.
    ForeignIssuer,
}

impl NotApplicable {
    /// A stable label for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAJwt => "the credential is not a JOSE JWT",
            Self::ForeignIssuer => "the token's issuer is not this OIDC provider",
        }
    }
}

/// Why a token that claims to be ours was refused.
///
/// Carries no claim value: the label is what reaches a log line (the token's fingerprint is the only
/// other handle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The `alg` is not in [`JoseAlgorithm::ALLOWED`] (`none`, `HS*`, `PS*`, ...).
    UnsupportedAlgorithm,
    /// The JOSE header declares a critical extension this server does not implement.
    UnsupportedCriticalHeader,
    /// The JWKS holds no key for this `kid`.
    UnknownKeyId,
    /// No candidate key verified the signature.
    SignatureMismatch,
    /// The key set could not be refreshed or parsed: fail closed, never fall through.
    KeySource,
    /// A claim has the wrong type, or a value this server refuses (an empty `sub`, a `sub`/group
    /// carrying a control character).
    MalformedClaims,
    /// There is no numeric `exp`.
    MissingExpiry,
    /// `exp` is in the past, beyond the tolerated skew.
    Expired,
    /// `nbf` is in the future, beyond the tolerated skew.
    NotYetValid,
    /// `iss` is not exactly the configured issuer.
    IssuerMismatch,
    /// `aud` does not contain the configured client id.
    AudienceMismatch,
    /// `sub` is absent, empty, or unusable.
    MissingSubject,
}

impl Rejection {
    /// A stable, claim-free explanation (safe for a log line and for an audit reason).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedAlgorithm => {
                "the JWT `alg` is not in the asymmetric allow-list (RS256/ES256/ES384/EdDSA)"
            }
            Self::UnsupportedCriticalHeader => {
                "the JWT declares a `crit` extension this server does not implement"
            }
            Self::UnknownKeyId => "no key in the OIDC key set matches the JWT `kid`",
            Self::SignatureMismatch => "the JWT signature does not verify",
            Self::KeySource => "the OIDC key set could not be refreshed",
            Self::MalformedClaims => {
                "a JWT claim has an unusable type or value (an empty `sub`, or a control character \
                 in `sub`/a group)"
            }
            Self::MissingExpiry => "the JWT has no numeric `exp`",
            Self::Expired => "the JWT is expired",
            Self::NotYetValid => "the JWT is not valid yet (`nbf`)",
            Self::IssuerMismatch => "the JWT `iss` is not the configured issuer",
            Self::AudienceMismatch => "the JWT `aud` does not contain the configured client id",
            Self::MissingSubject => "the JWT has no usable `sub`",
        }
    }
}

/// The outcome of evaluating one bearer token as an OIDC credential.
///
/// Finding `N2a`: this carried an `identity()` convenience that no caller used — the
/// [`TokenAuthenticator`] seam only ever wants the [`AuthenticatedCredential`] (it carries the
/// `exp - now` lifetime the cache is clamped to), so the unused accessor was removed rather than
/// documented as public API.
#[derive(Debug, Clone)]
pub enum OidcOutcome {
    /// The token verified: an identity (and the cache lifetime its `exp` allows).
    Accepted(AuthenticatedCredential),
    /// The token is not this server's to judge: a composite may try its fallback.
    NotApplicable(NotApplicable),
    /// The token claimed to be ours and failed: refuse it, and do **not** fall through.
    Rejected(Rejection),
}

/// A clock, injected so `exp`/`nbf` are testable without sleeping and without a fake system clock.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The parsed (and **entirely unverified**) shape of a JOSE token.
struct ParsedJwt<'a> {
    algorithm: Option<JoseAlgorithm>,
    key_id: Option<String>,
    issuer: Option<String>,
    has_critical_header: bool,
    claims: serde_json::Value,
    signing_input: &'a str,
    signature: Vec<u8>,
}

impl<'a> ParsedJwt<'a> {
    /// Splits and decodes a token without interpreting any claim as trusted.
    fn parse(token: &'a str) -> Option<Self> {
        let mut segments = token.split('.');
        let header_segment = segments.next()?;
        let payload_segment = segments.next()?;
        let signature_segment = segments.next()?;
        if segments.next().is_some() || header_segment.is_empty() || payload_segment.is_empty() {
            return None;
        }
        #[derive(Deserialize)]
        struct RawHeader {
            #[serde(default)]
            alg: Option<String>,
            #[serde(default)]
            kid: Option<String>,
            #[serde(default)]
            crit: Option<Vec<String>>,
        }
        let header: RawHeader = serde_json::from_slice(&decode_base64url(header_segment)?).ok()?;
        let claims: serde_json::Value =
            serde_json::from_slice(&decode_base64url(payload_segment)?).ok()?;
        if !claims.is_object() {
            return None;
        }
        // The signature covers `<header>.<payload>` verbatim: that exact byte range is what is
        // verified, so re-encoding the header could never change what was signed.
        let signing_input = &token[..header_segment.len() + 1 + payload_segment.len()];
        Some(Self {
            algorithm: header.alg.as_deref().and_then(JoseAlgorithm::parse),
            key_id: header
                .kid
                .as_deref()
                .map(str::trim)
                .filter(|kid| !kid.is_empty() && kid.chars().count() <= MAX_SUBJECT_CHARS)
                .map(ToOwned::to_owned),
            issuer: claims
                .get("iss")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            has_critical_header: header.crit.is_some_and(|crit| !crit.is_empty()),
            claims,
            signing_input,
            signature: decode_base64url(signature_segment).unwrap_or_default(),
        })
    }
}

/// The claims a verified token contributes.
struct VerifiedClaims {
    subject: String,
    groups: Vec<String>,
    expires_in: i64,
}

/// An OIDC JWT authenticator: local signature verification plus strict claim validation.
///
/// Construct it with a validated [`OidcConfig`] and a [`JwksCache`]; the cache is shared by every
/// clone of this type (`Arc`), so one server instance performs one fetch per refresh window.
pub struct OidcTokenAuthenticator {
    config: Arc<OidcConfig>,
    keys: Arc<JwksCache>,
    clock: Clock,
}

impl std::fmt::Debug for OidcTokenAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcTokenAuthenticator")
            .field("issuer", &self.config.issuer)
            .field("client_id", &self.config.client_id)
            .field("username_prefix", &self.config.username_prefix)
            .field("groups_prefix", &self.config.groups_prefix)
            .field("clock_skew", &self.config.clock_skew)
            .field("keys", &self.keys)
            .finish()
    }
}

impl OidcTokenAuthenticator {
    /// Builds the authenticator, re-validating the configuration.
    ///
    /// # Errors
    ///
    /// [`OidcConfigError`] when the configuration is unusable (an empty identity prefix, a plain-`http`
    /// issuer without the development flag, an over-large clock skew, ...). Validation happens here
    /// *and* in [`OidcConfig::validate`] so neither the binary nor an embedder can skip it.
    pub fn new(config: OidcConfig, keys: Arc<JwksCache>) -> Result<Self, OidcConfigError> {
        Self::with_clock(config, keys, Arc::new(SystemTime::now))
    }

    /// Builds the authenticator with an injected clock (tests, and a future replayed-audit tool).
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_clock(
        config: OidcConfig,
        keys: Arc<JwksCache>,
        clock: Clock,
    ) -> Result<Self, OidcConfigError> {
        let config = config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            keys,
            clock,
        })
    }

    /// The validated configuration.
    #[must_use]
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// The shared key cache.
    #[must_use]
    pub fn keys(&self) -> &Arc<JwksCache> {
        &self.keys
    }

    /// Evaluates `token`, reporting *why* it was not accepted (the composite needs the distinction;
    /// [`TokenAuthenticator`] does not).
    pub async fn evaluate(&self, token: &str) -> OidcOutcome {
        let Some(parsed) = ParsedJwt::parse(token) else {
            return OidcOutcome::NotApplicable(NotApplicable::NotAJwt);
        };
        // The `iss` here is **unverified** and is used only to decide whether this token is ours to
        // judge: it can never contribute to the identity, and a forged value can only make the token
        // *more* likely to be refused (never authenticated).
        if parsed.issuer.as_deref() != Some(self.config.issuer.as_str()) {
            return OidcOutcome::NotApplicable(NotApplicable::ForeignIssuer);
        }
        if parsed.has_critical_header {
            return refusal(token, Rejection::UnsupportedCriticalHeader);
        }
        let Some(algorithm) = parsed.algorithm else {
            return refusal(token, Rejection::UnsupportedAlgorithm);
        };
        let keys = match self
            .keys
            .keys_for(parsed.key_id.as_deref(), algorithm)
            .await
        {
            Ok(Some(keys)) => keys,
            Ok(None) => return refusal(token, Rejection::UnknownKeyId),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    fingerprint = %fingerprint_label(&token_fingerprint(token)),
                    "the OIDC key set could not be refreshed; refusing the token (fail closed)"
                );
                return OidcOutcome::Rejected(Rejection::KeySource);
            }
        };
        let verified = keys
            .candidates(parsed.key_id.as_deref(), algorithm)
            .into_iter()
            .any(|key| {
                key.verify(
                    algorithm,
                    parsed.signing_input.as_bytes(),
                    &parsed.signature,
                )
            });
        if !verified {
            return refusal(token, Rejection::SignatureMismatch);
        }
        let now = (self.clock)();
        match verify_claims(&self.config, &parsed.claims, now) {
            Ok(claims) => {
                let identity = AuthenticatedIdentity::new(
                    format!("{}{}", self.config.username_prefix, claims.subject),
                    claims
                        .groups
                        .iter()
                        .map(|group| format!("{}{}", self.config.groups_prefix, group))
                        .collect(),
                );
                let ttl = Duration::from_secs(u64::try_from(claims.expires_in.max(0)).unwrap_or(0));
                tracing::debug!(
                    fingerprint = %fingerprint_label(&token_fingerprint(token)),
                    user = %identity.username.as_deref().unwrap_or_default(),
                    groups = identity.groups.len(),
                    alg = algorithm.as_str(),
                    "the OIDC token verified locally"
                );
                OidcOutcome::Accepted(AuthenticatedCredential::expiring(identity, ttl))
            }
            Err(rejection) => refusal(token, rejection),
        }
    }
}

/// Logs one refusal (fingerprint only) and returns it.
fn refusal(token: &str, rejection: Rejection) -> OidcOutcome {
    tracing::info!(
        fingerprint = %fingerprint_label(&token_fingerprint(token)),
        reason = rejection.as_str(),
        "an OIDC bearer token was refused"
    );
    OidcOutcome::Rejected(rejection)
}

/// Turns an [`OidcOutcome`] into the [`TokenAuthenticator`] seam's answer.
///
/// Three failures, two answers. A token this server judged and refused — a bad signature, a wrong
/// audience, an expired `exp` — is `Ok(None)`: the client gets the ordinary `401`, an attacker
/// learns nothing, and the audit trail records a rejected *token*. A key set that could not be
/// refreshed **at all** is `Err(ApiError::Backend)` (finding `M2`), so an IdP outage is
/// distinguishable from an attacker's token in the log, in the audit trail and in the response —
/// it is a retryable condition, not a verdict about the caller's credential.
fn seam_outcome(outcome: OidcOutcome) -> Result<Option<AuthenticatedCredential>, ApiError> {
    match outcome {
        OidcOutcome::Accepted(credential) => Ok(Some(credential)),
        OidcOutcome::Rejected(Rejection::KeySource) => Err(ApiError::backend(
            &"the OIDC key set could not be refreshed",
        )),
        OidcOutcome::Rejected(_) => Ok(None),
        OidcOutcome::NotApplicable(reason) => {
            tracing::debug!(
                reason = reason.as_str(),
                "the token is not an OIDC credential"
            );
            Ok(None)
        }
    }
}

impl TokenAuthenticator for OidcTokenAuthenticator {
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
        Box::pin(async move {
            Ok(seam_outcome(self.evaluate(token).await)?.map(|credential| credential.identity))
        })
    }

    fn authenticate_credential<'a>(
        &'a self,
        token: &'a str,
    ) -> SeamFuture<'a, Option<AuthenticatedCredential>> {
        Box::pin(async move { seam_outcome(self.evaluate(token).await) })
    }
}

/// Validates the claims of a token whose signature has already verified.
fn verify_claims(
    config: &OidcConfig,
    claims: &serde_json::Value,
    now: SystemTime,
) -> Result<VerifiedClaims, Rejection> {
    let issuer = claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .ok_or(Rejection::MalformedClaims)?;
    if issuer != config.issuer {
        return Err(Rejection::IssuerMismatch);
    }
    if !audience_matches(claims.get("aud"), &config.client_id) {
        return Err(Rejection::AudienceMismatch);
    }
    let now_seconds = unix_seconds(now);
    let skew = i64::try_from(config.clock_skew.as_secs()).unwrap_or(0);
    let expires_at = claims
        .get("exp")
        .and_then(numeric_seconds)
        .ok_or(Rejection::MissingExpiry)?;
    if now_seconds > expires_at.saturating_add(skew) {
        return Err(Rejection::Expired);
    }
    if let Some(not_before) = claims.get("nbf") {
        let not_before = numeric_seconds(not_before).ok_or(Rejection::MalformedClaims)?;
        if now_seconds.saturating_add(skew) < not_before {
            return Err(Rejection::NotYetValid);
        }
    }
    let subject = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|subject| !subject.is_empty() && subject.chars().count() <= MAX_SUBJECT_CHARS)
        .ok_or(Rejection::MissingSubject)?;
    // Finding `M3`: a `sub` becomes a username that reaches a log line, an audit record and a
    // `TokenFingerprint`-adjacent event. A newline or an ANSI escape in it could forge one of those
    // records, so the claim is screened exactly like a bearer token is (`BearerToken::parse`) and
    // the token is refused rather than sanitized: a subject that is not a plain name is not an
    // identity this server can attribute anything to.
    if has_control_characters(subject) {
        return Err(Rejection::MalformedClaims);
    }
    let groups = match claims.get(&config.groups_claim) {
        Some(serde_json::Value::Array(values)) => {
            // Every string in the array is screened before any of it is mapped, so a control
            // character in the *last* group cannot slip past the length filter of the first.
            if values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(has_control_characters)
            {
                return Err(Rejection::MalformedClaims);
            }
            // Finding `N1a`: an over-long group is dropped — it can never become a group name, and
            // refusing the whole token over one bad entry would let an IdP misconfiguration lock a
            // user out of every project. The drop is counted and logged (debug, claim-free) rather
            // than silent: an operator who grants access to a group that "disappeared" needs that
            // line. The count is accumulated **without allocating**, so a claim carrying a million
            // group entries costs one pass and at most [`MAX_CLAIMED_GROUPS`] strings.
            let mut groups = Vec::new();
            let mut dropped_over_long = 0_usize;
            let mut dropped_over_count = 0_usize;
            for group in values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|group| !group.is_empty())
            {
                if group.chars().count() > MAX_GROUP_CHARS {
                    dropped_over_long += 1;
                    continue;
                }
                if groups.len() == MAX_CLAIMED_GROUPS {
                    dropped_over_count += 1;
                    continue;
                }
                groups.push(group.to_owned());
            }
            if dropped_over_long > 0 {
                tracing::debug!(
                    dropped_groups = dropped_over_long,
                    max_group_chars = MAX_GROUP_CHARS,
                    "over-long groups in the OIDC group claim were dropped from the identity"
                );
            }
            if dropped_over_count > 0 {
                tracing::debug!(
                    dropped_groups = dropped_over_count,
                    max_claimed_groups = MAX_CLAIMED_GROUPS,
                    "the OIDC group claim carries more groups than the identity accepts; the tail \
                     was dropped"
                );
            }
            groups
        }
        // A single string is a common (non-standard) shape; treat anything else as "no groups"
        // rather than refusing an otherwise valid token.
        //
        // Finding `N1`: this branch enforces the **same two budgets** as the array branch above —
        // a control character is refused and an over-long group is dropped — so the single-string
        // shape cannot carry something the array shape would reject. An over-long single group is
        // filtered to "no groups" (exactly like an over-long array element), never truncated.
        //
        // Finding `N1a`: the drop is logged here too, so the single-string shape cannot lose a
        // group more quietly than the array shape does.
        Some(serde_json::Value::String(group)) => {
            if has_control_characters(group) {
                return Err(Rejection::MalformedClaims);
            }
            let group = group.trim();
            if group.is_empty() {
                Vec::new()
            } else if group.chars().count() > MAX_GROUP_CHARS {
                tracing::debug!(
                    dropped_groups = 1_usize,
                    max_group_chars = MAX_GROUP_CHARS,
                    "an over-long single-string group in the OIDC group claim was dropped from \
                     the identity"
                );
                Vec::new()
            } else {
                vec![group.to_owned()]
            }
        }
        _ => Vec::new(),
    };
    Ok(VerifiedClaims {
        subject: subject.to_owned(),
        groups,
        expires_in: expires_at.saturating_sub(now_seconds),
    })
}

/// Whether `value` carries a control character (a newline, a NUL, an ANSI escape, ...).
///
/// The same rule [`crate::auth::BearerToken::parse`] applies to a credential: an identity claim is
/// rendered into log lines, audit records and `Application.status`, so a claim that could break a
/// record into two is refused instead of escaped.
fn has_control_characters(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// Whether `aud` (a string or an array of strings) contains `client_id`.
fn audience_matches(audience: Option<&serde_json::Value>, client_id: &str) -> bool {
    match audience {
        Some(serde_json::Value::String(value)) => value == client_id,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(client_id))
        }
        _ => false,
    }
}

/// A numeric JOSE date claim, in seconds since the epoch.
fn numeric_seconds(value: &serde_json::Value) -> Option<i64> {
    if let Some(seconds) = value.as_i64() {
        return Some(seconds);
    }
    value
        .as_f64()
        .filter(|seconds| seconds.is_finite() && seconds.abs() < 9.0e18)
        .map(|seconds| seconds.trunc() as i64)
}

/// Seconds since the Unix epoch, saturating instead of panicking on a pre-epoch clock.
fn unix_seconds(now: SystemTime) -> i64 {
    match now.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// The composite authenticator
// ---------------------------------------------------------------------------

/// "Try OIDC, then fall back to `TokenReview`" (`--auth-policy token-review-or-oidc`).
///
/// The ordering is the point: a token that carries this server's issuer is verified **locally** and,
/// if it fails, is *refused* — it is never forwarded to the Kubernetes API server, so a caller sending
/// malformed OIDC tokens cannot turn the API server into an etcd write amplifier. Only a token that is
/// not ours at all ([`NotApplicable`]) reaches the fallback, which is exactly the CI
/// `ServiceAccount`-token case (`T19.1` risks/trade-offs).
pub struct CompositeTokenAuthenticator {
    oidc: Arc<OidcTokenAuthenticator>,
    fallback: Arc<dyn TokenAuthenticator>,
}

impl std::fmt::Debug for CompositeTokenAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeTokenAuthenticator")
            .field("oidc", &self.oidc)
            .finish_non_exhaustive()
    }
}

impl CompositeTokenAuthenticator {
    /// Builds the composite: OIDC first, `fallback` (a `TokenReview`) only for foreign credentials.
    #[must_use]
    pub fn new(oidc: Arc<OidcTokenAuthenticator>, fallback: Arc<dyn TokenAuthenticator>) -> Self {
        Self { oidc, fallback }
    }

    /// The OIDC half (for logs and tests).
    #[must_use]
    pub fn oidc(&self) -> &Arc<OidcTokenAuthenticator> {
        &self.oidc
    }
}

impl TokenAuthenticator for CompositeTokenAuthenticator {
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
        Box::pin(async move {
            Ok(self
                .authenticate_credential(token)
                .await?
                .map(|c| c.identity))
        })
    }

    fn authenticate_credential<'a>(
        &'a self,
        token: &'a str,
    ) -> SeamFuture<'a, Option<AuthenticatedCredential>> {
        Box::pin(async move {
            match self.oidc.evaluate(token).await {
                // Only "not ours to judge" falls through. A rejection — and, above all, a key-source
                // failure (finding `M2`) — is this server's verdict and is returned as it stands: an
                // unreachable IdP must not turn into a `TokenReview` against the API server.
                OidcOutcome::NotApplicable(reason) => {
                    tracing::debug!(
                        reason = reason.as_str(),
                        "falling back to the TokenReview authenticator"
                    );
                    self.fallback.authenticate_credential(token).await
                }
                outcome => seam_outcome(outcome),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;

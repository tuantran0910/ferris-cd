//! Optional server-side (BFF) OIDC session flow (`T19.2`).
//!
//! The SPA mode [`crate::auth::AuthPolicy::Oidc`] is paired with by `apps/ferriscd-web`'s own
//! Authorization Code + PKCE flow: the browser holds a short-lived token in memory and sends it as a
//! bearer credential. That is the strongest XSS posture — nothing persistent ever stores the token —
//! but it also means a hard refresh (or a second tab) signs the operator out, because the token lives
//! only in one JavaScript heap.
//!
//! This module is the **opt-in alternative** (`--oidc-bff-enabled`): the *token exchange happens on
//! the server*, and the browser holds nothing but two cookies:
//!
//! | Cookie | `HttpOnly` | Contents |
//! |---|---|---|
//! | [`SESSION_COOKIE_NAME`] | yes | AEAD-encrypted `{ access token, expiry, CSRF token }` |
//! | [`CSRF_COOKIE_NAME`] | **no** (the SPA has to read it) | the double-submit CSRF token |
//!
//! The session cookie is sealed with `ChaCha20-Poly1305` under a 256-bit key taken from the
//! `ferriscd.io/secret-type: oidc` `Secret` (or a file containing it), so a stolen cookie is useless
//! without the key and a tampered one fails the AEAD tag instead of authenticating.
//!
//! What this module refuses, deliberately:
//!
//! * **Any PKCE method but `S256`.** The verifier is 32 CSPRNG bytes (43 base64url characters); the
//!   exchange always sends `code_challenge_method=S256` and the token request always sends the
//!   verifier. `plain` is not representable.
//! * **Any redirect URI but the one configured.** The `redirect_uri` parameter of `GET
//!   /api/v1/auth/login` must equal [`BffConfig::redirect_uri`] byte for byte; a request that tries
//!   to steer the IdP at another URI is refused *before* a single outbound request is made, which is
//!   what stops the route from being an open redirect.
//! * **An unverifiable `state`.** Each login gets a 32-byte random `state`, and the callback consumes
//!   it exactly once, from a bounded, TTL'd store. A replayed, unknown or expired `state` answers
//!   `400` (the request is unusable, not a failed credential) and issues no cookie.
//! * **A `state` that belongs to another browser.** The value is also written to a short-lived
//!   [`STATE_COOKIE_NAME`] cookie at `/api/v1/auth/login`, and the callback requires the query
//!   parameter and the cookie to match **in constant time** before any code is exchanged. Without
//!   that binding, an attacker who starts a sign-in of their own and talks a victim into opening the
//!   resulting callback URL would hand the victim an *attacker-controlled* session (login CSRF /
//!   account swap): the victim would then work inside the attacker's account and leak whatever they
//!   upload into it.
//! * **An unbounded number of sign-ins.** `/api/v1/auth/login` charges a bounded per-client budget
//!   ([`LoginBudget`]) before it does any work, so one caller cannot spin up sign-ins in a loop and
//!   evict every other operator's pending transaction from the bounded store.
//! * **A mutating request that carries a session cookie without the matching CSRF header.** See
//!   [`csrf`].
//! * **Logging a code, a verifier or a token.** [`CodeExchangeRequest`] and [`ExchangedTokens`] both
//!   write their own `Debug`, [`BffError`] never quotes a value, and the IdP's error *body* is never
//!   copied into a message or a log line.
//!
//! A limit worth stating: the session cookie is **stateless** — it carries the access token and an
//! expiry, and the server keeps no session record. `/api/v1/auth/logout` therefore only stops *this*
//! browser: a copy of the cookie taken before the sign-out keeps authenticating until the token or the
//! cookie expires. Revoking a copied cookie early needs the IdP to revoke the token (or a server-side
//! denial list), neither of which this module has.
//!
//! A note on `nonce`: it is generated per transaction and sent in the authorization request, but the
//! ID token is deliberately **not** trusted here — the cookie carries only the access token, which the
//! very next API request hands to the [`crate::auth::TokenAuthenticator`] (`T19.1`), where `iss`,
//! `aud`, `exp`, `nbf` and the signature are checked against the IdP's JWKS. A nonce that this server
//! never verifies would be security theatre, so the ID token is not parsed at all rather than parsed
//! and believed.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, FromRequestParts, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::StreamExt as _;
use futures::future::BoxFuture;
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Names, defaults and limits
// ---------------------------------------------------------------------------

/// The route that starts the server-side flow.
pub const LOGIN_PATH: &str = "/api/v1/auth/login";

/// The route the IdP redirects the browser back to (the **exact** registered redirect URI's path).
pub const CALLBACK_PATH: &str = "/api/v1/auth/callback";

/// The route that clears the session cookies.
pub const LOGOUT_PATH: &str = "/api/v1/auth/logout";

/// Name of the encrypted session cookie (the browser never sees a token in clear).
///
/// `__Host-` prefixed, like every cookie this module issues: the browser then accepts the cookie only
/// if it is `Secure`, has `Path=/` and carries **no** `Domain`. A sibling subdomain (or a page on
/// `*.ferriscd.example.com` that an attacker controls) can therefore neither set nor overwrite it,
/// which rules out cookie tossing against the session.
pub const SESSION_COOKIE_NAME: &str = "__Host-ferriscd_session";

/// Name of the double-submit CSRF cookie.
///
/// Deliberately **not** `HttpOnly`: the SPA has to read it to echo it back in [`CSRF_HEADER`]. It is
/// not a credential on its own — the same value is also sealed inside the session cookie, and the
/// middleware requires all three to agree.
pub const CSRF_COOKIE_NAME: &str = "__Host-ferriscd_csrf";

/// Name of the short-lived cookie that binds one `state` to the browser that started the sign-in.
///
/// `HttpOnly` (nothing in the SPA needs it) and one-shot: `/api/v1/auth/callback` requires it to
/// equal the `state` query parameter and expires it whatever the outcome. This is the defence
/// against login CSRF / account swap (see the module docs).
pub const STATE_COOKIE_NAME: &str = "__Host-ferriscd_oidc_state";

/// The header carrying the double-submit CSRF token on mutating requests.
pub const CSRF_HEADER: &str = "x-ferriscd-csrf";

/// The Fetch Metadata header that tells the server where a request was initiated (RFC 8942 §3).
///
/// A browser sets it and a page cannot forge it, which is what makes it usable as one more signal.
pub const SEC_FETCH_SITE_HEADER: &str = "sec-fetch-site";

/// The [`SEC_FETCH_SITE_HEADER`] value that marks a request as initiated by another site.
pub const CROSS_SITE_FETCH_SITE: &str = "cross-site";

/// The only PKCE method this server implements (`plain` is never accepted).
pub const PKCE_METHOD: &str = "S256";

/// Default lifetime of a BFF session cookie (one hour).
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600);

/// Longest accepted session lifetime (12 hours). A BFF cookie outlives a tab, so it gets a ceiling
/// the SPA's in-memory token does not need.
pub const MAX_SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// How long a pending sign-in transaction (state + verifier) stays usable.
pub const DEFAULT_TRANSACTION_TTL: Duration = Duration::from_secs(300);

/// Longest accepted transaction lifetime.
pub const MAX_TRANSACTION_TTL: Duration = Duration::from_secs(900);

/// How many in-flight sign-in transactions one server keeps (bounded memory, oldest evicted).
pub const MAX_PENDING_TRANSACTIONS: usize = 512;

/// How many sign-ins **one client address** may start inside [`LOGIN_WINDOW`].
///
/// `/api/v1/auth/login` is unauthenticated by necessity (it is where a credential is obtained), so it
/// is the one route an anonymous caller can make the server work for. The pending-transaction store
/// is bounded at [`MAX_PENDING_TRANSACTIONS`] and evicts the oldest entry, which means a single client
/// looping the route could evict every other operator's in-flight sign-in — a cheap denial of service
/// on the login flow. Capping the *per-client* rate leaves the shared store out of one caller's reach:
/// 8 concurrent/rapid sign-ins is already more than a browser tab will ever cause (a retry loop is
/// what it bounds), and a legitimate operator who hits the cap is answered `429` with a message that
/// says to wait.
pub const MAX_LOGINS_PER_CLIENT: usize = 8;

/// The window the per-client sign-in budget is measured over.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(60);

/// How many distinct client addresses the sign-in budget tracks.
///
/// Same reasoning as [`MAX_PENDING_TRANSACTIONS`]: a bound, so a flood of source addresses costs a
/// fixed amount of memory. When it is reached, expired windows are dropped first and then the least
/// recently active address.
pub const MAX_TRACKED_LOGIN_CLIENTS: usize = 1024;

/// The smallest session key the AEAD accepts (256 bits).
pub const MIN_SESSION_KEY_BYTES: usize = 32;

/// The largest `Set-Cookie` value this server will produce or accept.
pub const MAX_SESSION_COOKIE_BYTES: usize = 4096;

/// The largest access token the server will put inside a session cookie.
///
/// Browsers drop a cookie whose name + value + attributes exceed ~4 KiB, and the sealed value is
/// `base64url(nonce || ciphertext)`: 2048 token characters seal to roughly 2.9 KiB of cookie, which
/// leaves room for the attributes. A longer token is refused rather than issued into a cookie the
/// browser will silently discard (a JWT for every IdP this project supports is ~1–1.5 KiB).
pub const MAX_ACCESS_TOKEN_CHARS: usize = 2048;

/// The largest discovery/token-endpoint response the BFF reads.
pub const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;

/// The associated data binding a sealed cookie to this format version.
const SESSION_AAD: &[u8] = b"ferriscd.session.v1";

/// The post-login landing path when the operator did not configure one.
pub const DEFAULT_POST_LOGIN_PATH: &str = "/";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a [`BffConfig`] was refused.
///
/// Every message names the flag and the rule, never the value: the session key is a secret and the
/// redirect URI can be an internal hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BffConfigError {
    /// No issuer was configured.
    #[error("the BFF flow requires an OIDC issuer")]
    EmptyIssuer,
    /// The issuer is not https and the local-dev flag is off.
    #[error("the BFF flow requires an https issuer (use --oidc-insecure-http for a local IdP)")]
    InsecureIssuer,
    /// No client id was configured.
    #[error("the BFF flow requires an OAuth client id")]
    EmptyClientId,
    /// No redirect URI was configured.
    #[error("the BFF flow requires --oidc-bff-redirect-uri: the exact URI registered at the IdP")]
    EmptyRedirectUri,
    /// The redirect URI is not absolute.
    #[error("--oidc-bff-redirect-uri must be an absolute http(s) URL")]
    RedirectUriNotAbsolute,
    /// The redirect URI carries userinfo, a query or a fragment.
    #[error("--oidc-bff-redirect-uri must not carry credentials, a query string or a fragment")]
    RedirectUriCarriesAmbiguity,
    /// A plain-`http` redirect URI that is not loopback.
    #[error("--oidc-bff-redirect-uri must be https unless it points at a loopback address")]
    RedirectUriNotLoopback,
    /// No session key.
    #[error("the BFF flow requires a 256-bit session key")]
    MissingSessionKey,
    /// The session key is too short.
    #[error("the BFF session key must be at least 32 bytes")]
    SessionKeyTooShort,
    /// A zero session lifetime.
    #[error("the BFF session lifetime must be greater than zero")]
    ZeroSessionTtl,
    /// A session lifetime above [`MAX_SESSION_TTL`].
    #[error("the BFF session lifetime must not exceed 12 hours")]
    SessionTtlTooLong,
    /// A zero transaction lifetime.
    #[error("the sign-in transaction lifetime must be greater than zero")]
    ZeroTransactionTtl,
    /// A transaction lifetime above [`MAX_TRANSACTION_TTL`].
    #[error("the sign-in transaction lifetime must not exceed 15 minutes")]
    TransactionTtlTooLong,
    /// A post-login path that is not a same-origin absolute path.
    #[error("--oidc-bff-post-login-path must be an absolute path such as / or /applications")]
    InvalidPostLoginPath,
    /// An empty scope list.
    #[error("the BFF flow requires at least one scope")]
    EmptyScopes,
    /// The TLS client could not be built (an invalid CA bundle, for instance).
    #[error("the BFF HTTP client could not be built")]
    InvalidHttpClient,
}

/// A failed BFF operation.
///
/// No variant and no message ever contains an authorization code, a PKCE verifier, an access token
/// or an IdP error body: [`Self::Exchange`] reports the status code only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BffError {
    /// The server was started without `--oidc-bff-enabled`.
    #[error("the server-side (BFF) sign-in flow is not enabled on this server")]
    Disabled,
    /// The request is malformed (a missing `code`, a missing `state`).
    #[error("the sign-in response is not usable")]
    InvalidRequest,
    /// The `state` is unknown, replayed or expired.
    #[error("the sign-in state is unknown or has expired; start the sign-in again")]
    UnknownState,
    /// The `state` query parameter is not the one this browser was given.
    #[error("this browser did not start the sign-in; start it again from this tab")]
    StateNotBoundToBrowser,
    /// This client started too many sign-ins too quickly.
    #[error("too many sign-ins were started from this address; wait a minute and try again")]
    TooManyLogins,
    /// The `redirect_uri` is not the registered one.
    #[error("redirect_uri is not registered for this server")]
    RedirectUriNotRegistered,
    /// The identity provider could not be reached or answered with an unusable document.
    #[error("the identity provider could not be reached")]
    Transport,
    /// The identity provider refused the code exchange.
    #[error("the identity provider refused the authorization code exchange (HTTP {status})")]
    Exchange {
        /// The HTTP status the token endpoint returned.
        status: u16,
    },
    /// The token endpoint returned no usable access token.
    #[error("the identity provider returned no usable access token")]
    NoAccessToken,
    /// The access token is too long to fit in a session cookie.
    #[error(
        "the identity provider's access token is too large for a session cookie; configure a \
         shorter-lived/scoped token"
    )]
    TokenTooLarge,
    /// The session cookie is missing, tampered with, or expired.
    #[error("the session cookie is not usable")]
    SessionCookie,
    /// The OS CSPRNG failed.
    #[error("secure randomness is unavailable")]
    Random,
    /// The configuration was refused.
    #[error(transparent)]
    Config(#[from] BffConfigError),
}

// ---------------------------------------------------------------------------
// The session key
// ---------------------------------------------------------------------------

/// The 256-bit AEAD key that seals the session cookie.
///
/// `Debug` prints `<redacted>`: the key is the one secret that turns a stolen cookie into a session.
#[derive(Clone)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Takes the first 32 bytes of `bytes`.
    ///
    /// # Errors
    ///
    /// [`BffConfigError::SessionKeyTooShort`] below [`MIN_SESSION_KEY_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BffConfigError> {
        if bytes.len() < MIN_SESSION_KEY_BYTES {
            return Err(BffConfigError::SessionKeyTooShort);
        }
        let mut key = [0_u8; 32];
        key.copy_from_slice(&bytes[..32]);
        Ok(Self(key))
    }

    /// Reads a key file: base64url/base64 (= 43+ characters) or raw bytes.
    ///
    /// The usual source is a projected `ferriscd.io/secret-type: oidc` `Secret` volume, where the key
    /// is stored base64-encoded.
    ///
    /// # Errors
    ///
    /// [`BffConfigError::SessionKeyTooShort`] when the file holds fewer than 32 bytes of entropy, and
    /// [`BffConfigError::MissingSessionKey`] when it is empty.
    pub fn from_secret_material(material: &[u8]) -> Result<Self, BffConfigError> {
        let trimmed: Vec<u8> = material
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        if trimmed.is_empty() {
            return Err(BffConfigError::MissingSessionKey);
        }
        // A base64/base64url key file is decoded; anything else is taken as raw bytes.
        let decoded = URL_SAFE_NO_PAD
            .decode(&trimmed)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&trimmed));
        if let Ok(decoded) = decoded
            && decoded.len() >= MIN_SESSION_KEY_BYTES
        {
            return Self::from_bytes(&decoded);
        }
        Self::from_bytes(&trimmed)
    }

    fn aead_key(&self) -> Result<aead::LessSafeKey, BffError> {
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &self.0)
            .map_err(|_| BffError::SessionCookie)?;
        Ok(aead::LessSafeKey::new(unbound))
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Everything the BFF routes need, and nothing the SPA may not learn.
///
/// Built by the binary from `--oidc-bff-*` flags and validated by [`Self::validate`] — which
/// [`BffState::new`] calls again, so an embedder cannot construct an unvalidated configuration either.
#[derive(Clone)]
pub struct BffConfig {
    /// The IdP issuer (also published by `GET /api/v1/auth/config`).
    pub issuer: String,
    /// The OAuth client id registered for this server.
    pub client_id: String,
    /// The scopes the flow requests.
    pub scopes: Vec<String>,
    /// The **exact** redirect URI registered at the IdP (`https://ferriscd.example.com/api/v1/auth/callback`).
    pub redirect_uri: String,
    /// The AEAD key for the session cookie.
    pub session_key: Option<SessionKey>,
    /// How long a session cookie stays valid.
    pub session_ttl: Duration,
    /// How long a pending sign-in transaction stays usable.
    pub transaction_ttl: Duration,
    /// Where the browser lands after a successful sign-in (same-origin path only).
    pub post_login_path: String,
    /// Whether a plain-`http` issuer/redirect URI is tolerated (a local IdP only).
    pub allow_insecure_http: bool,
}

impl fmt::Debug for BffConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BffConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("redirect_uri", &self.redirect_uri)
            .field("session_key", &self.session_key)
            .field("session_ttl", &self.session_ttl)
            .field("transaction_ttl", &self.transaction_ttl)
            .field("post_login_path", &self.post_login_path)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish()
    }
}

impl Default for BffConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            scopes: crate::oidc::DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
            redirect_uri: String::new(),
            session_key: None,
            session_ttl: DEFAULT_SESSION_TTL,
            transaction_ttl: DEFAULT_TRANSACTION_TTL,
            post_login_path: DEFAULT_POST_LOGIN_PATH.to_owned(),
            allow_insecure_http: false,
        }
    }
}

impl BffConfig {
    /// A configuration for `issuer` + `client_id` with the safe defaults.
    #[must_use]
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            ..Self::default()
        }
    }

    /// Sets the exact redirect URI registered at the IdP.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = uri.into();
        self
    }

    /// Sets the AEAD session key.
    #[must_use]
    pub fn with_session_key(mut self, key: SessionKey) -> Self {
        self.session_key = Some(key);
        self
    }

    /// Sets the scopes the flow requests.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Sets the session lifetime.
    #[must_use]
    pub fn with_session_ttl(mut self, ttl: Duration) -> Self {
        self.session_ttl = ttl;
        self
    }

    /// Sets the pending-transaction lifetime.
    #[must_use]
    pub fn with_transaction_ttl(mut self, ttl: Duration) -> Self {
        self.transaction_ttl = ttl;
        self
    }

    /// Sets where the browser lands after signing in.
    #[must_use]
    pub fn with_post_login_path(mut self, path: impl Into<String>) -> Self {
        self.post_login_path = path.into();
        self
    }

    /// Allows a plain-`http` issuer (a local IdP only).
    #[must_use]
    pub fn with_allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Validates and normalizes the configuration.
    ///
    /// # Errors
    ///
    /// [`BffConfigError`] for a missing/insecure issuer, an empty client id, a redirect URI that is
    /// not an exact absolute URL, a missing or short session key, a lifetime outside its ceiling, or a
    /// post-login path that could leave the origin.
    pub fn validate(mut self) -> Result<Self, BffConfigError> {
        self.issuer = self.issuer.trim().trim_end_matches('/').to_owned();
        if self.issuer.is_empty() {
            return Err(BffConfigError::EmptyIssuer);
        }
        let issuer = reqwest::Url::parse(&self.issuer).map_err(|_| BffConfigError::EmptyIssuer)?;
        match issuer.scheme() {
            "https" => {}
            "http" if self.allow_insecure_http => {}
            _ => return Err(BffConfigError::InsecureIssuer),
        }

        self.client_id = self.client_id.trim().to_owned();
        if self.client_id.is_empty() {
            return Err(BffConfigError::EmptyClientId);
        }

        self.scopes = self
            .scopes
            .iter()
            .map(|scope| scope.trim().to_owned())
            .filter(|scope| !scope.is_empty())
            .collect();
        if self.scopes.is_empty() {
            return Err(BffConfigError::EmptyScopes);
        }

        self.redirect_uri = self.redirect_uri.trim().to_owned();
        if self.redirect_uri.is_empty() {
            return Err(BffConfigError::EmptyRedirectUri);
        }
        let redirect = reqwest::Url::parse(&self.redirect_uri)
            .map_err(|_| BffConfigError::RedirectUriNotAbsolute)?;
        match redirect.scheme() {
            "https" => {}
            "http" => {
                let loopback = redirect.host_str().is_some_and(|host| {
                    matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
                });
                if !loopback {
                    return Err(BffConfigError::RedirectUriNotLoopback);
                }
            }
            _ => return Err(BffConfigError::RedirectUriNotAbsolute),
        }
        if redirect.host_str().is_none()
            || !redirect.username().is_empty()
            || redirect.password().is_some()
            || redirect.query().is_some()
            || redirect.fragment().is_some()
        {
            return Err(BffConfigError::RedirectUriCarriesAmbiguity);
        }

        if self.session_key.is_none() {
            return Err(BffConfigError::MissingSessionKey);
        }
        if self.session_ttl.is_zero() {
            return Err(BffConfigError::ZeroSessionTtl);
        }
        if self.session_ttl > MAX_SESSION_TTL {
            return Err(BffConfigError::SessionTtlTooLong);
        }
        if self.transaction_ttl.is_zero() {
            return Err(BffConfigError::ZeroTransactionTtl);
        }
        if self.transaction_ttl > MAX_TRANSACTION_TTL {
            return Err(BffConfigError::TransactionTtlTooLong);
        }

        self.post_login_path = self.post_login_path.trim().to_owned();
        let path = &self.post_login_path;
        // A path, not a URL: `//evil.example` would be a protocol-relative open redirect.
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\\')
            || path.chars().any(char::is_control)
        {
            return Err(BffConfigError::InvalidPostLoginPath);
        }
        Ok(self)
    }
}

// ---------------------------------------------------------------------------
// PKCE (RFC 7636) and random values
// ---------------------------------------------------------------------------

/// A `code_verifier` and the `S256` challenge derived from it.
#[derive(Clone, PartialEq, Eq)]
pub struct PkcePair {
    /// The 43-character base64url verifier (32 CSPRNG bytes).
    pub verifier: String,
    /// `BASE64URL(SHA256(verifier))`, unpadded.
    pub challenge: String,
}

impl fmt::Debug for PkcePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The verifier is a credential for the code exchange; only the challenge is public.
        f.debug_struct("PkcePair")
            .field("verifier", &"<redacted>")
            .field("challenge", &self.challenge)
            .finish()
    }
}

impl PkcePair {
    /// Generates a verifier from 32 CSPRNG bytes and its `S256` challenge.
    ///
    /// # Errors
    ///
    /// [`BffError::Random`] when the OS CSPRNG fails (never guess a verifier).
    pub fn generate() -> Result<Self, BffError> {
        let verifier = random_urlsafe_token()?;
        let challenge = s256_challenge(&verifier);
        Ok(Self {
            verifier,
            challenge,
        })
    }

    /// The challenge for an existing verifier (RFC 7636 test vectors use this).
    #[must_use]
    pub fn from_verifier(verifier: &str) -> Self {
        Self {
            verifier: verifier.to_owned(),
            challenge: s256_challenge(verifier),
        }
    }
}

/// `BASE64URL(SHA256(verifier))` without padding — the only PKCE method this server accepts.
#[must_use]
pub fn s256_challenge(verifier: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// 32 CSPRNG bytes as an unpadded base64url string (43 characters, 256 bits of entropy).
///
/// # Errors
///
/// [`BffError::Random`] when the OS CSPRNG cannot answer.
pub fn random_urlsafe_token() -> Result<String, BffError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| BffError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

// ---------------------------------------------------------------------------
// Pending sign-in transactions
// ---------------------------------------------------------------------------

/// The server-side half of one in-flight sign-in: the `state` it issued and the verifier it will
/// send at the token endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingTransaction {
    /// The random `state` echoed by the IdP.
    pub state: String,
    /// The random `nonce` (bound to the ID token when the IdP returns one).
    pub nonce: String,
    /// The PKCE verifier.
    pub code_verifier: String,
    /// The exact redirect URI this transaction was started with.
    pub redirect_uri: String,
    /// When the transaction was created (TTL anchor).
    pub created: Instant,
}

impl fmt::Debug for PendingTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTransaction")
            .field("state", &self.state)
            .field("nonce", &"<redacted>")
            .field("code_verifier", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// A bounded, TTL'd, one-shot store of pending sign-in transactions.
///
/// One-shot is the point: a `state` that has already completed a login cannot complete a second one,
/// and a replayed callback finds nothing.
#[derive(Debug)]
pub struct PendingTransactions {
    entries: HashMap<String, PendingTransaction>,
    order: VecDeque<String>,
    ttl: Duration,
    capacity: usize,
}

impl PendingTransactions {
    /// A store holding at most `capacity` transactions, each valid for `ttl`.
    #[must_use]
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// How many transactions are stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stores `transaction`, sweeping expired entries and evicting the oldest when full.
    pub fn insert(&mut self, transaction: PendingTransaction, now: Instant) {
        self.sweep(now);
        while self.entries.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.order.push_back(transaction.state.clone());
        self.entries.insert(transaction.state.clone(), transaction);
    }

    /// Removes and returns the transaction for `state`, or `None` when unknown or expired.
    ///
    /// The entry is removed **before** the caller acts on it, so two concurrent callbacks with the
    /// same `state` cannot both proceed.
    pub fn take(&mut self, state: &str, now: Instant) -> Option<PendingTransaction> {
        let transaction = self.entries.remove(state)?;
        self.order.retain(|candidate| candidate != state);
        if now.saturating_duration_since(transaction.created) > self.ttl {
            return None;
        }
        Some(transaction)
    }

    /// Drops every expired transaction.
    pub fn sweep(&mut self, now: Instant) {
        let ttl = self.ttl;
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, transaction)| now.saturating_duration_since(transaction.created) > ttl)
            .map(|(state, _)| state.clone())
            .collect();
        for state in expired {
            self.entries.remove(&state);
        }
        self.order
            .retain(|state| self.entries.contains_key(state.as_str()));
    }

    /// Drops one transaction without consuming it as a callback would.
    ///
    /// Used when `/api/v1/auth/login` fails *after* it stored the transaction (an unreachable
    /// discovery document, an unusable authorization endpoint): a `state` the browser never received
    /// must not sit in the bounded store occupying a slot another operator's sign-in needs.
    pub fn remove(&mut self, state: &str) {
        self.entries.remove(state);
        self.order.retain(|candidate| candidate != state);
    }
}

// ---------------------------------------------------------------------------
// The per-client sign-in budget
// ---------------------------------------------------------------------------

/// A bounded, per-client budget on how many sign-ins may be started inside a window.
///
/// See [`MAX_LOGINS_PER_CLIENT`] for what this defends against. It is deliberately tiny and clock-
/// injectable (like [`PendingTransactions`]) so its behaviour is provable without sleeping: every
/// method takes the `now` the caller measured.
#[derive(Debug)]
pub struct LoginBudget {
    window: Duration,
    per_client: usize,
    capacity: usize,
    clients: HashMap<String, VecDeque<Instant>>,
}

impl LoginBudget {
    /// A budget of `per_client` sign-ins per `window`, tracking at most `capacity` clients.
    #[must_use]
    pub fn new(window: Duration, per_client: usize, capacity: usize) -> Self {
        Self {
            window,
            per_client: per_client.max(1),
            capacity: capacity.max(1),
            clients: HashMap::new(),
        }
    }

    /// The production budget ([`LOGIN_WINDOW`] / [`MAX_LOGINS_PER_CLIENT`]).
    #[must_use]
    pub fn standard() -> Self {
        Self::new(
            LOGIN_WINDOW,
            MAX_LOGINS_PER_CLIENT,
            MAX_TRACKED_LOGIN_CLIENTS,
        )
    }

    /// How many clients are currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Whether no client is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Charges one sign-in to `client`; `false` when the client's window is already full.
    ///
    /// A refused attempt is **not** recorded, so a client that keeps hammering is refused from its
    /// first over-budget request onwards until the window slides past its earlier attempts.
    pub fn try_acquire(&mut self, client: &str, now: Instant) -> bool {
        let window = self.window;
        if let Some(attempts) = self.clients.get_mut(client) {
            attempts.retain(|attempt| now.saturating_duration_since(*attempt) < window);
            if attempts.len() >= self.per_client {
                return false;
            }
            attempts.push_back(now);
            return true;
        }
        if self.clients.len() >= self.capacity {
            self.sweep(now);
            while self.clients.len() >= self.capacity {
                // The least recently active client is the one to forget: it is the one least likely
                // to be mid-sign-in.
                let Some(oldest) = self
                    .clients
                    .iter()
                    .filter_map(|(client, attempts)| attempts.back().map(|last| (client, *last)))
                    .min_by_key(|(_, last)| *last)
                    .map(|(client, _)| client.clone())
                else {
                    break;
                };
                self.clients.remove(&oldest);
            }
        }
        let mut attempts = VecDeque::with_capacity(1);
        attempts.push_back(now);
        self.clients.insert(client.to_owned(), attempts);
        true
    }

    /// Drops every client whose window has fully slid past.
    pub fn sweep(&mut self, now: Instant) {
        let window = self.window;
        self.clients.retain(|_, attempts| {
            attempts.retain(|attempt| now.saturating_duration_since(*attempt) < window);
            !attempts.is_empty()
        });
    }
}

// ---------------------------------------------------------------------------
// The sealed session cookie
// ---------------------------------------------------------------------------

/// What a BFF session cookie carries.
///
/// `Debug` redacts the access token and the CSRF token: this type is the one place a browser-visible
/// credential exists, and a stray `{:?}` must not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    /// The access token the server sends to the API on the browser's behalf.
    pub access_token: String,
    /// The double-submit CSRF token (also mirrored in the readable cookie).
    pub csrf_token: String,
    /// Unix seconds at which the session stops being accepted.
    pub expires_at_unix: u64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("access_token", &"<redacted>")
            .field("csrf_token", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl Session {
    /// Whether the session is expired at `now`.
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        unix_seconds(now) >= self.expires_at_unix
    }
}

/// Seals and opens the session cookie with `ChaCha20-Poly1305`.
///
/// Layout: `BASE64URL(nonce || ciphertext || tag)`. The nonce is random per cookie, and
/// [`SESSION_AAD`] binds the ciphertext to this format so a value sealed for something else cannot be
/// replayed as a session.
pub struct SessionSealer {
    key: aead::LessSafeKey,
}

impl fmt::Debug for SessionSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSealer(<redacted key>)")
    }
}

impl SessionSealer {
    /// Builds a sealer for `key`.
    ///
    /// # Errors
    ///
    /// [`BffError::SessionCookie`] when the key cannot initialize the AEAD (impossible for a 32-byte
    /// key, reported rather than unwrapped).
    pub fn new(key: &SessionKey) -> Result<Self, BffError> {
        Ok(Self {
            key: key.aead_key()?,
        })
    }

    /// Encrypts `session` into a cookie value.
    ///
    /// # Errors
    ///
    /// [`BffError::Random`] when no nonce can be generated, [`BffError::SessionCookie`] when the
    /// payload cannot be serialized or sealed.
    pub fn seal(&self, session: &Session) -> Result<String, BffError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            t: &'a str,
            c: &'a str,
            e: u64,
        }
        let payload = serde_json::to_vec(&Payload {
            t: &session.access_token,
            c: &session.csrf_token,
            e: session.expires_at_unix,
        })
        .map_err(|_| BffError::SessionCookie)?;
        let mut nonce_bytes = [0_u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| BffError::Random)?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut buffer = payload;
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(SESSION_AAD), &mut buffer)
            .map_err(|_| BffError::SessionCookie)?;
        let mut sealed = Vec::with_capacity(nonce_bytes.len() + buffer.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&buffer);
        let encoded = URL_SAFE_NO_PAD.encode(sealed);
        if encoded.len() > MAX_SESSION_COOKIE_BYTES {
            // Belt and braces: `MAX_ACCESS_TOKEN_CHARS` already keeps a real token well under the
            // browser's cookie ceiling, and a value the browser would drop must never be issued.
            return Err(BffError::TokenTooLarge);
        }
        Ok(encoded)
    }

    /// Decrypts and validates a cookie value.
    ///
    /// # Errors
    ///
    /// [`BffError::SessionCookie`] for a value that is not a sealed session (wrong key, tampered
    /// bytes, another format version), is oversized, or is expired.
    pub fn open(&self, cookie_value: &str, now: SystemTime) -> Result<Session, BffError> {
        if cookie_value.len() > MAX_SESSION_COOKIE_BYTES {
            return Err(BffError::SessionCookie);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(cookie_value.trim())
            .map_err(|_| BffError::SessionCookie)?;
        if decoded.len() <= 12 {
            return Err(BffError::SessionCookie);
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(12);
        let nonce_array: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| BffError::SessionCookie)?;
        let mut buffer = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce_array),
                aead::Aad::from(SESSION_AAD),
                &mut buffer,
            )
            .map_err(|_| BffError::SessionCookie)?;
        #[derive(Deserialize)]
        struct Payload {
            t: String,
            c: String,
            e: u64,
        }
        let payload: Payload =
            serde_json::from_slice(plaintext).map_err(|_| BffError::SessionCookie)?;
        if payload.t.is_empty() || payload.t.chars().count() > MAX_ACCESS_TOKEN_CHARS {
            return Err(BffError::SessionCookie);
        }
        if payload.c.is_empty() {
            return Err(BffError::SessionCookie);
        }
        let session = Session {
            access_token: payload.t,
            csrf_token: payload.c,
            expires_at_unix: payload.e,
        };
        if session.is_expired(now) {
            return Err(BffError::SessionCookie);
        }
        Ok(session)
    }
}

/// The credential a request presents through the BFF session cookie.
#[derive(Debug)]
pub enum SessionCredential {
    /// No session cookie at all (a bearer-credential client such as the CLI).
    Absent,
    /// A session cookie that does not open (tampered, expired, sealed with another key).
    Invalid,
    /// A valid session.
    Active(Session),
}

// ---------------------------------------------------------------------------
// The IdP side: authorization endpoint + code exchange
// ---------------------------------------------------------------------------

/// The endpoints the BFF flow needs from `<issuer>/.well-known/openid-configuration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcEndpoints {
    /// Where the browser is sent to authenticate.
    pub authorization_endpoint: String,
    /// Where the server exchanges the code.
    pub token_endpoint: String,
}

/// One authorization-code exchange.
///
/// `Debug` redacts both the code and the verifier: they are single-use credentials for the token
/// endpoint and must never reach a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeExchangeRequest {
    /// The authorization code from the callback.
    pub code: String,
    /// The PKCE verifier minted when the sign-in started.
    pub code_verifier: String,
    /// The exact redirect URI the code was issued for.
    pub redirect_uri: String,
}

impl fmt::Debug for CodeExchangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeExchangeRequest")
            .field("code", &"<redacted>")
            .field("code_verifier", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// What the token endpoint returned.
#[derive(Clone, PartialEq, Eq)]
pub struct ExchangedTokens {
    /// The access token (a JWT for every IdP this project supports).
    pub access_token: String,
    /// How long the IdP says the token lives.
    pub expires_in: Option<Duration>,
}

impl fmt::Debug for ExchangedTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangedTokens")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// The seam the BFF routes talk to the IdP through.
///
/// One trait rather than two because both halves come from the same discovery document, and because a
/// test can then prove the whole flow — redirect, state, exchange — without a network.
pub trait OidcSession: Send + Sync + fmt::Debug {
    /// The authorization endpoint (discovery, memoized by the implementation).
    fn authorization_endpoint(&self) -> BoxFuture<'_, Result<String, BffError>>;

    /// Exchanges one authorization code for tokens (no client secret: a public client with PKCE).
    fn exchange(
        &self,
        request: CodeExchangeRequest,
    ) -> BoxFuture<'_, Result<ExchangedTokens, BffError>>;
}

/// The production [`OidcSession`]: discovery + token endpoint over HTTPS.
///
/// Same rules as [`crate::oidc::HttpsJwksSource`]: HTTPS unless the local-dev flag allowed `http://`,
/// no redirect following, bounded timeouts and a bounded body.
pub struct HttpsOidcSession {
    issuer: String,
    client_id: String,
    allow_insecure_http: bool,
    client: reqwest::Client,
    endpoints: tokio::sync::Mutex<Option<OidcEndpoints>>,
}

impl fmt::Debug for HttpsOidcSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsOidcSession")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish_non_exhaustive()
    }
}

impl HttpsOidcSession {
    /// Builds the discovery/token client for a validated [`BffConfig`].
    ///
    /// # Errors
    ///
    /// [`BffConfigError::InvalidHttpClient`] when the TLS client cannot be built (an unfetchable
    /// discovery document is a runtime [`BffError::Transport`], not a startup failure).
    pub fn new(
        config: &BffConfig,
        ca_pem: Option<&[u8]>,
        http_timeout: Duration,
    ) -> Result<Self, BffConfigError> {
        let mut builder = reqwest::Client::builder()
            .timeout(http_timeout)
            .connect_timeout(http_timeout)
            .https_only(!config.allow_insecure_http)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("ferriscd-server/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = ca_pem {
            let certificates = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|_| BffConfigError::InvalidHttpClient)?;
            if certificates.is_empty() {
                return Err(BffConfigError::InvalidHttpClient);
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder
            .build()
            .map_err(|_| BffConfigError::InvalidHttpClient)?;
        Ok(Self {
            issuer: config.issuer.clone(),
            client_id: config.client_id.clone(),
            allow_insecure_http: config.allow_insecure_http,
            client,
            endpoints: tokio::sync::Mutex::new(None),
        })
    }

    /// Fetches (once) and validates the discovery document's endpoints.
    async fn endpoints(&self) -> Result<OidcEndpoints, BffError> {
        {
            let cached = self.endpoints.lock().await;
            if let Some(endpoints) = cached.as_ref() {
                return Ok(endpoints.clone());
            }
        }
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let body = fetch(&self.client, &url).await?;
        let endpoints = parse_endpoints(&body, &self.issuer, self.allow_insecure_http)?;
        let mut cached = self.endpoints.lock().await;
        *cached = Some(endpoints.clone());
        Ok(endpoints)
    }
}

impl OidcSession for HttpsOidcSession {
    fn authorization_endpoint(&self) -> BoxFuture<'_, Result<String, BffError>> {
        Box::pin(async move { Ok(self.endpoints().await?.authorization_endpoint) })
    }

    fn exchange(
        &self,
        request: CodeExchangeRequest,
    ) -> BoxFuture<'_, Result<ExchangedTokens, BffError>> {
        Box::pin(async move {
            let endpoints = self.endpoints().await?;
            // `application/x-www-form-urlencoded`, built with `Url`'s own percent encoder: the
            // `reqwest` `form` feature is not enabled in this workspace and adding it is not worth a
            // dependency for five pairs.
            let body = form_body(&[
                ("grant_type", "authorization_code"),
                ("code", &request.code),
                ("code_verifier", &request.code_verifier),
                ("redirect_uri", &request.redirect_uri),
                ("client_id", &self.client_id),
            ])?;
            let response = self
                .client
                .post(&endpoints.token_endpoint)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
                .map_err(|_| BffError::Transport)?;
            let status = response.status();
            if !status.is_success() {
                return Err(BffError::Exchange {
                    status: status.as_u16(),
                });
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| BffError::Transport)?;
                if body.len() + chunk.len() > MAX_HTTP_BODY_BYTES {
                    return Err(BffError::NoAccessToken);
                }
                body.extend_from_slice(&chunk);
            }
            parse_token_response(&body)
        })
    }
}

/// Percent-encodes `pairs` as an `application/x-www-form-urlencoded` body.
///
/// Uses `Url`'s query encoder rather than a hand-rolled escape: a code or a verifier may contain
/// `+`, `/` or `=`, and a token endpoint that receives a mis-encoded verifier fails the exchange.
fn form_body(pairs: &[(&str, &str)]) -> Result<String, BffError> {
    let mut url =
        reqwest::Url::parse("https://form.invalid/").map_err(|_| BffError::InvalidRequest)?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    Ok(url.query().unwrap_or_default().to_owned())
}

/// Reads one bounded JSON document (no redirects, bounded body).
async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, BffError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| BffError::Transport)?;
    let status = response.status();
    if !status.is_success() {
        return Err(BffError::Transport);
    }
    if let Some(declared) = response.content_length()
        && declared > MAX_HTTP_BODY_BYTES as u64
    {
        return Err(BffError::Transport);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| BffError::Transport)?;
        if body.len() + chunk.len() > MAX_HTTP_BODY_BYTES {
            return Err(BffError::Transport);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Validates a discovery document: exact `issuer`, and both endpoints present, `https` (unless the
/// local-dev flag) and credential-free.
fn parse_endpoints(
    document: &[u8],
    issuer: &str,
    allow_insecure_http: bool,
) -> Result<OidcEndpoints, BffError> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        issuer: Option<String>,
        #[serde(default)]
        authorization_endpoint: Option<String>,
        #[serde(default)]
        token_endpoint: Option<String>,
    }
    let raw: Raw = serde_json::from_slice(document).map_err(|_| BffError::Transport)?;
    let document_issuer = raw.issuer.ok_or(BffError::Transport)?;
    if document_issuer.trim_end_matches('/') != issuer {
        return Err(BffError::Transport);
    }
    let authorization_endpoint = validate_endpoint(
        raw.authorization_endpoint.ok_or(BffError::Transport)?,
        allow_insecure_http,
    )?;
    let token_endpoint = validate_endpoint(
        raw.token_endpoint.ok_or(BffError::Transport)?,
        allow_insecure_http,
    )?;
    Ok(OidcEndpoints {
        authorization_endpoint,
        token_endpoint,
    })
}

/// Validates one IdP endpoint URL.
fn validate_endpoint(raw: String, allow_insecure_http: bool) -> Result<String, BffError> {
    let url = reqwest::Url::parse(&raw).map_err(|_| BffError::Transport)?;
    match url.scheme() {
        "https" => {}
        "http" if allow_insecure_http => {}
        _ => return Err(BffError::Transport),
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(BffError::Transport);
    }
    Ok(raw)
}

/// Parses the token endpoint's JSON without ever quoting it in an error.
fn parse_token_response(document: &[u8]) -> Result<ExchangedTokens, BffError> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        access_token: Option<String>,
        #[serde(default)]
        expires_in: Option<u64>,
    }
    let raw: Raw = serde_json::from_slice(document).map_err(|_| BffError::NoAccessToken)?;
    let access_token = raw.access_token.unwrap_or_default();
    let access_token = access_token.trim().to_owned();
    if access_token.is_empty() || access_token.chars().count() > MAX_ACCESS_TOKEN_CHARS {
        return Err(BffError::NoAccessToken);
    }
    if access_token.chars().any(char::is_control) {
        return Err(BffError::NoAccessToken);
    }
    Ok(ExchangedTokens {
        access_token,
        expires_in: raw.expires_in.map(Duration::from_secs),
    })
}

// ---------------------------------------------------------------------------
// The BFF state the router holds
// ---------------------------------------------------------------------------

/// Everything the BFF routes share.
pub struct BffState {
    config: BffConfig,
    session: Arc<dyn OidcSession>,
    sealer: SessionSealer,
    pending: Mutex<PendingTransactions>,
    logins: Mutex<LoginBudget>,
}

impl fmt::Debug for BffState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pending = self
            .pending
            .lock()
            .map(|store| store.len())
            .unwrap_or_default();
        let clients = self
            .logins
            .lock()
            .map(|budget| budget.len())
            .unwrap_or_default();
        f.debug_struct("BffState")
            .field("config", &self.config)
            .field("pending_transactions", &pending)
            .field("tracked_login_clients", &clients)
            .finish_non_exhaustive()
    }
}

impl BffState {
    /// Builds the BFF state for a validated configuration.
    ///
    /// # Errors
    ///
    /// [`BffConfigError`] when the configuration is unusable; it cannot be constructed unvalidated.
    pub fn new(config: BffConfig, session: Arc<dyn OidcSession>) -> Result<Self, BffConfigError> {
        let config = config.validate()?;
        let key = config
            .session_key
            .clone()
            .ok_or(BffConfigError::MissingSessionKey)?;
        let sealer = SessionSealer::new(&key).map_err(|_| BffConfigError::MissingSessionKey)?;
        let pending = PendingTransactions::new(config.transaction_ttl, MAX_PENDING_TRANSACTIONS);
        Ok(Self {
            config,
            session,
            sealer,
            pending: Mutex::new(pending),
            logins: Mutex::new(LoginBudget::standard()),
        })
    }

    /// The validated configuration.
    #[must_use]
    pub fn config(&self) -> &BffConfig {
        &self.config
    }

    /// What the request's session cookie says (used by the auth middleware).
    #[must_use]
    pub fn session_credential(&self, headers: &HeaderMap, now: SystemTime) -> SessionCredential {
        match cookie_value(headers, SESSION_COOKIE_NAME) {
            None => SessionCredential::Absent,
            Some(value) => match self.sealer.open(value, now) {
                Ok(session) => SessionCredential::Active(session),
                Err(_) => SessionCredential::Invalid,
            },
        }
    }

    /// Charges one sign-in to `client`, or refuses when its budget is spent.
    fn acquire_login(&self, client: &str, now: Instant) -> bool {
        // A poisoned budget still has to answer; the worst case is one unbounded window.
        let mut budget = self.logins.lock().unwrap_or_else(PoisonError::into_inner);
        budget.try_acquire(client, now)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PendingTransactions> {
        // A poisoned store still has to answer; the worst case is losing one pending sign-in.
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// The peer address of this request, when the server installed connect info.
///
/// A tiny extractor rather than `Option<ConnectInfo<SocketAddr>>`: `axum` 0.8 implements
/// `OptionalFromRequestParts` for neither, so `ConnectInfo` in a handler signature would be a hard
/// requirement — and it is absent in every test (and in any embedder that does not use
/// [`crate::serve_listener`]). The per-client sign-in budget needs an address, not a failure mode.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(Option<SocketAddr>);

impl ClientAddr {
    /// The peer address, or `None` when the request carries none.
    #[must_use]
    pub fn address(self) -> Option<SocketAddr> {
        self.0
    }

    /// The budget key: the peer's IP (a port is per-connection, so it would defeat the budget), or
    /// `"unattributed"` for a router that was not built with connect info.
    #[must_use]
    pub fn budget_key(self) -> String {
        self.0
            .map_or_else(|| "unattributed".to_owned(), |peer| peer.ip().to_string())
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(peer)| *peer),
        ))
    }
}

/// The query of `GET /api/v1/auth/login`.
#[derive(Debug, Default, Deserialize)]
pub struct LoginQuery {
    /// The redirect URI the caller believes is registered. Must equal the configured one exactly.
    #[serde(default)]
    pub redirect_uri: Option<String>,
}

/// The query of `GET /api/v1/auth/callback`.
#[derive(Debug, Default, Deserialize)]
pub struct CallbackQuery {
    /// The authorization code.
    #[serde(default)]
    pub code: Option<String>,
    /// The `state` this server issued.
    #[serde(default)]
    pub state: Option<String>,
    /// An IdP error code (`access_denied`, ...). Never echoed back, only used to refuse cleanly.
    #[serde(default)]
    pub error: Option<String>,
}

/// `GET /api/v1/auth/login` — starts the BFF flow (`T19.2`).
///
/// Answers `302` to the IdP's authorization endpoint with a fresh `state`, `nonce` and `S256`
/// challenge — plus the short-lived [`STATE_COOKIE_NAME`] cookie that binds that `state` to this
/// browser — or `404` when the server was started without `--oidc-bff-enabled`.
///
/// `429` is the per-client sign-in budget ([`MAX_LOGINS_PER_CLIENT`] per [`LOGIN_WINDOW`]).
#[utoipa::path(
    get,
    path = "/api/v1/auth/login",
    tag = "auth",
    params(("redirect_uri" = Option<String>, Query, description = "The registered redirect URI; must match exactly")),
    responses(
        (status = 302, description = "Redirect to the identity provider's authorization endpoint"),
        (status = 400, description = "redirect_uri is not the registered one", body = crate::error::ApiErrorBody),
        (status = 404, description = "The BFF flow is not enabled on this server"),
        (status = 429, description = "Too many sign-ins were started from this address", body = crate::error::ApiErrorBody),
        (status = 502, description = "The identity provider's discovery document is unavailable", body = crate::error::ApiErrorBody),
    ),
)]
pub async fn login(
    State(state): State<AppState>,
    client_addr: ClientAddr,
    Query(query): Query<LoginQuery>,
) -> Response {
    let Some(bff) = state.bff.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(requested) = query.redirect_uri.as_deref() {
        // Exact match only: this route must never become an open redirect.
        if requested.trim() != bff.config.redirect_uri {
            return bff_error_response(BffError::RedirectUriNotRegistered);
        }
    }
    // The budget is charged before any work is done, so the cost of a refused request is one map
    // lookup (not a discovery fetch, a CSPRNG draw and a store entry).
    let client = client_addr.budget_key();
    if !bff.acquire_login(&client, Instant::now()) {
        tracing::info!(
            client = %client,
            "the BFF sign-in flow refused a request: the per-client sign-in budget is spent"
        );
        return bff_error_response(BffError::TooManyLogins);
    }
    let pair = match PkcePair::generate() {
        Ok(pair) => pair,
        Err(error) => return bff_error_response(error),
    };
    let (state_token, nonce) = match (random_urlsafe_token(), random_urlsafe_token()) {
        (Ok(state_token), Ok(nonce)) => (state_token, nonce),
        (Err(error), _) | (_, Err(error)) => return bff_error_response(error),
    };
    let transaction = PendingTransaction {
        state: state_token.clone(),
        nonce: nonce.clone(),
        code_verifier: pair.verifier.clone(),
        redirect_uri: bff.config.redirect_uri.clone(),
        created: Instant::now(),
    };
    bff.lock().insert(transaction, Instant::now());

    // From here on the transaction exists, so every failure path has to drop it: a `state` the
    // browser never received must not occupy one of the bounded store's slots (or, worse, be usable
    // by a callback whose URL nobody was given).
    let endpoint = match bff.session.authorization_endpoint().await {
        Ok(endpoint) => endpoint,
        Err(error) => {
            bff.lock().remove(&state_token);
            return bff_error_response(error);
        }
    };
    let url = match authorize_url(
        &endpoint,
        &bff.config.client_id,
        &bff.config.redirect_uri,
        &bff.config.scopes,
        &state_token,
        &nonce,
        &pair.challenge,
    ) {
        Ok(url) => url,
        Err(error) => {
            bff.lock().remove(&state_token);
            return bff_error_response(error);
        }
    };
    let location = match header::HeaderValue::from_str(&url) {
        Ok(location) => location,
        Err(_) => {
            bff.lock().remove(&state_token);
            return bff_error_response(BffError::InvalidRequest);
        }
    };
    let state_cookie = match header::HeaderValue::from_str(&session_cookie(
        STATE_COOKIE_NAME,
        &state_token,
        bff.config.transaction_ttl.as_secs().max(1),
        true,
    )) {
        Ok(cookie) => cookie,
        Err(_) => {
            bff.lock().remove(&state_token);
            return bff_error_response(BffError::InvalidRequest);
        }
    };
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    // The browser half of the `state` binding (`H1`): the callback requires this cookie to equal the
    // `state` query parameter, so a `state` an attacker obtained cannot be completed in *someone
    // else's* browser.
    response
        .headers_mut()
        .append(header::SET_COOKIE, state_cookie);
    no_store(&mut response);
    response
}

/// `GET /api/v1/auth/callback` — completes the BFF flow (`T19.2`).
///
/// Validates that `state` is **this browser's** (the [`STATE_COOKIE_NAME`] cookie must equal the query
/// parameter, compared in constant time), consumes the one-shot transaction, exchanges the code with
/// the stored verifier, seals a session cookie plus the CSRF cookie, and answers `303` to the
/// configured post-login path. The state cookie is expired on the response whatever the outcome.
#[utoipa::path(
    get,
    path = "/api/v1/auth/callback",
    tag = "auth",
    params(
        ("code" = Option<String>, Query, description = "The authorization code"),
        ("state" = Option<String>, Query, description = "The state this server issued"),
    ),
    responses(
        (status = 303, description = "Session established; redirect to the post-login path"),
        (status = 400, description = "The state is missing, unknown, expired or not this browser's", body = crate::error::ApiErrorBody),
        (status = 401, description = "The session cookie could not be sealed", body = crate::error::ApiErrorBody),
        (status = 404, description = "The BFF flow is not enabled on this server"),
        (status = 502, description = "The identity provider could not be reached", body = crate::error::ApiErrorBody),
    ),
)]
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(bff) = state.bff.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = match complete_callback(bff, &headers, query).await {
        Ok(response) => response,
        Err(error) => bff_error_response(error),
    };
    // Single use, whatever happened: only clear it when the browser actually sent one (a request with
    // no state cookie has nothing to forget, and answering it with a `Set-Cookie` would be noise).
    if cookie_value(&headers, STATE_COOKIE_NAME).is_some()
        && let Ok(value) = header::HeaderValue::from_str(&clear_cookie(STATE_COOKIE_NAME, true))
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// The body of [`callback`], minus the state-cookie bookkeeping.
///
/// # Errors
///
/// [`BffError`] for a refused sign-in: an IdP error, a missing/mismatched `state` cookie, an unknown
/// or expired transaction, a failed exchange, or an unsealable session.
async fn complete_callback(
    bff: &Arc<BffState>,
    headers: &HeaderMap,
    query: CallbackQuery,
) -> Result<Response, BffError> {
    if query.error.is_some() {
        // An IdP-side refusal (consent denied, expired request): no detail is reflected.
        return Err(BffError::InvalidRequest);
    }
    let Some(code) = query.code else {
        return Err(BffError::InvalidRequest);
    };
    let Some(query_state) = query.state else {
        return Err(BffError::InvalidRequest);
    };
    let query_state = query_state.trim().to_owned();
    // `H1`: the `state` must be the one *this browser* was given. Missing or mismatched is a refusal
    // *before* the exchange — otherwise an attacker who starts a sign-in of their own could hand a
    // victim a callback URL that signs the victim into the attacker's account (login CSRF / account
    // swap). Compared in constant time so the cookie value is not probeable byte by byte.
    let Some(cookie_state) = cookie_value(headers, STATE_COOKIE_NAME) else {
        return Err(BffError::StateNotBoundToBrowser);
    };
    if !bool::from(cookie_state.as_bytes().ct_eq(query_state.as_bytes())) {
        return Err(BffError::StateNotBoundToBrowser);
    }
    // The transaction is consumed before the exchange: a replayed callback (which would now also fail
    // the cookie check, since the state cookie is cleared on this response) can never complete twice.
    let Some(transaction) = bff.lock().take(&query_state, Instant::now()) else {
        return Err(BffError::UnknownState);
    };
    let tokens = bff
        .session
        .exchange(CodeExchangeRequest {
            code: code.trim().to_owned(),
            code_verifier: transaction.code_verifier,
            redirect_uri: transaction.redirect_uri,
        })
        .await?;
    let now = SystemTime::now();
    // The IdP's own lifetime is honoured but never extended past the configured ceiling.
    let ttl = tokens
        .expires_in
        .unwrap_or(bff.config.session_ttl)
        .min(bff.config.session_ttl);
    let csrf_token = random_urlsafe_token()?;
    let session = Session {
        access_token: tokens.access_token,
        csrf_token,
        expires_at_unix: unix_seconds(now).saturating_add(ttl.as_secs().max(1)),
    };
    let sealed = bff.sealer.seal(&session)?;
    let location = header::HeaderValue::from_str(&bff.config.post_login_path)
        .map_err(|_| BffError::InvalidRequest)?;
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    no_store(&mut response);
    let max_age = ttl.as_secs().max(1);
    for cookie in [
        session_cookie(SESSION_COOKIE_NAME, &sealed, max_age, true),
        session_cookie(CSRF_COOKIE_NAME, &session.csrf_token, max_age, false),
    ] {
        let value = header::HeaderValue::from_str(&cookie).map_err(|_| BffError::SessionCookie)?;
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    Ok(response)
}

/// `POST /api/v1/auth/logout` — clears the BFF session (`T19.2`).
///
/// Requires the double-submit CSRF header (see [`csrf`]) for a *usable* session: a cross-site page
/// must not be able to sign an operator out. A request the browser labels cross-site is refused
/// outright, even with no session cookie at all — otherwise any page could force the `Max-Age=0`
/// cookies to be stored. A cookie that no longer opens (expired, tampered, sealed under a rotated
/// key) is treated as absent here, because the caller's only remaining goal is to get rid of it —
/// refusing that would leave the browser stuck behind a `401` it cannot clear.
///
/// The session is stateless, so this cannot revoke a cookie that was copied before the sign-out: that
/// copy keeps working until the token (or the cookie) expires; only the IdP can revoke it earlier.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 204, description = "Session cookies cleared"),
        (status = 403, description = "The CSRF header is missing or does not match, or the sign-out was initiated from another site", body = crate::error::ApiErrorBody),
        (status = 404, description = "The BFF flow is not enabled on this server"),
    ),
)]
pub async fn logout(State(state): State<AppState>) -> Response {
    if state.bff.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    no_store(&mut response);
    for cookie in [
        clear_cookie(SESSION_COOKIE_NAME, true),
        clear_cookie(CSRF_COOKIE_NAME, false),
        clear_cookie(STATE_COOKIE_NAME, true),
    ] {
        match header::HeaderValue::from_str(&cookie) {
            Ok(value) => {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    response
}

/// The double-submit CSRF middleware for mutating API routes (`T19.2`).
///
/// It only engages for a request that actually carries the BFF session cookie: a `Bearer`-credential
/// request (the CLI, CI) cannot be forged by a cross-site page, so demanding a CSRF header from it
/// would break every scripted sync for no security gain. A request *with* a session cookie must echo
/// the CSRF token in [`CSRF_HEADER`] **and** in the readable [`CSRF_COOKIE_NAME`] cookie, and the
/// value must equal the one sealed inside the session — three-way equality, compared in constant
/// time.
///
/// [`LOGOUT_PATH`] is the one exception to "an unopenable cookie is a `401`": there, an invalid
/// session cookie is treated as *absent* so the handler can expire it. Otherwise a browser holding an
/// expired (or key-rotated) cookie could never clear it — every logout would be refused before the
/// handler ran, and the operator would be stuck signing in again. Nothing is authorized by that
/// request (the handler's only effect is `Set-Cookie: Max-Age=0`) — but it is still a *sign-out*, so
/// [`LOGOUT_PATH`] additionally refuses a request the browser itself labelled
/// [`CROSS_SITE_FETCH_SITE`]: a `SameSite=Lax` session cookie is withheld from a cross-site `POST`, so
/// such a request has nothing to authenticate — and answering it would still store the handler's
/// `Max-Age=0` cookies, which is a forced sign-out any page on the internet could trigger.
///
/// Only `cross-site` is refused: [`CROSS_SITE_FETCH_SITE`] is one browser-labelled value, and
/// `same-site` is deliberately **allowed**. A split-origin deployment (`app.example.com` calling
/// `api.example.com`, or two ports on one host) labels its own fetches `same-site`, so refusing that
/// would break it — and such a request still has to pass the three-way double-submit check above, which
/// a sibling-subdomain page cannot (it cannot set [`CSRF_HEADER`], and `Set-Cookie` is never sent on a
/// `403`). The residual is the dead-cookie path: a request with no *usable* session cookie is handed to
/// the [`LOGOUT_PATH`] handler, so a sibling subdomain can clear cookies that were already dead. That is
/// documented for operators in `deploy/README.md` ("CSRF and cross-site sign-out").
pub async fn csrf(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(bff) = state.bff.as_ref() else {
        return next.run(request).await;
    };
    let method = request.method().clone();
    if matches!(
        method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        return next.run(request).await;
    }
    let path = request.uri().path().to_owned();
    if path.starts_with("/api/v1/webhooks/") {
        // Webhooks authenticate with their own HMAC/token, never a cookie.
        return next.run(request).await;
    }
    if path == LOGOUT_PATH
        && request
            .headers()
            .get(SEC_FETCH_SITE_HEADER)
            .is_some_and(is_cross_site)
    {
        // The forced-sign-out defence: no cookie to authenticate with, and `Max-Age=0` must not be
        // delivered to a page that is not this origin. A browser that sends no `Sec-Fetch-Site`
        // (or `none`/`same-origin`/`same-site`) is unaffected, so the SPA and the dead-cookie
        // recovery path keep working.
        tracing::info!(
            path = %path,
            "cross-site sign-out refused: logout only accepts a request from this origin"
        );
        return ApiError::Forbidden {
            message: "sign-out is only accepted from this origin".to_owned(),
        }
        .into_response();
    }
    if cookie_value(request.headers(), SESSION_COOKIE_NAME).is_none() {
        return next.run(request).await;
    }
    let session = match bff.session_credential(request.headers(), SystemTime::now()) {
        SessionCredential::Active(session) => session,
        SessionCredential::Invalid => {
            if path == LOGOUT_PATH {
                // Nothing to authorize and nothing to protect (see the item docs): let the handler
                // clear the dead cookie instead of refusing the only request that can fix it.
                tracing::debug!(
                    path = %path,
                    "clearing an unusable BFF session cookie: logout treats it as absent"
                );
                return next.run(request).await;
            }
            return ApiError::unauthorized("the session cookie is not usable; sign in again")
                .into_response();
        }
        SessionCredential::Absent => return next.run(request).await,
    };
    // Scoped so the two borrowed tokens are released before `request` is moved into `next`.
    let csrf_ok = {
        let expected = session.csrf_token.as_bytes();
        let header_token = request
            .headers()
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .unwrap_or_default();
        let cookie_token = cookie_value(request.headers(), CSRF_COOKIE_NAME).unwrap_or_default();
        !header_token.is_empty()
            && bool::from(header_token.as_bytes().ct_eq(expected))
            && bool::from(cookie_token.as_bytes().ct_eq(expected))
    };
    if !csrf_ok {
        tracing::info!(
            path = %path,
            "mutating request refused: the CSRF header is missing or does not match the session"
        );
        return ApiError::Forbidden {
            message: "this request must carry the X-FerrisCD-CSRF header that matches the session \
                      cookie"
                .to_owned(),
        }
        .into_response();
    }
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds the authorization URL, percent-encoding every parameter.
///
/// `redirect_uri` is the configured value, verbatim: the IdP compares it byte for byte, and any
/// canonicalization here would break the registration match.
///
/// # Errors
///
/// [`BffError::Transport`] when `endpoint` is not an absolute URL.
pub fn authorize_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    nonce: &str,
    challenge: &str,
) -> Result<String, BffError> {
    let mut url = reqwest::Url::parse(endpoint).map_err(|_| BffError::Transport)?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", client_id);
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("scope", &scopes.join(" "));
        query.append_pair("state", state);
        query.append_pair("nonce", nonce);
        query.append_pair("code_challenge", challenge);
        query.append_pair("code_challenge_method", PKCE_METHOD);
    }
    Ok(url.into())
}

/// A `Set-Cookie` value for the session (`http_only`) or CSRF (`!http_only`) cookie.
fn session_cookie(name: &str, value: &str, max_age_secs: u64, http_only: bool) -> String {
    let mut cookie =
        format!("{name}={value}; Path=/; Max-Age={max_age_secs}; Secure; SameSite=Lax");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    cookie
}

/// A `Set-Cookie` value that deletes one cookie.
fn clear_cookie(name: &str, http_only: bool) -> String {
    let mut cookie = format!(
        "{name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=Lax"
    );
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    cookie
}

/// Whether a [`SEC_FETCH_SITE_HEADER`] value marks the request as cross-site.
///
/// The Fetch Metadata spec uses lowercase ASCII values, and the comparison is case-insensitive
/// anyway: a hand-written client must not be able to slip past the check by capitalising it.
fn is_cross_site(value: &header::HeaderValue) -> bool {
    value
        .to_str()
        .is_ok_and(|value| value.trim().eq_ignore_ascii_case(CROSS_SITE_FETCH_SITE))
}

/// Reads one cookie from the request headers.
fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    for header in headers.get_all(header::COOKIE) {
        let Ok(raw) = header.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            if key.trim() == name {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Marks a response as uncacheable and non-referrer-leaking.
fn no_store(response: &mut Response) {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
}

/// Maps a [`BffError`] onto a response the browser can act on, without echoing anything.
fn bff_error_response(error: BffError) -> Response {
    tracing::warn!(error = %error, "the BFF sign-in flow refused a request");
    match error {
        BffError::Disabled => StatusCode::NOT_FOUND.into_response(),
        // A malformed or unbound request is the caller's to fix by starting again, so it is a `400`
        // (the same status the `state` cases answer): none of them is a verdict about a credential.
        BffError::InvalidRequest
        | BffError::UnknownState
        | BffError::StateNotBoundToBrowser
        | BffError::RedirectUriNotRegistered => {
            ApiError::bad_request(error.to_string()).into_response()
        }
        BffError::TooManyLogins => ApiError::too_many_requests(error.to_string()).into_response(),
        BffError::SessionCookie => {
            ApiError::unauthorized("the session cookie is not usable; sign in again")
                .into_response()
        }
        // Infrastructure failures (an unreachable IdP, a refused exchange, an exhausted CSPRNG) are
        // `502`: the caller did nothing wrong and retrying later is the right move.
        BffError::Transport
        | BffError::Exchange { .. }
        | BffError::NoAccessToken
        | BffError::TokenTooLarge
        | BffError::Random => ApiError::backend(&error).into_response(),
        BffError::Config(_) => {
            ApiError::bad_request("the sign-in request could not be prepared").into_response()
        }
    }
}

/// Unix seconds for `time` (0 before the epoch, which no real clock reports).
fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;

//! API authentication via Kubernetes `TokenReview` (`T14.3`).
//!
//! The router keeps three disjoint route groups, and only the middle one is bearer-authenticated:
//!
//! | Group | Routes | Authentication |
//! |---|---|---|
//! | Public | `/healthz`, `/readyz` | none by design (probes carry no credential) |
//! | Webhooks | `/api/v1/webhooks/{github,gitlab}` | the webhook secret itself (`T14.2`) |
//! | Protected | every other `/api/v1/*` | [`AuthPolicy::TokenReview`] (default) |
//!
//! `T19.1` adds two policies that authenticate the same header with an enterprise IdP instead of the
//! cluster: [`AuthPolicy::Oidc`] (OIDC JWTs only) and [`AuthPolicy::TokenReviewOrOidc`] (a JWT *or* a
//! `ServiceAccount` token). Nothing else changes — the middleware still resolves an
//! [`AuthenticatedIdentity`] for the protected group, so every handler and every `RbacPolicy` rule is
//! untouched ([`crate::oidc`]).
//!
//! # The mechanism
//!
//! [`AuthPolicy::TokenReview`] — the **default** — reads `Authorization: Bearer <token>`, hashes the
//! token with SHA-256 and, on a cache miss, submits an `authentication.k8s.io/v1` `TokenReview` with
//! that token. Kubernetes is the only authority: FerrisCD stores no user database and validates no
//! JWT itself. A request with no token, a malformed header, a rejected token, an unreachable API
//! server, or an expired cached identity is answered `401 Unauthorized` — the policy is
//! **default-deny**, not "authenticate if you feel like it".
//!
//! ## Why a positive-only, 30 s cache
//!
//! Every protected request would otherwise cost one `TokenReview` write to the API server, which is
//! an etcd write: a dashboard polling `/api/v1/applications` every second would become an etcd
//! client. Only **successful** reviews are cached ([`IdentityCache`], 30 s, bounded), for two
//! reasons:
//!
//! * a **negative** result is exactly what an attacker controls. Caching "this token is bad" lets a
//!   hostile caller fill the cache and evict legitimate identities (and it changes nothing for the
//!   attacker, who is just as refused either way).
//! * a token that Kubernetes only *just* started accepting (a freshly minted projected
//!   `ServiceAccount` token) works on the first try, with no 30 s window of spurious `401`s.
//!
//! The cache is keyed by the token's SHA-256, never by the token: a heap dump of the API process
//! holds no usable credential, and neither a log line nor a `Debug` rendering can print one
//! ([`token_fingerprint`] is the only handle that ever reaches a log, and it is one-way).
//!
//! ## What a client learns
//!
//! A `401` never says *why* beyond "a valid Kubernetes bearer token is required": distinguishing
//! "no token", "expired token" and "token exists but is not a ServiceAccount" would help an attacker
//! enumerate credentials, and it helps a legitimate caller not at all (they re-run `ferriscd login`).
//! The detailed reason goes to the log, keyed by fingerprint.
//!
//! Authorization (which project an identity may read or sync) is `T14.4`'s [`crate::rbac`]; this
//! module only produces the [`AuthenticatedIdentity`] it consumes.
//!
//! ## The development escape hatch
//!
//! [`AuthPolicy::PassThrough`] authenticates nobody and lets every protected request through with an
//! anonymous identity. It exists for `kind`/`--api-addr 127.0.0.1` development and is refused by
//! nothing but the operator's judgment — so [`exposes_unauthenticated_api`] makes the combination
//! "pass-through on a non-loopback address" a startup warning in both the binary and
//! [`crate::serve_listener`]. [`AuthPolicy::DenyAll`] is the other extreme: a lockdown switch that
//! refuses every protected request *without* calling the API server (no token is even parsed).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ferriscd_engine::diff::sha256;

use crate::audit::{RequestId, TokenFingerprint, record_auth_denied};
use crate::error::ApiError;
use crate::state::{AppState, SeamFuture};

/// How long a successful `TokenReview` is trusted.
///
/// Kubernetes's own projected `ServiceAccount` tokens default to a one-hour lifetime and are rotated
/// well before expiry, so 30 s of staleness cannot outlive a revocation by more than the window —
/// while turning a polling dashboard's API-server write traffic into one write per identity per
/// 30 s.
pub const DEFAULT_IDENTITY_CACHE_TTL: Duration = Duration::from_secs(30);

/// How many identities the positive cache holds.
///
/// Bounded so a cluster with thousands of `ServiceAccount`s cannot make the API's memory a function
/// of the cluster size. When the cache is full, expired entries go first and then the oldest one.
pub const DEFAULT_IDENTITY_CACHE_CAPACITY: usize = 10_000;

/// Longest bearer token the API will even hash.
///
/// A token is attacker-controlled input: a 10 MiB `Authorization` header must not be hashed, cached,
/// or forwarded in a `TokenReview` request body. Every real token (a JWT, a legacy
/// `ServiceAccount` secret) is well under a kilobyte.
pub const MAX_BEARER_TOKEN_CHARS: usize = 4096;

/// The audit reason a credential that failed verification is recorded under.
///
/// Finding `N3`: the wording names **no credential and no scheme**. The audit sink runs every reason
/// through `sanitize_audit_reason`, which reads the word following `bearer` as an inline credential;
/// the previous reason (`the bearer token was rejected`) therefore reached an auditor as
/// `the bearer <redacted> was rejected` — a redaction of the word "token", not of a secret, that
/// made the trail harder to read and harder to trust. A claim-free phrasing is passed through
/// verbatim, which is why `auth::tests` asserts this exact string (see
/// `the_rejected_credential_audit_reason_is_claim_free_and_not_redacted`).
pub const REJECTED_CREDENTIAL_REASON: &str = "the presented credential was rejected";

/// The extension inserted on every request that reaches a protected handler.
///
/// Holds no credential: the token is never stored here (nor anywhere outside [`BearerToken`], which
/// is dropped before the handler runs), so a handler cannot leak it by accident.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthenticatedIdentity {
    /// Kubernetes user name (`system:serviceaccount:ns:name`), `None` when unauthenticated.
    pub username: Option<String>,
    /// Kubernetes groups.
    pub groups: Vec<String>,
}

impl AuthenticatedIdentity {
    /// The identity of a request that carried no credential (the pass-through dev escape).
    #[must_use]
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// The identity a `TokenReview` resolved.
    #[must_use]
    pub fn new(username: impl Into<String>, groups: Vec<String>) -> Self {
        Self {
            username: Some(username.into()),
            groups,
        }
    }

    /// Whether this identity came from a credential at all.
    ///
    /// `false` means the pass-through policy allowed the request anonymously — which is why `T14.4`
    /// treats it as unrestricted: refusing it would make the dev escape useless, and it is already
    /// the configuration that logs a loud startup warning.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.username.is_some()
    }

    /// Whether `group` is one of the identity's Kubernetes groups.
    #[must_use]
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|candidate| candidate == group)
    }
}

/// How protected routes are authenticated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthPolicy {
    /// Default: validate `Authorization: Bearer` with a Kubernetes `TokenReview`.
    ///
    /// **Default-deny**: a request without a valid token is `401`, including when the API server
    /// cannot be reached at all.
    #[default]
    TokenReview,
    /// `T19.1`: validate `Authorization: Bearer` as an OIDC JWT against the IdP's JWKS.
    ///
    /// Only human IdP tokens are accepted: a Kubernetes `ServiceAccount` token is refused (use
    /// [`Self::TokenReviewOrOidc`] to accept both). Verification is local, so a valid token costs no
    /// cluster round trip.
    Oidc,
    /// `T19.1`: accept an OIDC JWT **or** a Kubernetes `ServiceAccount` token.
    ///
    /// OIDC is consulted first ([`CompositeTokenAuthenticator`](crate::oidc::CompositeTokenAuthenticator)):
    /// a token carrying this server's issuer is verified locally and never costs a `TokenReview`,
    /// and only a credential that is not an OIDC token of ours falls through to the API server.
    TokenReviewOrOidc,
    /// Development escape hatch: no authentication, anonymous identity.
    ///
    /// Only defensible on a loopback bind ([`exposes_unauthenticated_api`]); every `/api/v1/*` route,
    /// sync and rollback included, is then writable by anyone who can reach the address.
    PassThrough,
    /// Lockdown: refuse every protected request without parsing a token or calling the API server.
    DenyAll,
}

impl AuthPolicy {
    /// A stable label for logs, `--auth-policy` and `GET /api/v1/auth/config`'s `authMode`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenReview => "token-review",
            Self::Oidc => "oidc",
            Self::TokenReviewOrOidc => "token-review-or-oidc",
            Self::PassThrough => "pass-through",
            Self::DenyAll => "deny-all",
        }
    }

    /// Whether this policy authenticates a bearer credential at all.
    ///
    /// The three bearer policies are the ones an empty RBAC policy makes useless (every
    /// authenticated caller is refused), and the ones `GET /api/v1/auth/config` publishes as a
    /// sign-in mode.
    #[must_use]
    pub const fn authenticates_bearer(self) -> bool {
        matches!(
            self,
            Self::TokenReview | Self::Oidc | Self::TokenReviewOrOidc
        )
    }

    /// Whether this policy needs a configured OIDC authenticator to work.
    ///
    /// The binary refuses to start (`--oidc-issuer`/`--oidc-client-id` are required) rather than
    /// silently serving a policy that can never authenticate anybody.
    #[must_use]
    pub const fn requires_oidc(self) -> bool {
        matches!(self, Self::Oidc | Self::TokenReviewOrOidc)
    }
}

/// The `--auth-policy` / `FERRISCD_AUTH_POLICY` parse failure.
///
/// Carries no value: a rejected policy string is not a secret, but echoing arbitrary operator input
/// back into a log line is a habit worth not having.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown authentication policy: expected `token-review` (default), `oidc`, \
     `token-review-or-oidc`, `pass-through` (development only) or `deny-all`"
)]
pub struct UnknownAuthPolicy;

impl std::str::FromStr for AuthPolicy {
    type Err = UnknownAuthPolicy;

    /// Parses the exact `--auth-policy` values.
    ///
    /// Surrounding whitespace is trimmed (an env var picked up from a `ConfigMap` routinely carries
    /// it) and nothing else is accepted. No synonyms: `--auth-policy none` must **not** be a
    /// plausible spelling of the policy that turns authentication off, or a typo becomes a security
    /// downgrade that reads like intent.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "token-review" => Ok(Self::TokenReview),
            "oidc" => Ok(Self::Oidc),
            "token-review-or-oidc" => Ok(Self::TokenReviewOrOidc),
            "pass-through" => Ok(Self::PassThrough),
            // `default-deny` was the pre-`T14.3` spelling of the lockdown; it still parses so an
            // existing manifest/flag keeps the safe meaning.
            "deny-all" | "default-deny" => Ok(Self::DenyAll),
            _ => Err(UnknownAuthPolicy),
        }
    }
}

/// Whether `addr` + `policy` serve the protected API to callers who never authenticate.
///
/// [`AuthPolicy::PassThrough`] cannot authenticate anybody, so it is only defensible on a loopback
/// bind: anywhere else, every `/api/v1/*` route — sync and rollback included — is writable by any
/// pod that can reach the address. The binary calls this and logs a warning, so the combination is
/// visible instead of implied by a flag.
#[must_use]
pub fn exposes_unauthenticated_api(addr: SocketAddr, policy: AuthPolicy) -> bool {
    policy == AuthPolicy::PassThrough && !addr.ip().is_loopback()
}

/// A resolved identity plus the lifetime its own credential allows it to be cached for.
///
/// `T14.3`'s `TokenReview` has no per-credential expiry the server can see, so it caches for
/// [`DEFAULT_IDENTITY_CACHE_TTL`]. `T19.1`'s OIDC JWTs carry `exp`: caching such a token for the full
/// 30 s window would serve an identity for up to 30 s **past** its expiry, so the authenticator
/// reports `exp - now` and [`IdentityCache::insert_with_ttl`] clamps the entry to the shorter of the
/// two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCredential {
    /// The identity the credential resolved to.
    pub identity: AuthenticatedIdentity,
    /// The cache lifetime the credential itself allows, when it has one.
    pub ttl: Option<Duration>,
}

impl AuthenticatedCredential {
    /// A credential with no expiry of its own (a `TokenReview` result).
    #[must_use]
    pub fn new(identity: AuthenticatedIdentity) -> Self {
        Self {
            identity,
            ttl: None,
        }
    }

    /// A credential that must not be cached for longer than `ttl`.
    #[must_use]
    pub fn expiring(identity: AuthenticatedIdentity, ttl: Duration) -> Self {
        Self {
            identity,
            ttl: Some(ttl),
        }
    }
}

/// Where a bearer token goes to be validated.
///
/// The production implementations are [`KubeTokenAuthenticator`](crate::kube::KubeTokenAuthenticator)
/// (one `TokenReview` per cache miss), the `T19.1` OIDC authenticator
/// ([`OidcTokenAuthenticator`](crate::oidc::OidcTokenAuthenticator)) and their composite
/// ([`CompositeTokenAuthenticator`](crate::oidc::CompositeTokenAuthenticator)); a test substitutes a
/// table of fake tokens, which is what makes the whole middleware — cache included — testable without
/// a cluster.
///
/// Implementations **must not** retain, log, or cache the token themselves: caching is
/// [`IdentityCache`]'s job, keyed by [`token_fingerprint`].
pub trait TokenAuthenticator: Send + Sync + 'static {
    /// Validates `token`.
    ///
    /// `Ok(None)` is the ordinary "this token is not valid" answer. `Err` is "the review could not be
    /// performed" (the API server is unreachable, the token is too long); the middleware fails closed
    /// for both, and only the log distinguishes them.
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>>;

    /// Validates `token`, reporting the lifetime its credential allows.
    ///
    /// The default wraps [`Self::authenticate`] with "no expiry of its own", so every existing
    /// implementation keeps its behaviour; an authenticator whose credential *does* carry an expiry
    /// (`T19.1`'s OIDC JWT) overrides this to report it.
    fn authenticate_credential<'a>(
        &'a self,
        token: &'a str,
    ) -> SeamFuture<'a, Option<AuthenticatedCredential>> {
        Box::pin(async move {
            Ok(self
                .authenticate(token)
                .await?
                .map(AuthenticatedCredential::new))
        })
    }
}

/// A [`TokenAuthenticator`] that validates nothing, so every token is refused.
///
/// This is what an [`AppState`] starts with: forgetting to wire the real authenticator therefore
/// fails **closed** (everything is `401`) instead of open.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredTokenAuthenticator;

impl TokenAuthenticator for UnconfiguredTokenAuthenticator {
    fn authenticate<'a>(
        &'a self,
        _token: &'a str,
    ) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
        Box::pin(async { Ok(None) })
    }
}

/// The SHA-256 fingerprint of a bearer token.
///
/// The **only** representation of a token that may be logged, cached, or compared. One-way by
/// construction: the cache cannot be turned back into credentials.
#[must_use]
pub fn token_fingerprint(token: &str) -> [u8; 32] {
    sha256::digest(token.as_bytes())
}

/// The first 12 hex characters of a [`token_fingerprint`], for a log line.
///
/// Prefixed so a reader cannot mistake it for the token itself. 48 bits is ample to correlate one
/// identity's requests in a log without being a lookup key.
#[must_use]
pub fn fingerprint_label(fingerprint: &[u8; 32]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut label = String::with_capacity(12);
    for byte in &fingerprint[..6] {
        label.push(char::from(HEX[usize::from(byte >> 4)]));
        label.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    label
}

/// The bounded, positive-only `TokenReview` cache.
///
/// See the module docs for why negatives are never cached. `Debug`, `Display` and every error path
/// render only the entry count: the map is keyed by a fingerprint and holds identities, so there is
/// nothing secret in it — but rendering thousands of identities into a log line is still wrong.
pub struct IdentityCache {
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<[u8; 32], CachedIdentity>>,
}

/// One cached identity and the lifetime it is trusted for.
///
/// The lifetime is **per entry**, not the cache's: `T19.1` clamps an OIDC identity to
/// `min(DEFAULT_IDENTITY_CACHE_TTL, jwt_exp - now)` so a token with 5 s left is cached for 5 s. The
/// elapsed time is measured from `stored_at` rather than against an absolute deadline, so no instant
/// arithmetic can overflow.
///
/// `tokio::time::Instant` rather than `std::time::Instant` so the TTL is testable on a paused clock
/// (no sleeping test) and cannot skew if the system clock is stepped.
#[derive(Debug, Clone)]
struct CachedIdentity {
    stored_at: tokio::time::Instant,
    ttl: Duration,
    identity: AuthenticatedIdentity,
}

impl CachedIdentity {
    /// Whether this entry is still inside its lifetime.
    fn is_live(&self, now: tokio::time::Instant) -> bool {
        now.duration_since(self.stored_at) < self.ttl
    }
}

impl std::fmt::Debug for IdentityCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityCache")
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .field("entries", &self.len())
            .finish()
    }
}

impl Default for IdentityCache {
    fn default() -> Self {
        Self::new(DEFAULT_IDENTITY_CACHE_TTL, DEFAULT_IDENTITY_CACHE_CAPACITY)
    }
}

impl IdentityCache {
    /// Builds a cache with an explicit TTL and capacity (tests use short values).
    ///
    /// A `ttl` of zero disables caching entirely (every lookup misses), which is what a test that
    /// wants to count `TokenReview` calls uses.
    #[must_use]
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The TTL this cache was built with.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// How many identities are currently cached (expired ones included until they are pruned).
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// The cached identity for `fingerprint`, if it is still inside its lifetime.
    ///
    /// An expired entry is removed on read, so a revoked identity is never resurrected by a later
    /// lookup.
    #[must_use]
    pub fn get(&self, fingerprint: &[u8; 32]) -> Option<AuthenticatedIdentity> {
        if self.ttl.is_zero() {
            return None;
        }
        let now = tokio::time::Instant::now();
        let mut entries = self.lock();
        match entries.get(fingerprint) {
            Some(cached) if cached.is_live(now) => Some(cached.identity.clone()),
            Some(_) => {
                entries.remove(fingerprint);
                None
            }
            None => None,
        }
    }

    /// Remembers `identity` for `fingerprint` until the cache TTL elapses.
    pub fn insert(&self, fingerprint: [u8; 32], identity: AuthenticatedIdentity) {
        self.insert_with_ttl(fingerprint, identity, self.ttl);
    }

    /// Remembers `identity` for `fingerprint`, for at most `ttl` and never longer than the cache's
    /// own TTL.
    ///
    /// `T19.1`: the middleware passes `exp - now` for an OIDC JWT, so an identity is never served
    /// past the expiry of the token that earned it. A zero (or already elapsed) TTL stores nothing —
    /// a credential with no remaining life is not worth a cache entry, and a negative authentication
    /// result is never cached at all (an attacker controls negativeness; it is also the answer they
    /// already have).
    pub fn insert_with_ttl(
        &self,
        fingerprint: [u8; 32],
        identity: AuthenticatedIdentity,
        ttl: Duration,
    ) {
        let ttl = ttl.min(self.ttl);
        if ttl.is_zero() {
            return;
        }
        let now = tokio::time::Instant::now();
        let mut entries = self.lock();
        if entries.len() >= self.capacity && !entries.contains_key(&fingerprint) {
            // Expired entries are free space; only then evict the least valuable live one (the
            // oldest), so a burst of new identities can never grow the map past `capacity`.
            entries.retain(|_, cached| cached.is_live(now));
            while entries.len() >= self.capacity {
                let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, cached)| cached.stored_at)
                    .map(|(key, _)| *key)
                else {
                    break;
                };
                entries.remove(&oldest);
            }
        }
        entries.insert(
            fingerprint,
            CachedIdentity {
                stored_at: now,
                ttl,
                identity,
            },
        );
    }

    /// Drops every cached identity (a test and an operator-reachable reset point).
    pub fn clear(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<[u8; 32], CachedIdentity>> {
        // A poisoned cache is still usable: the worst case is one extra `TokenReview`.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Why an `Authorization` header did not yield a token.
///
/// The variants exist for the log; the client only ever sees the one `401`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerError {
    /// No `Authorization` header at all.
    Missing,
    /// Present, but not `Bearer <token>` (another scheme, no credential, or a control character).
    Malformed,
    /// A token longer than [`MAX_BEARER_TOKEN_CHARS`].
    TooLong,
}

impl BearerError {
    /// A secret-free, **claim-free** explanation (never quotes the header).
    ///
    /// Finding `M1`: these strings are also the reason an audit record is written under
    /// ([`authenticate`] passes `as_str()` to `record_auth_denied`), and the audit sink runs every
    /// reason through `sanitize_audit_reason`, which reads the word following `bearer`, `basic` or
    /// `authorization` as an inline credential. The previous wording named the scheme, so an
    /// auditor read `no Authorization <redacted> was presented`, `the Authorization <redacted> is
    /// not ...` and `the bearer <redacted> is longer ...` — redactions of ordinary English words,
    /// which hid nothing and made the trail read as if it had hidden something. No scheme word
    /// appears below, so the sanitizer passes each reason through verbatim; `auth::tests` asserts
    /// exactly that (see `every_bearer_error_reason_survives_the_audit_sanitizer`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "no credential header was presented",
            Self::Malformed => "the credential header does not carry a parseable token",
            Self::TooLong => "the credential exceeds the accepted length",
        }
    }
}

/// A parsed `Authorization: Bearer <token>` credential.
///
/// A newtype with a redacting `Debug` and no `Display`: the token is readable only through
/// [`Self::expose`] (crate-internal) and is never cloned into a log, a response, or a cache.
#[derive(Clone)]
pub struct BearerToken(String);

impl BearerToken {
    /// Extracts the bearer token from a request's headers.
    ///
    /// # Errors
    ///
    /// [`BearerError`] for a missing, malformed (another scheme, an empty credential, a control
    /// character) or over-long credential.
    pub fn parse(headers: &HeaderMap) -> Result<Self, BearerError> {
        // RFC 7235 allows repeated `Authorization` headers; taking the first is the documented
        // behaviour, and a second one is not evidence of anything a proxy would honour.
        let Some(raw) = headers.get_all(AUTHORIZATION).iter().next() else {
            return Err(BearerError::Missing);
        };
        let raw = raw.to_str().map_err(|_| BearerError::Malformed)?;
        let (scheme, credential) = raw.split_once(' ').ok_or(BearerError::Malformed)?;
        // The scheme is case-insensitive (`Bearer`/`bearer`); the credential is not touched.
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(BearerError::Malformed);
        }
        let credential = credential.trim();
        if credential.is_empty() || credential.chars().any(char::is_control) {
            return Err(BearerError::Malformed);
        }
        if credential.chars().count() > MAX_BEARER_TOKEN_CHARS {
            return Err(BearerError::TooLong);
        }
        Ok(Self(credential.to_owned()))
    }

    /// The token itself, for the one call that has to hand it to Kubernetes.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// The one-way handle used for caching and logging.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        token_fingerprint(&self.0)
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// The `axum` middleware installed on the protected route group.
///
/// It runs **before** the handler and before any body is read, so an unauthenticated caller cannot
/// reach a decoder, a cluster read, a diff computation, or the RBAC policy.
pub async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|id| id.0.clone());
    let path = request.uri().path().to_owned();
    match state.auth {
        AuthPolicy::PassThrough => {
            request
                .extensions_mut()
                .insert(AuthenticatedIdentity::anonymous());
            next.run(request).await
        }
        // No token is parsed and no cluster call is made: lockdown means lockdown.
        AuthPolicy::DenyAll => {
            record_auth_denied(
                &state.audit,
                request_id.as_deref(),
                &path,
                None,
                "authentication is disabled on this server (deny-all)",
            );
            unauthorized("authentication is disabled on this server (deny-all)")
        }
        // `T19.1`: the three bearer policies share this arm. Which mechanism actually runs is decided
        // by the [`TokenAuthenticator`] the binary wired (a `TokenReview`, an OIDC verifier, or the
        // composite), so the middleware — and every handler behind it — is unchanged by the new
        // policy: it resolves an identity or it answers `401`.
        AuthPolicy::TokenReview | AuthPolicy::Oidc | AuthPolicy::TokenReviewOrOidc => {
            let token = match BearerToken::parse(request.headers()) {
                Ok(token) => token,
                Err(error) => {
                    tracing::debug!(
                        path = %path,
                        reason = error.as_str(),
                        "protected request refused: no usable bearer token"
                    );
                    record_auth_denied(
                        &state.audit,
                        request_id.as_deref(),
                        &path,
                        None,
                        error.as_str(),
                    );
                    return unauthorized("a valid bearer token is required");
                }
            };
            let fingerprint = token.fingerprint();
            let label = fingerprint_label(&fingerprint);
            if let Some(identity) = state.identities.get(&fingerprint) {
                tracing::debug!(
                    path = %path,
                    fingerprint = %label,
                    user = %identity.username.as_deref().unwrap_or_default(),
                    "bearer token accepted from the positive cache"
                );
                return allow(request, identity, Some(TokenFingerprint(label)), next).await;
            }
            match state.tokens.authenticate_credential(token.expose()).await {
                Ok(Some(credential)) => {
                    let identity = credential.identity;
                    // `T19.1`: an OIDC JWT reports `exp - now`, so the entry is clamped to the token's
                    // own remaining life and never outlives it.
                    state.identities.insert_with_ttl(
                        fingerprint,
                        identity.clone(),
                        credential.ttl.unwrap_or_else(|| state.identities.ttl()),
                    );
                    tracing::debug!(
                        path = %path,
                        fingerprint = %label,
                        user = %identity.username.as_deref().unwrap_or_default(),
                        groups = identity.groups.len(),
                        "the authenticator accepted the bearer token"
                    );
                    allow(request, identity, Some(TokenFingerprint(label)), next).await
                }
                Ok(None) => {
                    tracing::info!(
                        path = %path,
                        fingerprint = %label,
                        "the authenticator rejected the bearer token"
                    );
                    record_auth_denied(
                        &state.audit,
                        request_id.as_deref(),
                        &path,
                        Some(&label),
                        // Finding `N3`: claim-free wording. `"the bearer token ..."` made the audit
                        // sanitizer redact the *word* "token" (it reads the word after `bearer` as
                        // an inline credential), so an auditor read `the bearer <redacted> was
                        // rejected` — a redaction that hid nothing and hid that it hid nothing.
                        REJECTED_CREDENTIAL_REASON,
                    );
                    unauthorized("a valid bearer token is required")
                }
                // Fail closed. The reason is logged (bounded, fingerprint-keyed) because an operator
                // needs it, and the client is told nothing it could use to probe the cluster or the
                // IdP.
                //
                // `T19.1` finding `M2`: an IdP that cannot answer is **not** an attacker's token.
                // The OIDC authenticator reports that as `ApiError::Backend`, so it lands here — with
                // a `warn!` naming the backend, the `authentication backend error` audit reason and
                // the "try again" message — instead of in the `Ok(None)` arm, where a reviewer of the
                // audit trail could not tell an outage from a forged token. The client's `401` shape
                // is unchanged (the `T14.3` contract: a `401` never explains itself), and the
                // backend's own message is never published.
                Err(error) => {
                    tracing::warn!(
                        path = %path,
                        fingerprint = %label,
                        error = %error,
                        "the token could not be validated; refusing the request (fail closed)"
                    );
                    record_auth_denied(
                        &state.audit,
                        request_id.as_deref(),
                        &path,
                        Some(&label),
                        "authentication backend error (fail closed)",
                    );
                    unauthorized("the bearer token could not be validated; try again")
                }
            }
        }
    }
}

/// Inserts the resolved identity (and optional 12-hex token fingerprint) and runs the rest of the
/// chain.
async fn allow(
    mut request: Request,
    identity: AuthenticatedIdentity,
    fingerprint: Option<TokenFingerprint>,
    next: Next,
) -> Response {
    request.extensions_mut().insert(identity);
    if let Some(fingerprint) = fingerprint {
        request.extensions_mut().insert(fingerprint);
    }
    next.run(request).await
}

/// The single `401` shape, with the standard challenge so a client knows to send a token.
fn unauthorized(message: &str) -> Response {
    let mut response = ApiError::unauthorized(message).into_response();
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Body;
    use axum::http::StatusCode;
    use tower::ServiceExt as _;

    use super::*;
    use crate::audit::{AuditLogger, RecordingAuditSink};

    #[test]
    fn the_default_policy_requires_a_token_review() {
        assert_eq!(AuthPolicy::default(), AuthPolicy::TokenReview);
        assert_eq!(AuthPolicy::TokenReview.as_str(), "token-review");
        assert_eq!(AuthPolicy::PassThrough.as_str(), "pass-through");
        assert_eq!(AuthPolicy::DenyAll.as_str(), "deny-all");
    }

    #[test]
    fn an_anonymous_identity_carries_no_claims() {
        let identity = AuthenticatedIdentity::anonymous();
        assert_eq!(identity.username, None);
        assert!(identity.groups.is_empty());
        assert!(!identity.is_authenticated());
        assert!(!identity.in_group("system:authenticated"));
    }

    #[test]
    fn a_reviewed_identity_carries_its_groups() {
        let identity = AuthenticatedIdentity::new(
            "system:serviceaccount:payments:deployer",
            vec![
                "payments-team".to_owned(),
                "system:authenticated".to_owned(),
            ],
        );
        assert!(identity.is_authenticated());
        assert!(identity.in_group("payments-team"));
        assert!(!identity.in_group("platform-admins"));
    }

    /// **Finding `P14-H1` + `T14.3`:** `--auth-policy` cannot be *typed* ambiguously — every
    /// documented spelling parses, a typo is refused instead of falling back to either the permissive
    /// policy or the lockdown, and whitespace from an env var is tolerated.
    #[test]
    fn the_auth_policy_flag_values_parse_exactly() {
        assert_eq!(
            "token-review".parse::<AuthPolicy>(),
            Ok(AuthPolicy::TokenReview)
        );
        assert_eq!("deny-all".parse::<AuthPolicy>(), Ok(AuthPolicy::DenyAll));
        assert_eq!(
            "  deny-all\n".parse::<AuthPolicy>(),
            Ok(AuthPolicy::DenyAll)
        );
        assert_eq!(
            "pass-through".parse::<AuthPolicy>(),
            Ok(AuthPolicy::PassThrough)
        );
        // `T19.1`: the two OIDC policies are spelled exactly as the design document does.
        assert_eq!("oidc".parse::<AuthPolicy>(), Ok(AuthPolicy::Oidc));
        assert_eq!(
            "token-review-or-oidc".parse::<AuthPolicy>(),
            Ok(AuthPolicy::TokenReviewOrOidc)
        );
        for rejected in [
            "",
            "pass_through",
            "DenyAll",
            "open",
            "pass-through,deny-all",
            // No synonyms for the permissive policy: a typo must not turn authentication off.
            "none",
            "passthrough",
            "review",
            "off",
            // Nor for OIDC: a typo must never silently select the cluster-only default *or* a mode the
            // operator did not ask for.
            "sso",
            "OIDC",
            "token-review-or-sso",
            "token_review_or_oidc",
        ] {
            assert_eq!(
                rejected.parse::<AuthPolicy>(),
                Err(UnknownAuthPolicy),
                "{rejected:?} must not select a policy"
            );
        }
        // Every accepted spelling round-trips through `as_str`, so help text and logs agree.
        for policy in [
            AuthPolicy::TokenReview,
            AuthPolicy::Oidc,
            AuthPolicy::TokenReviewOrOidc,
            AuthPolicy::PassThrough,
            AuthPolicy::DenyAll,
        ] {
            assert_eq!(policy.as_str().parse::<AuthPolicy>(), Ok(policy));
        }
        // The predicates the binary and the startup warnings key on.
        for policy in [
            AuthPolicy::TokenReview,
            AuthPolicy::Oidc,
            AuthPolicy::TokenReviewOrOidc,
        ] {
            assert!(policy.authenticates_bearer(), "{policy:?}");
        }
        for policy in [AuthPolicy::PassThrough, AuthPolicy::DenyAll] {
            assert!(!policy.authenticates_bearer(), "{policy:?}");
            assert!(!policy.requires_oidc(), "{policy:?}");
        }
        assert!(!AuthPolicy::TokenReview.requires_oidc());
        assert!(AuthPolicy::Oidc.requires_oidc());
        assert!(AuthPolicy::TokenReviewOrOidc.requires_oidc());
    }

    /// **Trap guard (finding `P14-H1`):** the pass-through policy is only "safe" on loopback, and
    /// that is a decision the binary can ask about instead of an assumption. Token-review and
    /// deny-all can never expose an unauthenticated API, whatever the bind.
    #[test]
    fn pass_through_is_only_unauthenticated_off_loopback() {
        for addr in ["0.0.0.0:8080", "[::]:8080", "10.0.0.7:8080"] {
            let addr: SocketAddr = addr.parse().expect("a socket address");
            assert!(
                exposes_unauthenticated_api(addr, AuthPolicy::PassThrough),
                "{addr} with pass-through serves every /api/v1/* route to strangers"
            );
            assert!(
                !exposes_unauthenticated_api(addr, AuthPolicy::TokenReview),
                "{addr}: token-review authenticates every caller"
            );
            assert!(
                !exposes_unauthenticated_api(addr, AuthPolicy::DenyAll),
                "{addr}: deny-all refuses everybody"
            );
        }
        for addr in ["127.0.0.1:8080", "[::1]:8080"] {
            let addr: SocketAddr = addr.parse().expect("a socket address");
            assert!(
                !exposes_unauthenticated_api(addr, AuthPolicy::PassThrough),
                "{addr} is loopback: only the pod itself can reach it"
            );
        }
    }

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(value).expect("a header value"),
        );
        headers
    }

    #[test]
    fn a_bearer_header_is_parsed_in_any_case() {
        assert_eq!(
            BearerToken::parse(&headers("Bearer abc.def.ghi"))
                .expect("a token")
                .expose(),
            "abc.def.ghi"
        );
        assert_eq!(
            BearerToken::parse(&headers("bearer   abc.def.ghi  "))
                .expect("the scheme is case-insensitive")
                .expose(),
            "abc.def.ghi"
        );
        // Only the first space separates the scheme from the credential: a JWT never contains one,
        // but a base64 credential with padding must not be truncated.
        assert_eq!(
            BearerToken::parse(&headers("Bearer a== b"))
                .expect("a token")
                .expose(),
            "a== b"
        );
    }

    #[test]
    fn a_header_that_is_not_a_bearer_token_is_refused() {
        assert_eq!(
            BearerToken::parse(&HeaderMap::new()).err(),
            Some(BearerError::Missing)
        );
        for malformed in [
            "Bearer",
            "Bearer ",
            "Basic dXNlcjpwYXNz",
            "Token abc",
            "",
            "Bearer\tx",
        ] {
            assert_eq!(
                BearerToken::parse(&headers(malformed)).err(),
                Some(BearerError::Malformed),
                "{malformed:?}"
            );
        }
        // A token is attacker-controlled: an unbounded credential is refused before it is hashed,
        // cached, or forwarded in a TokenReview request body.
        let long = format!("Bearer {}", "a".repeat(MAX_BEARER_TOKEN_CHARS + 1));
        assert_eq!(
            BearerToken::parse(&headers(&long)).err(),
            Some(BearerError::TooLong)
        );
        let exact = format!("Bearer {}", "a".repeat(MAX_BEARER_TOKEN_CHARS));
        assert!(BearerToken::parse(&headers(&exact)).is_ok());
    }

    /// **`T19.1` findings `M1`/`N3`:** every [`BearerError`] reason is *claim-free*, so the audit
    /// sink stores it verbatim.
    ///
    /// The reasons reach an audit record through
    /// [`authenticate`]'s `record_auth_denied`, and the sink runs each one through
    /// `sanitize_audit_reason`, which reads the word after `bearer`/`basic`/`authorization` as an
    /// inline credential. Any reason naming a scheme therefore reaches an auditor as
    /// `the bearer <redacted> ...`. The table asserts the literal each error is recorded under and
    /// that the sanitizer leaves it alone, so a reword **or** a sanitizer change fails here.
    #[test]
    fn every_bearer_error_reason_survives_the_audit_sanitizer() {
        for (error, expected) in [
            (BearerError::Missing, "no credential header was presented"),
            (
                BearerError::Malformed,
                "the credential header does not carry a parseable token",
            ),
            (
                BearerError::TooLong,
                "the credential exceeds the accepted length",
            ),
        ] {
            assert_eq!(error.as_str(), expected, "{error:?} wording");
            let recorded = crate::audit::sanitize_audit_reason(error.as_str());
            assert_eq!(
                recorded, expected,
                "{error:?} must reach the audit sink verbatim: {recorded}"
            );
            assert!(
                !recorded.contains("<redacted>"),
                "{error:?}: an ordinary English word must never be redacted out of the reason: \
                 {recorded}"
            );
        }
    }

    /// A token must never be printable: `Debug` is what a log line, a panic message, or a `dbg!`
    /// renders, and the API process holds a live credential for the length of one request.
    #[test]
    fn a_bearer_token_never_renders_itself() {
        let token = BearerToken::parse(&headers("Bearer super-secret-token")).expect("a token");
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");

        let cache = IdentityCache::default();
        cache.insert(
            token.fingerprint(),
            AuthenticatedIdentity::new("system:serviceaccount:ns:sa", Vec::new()),
        );
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
    }

    #[test]
    fn the_fingerprint_is_one_way_and_stable() {
        let token = BearerToken::parse(&headers("Bearer abc")).expect("a token");
        assert_eq!(token.fingerprint(), token_fingerprint("abc"));
        assert_ne!(token.fingerprint(), token_fingerprint("abd"));
        // The log label is short, hex, and cannot be turned back into the digest whole.
        let label = fingerprint_label(&token.fingerprint());
        assert_eq!(label.len(), 12);
        assert!(label.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(label, fingerprint_label(&token.fingerprint()));
    }

    #[tokio::test(start_paused = true)]
    async fn the_cache_serves_until_the_ttl_elapses_then_forgets() {
        let cache = IdentityCache::new(Duration::from_secs(30), 8);
        let fingerprint = token_fingerprint("token-a");
        let identity = AuthenticatedIdentity::new("system:serviceaccount:ns:a", Vec::new());
        assert!(cache.get(&fingerprint).is_none(), "an empty cache misses");

        cache.insert(fingerprint, identity.clone());
        assert_eq!(cache.get(&fingerprint), Some(identity.clone()));
        assert_eq!(cache.len(), 1);

        // A different token is a different key: nothing is served across credentials.
        assert!(cache.get(&token_fingerprint("token-b")).is_none());

        // Just inside the window, then just outside it — no sleeping, the clock is paused.
        tokio::time::advance(Duration::from_secs(29)).await;
        assert_eq!(cache.get(&fingerprint), Some(identity));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(
            cache.get(&fingerprint).is_none(),
            "a credential that sat in the cache for 31s must be re-reviewed"
        );
        assert_eq!(cache.len(), 0, "the expired entry is dropped on read");
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_ttl_disables_the_cache_entirely() {
        let cache = IdentityCache::new(Duration::ZERO, 8);
        let fingerprint = token_fingerprint("token-a");
        cache.insert(
            fingerprint,
            AuthenticatedIdentity::new("system:serviceaccount:ns:a", Vec::new()),
        );
        assert!(cache.get(&fingerprint).is_none());
        assert!(cache.is_empty());
    }

    /// The cache is bounded: a flood of distinct tokens cannot grow it past its capacity, and it
    /// evicts the oldest entry rather than a freshly reviewed (i.e. actively used) one.
    #[tokio::test(start_paused = true)]
    async fn the_cache_is_bounded_and_evicts_the_oldest_entry() {
        let cache = IdentityCache::new(Duration::from_secs(30), 4);
        for index in 0..4 {
            cache.insert(
                token_fingerprint(&format!("token-{index}")),
                AuthenticatedIdentity::new(
                    format!("system:serviceaccount:ns:user-{index}"),
                    Vec::new(),
                ),
            );
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert_eq!(cache.len(), 4);
        assert!(cache.get(&token_fingerprint("token-0")).is_some());

        cache.insert(
            token_fingerprint("token-4"),
            AuthenticatedIdentity::new("system:serviceaccount:ns:user-4", Vec::new()),
        );
        assert_eq!(
            cache.len(),
            4,
            "a bounded cache never grows past its capacity"
        );
        assert!(
            cache.get(&token_fingerprint("token-0")).is_none(),
            "the oldest identity is the one evicted"
        );
        for index in 1..=4 {
            assert!(
                cache
                    .get(&token_fingerprint(&format!("token-{index}")))
                    .is_some(),
                "token-{index} must still be served"
            );
        }
    }

    /// Expired entries are reclaimed *before* a live one, so a quiet period makes room without
    /// throwing away an identity a caller is actively using.
    #[tokio::test(start_paused = true)]
    async fn expired_entries_are_evicted_before_live_ones() {
        let cache = IdentityCache::new(Duration::from_secs(10), 2);
        cache.insert(
            token_fingerprint("old"),
            AuthenticatedIdentity::new("system:serviceaccount:ns:old", Vec::new()),
        );
        tokio::time::advance(Duration::from_secs(20)).await;
        cache.insert(
            token_fingerprint("live"),
            AuthenticatedIdentity::new("system:serviceaccount:ns:live", Vec::new()),
        );
        cache.insert(
            token_fingerprint("newer"),
            AuthenticatedIdentity::new("system:serviceaccount:ns:newer", Vec::new()),
        );
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&token_fingerprint("old")).is_none());
        assert!(cache.get(&token_fingerprint("live")).is_some());
        assert!(cache.get(&token_fingerprint("newer")).is_some());
    }

    #[test]
    fn clearing_the_cache_forgets_every_identity() {
        let cache = IdentityCache::default();
        cache.insert(
            token_fingerprint("token"),
            AuthenticatedIdentity::new("system:serviceaccount:ns:a", Vec::new()),
        );
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    /// **`T19.1` verification bullet 4:** an entry is evicted at the credential's own expiry, even when
    /// that is far shorter than the cache's 30 s window — a JWT with 5 s left is never served for 30 s.
    #[tokio::test(start_paused = true)]
    async fn a_cached_identity_never_outlives_the_credential_that_earned_it() {
        let cache = IdentityCache::new(DEFAULT_IDENTITY_CACHE_TTL, 8);
        let short = token_fingerprint("oidc-with-5s-left");
        let full = token_fingerprint("token-review");

        cache.insert_with_ttl(
            short,
            AuthenticatedIdentity::new("oidc:alice", vec!["oidc:payments-team".to_owned()]),
            Duration::from_secs(5),
        );
        cache.insert(
            full,
            AuthenticatedIdentity::new("system:serviceaccount:ns:ci", Vec::new()),
        );

        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(
            cache.get(&short).is_some(),
            "the JWT is still valid: it must be served from the cache"
        );
        assert!(cache.get(&full).is_some());

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            cache.get(&short).is_none(),
            "the JWT expired: serving it from cache would authenticate past `exp`"
        );
        assert!(
            cache.get(&full).is_some(),
            "the per-entry clamp must not shorten the 30 s default for a TokenReview identity"
        );
    }

    /// A credential with no remaining life is not worth an entry, and the cache can never be talked
    /// into caching longer than its own TTL.
    #[tokio::test(start_paused = true)]
    async fn a_zero_or_oversized_credential_ttl_is_clamped() {
        let cache = IdentityCache::new(Duration::from_secs(30), 8);
        let expired = token_fingerprint("expired");
        cache.insert_with_ttl(
            expired,
            AuthenticatedIdentity::new("oidc:bob", Vec::new()),
            Duration::ZERO,
        );
        assert!(cache.is_empty(), "nothing is cached for a dead credential");

        let long_lived = token_fingerprint("long-lived");
        cache.insert_with_ttl(
            long_lived,
            AuthenticatedIdentity::new("oidc:carol", Vec::new()),
            Duration::from_secs(86_400),
        );
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(cache.get(&long_lived).is_some());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(
            cache.get(&long_lived).is_none(),
            "a 24-hour `exp` is still clamped to the cache's 30 s window"
        );
    }

    // -----------------------------------------------------------------------
    // The middleware, end to end (findings `H2`, `H3`, `M2`)
    // -----------------------------------------------------------------------

    /// The audit reason a refused credential is recorded under, **verbatim**.
    ///
    /// Finding `N3`: the reason is claim-free, so `sanitize_audit_reason` passes it through
    /// unchanged and the assertion can be on the literal an auditor reads. That is asserted once,
    /// in [`the_rejected_credential_audit_reason_is_claim_free_and_not_redacted`]; the two
    /// middleware tests below use the constant so a reword fails in one place, not three.
    const REJECTED_REASON: &str = REJECTED_CREDENTIAL_REASON;

    /// The audit reason a backend failure is recorded under.
    const BACKEND_FAILURE_REASON: &str = "authentication backend error (fail closed)";

    /// A [`TokenAuthenticator`] that answers from a fixed table and **counts every call**, so the
    /// assertions below measure the middleware's cache rather than the authenticator.
    #[derive(Default)]
    struct CountingAuthenticator {
        calls: AtomicUsize,
        credential: Option<AuthenticatedCredential>,
        failure: Option<ApiError>,
    }

    impl CountingAuthenticator {
        /// An authenticator that refuses every token (`Ok(None)`).
        fn refusing() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// An authenticator that accepts every token with `ttl` as the credential's own lifetime.
        fn accepting(identity: AuthenticatedIdentity, ttl: Option<Duration>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                credential: Some(match ttl {
                    Some(ttl) => AuthenticatedCredential::expiring(identity, ttl),
                    None => AuthenticatedCredential::new(identity),
                }),
                failure: None,
            })
        }

        /// An authenticator whose backend cannot answer at all (`Err`).
        fn failing(failure: ApiError) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                credential: None,
                failure: Some(failure),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl TokenAuthenticator for CountingAuthenticator {
        fn authenticate<'a>(
            &'a self,
            _token: &'a str,
        ) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
            Box::pin(async { Ok(None) })
        }

        fn authenticate_credential<'a>(
            &'a self,
            _token: &'a str,
        ) -> SeamFuture<'a, Option<AuthenticatedCredential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let failure = self.failure.clone();
            let credential = self.credential.clone();
            Box::pin(async move {
                match failure {
                    Some(failure) => Err(failure),
                    None => Ok(credential),
                }
            })
        }
    }

    /// A protected-route state wired to `tokens`, with an audit recorder so the *reason* a request
    /// was refused is assertable (the `T19.1` `M2` distinction lives there, not in the `401`).
    fn bearer_state(tokens: &Arc<CountingAuthenticator>) -> (AppState, Arc<RecordingAuditSink>) {
        let recorder = Arc::new(RecordingAuditSink::new());
        let sink: Arc<dyn crate::audit::AuditSink> = Arc::clone(&recorder) as _;
        let audit = AuditLogger::default().with_additional_sink(sink);
        let state = crate::tests_support::state(Arc::new(crate::state::ServingReadiness))
            .with_auth(AuthPolicy::TokenReview)
            .with_token_authenticator(Arc::clone(tokens) as Arc<dyn TokenAuthenticator>)
            .with_audit(audit);
        (state, recorder)
    }

    /// Drives one protected `GET` through the **real** router and returns its status and audit
    /// reasons.
    async fn get_protected(
        state: AppState,
        recorder: &RecordingAuditSink,
        token: &str,
    ) -> (StatusCode, Vec<String>) {
        recorder.clear();
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/applications")
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).expect("a header value"),
            )
            .body(Body::empty())
            .expect("a request");
        let response = crate::api::router(state)
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        // The body is drained so a failure cannot be masked by an unread stream.
        let _ = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        let reasons = recorder
            .events()
            .into_iter()
            .filter_map(|event| event.reason)
            .collect();
        (status, reasons)
    }

    /// **`T19.1` finding `H2` (the `T19.1` trap guard: "never cache negative auth failures").**
    ///
    /// Two requests carrying the *same* bogus token must both be refused **and** both reach the
    /// authenticator: a negative result is never inserted into [`IdentityCache`], so an attacker
    /// cannot (a) fill the bounded cache with the tokens they control and evict legitimate
    /// identities, or (b) learn from a later response that a token is "already known bad". The
    /// assertion is on the cache, not just on the status: caching `Ok(None)` would still answer
    /// `401` in both cases, and only `calls == 2` catches it.
    #[tokio::test]
    async fn a_rejected_token_is_never_cached_and_is_revalidated_every_time() {
        let tokens = CountingAuthenticator::refusing();
        let (state, recorder) = bearer_state(&tokens);

        for attempt in 0..2 {
            let (status, reasons) = get_protected(state.clone(), &recorder, "bogus-token").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
            assert!(
                state.identities.is_empty(),
                "a negative authentication result must never be cached (attempt {attempt})"
            );
            assert_eq!(
                reasons,
                vec![REJECTED_REASON.to_owned()],
                "the refusal is audited as a rejected credential (attempt {attempt})"
            );
        }

        assert_eq!(
            tokens.calls(),
            2,
            "the authenticator must be consulted on every request, not served from a negative cache"
        );
        assert!(
            state.identities.is_empty(),
            "and the cache is still empty at the end"
        );
    }

    /// **`T19.1` finding `H3`.** The middleware must cache for the credential's **own** lifetime
    /// (`credential.ttl`, which is `exp - now` for an OIDC JWT), not for
    /// [`DEFAULT_IDENTITY_CACHE_TTL`]: a token with 1 s left is cached for 1 s, and the request two
    /// seconds later is verified again instead of being served an identity whose token has expired.
    ///
    /// Using the cache's 30 s default here would keep `calls` at 1 after the advance, so the test
    /// fails exactly on the bug it exists for.
    #[tokio::test(start_paused = true)]
    async fn the_middleware_caches_for_the_credentials_ttl_not_the_cache_default() {
        let tokens = CountingAuthenticator::accepting(
            AuthenticatedIdentity::new("oidc:alice", vec!["oidc:payments-team".to_owned()]),
            Some(Duration::from_secs(1)),
        );
        let (state, recorder) = bearer_state(&tokens);

        let (status, _) = get_protected(state.clone(), &recorder, "short-lived-jwt").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            tokens.calls(),
            1,
            "the first request resolves the credential"
        );
        assert_eq!(
            state.identities.len(),
            1,
            "a credential with 1 s left is still worth exactly one entry"
        );

        // Well inside the credential's own lifetime: served from the cache, no second review.
        let (status, _) = get_protected(state.clone(), &recorder, "short-lived-jwt").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            tokens.calls(),
            1,
            "inside the credential's ttl the cache serves the identity"
        );

        // Past it — but still far inside the cache's 30 s default window.
        tokio::time::advance(Duration::from_secs(2)).await;
        let (status, _) = get_protected(state.clone(), &recorder, "short-lived-jwt").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            tokens.calls(),
            2,
            "past the credential's ttl the middleware must ask again, not serve a 30 s entry"
        );
    }

    /// A credential that reports no expiry of its own (a `TokenReview`) keeps the cache default, so
    /// the `H3` clamp is a per-credential narrowing and not a second, accidental TTL.
    #[tokio::test(start_paused = true)]
    async fn a_credential_without_its_own_ttl_keeps_the_cache_default() {
        let tokens = CountingAuthenticator::accepting(
            AuthenticatedIdentity::new("system:serviceaccount:ns:ci", Vec::new()),
            None,
        );
        let (state, recorder) = bearer_state(&tokens);

        let (status, _) = get_protected(state.clone(), &recorder, "sa-token").await;
        assert_eq!(status, StatusCode::OK);
        tokio::time::advance(Duration::from_secs(20)).await;
        let (status, _) = get_protected(state.clone(), &recorder, "sa-token").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tokens.calls(), 1, "the 30 s default still applies");

        tokio::time::advance(Duration::from_secs(11)).await;
        let (status, _) = get_protected(state.clone(), &recorder, "sa-token").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tokens.calls(), 2, "and it expires on its own schedule");
    }

    /// **`T19.1` finding `M2`.** An IdP outage must be distinguishable from an attacker's token.
    ///
    /// Both answer `401` to the client — a `401` never explains itself (`T14.3`) — but the audit
    /// trail and the log must not call an outage "the presented credential was rejected": the outage
    /// lands in the backend-error arm (`authentication backend error`, fingerprint-only) while a
    /// forged token lands in the rejected-credential arm. The raw backend message is never recorded.
    #[tokio::test]
    async fn a_key_source_outage_is_audited_as_a_backend_failure_not_a_rejected_token() {
        let attacker = CountingAuthenticator::refusing();
        let (state, recorder) = bearer_state(&attacker);
        let (status, reasons) = get_protected(state, &recorder, "forged.jwt.value").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            reasons,
            vec![REJECTED_REASON.to_owned()],
            "an attacker's token is a rejected credential"
        );

        let outage = CountingAuthenticator::failing(ApiError::backend(
            &"the OIDC key set could not be refreshed: connection refused",
        ));
        let (state, recorder) = bearer_state(&outage);
        let (status, reasons) = get_protected(state, &recorder, "valid.jwt.value").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "fail closed, and the 401 shape is unchanged"
        );
        assert_eq!(
            reasons,
            vec![BACKEND_FAILURE_REASON.to_owned()],
            "an IdP outage is a backend failure, never a verdict about the caller's token"
        );
        assert!(
            !reasons
                .iter()
                .any(|reason| reason.contains("connection refused")),
            "the backend's own message is logged, never audited: {reasons:?}"
        );
    }

    /// **`T19.1` finding `N3`:** the audit reason a refused credential is recorded under is
    /// claim-free, so an auditor reads a sentence rather than a redaction.
    ///
    /// The literal is asserted here (never derived from `sanitize_audit_reason`, which would agree
    /// with itself): the previous wording reached the audit sink as
    /// `the bearer <redacted> was rejected`, because the sanitizer reads the word after `bearer` as
    /// an inline credential. A regression in the wording **or** in the sanitizer fails this test.
    #[test]
    fn the_rejected_credential_audit_reason_is_claim_free_and_not_redacted() {
        assert_eq!(
            REJECTED_CREDENTIAL_REASON,
            "the presented credential was rejected"
        );

        let recorded = crate::audit::sanitize_audit_reason(REJECTED_CREDENTIAL_REASON);
        assert_eq!(
            recorded, "the presented credential was rejected",
            "the audit sink must store the reason verbatim, with nothing redacted"
        );
        assert!(
            !recorded.contains("<redacted>"),
            "a non-secret word must never be redacted out of the reason: {recorded}"
        );
        assert!(
            !recorded.to_ascii_lowercase().contains("bearer"),
            "the reason names no credential and no scheme: {recorded}"
        );
    }
}

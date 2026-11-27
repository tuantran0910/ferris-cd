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
    /// Development escape hatch: no authentication, anonymous identity.
    ///
    /// Only defensible on a loopback bind ([`exposes_unauthenticated_api`]); every `/api/v1/*` route,
    /// sync and rollback included, is then writable by anyone who can reach the address.
    PassThrough,
    /// Lockdown: refuse every protected request without parsing a token or calling the API server.
    DenyAll,
}

impl AuthPolicy {
    /// A stable label for logs and `--auth-policy`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenReview => "token-review",
            Self::PassThrough => "pass-through",
            Self::DenyAll => "deny-all",
        }
    }
}

/// The `--auth-policy` / `FERRISCD_AUTH_POLICY` parse failure.
///
/// Carries no value: a rejected policy string is not a secret, but echoing arbitrary operator input
/// back into a log line is a habit worth not having.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown authentication policy: expected `token-review` (default), `pass-through` (development \
     only) or `deny-all`"
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

/// Where a bearer token goes to be validated.
///
/// The production implementation is
/// [`KubeTokenAuthenticator`](crate::kube::KubeTokenAuthenticator) (one `TokenReview` per cache
/// miss); a test substitutes a table of fake tokens, which is what makes the whole middleware —
/// cache included — testable without a cluster.
///
/// Implementations **must not** retain, log, or cache the token themselves: caching is
/// [`IdentityCache`]'s job, keyed by [`token_fingerprint`].
pub trait TokenAuthenticator: Send + Sync + 'static {
    /// Validates `token`.
    ///
    /// `Ok(None)` is the ordinary "Kubernetes does not know this token" answer. `Err` is "the review
    /// could not be performed" (the API server is unreachable, the token is too long); the
    /// middleware fails closed for both, and only the log distinguishes them.
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>>;
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

/// One cached identity and the instant it stops being trusted.
///
/// `tokio::time::Instant` rather than `std::time::Instant` so the TTL is testable on a paused clock
/// (no sleeping test) and cannot skew if the system clock is stepped.
#[derive(Debug, Clone)]
struct CachedIdentity {
    stored_at: tokio::time::Instant,
    identity: AuthenticatedIdentity,
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

    /// The cached identity for `fingerprint`, if it is still inside the TTL.
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
            Some(cached) if now.duration_since(cached.stored_at) < self.ttl => {
                Some(cached.identity.clone())
            }
            Some(_) => {
                entries.remove(fingerprint);
                None
            }
            None => None,
        }
    }

    /// Remembers `identity` for `fingerprint` until the TTL elapses.
    pub fn insert(&self, fingerprint: [u8; 32], identity: AuthenticatedIdentity) {
        if self.ttl.is_zero() {
            return;
        }
        let now = tokio::time::Instant::now();
        let mut entries = self.lock();
        if entries.len() >= self.capacity && !entries.contains_key(&fingerprint) {
            // Expired entries are free space; only then evict the least valuable live one (the
            // oldest), so a burst of new identities can never grow the map past `capacity`.
            entries.retain(|_, cached| now.duration_since(cached.stored_at) < self.ttl);
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
    /// A secret-free explanation (never quotes the header).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "no Authorization header was presented",
            Self::Malformed => "the Authorization header is not `Bearer <token>`",
            Self::TooLong => "the bearer token is longer than the API accepts",
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
        AuthPolicy::TokenReview => {
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
                    return unauthorized("a valid Kubernetes bearer token is required");
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
            match state.tokens.authenticate(token.expose()).await {
                Ok(Some(identity)) => {
                    state.identities.insert(fingerprint, identity.clone());
                    tracing::debug!(
                        path = %path,
                        fingerprint = %label,
                        user = %identity.username.as_deref().unwrap_or_default(),
                        groups = identity.groups.len(),
                        "TokenReview accepted the bearer token"
                    );
                    allow(request, identity, Some(TokenFingerprint(label)), next).await
                }
                Ok(None) => {
                    tracing::info!(
                        path = %path,
                        fingerprint = %label,
                        "TokenReview rejected the bearer token"
                    );
                    record_auth_denied(
                        &state.audit,
                        request_id.as_deref(),
                        &path,
                        Some(&label),
                        "TokenReview rejected bearer token",
                    );
                    unauthorized("a valid Kubernetes bearer token is required")
                }
                // Fail closed. The reason is logged (bounded, fingerprint-keyed) because an operator
                // needs it, and the client is told nothing it could use to probe the cluster.
                Err(error) => {
                    tracing::warn!(
                        path = %path,
                        fingerprint = %label,
                        error = %error,
                        "the token could not be reviewed; refusing the request (fail closed)"
                    );
                    record_auth_denied(
                        &state.audit,
                        request_id.as_deref(),
                        &path,
                        Some(&label),
                        "TokenReview backend error (fail closed)",
                    );
                    unauthorized("the bearer token could not be reviewed; try again")
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
    use super::*;

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
            AuthPolicy::PassThrough,
            AuthPolicy::DenyAll,
        ] {
            assert_eq!(policy.as_str().parse::<AuthPolicy>(), Ok(policy));
        }
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
}

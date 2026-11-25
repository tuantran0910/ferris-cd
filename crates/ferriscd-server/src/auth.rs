//! The authentication seam (`T14.3`).
//!
//! Phase 14 part 1 ships the **split**, not the mechanism: the router keeps three disjoint route
//! groups so `T14.3` can add Kubernetes `TokenReview` in exactly one place, and no bearer token is
//! read, parsed, cached, or logged yet:
//!
//! | Group | Routes | Authentication today |
//! |---|---|---|
//! | Public | `/healthz`, `/readyz` | none by design (probes carry no credential) |
//! | Webhooks | `/api/v1/webhooks/{github,gitlab}` | the webhook secret itself (`T14.2`) |
//! | Protected | every other `/api/v1/*` | [`AuthPolicy::PassThrough`] |
//!
//! [`AuthPolicy`] is the seam. [`AuthPolicy::PassThrough`] injects an anonymous identity and lets
//! the request through (the pre-`T14.3` behaviour); [`AuthPolicy::DenyAll`] answers `401` for every
//! protected route. `T14.3` replaces the pass-through arm with a `TokenReview` call and flips the
//! default to default-deny — the tests here already pin that split, so the flip cannot accidentally
//! expose an endpoint or lock `healthz`/webhooks behind a bearer token.
//!
//! `ferriscd server --auth-policy {pass-through|deny-all}` (or `FERRISCD_AUTH_POLICY`) selects the
//! policy, so an operator can already refuse every protected request instead of waiting for
//! `T14.3`; [`exposes_unauthenticated_api`] is what makes the dangerous combination — pass-through on
//! a non-loopback address — impossible to miss (the binary warns loudly at startup).
//!
//! Authentication is installed with `route_layer` **before** any protected route is merged into the
//! app, so a route added later cannot silently escape it: the layer is part of the group, not a
//! per-handler annotation.

use std::net::SocketAddr;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;
use crate::state::AppState;

/// Extension inserted on every request that reaches a protected handler.
///
/// `T14.4` (RBAC) needs the *resolved* identity; producing it here keeps the two tasks apart.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthenticatedIdentity {
    /// Kubernetes user name (`system:serviceaccount:ns:name`), `None` when unauthenticated.
    pub username: Option<String>,
    /// Kubernetes groups.
    pub groups: Vec<String>,
}

impl AuthenticatedIdentity {
    /// The identity of a request that carried no credential (the pass-through default).
    #[must_use]
    pub fn anonymous() -> Self {
        Self::default()
    }
}

/// How protected routes are authenticated.
///
/// Defaults to [`Self::PassThrough`]: `T14.3` owns turning this into `TokenReview`, and flipping the
/// default there is a one-line change guarded by the tests in this crate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthPolicy {
    /// No authentication yet: every protected request is allowed and annotated anonymous.
    #[default]
    PassThrough,
    /// Default-deny: every protected request is refused with `401` until `T14.3` resolves an
    /// identity.
    DenyAll,
}

impl AuthPolicy {
    /// A stable label for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PassThrough => "pass-through",
            Self::DenyAll => "default-deny",
        }
    }
}

/// The `--auth-policy` / `FERRISCD_AUTH_POLICY` parse failure.
///
/// Carries no value: a rejected policy string is not a secret, but echoing arbitrary operator input
/// back into a log line is a habit worth not having.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown authentication policy: expected `pass-through` or `deny-all`")]
pub struct UnknownAuthPolicy;

impl std::str::FromStr for AuthPolicy {
    type Err = UnknownAuthPolicy;

    /// Parses the exact `--auth-policy` values.
    ///
    /// Surrounding whitespace is trimmed (an env var picked up from a `ConfigMap` routinely carries
    /// it); anything else is refused rather than defaulted, because a typo must not silently select
    /// the permissive policy. `deny-all` and the log label `default-deny` are the same policy.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "pass-through" => Ok(Self::PassThrough),
            "deny-all" | "default-deny" => Ok(Self::DenyAll),
            _ => Err(UnknownAuthPolicy),
        }
    }
}

/// Whether `addr` + `policy` serve the protected API to callers who never authenticate.
///
/// [`AuthPolicy::PassThrough`] is the pre-`T14.3` behaviour and cannot authenticate anybody, so it is
/// only defensible on a loopback bind: anywhere else, every `/api/v1/*` route — sync and rollback
/// included — is writable by any pod that can reach the address. The binary calls this and logs a
/// warning, so the combination is visible instead of implied by a default.
#[must_use]
pub fn exposes_unauthenticated_api(addr: SocketAddr, policy: AuthPolicy) -> bool {
    policy == AuthPolicy::PassThrough && !addr.ip().is_loopback()
}

/// The `axum` middleware installed on the protected route group.
///
/// It runs **before** the handler and before any body is read, so an unauthenticated caller cannot
/// reach a decoder, a cluster read, or a diff computation.
pub async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    match state.auth {
        AuthPolicy::PassThrough => {
            request
                .extensions_mut()
                .insert(AuthenticatedIdentity::anonymous());
            next.run(request).await
        }
        AuthPolicy::DenyAll => ApiError::unauthorized(format!(
            "authentication is required for {} ({} policy); no identity was presented",
            request.uri().path(),
            state.auth.as_str()
        ))
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_is_the_documented_pass_through() {
        assert_eq!(AuthPolicy::default(), AuthPolicy::PassThrough);
        assert_eq!(AuthPolicy::PassThrough.as_str(), "pass-through");
        assert_eq!(AuthPolicy::DenyAll.as_str(), "default-deny");
    }

    #[test]
    fn an_anonymous_identity_carries_no_claims() {
        let identity = AuthenticatedIdentity::anonymous();
        assert_eq!(identity.username, None);
        assert!(identity.groups.is_empty());
    }

    /// **Finding `P14-H1`:** `--auth-policy` cannot be *typed* ambiguously — the two documented
    /// values parse, a typo is refused instead of falling back to the permissive default, and
    /// whitespace from an env var is tolerated.
    #[test]
    fn the_auth_policy_flag_values_parse_exactly() {
        assert_eq!(
            "pass-through".parse::<AuthPolicy>(),
            Ok(AuthPolicy::PassThrough)
        );
        assert_eq!("deny-all".parse::<AuthPolicy>(), Ok(AuthPolicy::DenyAll));
        assert_eq!(
            "  deny-all\n".parse::<AuthPolicy>(),
            Ok(AuthPolicy::DenyAll)
        );
        for rejected in [
            "",
            "pass_through",
            "DenyAll",
            "open",
            "pass-through,deny-all",
        ] {
            assert_eq!(
                rejected.parse::<AuthPolicy>(),
                Err(UnknownAuthPolicy),
                "{rejected:?} must not select a policy"
            );
        }
        // Every accepted spelling round-trips through `as_str`, so help text and logs agree.
        for policy in [AuthPolicy::PassThrough, AuthPolicy::DenyAll] {
            assert_eq!(policy.as_str().parse::<AuthPolicy>(), Ok(policy));
        }
    }

    /// **Trap guard (finding `P14-H1`):** the pass-through policy is only "safe" on loopback, and
    /// that is a decision the binary can ask about instead of an assumption.
    #[test]
    fn pass_through_is_only_unauthenticated_off_loopback() {
        for addr in ["0.0.0.0:8080", "[::]:8080", "10.0.0.7:8080"] {
            let addr: SocketAddr = addr.parse().expect("a socket address");
            assert!(
                exposes_unauthenticated_api(addr, AuthPolicy::PassThrough),
                "{addr} with pass-through serves every /api/v1/* route to strangers"
            );
            assert!(
                !exposes_unauthenticated_api(addr, AuthPolicy::DenyAll),
                "{addr}: default-deny authenticates (and refuses) everybody"
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
}

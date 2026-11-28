//! Tests for `T19.1`: OIDC/JWKS verification, the JWKS cache, the composite authenticator, and the
//! `GET /api/v1/auth/config` route.
//!
//! Everything here is hermetic: the keys are generated in-process (`ring`), the JWKS is a table
//! ([`FakeSource`]), the clock is injected, and the HTTP layer is the **real** router driven with
//! `tower::ServiceExt::oneshot`. No test opens a socket, sleeps, or talks to an IdP.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use ferriscd_crd::Application;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaKeyPair};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::auth::AuthPolicy;
use crate::rbac::{Actor, RbacPolicy};
use crate::state::{AppState, ApplicationSource, PublicAuthConfig};

// ---------------------------------------------------------------------------
// Fixtures: an IdP, a clock, and a key table
// ---------------------------------------------------------------------------

/// The issuer every test token carries.
const ISSUER: &str = "https://idp.example.com";

/// The client id every test token is addressed to.
const CLIENT_ID: &str = "ferriscd";

/// The instant the injected clock reports (2027-01-15T08:00:00Z).
const NOW: i64 = 1_800_000_000;

/// A throwaway RSA-2048 key, generated once with `openssl genpkey` and embedded because `ring` can
/// verify and sign with RSA but cannot *generate* an RSA key. It is a test fixture, never a secret:
/// nothing outside this file trusts it, and it is reproducible by anyone.
const TEST_RSA_PKCS8_BASE64: &str = concat!(
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDct4GxIPEDmUfYiwkR2GptVQX+65ZSs8SDXdy6QI11W+BJ",
    "d5NiesY32yCbyllb195oMqZNl/3sjaIfvu/Se2/BKj8qrVr8ttY8XOfZYgO+imPCdQqrkXB1T9lolgsA/MQDuMrGz3x9wRWm",
    "F0Ap8QXkoCQ/EJsMFbyIdByDmdTl5BL5csgVHwsoGMM+jFjaMhUwBs6qPyz1nE6HvB9qrLDnejGDyS9PSaVhDb8F+8axpWHc",
    "Z9wJuiIqWrdYieitWCISPG9zgNlDtDPyNXBIYzrryaomqjCKVAvfmi0M2wi6g1VuN9gPCvheIUjWtOygHXwap+ptp+CXbBJR",
    "ORV6tum9AgMBAAECggEAUoL3pPQfpazDwxwXA+jXwI+sciQ4SiqSKFoKjkZbm6gBLPXaz1H+kBsHEbaPuVn19xYYPaG4d5pr",
    "JVsH5LPoj1nvy1CLVzYy2NYShp2xsKWjrap7lrAETpbPO937tx7HWGzYwYIHlCt+oFzIy+UiwtlrM3hNvjLSDGD71+bGRDpR",
    "S43AcpjVtxyte94i/EC0SIgiqctQaZEariD1Z466WKHSba4AlyqI15Kp7kEJr2elhazGZnTjVGJZob7Y+avdPCWPSV03OsDB",
    "PFeIW7povMO6SEZasjLudi+J83wZ7zF+b6Q1uZK7plKKnEzTyLEO+3v+b7oFcYSRISOvYsrWsQKBgQD33imWSl+nsmnz1yBF",
    "1jUbCY6pbfJk4aQGh+ezE+IfJAMk1LeePyVFW5zT08OKUIoymalwBLRqX7qdVjALlysJ+Gz3SBTusUyI/aWL1rHwvUO2ixYy",
    "biVnX7eiKaK4o1pfdMdBTX/GuRNdt7xMqQq8vFR/aIaS+H0bIULIuNJW9wKBgQDj9U2qqYGnFgdel1MCOv6vaAA9ypgoiKXw",
    "0jFBvlw1UVGRhDkqW7ffb1trgAM9QJ3pnWq+6LEwG9E7h0yAljrl8hM5/RCLUb8wRdjcV+rWf8+7OZoQU8uptl2sAAmnXiKs",
    "pwhLNlEVtst0A8SWi5C5TWjBdPifoRX5rWIWBUlT6wKBgHb9Io+wUm0pm+1ft3FvHH1HQEIbssI1A83SzirMf7+dRRkYOLFx",
    "9M1v5kBWJ0et1DnoREuvJoDuRaKkLlpSDmox5PVsmAfh+zDEOwV/YlqEMQ5fhJ9e+vu+GmRxglkKqiaq48B4mL9oN2DFBFL0",
    "z1+9NP8YyYmiWkR82heLigYPAoGBAIjtYjevFegNfWO+NehTE4S9TdfQB9HhMvwS5e99rtl//SURbV0aNrqJozpRbKCwXapk",
    "GiiOkVA6hVXikXtzwfE5lX7xmax18AfJDNheHvu1TkxB7177VoyctGuKokHcc6uNsZesCsymPlNzp/Rd5RLJgrEh1+3azt5o",
    "3VAo4MD9AoGANN5kIONvxA8jsLwyTVmrugOBvN6QI7G84miKWa4tm/nfUmtYyyfmNo0KJ1dxmNaoFGq/KBr54klSPnxcTapz",
    "eVJFEiFdPxfXTLKcD+ne9oNrX0BXWmHvf6sde6R1a+S3hT81Up2ZKfPhqn8+z4XLOIWUauTJYkEZXfe7Gx6R0wY=",
);

/// The modulus (`n`) of [`TEST_RSA_PKCS8_BASE64`], base64url, as a JWK publishes it.
const TEST_RSA_MODULUS_BASE64URL: &str = concat!(
    "3LeBsSDxA5lH2IsJEdhqbVUF_uuWUrPEg13cukCNdVvgSXeTYnrGN9sgm8pZW9feaDKmTZf97I2iH77v0ntvwSo_Kq1a_Lb",
    "WPFzn2WIDvopjwnUKq5FwdU_ZaJYLAPzEA7jKxs98fcEVphdAKfEF5KAkPxCbDBW8iHQcg5nU5eQS-XLIFR8LKBjDPoxY2jIVM",
    "AbOqj8s9ZxOh7wfaqyw53oxg8kvT0mlYQ2_BfvGsaVh3GfcCboiKlq3WInorVgiEjxvc4DZQ7Qz8jVwSGM668mqJqowilQL35ot",
    "DNsIuoNVbjfYDwr4XiFI1rTsoB18Gqfqbafgl2wSUTkVerbpvQ",
);

/// The public exponent (`e`) of [`TEST_RSA_PKCS8_BASE64`]: 65537, base64url (`AQAB`).
const TEST_RSA_EXPONENT_BASE64URL: &str = "AQAB";

fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// One generated key pair plus the JWK that publishes its public half.
struct TestKey {
    algorithm: JoseAlgorithm,
    kid: String,
    signing: Signing,
}

enum Signing {
    Rsa(Box<RsaKeyPair>),
    Ecdsa(Box<EcdsaKeyPair>),
    Ed25519(Box<Ed25519KeyPair>),
}

impl TestKey {
    fn rsa(kid: &str) -> Self {
        let pkcs8 = base64::engine::general_purpose::STANDARD
            .decode(TEST_RSA_PKCS8_BASE64)
            .expect("the fixture key decodes");
        Self {
            algorithm: JoseAlgorithm::Rs256,
            kid: kid.to_owned(),
            signing: Signing::Rsa(Box::new(
                RsaKeyPair::from_pkcs8(&pkcs8).expect("the fixture key parses"),
            )),
        }
    }

    fn ecdsa(algorithm: JoseAlgorithm, kid: &str) -> Self {
        let signing_algorithm: &'static signature::EcdsaSigningAlgorithm = match algorithm {
            JoseAlgorithm::Es256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            JoseAlgorithm::Es384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            other => unreachable!("{other:?} is not an ECDSA algorithm"),
        };
        let rng = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(signing_algorithm, &rng).expect("a fresh ECDSA key");
        let pair = EcdsaKeyPair::from_pkcs8(signing_algorithm, document.as_ref(), &rng)
            .expect("the generated key parses");
        Self {
            algorithm,
            kid: kid.to_owned(),
            signing: Signing::Ecdsa(Box::new(pair)),
        }
    }

    fn ed25519(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng).expect("a fresh Ed25519 key");
        Self {
            algorithm: JoseAlgorithm::EdDsa,
            kid: kid.to_owned(),
            signing: Signing::Ed25519(Box::new(
                Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("the generated key parses"),
            )),
        }
    }

    /// The JWK the IdP publishes for this key.
    fn jwk(&self) -> Value {
        match &self.signing {
            Signing::Rsa(_) => json!({
                "kty": "RSA",
                "use": "sig",
                "kid": self.kid,
                "alg": self.algorithm.as_str(),
                "n": TEST_RSA_MODULUS_BASE64URL,
                "e": TEST_RSA_EXPONENT_BASE64URL,
            }),
            Signing::Ecdsa(pair) => {
                let point = pair.public_key().as_ref();
                let (x, y) = point[1..].split_at((point.len() - 1) / 2);
                json!({
                    "kty": "EC",
                    "use": "sig",
                    "kid": self.kid,
                    "alg": self.algorithm.as_str(),
                    "crv": match self.algorithm {
                        JoseAlgorithm::Es384 => "P-384",
                        _ => "P-256",
                    },
                    "x": base64url(x),
                    "y": base64url(y),
                })
            }
            Signing::Ed25519(pair) => json!({
                "kty": "OKP",
                "use": "sig",
                "kid": self.kid,
                "alg": self.algorithm.as_str(),
                "crv": "Ed25519",
                "x": base64url(pair.public_key().as_ref()),
            }),
        }
    }

    /// A one-key JWKS holding this key.
    fn key_set(&self) -> JwkSet {
        JwkSet::parse_json(&serde_json::to_vec(&json!({"keys": [self.jwk()]})).expect("json"))
            .expect("a usable key set")
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match &self.signing {
            Signing::Rsa(pair) => {
                let mut signature = vec![0_u8; pair.public().modulus_len()];
                pair.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature)
                    .expect("RSA signing");
                signature
            }
            Signing::Ecdsa(pair) => pair
                .sign(&rng, message)
                .expect("ECDSA signing")
                .as_ref()
                .to_vec(),
            Signing::Ed25519(pair) => pair.sign(message).as_ref().to_vec(),
        }
    }

    /// Signs an arbitrary JOSE header over `claims`.
    fn token_with_header(&self, header: Value, claims: &Value) -> String {
        let header = base64url(&serde_json::to_vec(&header).expect("json"));
        let payload = base64url(&serde_json::to_vec(claims).expect("json"));
        let signing_input = format!("{header}.{payload}");
        let signature = self.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", base64url(&signature))
    }

    /// The ordinary token: this key's `alg` and `kid`.
    fn token(&self, claims: &Value) -> String {
        self.token_with_header(
            json!({"alg": self.algorithm.as_str(), "kid": self.kid, "typ": "JWT"}),
            claims,
        )
    }

    /// A token naming `kid` in the header (a key the set may not hold).
    fn token_with_kid(&self, kid: &str, claims: &Value) -> String {
        self.token_with_header(
            json!({"alg": self.algorithm.as_str(), "kid": kid, "typ": "JWT"}),
            claims,
        )
    }
}

/// Swaps the payload of a valid token while keeping its header and signature: the classic
/// claim-substitution attack, and the way a "signed by a key we do not publish" test is expressed
/// without a second RSA fixture.
fn substitute_claims(token: &str, claims: &Value) -> String {
    let mut segments = token.split('.');
    let header = segments.next().expect("a header segment");
    segments.next();
    let signature = segments.next().expect("a signature segment");
    format!(
        "{header}.{}.{signature}",
        base64url(&serde_json::to_vec(claims).expect("json"))
    )
}

/// The claims a valid token carries.
fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "alice-123",
        "groups": ["payments-team", "platform-readers"],
        "iat": NOW - 60,
        "exp": NOW + 300,
    })
}

/// The response a fake [`JwksSource`] hands out.
#[derive(Debug)]
struct FakeSource {
    sets: Mutex<Vec<JwkSet>>,
    fetches: AtomicUsize,
    failure: Mutex<Option<OidcError>>,
    /// How many upcoming fetches hang until they are cancelled.
    hang_next: AtomicUsize,
    /// How many scheduler yields each upcoming fetch takes before it answers (a slow but healthy
    /// IdP — what lets concurrent callers pile up behind one fetch deterministically).
    yield_next: AtomicUsize,
}

impl FakeSource {
    fn new(sets: Vec<JwkSet>) -> Arc<Self> {
        Arc::new(Self {
            sets: Mutex::new(sets),
            fetches: AtomicUsize::new(0),
            failure: Mutex::new(None),
            hang_next: AtomicUsize::new(0),
            yield_next: AtomicUsize::new(0),
        })
    }

    /// Publishes a new key set (an IdP key rotation).
    fn publish(&self, set: JwkSet) {
        self.sets.lock().expect("test state").push(set);
    }

    /// Makes every subsequent fetch fail.
    fn fail_with(&self, error: OidcError) {
        *self.failure.lock().expect("test state") = Some(error);
    }

    /// Makes the next `count` fetches hang (a slow IdP whose request is dropped).
    fn hang(&self, count: usize) {
        self.hang_next.store(count, Ordering::SeqCst);
    }

    /// Makes each upcoming fetch yield `count` times before answering: the caller's peers get to
    /// subscribe while the fetch is still in flight, without a wall-clock sleep.
    fn yields(&self, count: usize) {
        self.yield_next.store(count, Ordering::SeqCst);
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

impl JwksSource for FakeSource {
    fn fetch(&self) -> BoxFuture<'static, Result<JwkSet, OidcError>> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if self
            .hang_next
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            // Never resolves: the caller is expected to drop (cancel) this future.
            return Box::pin(std::future::pending());
        }
        let yields = self.yield_next.load(Ordering::SeqCst);
        if yields > 0 {
            self.yield_next.fetch_sub(1, Ordering::SeqCst);
        }
        let failure = self.failure.lock().expect("test state").clone();
        if let Some(error) = failure {
            return Box::pin(async move {
                for _ in 0..yields {
                    tokio::task::yield_now().await;
                }
                Err(error)
            });
        }
        let set = self
            .sets
            .lock()
            .expect("test state")
            .last()
            .cloned()
            .unwrap_or_default();
        let outcome = if set.is_empty() {
            Err(OidcError::NoUsableKeys)
        } else {
            Ok(set)
        };
        Box::pin(async move {
            for _ in 0..yields {
                tokio::task::yield_now().await;
            }
            outcome
        })
    }
}

/// A fixed clock, so `exp`/`nbf` are asserted without sleeping and without the host clock.
fn clock_at(seconds: i64) -> Clock {
    Arc::new(move || UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap_or(0)))
}

fn config() -> OidcConfig {
    OidcConfig::new(ISSUER, CLIENT_ID)
}

/// Builds an authenticator over `source` whose clock reads [`NOW`].
fn authenticator(source: &Arc<FakeSource>) -> OidcTokenAuthenticator {
    authenticator_at(source, config(), NOW)
}

fn authenticator_at(
    source: &Arc<FakeSource>,
    config: OidcConfig,
    now: i64,
) -> OidcTokenAuthenticator {
    let cache = Arc::new(
        JwksCache::new(
            Arc::clone(source) as Arc<dyn JwksSource>,
            config.jwks_min_refresh_interval,
        )
        .expect("a validated config carries a non-zero refresh interval"),
    );
    OidcTokenAuthenticator::with_clock(config, cache, clock_at(now))
        .expect("the test configuration is valid")
}

/// The identity an OIDC token resolves to, or `None`.
async fn identity_of(auth: &OidcTokenAuthenticator, token: &str) -> Option<AuthenticatedIdentity> {
    auth.authenticate(token).await.expect("no backend failure")
}

/// The rejection an evaluation produced (`None` for an accepted or foreign token).
async fn rejection_of(auth: &OidcTokenAuthenticator, token: &str) -> Option<Rejection> {
    match auth.evaluate(token).await {
        OidcOutcome::Rejected(rejection) => Some(rejection),
        OidcOutcome::Accepted(_) | OidcOutcome::NotApplicable(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Configuration (the trap guards: startup refuses, not the request)
// ---------------------------------------------------------------------------

/// **Trap guard:** an empty username/groups prefix, a plain-`http` issuer without the local-dev flag,
/// an over-large clock skew and an empty scope list are all *startup* failures — a deployment cannot
/// boot into a configuration that would let an IdP claim impersonate a Kubernetes identity.
#[test]
fn an_unusable_configuration_is_refused_at_startup() {
    assert!(
        config().validate().is_ok(),
        "the documented default is usable"
    );
    let validated = config().validate().expect("valid");
    assert_eq!(validated.issuer, ISSUER);
    assert_eq!(validated.username_prefix, "oidc:");
    assert_eq!(validated.groups_prefix, "oidc:");
    assert_eq!(
        validated.scopes,
        vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned()
        ]
    );
    assert_eq!(validated.clock_skew, MAX_CLOCK_SKEW);

    for (config, expected) in [
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_username_prefix(""),
            OidcConfigError::EmptyUsernamePrefix,
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_username_prefix("   "),
            OidcConfigError::EmptyUsernamePrefix,
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_username_prefix("oidc users:"),
            OidcConfigError::MalformedPrefix { which: "username" },
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_username_prefix("system:"),
            OidcConfigError::ReservedPrefix { which: "username" },
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_groups_prefix(""),
            OidcConfigError::EmptyGroupsPrefix,
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_groups_prefix("system:"),
            OidcConfigError::ReservedPrefix { which: "groups" },
        ),
        (OidcConfig::new(ISSUER, ""), OidcConfigError::EmptyClientId),
        (OidcConfig::new("", CLIENT_ID), OidcConfigError::EmptyIssuer),
        (
            OidcConfig::new("http://idp.internal", CLIENT_ID),
            OidcConfigError::InsecureIssuer,
        ),
        (
            OidcConfig::new("ftp://idp.internal", CLIENT_ID),
            OidcConfigError::IssuerNotAbsolute,
        ),
        (
            OidcConfig::new("https://idp.example.com/?tenant=1", CLIENT_ID),
            OidcConfigError::IssuerCarriesAmbiguity,
        ),
        (
            OidcConfig::new("https://user:pass@idp.example.com", CLIENT_ID),
            OidcConfigError::IssuerCarriesAmbiguity,
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_clock_skew(Duration::from_secs(31)),
            OidcConfigError::ClockSkewTooLarge,
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_jwks_min_refresh_interval(Duration::ZERO),
            OidcConfigError::ZeroRefreshInterval,
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_http_timeout(Duration::ZERO),
            OidcConfigError::ZeroHttpTimeout,
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_scopes(Vec::new()),
            OidcConfigError::EmptyScopes,
        ),
        (
            OidcConfig::new(ISSUER, CLIENT_ID).with_scopes(vec!["openid admin".to_owned()]),
            OidcConfigError::MalformedScope,
        ),
    ] {
        assert_eq!(config.validate().err(), Some(expected));
    }

    // The local development path is explicit and does not require a rebuild.
    let development = OidcConfig::new("http://dex.ferriscd-system.svc:5556", CLIENT_ID)
        .with_allow_insecure_http(true)
        .validate()
        .expect("the development flag allows a plain-http IdP");
    assert!(development.allow_insecure_http);

    // The trailing slash an operator pastes from the IdP's documentation is normalized, not refused.
    assert_eq!(
        OidcConfig::new("https://idp.example.com/", CLIENT_ID)
            .validate()
            .expect("valid")
            .issuer,
        ISSUER
    );
}

/// **Trap guard:** the authenticator re-validates, so an embedder cannot bypass the startup checks by
/// constructing the type directly.
#[test]
fn the_authenticator_refuses_an_invalid_configuration() {
    let source = FakeSource::new(Vec::new());
    let cache = Arc::new(
        JwksCache::new(
            Arc::clone(&source) as Arc<dyn JwksSource>,
            DEFAULT_JWKS_MIN_REFRESH_INTERVAL,
        )
        .expect("the default refresh interval is not zero"),
    );
    assert_eq!(
        OidcTokenAuthenticator::with_clock(
            OidcConfig::new(ISSUER, CLIENT_ID).with_groups_prefix(""),
            cache,
            clock_at(NOW),
        )
        .err(),
        Some(OidcConfigError::EmptyGroupsPrefix)
    );
}

/// **`T19.1` finding `N5`:** the trap guard ("at most one outbound JWKS fetch per 60 s") lives in the
/// cache, so the cache itself refuses a zero interval. `OidcConfig::validate` already rejects one at
/// startup, but the constructor is public and an embedder that never calls `validate` would otherwise
/// be able to disable the guard — the very thing that keeps a burst of 100 tokens with 100 random
/// `kid`s from becoming 100 requests to the IdP.
#[test]
fn the_jwks_cache_refuses_a_zero_refresh_interval() {
    let source = FakeSource::new(Vec::new());
    assert_eq!(
        JwksCache::new(Arc::clone(&source) as Arc<dyn JwksSource>, Duration::ZERO,).err(),
        Some(OidcError::ZeroRefreshInterval)
    );
    // The smallest non-zero interval is accepted: the guard needs *a* bound, not necessarily 60 s.
    assert!(
        JwksCache::new(
            Arc::clone(&source) as Arc<dyn JwksSource>,
            Duration::from_nanos(1),
        )
        .is_ok()
    );
    assert_eq!(source.fetches(), 0, "constructing a cache performs no I/O");
}

/// The allow-list is an enum: `none`, the symmetric `HS*` family, `PS*` and the deprecated curves are
/// not expressible, so no later string comparison can widen what is accepted.
#[test]
fn only_the_four_asymmetric_algorithms_are_representable() {
    for allowed in ["RS256", "ES256", "ES384", "EdDSA"] {
        let algorithm = JoseAlgorithm::parse(allowed).expect("an allowed algorithm");
        assert_eq!(algorithm.as_str(), allowed);
    }
    assert_eq!(JoseAlgorithm::ALLOWED.len(), 4);
    for rejected in [
        "none", "None", "NONE", "HS256", "HS384", "HS512", "RS384", "RS512", "PS256", "ES256K", "",
    ] {
        assert_eq!(
            JoseAlgorithm::parse(rejected),
            None,
            "{rejected:?} must not be representable"
        );
    }
}

// ---------------------------------------------------------------------------
// Verification: the happy paths (all four algorithms) and RBAC integration
// ---------------------------------------------------------------------------

/// **Verification bullet 1:** a valid `RS256`/`ES256`/`ES384`/`EdDSA` token maps a prefixed username
/// and prefixed groups, and the resulting identity authorizes against an ordinary `RbacPolicy` — with
/// no handler or policy change.
#[tokio::test]
async fn every_allowed_algorithm_maps_prefixed_claims_into_the_rbac_policy() {
    let keys = [
        TestKey::rsa("rsa-1"),
        TestKey::ecdsa(JoseAlgorithm::Es256, "ec-256"),
        TestKey::ecdsa(JoseAlgorithm::Es384, "ec-384"),
        TestKey::ed25519("ed-1"),
    ];
    let sets: Vec<JwkSet> = keys.iter().map(TestKey::key_set).collect();
    let mut all_keys = Vec::new();
    for set in &sets {
        all_keys.extend(set.keys().iter().cloned());
    }
    let source = FakeSource::new(vec![JwkSet::new(all_keys)]);
    let auth = authenticator(&source);

    let policy = RbacPolicy::parse(
        r#"
rules:
  - subject: {kind: group, name: "oidc:payments-team"}
    project: payments
    actions: [get, diff]
"#,
    )
    .expect("the documented policy parses");

    for key in &keys {
        let token = key.token(&claims());
        let credential = auth
            .authenticate_credential(&token)
            .await
            .expect("no backend failure")
            .unwrap_or_else(|| panic!("{} must verify", key.algorithm.as_str()));
        assert_eq!(
            credential.identity.username.as_deref(),
            Some("oidc:alice-123"),
            "{}",
            key.algorithm.as_str()
        );
        assert_eq!(
            credential.identity.groups,
            vec![
                "oidc:payments-team".to_owned(),
                "oidc:platform-readers".to_owned()
            ],
            "{}",
            key.algorithm.as_str()
        );
        // `exp - now` is what the cache is clamped to.
        assert_eq!(credential.ttl, Some(Duration::from_secs(300)));

        let actor = Actor::new(&policy, &credential.identity);
        assert!(
            actor.can_see("payments"),
            "{}: the prefixed group must authorize the project",
            key.algorithm.as_str()
        );
        assert!(
            !actor.can_see("tenant-a"),
            "{}: and nothing else",
            key.algorithm.as_str()
        );
        // The audit actor is attributed as `oidc:<sub>` (`T17.2` dependency).
        let actor = crate::audit::actor_from_identity(&credential.identity, None);
        assert_eq!(actor.username.as_deref(), Some("oidc:alice-123"));
        assert_eq!(actor.groups, credential.identity.groups);
    }
    assert_eq!(
        source.fetches(),
        1,
        "one key set serves every algorithm: verification is local"
    );
}

/// **Non-functional:** after the first fetch a verified token costs nothing but a local signature
/// check — no per-request IdP call, no cache refresh.
#[tokio::test(start_paused = true)]
async fn a_verified_token_never_touches_the_idp_again() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);
    let token = key.token(&claims());

    for _ in 0..100 {
        assert!(identity_of(&auth, &token).await.is_some());
    }
    assert_eq!(
        source.fetches(),
        1,
        "100 verifications must not produce a second JWKS fetch"
    );
}

// ---------------------------------------------------------------------------
// Verification: the attacks
// ---------------------------------------------------------------------------

/// **Verification bullet 2 (part 1):** `alg: none` is refused — and refused *by name*, before any key
/// is consulted, so an unsigned token can never be "verified" by a fallback path.
#[tokio::test]
async fn an_unsigned_none_algorithm_token_is_refused() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);

    let header = base64url(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = base64url(&serde_json::to_vec(&claims()).expect("json"));
    for token in [
        // The RFC 7519 spelling: an empty signature segment.
        format!("{header}.{payload}."),
        // A "signature" that is not one.
        format!("{header}.{payload}.{}", base64url(b"nothing")),
    ] {
        assert_eq!(
            rejection_of(&auth, &token).await,
            Some(Rejection::UnsupportedAlgorithm)
        );
        assert!(identity_of(&auth, &token).await.is_none());
    }
    assert_eq!(
        source.fetches(),
        0,
        "an unsupported `alg` must not even fetch the key set"
    );
}

/// **Verification bullet 2 (part 2), the key-confusion attack:** an `HS256` token signed with the RSA
/// *public* key as the HMAC secret. The signature is perfectly valid HMAC; it must still be refused,
/// because `HS256` is not an algorithm this server will ever consider.
#[tokio::test]
async fn an_hs256_token_signed_with_the_public_key_is_refused() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);

    let header = base64url(br#"{"alg":"HS256","kid":"rsa-1","typ":"JWT"}"#);
    let payload = base64url(&serde_json::to_vec(&claims()).expect("json"));
    let signing_input = format!("{header}.{payload}");
    // The classic confusion: the verifier's *public* key is the attacker's HMAC secret.
    let secret = URL_SAFE_NO_PAD
        .decode(TEST_RSA_MODULUS_BASE64URL)
        .expect("the modulus decodes");
    let mac = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret),
        signing_input.as_bytes(),
    );
    let token = format!("{signing_input}.{}", base64url(mac.as_ref()));

    assert_eq!(
        rejection_of(&auth, &token).await,
        Some(Rejection::UnsupportedAlgorithm)
    );
    assert!(identity_of(&auth, &token).await.is_none());
}
/// **Verification bullet 2 (part 3):** `exp` and `nbf` are enforced with a bounded skew — a token that
/// expired within the last 30 s is still good (clocks drift), one that expired 31 s ago is not, and
/// the same holds, mirrored, for `nbf`.
#[tokio::test]
async fn exp_and_nbf_are_enforced_with_a_bounded_skew() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);

    for (exp_offset, expected) in [
        (300_i64, None),
        (-30, None),
        (-31, Some(Rejection::Expired)),
        (-3600, Some(Rejection::Expired)),
    ] {
        let mut claims = claims();
        claims["exp"] = json!(NOW + exp_offset);
        let token = key.token(&claims);
        assert_eq!(
            rejection_of(&auth, &token).await,
            expected,
            "exp offset {exp_offset}"
        );
    }

    for (nbf_offset, expected) in [
        (-300_i64, None),
        (30, None),
        (31, Some(Rejection::NotYetValid)),
        (3600, Some(Rejection::NotYetValid)),
    ] {
        let mut claims = claims();
        claims["nbf"] = json!(NOW + nbf_offset);
        let token = key.token(&claims);
        assert_eq!(
            rejection_of(&auth, &token).await,
            expected,
            "nbf offset {nbf_offset}"
        );
    }

    // A token with no `exp` at all is not a session this server will accept.
    let mut claims = claims();
    claims.as_object_mut().expect("claims").remove("exp");
    let token = key.token(&claims);
    assert_eq!(
        rejection_of(&auth, &token).await,
        Some(Rejection::MissingExpiry)
    );
}

/// **Verification bullet 2 (part 4):** `iss` and `aud` are matched exactly — a token from another IdP
/// is not ours to judge (the composite falls through), and a token addressed to another client is
/// refused.
#[tokio::test]
async fn the_issuer_and_audience_are_matched_exactly() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);

    let mut foreign = claims();
    foreign["iss"] = json!("https://kubernetes.default.svc");
    let token = key.token(&foreign);
    assert!(matches!(
        auth.evaluate(&token).await,
        OidcOutcome::NotApplicable(NotApplicable::ForeignIssuer)
    ));

    // A trailing slash is a different issuer (the discovery document must match exactly), so the
    // token is somebody else's and is never verified against our keys.
    let mut slashed = claims();
    slashed["iss"] = json!(format!("{ISSUER}/"));
    assert!(matches!(
        auth.evaluate(&key.token(&slashed)).await,
        OidcOutcome::NotApplicable(NotApplicable::ForeignIssuer)
    ));

    for audience in [
        json!("another-client"),
        json!([]),
        json!(["a", "b"]),
        json!(7),
    ] {
        let mut claims = claims();
        claims["aud"] = audience.clone();
        let token = key.token(&claims);
        assert_eq!(
            rejection_of(&auth, &token).await,
            Some(Rejection::AudienceMismatch),
            "aud {audience}"
        );
    }
    // The documented shapes both work: a single string and an array containing the client id.
    for audience in [json!(CLIENT_ID), json!(["another-client", CLIENT_ID])] {
        let mut claims = claims();
        claims["aud"] = audience.clone();
        let token = key.token(&claims);
        assert!(
            identity_of(&auth, &token).await.is_some(),
            "aud {audience} must be accepted"
        );
    }
}

/// **Verification bullet 2 (part 5):** a token without a usable `sub` has no identity to authorize, and
/// one that declares a critical extension this server does not implement is refused (RFC 7515 §4.1.11).
#[tokio::test]
async fn a_missing_subject_or_an_unknown_critical_header_is_refused() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);

    for subject in [json!(""), json!("   "), json!(null), json!(42)] {
        let mut claims = claims();
        claims["sub"] = subject.clone();
        let token = key.token(&claims);
        assert_eq!(
            rejection_of(&auth, &token).await,
            Some(Rejection::MissingSubject),
            "sub {subject}"
        );
    }

    let token = key.token_with_header(
        json!({"alg": "RS256", "kid": "rsa-1", "crit": ["exp-b64"], "typ": "JWT"}),
        &claims(),
    );
    assert_eq!(
        rejection_of(&auth, &token).await,
        Some(Rejection::UnsupportedCriticalHeader)
    );

    // A token whose signature does not cover the payload is a plain mismatch.
    let token = key.token(&claims());
    let mut tampered = token.clone().into_bytes();
    let last = tampered.len() - 3;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("ascii");
    assert_eq!(
        rejection_of(&auth, &tampered).await,
        Some(Rejection::SignatureMismatch)
    );

    // A token whose claims were swapped after signing: the `kid` names our key, but the signature
    // covers different bytes.
    let mut substituted = claims();
    substituted["groups"] = json!(["platform-admins"]);
    let token = substitute_claims(&key.token(&claims()), &substituted);
    assert_eq!(
        rejection_of(&auth, &token).await,
        Some(Rejection::SignatureMismatch),
        "a substituted claim must not verify"
    );
}

// ---------------------------------------------------------------------------
// The JWKS cache: rotation, the 60 s rate limit, and a broken IdP
// ---------------------------------------------------------------------------

/// **Verification bullet 3 (the trap guard):** 100 requests carrying an unknown `kid` trigger **at most
/// one** JWKS fetch inside the 60 s window, and a rotated key becomes usable as soon as the window
/// allows exactly one more fetch.
#[tokio::test(start_paused = true)]
async fn an_unknown_kid_refetches_at_most_once_per_minute() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);
    let unknown = key.token_with_kid("rotation-2", &claims());

    for request in 0..100 {
        assert_eq!(
            rejection_of(&auth, &unknown).await,
            Some(Rejection::UnknownKeyId),
            "request {request}"
        );
    }
    assert_eq!(
        source.fetches(),
        1,
        "100 unknown-`kid` requests must cost the IdP exactly one fetch"
    );

    // The IdP rotates: the token is now valid, but the cache refuses to refetch inside the window.
    let rotated = TestKey::rsa("rotation-2");
    source.publish(rotated.key_set());
    let rotated_token = rotated.token(&claims());
    let fetches_before = source.fetches();
    assert_eq!(
        rejection_of(&auth, &rotated_token).await,
        Some(Rejection::UnknownKeyId)
    );
    assert_eq!(
        source.fetches(),
        fetches_before,
        "the rate limit applies to a genuine rotation too"
    );

    // One minute later the single permitted refetch happens and the rotated key is picked up.
    tokio::time::advance(Duration::from_secs(59)).await;
    assert_eq!(
        rejection_of(&auth, &rotated_token).await,
        Some(Rejection::UnknownKeyId)
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let credential = auth
        .authenticate_credential(&rotated_token)
        .await
        .expect("no backend failure")
        .expect("the rotated key is picked up");
    assert_eq!(
        credential.identity.username.as_deref(),
        Some("oidc:alice-123")
    );
    assert_eq!(
        source.fetches(),
        fetches_before + 1,
        "exactly one more fetch, not one per request"
    );
}

/// A broken IdP fails **closed** (the token is refused, never silently accepted) and the failure is
/// still rate limited, so a hanging IdP is polled at the same bounded rate as a healthy one.
///
/// `T19.1` finding `M2`: the seam reports that as an `Err` (a backend failure), not as `Ok(None)` (a
/// rejected credential), so an outage is distinguishable from an attacker's token.
#[tokio::test(start_paused = true)]
async fn a_broken_key_source_refuses_tokens_and_is_retried_at_the_bounded_rate() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    source.fail_with(OidcError::Jwks("connection refused".to_owned()));
    let auth = authenticator(&source);
    let token = key.token(&claims());

    // The fetch that fails is reported as a key-source failure and the token is refused — as a
    // backend error, which the middleware audits as an outage rather than as a rejected token.
    assert_eq!(
        rejection_of(&auth, &token).await,
        Some(Rejection::KeySource)
    );
    for _ in 0..10 {
        match auth.authenticate(&token).await {
            Err(error) => assert_eq!(error.code(), "BackendUnavailable"),
            Ok(identity) => panic!("a broken key source must fail closed, got {identity:?}"),
        }
    }
    assert_eq!(source.fetches(), 1, "one attempt inside the window");

    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(auth.authenticate(&token).await.is_err());
    assert_eq!(source.fetches(), 2, "and exactly one more after it");
}

/// **Cancellation safety:** a request dropped while its JWKS fetch is in flight must not wedge the
/// cache. The rate-limit stamp is claimed before the fetch, so the next window recovers instead of a
/// "refresh in progress" flag latching forever.
#[tokio::test(start_paused = true)]
async fn a_cancelled_refresh_does_not_wedge_the_cache() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let cache = JwksCache::new(
        Arc::clone(&source) as Arc<dyn JwksSource>,
        DEFAULT_JWKS_MIN_REFRESH_INTERVAL,
    )
    .expect("the default refresh interval is not zero");
    source.hang(1);

    // The first fetch hangs; the request it belonged to is dropped (a disconnect, a timeout).
    let cancelled = tokio::time::timeout(
        Duration::from_secs(1),
        cache.keys_for(Some("rsa-1"), JoseAlgorithm::Rs256),
    )
    .await;
    assert!(cancelled.is_err(), "the fetch was cancelled, not answered");
    assert_eq!(source.fetches(), 1);
    assert!(cache.cached().is_none());

    // Inside the window the cache refuses to hammer the (slow) IdP. With no key set cached at all it
    // reports that as an outage (`M2`), not as a refused token: nobody can be authenticated until
    // the next window, which is a backend condition, not a verdict about the caller's credential.
    assert!(matches!(
        cache.keys_for(Some("rsa-1"), JoseAlgorithm::Rs256).await,
        Err(OidcError::KeySetUnavailable(_))
    ));
    assert_eq!(source.fetches(), 1);

    // Once the window elapses the cache fetches again, and this time it recovers.
    tokio::time::advance(DEFAULT_JWKS_MIN_REFRESH_INTERVAL).await;
    let keys = cache
        .keys_for(Some("rsa-1"), JoseAlgorithm::Rs256)
        .await
        .expect("the retry succeeds")
        .expect("the key is served");
    assert_eq!(keys.len(), 1);
    assert_eq!(source.fetches(), 2);
}

/// **`T19.1` finding `M1` (single-flight):** callers that arrive while a refresh is already in
/// flight wait for **that** refresh — one outbound fetch, one answer for everybody — instead of
/// being told "rate limited" and refusing a token that is perfectly valid.
///
/// Without the flight, seven of these eight callers would receive `RefreshRateLimited` and turn into
/// `UnknownKeyId` → `401`: the `T19.1` trap guard ("at most one fetch per 60 s") would have been
/// satisfied by breaking authentication for everyone but the leader.
#[tokio::test]
async fn concurrent_callers_await_one_in_flight_refresh() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let cache = Arc::new(
        JwksCache::new(
            Arc::clone(&source) as Arc<dyn JwksSource>,
            DEFAULT_JWKS_MIN_REFRESH_INTERVAL,
        )
        .expect("the default refresh interval is not zero"),
    );
    // The fetch yields a few times, so every caller below is registered while it is in flight.
    source.yields(4);

    let calls = (0..8).map(|_| cache.keys_for(Some("rsa-1"), JoseAlgorithm::Rs256));
    let results = futures::future::join_all(calls).await;

    assert_eq!(
        source.fetches(),
        1,
        "eight concurrent callers must cost the IdP exactly one fetch"
    );
    assert_eq!(cache.fetch_attempts(), 1);
    let served: Vec<Arc<JwkSet>> = results
        .into_iter()
        .map(|result| {
            result
                .expect("a shared, successful fetch is never a rate limit")
                .expect("the key is served to every caller")
        })
        .collect();
    assert_eq!(served.len(), 8);
    for keys in &served {
        assert!(
            Arc::ptr_eq(&served[0], keys),
            "every caller shares the one fetched key set"
        );
        assert_eq!(keys.len(), 1);
    }

    // A later caller, inside the window, is still rate limited: single-flight did not turn the
    // cache into something that refetches per request.
    assert!(
        cache
            .keys_for(Some("unknown-kid"), JoseAlgorithm::Rs256)
            .await
            .is_ok_and(|keys| keys.is_none())
    );
    assert_eq!(source.fetches(), 1);
}

/// A failed fetch is shared too: the followers get the same `Err` (an IdP outage) rather than a
/// second attempt, so a down IdP is still polled at the bounded rate.
#[tokio::test]
async fn concurrent_callers_share_one_failed_refresh() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    source.fail_with(OidcError::Jwks("connection refused".to_owned()));
    source.yields(4);
    let cache = Arc::new(
        JwksCache::new(
            Arc::clone(&source) as Arc<dyn JwksSource>,
            DEFAULT_JWKS_MIN_REFRESH_INTERVAL,
        )
        .expect("the default refresh interval is not zero"),
    );

    let calls = (0..4).map(|_| cache.keys_for(Some("rsa-1"), JoseAlgorithm::Rs256));
    let results = futures::future::join_all(calls).await;

    assert_eq!(source.fetches(), 1, "a failure is one outbound fetch too");
    for result in results {
        assert!(
            matches!(result, Err(OidcError::Jwks(_))),
            "every caller learns the IdP could not answer: {result:?}"
        );
    }
}

/// **`T19.1` finding `M2`:** an IdP outage and an attacker's token are *different answers*.
///
/// A token this server judged and refused is `Ok(None)` — the ordinary `401`, which tells an
/// attacker nothing and is exactly what a forged signature earns. A key set that could not be
/// refreshed **at all** is `Err(ApiError::Backend)`: retryable, and audited by the middleware as a
/// backend failure rather than as a rejected credential.
#[tokio::test]
async fn an_idp_outage_is_a_backend_error_while_a_forged_token_is_a_refusal() {
    let key = TestKey::rsa("rsa-1");

    // A healthy IdP: the forged token is judged, and refused as a token.
    let healthy = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&healthy);
    let mut escalated = claims();
    escalated["groups"] = json!(["platform-admins"]);
    let forged = substitute_claims(&key.token(&claims()), &escalated);
    assert!(
        auth.authenticate_credential(&forged)
            .await
            .expect("a judged token is never a backend error")
            .is_none(),
        "a forged signature is a refusal, not a retryable condition"
    );
    assert!(auth.authenticate(&forged).await.is_ok());

    // An IdP that cannot answer: the same shape of request is a backend failure.
    let broken = FakeSource::new(vec![key.key_set()]);
    broken.fail_with(OidcError::Jwks("connection refused".to_owned()));
    let offline = authenticator(&broken);
    let error = offline
        .authenticate_credential(&key.token(&claims()))
        .await
        .expect_err("an unreachable IdP is not a verdict about the token");
    assert_eq!(error.code(), "BackendUnavailable");
    assert_eq!(error.status().as_u16(), 502);
    assert!(
        !error.message().contains("connection refused"),
        "the transport detail stays in the log: {}",
        error.message()
    );
    // `authenticate` reports the same condition: the composite may never fall through on it.
    assert!(offline.authenticate(&key.token(&claims())).await.is_err());
    assert_eq!(
        broken.fetches(),
        1,
        "the outage is still rate limited, not retried per call"
    );
}

// ---------------------------------------------------------------------------
// Claim screening (`M3`)
// ---------------------------------------------------------------------------

/// **`T19.1` finding `M3`:** a `sub` or a group carrying a control character is refused, exactly
/// like a bearer token is (`BearerToken::parse`).
///
/// The identity these claims produce is rendered into log lines, `Application.status` messages and
/// audit records, so a newline or an ANSI escape could forge a record ("`oidc:alice`\nsync
/// succeeded") or wipe a terminal. The claim is never sanitized into something usable: the token is
/// refused, and no identity is ever built from it.
#[tokio::test]
async fn a_claim_carrying_a_control_character_is_refused() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);

    // `sub` variants: a forged log line, an ANSI escape, a NUL, and an embedded CRLF.
    for subject in [
        "alice\nsystem:masters",
        "alice\u{1b}[2Joidc:admin",
        "ali\u{0}ce",
        "alice\r\nspoofed record",
        "alice\tsystem:masters",
    ] {
        let mut forged = claims();
        forged["sub"] = json!(subject);
        let token = key.token(&forged);
        assert_eq!(
            rejection_of(&auth, &token).await,
            Some(Rejection::MalformedClaims),
            "sub {subject:?} must be refused"
        );
        assert!(
            identity_of(&auth, &token).await.is_none(),
            "sub {subject:?} must never become an identity"
        );
    }

    // Groups: an array element and the single-string form are screened identically.
    for groups in [
        json!(["payments-team\nsystem:masters"]),
        json!(["ok-team", "payments-team\u{1b}[31m"]),
        json!("payments-team\nsystem:masters"),
    ] {
        let mut forged = claims();
        forged["groups"] = groups.clone();
        let token = key.token(&forged);
        assert_eq!(
            rejection_of(&auth, &token).await,
            Some(Rejection::MalformedClaims),
            "groups {groups}"
        );
        assert!(
            identity_of(&auth, &token).await.is_none(),
            "groups {groups} must never become an identity"
        );
    }

    // The screen runs **before** the length filter: a control character inside an oversized group
    // is refused rather than silently dropped along with the group.
    let mut oversized = claims();
    oversized["groups"] = json!([format!("{}\n{}", "a".repeat(MAX_GROUP_CHARS + 1), "b")]);
    assert_eq!(
        rejection_of(&auth, &key.token(&oversized)).await,
        Some(Rejection::MalformedClaims)
    );

    // Finding `N1`: the single-string shape enforces the **same length budget** as the array shape.
    // The boundary length is an ordinary group; one character more is filtered to "no groups" (like
    // an over-long array element) rather than truncated into a group that silently lost its tail.
    let at_limit = "g".repeat(MAX_GROUP_CHARS);
    let mut boundary = claims();
    boundary["groups"] = json!(at_limit);
    let identity = identity_of(&auth, &key.token(&boundary))
        .await
        .expect("a `MAX_GROUP_CHARS`-long single group is an identity");
    assert_eq!(
        identity.groups,
        vec![format!("oidc:{at_limit}")],
        "the boundary-length single group is mapped, not dropped"
    );

    let mut over_limit = claims();
    over_limit["groups"] = json!("g".repeat(MAX_GROUP_CHARS + 1));
    let identity = identity_of(&auth, &key.token(&over_limit))
        .await
        .expect("an over-long single group filters the claim, it does not refuse the token");
    assert!(
        identity.groups.is_empty(),
        "an over-long single group is dropped exactly like an over-long array element: {:?}",
        identity.groups
    );

    // The refusal reason is a constant: it can carry no claim value and no control character.
    let reason = Rejection::MalformedClaims.as_str();
    assert!(reason.chars().all(|character| !character.is_control()));
    assert!(!reason.contains("payments-team") && !reason.contains("alice"));

    // And an ordinary identity still works: the screen rejects control characters, not Unicode.
    let mut unicode = claims();
    unicode["sub"] = json!("älice-123");
    assert!(
        identity_of(&auth, &key.token(&unicode)).await.is_some(),
        "a non-ASCII subject is an identity, not an injection"
    );
}

/// **`T19.1` findings `N1a`/`N1b`:** the two group budgets are enforced on the claim and the
/// result is bounded — never silently larger, and never silently smaller than the claim allows.
///
/// An over-long group is dropped (findings `N1`, `N1a`; the drop is counted in a debug log) while
/// its ordinary siblings survive, and a claim carrying more groups than [`MAX_CLAIMED_GROUPS`] is
/// truncated to exactly that many. Both bounds are asserted here because both are what an
/// authorization decision is made against: a token cannot widen its own reach by padding its group
/// list, and a stray over-long entry cannot narrow it to nothing.
#[tokio::test]
async fn a_group_claim_over_the_count_cap_is_truncated_to_the_cap() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let auth = authenticator(&source);

    // `N1b`: one more group than the cap truncates to the cap, and the surviving groups are the
    // *first* ones in claim order (so the truncation is deterministic, not arbitrary). The names
    // are deliberately short: a JOSE segment is capped at 4096 characters, so a realistic-length
    // 257-group claim is refused as "not a JWT" before the group budget is ever consulted — the
    // budget pinned here is the one a *decodable* claim hits.
    let over_cap: Vec<String> = (0..=MAX_CLAIMED_GROUPS)
        .map(|index| format!("g{index:03}"))
        .collect();
    assert_eq!(over_cap.len(), MAX_CLAIMED_GROUPS + 1);
    let mut flooded = claims();
    flooded["groups"] = json!(over_cap);
    let identity = identity_of(&auth, &key.token(&flooded))
        .await
        .expect("an over-large group list is truncated, it does not refuse the token");
    assert_eq!(
        identity.groups.len(),
        MAX_CLAIMED_GROUPS,
        "257 groups must truncate to `MAX_CLAIMED_GROUPS`, not pass through"
    );
    assert_eq!(
        identity.groups.first().map(String::as_str),
        Some("oidc:g000")
    );
    let last_kept = format!("oidc:g{:03}", MAX_CLAIMED_GROUPS - 1);
    assert_eq!(
        identity.groups.last().map(String::as_str),
        Some(last_kept.as_str()),
        "the tail — the group past the cap — is the one dropped"
    );
    assert!(
        !identity.groups.iter().any(|group| group == "oidc:g256"),
        "the 257th group is the one the cap drops: {:?}",
        identity.groups.last()
    );

    // `N1a`: an over-long *element* is dropped on its own; the rest of the array is still an
    // identity, so the drop is a budget on one entry and not on the claim.
    let mut mixed = claims();
    mixed["groups"] = json!(["keep-one", "g".repeat(MAX_GROUP_CHARS + 1), "keep-two",]);
    let identity = identity_of(&auth, &key.token(&mixed))
        .await
        .expect("one over-long group does not refuse the token");
    assert_eq!(
        identity.groups,
        vec!["oidc:keep-one".to_owned(), "oidc:keep-two".to_owned()],
        "only the over-long group is dropped"
    );
}

// ---------------------------------------------------------------------------
// The composite authenticator: ordering and fallback
// ---------------------------------------------------------------------------

/// A `TokenReview` stand-in that records how many tokens reached Kubernetes.
#[derive(Default)]
struct FakeTokenReview {
    reviews: Mutex<Vec<String>>,
}

impl FakeTokenReview {
    fn reviews(&self) -> usize {
        self.reviews.lock().expect("test state").len()
    }
}

impl TokenAuthenticator for FakeTokenReview {
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
        self.reviews
            .lock()
            .expect("test state")
            .push(token.to_owned());
        let identity = (token == "sa-token").then(|| {
            AuthenticatedIdentity::new(
                "system:serviceaccount:ferriscd-system:ci",
                vec!["ci-deployers".to_owned()],
            )
        });
        Box::pin(async move { Ok(identity) })
    }
}

/// **Verification bullet 5 and the `T19.1` risk note:** the composite accepts both a valid OIDC JWT and
/// a valid `TokenReview` token, consults OIDC first, and **never** forwards a token that claims to be
/// ours to the API server — so malformed OIDC tokens cannot be turned into etcd writes.
#[tokio::test]
async fn the_composite_authenticator_only_falls_back_for_foreign_credentials() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let oidc = Arc::new(authenticator(&source));
    let reviews = Arc::new(FakeTokenReview::default());
    let composite = CompositeTokenAuthenticator::new(Arc::clone(&oidc), reviews.clone());

    // 1. A valid OIDC JWT is accepted locally: zero TokenReview calls.
    let identity = composite
        .authenticate(&key.token(&claims()))
        .await
        .expect("no backend failure")
        .expect("the OIDC token is accepted");
    assert_eq!(identity.username.as_deref(), Some("oidc:alice-123"));
    assert_eq!(reviews.reviews(), 0);

    // 2. An opaque `ServiceAccount` token is not a JWT: it falls through and is reviewed.
    let identity = composite
        .authenticate("sa-token")
        .await
        .expect("no backend failure")
        .expect("the SA token is accepted");
    assert_eq!(
        identity.username.as_deref(),
        Some("system:serviceaccount:ferriscd-system:ci")
    );
    assert_eq!(reviews.reviews(), 1);

    // 3. A Kubernetes token that *is* a JWT carries a different issuer, so it also falls through.
    let mut foreign = claims();
    foreign["iss"] = json!("https://kubernetes.default.svc");
    let foreign_token = key.token(&foreign);
    assert!(
        composite
            .authenticate(&foreign_token)
            .await
            .expect("ok")
            .is_none()
    );
    assert_eq!(reviews.reviews(), 2, "a foreign issuer is reviewed");

    // 4. **The trap:** a token carrying *our* issuer with a bad signature, an unsupported `alg` or an
    //    expired `exp` is refused outright — no TokenReview, no cluster write.
    let mut escalated = claims();
    escalated["groups"] = json!(["platform-admins"]);
    let bad_signature = substitute_claims(&key.token(&claims()), &escalated);
    let mut expired = claims();
    expired["exp"] = json!(NOW - 3600);
    let unsigned_header = base64url(br#"{"alg":"none","typ":"JWT"}"#);
    let unsigned = format!(
        "{unsigned_header}.{}.{}",
        base64url(&serde_json::to_vec(&claims()).expect("json")),
        ""
    );
    for token in [bad_signature, key.token(&expired), unsigned] {
        assert!(
            composite.authenticate(&token).await.expect("ok").is_none(),
            "an OIDC credential of ours must never fall through"
        );
    }
    assert_eq!(
        reviews.reviews(),
        2,
        "no malformed OIDC token may cost a TokenReview"
    );
}

/// The composite preserves the credential's own expiry, so the cache clamp survives the extra layer.
#[tokio::test]
async fn the_composite_preserves_the_credential_ttl() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let oidc = Arc::new(authenticator(&source));
    let composite = CompositeTokenAuthenticator::new(oidc, Arc::new(FakeTokenReview::default()));
    let credential = composite
        .authenticate_credential(&key.token(&claims()))
        .await
        .expect("no backend failure")
        .expect("accepted");
    assert_eq!(credential.ttl, Some(Duration::from_secs(300)));

    let reviewed = composite
        .authenticate_credential("sa-token")
        .await
        .expect("no backend failure")
        .expect("accepted");
    assert_eq!(reviewed.ttl, None, "a TokenReview carries no expiry");
}

// ---------------------------------------------------------------------------
// The JWKS document and the discovery document
// ---------------------------------------------------------------------------

/// **Trap guard (key material):** symmetric keys, encryption keys, keys pinned to an algorithm this
/// server refuses and malformed coordinates never enter the key set — a document with nothing usable
/// is an error, not an empty cache that rejects everybody silently.
#[test]
fn the_key_set_is_filtered_to_usable_asymmetric_signing_keys() {
    let document = json!({
        "keys": [
            // The symmetric half of a key-confusion attack.
            {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"},
            // An encryption key.
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": TEST_RSA_MODULUS_BASE64URL, "e": "AQAB"},
            // A key pinned to an algorithm outside the allow-list.
            {"kty": "RSA", "kid": "ps", "alg": "PS256", "n": TEST_RSA_MODULUS_BASE64URL, "e": "AQAB"},
            // A key that only signs (never verifies) is not a candidate either.
            {"kty": "RSA", "kid": "sign-only", "key_ops": ["sign"], "n": TEST_RSA_MODULUS_BASE64URL, "e": "AQAB"},
            // Truncated coordinates.
            {"kty": "EC", "kid": "short", "crv": "P-256", "x": "AA", "y": "AA"},
            // An unknown curve.
            {"kty": "EC", "kid": "curve", "crv": "secp256k1", "x": "AA", "y": "AA"},
            // The one usable key.
            {"kty": "RSA", "kid": "ok", "alg": "RS256", "use": "sig", "n": TEST_RSA_MODULUS_BASE64URL, "e": "AQAB"},
        ]
    });
    let set = JwkSet::parse_json(&serde_json::to_vec(&document).expect("json"))
        .expect("the document holds one usable key");
    assert_eq!(set.len(), 1);
    assert_eq!(set.keys()[0].kid.as_deref(), Some("ok"));
    assert!(set.has_candidate(Some("ok"), JoseAlgorithm::Rs256));
    assert!(!set.has_candidate(Some("hmac"), JoseAlgorithm::Rs256));
    // The u64 exponent is not a key.
    assert!(!set.has_candidate(None, JoseAlgorithm::Es256));

    assert_eq!(
        JwkSet::parse_json(br#"{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}"#).err(),
        Some(OidcError::NoUsableKeys),
        "a document with no usable key must fail loudly"
    );
    assert_eq!(
        JwkSet::parse_json(br#"{"keys":[]}"#).err(),
        Some(OidcError::NoUsableKeys)
    );
    assert!(matches!(
        JwkSet::parse_json(b"not a JWKS"),
        Err(OidcError::InvalidJwks(_))
    ));
}

/// **Finding (nit):** the key budget is spent on **usable** keys, not on raw document entries.
///
/// A JWKS legitimately carries encryption keys and symmetric secrets, and an IdP is free to publish
/// them first. Taking the first `MAX_JWKS_KEYS` entries verbatim would let a document with 64
/// encryption keys ahead of the signing key fail with `NoUsableKeys` — a valid deployment refusing
/// every login. The cap is still a cap: it bounds how many keys one authenticated request walks.
#[test]
fn the_key_budget_counts_usable_keys_not_raw_entries() {
    let mut document = Vec::new();
    for index in 0..(MAX_JWKS_KEYS + 2) {
        document.push(json!({"kty": "oct", "kid": format!("hmac-{index}"), "k": "c2VjcmV0"}));
    }
    document.push(json!({
        "kty": "RSA",
        "kid": "signing",
        "alg": "RS256",
        "use": "sig",
        "n": TEST_RSA_MODULUS_BASE64URL,
        "e": "AQAB",
    }));
    let set = JwkSet::parse_json(&serde_json::to_vec(&json!({"keys": document})).expect("json"))
        .expect("the signing key is still found behind the unusable entries");
    assert_eq!(set.len(), 1);
    assert!(set.has_candidate(Some("signing"), JoseAlgorithm::Rs256));

    // And the budget still truncates: 72 usable keys contribute at most `MAX_JWKS_KEYS`.
    let mut many = Vec::new();
    for index in 0..(MAX_JWKS_KEYS + 8) {
        many.push(json!({
            "kty": "RSA",
            "kid": format!("rsa-{index}"),
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_MODULUS_BASE64URL,
            "e": "AQAB",
        }));
    }
    let set = JwkSet::parse_json(&serde_json::to_vec(&json!({"keys": many})).expect("json"))
        .expect("a usable key set");
    assert_eq!(
        set.len(),
        MAX_JWKS_KEYS,
        "the cap bounds how many keys one request can be made to walk"
    );
}

/// **Trap guard (discovery):** the document must describe *our* issuer, and `jwks_uri` must be HTTPS,
/// credential-free and fragment-free — otherwise a hostile (or compromised) discovery document would
/// redirect key fetching to an attacker's host.
#[test]
fn the_discovery_document_is_validated() {
    let document = |issuer: &str, jwks_uri: &str| {
        serde_json::to_vec(&json!({"issuer": issuer, "jwks_uri": jwks_uri})).expect("json")
    };
    let valid = validate_discovery(
        &document(ISSUER, "https://idp.example.com/keys"),
        ISSUER,
        false,
    )
    .expect("a well-formed document");
    assert_eq!(valid.issuer, ISSUER);
    assert_eq!(valid.jwks_uri, "https://idp.example.com/keys");

    let rejected = |document: &[u8]| match validate_discovery(document, ISSUER, false) {
        Err(OidcError::InvalidDiscovery(reason)) => reason,
        other => panic!("expected an invalid discovery document, got {other:?}"),
    };
    assert!(
        rejected(&document(
            "https://evil.example.com",
            "https://idp.example.com/keys"
        ))
        .contains("does not match the configured issuer")
    );
    assert!(
        rejected(&document(ISSUER, "http://idp.example.com/keys")).contains("must be an https URL")
    );
    assert!(
        rejected(&document(ISSUER, "https://user:pass@idp.example.com/keys"))
            .contains("credentials")
    );
    assert!(rejected(&document(ISSUER, "https://idp.example.com/keys#frag")).contains("fragment"));
    assert!(rejected(br#"{"issuer":"https://idp.example.com"}"#).contains("`jwks_uri`"));
    assert!(rejected(b"{}").contains("`issuer`"));

    // A plain-http `jwks_uri` is tolerated only with the local-development flag.
    assert!(
        validate_discovery(&document(ISSUER, "http://dex:5556/keys"), ISSUER, true).is_ok(),
        "the development flag covers a local IdP"
    );
}

/// The production source builds one bounded client, refuses a CA bundle that is not a certificate, and
/// exposes its issuer (never a secret).
#[test]
fn the_production_key_source_is_bounded_and_validates_its_ca() {
    ferriscd_controller::impersonation::ensure_crypto_provider();
    let invalid = OidcConfig::new(ISSUER, CLIENT_ID)
        .with_ca_pem(Some(b"not a certificate".to_vec()))
        .validate()
        .expect("the configuration is otherwise valid");
    assert_eq!(
        HttpsJwksSource::new(&invalid).err(),
        Some(OidcConfigError::InvalidCa)
    );

    // An empty bundle is not "no bundle": it is a misconfiguration and is refused.
    let empty = OidcConfig::new(ISSUER, CLIENT_ID)
        .with_ca_pem(Some(Vec::new()))
        .validate()
        .expect("the configuration is otherwise valid");
    assert_eq!(
        HttpsJwksSource::new(&empty).err(),
        Some(OidcConfigError::InvalidCa)
    );

    let source = HttpsJwksSource::new(&config().validate().expect("valid"))
        .expect("the default client builds");
    assert_eq!(source.issuer(), ISSUER);
    assert!(
        !format!("{source:?}").contains("BEGIN"),
        "a source never renders its CA bundle"
    );
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// **Non-functional:** neither the token nor the CA bundle is printable. `Debug` is what a log line,
/// a panic message or a `dbg!` renders, and the API process holds a live credential per request.
#[tokio::test]
async fn neither_the_token_nor_the_ca_bundle_is_ever_rendered() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);
    let config = config().with_ca_pem(Some(b"-----BEGIN CERTIFICATE-----\nsecret\n".to_vec()));
    let auth = authenticator_at(&source, config, NOW);
    let token = key.token(&claims());
    assert!(identity_of(&auth, &token).await.is_some());

    let rendered = format!("{auth:?} {:?} {:?}", auth.keys(), auth.config());
    assert!(!rendered.contains(&token), "{rendered}");
    assert!(!rendered.contains("secret"), "{rendered}");
    assert!(
        !rendered.contains(&fingerprint_label(&token_fingerprint(&token))),
        "the state renders no request-derived handle either: {rendered}"
    );
    // The configuration still names what an operator needs to debug a failed login.
    assert!(rendered.contains(ISSUER), "{rendered}");

    // The only handle a log line may carry for a token is its 12-hex fingerprint.
    let label = fingerprint_label(&token_fingerprint(&token));
    assert_eq!(label.len(), 12);
    assert!(!token.contains(&label));
}

// ---------------------------------------------------------------------------
// The router: `GET /api/v1/auth/config` and 200/401 through the real middleware
// ---------------------------------------------------------------------------

fn application() -> Application {
    let spec: ferriscd_crd::ApplicationSpec = serde_json::from_value(json!({
        "project": "payments",
        "source": {"git": {"repoURL": "https://github.com/example/payments.git", "path": "deploy"}},
        "destination": {"cluster": "in-cluster", "namespace": "payments"},
    }))
    .expect("a valid ApplicationSpec");
    let mut application = Application::new("payments-api", spec);
    application.metadata.namespace = Some("ferriscd-system".to_owned());
    application
}

struct OneApplication;

impl ApplicationSource for OneApplication {
    fn list(&self) -> SeamFuture<'_, Vec<Application>> {
        Box::pin(async { Ok(vec![application()]) })
    }

    fn get(&self, _namespace: &str, _name: &str) -> SeamFuture<'_, Option<Application>> {
        Box::pin(async { Ok(Some(application())) })
    }
}

/// The policy an operator publishes to authorize the IdP's `payments-team` group.
fn policy() -> Arc<RbacPolicy> {
    Arc::new(
        RbacPolicy::parse(
            r#"
rules:
  - subject: {kind: group, name: "oidc:payments-team"}
    project: payments
    actions: [get, diff, sync]
"#,
        )
        .expect("the documented policy parses"),
    )
}

fn oidc_state(auth: OidcTokenAuthenticator) -> AppState {
    use crate::state::ServingReadiness;
    use crate::tests_support::{
        EmptyDiff, NoClusters, NoGraph, NoInventory, NoOperations, NoProjects,
    };

    // `AppState::new` is the seam every handler reads; the OIDC authenticator and the RBAC policy are
    // the real ones, so a request exercises the whole chain: parse, verify, cache, RBAC, handler.
    AppState::new(
        Arc::new(OneApplication),
        Arc::new(NoProjects),
        Arc::new(NoClusters),
        Arc::new(NoOperations),
        Arc::new(NoInventory),
        Arc::new(NoGraph),
        Arc::new(EmptyDiff),
        Arc::new(ServingReadiness),
    )
    .with_auth(AuthPolicy::Oidc)
    // Boxed into the seam exactly as the binary does it.
    .with_token_authenticator(Arc::new(auth))
    .with_rbac(policy())
    .with_auth_config(PublicAuthConfig::oidc(
        ISSUER,
        CLIENT_ID,
        vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ],
    ))
}

async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = crate::api::router(state)
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, body)
}

async fn get(state: AppState, path: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("a request");
    if let Some(token) = token {
        request = Request::builder()
            .method("GET")
            .uri(path)
            .header(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).expect("a header value"),
            )
            .body(Body::empty())
            .expect("a request");
    }
    send(state, request).await
}

/// **Verification bullet 1, end to end:** the real router accepts a valid OIDC token, resolves the
/// prefixed identity, and the RBAC policy (unchanged, no OIDC awareness) authorizes the project — while
/// every rejected token is a `401` that never echoes the credential.
#[tokio::test]
async fn a_valid_oidc_token_reaches_the_handler_and_every_rejection_is_a_401() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);

    let (status, body) = get(
        oidc_state(authenticator(&source)),
        "/api/v1/applications",
        Some(&key.token(&claims())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["items"][0]["name"], "payments-api",
        "the OIDC identity's prefixed group authorizes the payments project: {body}"
    );

    // A token whose groups are not granted sees nothing — the filter is the authorization.
    let mut unprivileged = claims();
    unprivileged["groups"] = json!(["some-other-team"]);
    let (status, body) = get(
        oidc_state(authenticator(&source)),
        "/api/v1/applications",
        Some(&key.token(&unprivileged)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], json!([]), "{body}");

    // `T19.1` verification bullet 2: every bad token is a `401` with the standard challenge, and the
    // refusal never carries the credential.
    let mut expired = claims();
    expired["exp"] = json!(NOW - 3600);
    let mut wrong_audience = claims();
    wrong_audience["aud"] = json!("another-client");
    let mut escalated = claims();
    escalated["groups"] = json!(["platform-admins"]);
    let bad_signature = substitute_claims(&key.token(&claims()), &escalated);
    let unsigned = format!(
        "{}.{}.",
        base64url(br#"{"alg":"none","typ":"JWT"}"#),
        base64url(&serde_json::to_vec(&claims()).expect("json"))
    );
    for token in [
        key.token(&expired),
        key.token(&wrong_audience),
        bad_signature,
        unsigned,
        "not-a-jwt".to_owned(),
    ] {
        let (status, body) = get(
            oidc_state(authenticator(&source)),
            "/api/v1/applications",
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token}");
        assert_eq!(body["error"]["code"], "Unauthorized");
        assert!(
            !body.to_string().contains(&token),
            "the refusal must never echo the credential: {body}"
        );
    }

    // No credential at all is the same `401` (and the same shape as a bad one).
    let (status, body) = get(
        oidc_state(authenticator(&source)),
        "/api/v1/applications",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "Unauthorized");

    // `--auth-policy oidc` refuses a `ServiceAccount`-style opaque token: no fallback is wired.
    let (status, _) = get(
        oidc_state(authenticator(&source)),
        "/api/v1/applications",
        Some("sa-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// **`GET /api/v1/auth/config`** is public, publishes the sign-in mode plus the *public* OIDC facts, and
/// never a secret — and it answers identically whether or not the caller presents a token.
#[tokio::test]
async fn the_auth_config_endpoint_is_public_and_carries_no_secret() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);

    let (status, body) = get(
        oidc_state(authenticator(&source)),
        "/api/v1/auth/config",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["authMode"], "oidc");
    assert_eq!(body["issuer"], ISSUER);
    assert_eq!(body["clientId"], CLIENT_ID);
    assert_eq!(body["scopes"], json!(["openid", "profile", "email"]));
    assert_eq!(body["bffEnabled"], false, "the BFF flow lands in T19.2");

    // A bogus token changes nothing: the endpoint is not behind the auth layer.
    let (status, same) = get(
        oidc_state(authenticator(&source)),
        "/api/v1/auth/config",
        Some("garbage"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(same, body);

    // A `token-review` deployment publishes its mode and no OIDC facts at all.
    let token_review_state = crate::tests_support::state(Arc::new(crate::state::ServingReadiness))
        .with_auth(AuthPolicy::TokenReview);
    let (status, body) = get(token_review_state, "/api/v1/auth/config", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authMode"], "token-review");
    assert_eq!(body["bffEnabled"], false);
    // Finding `N4`: the contract says `issuer`/`clientId` are **absent** when OIDC is off (never
    // `null`, which is what the published schema used to promise) while `scopes` is **always**
    // present — required in the schema, and published as `[]` rather than omitted here.
    assert!(
        body.get("issuer").is_none() && body.get("clientId").is_none(),
        "no OIDC facts are invented when OIDC is off, and they are absent rather than null: {body}"
    );
    assert_eq!(
        body["scopes"],
        json!([]),
        "`scopes` is always serialized (the schema marks it required): {body}"
    );

    // The documented policy spellings, including the new ones, are what `authMode` reports.
    for (policy, expected) in [
        (AuthPolicy::Oidc, "oidc"),
        (AuthPolicy::TokenReviewOrOidc, "token-review-or-oidc"),
        (AuthPolicy::TokenReview, "token-review"),
        (AuthPolicy::DenyAll, "deny-all"),
        (AuthPolicy::PassThrough, "pass-through"),
    ] {
        assert_eq!(policy.as_str(), expected);
        assert_eq!(expected.parse::<crate::auth::AuthPolicy>(), Ok(policy));
    }
}

/// **`T19.1` finding `N4a`:** an OIDC policy and the public OIDC facts are one decision, so a
/// half-built `AppState` is detectable instead of publishing a sign-in mode that cannot work.
///
/// The binary refuses to start without `--oidc-issuer`/`--oidc-client-id`, so only a library
/// embedder can build the broken pair; the discovery handler `debug_assert!`s
/// [`AppState::auth_config_matches_policy`], and this test pins the predicate the assertion reads.
#[tokio::test]
async fn an_oidc_policy_requires_the_public_auth_config_it_publishes() {
    let key = TestKey::rsa("rsa-1");
    let source = FakeSource::new(vec![key.key_set()]);

    assert!(
        oidc_state(authenticator(&source)).auth_config_matches_policy(),
        "the binary's pairing (`with_auth` + `with_auth_config`) is complete"
    );

    // The builder mistake: `authMode: "oidc"` with no issuer and no client id.
    for policy in [AuthPolicy::Oidc, AuthPolicy::TokenReviewOrOidc] {
        let unpaired =
            crate::tests_support::state(Arc::new(crate::state::ServingReadiness)).with_auth(policy);
        assert!(
            !unpaired.auth_config_matches_policy(),
            "{policy:?} without `with_auth_config` would publish an unusable sign-in mode"
        );
    }

    // Every policy that authenticates nobody through OIDC needs no OIDC facts, and neither does an
    // OIDC policy that carries only half of them.
    for policy in [
        AuthPolicy::TokenReview,
        AuthPolicy::PassThrough,
        AuthPolicy::DenyAll,
    ] {
        let state =
            crate::tests_support::state(Arc::new(crate::state::ServingReadiness)).with_auth(policy);
        assert!(
            state.auth_config_matches_policy(),
            "{policy:?} publishes no OIDC sign-in mode, so nothing is missing"
        );
    }
    let half = crate::tests_support::state(Arc::new(crate::state::ServingReadiness))
        .with_auth(AuthPolicy::Oidc)
        .with_auth_config(PublicAuthConfig {
            issuer: Some(ISSUER.to_owned()),
            client_id: None,
            scopes: Vec::new(),
            bff_enabled: false,
        });
    assert!(
        !half.auth_config_matches_policy(),
        "an issuer without a client id is still a sign-in flow no client can start"
    );

    // And the endpoint the invariant protects still answers with the paired configuration.
    let (status, body) = get(
        oidc_state(authenticator(&source)),
        "/api/v1/auth/config",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["authMode"], "oidc");
    assert_eq!(body["issuer"], ISSUER);
}

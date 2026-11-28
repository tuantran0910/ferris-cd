//! Hermetic tests for the optional BFF session flow (`T19.2`).
//!
//! No network: the IdP is a fake [`OidcSession`], the router is driven with
//! `tower::ServiceExt::oneshot`, and every assertion is about bytes on the wire or state in memory.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use axum::http::{HeaderMap, Request as HttpRequest, StatusCode};
use futures::future::BoxFuture;
use tower::ServiceExt as _;

use super::*;
use crate::auth::{AuthenticatedIdentity, TokenAuthenticator};
use crate::state::{AppState, SeamFuture};

// ---------------------------------------------------------------------------
// A fake IdP
// ---------------------------------------------------------------------------

/// Records every exchange and returns a canned token.
#[derive(Debug, Default)]
struct FakeIdp {
    exchanges: AtomicUsize,
    seen: Mutex<Vec<CodeExchangeRequest>>,
    fail: AtomicUsize,
}

impl FakeIdp {
    fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }

    fn last_request(&self) -> Option<CodeExchangeRequest> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .cloned()
    }

    fn fail_next(&self) {
        self.fail.store(1, Ordering::SeqCst);
    }
}

impl OidcSession for FakeIdp {
    fn authorization_endpoint(&self) -> BoxFuture<'_, Result<String, BffError>> {
        Box::pin(async { Ok("https://idp.example.com/oauth2/authorize".to_owned()) })
    }

    fn exchange(
        &self,
        request: CodeExchangeRequest,
    ) -> BoxFuture<'_, Result<ExchangedTokens, BffError>> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
        let fail = self.fail.swap(0, Ordering::SeqCst) == 1;
        Box::pin(async move {
            if fail {
                return Err(BffError::Exchange { status: 400 });
            }
            Ok(ExchangedTokens {
                access_token: "idp-access-token-value".to_owned(),
                expires_in: Some(Duration::from_secs(600)),
            })
        })
    }
}

/// Accepts exactly one token and maps it into an identity.
#[derive(Debug, Default)]
struct FakeAuthenticator {
    calls: AtomicUsize,
    reject: bool,
}

impl TokenAuthenticator for FakeAuthenticator {
    fn authenticate(&self, _credential: &str) -> SeamFuture<'_, Option<AuthenticatedIdentity>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let accepted = !self.reject;
        Box::pin(async move {
            Ok(accepted.then(|| AuthenticatedIdentity::new("oidc:alice", Vec::new())))
        })
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const TEST_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

fn bff_config() -> BffConfig {
    BffConfig::new("https://idp.example.com", "ferriscd-web")
        .with_redirect_uri("https://ferriscd.example.com/api/v1/auth/callback")
        .with_session_key(
            SessionKey::from_bytes(TEST_KEY).expect("a 32-byte session key is accepted"),
        )
}

fn bff_state(config: BffConfig) -> Arc<BffState> {
    Arc::new(
        BffState::new(config, Arc::new(FakeIdp::default()))
            .expect("the test configuration is valid"),
    )
}

/// A state with the BFF flow enabled and a permissive authenticator.
fn state_with_bff(bff: Arc<BffState>) -> AppState {
    crate::tests_support::state(Arc::new(crate::state::ServingReadiness))
        .with_auth(crate::auth::AuthPolicy::Oidc)
        .with_token_authenticator(Arc::new(FakeAuthenticator::default()))
        .with_bff(bff)
}

/// The `Set-Cookie` values a response carries, as `name=value` pairs and as full header values.
fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect()
}

/// Every `Set-Cookie` value whose name is `name`.
fn cookies_starting_with(headers: &HeaderMap, name: &str) -> Vec<String> {
    set_cookies(headers)
        .into_iter()
        .filter(|cookie| cookie.starts_with(&format!("{name}=")))
        .collect()
}

/// The `name=value` pair of the first `Set-Cookie` for `name`.
fn cookie_pair(headers: &HeaderMap, name: &str) -> Option<String> {
    set_cookies(headers)
        .into_iter()
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
        .and_then(|cookie| cookie.split(';').next().map(str::to_owned))
}

/// Sends one HTTP request from `peer` (so the per-client sign-in budget has a real address).
async fn send_from(
    state: AppState,
    peer: SocketAddr,
    mut request: HttpRequest<Body>,
) -> (StatusCode, HeaderMap, String) {
    request.extensions_mut().insert(ConnectInfo(peer));
    send(state, request).await
}

async fn send(state: AppState, request: HttpRequest<Body>) -> (StatusCode, HeaderMap, String) {
    let response = crate::api::router(state)
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a bounded body");
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn get(uri: &str) -> HttpRequest<Body> {
    HttpRequest::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("a valid request")
}

fn post_with_cookies(uri: &str, cookies: &[&str], csrf: Option<&str>) -> HttpRequest<Body> {
    let mut builder = HttpRequest::builder().method("POST").uri(uri);
    if !cookies.is_empty() {
        builder = builder.header(header::COOKIE, cookies.join("; "));
    }
    if let Some(csrf) = csrf {
        builder = builder.header(CSRF_HEADER, csrf);
    }
    builder.body(Body::empty()).expect("a valid request")
}

/// The `Location` of a login redirect (the IdP's authorization URL).
fn start_login(response_headers: &HeaderMap) -> String {
    let location = response_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("a redirect");
    location.to_owned()
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

/// The RFC 7636 appendix B vector: `S256` is SHA-256, base64url, unpadded.
#[test]
fn the_s256_challenge_matches_the_rfc_7636_test_vector() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        s256_challenge(verifier),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert_eq!(
        PkcePair::from_verifier(verifier).challenge,
        s256_challenge(verifier)
    );
}

#[test]
fn generated_verifiers_carry_256_bits_and_are_unique() {
    let first = PkcePair::generate().expect("randomness");
    let second = PkcePair::generate().expect("randomness");
    assert_eq!(first.verifier.len(), 43, "32 bytes base64url, unpadded");
    assert!(
        first
            .verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    );
    assert_ne!(first.verifier, second.verifier);
    assert_ne!(first.verifier, first.challenge);
    assert_eq!(first.challenge, s256_challenge(&first.verifier));

    let state = random_urlsafe_token().expect("randomness");
    let nonce = random_urlsafe_token().expect("randomness");
    assert_eq!(state.len(), 43);
    assert_eq!(nonce.len(), 43);
    assert_ne!(state, nonce);
}

/// The verifier is a token-endpoint credential: `Debug` may not print it, nor may it print the state
/// secret material.
#[test]
fn the_pkce_pair_and_transaction_redact_their_secrets() {
    let pair = PkcePair::from_verifier("super-secret-verifier-value");
    let rendered = format!("{pair:?}");
    assert!(
        !rendered.contains("super-secret-verifier-value"),
        "{rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let transaction = PendingTransaction {
        state: "the-state".to_owned(),
        nonce: "the-nonce-value".to_owned(),
        code_verifier: "the-verifier-value".to_owned(),
        redirect_uri: "https://ferriscd.example.com/api/v1/auth/callback".to_owned(),
        created: Instant::now(),
    };
    let rendered = format!("{transaction:?}");
    assert!(!rendered.contains("the-verifier-value"), "{rendered}");
    assert!(!rendered.contains("the-nonce-value"), "{rendered}");

    let request = CodeExchangeRequest {
        code: "authorization-code-value".to_owned(),
        code_verifier: "the-verifier-value".to_owned(),
        redirect_uri: "https://ferriscd.example.com/api/v1/auth/callback".to_owned(),
    };
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("authorization-code-value"), "{rendered}");
    assert!(!rendered.contains("the-verifier-value"), "{rendered}");

    let tokens = ExchangedTokens {
        access_token: "idp-access-token".to_owned(),
        expires_in: None,
    };
    assert!(!format!("{tokens:?}").contains("idp-access-token"));
    assert!(
        !format!("{:?}", SessionKey::from_bytes(TEST_KEY).expect("a key")).contains("0123456789")
    );
}

// ---------------------------------------------------------------------------
// The authorize URL and the state machine
// ---------------------------------------------------------------------------

#[test]
fn the_authorize_url_carries_s256_and_the_exact_redirect_uri() {
    let url = authorize_url(
        "https://idp.example.com/oauth2/authorize",
        "ferriscd-web",
        "https://ferriscd.example.com/api/v1/auth/callback",
        &["openid".to_owned(), "email".to_owned()],
        "the-state",
        "the-nonce",
        "the-challenge",
    )
    .expect("a valid authorize URL");
    assert!(
        url.starts_with("https://idp.example.com/oauth2/authorize?"),
        "{url}"
    );
    assert!(url.contains("response_type=code"), "{url}");
    assert!(url.contains("code_challenge_method=S256"), "{url}");
    assert!(url.contains("code_challenge=the-challenge"), "{url}");
    assert!(url.contains("state=the-state"), "{url}");
    assert!(url.contains("nonce=the-nonce"), "{url}");
    assert!(url.contains("scope=openid+email"), "{url}");
    // Percent-encoded but otherwise byte-identical: the IdP compares it to the registered value.
    assert!(
        url.contains(
            "redirect_uri=https%3A%2F%2Fferriscd.example.com%2Fapi%2Fv1%2Fauth%2Fcallback"
        ),
        "{url}"
    );
    // `plain` is never offered.
    assert!(!url.contains("code_challenge_method=plain"), "{url}");
}

#[test]
fn a_pending_transaction_is_one_shot_and_expires() {
    let ttl = Duration::from_secs(60);
    let mut store = PendingTransactions::new(ttl, 4);
    let now = Instant::now();
    let transaction = PendingTransaction {
        state: "state-1".to_owned(),
        nonce: "nonce-1".to_owned(),
        code_verifier: "verifier-1".to_owned(),
        redirect_uri: "https://ferriscd.example.com/api/v1/auth/callback".to_owned(),
        created: now,
    };
    store.insert(transaction.clone(), now);
    assert_eq!(store.len(), 1);

    // A second callback with the same state finds nothing: the state was consumed.
    assert!(store.take("state-1", now).is_some());
    assert!(store.take("state-1", now).is_none());

    // An expired transaction is refused even though it is still stored.
    store.insert(transaction, now);
    assert!(
        store
            .take("state-1", now + ttl + Duration::from_secs(1))
            .is_none()
    );
    assert!(store.is_empty());
}

#[test]
fn the_pending_store_is_bounded_and_evicts_the_oldest() {
    let now = Instant::now();
    let mut store = PendingTransactions::new(Duration::from_secs(60), 2);
    for index in 0..3 {
        store.insert(
            PendingTransaction {
                state: format!("state-{index}"),
                nonce: "nonce".to_owned(),
                code_verifier: "verifier".to_owned(),
                redirect_uri: "https://ferriscd.example.com/api/v1/auth/callback".to_owned(),
                created: now,
            },
            now,
        );
    }
    assert_eq!(store.len(), 2, "the store never exceeds its capacity");
    assert!(
        store.take("state-0", now).is_none(),
        "the oldest was evicted"
    );
    assert!(store.take("state-2", now).is_some());
}

// ---------------------------------------------------------------------------
// The sealed session cookie
// ---------------------------------------------------------------------------

#[test]
fn a_sealed_session_round_trips_and_refuses_tampering_or_another_key() {
    let sealer =
        SessionSealer::new(&SessionKey::from_bytes(TEST_KEY).expect("a key")).expect("a sealer");
    let now = SystemTime::now();
    let session = Session {
        access_token: "the-access-token".to_owned(),
        csrf_token: "the-csrf-token".to_owned(),
        expires_at_unix: unix_seconds(now) + 600,
    };
    let sealed = sealer.seal(&session).expect("sealing works");
    assert!(
        !sealed.contains("the-access-token"),
        "the cookie is ciphertext"
    );
    let opened = sealer.open(&sealed, now).expect("the cookie opens");
    assert_eq!(opened, session);

    // A flipped bit fails the AEAD tag instead of decrypting to something else.
    let mut tampered: Vec<char> = sealed.chars().collect();
    let index = tampered.len() - 2;
    tampered[index] = if tampered[index] == 'A' { 'B' } else { 'A' };
    let tampered: String = tampered.into_iter().collect();
    assert!(sealer.open(&tampered, now).is_err());

    // A cookie sealed under another key is not a session on this server.
    let other = SessionSealer::new(
        &SessionKey::from_bytes(b"ffffffffffffffffffffffffffffffff").expect("a key"),
    )
    .expect("a sealer");
    assert!(other.open(&sealed, now).is_err());

    // Expiry is enforced on open, not left to the caller.
    assert!(
        sealer
            .open(&sealed, SystemTime::now() + Duration::from_secs(3600))
            .is_err()
    );
}

#[test]
fn session_keys_are_validated_and_never_printed() {
    assert_eq!(
        SessionKey::from_bytes(b"short").err(),
        Some(BffConfigError::SessionKeyTooShort)
    );
    assert_eq!(
        SessionKey::from_secret_material(b"   \n").err(),
        Some(BffConfigError::MissingSessionKey)
    );
    // A base64-encoded 32-byte key file is decoded, not truncated.
    let encoded = URL_SAFE_NO_PAD.encode(TEST_KEY);
    let decoded = SessionKey::from_secret_material(encoded.as_bytes()).expect("a key");
    assert!(!format!("{decoded:?}").contains("0123456789"));
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn the_bff_configuration_refuses_open_redirects_and_weak_keys() {
    let key = SessionKey::from_bytes(TEST_KEY).expect("a key");
    // The redirect URI must be the exact registered absolute URL.
    assert_eq!(
        BffConfig::new("https://idp.example.com", "client")
            .with_session_key(key.clone())
            .validate()
            .err(),
        Some(BffConfigError::EmptyRedirectUri)
    );
    assert_eq!(
        BffConfig::new("https://idp.example.com", "client")
            .with_redirect_uri("/api/v1/auth/callback")
            .with_session_key(key.clone())
            .validate()
            .err(),
        Some(BffConfigError::RedirectUriNotAbsolute)
    );
    assert_eq!(
        BffConfig::new("https://idp.example.com", "client")
            .with_redirect_uri("https://ferriscd.example.com/cb?next=https://evil.example")
            .with_session_key(key.clone())
            .validate()
            .err(),
        Some(BffConfigError::RedirectUriCarriesAmbiguity)
    );
    assert_eq!(
        BffConfig::new("https://idp.example.com", "client")
            .with_redirect_uri("http://ferriscd.example.com/cb")
            .with_session_key(key.clone())
            .validate()
            .err(),
        Some(BffConfigError::RedirectUriNotLoopback)
    );
    // A missing key is refused, never defaulted.
    assert_eq!(
        BffConfig::new("https://idp.example.com", "client")
            .with_redirect_uri("https://ferriscd.example.com/cb")
            .validate()
            .err(),
        Some(BffConfigError::MissingSessionKey)
    );
    // A protocol-relative post-login path would be an open redirect.
    assert_eq!(
        BffConfig::new("https://idp.example.com", "client")
            .with_redirect_uri("https://ferriscd.example.com/cb")
            .with_session_key(key.clone())
            .with_post_login_path("//evil.example")
            .validate()
            .err(),
        Some(BffConfigError::InvalidPostLoginPath)
    );
    assert_eq!(
        BffConfig::new("http://idp.example.com", "client")
            .with_redirect_uri("https://ferriscd.example.com/cb")
            .with_session_key(key.clone())
            .validate()
            .err(),
        Some(BffConfigError::InsecureIssuer)
    );
    // A loopback http redirect URI is the documented local-development case.
    assert!(
        BffConfig::new("https://idp.example.com", "client")
            .with_redirect_uri("http://127.0.0.1:8080/api/v1/auth/callback")
            .with_session_key(key)
            .validate()
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// HTTP: the flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_redirects_to_the_idp_with_pkce_and_refuses_an_unregistered_redirect_uri() {
    let state = state_with_bff(bff_state(bff_config()));
    let (status, headers, _) = send(state.clone(), get("/api/v1/auth/login")).await;
    assert_eq!(status, StatusCode::FOUND);
    let location = start_login(&headers);
    assert!(
        location.contains("code_challenge_method=S256"),
        "{location}"
    );
    assert!(location.contains("state="), "{location}");
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    // An attacker-supplied redirect_uri is refused before anything leaves the process.
    let (status, _, body) = send(
        state,
        get("/api/v1/auth/login?redirect_uri=https%3A%2F%2Fevil.example%2Fsteal"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("not registered"), "{body}");
    assert!(
        !body.contains("evil.example"),
        "the value is not reflected: {body}"
    );
}

#[tokio::test]
async fn the_bff_routes_answer_404_when_the_flow_is_disabled() {
    let state = crate::tests_support::state(Arc::new(crate::state::ServingReadiness));
    for request in [
        get("/api/v1/auth/login"),
        get("/api/v1/auth/callback?code=c&state=s"),
        post_with_cookies("/api/v1/auth/logout", &[], None),
    ] {
        let (status, _, _) = send(state.clone(), request).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

/// **`T19.2` finding `H1` (login CSRF / account swap).**
///
/// The `state` alone is not enough to complete a sign-in: it must be the one *this browser* was given,
/// i.e. the query parameter has to equal the `HttpOnly` state cookie that `/api/v1/auth/login` set.
/// A correct `state` presented **without** the cookie is answered `400`, issues no cookie at all and
/// never reaches the token endpoint — which is exactly what an attacker relies on when they hand a
/// victim the callback URL of a sign-in *they* started.
#[tokio::test]
async fn a_correct_state_without_the_state_cookie_is_refused_without_an_exchange() {
    let idp = Arc::new(FakeIdp::default());
    let bff = Arc::new(BffState::new(bff_config(), idp.clone()).expect("a valid configuration"));
    let state = state_with_bff(bff);

    let (status, headers, _) = send(state.clone(), get(LOGIN_PATH)).await;
    assert_eq!(status, StatusCode::FOUND);
    let issued_state = state_parameter(&start_login(&headers));

    let (status, headers, body) = send(
        state,
        get(&format!(
            "/api/v1/auth/callback?code=attacker-code&state={issued_state}"
        )),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a state that is not this browser's is not usable"
    );
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "nothing to clear and nothing to issue: {body}"
    );
    assert!(
        !body.contains("attacker-code"),
        "the code is never reflected: {body}"
    );
    assert_eq!(
        idp.exchanges(),
        0,
        "no code exchange without the browser-bound state cookie"
    );
}

/// A cookie that does not match the query parameter is refused, its own copy is expired, and the code
/// is still never exchanged.
#[tokio::test]
async fn a_state_cookie_that_does_not_match_the_query_parameter_is_refused() {
    let idp = Arc::new(FakeIdp::default());
    let bff = Arc::new(BffState::new(bff_config(), idp.clone()).expect("a valid configuration"));
    let state = state_with_bff(bff);

    let (status, headers, _) = send(state.clone(), get(LOGIN_PATH)).await;
    assert_eq!(status, StatusCode::FOUND);
    let issued_state = state_parameter(&start_login(&headers));

    let (status, headers, _) = send(
        state,
        HttpRequest::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/auth/callback?code=attacker-code&state={issued_state}"
            ))
            .header(
                header::COOKIE,
                format!("{STATE_COOKIE_NAME}=some-other-browser-state"),
            )
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(idp.exchanges(), 0, "the code is never exchanged");
    let cleared = set_cookies(&headers);
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    assert!(cleared[0].starts_with(STATE_COOKIE_NAME), "{cleared:?}");
    assert!(cleared[0].contains("Max-Age=0"), "{cleared:?}");
}

#[tokio::test]
async fn a_callback_with_an_unknown_state_is_refused_without_a_cookie_or_an_exchange() {
    let idp = Arc::new(FakeIdp::default());
    let bff = Arc::new(BffState::new(bff_config(), idp.clone()).expect("a valid configuration"));
    let state = state_with_bff(bff);

    // A browser that never started a sign-in: no state cookie, so the callback is refused before the
    // transaction store is even consulted.
    let (status, headers, body) = send(
        state,
        get("/api/v1/auth/callback?code=attacker-code&state=never-issued"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "no session is issued"
    );
    assert!(
        !body.contains("attacker-code"),
        "the code is never reflected: {body}"
    );
    assert_eq!(idp.exchanges(), 0, "no code exchange without a valid state");
}

#[tokio::test]
async fn the_full_flow_issues_http_only_secure_cookies_and_authenticates_the_session() {
    let idp = Arc::new(FakeIdp::default());
    let bff = Arc::new(BffState::new(bff_config(), idp.clone()).expect("a valid configuration"));
    let state = state_with_bff(bff.clone());

    let (status, headers, _) = send(state.clone(), get("/api/v1/auth/login")).await;
    assert_eq!(status, StatusCode::FOUND);
    let location = start_login(&headers);
    let state_param = state_parameter(&location);
    // `H1`: the login response binds the state to *this* browser.
    let state_cookie_header = set_cookies(&headers)
        .into_iter()
        .find(|cookie| cookie.starts_with(STATE_COOKIE_NAME))
        .expect("the login redirect sets the state cookie");
    assert!(
        state_cookie_header.contains("HttpOnly"),
        "{state_cookie_header}"
    );
    assert!(
        state_cookie_header.contains("Secure"),
        "{state_cookie_header}"
    );
    assert!(
        state_cookie_header.contains("SameSite=Lax"),
        "{state_cookie_header}"
    );
    assert!(
        state_cookie_header.contains("Path=/"),
        "{state_cookie_header}"
    );
    let state_cookie = state_cookie_header
        .split(';')
        .next()
        .expect("name=value")
        .to_owned();

    // The callback the IdP would deliver, with the cookie the login response set.
    let (status, headers, _) = send(
        state.clone(),
        HttpRequest::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/auth/callback?code=the-code&state={state_param}"
            ))
            .header(header::COOKIE, &state_cookie)
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/")
    );
    let cookies = set_cookies(&headers);
    // The state cookie is one-shot: it is expired on the very response that completes the sign-in.
    let cleared_state = cookies
        .iter()
        .find(|cookie| cookie.starts_with(STATE_COOKIE_NAME))
        .expect("the state cookie is cleared");
    assert!(cleared_state.contains("Max-Age=0"), "{cleared_state}");
    assert_eq!(
        cookies
            .iter()
            .filter(|cookie| !cookie.starts_with(STATE_COOKIE_NAME))
            .count(),
        2,
        "{cookies:?}"
    );
    let session_cookie = cookies
        .iter()
        .find(|cookie| cookie.starts_with(SESSION_COOKIE_NAME))
        .expect("a session cookie");
    assert!(session_cookie.contains("HttpOnly"), "{session_cookie}");
    assert!(session_cookie.contains("Secure"), "{session_cookie}");
    assert!(session_cookie.contains("SameSite=Lax"), "{session_cookie}");
    assert!(session_cookie.contains("Path=/"), "{session_cookie}");
    // The access token never appears in clear, in either cookie.
    assert!(
        !session_cookie.contains("idp-access-token-value"),
        "{session_cookie}"
    );
    let csrf_cookie = cookies
        .iter()
        .find(|cookie| cookie.starts_with(CSRF_COOKIE_NAME))
        .expect("a CSRF cookie");
    assert!(!csrf_cookie.contains("HttpOnly"), "{csrf_cookie}");
    assert!(csrf_cookie.contains("Secure"), "{csrf_cookie}");

    // The exchange sent the verifier minted at login, to the registered redirect URI.
    let exchanged = idp.last_request().expect("one exchange");
    assert_eq!(exchanged.code, "the-code");
    assert_eq!(
        exchanged.redirect_uri,
        "https://ferriscd.example.com/api/v1/auth/callback"
    );
    assert_eq!(exchanged.code_verifier.len(), 43);
    assert_eq!(idp.exchanges(), 1);

    // Replaying the callback cannot mint a second session, even with the (now expired) cookie.
    let (status, headers, _) = send(
        state.clone(),
        HttpRequest::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/auth/callback?code=the-code&state={state_param}"
            ))
            .header(header::COOKIE, &state_cookie)
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        cookies_starting_with(&headers, SESSION_COOKIE_NAME).is_empty(),
        "a replayed callback never issues a session"
    );

    // The sealed cookie authenticates a protected request through the normal middleware.
    let cookie_pair = session_cookie.split(';').next().expect("name=value");
    let (status, _, body) = send(
        state,
        HttpRequest::builder()
            .method("GET")
            .uri("/api/v1/applications")
            .header(header::COOKIE, cookie_pair)
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_expired_or_tampered_session_cookie_is_a_401() {
    let bff = bff_state(bff_config());
    let state = state_with_bff(bff.clone());
    let (status, _, _) = send(
        state,
        HttpRequest::builder()
            .method("GET")
            .uri("/api/v1/applications")
            .header(
                header::COOKIE,
                format!("{SESSION_COOKIE_NAME}=not-a-sealed-session"),
            )
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_mutating_request_with_a_session_cookie_requires_the_csrf_header() {
    let bff = bff_state(bff_config());
    let state = state_with_bff(bff.clone());
    let session = established_session(&state, &bff).await;
    let cookie_pair = session.cookie_pair();
    let uri = "/api/v1/applications/ferriscd-system/payments-api/sync";

    // Without the header: 403, and the handler is never reached.
    let (status, _, body) =
        send(state.clone(), post_with_cookies(uri, &[&cookie_pair], None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("CSRF"), "{body}");

    // A mismatched header is refused too.
    let (status, _, _) = send(
        state.clone(),
        post_with_cookies(
            uri,
            &[&cookie_pair, &format!("{CSRF_COOKIE_NAME}=wrong")],
            Some("wrong"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The matching header + cookie lets the request through to the handler (which then fails on its
    // own seam, never with 403).
    let (status, _, _) = send(
        state.clone(),
        post_with_cookies(
            uri,
            &[
                &cookie_pair,
                &format!("{CSRF_COOKIE_NAME}={}", session.csrf_token),
            ],
            Some(&session.csrf_token),
        ),
    )
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN);

    // A bearer-only client (the CLI) is not forced to send a CSRF header.
    let (status, _, _) = send(
        state,
        HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer a-cli-token")
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn logout_requires_csrf_and_clears_every_bff_cookie() {
    let bff = bff_state(bff_config());
    let state = state_with_bff(bff.clone());
    let session = established_session(&state, &bff).await;
    let cookie_pair = session.cookie_pair();
    let csrf_cookie = format!("{CSRF_COOKIE_NAME}={}", session.csrf_token);

    // No CSRF header: the cross-site logout is refused.
    let (status, _, _) = send(
        state.clone(),
        post_with_cookies("/api/v1/auth/logout", &[&cookie_pair, &csrf_cookie], None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, headers, _) = send(
        state,
        post_with_cookies(
            "/api/v1/auth/logout",
            &[&cookie_pair, &csrf_cookie],
            Some(&session.csrf_token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let cookies = set_cookies(&headers);
    // The session and CSRF cookies, plus the (normally already cleared) state cookie: a browser that
    // is signed out holds no BFF cookie at all.
    assert_eq!(cookies.len(), 3, "{cookies:?}");
    for name in [SESSION_COOKIE_NAME, CSRF_COOKIE_NAME, STATE_COOKIE_NAME] {
        let cookie = cookies
            .iter()
            .find(|cookie| cookie.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} is cleared: {cookies:?}"));
        assert!(cookie.contains("Max-Age=0"), "{cookie}");
        assert!(cookie.contains("Secure"), "{cookie}");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
        assert!(cookie.contains("Path=/"), "{cookie}");
    }
}

/// **`T19.2` review finding: logout must be able to clear a cookie that no longer opens.**
///
/// An expired (or key-rotated) session cookie is a `401` on every other mutating route, which is
/// correct — but on `POST /api/v1/auth/logout` it would mean the browser can *never* get rid of the
/// dead cookie: the `401` comes from the CSRF middleware, before the handler that expires it runs. So
/// the logout path treats `SessionCredential::Invalid` as absent, answers `204` and clears the
/// cookies. Nothing is authorized by that: the handler's only effect is `Max-Age=0`.
#[tokio::test]
async fn logout_clears_a_session_cookie_that_no_longer_opens() {
    let bff = bff_state(bff_config());
    let state = state_with_bff(bff);

    for dead in [
        format!("{SESSION_COOKIE_NAME}=not-a-sealed-session"),
        format!("{SESSION_COOKIE_NAME}={}", "A".repeat(200)),
    ] {
        let (status, headers, body) = send(
            state.clone(),
            post_with_cookies(LOGOUT_PATH, &[&dead], None),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let cleared = set_cookies(&headers);
        assert_eq!(cleared.len(), 3, "{cleared:?}");
        assert!(
            cleared
                .iter()
                .any(|cookie| cookie.starts_with(SESSION_COOKIE_NAME)
                    && cookie.contains("Max-Age=0")),
            "{cleared:?}"
        );
    }

    // Every other mutating route still refuses an unusable cookie outright.
    let (status, _, _) = send(
        state,
        post_with_cookies(
            "/api/v1/applications/ferriscd-system/payments-api/sync",
            &[&format!("{SESSION_COOKIE_NAME}=not-a-sealed-session")],
            Some("anything"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// **`T19.2` round-3 finding: a cross-site `POST` could force a sign-out.**
///
/// `POST /api/v1/auth/logout` deliberately treats an unopenable session cookie as absent, and it
/// answers `Set-Cookie: …; Max-Age=0` even to a request that carries no cookie at all. A
/// `SameSite=Lax` cookie is withheld from a cross-site `POST`, so such a request could never be
/// authenticated by the cookie — but the browser still stores the response's deletions. Any page on
/// the internet could therefore sign an operator out. The middleware now refuses a request the
/// browser labels `cross-site`, and only that: the SPA's own fetch (`same-origin`) and the
/// dead-cookie recovery path keep working.
#[tokio::test]
async fn a_cross_site_logout_is_refused_while_a_same_origin_one_is_not() {
    let bff = bff_state(bff_config());
    let state = state_with_bff(bff.clone());
    let session = established_session(&state, &bff).await;
    let cookie_pair = session.cookie_pair();
    let csrf_cookie = format!("{CSRF_COOKIE_NAME}={}", session.csrf_token);

    // 1. The attack: no cookie at all, cross-site, so the CSRF middleware would otherwise pass it on
    //    and the handler would hand the browser three `Max-Age=0` cookies.
    let (status, headers, body) = send(
        state.clone(),
        HttpRequest::builder()
            .method("POST")
            .uri(LOGOUT_PATH)
            .header(SEC_FETCH_SITE_HEADER, CROSS_SITE_FETCH_SITE)
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "a refused sign-out must not clear anything: {headers:?}"
    );

    // The check is case-insensitive, so a hand-written client cannot capitalise its way past it.
    let (status, _, _) = send(
        state.clone(),
        HttpRequest::builder()
            .method("POST")
            .uri(LOGOUT_PATH)
            .header(SEC_FETCH_SITE_HEADER, "Cross-Site")
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 2. A signed-in operator's own sign-out (the SPA's same-origin fetch) still works.
    let (status, headers, _) = send(
        state.clone(),
        HttpRequest::builder()
            .method("POST")
            .uri(LOGOUT_PATH)
            .header(SEC_FETCH_SITE_HEADER, "same-origin")
            .header(header::COOKIE, format!("{cookie_pair}; {csrf_cookie}"))
            .header(CSRF_HEADER, &session.csrf_token)
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(set_cookies(&headers).len(), 3);

    // 3. A browser that sends no Fetch Metadata header at all (older browsers, curl) is unaffected:
    //    the check can only ever *add* a refusal for a request the browser labelled cross-site.
    let (status, _, _) = send(
        state.clone(),
        post_with_cookies(
            LOGOUT_PATH,
            &[&format!("{SESSION_COOKIE_NAME}=not-a-sealed-session")],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // …and a cross-site page gets nothing even with a *valid* session: the refusal happens before the
    // cookie is looked at, so no CSRF token can be probed through it either.
    let (status, headers, _) = send(
        state,
        HttpRequest::builder()
            .method("POST")
            .uri(LOGOUT_PATH)
            .header(SEC_FETCH_SITE_HEADER, CROSS_SITE_FETCH_SITE)
            .header(header::COOKIE, format!("{cookie_pair}; {csrf_cookie}"))
            .header(CSRF_HEADER, &session.csrf_token)
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(headers.get(header::SET_COOKIE).is_none());
}

/// The dead-cookie recovery path deliberately survives the cross-site refusal: same-origin, an
/// unopenable cookie, no CSRF header — `204` and the cookies are expired.
#[tokio::test]
async fn a_same_origin_logout_still_clears_a_dead_cookie() {
    let bff = bff_state(bff_config());
    let state = state_with_bff(bff);
    let (status, headers, body) = send(
        state,
        HttpRequest::builder()
            .method("POST")
            .uri(LOGOUT_PATH)
            .header(SEC_FETCH_SITE_HEADER, "same-origin")
            .header(
                header::COOKIE,
                format!("{SESSION_COOKIE_NAME}=not-a-sealed-session"),
            )
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let cleared = set_cookies(&headers);
    assert_eq!(cleared.len(), 3, "{cleared:?}");
    assert!(
        cleared.iter().all(|cookie| cookie.contains("Max-Age=0")),
        "{cleared:?}"
    );
}

// ---------------------------------------------------------------------------
// The per-client sign-in budget (`H1` follow-up: login cannot evict other sign-ins)
// ---------------------------------------------------------------------------

/// **`T19.2` review finding: `/api/v1/auth/login` could be spammed to evict pending sign-ins.**
///
/// The pending-transaction store is bounded and evicts the oldest entry, so one client looping the
/// (necessarily unauthenticated) login route could drop every other operator's in-flight sign-in. The
/// budget stops that at the source, per client address: the ninth sign-in inside the window is `429`
/// and does not even reach the transaction store.
#[tokio::test]
async fn the_login_route_spends_a_bounded_per_client_budget() {
    let bff = bff_state(bff_config());
    let state = state_with_bff(bff.clone());
    let spammer: SocketAddr = "203.0.113.9:40000".parse().expect("a socket address");
    let operator: SocketAddr = "198.51.100.4:40001".parse().expect("a socket address");

    for attempt in 0..MAX_LOGINS_PER_CLIENT {
        let (status, _, body) = send_from(state.clone(), spammer, get(LOGIN_PATH)).await;
        assert_eq!(status, StatusCode::FOUND, "attempt {attempt}: {body}");
    }
    let (status, headers, body) = send_from(state.clone(), spammer, get(LOGIN_PATH)).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the budget refuses the request before any work: {body}"
    );
    assert!(body.contains("TooManyRequests"), "{body}");
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "a refused sign-in sets no cookie"
    );

    // Another address keeps its own budget: one client cannot lock everybody out.
    let (status, _, _) = send_from(state, operator, get(LOGIN_PATH)).await;
    assert_eq!(status, StatusCode::FOUND);
}

/// The budget is a sliding window over client-supplied *addresses*, and it is bounded in memory.
///
/// Driven with an injected clock so the assertions are exact and nothing sleeps.
#[test]
fn the_login_budget_slides_its_window_and_stays_bounded() {
    let window = Duration::from_secs(60);
    let now = Instant::now();
    let mut budget = LoginBudget::new(window, 2, 4);

    assert!(budget.try_acquire("a", now));
    assert!(budget.try_acquire("a", now + Duration::from_secs(1)));
    assert!(
        !budget.try_acquire("a", now + Duration::from_secs(2)),
        "the third sign-in inside the window is refused"
    );
    // A refused attempt is not recorded, so the window still slides from the *accepted* ones.
    assert!(!budget.try_acquire("a", now + Duration::from_secs(59)));
    assert!(
        budget.try_acquire("a", now + Duration::from_secs(61)),
        "past the window the client is allowed again"
    );
    // Another client is unaffected.
    assert!(budget.try_acquire("b", now));

    // Bounded: 4 clients at most, and the least recently active one is the one forgotten.
    for (index, client) in ["c", "d", "e", "f"].iter().enumerate() {
        let at = now + Duration::from_secs(70 + index as u64);
        assert!(budget.try_acquire(client, at));
    }
    assert!(budget.len() <= 4, "{} clients tracked", budget.len());

    // An idle client's entry is dropped once its window has fully passed.
    let mut budget = LoginBudget::new(window, 2, 4);
    assert!(budget.try_acquire("idle", now));
    budget.sweep(now + window + Duration::from_secs(1));
    assert!(budget.is_empty());
}

#[tokio::test]
async fn a_failed_exchange_issues_no_cookie_and_never_echoes_the_code() {
    let idp = Arc::new(FakeIdp::default());
    idp.fail_next();
    let bff = Arc::new(BffState::new(bff_config(), idp.clone()).expect("a valid configuration"));
    let state = state_with_bff(bff);

    let (_, headers, _) = send(state.clone(), get("/api/v1/auth/login")).await;
    let state_param = state_parameter(&start_login(&headers));
    let state_cookie = cookie_pair(&headers, STATE_COOKIE_NAME).expect("the state cookie");
    let (status, headers, body) = send(
        state,
        HttpRequest::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/auth/callback?code=secret-code&state={state_param}"
            ))
            .header(header::COOKIE, state_cookie)
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(
        cookies_starting_with(&headers, SESSION_COOKIE_NAME).is_empty(),
        "a failed exchange never issues a session: {headers:?}"
    );
    assert!(
        cookies_starting_with(&headers, CSRF_COOKIE_NAME).is_empty(),
        "a failed exchange never issues a CSRF cookie: {headers:?}"
    );
    assert!(!body.contains("secret-code"), "{body}");
    assert!(!body.contains("access-token"), "{body}");
}

#[test]
fn a_token_too_large_for_a_browser_cookie_is_refused_at_every_step() {
    // 1. The token endpoint's own JSON parser refuses an oversized `access_token`, so the flow never
    //    reaches the sealing step with one.
    let huge = format!(
        r#"{{"access_token":"{}","expires_in":60}}"#,
        "a".repeat(MAX_ACCESS_TOKEN_CHARS + 1)
    );
    assert_eq!(
        parse_token_response(huge.as_bytes()).err(),
        Some(BffError::NoAccessToken)
    );
    // A missing/blank/control-character token is refused the same way.
    assert_eq!(
        parse_token_response(br#"{"access_token":"   "}"#).err(),
        Some(BffError::NoAccessToken)
    );
    assert_eq!(
        parse_token_response(br#"{"access_token":"abc\u0000def"}"#).err(),
        Some(BffError::NoAccessToken)
    );
    assert_eq!(
        parse_token_response(b"not json").err(),
        Some(BffError::NoAccessToken)
    );

    // 2. The sealer is the belt-and-braces guard: a session whose sealed cookie would exceed what a
    //    browser stores is refused instead of issued (the browser would silently drop it).
    let sealer =
        SessionSealer::new(&SessionKey::from_bytes(TEST_KEY).expect("a key")).expect("a sealer");
    let oversized = Session {
        access_token: "a".repeat(MAX_SESSION_COOKIE_BYTES),
        csrf_token: "csrf".to_owned(),
        expires_at_unix: unix_seconds(SystemTime::now()) + 60,
    };
    assert_eq!(sealer.seal(&oversized).err(), Some(BffError::TokenTooLarge));
    // A token inside the documented ceiling seals to a value a browser keeps.
    let fitting = Session {
        access_token: "a".repeat(MAX_ACCESS_TOKEN_CHARS),
        csrf_token: "csrf".to_owned(),
        expires_at_unix: unix_seconds(SystemTime::now()) + 60,
    };
    let sealed = sealer.seal(&fitting).expect("a fitting token seals");
    assert!(
        sealed.len() <= MAX_SESSION_COOKIE_BYTES,
        "the cookie is {} bytes",
        sealed.len()
    );
    assert!(sealer.open(&sealed, SystemTime::now()).is_ok());
}

/// A named cookie pair plus its CSRF token, from a real login + callback round trip.
struct EstablishedSession {
    cookie: String,
    csrf_token: String,
}

impl EstablishedSession {
    fn cookie_pair(&self) -> String {
        self.cookie.clone()
    }
}

async fn established_session(state: &AppState, bff: &Arc<BffState>) -> EstablishedSession {
    let (_, headers, _) = send(state.clone(), get(LOGIN_PATH)).await;
    let state_param = state_parameter(&start_login(&headers));
    let state_cookie = cookie_pair(&headers, STATE_COOKIE_NAME).expect("the state cookie");
    let (status, headers, _) = send(
        state.clone(),
        HttpRequest::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/auth/callback?code=the-code&state={state_param}"
            ))
            .header(header::COOKIE, state_cookie)
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|cookie| cookie.starts_with(SESSION_COOKIE_NAME))
        .expect("a session cookie")
        .split(';')
        .next()
        .expect("name=value")
        .to_owned();
    // The CSRF token is inside the sealed cookie; read it back through the sealer the server uses.
    let session = match bff.session_credential(&cookie_headers(&cookie), SystemTime::now()) {
        SessionCredential::Active(session) => session,
        other => panic!("the cookie did not open: {other:?}"),
    };
    EstablishedSession {
        cookie,
        csrf_token: session.csrf_token,
    }
}

fn cookie_headers(cookie: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        header::HeaderValue::from_str(cookie).expect("a valid cookie header"),
    );
    headers
}

/// Extracts the `state` query parameter from an authorize URL.
fn state_parameter(location: &str) -> String {
    let url = reqwest::Url::parse(location).expect("an absolute URL");
    url.query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("the authorize URL carries a state")
}

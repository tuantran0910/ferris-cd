//! Pooled `ServiceAccount` impersonation (`T12.3`, finding H5, trap T12).
//!
//! An `Application` that sets `spec.serviceAccountName` must be deployed **as that
//! ServiceAccount**, not as the controller's own (privileged) identity. Kubernetes exposes that
//! through the impersonation headers, and the two halves below are what make it safe:
//!
//! * [`Impersonation`] — the validated header set. It is built **once**, from the
//!   `ServiceAccount` resolved in `spec.destination.namespace`, and only after
//!   [`AppProjectPolicy`](ferriscd_engine::policy::AppProjectPolicy) has authorized the
//!   destination *and* the ServiceAccount name. Names are validated as Kubernetes identifiers, so
//!   nothing user-controlled can produce a `system:` principal the controller did not mean, and
//!   `system:masters` is never part of the injected group set.
//! * [`ImpersonationPool`] — the connection pool. Building a `kube::Client` per reconcile would
//!   leak a TLS connector (and its file descriptors) on every pass, so the pool owns exactly
//!   **one** [`hyper_util::client::legacy::Client`] (one TLS connector, one connection pool) built
//!   from the controller's own [`kube::Config`], plus one [`ImpersonationLayer`] per identity on
//!   top of it. Every impersonated `kube::Client` is a cheap clone of that shared connector, and
//!   the clients are cached per identity.
//!
//! ## The exact header set
//!
//! For `system:serviceaccount:<dest_ns>:<sa_name>` (see [`Impersonation::for_service_account`]):
//!
//! | Header | Value |
//! |---|---|
//! | `Impersonate-User` | `system:serviceaccount:<dest_ns>:<sa_name>` |
//! | `Impersonate-Group` | `system:serviceaccounts` |
//! | `Impersonate-Group` | `system:serviceaccounts:<dest_ns>` |
//! | `Impersonate-Group` | `system:authenticated` |
//!
//! ## Why the groups are not optional (finding H5)
//!
//! Kubernetes authorizes *groups*, not users: a `RoleBinding` that lists
//! `kind: Group, name: system:serviceaccounts:<ns>` is how an operator grants a whole tenant
//! namespace to every ServiceAccount in it, and a `RoleBinding` to
//! `system:serviceaccounts` or `system:authenticated` is how cluster add-ons do it. Sending only
//! `Impersonate-User` makes the impersonated identity belong to **no** group, so every such
//! binding silently stops applying. The three groups above are exactly the ones the kubelet puts
//! in a ServiceAccount's token, so an impersonated pod and a real pod are authorized identically.
//!
//! ## Required controller RBAC
//!
//! Impersonation is itself a privileged verb, so the controller's `ClusterRole` needs:
//!
//! ```yaml
//! - apiGroups: [""]
//!   resources: ["users", "groups"]
//!   verbs: ["impersonate"]
//! ```
//!
//! Impersonating a `ServiceAccount` **additionally** requires `impersonate` on
//! `serviceaccounts` in the destination namespace (the API server checks the
//! `system:serviceaccount:<ns>:<name>` user against that resource). `system:masters` must never
//! be delegated: it bypasses authorization entirely, which is why
//! [`Impersonation::new`] rejects it and the ServiceAccount constructor cannot produce it.
//!
//! ## Limits (documented, not hidden)
//!
//! * One pool per [`kube::Config`] — i.e. one per cluster. Remote clusters (`T13.1`) will hold
//!   their own [`ImpersonationPool`], so each destination cluster keeps its own connector.
//! * The pool's shared connector is built from the controller's `kube::Config`, so the
//!   controller's credential is used to *authenticate* the request and then delegate to the
//!   impersonated principal. A proxied `kube::Config` (`proxy_url`) is refused rather than
//!   silently un-proxied; with the current feature set `kube` refuses it anyway.
//! * The client cache is **bounded** ([`MAX_CACHED_IDENTITIES`]). Its key is
//!   `(destination namespace, ServiceAccount)`, i.e. tenant-influenced through
//!   `spec.destination.namespace`/`spec.serviceAccountName`, so an unbounded map would let a tenant
//!   that cycles ServiceAccount names grow the controller's memory (and one `tower::buffer` task
//!   per client) without limit. When the cap is reached the oldest entry is evicted and a warning
//!   is logged; the shared connector is untouched, so a miss costs one middleware-stack rebuild.
//! * **No `TraceLayer`.** `kube`'s own client builder wraps its stack in a `tower_http::trace`
//!   `TraceLayer` (a `debug` span per HTTP call, carrying `http.url`). This pool assembles the
//!   stack by hand and deliberately omits it: `tower-http` would be a new direct dependency for
//!   observability only, and the omitted span is the one field that would quote a request URL for
//!   *tenant* traffic. The pipeline's own spans (`reconcile` plus the per-resource
//!   apply/prune/hook logs) still cover what an operator needs to debug a tenant sync.
//! * Only **workload** traffic is impersonated. The `Application`'s own `/status`, its finalizer,
//!   and the rollback spec patch stay on the controller's identity: a tenant's ServiceAccount
//!   normally has no RBAC on the `Application` CR, while the controller must always be able to
//!   record what happened.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ferriscd_crd::Application;
use http::{HeaderMap, HeaderName, HeaderValue, Request};
use kube::Client;
use kube::client::{Body, ConfigExt};
use kube::config::Config;
use tower::{Layer, Service};

use crate::dry_run::DynamicDryRunApi;
use crate::live_state::{ClusterStateReader, DynamicApiSource, LiveObjectSource};
use crate::reconcile::ReconcileError;
use crate::sync::{Applier, DynamicApiApplier};

/// Header naming the user to impersonate.
pub const IMPERSONATE_USER_HEADER: HeaderName = HeaderName::from_static("impersonate-user");

/// Header naming one group to impersonate (sent once per group).
pub const IMPERSONATE_GROUP_HEADER: HeaderName = HeaderName::from_static("impersonate-group");

/// Header naming the **uid** to impersonate. Never set by FerrisCD.
///
/// A uid selects a principal by object identity rather than by name, which is a different (and
/// re-creatable) authorization subject. The pool only ever selects a ServiceAccount by name, so a
/// pre-existing `Impersonate-Uid` (a kubeconfig `headers:` entry, another middleware) is stripped
/// instead of being allowed to ride along (finding M-5).
pub const IMPERSONATE_UID_HEADER: HeaderName = HeaderName::from_static("impersonate-uid");

/// Prefix of Kubernetes' extra-attribute impersonation headers (`Impersonate-Extra-<key>`).
///
/// Extra attributes are additional authorization-relevant claims (for example the `scopes`
/// attribute an OIDC provider puts in a token). FerrisCD never sets them, so they are stripped
/// like [`IMPERSONATE_UID_HEADER`].
pub const IMPERSONATE_EXTRA_PREFIX: &str = "impersonate-extra-";

/// Group every ServiceAccount belongs to.
pub const GROUP_SERVICE_ACCOUNTS: &str = "system:serviceaccounts";

/// Group every authenticated principal belongs to.
pub const GROUP_AUTHENTICATED: &str = "system:authenticated";

/// The one group that must never be injected: it bypasses authorization entirely (trap T12).
pub const FORBIDDEN_GROUP: &str = "system:masters";

/// Prefix of the user name Kubernetes uses for a `ServiceAccount`.
pub const SERVICE_ACCOUNT_USER_PREFIX: &str = "system:serviceaccount:";

/// Longest valid `ServiceAccount` name (RFC 1123 subdomain).
const MAX_SERVICE_ACCOUNT_NAME_LEN: usize = 253;

/// Longest valid namespace name (RFC 1123 label).
const MAX_NAMESPACE_NAME_LEN: usize = 63;

/// Longest impersonated user/group name the pool will send.
///
/// Kubernetes does not document a limit for impersonation names; the cap exists so a malformed
/// CR cannot turn into an unbounded header value.
const MAX_IMPERSONATED_NAME_LEN: usize = 512;

/// Maximum number of impersonated clients the pool caches (one per distinct identity).
///
/// The cache key — `(destination namespace, ServiceAccount)` — is tenant-influenced, so an
/// unbounded map would let a tenant that cycles `spec.serviceAccountName` values grow the
/// controller's memory without limit (finding M2). A real deployment uses a handful of tenant
/// identities, so the cap is small; a miss rebuilds one middleware stack over the **same**
/// shared connector, which is cheap and leaks nothing.
pub const MAX_CACHED_IDENTITIES: usize = 64;

/// Pins the process-level `rustls` `CryptoProvider` to `ring`.
///
/// Two providers are linked into this workspace: `kube` enables `rustls/ring`, while `gix`'s
/// HTTP transport (`reqwest`) enables `rustls/aws-lc-rs`. `rustls` deliberately refuses to guess
/// between them — `ClientConfig::builder()` panics with "Could not automatically determine the
/// process-level CryptoProvider" — so **any** HTTPS `kube::Client` construction (the
/// controller's own client included, not only an impersonated one) needs a process-level default
/// first.
///
/// `ring` is selected because it is `kube`'s own default: an impersonated client then behaves
/// exactly like the controller's own, instead of using a different TLS stack. The call is
/// idempotent (a second provider loses the install race and is dropped), so it is safe from every
/// entry point — the binary, the impersonation pool, and tests.
pub fn ensure_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Losing the race means another thread installed the same provider first.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// Problems building or using an impersonated identity.
///
/// Every variant is **terminal**: an invalid `ServiceAccount` name, a forbidden group, or a
/// transport configuration the pool cannot honour can never be fixed by retrying the same
/// `Application`.
#[derive(Debug, thiserror::Error)]
pub enum ImpersonationError {
    /// `spec.serviceAccountName` is not a valid Kubernetes `ServiceAccount` name.
    #[error(
        "spec.serviceAccountName {service_account:?} is not a valid Kubernetes ServiceAccount \
         name (a lowercase RFC 1123 subdomain): impersonation is refused"
    )]
    InvalidServiceAccountName {
        /// The rejected name.
        service_account: String,
    },

    /// `spec.destination.namespace` is not a valid namespace name.
    #[error(
        "spec.destination.namespace {namespace:?} is not a valid Kubernetes namespace name \
         (a lowercase RFC 1123 label), so ServiceAccount {service_account:?} cannot be resolved \
         in it"
    )]
    InvalidNamespace {
        /// The rejected namespace.
        namespace: String,
        /// The ServiceAccount that would have been impersonated in it.
        service_account: String,
    },

    /// A group that may never be impersonated was requested.
    #[error(
        "refusing to impersonate group {group:?}: it bypasses authorization (only the three \
         ServiceAccount groups {GROUP_SERVICE_ACCOUNTS}, {GROUP_SERVICE_ACCOUNTS}:<namespace>, \
         {GROUP_AUTHENTICATED} are injected)"
    )]
    ForbiddenGroup {
        /// The rejected group.
        group: String,
    },

    /// An impersonated user or group name is unusable as an HTTP header value.
    #[error("impersonating {principal:?} is not possible: {reason}")]
    InvalidPrincipal {
        /// The rejected user or group.
        principal: String,
        /// Why it is unusable.
        reason: String,
    },

    /// The `kube::Config` cannot be wrapped in an impersonation pool.
    #[error("cannot build the impersonation connector: {reason}")]
    UnsupportedConfig {
        /// Why the configuration is unusable.
        reason: String,
    },

    /// An `Application` asks for impersonation but no pool is wired into the pipeline.
    #[error(
        "{service_account} was requested by spec.serviceAccountName, but no impersonation pool is \
         wired into the sync pipeline: refusing to deploy with the controller's own identity \
         (wire `ImpersonationPool`/`ImpersonatingAccess` when building the pipeline)"
    )]
    NotWired {
        /// The identity that was requested.
        service_account: String,
    },

    /// The TLS connector could not be built from the `kube::Config`.
    #[error(transparent)]
    Config(#[from] kube::Error),
}

/// One impersonated identity: the validated `Impersonate-User`/`Impersonate-Group` header set.
///
/// Also the cache key of [`ImpersonationPool`], so it is `Hash`/`Eq` and cheap to clone.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Impersonation {
    user: String,
    groups: Vec<String>,
}

impl Impersonation {
    /// Builds the identity of `service_account` **in the destination namespace**.
    ///
    /// The `ServiceAccount` always resolves in `spec.destination.namespace` — never in the
    /// `Application`'s own namespace (ADR-007): a tenant `Application` in `team-a` that deploys
    /// into `payments` impersonates `system:serviceaccount:payments:<name>`, which is exactly the
    /// account (and the RBAC) its workloads run with.
    ///
    /// # Errors
    ///
    /// [`ImpersonationError::InvalidServiceAccountName`] or
    /// [`ImpersonationError::InvalidNamespace`] for a name Kubernetes could never have accepted.
    pub fn for_service_account(
        namespace: &str,
        service_account: &str,
    ) -> Result<Self, ImpersonationError> {
        let service_account = service_account.trim();
        let namespace = namespace.trim();
        if !is_valid_subdomain(service_account, MAX_SERVICE_ACCOUNT_NAME_LEN) {
            return Err(ImpersonationError::InvalidServiceAccountName {
                service_account: service_account.to_owned(),
            });
        }
        if !is_valid_label(namespace, MAX_NAMESPACE_NAME_LEN) {
            return Err(ImpersonationError::InvalidNamespace {
                namespace: namespace.to_owned(),
                service_account: service_account.to_owned(),
            });
        }
        let user = format!("{SERVICE_ACCOUNT_USER_PREFIX}{namespace}:{service_account}");
        Self::new(
            user,
            [
                GROUP_SERVICE_ACCOUNTS.to_owned(),
                format!("{GROUP_SERVICE_ACCOUNTS}:{namespace}"),
                GROUP_AUTHENTICATED.to_owned(),
            ],
        )
    }

    /// Builds an identity from a user and its groups.
    ///
    /// Used by [`Self::for_service_account`] and by tests; the validation is the security
    /// boundary, so it runs for both. A principal is rejected when it is empty, too long, or
    /// contains whitespace/control characters (which an HTTP header value cannot carry) — the
    /// header is never built from unvalidated input.
    ///
    /// # Errors
    ///
    /// [`ImpersonationError::ForbiddenGroup`] for `system:masters`,
    /// [`ImpersonationError::InvalidPrincipal`] for any unusable name.
    pub fn new<I>(user: impl Into<String>, groups: I) -> Result<Self, ImpersonationError>
    where
        I: IntoIterator<Item = String>,
    {
        let user = user.into();
        validate_principal(&user)?;
        let mut validated: Vec<String> = Vec::new();
        for group in groups {
            if group.trim() == FORBIDDEN_GROUP {
                return Err(ImpersonationError::ForbiddenGroup { group });
            }
            validate_principal(&group)?;
            if !validated.contains(&group) {
                validated.push(group);
            }
        }
        Ok(Self {
            user,
            groups: validated,
        })
    }

    /// The identity of the `ServiceAccount` an `Application` asks for, if any.
    ///
    /// `Ok(None)` means "no impersonation": the `Application` names no `serviceAccountName` and is
    /// deployed with the controller's own identity — which the tenancy policy only permits for an
    /// `Application` in the control-plane namespace (a tenant `Application` without a
    /// `serviceAccountName` is a terminal [`PolicyError`](ferriscd_engine::policy::PolicyError),
    /// never a controller-identity deployment).
    ///
    /// # Errors
    ///
    /// See [`Self::for_service_account`].
    pub fn for_application(app: &Application) -> Result<Option<Self>, ImpersonationError> {
        match app.spec.service_account_name.as_deref().map(str::trim) {
            None | Some("") => Ok(None),
            Some(service_account) => {
                Self::for_service_account(&app.spec.destination.namespace, service_account)
                    .map(Some)
            }
        }
    }

    /// The `Impersonate-User` value (`system:serviceaccount:<ns>:<name>`).
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The `Impersonate-Group` values, in injection order.
    #[must_use]
    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    /// Returns whether `group` is part of this identity.
    #[must_use]
    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|candidate| candidate == group)
    }

    /// Builds the exact header map injected on every request.
    ///
    /// # Errors
    ///
    /// [`ImpersonationError::InvalidPrincipal`] when a value cannot be represented as an HTTP
    /// header value. [`Self::new`] already rejected those, so this is a defensive branch rather
    /// than an expected one — and it is an error, never a silently dropped header.
    pub fn headers(&self) -> Result<HeaderMap, ImpersonationError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            IMPERSONATE_USER_HEADER,
            header_value(&self.user).map_err(|reason| ImpersonationError::InvalidPrincipal {
                principal: self.user.clone(),
                reason,
            })?,
        );
        for group in &self.groups {
            headers.append(
                IMPERSONATE_GROUP_HEADER,
                header_value(group).map_err(|reason| ImpersonationError::InvalidPrincipal {
                    principal: group.clone(),
                    reason,
                })?,
            );
        }
        Ok(headers)
    }
}

impl fmt::Display for Impersonation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.user)
    }
}

/// Rejects principals an HTTP header cannot carry (or that are absurdly long).
fn validate_principal(principal: &str) -> Result<(), ImpersonationError> {
    let reason = if principal.trim().is_empty() {
        Some("an impersonated principal must not be empty".to_owned())
    } else if principal.chars().count() > MAX_IMPERSONATED_NAME_LEN {
        Some(format!(
            "an impersonated principal must be at most {MAX_IMPERSONATED_NAME_LEN} characters"
        ))
    } else if principal
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        Some(
            "an impersonated principal must not contain whitespace or control characters"
                .to_owned(),
        )
    } else {
        None
    };
    match reason {
        Some(reason) => Err(ImpersonationError::InvalidPrincipal {
            principal: principal.to_owned(),
            reason,
        }),
        None => Ok(()),
    }
}

/// Builds a header value, reporting why an unusable principal was rejected.
fn header_value(principal: &str) -> Result<HeaderValue, String> {
    HeaderValue::from_str(principal).map_err(|err| format!("not a valid header value: {err}"))
}

/// Whether `value` is a valid RFC 1123 label (`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).
fn is_valid_label(value: &str, max_len: usize) -> bool {
    is_valid_dns_name(value, max_len, false)
}

/// Whether `value` is a valid RFC 1123 subdomain (dot-separated labels).
fn is_valid_subdomain(value: &str, max_len: usize) -> bool {
    is_valid_dns_name(value, max_len, true)
}

fn is_valid_dns_name(value: &str, max_len: usize, allow_dots: bool) -> bool {
    if value.is_empty() || value.len() > max_len {
        return false;
    }
    let is_alnum = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    if allow_dots {
        value.split('.').all(|label| {
            is_valid_dns_name(label, max_len, false)
                // A subdomain label is never empty (`a..b` is not a name).
                && !label.is_empty()
        })
    } else {
        value.chars().all(|c| is_alnum(c) || c == '-')
            && value.chars().next().is_some_and(is_alnum)
            && value.chars().next_back().is_some_and(is_alnum)
    }
}

/// A `tower` layer that injects one [`Impersonation`] on every request.
///
/// Applied **innermost** (immediately above the shared connector), so it runs last: a
/// `kube::Config` `headers` entry or any other middleware cannot rewrite the identity the
/// controller decided on.
#[derive(Clone, Debug)]
pub struct ImpersonationLayer {
    headers: HeaderMap,
}

impl ImpersonationLayer {
    /// Builds the layer for `impersonation`.
    ///
    /// # Errors
    ///
    /// See [`Impersonation::headers`].
    pub fn new(impersonation: &Impersonation) -> Result<Self, ImpersonationError> {
        Ok(Self {
            headers: impersonation.headers()?,
        })
    }

    /// The headers this layer injects.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

impl<S> Layer<S> for ImpersonationLayer {
    type Service = ImpersonationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ImpersonationService {
            inner,
            headers: self.headers.clone(),
        }
    }
}

/// The service [`ImpersonationLayer`] produces.
#[derive(Clone, Debug)]
pub struct ImpersonationService<S> {
    inner: S,
    headers: HeaderMap,
}

impl<S, B> Service<Request<B>> for ImpersonationService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let headers = request.headers_mut();
        // Replace, never extend: a pre-existing `Impersonate-User`/`-Group` (from a kubeconfig
        // `headers` entry) must not survive next to ours — the API server would either see two
        // users or, worse, keep the one we did not choose.
        headers.remove(IMPERSONATE_USER_HEADER);
        headers.remove(IMPERSONATE_GROUP_HEADER);
        // The same applies to the principal-selection headers this layer never sets: a uid or an
        // extra attribute of *another* principal would otherwise be authorized alongside the
        // ServiceAccount we chose (finding M-5).
        let foreign: Vec<HeaderName> = headers
            .keys()
            .filter(|name| is_foreign_impersonation_header(name))
            .cloned()
            .collect();
        for name in foreign {
            headers.remove(name);
        }
        for (name, value) in &self.headers {
            // `HeaderMap` iterates one entry per value, so `append` reconstructs the
            // multi-valued `Impersonate-Group` list exactly.
            headers.append(name.clone(), value.clone());
        }
        self.inner.call(request)
    }
}

/// Whether `name` is an impersonation header the layer must strip rather than pass through.
fn is_foreign_impersonation_header(name: &HeaderName) -> bool {
    name == IMPERSONATE_UID_HEADER || name.as_str().starts_with(IMPERSONATE_EXTRA_PREFIX)
}

/// Builds one impersonated [`Client`] over the pool's shared connector.
///
/// A trait object rather than a concrete service type: the `kube` middleware stack it wraps is
/// unnameable by construction (`tower::ServiceBuilder` returns an anonymous type), and the only
/// thing a caller needs is the [`Client`].
type ClientBuilder =
    Box<dyn Fn(&Impersonation) -> Result<Client, ImpersonationError> + Send + Sync>;

/// The pool's client cache: an insertion-ordered (FIFO) map with a hard cap.
///
/// `HashMap` alone would be unbounded, and a real LRU needs a second index for no benefit here:
/// what matters is that the memory is bounded and the eviction is deterministic and logged.
#[derive(Default)]
struct ClientCache {
    clients: HashMap<Impersonation, Client>,
    /// Identities in insertion order, so the oldest entry is the one evicted.
    order: VecDeque<Impersonation>,
}

/// A cached pool of impersonated [`Client`]s over **one** shared connector.
///
/// The pool owns exactly one [`hyper_util::client::legacy::Client`] — one TLS connector and one
/// connection pool — built from the controller's [`kube::Config`]. Every impersonated client is a
/// `kube` middleware stack over a clone of that connector, so reconciling a thousand times (or a
/// thousand tenants) never opens a second HTTPS pool per pass.
///
/// Building is *lazy per identity*: the first [`Self::client`] call for an identity assembles its
/// middleware stack (no I/O — the TLS material is reused, the token refresh is handled inside
/// `kube`), and every later call returns the cached client.
pub struct ImpersonationPool {
    /// Builds the middleware stack for one identity over the shared connector.
    build: ClientBuilder,
    clients: Mutex<ClientCache>,
    builds: AtomicUsize,
    default_namespace: String,
}

impl fmt::Debug for ImpersonationPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImpersonationPool")
            .field("connectors", &1)
            .field("default_namespace", &self.default_namespace)
            .field("cached_clients", &self.cached())
            .field("builds", &self.builds())
            .finish()
    }
}

impl ImpersonationPool {
    /// Builds the one shared connector from `config`.
    ///
    /// This is the only place an HTTP/TLS connector is constructed, and it happens once per
    /// controller (per cluster). It performs the same (file) reads `kube`'s own client
    /// construction performs — the CA bundle — so callers should run it on a blocking task.
    ///
    /// # Errors
    ///
    /// [`ImpersonationError::UnsupportedConfig`] for a proxied configuration the pool cannot
    /// honour (fail loudly instead of silently dropping the proxy), and
    /// [`ImpersonationError::Config`] when `kube` cannot build the TLS connector at all.
    pub fn new(config: &Config) -> Result<Self, ImpersonationError> {
        if let Some(proxy_url) = &config.proxy_url {
            return Err(ImpersonationError::UnsupportedConfig {
                reason: format!(
                    "the kubeconfig sets proxy_url {proxy_url}: impersonated clients cannot be \
                     built over a proxy by this pool (use an unproxied kubeconfig, or a \
                     `ferriscd.io/secret-type=cluster` Secret without a proxy)"
                ),
            });
        }

        // Building the connector needs a process-level crypto provider; see
        // [`ensure_crypto_provider`] for why it cannot be left to `rustls`' feature detection.
        ensure_crypto_provider();
        let mut connector = hyper_timeout::TimeoutConnector::new(config.rustls_https_connector()?);
        // The same transport timeouts `kube`'s own client builder applies, so an impersonated
        // request cannot outlive the controller's own.
        connector.set_connect_timeout(config.connect_timeout);
        connector.set_read_timeout(config.read_timeout);
        connector.set_write_timeout(config.write_timeout);
        connector.set_reset_reader_on_write(config.reset_reader_on_write);

        // The ONE connector. `hyper`'s client is the connection pool itself, and it is `Clone`:
        // every impersonated client below clones this handle rather than building a new one.
        let http: hyper_util::client::legacy::Client<_, Body> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);

        let config = config.clone();
        let default_namespace = config.default_namespace.clone();
        let client_namespace = default_namespace.clone();
        let build = Box::new(move |impersonation: &Impersonation| {
            // Innermost layer (first `.layer()` is outermost), so the identity runs immediately
            // before the transport and cannot be overwritten by the kubeconfig's extra headers.
            // `map_err` is added last, i.e. applied directly to the connector: `box`ing the
            // transport error first is what lets `RetryPolicy` (whose `Policy` impl is written
            // against `BoxError`, exactly as in `kube`'s own client builder) sit above it.
            let stack = tower::ServiceBuilder::new()
                .layer(config.base_uri_layer())
                .option_layer(config.default_retry.then(|| {
                    tower::retry::RetryLayer::new(kube::client::retry::RetryPolicy::server_retry())
                }))
                .option_layer(config.auth_layer()?)
                .layer(config.extra_headers_layer()?)
                .layer(ImpersonationLayer::new(impersonation)?)
                .map_err(tower::BoxError::from)
                .service(http.clone());
            Ok(Client::new(stack, client_namespace.clone()))
        });

        Ok(Self {
            build,
            clients: Mutex::new(ClientCache::default()),
            builds: AtomicUsize::new(0),
            default_namespace,
        })
    }

    /// Returns the impersonated client for `impersonation`, building it at most once.
    ///
    /// Must be called from a Tokio runtime (like every `kube::Client`): `kube` wraps the stack in
    /// a `tower::buffer` with its own worker task. That is one small task per **cached identity**,
    /// not one per reconcile, and the transport itself (the sockets) is shared. For the same
    /// reason the build cannot be moved to `spawn_blocking` — a blocking task has no runtime
    /// context for `kube` to spawn its buffer worker in.
    ///
    /// The first call for an identity therefore performs the same tiny, blocking **token-file
    /// read** `kube`'s own client construction performs (`std::fs::read_to_string` of the
    /// projected `token`). It happens once per identity and is cached for the process lifetime:
    /// never on the per-reconcile path, and never per resource.
    ///
    /// # Errors
    ///
    /// See [`ImpersonationLayer::new`] (an unusable principal) — never an I/O error: the client is
    /// a middleware stack over the connector the pool already owns.
    pub fn client(&self, impersonation: &Impersonation) -> Result<Client, ImpersonationError> {
        let mut cache = crate::lock_recover(&self.clients);
        if let Some(client) = cache.clients.get(impersonation) {
            return Ok(client.clone());
        }
        let client = (self.build)(impersonation)?;
        self.builds.fetch_add(1, Ordering::SeqCst);
        // Finding M2: the key is tenant-influenced, so the cache must not grow without bound.
        while cache.order.len() >= MAX_CACHED_IDENTITIES {
            let Some(evicted) = cache.order.pop_front() else {
                break;
            };
            cache.clients.remove(&evicted);
            tracing::warn!(
                evicted_identity = %evicted.user(),
                cached_identities = MAX_CACHED_IDENTITIES,
                "evicted the oldest cached impersonated client: more distinct ServiceAccounts are \
                 in use than the cache holds (it is rebuilt on its next use; the one shared \
                 HTTP/TLS connector is unaffected)"
            );
        }
        cache.order.push_back(impersonation.clone());
        cache.clients.insert(impersonation.clone(), client.clone());
        Ok(client)
    }

    /// The default namespace of the cluster this pool belongs to (from the `kube::Config`).
    #[must_use]
    pub fn default_namespace(&self) -> &str {
        &self.default_namespace
    }

    /// How many identities are cached (one client each).
    #[must_use]
    pub fn cached(&self) -> usize {
        crate::lock_recover(&self.clients).clients.len()
    }

    /// How many clients this pool has assembled (one per distinct identity, ever).
    ///
    /// The seam that proves the pool does not rebuild its transport per reconcile: it must equal
    /// [`Self::cached`] however often [`Self::client`] is called.
    #[must_use]
    pub fn builds(&self) -> usize {
        self.builds.load(Ordering::SeqCst)
    }

    /// How many HTTP/TLS connectors this pool owns.
    ///
    /// Always exactly one: it is built in [`Self::new`] and every impersonated client clones the
    /// shared handle instead of opening its own (trap T12 / finding H5).
    #[must_use]
    pub fn connectors(&self) -> usize {
        1
    }
}

/// Which identity a pass's cluster access acts as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClusterIdentity {
    /// The controller's own credential: no impersonation headers.
    Controller,
    /// A tenant `ServiceAccount`, resolved in the destination namespace (`T12.3`).
    ServiceAccount(Impersonation),
}

impl fmt::Display for ClusterIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Controller => f.write_str("controller"),
            Self::ServiceAccount(impersonation) => f.write_str(impersonation.user()),
        }
    }
}

/// Everything one reconcile pass uses to talk to the cluster.
///
/// The sync pipeline builds one of these per pass: either over its own seams
/// ([`Self::controller`], the controller identity) or over an impersonated [`Client`]
/// ([`Self::impersonated`]). Both hold `Arc`s, so building one is two atomic increments — the
/// non-impersonated path is byte-for-byte the behaviour it had before `T12.3`.
#[derive(Clone)]
pub struct ClusterAccess {
    identity: ClusterIdentity,
    applier: Arc<dyn Applier>,
    live: Arc<dyn LiveObjectSource>,
    dry_run: Arc<dyn crate::dry_run::DryRunApi>,
    reader: ClusterStateReader,
}

impl fmt::Debug for ClusterAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterAccess")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl ClusterAccess {
    /// Wraps existing seams (the controller identity).
    #[must_use]
    pub fn new(
        identity: ClusterIdentity,
        applier: Arc<dyn Applier>,
        live: Arc<dyn LiveObjectSource>,
        dry_run: Arc<dyn crate::dry_run::DryRunApi>,
    ) -> Self {
        Self {
            identity,
            reader: ClusterStateReader::new(live.clone()),
            applier,
            live,
            dry_run,
        }
    }

    /// Builds the access bundle for an impersonated `kube::Client`.
    ///
    /// Every workload call the sync pipeline makes — live reads, SSA dry-run diffs, applies,
    /// deletes, hook creates — goes through this client, i.e. through the impersonated identity.
    #[must_use]
    pub fn impersonated(client: Client, impersonation: Impersonation) -> Self {
        let live: Arc<dyn LiveObjectSource> = Arc::new(DynamicApiSource::new(client.clone()));
        Self::new(
            ClusterIdentity::ServiceAccount(impersonation),
            Arc::new(DynamicApiApplier::new(client.clone())),
            live,
            Arc::new(DynamicDryRunApi::new(client)),
        )
    }

    /// The identity this pass acts as.
    #[must_use]
    pub fn identity(&self) -> &ClusterIdentity {
        &self.identity
    }

    /// The applier (SSA applies, deletes, hook creates).
    #[must_use]
    pub fn applier(&self) -> &dyn Applier {
        self.applier.as_ref()
    }

    /// The live-state source (scoped GETs).
    #[must_use]
    pub fn live(&self) -> &dyn LiveObjectSource {
        self.live.as_ref()
    }

    /// The live-state reader over [`Self::live`].
    #[must_use]
    pub fn reader(&self) -> &ClusterStateReader {
        &self.reader
    }

    /// The `dryRun=All` diff source.
    #[must_use]
    pub fn dry_run(&self) -> &dyn crate::dry_run::DryRunApi {
        self.dry_run.as_ref()
    }

    /// The `dryRun=All` diff source as a shared handle (`DryRunEvaluator::with_api`).
    #[must_use]
    pub fn dry_run_arc(&self) -> Arc<dyn crate::dry_run::DryRunApi> {
        self.dry_run.clone()
    }
}

/// Builds the cluster access of an impersonated `Application` (`T12.3`).
///
/// The pipeline holds one of these and consults it **after** the `AppProject` policy has
/// authorized the destination: the policy decides *whether* this `ServiceAccount` may be used,
/// this seam decides *how* to reach the cluster as it.
pub trait ImpersonationSource: Send + Sync + 'static {
    /// Returns the access bundle for `impersonation`.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Impersonation`] when the identity cannot be used. Implementations must
    /// **cache** their clients: building a transport per call would leak a connection pool per
    /// reconcile (trap T12).
    fn access_for(&self, impersonation: &Impersonation) -> Result<ClusterAccess, ReconcileError>;
}

/// The production [`ImpersonationSource`]: a shared [`ImpersonationPool`].
pub struct ImpersonatingAccess {
    pool: Arc<ImpersonationPool>,
}

impl fmt::Debug for ImpersonatingAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImpersonatingAccess")
            .field("pool", &self.pool)
            .finish()
    }
}

impl ImpersonatingAccess {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: Arc<ImpersonationPool>) -> Self {
        Self { pool }
    }

    /// The pool this source resolves identities through.
    #[must_use]
    pub fn pool(&self) -> &Arc<ImpersonationPool> {
        &self.pool
    }
}

impl ImpersonationSource for ImpersonatingAccess {
    fn access_for(&self, impersonation: &Impersonation) -> Result<ClusterAccess, ReconcileError> {
        let client = self.pool.client(impersonation)?;
        Ok(ClusterAccess::impersonated(client, impersonation.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use ferriscd_crd::{Application, ApplicationSpec, DestinationSpec, GitSourceSpec, SourceSpec};
    use http::Request;
    use kube::config::Config;
    use tower::{Layer, Service, ServiceExt as _};

    use super::*;

    /// A `kube::Config` with no cluster behind it: building the connector never dials out, which
    /// is exactly what the pool's one-connector property is asserted on.
    fn config() -> Config {
        let mut config = Config::new("https://127.0.0.1:6443".parse().expect("cluster url"));
        config.default_namespace = "ferriscd-system".to_owned();
        config.default_retry = false;
        config
    }

    fn deployer() -> Impersonation {
        Impersonation::for_service_account("payments", "deployer").expect("valid names")
    }

    /// A pool whose per-identity client is a cheap offline stack (no TLS connector, no dialing),
    /// for tests that only assert the cache's bookkeeping.
    fn cheap_pool() -> ImpersonationPool {
        let build: ClientBuilder = Box::new(|_impersonation: &Impersonation| {
            Ok(Client::new(
                tower::service_fn(|_request| async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(Body::empty()))
                }),
                "ferriscd-system",
            ))
        });
        ImpersonationPool {
            build,
            clients: Mutex::new(ClientCache::default()),
            builds: AtomicUsize::new(0),
            default_namespace: "ferriscd-system".to_owned(),
        }
    }

    #[test]
    fn a_service_account_produces_exactly_the_four_impersonation_headers() {
        let impersonation = deployer();
        assert_eq!(
            impersonation.user(),
            "system:serviceaccount:payments:deployer"
        );
        assert_eq!(
            impersonation.groups(),
            [
                "system:serviceaccounts",
                "system:serviceaccounts:payments",
                "system:authenticated",
            ],
            "finding H5: a group-based RoleBinding only works if the groups are impersonated too"
        );

        let headers = impersonation.headers().expect("headers");
        assert_eq!(
            headers
                .get_all(IMPERSONATE_USER_HEADER)
                .iter()
                .map(|value| value.to_str().expect("ascii"))
                .collect::<Vec<_>>(),
            ["system:serviceaccount:payments:deployer"],
            "exactly one Impersonate-User"
        );
        assert_eq!(
            headers
                .get_all(IMPERSONATE_GROUP_HEADER)
                .iter()
                .map(|value| value.to_str().expect("ascii"))
                .collect::<Vec<_>>(),
            [
                "system:serviceaccounts",
                "system:serviceaccounts:payments",
                "system:authenticated",
            ],
            "three Impersonate-Group values, in the documented order"
        );
        assert_eq!(headers.len(), 4, "no other header is injected here");
    }

    /// Trap T12 / finding H5: `system:masters` bypasses authorization, so it must never be
    /// injectable — and the ServiceAccount constructor must never produce it.
    #[test]
    fn system_masters_is_never_impersonated() {
        let err = Impersonation::new(
            "system:serviceaccount:payments:deployer",
            [FORBIDDEN_GROUP.to_owned()],
        )
        .expect_err("system:masters must be refused");
        assert!(
            matches!(err, ImpersonationError::ForbiddenGroup { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains(FORBIDDEN_GROUP), "{err}");

        // ...and no ServiceAccount name can smuggle it in: the groups are derived, not supplied.
        for (namespace, service_account) in [
            ("payments", "deployer"),
            ("system", "masters"),
            ("default", "system-masters"),
        ] {
            let impersonation =
                Impersonation::for_service_account(namespace, service_account).expect("valid");
            assert!(
                !impersonation.has_group(FORBIDDEN_GROUP),
                "{impersonation:?}"
            );
            assert!(
                impersonation
                    .groups()
                    .iter()
                    .all(|group| group != FORBIDDEN_GROUP),
                "{impersonation:?}"
            );
        }
    }

    #[test]
    fn an_application_without_a_service_account_is_not_impersonated() {
        let app = application(None);
        assert_eq!(
            Impersonation::for_application(&app).expect("no impersonation"),
            None,
            "non-impersonated Applications keep the controller identity"
        );

        // A blank name is not a ServiceAccount either (the policy treats it as absent).
        let mut blank = application(Some("   "));
        assert_eq!(Impersonation::for_application(&blank).expect("blank"), None);
        blank.spec.service_account_name = Some(String::new());
        assert_eq!(Impersonation::for_application(&blank).expect("empty"), None);
    }

    #[test]
    fn the_service_account_resolves_in_the_destination_namespace() {
        // A tenant Application in `team-a` deploying into `payments` impersonates the account in
        // `payments` (ADR-007): that is the account its workloads actually run as.
        let mut app = application(Some("deployer"));
        app.metadata.namespace = Some("team-a".to_owned());
        app.spec.destination.namespace = "payments".to_owned();

        let impersonation = Impersonation::for_application(&app)
            .expect("valid")
            .expect("impersonated");
        assert_eq!(
            impersonation.user(),
            "system:serviceaccount:payments:deployer",
            "the ServiceAccount resolves in the destination namespace, never in the tenant's own"
        );
        assert!(impersonation.has_group("system:serviceaccounts:payments"));
        assert!(
            !impersonation.has_group("system:serviceaccounts:team-a"),
            "the Application's own namespace must not leak into the group set"
        );

        // The same name in a different destination namespace is a different identity.
        app.spec.destination.namespace = "payments-staging".to_owned();
        let other = Impersonation::for_application(&app)
            .expect("valid")
            .expect("impersonated");
        assert_ne!(other, impersonation);
        assert!(other.has_group("system:serviceaccounts:payments-staging"));
    }

    #[test]
    fn invalid_names_are_refused_before_a_header_is_built() {
        for service_account in [
            "",
            "Deployer",
            "deployer_1",
            "system:serviceaccount:x",
            "../x",
            "-lead",
            "trail-",
            "with space",
            "with\nnewline",
        ] {
            let err = Impersonation::for_service_account("payments", service_account)
                .expect_err("an invalid ServiceAccount name must be refused");
            assert!(
                matches!(err, ImpersonationError::InvalidServiceAccountName { .. }),
                "{service_account:?} produced {err:?}"
            );
        }
        for namespace in ["", "Payments", "pay_ments", "team-a.", ".team-a", "team..a"] {
            let err = Impersonation::for_service_account(namespace, "deployer")
                .expect_err("an invalid namespace must be refused");
            assert!(
                matches!(err, ImpersonationError::InvalidNamespace { .. }),
                "{namespace:?} produced {err:?}"
            );
        }
        // A dotted ServiceAccount name is a valid subdomain (Kubernetes allows it).
        assert!(Impersonation::for_service_account("team-a", "deployer.v2").is_ok());

        // Arbitrary principals are validated too: the pool never builds a header from raw input.
        for (user, groups) in [
            ("".to_owned(), Vec::new()),
            ("user name".to_owned(), Vec::new()),
            ("user".to_owned(), vec![String::new()]),
            ("user".to_owned(), vec!["\u{0}".to_owned()]),
            ("u".repeat(MAX_IMPERSONATED_NAME_LEN + 1), Vec::new()),
        ] {
            let err = Impersonation::new(user, groups)
                .expect_err("an unusable principal must be refused");
            assert!(
                matches!(err, ImpersonationError::InvalidPrincipal { .. }),
                "{err:?}"
            );
        }

        // Duplicate groups collapse, so a header list is deterministic.
        let deduplicated = Impersonation::new(
            "alice",
            [
                GROUP_AUTHENTICATED.to_owned(),
                GROUP_AUTHENTICATED.to_owned(),
            ],
        )
        .expect("valid");
        assert_eq!(deduplicated.groups(), [GROUP_AUTHENTICATED]);
    }

    // ---------------------------------------------------------------------
    // The tower layer
    // ---------------------------------------------------------------------

    /// A `tower` service that records the headers it received and shares one counter.
    #[derive(Clone, Default)]
    struct RecordingService {
        calls: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<http::HeaderMap>>>,
    }

    impl Service<Request<Body>> for RecordingService {
        type Response = http::Response<Body>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<Body>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            crate::lock_recover(&self.seen).push(request.headers().clone());
            std::future::ready(Ok(http::Response::new(Body::empty())))
        }
    }

    #[tokio::test]
    async fn the_layer_injects_the_identity_and_replaces_a_foreign_one() {
        let recording = RecordingService::default();
        let mut service = ImpersonationLayer::new(&deployer())
            .expect("layer")
            .layer(recording.clone());

        let mut request = Request::builder()
            .uri("https://127.0.0.1:6443/api/v1/namespaces/payments/configmaps")
            .body(Body::empty())
            .expect("request");
        // A kubeconfig `headers` entry (or any other middleware) asked for a different identity.
        request.headers_mut().insert(
            IMPERSONATE_USER_HEADER,
            HeaderValue::from_static("system:admin"),
        );
        request.headers_mut().append(
            IMPERSONATE_GROUP_HEADER,
            HeaderValue::from_static(FORBIDDEN_GROUP),
        );
        // ... and it selected the principal by uid *and* extra attributes, neither of which this
        // layer ever sets: both must be stripped, not passed through (finding M-5).
        request.headers_mut().insert(
            IMPERSONATE_UID_HEADER,
            HeaderValue::from_static("3f2a1c9e-0000-4000-8000-000000000000"),
        );
        request.headers_mut().insert(
            HeaderName::from_static("impersonate-extra-scopes"),
            HeaderValue::from_static("cluster-admin"),
        );

        service
            .ready()
            .await
            .expect("ready")
            .call(request)
            .await
            .expect("call");

        let seen = crate::lock_recover(&recording.seen);
        assert_eq!(seen.len(), 1);
        let headers = &seen[0];
        assert_eq!(
            headers
                .get_all(IMPERSONATE_USER_HEADER)
                .iter()
                .map(|value| value.to_str().expect("ascii"))
                .collect::<Vec<_>>(),
            ["system:serviceaccount:payments:deployer"],
            "the pre-existing identity must be replaced, not appended to"
        );
        assert_eq!(
            headers
                .get_all(IMPERSONATE_GROUP_HEADER)
                .iter()
                .map(|value| value.to_str().expect("ascii"))
                .collect::<Vec<_>>(),
            [
                "system:serviceaccounts",
                "system:serviceaccounts:payments",
                "system:authenticated",
            ],
            "the forbidden group must not survive next to the injected ones"
        );
        assert!(
            !headers.contains_key(IMPERSONATE_UID_HEADER),
            "a foreign Impersonate-Uid must be stripped: {headers:?}"
        );
        assert!(
            headers
                .keys()
                .all(|name| !name.as_str().starts_with(IMPERSONATE_EXTRA_PREFIX)),
            "a foreign Impersonate-Extra-* header must be stripped: {headers:?}"
        );
        assert_eq!(headers.len(), 4, "only the four injected headers survive");
    }

    #[test]
    fn a_layer_without_impersonation_does_not_exist_by_construction() {
        // The only way to build the layer is from a validated `Impersonation`, so there is no
        // "layer with no identity" state that could silently deploy as the controller.
        let impersonation =
            Impersonation::for_service_account("payments", "deployer").expect("valid");
        let layer = ImpersonationLayer::new(&impersonation).expect("layer");
        assert_eq!(layer.headers().len(), 4);
        assert!(
            Impersonation::for_service_account("payments", "")
                .and_then(|impersonation| ImpersonationLayer::new(&impersonation))
                .is_err(),
            "an empty ServiceAccount can never produce a layer"
        );
    }

    // ---------------------------------------------------------------------
    // The pool
    // ---------------------------------------------------------------------

    /// **Trap T12 / finding H5:** the pool owns ONE connector and builds ONE client per identity,
    /// so reconciling (however often) never opens a new TLS pool.
    #[tokio::test]
    async fn the_pool_reuses_one_connector_for_every_identity() {
        let pool = ImpersonationPool::new(&config()).expect("pool");
        assert_eq!(pool.connectors(), 1, "exactly one HTTP/TLS connector");
        assert_eq!(
            pool.builds(),
            0,
            "nothing is built before an identity is used"
        );
        assert_eq!(pool.cached(), 0);

        let deployer = deployer();
        let staging =
            Impersonation::for_service_account("payments-staging", "deployer").expect("valid");

        let first = pool.client(&deployer).expect("client");
        assert_eq!(pool.builds(), 1);
        assert_eq!(pool.cached(), 1);

        // The same identity again: cache hit, no rebuild, still one connector.
        for _ in 0..8 {
            let _ = pool.client(&deployer).expect("cached client");
        }
        assert_eq!(
            pool.builds(),
            1,
            "a repeat reconcile must not rebuild the transport"
        );
        assert_eq!(pool.cached(), 1);
        assert_eq!(pool.connectors(), 1);

        let second = pool.client(&staging).expect("client");
        assert_eq!(pool.builds(), 2, "one build per distinct identity, ever");
        assert_eq!(pool.cached(), 2);
        assert_eq!(pool.connectors(), 1, "both clients share the one connector");

        // Dropping a client must not drop the pool's connector: the next call still hits the cache.
        drop(first);
        drop(second);
        let _ = pool.client(&deployer).expect("client");
        assert_eq!(pool.builds(), 2);
        assert_eq!(pool.default_namespace(), "ferriscd-system");
    }

    /// The cache key is tenant-influenced (`spec.destination.namespace`/`spec.serviceAccountName`),
    /// so it must not grow without bound (finding M2). Eviction drops the *client*, never the one
    /// shared connector.
    #[tokio::test]
    async fn the_identity_cache_is_bounded_and_evicts_the_oldest_entry() {
        let pool = cheap_pool();
        let identities: Vec<Impersonation> = (0..MAX_CACHED_IDENTITIES + 8)
            .map(|index| {
                Impersonation::for_service_account("payments", &format!("deployer-{index}"))
                    .expect("valid ServiceAccount name")
            })
            .collect();

        for identity in &identities {
            pool.client(identity).expect("client");
        }
        assert_eq!(
            pool.builds(),
            identities.len(),
            "one build per distinct identity, however many there are"
        );
        assert_eq!(
            pool.cached(),
            MAX_CACHED_IDENTITIES,
            "the cache must never hold more than its cap ({MAX_CACHED_IDENTITIES})"
        );
        assert_eq!(pool.connectors(), 1, "eviction never opens a new connector");

        // The oldest identities were evicted, so reusing one rebuilds it — and its rebuild evicts
        // the next-oldest entry, so the cache still cannot grow.
        pool.client(&identities[0]).expect("rebuilt client");
        assert_eq!(
            pool.builds(),
            identities.len() + 1,
            "an evicted identity is rebuilt on demand"
        );
        assert_eq!(pool.cached(), MAX_CACHED_IDENTITIES);
        assert_eq!(pool.connectors(), 1);

        // A still-cached (recent) identity does not rebuild.
        let builds = pool.builds();
        pool.client(&identities[identities.len() - 1])
            .expect("cached client");
        assert_eq!(pool.builds(), builds, "recent identities stay cached");
    }

    #[tokio::test]
    async fn a_proxied_configuration_is_refused_instead_of_silently_unproxied() {
        let mut config = config();
        config.proxy_url = Some("http://127.0.0.1:3128".parse().expect("proxy url"));
        let err = ImpersonationPool::new(&config).expect_err("a proxy must be refused");
        assert!(
            matches!(err, ImpersonationError::UnsupportedConfig { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("proxy_url"), "{err}");
    }

    #[tokio::test]
    async fn the_production_source_returns_an_impersonated_access_bundle() {
        let pool = Arc::new(ImpersonationPool::new(&config()).expect("pool"));
        let source = ImpersonatingAccess::new(pool.clone());
        let impersonation = deployer();

        let access = source.access_for(&impersonation).expect("access");
        assert_eq!(
            access.identity(),
            &ClusterIdentity::ServiceAccount(impersonation.clone())
        );
        assert_eq!(access.identity().to_string(), impersonation.user());

        // Every seam of the bundle is wired to the impersonated client, and resolving twice hits
        // the same cached client rather than a second transport.
        let again = source.access_for(&impersonation).expect("access");
        assert_eq!(again.identity(), access.identity());
        assert_eq!(
            source.pool().builds(),
            1,
            "the pool builds once per identity"
        );
        assert_eq!(source.pool().connectors(), 1);
    }

    #[test]
    fn the_controller_identity_is_labelled_for_logs() {
        assert_eq!(ClusterIdentity::Controller.to_string(), "controller");
        assert_eq!(
            ClusterIdentity::ServiceAccount(deployer()).to_string(),
            "system:serviceaccount:payments:deployer"
        );
    }

    fn application(service_account: Option<&str>) -> Application {
        let spec = ApplicationSpec {
            project: ferriscd_crd::DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: service_account.map(str::to_owned),
            source: Some(SourceSpec {
                git: Some(GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "main".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: Default::default(),
            }),
            sources: Vec::new(),
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: 180,
            revision_history_limit: 10,
        };
        let mut app = Application::new("demo", spec);
        app.metadata.namespace = Some("ferriscd-system".to_owned());
        app
    }
}

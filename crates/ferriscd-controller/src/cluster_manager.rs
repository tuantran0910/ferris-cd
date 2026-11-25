//! Secret-based remote cluster registry (`T13.1`).
//!
//! One FerrisCD control plane reconciles `Application`s onto the cluster it runs in
//! (`destination.cluster: in-cluster`) **and** onto remote workload clusters that an operator
//! registers with a `Secret`. This module is the registry:
//!
//! * [`ClusterManager`] holds a `DashMap` of [`ClusterHandle`]s — one per registered cluster — and
//!   always answers `in-cluster` with the control plane's own handle.
//! * A handle owns its [`kube::Client`], its own [`DiscoveryCache`] (the API surface and the
//!   Kubernetes version are per cluster: a remote cluster may run a different minor version, and a
//!   kind the control plane serves may be absent there) and its own
//!   [`ImpersonationPool`](crate::impersonation::ImpersonationPool) — i.e. **one** HTTP/TLS
//!   connector per cluster, shared by every impersonated identity on it (`T12.3`).
//! * [`ClusterSecret`] is the parsed form of a `ferriscd.io/secret-type=cluster` `Secret`: API
//!   server URL, CA bundle, and static auth (bearer token, client certificate, or a full
//!   kubeconfig). Parsing is pure, so every validation rule is unit-testable without a cluster.
//!
//! ## Why the registry is watched, not read per reconcile
//!
//! A `Secret` read on every reconcile would cost one API round trip per pass and would still be
//! stale for the rest of the pass. The registry instead **watches** the labeled `Secret`s — strictly
//! inside the control-plane namespace — rebuilds a handle when its `Secret` changes, and removes it
//! when the `Secret` is deleted. A reconcile then costs a map lookup.
//!
//! The re-list bracketing is part of that contract: Kubernetes delivers no `Delete` for a `Secret`
//! that disappeared while the watch was reconnecting, so a completed list (`InitDone`) — not a
//! delete — is what revokes a registration the list no longer reports (finding H2). Building a
//! handle is asynchronous because loading a CA bundle into a `rustls` store and constructing a
//! `kube::Client` are blocking, and they must never run on a Tokio worker (finding H1).
//!
//! ## Security rules (all enforced by [`ClusterSecret::parse`])
//!
//! | Rule | Why |
//! |---|---|
//! | The `ferriscd.io/secret-type=cluster` label is required | the label is the opt-in: a `Secret` that merely exists in `ferriscd-system` is never used as cluster credentials |
//! | The watch is a *namespaced* `Api<Secret>` | a cluster-wide `Secret` watch would show the controller every secret in the cluster (the `T12.4` trap guard, applied to cluster credentials) |
//! | TLS is verified: `insecureSkipTLSVerify: true` is refused unless the controller was started with the explicit local-dev opt-in | a MITM on the control-plane-to-workload path is a full cluster compromise |
//! | `http://` API servers are refused unless the same opt-in is set | credentials and manifests would travel in the clear |
//! | `exec`/`auth-provider` credentials, `proxy-url`, and path-based (`certificate-authority`, `client-certificate`, `client-key`, `tokenFile`) kubeconfig fields are refused | those make the controller run a binary or read a pod file chosen by whoever can write the `Secret` |
//! | `in-cluster` is a reserved name | it would shadow the control plane's own identity |
//! | No error, log line, or `Debug` impl carries a token, key, or certificate body | `/status` is readable by anyone allowed to `get` the `Application` |
//!
//! ## Credentials on the remote cluster
//!
//! The controller authenticates to a remote cluster **as the credential in the `Secret`**, then
//! impersonates `Application.spec.serviceAccountName` there exactly as it does in-cluster. The
//! remote binding for that credential therefore needs the same `impersonate` verbs the in-cluster
//! one does (`users`, `groups`, `serviceaccounts`) plus the workload verbs `AppProject` allows; see
//! `deploy/README.md`. The `Application`'s own `/status` and finalizer always stay on the **control
//! plane** — the remote credential is never asked to write a FerrisCD CR the remote cluster may not
//! even serve.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use ferriscd_crd::CONTROL_PLANE_NAMESPACE;
use ferriscd_engine::manifest::redact_repo_url;
use futures::StreamExt;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::config::Kubeconfig;
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client, ResourceExt};
use tokio_util::sync::CancellationToken;

use crate::credentials::SECRET_TYPE_LABEL;
use crate::discovery::DiscoveryCache;
use crate::dry_run::DynamicDryRunApi;
use crate::impersonation::{ImpersonatingAccess, ImpersonationPool, ImpersonationSource};
use crate::live_state::DynamicApiSource;
use crate::reconcile::ReconcileError;
use crate::sync::DynamicApiApplier;
use crate::{ClusterAccess, ClusterIdentity};

/// Label value selecting a cluster-registration `Secret`.
pub const SECRET_TYPE_CLUSTER: &str = "cluster";

/// The destination cluster name every `Application` uses to mean "the cluster the controller runs
/// in" (the `ferriscd.io/v1alpha1` `destination.cluster` default).
pub const IN_CLUSTER: &str = ferriscd_crd::application::DEFAULT_DESTINATION_CLUSTER;

/// `Secret` key holding the remote API server URL (`https://host:port`).
pub const KEY_SERVER: &str = "server";

/// `Secret` key holding the CA bundle the API server's certificate must chain to.
pub const KEY_CA_CRT: &str = "ca.crt";

/// `Secret` key holding a bearer token.
pub const KEY_BEARER_TOKEN: &str = "bearerToken";

/// `Secret` key holding the client certificate (PEM).
pub const KEY_TLS_CRT: &str = "tls.crt";

/// `Secret` key holding the client private key (PEM, unencrypted).
pub const KEY_TLS_KEY: &str = "tls.key";

/// `Secret` key holding a complete kubeconfig document.
pub const KEY_KUBECONFIG: &str = "kubeconfig";

/// `Secret` key holding `true` to disable TLS verification (refused unless opted in).
pub const KEY_INSECURE_SKIP_TLS_VERIFY: &str = "insecureSkipTLSVerify";

/// `Secret` key overriding the cluster name (defaults to the `Secret`'s own name).
pub const KEY_NAME: &str = "name";

/// `Secret` key overriding the default namespace of the remote cluster.
pub const KEY_NAMESPACE: &str = "namespace";

/// A validated cluster name.
///
/// Kubernetes resource names stay RFC 1123 subdomains, so the name that appears in
/// `spec.destination.cluster` and the name of the `Secret` that defines it are validated the same
/// way. [`IN_CLUSTER`] is reserved and can never be registered.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClusterName(String);

impl ClusterName {
    /// Longest valid RFC 1123 subdomain.
    const MAX_LEN: usize = 253;

    /// Validates `name`.
    ///
    /// # Errors
    ///
    /// [`ClusterError::InvalidName`] for an empty, over-long, or non-DNS name, and
    /// [`ClusterError::ReservedName`] for [`IN_CLUSTER`].
    pub fn parse(name: &str) -> Result<Self, ClusterError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ClusterError::InvalidName {
                name: String::new(),
                reason: "the cluster name is empty".to_owned(),
            });
        }
        if name == IN_CLUSTER {
            return Err(ClusterError::ReservedName {
                name: name.to_owned(),
            });
        }
        if name.len() > Self::MAX_LEN {
            return Err(ClusterError::InvalidName {
                name: name.to_owned(),
                reason: format!("a cluster name is at most {} characters", Self::MAX_LEN),
            });
        }
        let valid = name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
        if !valid {
            return Err(ClusterError::InvalidName {
                name: name.to_owned(),
                reason: "a cluster name must be an RFC 1123 subdomain (lowercase alphanumerics, \
                         '-' and '.', and must not start or end with '-')"
                    .to_owned(),
            });
        }
        Ok(Self(name.to_owned()))
    }

    /// The reserved [`IN_CLUSTER`] name.
    ///
    /// Only the control plane's own handle is ever built with it: [`Self::parse`] refuses the name
    /// for a registration, so a `Secret` can never claim it.
    #[must_use]
    pub fn in_cluster() -> Self {
        Self(IN_CLUSTER.to_owned())
    }

    /// Whether this is the control plane's own cluster.
    #[must_use]
    pub fn is_in_cluster(&self) -> bool {
        self.0 == IN_CLUSTER
    }

    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClusterName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ClusterName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// How the controller authenticates to a remote cluster.
///
/// Static credentials only: no `exec` plugin, no `auth-provider`, no pod-local file paths. Whoever
/// can write a `Secret` in the control-plane namespace can already choose the credential, but they
/// must not be able to make the controller *run a binary* or *read a file* with it.
#[derive(Clone, PartialEq, Eq)]
pub enum ClusterAuth {
    /// A bearer token.
    BearerToken(String),
    /// A client certificate and its unencrypted private key (PEM).
    ClientCertificate {
        /// PEM-encoded certificate chain.
        certificate: Vec<u8>,
        /// PEM-encoded private key.
        key: Vec<u8>,
    },
    /// A complete kubeconfig document, validated on every use.
    Kubeconfig(String),
}

impl fmt::Debug for ClusterAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Trap T4: a token, a key, or a kubeconfig body is secret material.
        match self {
            Self::BearerToken(_) => f.write_str("BearerToken(<redacted>)"),
            Self::ClientCertificate { .. } => f.write_str("ClientCertificate(<redacted>)"),
            Self::Kubeconfig(_) => f.write_str("Kubeconfig(<redacted>)"),
        }
    }
}

/// TLS policy for cluster registrations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClusterOptions {
    /// Accept `insecureSkipTLSVerify: true` and plaintext `http://` API servers.
    ///
    /// Only ever set from the explicit local-dev flag: both settings let anything on the path read
    /// and rewrite every manifest FerrisCD applies.
    pub allow_insecure: bool,
}

impl ClusterOptions {
    /// Strict TLS verification (the production default).
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Local-dev opt-in for `insecureSkipTLSVerify` / `http://`.
    #[must_use]
    pub fn allowing_insecure() -> Self {
        Self {
            allow_insecure: true,
        }
    }
}

/// The parsed contents of one `ferriscd.io/secret-type=cluster` `Secret`.
///
/// Holds credential material, so its `Debug` reports only *what kind* of auth it carries
/// (trap T4). Equality is structural, which is exactly what [`ClusterManager`] compares to decide
/// whether a changed `Secret` needs a new handle.
#[derive(Clone, PartialEq, Eq)]
pub struct ClusterSecret {
    name: ClusterName,
    /// Name of the `Secret` the material came from.
    secret: String,
    /// Namespace of that `Secret` (the control-plane namespace).
    namespace: String,
    server: Option<String>,
    ca_cert: Option<Vec<u8>>,
    auth: ClusterAuth,
    insecure_skip_tls_verify: bool,
    default_namespace: Option<String>,
}

impl fmt::Debug for ClusterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterSecret")
            .field("name", &self.name)
            .field("secret", &self.secret_id())
            // An API server URL is written like a repository URL and routinely carries userinfo
            // (`https://user:token@api.example.com:6443`), so it goes through the shared redaction
            // helper here too (finding M-new-2): a `Debug` line lands in the controller's logs.
            .field("server", &self.server.as_deref().map(redact_repo_url))
            .field("ca_cert", &self.ca_cert.as_ref().map(|_| "<redacted>"))
            .field("auth", &self.auth)
            .field("insecure_skip_tls_verify", &self.insecure_skip_tls_verify)
            .field("default_namespace", &self.default_namespace)
            .finish()
    }
}

impl ClusterSecret {
    /// Parses a cluster-registration `Secret`.
    ///
    /// # Errors
    ///
    /// [`ClusterError::NotAClusterSecret`] when the `Secret` is not labeled
    /// `ferriscd.io/secret-type=cluster`, and every other [`ClusterError`] variant for material
    /// that cannot be used safely. No variant carries a secret value.
    pub fn parse(secret: &Secret, options: ClusterOptions) -> Result<Self, ClusterError> {
        let secret_name = secret.name_any();
        let namespace = secret
            .namespace()
            .unwrap_or_else(|| CONTROL_PLANE_NAMESPACE.to_owned());
        let context = SecretContext {
            secret: &secret_name,
            namespace: &namespace,
        };

        if !is_cluster_secret(secret) {
            return Err(ClusterError::NotAClusterSecret {
                secret: secret_name,
                namespace,
            });
        }

        // The cluster name is the `Secret`'s own name unless it overrides it: rotating credentials
        // by replacing the `Secret` then keeps the name that `spec.destination.cluster` refers to.
        let raw_name = data_value(secret, KEY_NAME)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| secret_name.clone());
        let name = ClusterName::parse(&raw_name)?;

        let insecure_skip_tls_verify = match data_value(secret, KEY_INSECURE_SKIP_TLS_VERIFY) {
            Some(value) => parse_bool(&value).ok_or_else(|| {
                context.invalid(format!(
                    "the {KEY_INSECURE_SKIP_TLS_VERIFY:?} key must be \"true\" or \"false\""
                ))
            })?,
            None => false,
        };
        if insecure_skip_tls_verify && !options.allow_insecure {
            return Err(ClusterError::InsecureTls {
                secret: context.secret.to_owned(),
                namespace: context.namespace.to_owned(),
            });
        }

        let kubeconfig =
            data_value(secret, KEY_KUBECONFIG).filter(|value| !value.trim().is_empty());
        let server = data_value(secret, KEY_SERVER).filter(|value| !value.trim().is_empty());
        let token = data_value(secret, KEY_BEARER_TOKEN).filter(|value| !value.trim().is_empty());
        let certificate = secret_bytes(secret, KEY_TLS_CRT);
        let key = secret_bytes(secret, KEY_TLS_KEY);

        let auth = match (kubeconfig, &server) {
            // A full kubeconfig is self-contained; mixing it with the explicit keys would make the
            // effective credential depend on which key a future version reads first.
            (Some(kubeconfig), _) => {
                if server.is_some() || token.is_some() || certificate.is_some() || key.is_some() {
                    return Err(context.invalid(format!(
                        "the Secret carries {KEY_KUBECONFIG:?} together with \
                         {KEY_SERVER:?}/{KEY_BEARER_TOKEN:?}/{KEY_TLS_CRT:?}/{KEY_TLS_KEY:?}; keep \
                         either the kubeconfig or the explicit keys, never both"
                    )));
                }
                ClusterAuth::Kubeconfig(kubeconfig)
            }
            (None, None) => {
                return Err(context.invalid(format!(
                    "the Secret carries no API server: set {KEY_SERVER:?} (or a full \
                     {KEY_KUBECONFIG:?})"
                )));
            }
            (None, Some(server)) => {
                validate_server(&context, server, options)?;
                match (token, certificate, key) {
                    (Some(token), None, None) => ClusterAuth::BearerToken(token),
                    (None, Some(certificate), Some(key)) => {
                        ClusterAuth::ClientCertificate { certificate, key }
                    }
                    (None, Some(_), None) => {
                        return Err(context.invalid(format!(
                            "the Secret carries {KEY_TLS_CRT:?} without {KEY_TLS_KEY:?}"
                        )));
                    }
                    (None, None, Some(_)) => {
                        return Err(context.invalid(format!(
                            "the Secret carries {KEY_TLS_KEY:?} without {KEY_TLS_CRT:?}"
                        )));
                    }
                    (Some(_), _, _) => {
                        return Err(context.invalid(format!(
                            "the Secret carries {KEY_BEARER_TOKEN:?} together with client \
                             certificate keys; use one of them"
                        )));
                    }
                    (None, None, None) => {
                        return Err(context.invalid(format!(
                            "the Secret carries no credentials: set {KEY_BEARER_TOKEN:?} or both \
                             {KEY_TLS_CRT:?} and {KEY_TLS_KEY:?} (or a full {KEY_KUBECONFIG:?})"
                        )));
                    }
                }
            }
        };

        let parsed = Self {
            name,
            secret: secret_name,
            namespace,
            server,
            ca_cert: secret_bytes(secret, KEY_CA_CRT),
            auth,
            insecure_skip_tls_verify,
            default_namespace: data_value(secret, KEY_NAMESPACE).filter(|value| !value.is_empty()),
        };
        // Validate eagerly, so a `Secret` that cannot produce a client is rejected when it is
        // seeded instead of on the first `Application` that names it.
        parsed.kube_config(options)?;
        Ok(parsed)
    }

    /// The cluster name this registration defines.
    #[must_use]
    pub fn name(&self) -> &ClusterName {
        &self.name
    }

    /// `<namespace>/<secret-name>` of the `Secret` this came from.
    #[must_use]
    pub fn secret_id(&self) -> String {
        format!("{}/{}", self.namespace, self.secret)
    }

    /// The configured API server URL (`None` when the kubeconfig supplies it).
    #[must_use]
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// Whether TLS verification is disabled (only possible with [`ClusterOptions::allow_insecure`]).
    #[must_use]
    pub fn insecure_skip_tls_verify(&self) -> bool {
        self.insecure_skip_tls_verify
    }

    /// The auth kind this registration uses (a stable label, never a value).
    #[must_use]
    pub fn auth_kind(&self) -> &'static str {
        match self.auth {
            ClusterAuth::BearerToken(_) => "bearer-token",
            ClusterAuth::ClientCertificate { .. } => "client-certificate",
            ClusterAuth::Kubeconfig(_) => "kubeconfig",
        }
    }

    /// The default namespace of the remote cluster, when the registration sets one.
    #[must_use]
    pub fn default_namespace(&self) -> Option<&str> {
        self.default_namespace.as_deref()
    }

    /// Builds the `kube::Config` (and therefore the credential) for this registration.
    ///
    /// Pure: every credential is held in memory, so nothing here reads a file or opens a socket.
    ///
    /// # Errors
    ///
    /// [`ClusterError::MalformedKubeconfig`] when the material cannot produce a usable
    /// configuration, [`ClusterError::UnsupportedKubeconfig`] for the field kinds the manager
    /// refuses to honour, and [`ClusterError::InsecureTls`] when the resulting configuration would
    /// skip verification without the opt-in.
    pub fn kube_config(&self, options: ClusterOptions) -> Result<kube::Config, ClusterError> {
        let kubeconfig = self.kubeconfig(options)?;
        let mut config = kube::Config::try_from(kubeconfig).map_err(|err| {
            ClusterError::MalformedKubeconfig {
                secret: self.secret.clone(),
                namespace: self.namespace.clone(),
                reason: crate::reconcile::bounded(&err.to_string()),
            }
        })?;
        if config.accept_invalid_certs && !options.allow_insecure {
            return Err(ClusterError::InsecureTls {
                secret: self.secret.clone(),
                namespace: self.namespace.clone(),
            });
        }
        if let Some(namespace) = &self.default_namespace {
            config.default_namespace.clone_from(namespace);
        }
        // Never inherit the controller pod's ambient `HTTPS_PROXY` (kube reads it while loading a
        // kubeconfig): routing workload traffic through an unconfigured proxy is both a footgun and
        // a data-egress path. Cluster traffic is direct, always.
        config.proxy_url = None;
        Ok(config)
    }

    /// Parses the kubeconfig this registration carries, synthesizing one from the explicit keys
    /// when needed, and validates the field kinds the manager refuses to honour.
    fn kubeconfig(&self, options: ClusterOptions) -> Result<Kubeconfig, ClusterError> {
        let document = match &self.auth {
            ClusterAuth::Kubeconfig(document) => document.clone(),
            ClusterAuth::BearerToken(_) | ClusterAuth::ClientCertificate { .. } => {
                self.synthesized_kubeconfig()?
            }
        };
        // The document is written by whoever can create a `Secret`, so it goes through the engine's
        // YAML budgets and alias-replay limits: a billion-laughs bomb here would expand on the
        // watch task that observed it (finding M4). The refusal is content-free — a parser message
        // can quote the line it choked on, and that line may be the token or the private key.
        let kubeconfig: Kubeconfig =
            ferriscd_engine::manifest::parse_document(&document).map_err(|err| {
                ClusterError::MalformedKubeconfig {
                    secret: self.secret.clone(),
                    namespace: self.namespace.clone(),
                    reason: format!("the kubeconfig {err}"),
                }
            })?;
        validate_kubeconfig(self, &kubeconfig, options)?;
        Ok(kubeconfig)
    }

    /// Builds a kubeconfig document from the explicit `server`/`ca.crt`/auth keys.
    ///
    /// The document is assembled with JSON-escaped scalars (`serde_json::to_string` produces a
    /// valid YAML 1.2 double-quoted scalar), so a token that contains `:`, `#`, or a newline can
    /// never break out of its value and inject another field.
    fn synthesized_kubeconfig(&self) -> Result<String, ClusterError> {
        let server = self.server.as_deref().ok_or_else(|| {
            self.invalid(format!(
                "the {KEY_SERVER:?} key is required for token or client-certificate credentials"
            ))
        })?;
        let escape = |value: &str| {
            serde_json::to_string(value).map_err(|err| ClusterError::MalformedKubeconfig {
                secret: self.secret.clone(),
                namespace: self.namespace.clone(),
                reason: crate::reconcile::bounded(&err.to_string()),
            })
        };

        let mut document = String::from(
            "apiVersion: v1\nkind: Config\ncurrent-context: ferriscd\nclusters:\n- name: ferriscd\n  cluster:\n",
        );
        document.push_str(&format!("    server: {}\n", escape(server)?));
        if let Some(ca) = &self.ca_cert {
            document.push_str(&format!(
                "    certificate-authority-data: {}\n",
                base64_encode(ca)
            ));
        }
        if self.insecure_skip_tls_verify {
            document.push_str("    insecure-skip-tls-verify: true\n");
        }
        let namespace = self.default_namespace.as_deref().unwrap_or("default");
        document.push_str("contexts:\n- name: ferriscd\n  context:\n    cluster: ferriscd\n");
        document.push_str(&format!(
            "    user: ferriscd\n    namespace: {}\n",
            escape(namespace)?
        ));
        document.push_str("users:\n- name: ferriscd\n  user:\n");
        match &self.auth {
            ClusterAuth::BearerToken(token) => {
                document.push_str(&format!("    token: {}\n", escape(token)?));
            }
            ClusterAuth::ClientCertificate { certificate, key } => {
                document.push_str(&format!(
                    "    client-certificate-data: {}\n",
                    base64_encode(certificate)
                ));
                document.push_str(&format!("    client-key-data: {}\n", base64_encode(key)));
            }
            ClusterAuth::Kubeconfig(_) => {}
        }
        Ok(document)
    }

    /// A secret-free error for unusable contents.
    fn invalid(&self, reason: String) -> ClusterError {
        ClusterError::Malformed {
            secret: self.secret.clone(),
            namespace: self.namespace.clone(),
            reason,
        }
    }
}

/// The `Secret` a parse error belongs to, so messages name it without repeating the plumbing.
struct SecretContext<'a> {
    secret: &'a str,
    namespace: &'a str,
}

impl SecretContext<'_> {
    /// A secret-free error for unusable contents.
    fn invalid(&self, reason: String) -> ClusterError {
        ClusterError::Malformed {
            secret: self.secret.to_owned(),
            namespace: self.namespace.to_owned(),
            reason,
        }
    }
}

/// Problems with a cluster registration or a cluster lookup.
///
/// Every variant is **terminal**: a `Secret` the controller does not write can only be fixed by an
/// operator, and pretending a remote cluster is reachable would apply manifests to the wrong place.
/// No variant carries a credential value.
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    /// The `Secret` is not labeled `ferriscd.io/secret-type=cluster`.
    #[error(
        "Secret {secret} in namespace {namespace:?} is not a cluster registration: it must be \
         labeled {SECRET_TYPE_LABEL}={SECRET_TYPE_CLUSTER}"
    )]
    NotAClusterSecret {
        /// Name of the `Secret`.
        secret: String,
        /// Namespace it was read from.
        namespace: String,
    },

    /// The configured cluster name is not a usable identifier.
    #[error("cluster name {name:?} is invalid: {reason}")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// What is wrong with it.
        reason: String,
    },

    /// The reserved [`IN_CLUSTER`] name was used for a registration.
    #[error(
        "cluster name {name:?} is reserved: it always means the cluster the controller runs in, so \
         a Secret cannot define it"
    )]
    ReservedName {
        /// The reserved name.
        name: String,
    },

    /// A cluster registration `Secret` cannot be used.
    #[error("cluster Secret {secret} in namespace {namespace:?} cannot be used: {reason}")]
    Malformed {
        /// Name of the offending `Secret`.
        secret: String,
        /// Namespace it was read from (the control-plane namespace).
        namespace: String,
        /// Actionable, secret-free description.
        reason: String,
    },

    /// The registration asks for TLS verification to be skipped.
    #[error(
        "cluster Secret {secret} in namespace {namespace:?} sets {KEY_INSECURE_SKIP_TLS_VERIFY} or a \
         plaintext http:// API server; refusing, because TLS verification is what stops anything on \
         the control-plane-to-workload path from reading and rewriting every manifest (set the \
         local-dev opt-in only on a throwaway cluster)"
    )]
    InsecureTls {
        /// Name of the offending `Secret`.
        secret: String,
        /// Namespace it was read from.
        namespace: String,
    },

    /// The kubeconfig cannot be turned into a client configuration.
    #[error(
        "cluster Secret {secret} in namespace {namespace:?} has an unusable kubeconfig: {reason}"
    )]
    MalformedKubeconfig {
        /// Name of the offending `Secret`.
        secret: String,
        /// Namespace it was read from.
        namespace: String,
        /// Actionable, secret-free description.
        reason: String,
    },

    /// The kubeconfig carries a field kind FerrisCD refuses to honour.
    #[error(
        "cluster Secret {secret} in namespace {namespace:?} uses {field}, which FerrisCD does not \
         honour for a remote cluster: supply static credentials ({KEY_BEARER_TOKEN:?}, \
         {KEY_TLS_CRT:?}/{KEY_TLS_KEY:?}, or a kubeconfig with a token or client certificate)"
    )]
    UnsupportedKubeconfig {
        /// Name of the offending `Secret`.
        secret: String,
        /// Namespace it was read from.
        namespace: String,
        /// The refusing field (`exec`, `auth-provider`, `proxy-url`, a certificate *path*, ...).
        field: String,
    },

    /// The credential material cannot build an HTTP/TLS client.
    #[error(
        "cluster Secret {secret} in namespace {namespace:?} cannot build a client: {reason} (an \
         unparseable CA bundle or client key lands here)"
    )]
    Transport {
        /// Name of the offending `Secret`.
        secret: String,
        /// Namespace it was read from.
        namespace: String,
        /// The underlying failure, redacted.
        reason: String,
    },

    /// No registration exists for the requested cluster name.
    #[error(
        "destination cluster {cluster:?} is not registered: no {SECRET_TYPE_LABEL}={SECRET_TYPE_CLUSTER} \
         Secret in namespace {namespace:?} defines it (only {IN_CLUSTER:?} is always available)"
    )]
    NotFound {
        /// The requested cluster name.
        cluster: String,
        /// The namespace registrations are read from.
        namespace: String,
    },
}

impl ClusterError {
    /// Whether the error can never be fixed by retrying.
    ///
    /// Always `true`: every variant is a configuration problem or a missing registration.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        true
    }

    /// Whether the failure is "this cluster is not registered (any more)".
    ///
    /// The cleanup path uses this to release the finalizer instead of wedging a deleted
    /// `Application` in `Terminating` (finding C5).
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Whether the failure is a **blank** destination cluster name — a spec typo, never a
    /// registration.
    ///
    /// `serde(default)` already covers the omitted field (finding M11), so a blank
    /// `spec.destination.cluster` is an authoring mistake: no `Secret` can ever register it. The
    /// cleanup path treats it like a missing registration (finding M-new-1) — otherwise a deleted
    /// `Application` with a blank destination would sit in `Terminating` forever, because
    /// [`Self::InvalidName`] is not [`Self::is_not_found`].
    #[must_use]
    pub fn is_blank_cluster_name(&self) -> bool {
        matches!(self, Self::InvalidName { name, .. } if name.trim().is_empty())
    }

    /// Whether the failure means "there is nothing to clean up with".
    ///
    /// Combines [`Self::is_not_found`] and [`Self::is_blank_cluster_name`]: both release the
    /// finalizer with a warning instead of retaining it (findings C5, M-new-1).
    #[must_use]
    pub fn blocks_cleanup(&self) -> bool {
        self.is_not_found() || self.is_blank_cluster_name()
    }
}

/// Whether `secret` opts in as a cluster registration.
#[must_use]
pub fn is_cluster_secret(secret: &Secret) -> bool {
    secret
        .labels()
        .get(SECRET_TYPE_LABEL)
        .is_some_and(|value| value.trim() == SECRET_TYPE_CLUSTER)
}

/// Everything one cluster contributes to a reconcile pass.
///
/// The pipeline resolves one of these per pass: a remote cluster's own [`DiscoveryCache`] and
/// client seams, or the control plane's. The `Application`'s `/status` and finalizer never go
/// through it — they always stay on the control plane.
#[derive(Clone)]
pub struct ClusterTarget {
    name: String,
    discovery: DiscoveryCache,
    access: ClusterAccess,
    impersonation: Option<Arc<dyn ImpersonationSource>>,
}

impl fmt::Debug for ClusterTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterTarget")
            .field("name", &self.name)
            .field("discovery", &self.discovery)
            .field("identity", &self.access.identity())
            .field("impersonation", &self.impersonation.is_some())
            .finish()
    }
}

impl ClusterTarget {
    /// Builds a target from already-resolved seams.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        discovery: DiscoveryCache,
        access: ClusterAccess,
        impersonation: Option<Arc<dyn ImpersonationSource>>,
    ) -> Self {
        Self {
            name: name.into(),
            discovery,
            access,
            impersonation,
        }
    }

    /// The cluster this target points at.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The discovery cache of this cluster (scopes and `kube_version` are per cluster).
    #[must_use]
    pub fn discovery(&self) -> &DiscoveryCache {
        &self.discovery
    }

    /// The pass's cluster access as the controller's credential.
    #[must_use]
    pub fn access(&self) -> &ClusterAccess {
        &self.access
    }

    /// How to reach this cluster as an `Application`'s `ServiceAccount`, if impersonation is wired.
    #[must_use]
    pub fn impersonation(&self) -> Option<&Arc<dyn ImpersonationSource>> {
        self.impersonation.as_ref()
    }
}

/// Resolves a `spec.destination.cluster` name to the seams one pass needs.
///
/// The pipeline consults this **after** the `AppProject` policy authorized the destination, so a
/// tenant can only ever probe cluster names its project lists.
pub trait ClusterSource: Send + Sync + 'static {
    /// Returns the target for `name`.
    ///
    /// # Errors
    ///
    /// [`ClusterError::NotFound`] (terminal) when nothing registers `name`.
    fn target(&self, name: &str) -> Result<ClusterTarget, ReconcileError>;
}

/// One registered cluster: its client, its discovery cache, and its one shared connector.
pub struct ClusterHandle {
    name: ClusterName,
    client: Client,
    discovery: DiscoveryCache,
    base_connector: Arc<ImpersonationPool>,
    impersonation: Arc<dyn ImpersonationSource>,
}

impl fmt::Debug for ClusterHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterHandle")
            .field("name", &self.name)
            .field("discovery", &self.discovery)
            .field("base_connector", &self.base_connector)
            .field("impersonation", &true)
            .finish()
    }
}

impl ClusterHandle {
    /// Wraps a client, its discovery cache and its one shared connector.
    ///
    /// `base_connector` is the per-cluster [`ImpersonationPool`]: every impersonated identity on
    /// this cluster is a middleware stack over that single HTTP/TLS connector (`T12.3`, trap T12).
    #[must_use]
    pub fn new(
        name: ClusterName,
        client: Client,
        discovery: DiscoveryCache,
        base_connector: Arc<ImpersonationPool>,
    ) -> Self {
        let impersonation: Arc<dyn ImpersonationSource> =
            Arc::new(ImpersonatingAccess::new(base_connector.clone()));
        Self {
            name,
            client,
            discovery,
            base_connector,
            impersonation,
        }
    }

    /// Replaces the impersonation seam (tests, and a cluster that must not impersonate).
    #[must_use]
    pub fn with_impersonation_source(mut self, source: Arc<dyn ImpersonationSource>) -> Self {
        self.impersonation = source;
        self
    }

    /// The cluster name.
    #[must_use]
    pub fn name(&self) -> &ClusterName {
        &self.name
    }

    /// The client every workload call on this cluster goes through.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// This cluster's discovery cache.
    #[must_use]
    pub fn discovery(&self) -> &DiscoveryCache {
        &self.discovery
    }

    /// The one HTTP/TLS connector this cluster's impersonated clients share.
    #[must_use]
    pub fn base_connector(&self) -> &Arc<ImpersonationPool> {
        &self.base_connector
    }

    /// The pass-scoped view of this cluster.
    ///
    /// Every call is an `Arc` clone: live reads, `dryRun=All` diffs, applies, deletes, hook creates
    /// and prunes all run over **this** cluster's client.
    #[must_use]
    pub fn target(&self) -> ClusterTarget {
        let access = ClusterAccess::new(
            ClusterIdentity::Controller,
            Arc::new(DynamicApiApplier::new(self.client.clone())),
            Arc::new(DynamicApiSource::new(self.client.clone())),
            Arc::new(DynamicDryRunApi::new(self.client.clone())),
        );
        ClusterTarget::new(
            self.name.as_str().to_owned(),
            self.discovery.clone(),
            access,
            Some(self.impersonation.clone()),
        )
    }
}

/// Builds a [`ClusterHandle`] from parsed material.
///
/// The seam exists so the registry's add/change/delete behaviour is testable without a cluster:
/// production uses [`KubeClusterBuilder`], tests use a fake that never dials out.
pub trait ClusterHandleBuilder: Send + Sync + 'static {
    /// Builds the handle for `material`.
    ///
    /// **Asynchronous on purpose** (finding H1). Building the handle means loading the CA bundle
    /// into a `rustls` certificate store and constructing a `kube::Client` — both blocking, and
    /// both driven by a `Secret` an operator can write. Doing that inline would stall a Tokio
    /// worker (and the watch loop, and every reconcile on it) for the duration of the file and
    /// CPU work; [`KubeClusterBuilder`] therefore returns a future that hands the blocking half to
    /// `tokio::task::spawn_blocking`.
    ///
    /// The future still needs a Tokio runtime (a `kube::Client` owns a buffer worker task), and it
    /// performs no network I/O: all credential material is already in memory.
    ///
    /// # Errors
    ///
    /// [`ClusterError`] when the material cannot build a client.
    fn build<'a>(
        &'a self,
        material: &'a ClusterSecret,
    ) -> BoxFuture<'a, Result<ClusterHandle, ClusterError>>;
}

/// The production [`ClusterHandleBuilder`].
#[derive(Debug, Clone, Copy, Default)]
pub struct KubeClusterBuilder {
    options: ClusterOptions,
}

impl KubeClusterBuilder {
    /// Builds handles under `options` (the TLS policy).
    #[must_use]
    pub fn new(options: ClusterOptions) -> Self {
        Self { options }
    }

    /// The blocking half of [`ClusterHandleBuilder::build`]: TLS certificate loading and client
    /// construction.
    ///
    /// Never call this from an async task (finding H1): [`ImpersonationPool::new`] loads the CA
    /// bundle into a `rustls` certificate store and [`Client::try_from`] builds the tower stack.
    /// It is only ever reached through [`Self::offload`].
    fn build_blocking(
        config: kube::Config,
        name: ClusterName,
        secret: String,
        namespace: String,
    ) -> Result<ClusterHandle, ClusterError> {
        // Finding H1's proof, recorded *inside* the blocking half: if a future change inlined this
        // function into `build`, the recorded thread would be the async worker's and the test below
        // fails. Recording it from the caller's side would prove nothing.
        #[cfg(test)]
        record_blocking_thread();
        let transport_error = |reason: &dyn fmt::Display| ClusterError::Transport {
            secret: secret.clone(),
            namespace: namespace.clone(),
            reason: crate::reconcile::bounded(&reason.to_string()),
        };
        let pool = ImpersonationPool::new(&config).map_err(|err| transport_error(&err))?;
        let client = Client::try_from(config).map_err(|err| transport_error(&err))?;
        let discovery = DiscoveryCache::new(client.clone());
        Ok(ClusterHandle::new(name, client, discovery, Arc::new(pool)))
    }

    /// Runs `work` on a blocking worker, mapping a panicking worker to a redacted error.
    ///
    /// The single place this module moves blocking work off the async workers, so the registry
    /// never stalls a Tokio worker while a certificate store is built (finding H1). When `work`
    /// panics the join error is reported as a terminal [`ClusterError::Transport`]: a panic in the
    /// blocking pool must still leave the registry consistent, and must not take the controller
    /// down.
    async fn offload<T, F>(secret: String, namespace: String, work: F) -> Result<T, ClusterError>
    where
        F: FnOnce() -> Result<T, ClusterError> + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|err| ClusterError::Transport {
                secret,
                namespace,
                reason: crate::reconcile::bounded(&err.to_string()),
            })?
    }
}

impl ClusterHandleBuilder for KubeClusterBuilder {
    fn build<'a>(
        &'a self,
        material: &'a ClusterSecret,
    ) -> BoxFuture<'a, Result<ClusterHandle, ClusterError>> {
        Box::pin(async move {
            // The pure half stays on this side: `kube_config` only assembles an in-memory
            // `kube::Config` (no file, no socket), and *moving* that config into the blocking task
            // means the credential material is never copied.
            let config = material.kube_config(self.options)?;
            let name = material.name.clone();
            let secret = material.secret.clone();
            let namespace = material.namespace.clone();
            let worker_secret = secret.clone();
            let worker_namespace = namespace.clone();
            Self::offload(secret, namespace, move || {
                Self::build_blocking(config, name, worker_secret, worker_namespace)
            })
            .await
        })
    }
}

/// What seeding one `Secret` did to the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterChange {
    /// The cluster was not registered before.
    Added,
    /// The `Secret` changed and the handle was rebuilt.
    Rebuilt,
    /// The material is unchanged, so the existing handle (and its connector) was reused.
    Unchanged,
}

/// The registry of remote clusters plus the control plane's own handle.
///
/// `handles` is exactly the `DashMap<ClusterName, Arc<ClusterHandle>>` the milestone specifies;
/// `materials` holds the parsed `Secret` each handle was built from, so an unchanged `Secret` never
/// rebuilds a connector and a changed one always does. Both maps are only ever written through
/// [`Self::store`] / [`Self::remove`], so they cannot drift apart.
pub struct ClusterManager {
    handles: DashMap<ClusterName, Arc<ClusterHandle>>,
    materials: DashMap<ClusterName, ClusterSecret>,
    in_cluster: Arc<ClusterHandle>,
    namespace: String,
    options: ClusterOptions,
    builder: Arc<dyn ClusterHandleBuilder>,
    rebuilds: AtomicUsize,
}

impl fmt::Debug for ClusterManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterManager")
            .field("namespace", &self.namespace)
            .field("in_cluster", &self.in_cluster.name())
            .field("clusters", &self.names())
            .field("rebuilds", &self.rebuilds())
            .finish()
    }
}

impl ClusterManager {
    /// Builds the registry around the control plane's own handle.
    ///
    /// `in_cluster` answers [`IN_CLUSTER`]; it is built from the controller's own client and
    /// impersonation pool, so it shares the control plane's single connector instead of opening a
    /// second one.
    #[must_use]
    pub fn new(
        in_cluster: Arc<ClusterHandle>,
        namespace: impl Into<String>,
        options: ClusterOptions,
        builder: Arc<dyn ClusterHandleBuilder>,
    ) -> Self {
        Self {
            handles: DashMap::new(),
            materials: DashMap::new(),
            in_cluster,
            namespace: namespace.into(),
            options,
            builder,
            rebuilds: AtomicUsize::new(0),
        }
    }

    /// The control-plane namespace cluster `Secret`s are read from.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The TLS policy registrations are validated under.
    #[must_use]
    pub fn options(&self) -> ClusterOptions {
        self.options
    }

    /// The control plane's own handle.
    #[must_use]
    pub fn in_cluster(&self) -> &Arc<ClusterHandle> {
        &self.in_cluster
    }

    /// Registered (non-`in-cluster`) cluster names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .handles
            .iter()
            .map(|entry| entry.key().as_str().to_owned())
            .collect();
        names.sort();
        names
    }

    /// How many remote clusters are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Whether no remote cluster is registered (the default: in-cluster only).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// How many handles this registry has built (a rebuild-count seam, not a stable API).
    #[must_use]
    pub fn rebuilds(&self) -> usize {
        self.rebuilds.load(Ordering::SeqCst)
    }

    /// Resolves `name` to its handle.
    ///
    /// # Errors
    ///
    /// [`ClusterError::NotFound`] for an unregistered name (terminal), and
    /// [`ClusterError::InvalidName`] for a name that is not a valid identifier.
    pub fn get(&self, name: &str) -> Result<Arc<ClusterHandle>, ClusterError> {
        if name.trim() == IN_CLUSTER {
            return Ok(self.in_cluster.clone());
        }
        let parsed = ClusterName::parse(name)?;
        self.handles
            .get(&parsed)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| ClusterError::NotFound {
                cluster: parsed.as_str().to_owned(),
                namespace: self.namespace.clone(),
            })
    }

    /// Registers (or refreshes) the cluster a `Secret` defines.
    ///
    /// Async because the handle's transport is built off the async workers (finding H1).
    ///
    /// # Errors
    ///
    /// Every [`ClusterError`] `parse` or the builder raises. A failed seed does **not** remove an
    /// existing registration by itself — [`Self::run`] does that, so a rotated, unusable credential
    /// can never keep working.
    pub async fn seed(&self, secret: &Secret) -> Result<ClusterChange, ClusterError> {
        let material = ClusterSecret::parse(secret, self.options)?;
        let name = material.name.clone();
        if self
            .materials
            .get(&name)
            .is_some_and(|existing| existing.value() == &material)
        {
            return Ok(ClusterChange::Unchanged);
        }
        let replaced = self.materials.contains_key(&name);
        let handle = self.builder.build(&material).await?;
        self.rebuilds.fetch_add(1, Ordering::SeqCst);
        // A `Secret` that renamed itself (`name: eu-prod`) no longer backs its previous cluster, so
        // the old registration must go: it would otherwise stay addressable with a credential the
        // operator just retargeted away from it.
        let stale: Vec<ClusterName> = self
            .materials
            .iter()
            .filter(|entry| {
                entry.value().secret == material.secret
                    && entry.value().namespace == material.namespace
                    && entry.key() != &name
            })
            .map(|entry| entry.key().clone())
            .collect();
        self.store(material, Arc::new(handle));
        for old in stale {
            self.remove(&old);
        }
        Ok(if replaced {
            ClusterChange::Rebuilt
        } else {
            ClusterChange::Added
        })
    }

    /// Forgets the cluster named `name` (its `Secret` was deleted).
    ///
    /// Returns whether a registration was removed. The next `get` for that name fails closed with
    /// [`ClusterError::NotFound`], which is what makes a deleted `Secret` visible in `/status`
    /// instead of silently keeping a stale connector alive.
    pub fn forget(&self, name: &str) -> bool {
        let Ok(parsed) = ClusterName::parse(name) else {
            return false;
        };
        self.remove(&parsed)
    }

    /// Forgets every registration built from the `Secret` named `secret_name`.
    ///
    /// The watch reports a `Secret` by *its* name, which need not be the cluster name a
    /// registration overrides with the `name` key — so deleting that `Secret` has to be resolved
    /// back to whichever cluster names it currently backs. Returns those names.
    pub fn forget_secret(&self, secret_name: &str) -> Vec<String> {
        let names: Vec<ClusterName> = self
            .materials
            .iter()
            .filter(|entry| entry.value().secret == secret_name)
            .map(|entry| entry.key().clone())
            .collect();
        let mut forgotten = Vec::with_capacity(names.len());
        for name in names {
            if self.remove(&name) {
                forgotten.push(name.as_str().to_owned());
            }
        }
        forgotten
    }

    /// Writes both maps together, so a handle and its material can never disagree.
    fn store(&self, material: ClusterSecret, handle: Arc<ClusterHandle>) {
        self.materials.insert(material.name.clone(), material);
        self.handles.insert(handle.name().clone(), handle);
    }

    /// Drops both maps together.
    fn remove(&self, name: &ClusterName) -> bool {
        let material = self.materials.remove(name).is_some();
        let handle = self.handles.remove(name).is_some();
        material || handle
    }

    /// Drives the registry from a `Secret` event stream until `stop` is cancelled.
    ///
    /// An event that cannot be used logs a warning and — deliberately — **invalidates** the
    /// cluster's handle: keeping the previous credential alive after its `Secret` changed would mean
    /// the controller keeps deploying with credentials the operator just revoked.
    ///
    /// A re-list (`[Init, InitApply…, InitDone]`) is a **complete snapshot**, and it is the only
    /// thing that can report a `Secret` which disappeared while the watch was reconnecting:
    /// Kubernetes sends no `Delete` for anything that vanished during the gap (finding H2). The
    /// registry therefore records the `Secret` names it saw between `Init` and `InitDone`, and on
    /// `InitDone` forgets every registration whose `Secret` was not observed — a revoked cluster
    /// credential must not stay addressable just because its deletion was never delivered.
    pub async fn run(
        self: Arc<Self>,
        source: Arc<dyn ClusterSecretSource>,
        stop: CancellationToken,
    ) {
        let mut events = source.events();
        // `Secret` names observed since the last `Init`, while a re-list is in progress.
        let mut seen: HashSet<String> = HashSet::new();
        let mut listing = false;
        loop {
            let event = tokio::select! {
                () = stop.cancelled() => break,
                event = events.next() => event,
            };
            let Some(event) = event else {
                tracing::warn!(
                    namespace = %self.namespace,
                    "the cluster Secret watch ended; registered clusters stay as they are"
                );
                break;
            };
            match event {
                Ok(ClusterSecretEvent::Init) => {
                    // A new list supersedes the previous one: only what this list reports exists.
                    seen.clear();
                    listing = true;
                }
                Ok(ClusterSecretEvent::InitDone) => {
                    // Only a list this loop watched start is authoritative. An `InitDone` that is
                    // not bracketed by our own `Init` (a misbehaving source) must never be read as
                    // "nothing is registered".
                    if !std::mem::take(&mut listing) {
                        tracing::debug!(
                            namespace = %self.namespace,
                            "cluster Secret re-list completed without a matching start; keeping the \
                             registry as it is"
                        );
                        continue;
                    }
                    let stale = self.retain_secret_names(&seen);
                    if !stale.is_empty() {
                        tracing::warn!(
                            namespace = %self.namespace,
                            clusters = ?stale,
                            "cluster registrations disappeared while the watch was reconnecting; \
                             forgetting them so no Application keeps deploying with a credential \
                             that was revoked"
                        );
                    }
                }
                Ok(ClusterSecretEvent::Upsert(secret)) => {
                    let name = secret.name_any();
                    if listing {
                        // Recorded even when the material is unusable: the `Secret` itself was
                        // observed, so the registration it backs is not a re-list casualty.
                        seen.insert(name.clone());
                    }
                    match self.seed(&secret).await {
                        Ok(change) => tracing::info!(
                            secret = %name,
                            change = ?change,
                            clusters = ?self.names(),
                            "cluster registration observed"
                        ),
                        Err(err) => {
                            tracing::warn!(
                                secret = %name,
                                error = %err,
                                "cluster Secret cannot be used; forgetting the cluster so no \
                                 Application keeps deploying with credentials it no longer has"
                            );
                            self.forget_secret(&name);
                        }
                    }
                }
                Ok(ClusterSecretEvent::Deleted(name)) => {
                    let removed = self.forget_secret(&name);
                    tracing::info!(
                        secret = %name,
                        clusters = ?removed,
                        "cluster registration deleted"
                    );
                }
                Err(err) => tracing::warn!(
                    error = %err,
                    "cluster Secret watch error; the registration will be rebuilt on reconnect"
                ),
            }
        }
    }

    /// Forgets every registration whose `Secret` name is **not** in `seen`.
    ///
    /// The completed re-list is the authority: anything it did not report no longer exists (finding
    /// H2). Returns the cluster names that were forgotten, so the caller can log the revocation.
    fn retain_secret_names(&self, seen: &HashSet<String>) -> Vec<String> {
        let stale: Vec<ClusterName> = self
            .materials
            .iter()
            .filter(|entry| !seen.contains(&entry.value().secret))
            .map(|entry| entry.key().clone())
            .collect();
        let mut forgotten = Vec::with_capacity(stale.len());
        for name in stale {
            if self.remove(&name) {
                forgotten.push(name.as_str().to_owned());
            }
        }
        forgotten.sort();
        forgotten
    }
}

impl ClusterSource for ClusterManager {
    fn target(&self, name: &str) -> Result<ClusterTarget, ReconcileError> {
        Ok(self.get(name)?.target())
    }
}

/// One change to the set of registered clusters.
///
/// Mirrors the four things a Kubernetes watch can say, including the re-list bracketing: a
/// `[Init, Upsert…, InitDone]` sequence is a complete snapshot, and it is the only way the registry
/// learns that a `Secret` disappeared while the watch was reconnecting (finding H2).
#[derive(Clone)]
pub enum ClusterSecretEvent {
    /// A (re-)list is starting: the [`Self::Upsert`] events that follow are a complete snapshot.
    Init,
    /// A cluster `Secret` was added or changed.
    ///
    /// Boxed: an event flows through one bounded stream, and a `Secret` is much larger than any
    /// other variant (clippy's `large_enum_variant`).
    Upsert(Box<Secret>),
    /// The `Secret` named here was deleted.
    Deleted(String),
    /// The snapshot started by [`Self::Init`] is complete: anything it did not report is gone.
    InitDone,
}

impl fmt::Debug for ClusterSecretEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The `Secret` itself is never printed: its data is credential material.
            Self::Init => f.write_str("Init"),
            Self::Upsert(secret) => f.debug_tuple("Upsert").field(&secret.name_any()).finish(),
            Self::Deleted(name) => f.debug_tuple("Deleted").field(name).finish(),
            Self::InitDone => f.write_str("InitDone"),
        }
    }
}

/// A watch failure (surfaced, never fatal: the watch reconnects).
#[derive(Debug, Clone, thiserror::Error)]
#[error("cluster Secret watch failed: {message}")]
pub struct ClusterWatchError {
    /// The underlying failure, redacted.
    pub message: String,
}

/// The source of cluster-registration events.
///
/// A single seam, so the whole add/change/delete behaviour of [`ClusterManager`] is testable with a
/// scripted stream and no cluster.
pub trait ClusterSecretSource: Send + Sync + 'static {
    /// The event stream. It is `'static`: the watcher owns its reconnect loop.
    fn events(&self) -> BoxStream<'static, Result<ClusterSecretEvent, ClusterWatchError>>;
}

/// The production [`ClusterSecretSource`]: a **namespaced** watch of labeled `Secret`s.
pub struct SecretClusterSource {
    api: Api<Secret>,
    namespace: String,
}

impl SecretClusterSource {
    /// Watches the cluster registrations of `namespace` (the control-plane namespace).
    ///
    /// The `Api` is namespaced by construction, so no code path can turn this into a cluster-wide
    /// `Secret` watch.
    #[must_use]
    pub fn new(client: Client, namespace: impl Into<String>) -> Self {
        let namespace = namespace.into();
        Self {
            api: Api::namespaced(client, &namespace),
            namespace,
        }
    }

    /// The namespace registrations are read from.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The label selector every watch uses (`ferriscd.io/secret-type=cluster`).
    #[must_use]
    pub fn label_selector() -> String {
        format!("{SECRET_TYPE_LABEL}={SECRET_TYPE_CLUSTER}")
    }
}

impl fmt::Debug for SecretClusterSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretClusterSource")
            .field("namespace", &self.namespace)
            .field("selector", &Self::label_selector())
            .finish_non_exhaustive()
    }
}

impl ClusterSecretSource for SecretClusterSource {
    fn events(&self) -> BoxStream<'static, Result<ClusterSecretEvent, ClusterWatchError>> {
        let config = watcher::Config::default().labels(&Self::label_selector());
        watcher::watcher(self.api.clone(), config)
            // The watch reconnects on its own; a transport error is surfaced, not fatal.
            .default_backoff()
            .filter_map(|event| async move {
                match event {
                    Ok(watcher::Event::Apply(secret)) | Ok(watcher::Event::InitApply(secret)) => {
                        Some(Ok(ClusterSecretEvent::Upsert(Box::new(secret))))
                    }
                    Ok(watcher::Event::Delete(secret)) => {
                        Some(Ok(ClusterSecretEvent::Deleted(secret.name_any())))
                    }
                    // The re-list bracketing is forwarded, never swallowed (finding H2): a
                    // `Secret` deleted while the watch was reconnecting produces no `Delete`, so
                    // `InitDone` is the only signal that the registry must re-derive its set.
                    Ok(watcher::Event::Init) => Some(Ok(ClusterSecretEvent::Init)),
                    Ok(watcher::Event::InitDone) => Some(Ok(ClusterSecretEvent::InitDone)),
                    Err(err) => Some(Err(ClusterWatchError {
                        message: crate::reconcile::bounded(&err.to_string()),
                    })),
                }
            })
            .boxed()
    }
}

/// Reads a `Secret` data value as UTF-8.
fn data_value(secret: &Secret, key: &str) -> Option<String> {
    let data = secret.data.as_ref()?;
    let value = data.get(key)?;
    std::str::from_utf8(&value.0).ok().map(ToOwned::to_owned)
}

/// Reads a `Secret` data value as raw bytes, treating an empty value as absent.
fn secret_bytes(secret: &Secret, key: &str) -> Option<Vec<u8>> {
    let ByteString(bytes) = secret.data.as_ref()?.get(key)?;
    (!bytes.is_empty()).then(|| bytes.clone())
}

/// Parses a `Secret` boolean, accepting the spellings Kubernetes tooling uses.
fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

/// Validates the explicit `server` key.
///
/// The value is echoed only through [`redact_repo_url`]: an API server URL is written like a
/// repository URL and routinely carries userinfo (`https://user:token@api.example.com:6443`), so
/// quoting it verbatim would put a credential in `/status` and in the controller's logs
/// (finding M11).
fn validate_server(
    context: &SecretContext<'_>,
    server: &str,
    options: ClusterOptions,
) -> Result<(), ClusterError> {
    validate_server_url(context, &format!("the {KEY_SERVER:?} key"), server, options)
}

/// The **one** rule every API server URL goes through, whichever key carried it (finding H3).
///
/// `kube::Config::try_from` happily accepts a plaintext `http://` server, so validating only the
/// explicit `server` key would let a `Secret` author force plaintext credentials — and manifests —
/// through a kubeconfig's `clusters[].cluster.server`, without the `--allow-insecure-cluster-tls`
/// opt-in. A non-`https` scheme, a relative URL, and a URL with no host are refused for the same
/// reason. `subject` names where the URL came from (`the "server" key`, a kubeconfig cluster) so the
/// message stays actionable; `server` itself is only ever echoed redacted.
fn validate_server_url(
    context: &SecretContext<'_>,
    subject: &str,
    server: &str,
    options: ClusterOptions,
) -> Result<(), ClusterError> {
    let server = server.trim();
    let uri: http::Uri = server.parse().map_err(|_| {
        context.invalid(format!(
            "{subject} {:?} is not an absolute URL, e.g. https://10.0.0.1:6443",
            redact_repo_url(server)
        ))
    })?;
    if uri.authority().is_none() {
        return Err(context.invalid(format!(
            "{subject} {:?} has no host",
            redact_repo_url(server)
        )));
    }
    match uri.scheme_str() {
        Some("https") => Ok(()),
        Some("http") if options.allow_insecure => {
            tracing::warn!(
                server = %redact_repo_url(server),
                "cluster registration uses a plaintext http:// API server (local-dev opt-in)"
            );
            Ok(())
        }
        Some("http") => Err(ClusterError::InsecureTls {
            secret: context.secret.to_owned(),
            namespace: context.namespace.to_owned(),
        }),
        _ => Err(context.invalid(format!(
            "{subject} {:?} must use https://",
            redact_repo_url(server)
        ))),
    }
}

/// Refuses the kubeconfig field kinds the manager will not honour.
fn validate_kubeconfig(
    material: &ClusterSecret,
    kubeconfig: &Kubeconfig,
    options: ClusterOptions,
) -> Result<(), ClusterError> {
    let unsupported = |field: &str| ClusterError::UnsupportedKubeconfig {
        secret: material.secret.clone(),
        namespace: material.namespace.clone(),
        field: field.to_owned(),
    };
    let context = SecretContext {
        secret: &material.secret,
        namespace: &material.namespace,
    };

    for named in &kubeconfig.clusters {
        let Some(cluster) = &named.cluster else {
            continue;
        };
        // Finding H3: the API server URL inside a kubeconfig goes through the *same* rule as the
        // explicit `server` key. `kube::Config::try_from` accepts `http://`, so skipping this would
        // let a `Secret` author opt into plaintext credentials without the local-dev flag.
        if let Some(server) = &cluster.server {
            validate_server_url(
                &context,
                &format!("the kubeconfig server of cluster {:?}", named.name),
                server,
                options,
            )?;
        }
        if cluster
            .proxy_url
            .as_deref()
            .is_some_and(|url| !url.is_empty())
        {
            return Err(unsupported("proxy-url"));
        }
        if cluster
            .certificate_authority
            .as_deref()
            .is_some_and(|path| !path.is_empty())
        {
            return Err(unsupported("certificate-authority (a path)"));
        }
        if cluster
            .insecure_skip_tls_verify
            .is_some_and(|insecure| insecure)
            && !options.allow_insecure
        {
            // A kubeconfig may disable verification, but only under the same explicit local-dev
            // opt-in the dedicated `insecureSkipTLSVerify` key requires: two ways in must not mean
            // two different policies.
            return Err(ClusterError::InsecureTls {
                secret: material.secret.clone(),
                namespace: material.namespace.clone(),
            });
        }
    }

    for named in &kubeconfig.auth_infos {
        let Some(user) = &named.auth_info else {
            continue;
        };
        if user.exec.is_some() {
            return Err(unsupported("exec"));
        }
        if user.auth_provider.is_some() {
            return Err(unsupported("auth-provider"));
        }
        if user
            .token_file
            .as_deref()
            .is_some_and(|path| !path.is_empty())
        {
            return Err(unsupported("tokenFile (a path)"));
        }
        if user
            .client_certificate
            .as_deref()
            .is_some_and(|path| !path.is_empty())
        {
            return Err(unsupported("client-certificate (a path)"));
        }
        if user
            .client_key
            .as_deref()
            .is_some_and(|path| !path.is_empty())
        {
            return Err(unsupported("client-key (a path)"));
        }
        if user
            .impersonate
            .as_deref()
            .is_some_and(|name| !name.is_empty())
            || user
                .impersonate_groups
                .as_ref()
                .is_some_and(|groups| !groups.is_empty())
        {
            return Err(unsupported("as / as-groups (FerrisCD owns impersonation)"));
        }
    }

    // Static credentials only: a kubeconfig whose users carry none would authenticate as the
    // anonymous user, which can only ever answer `401` — reported here, where the message can name
    // the `Secret`, instead of on every reconcile.
    let has_static_credential = kubeconfig.auth_infos.iter().any(|named| {
        named.auth_info.as_ref().is_some_and(|user| {
            user.token.is_some()
                || user.client_certificate_data.is_some()
                || user.client_key_data.is_some()
                || (user.username.is_some() && user.password.is_some())
        })
    });
    if !has_static_credential {
        return Err(ClusterError::MalformedKubeconfig {
            secret: material.secret.clone(),
            namespace: material.namespace.clone(),
            reason: "the kubeconfig names no user with a static credential: supply \
                     bearerToken / tls.crt+tls.key on the Secret, or a kubeconfig user with a \
                     token, a client certificate, or basic auth"
                .to_owned(),
        });
    }
    Ok(())
}

/// Base64-encodes `bytes` for a kubeconfig `*-data` field.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The threads the blocking half of a build ran on (a test-only seam, finding H1).
///
/// A `Vec` rather than a slot: the workspace's tests run in parallel, so a second builder recording
/// at the same time must not overwrite the observation the assertion is about.
#[cfg(test)]
static BLOCKING_THREADS: std::sync::Mutex<Vec<std::thread::ThreadId>> =
    std::sync::Mutex::new(Vec::new());

/// Records the current thread as a thread the blocking half ran on (test-only, finding H1).
#[cfg(test)]
fn record_blocking_thread() {
    let mut threads = BLOCKING_THREADS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    threads.push(std::thread::current().id());
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    use kube::config::Config;

    use super::*;

    const TOKEN: &str = "super-secret-bearer-token-value";
    const CLIENT_KEY: &str = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key-but-still-secret\n";

    /// A real self-signed CA, so the positive paths exercise `kube`'s own PEM parser instead of
    /// passing a placeholder that only looks like a certificate.
    const CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC9jCCAd6gAwIBAgIUBoS7jl1CY/lFamrFA9cf4+1SuiQwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQZmVycmlzY2QtdGVzdC1jYTAeFw0yNjExMjUyMDM1NTVa
Fw0zNjExMjIyMDM1NTVaMBsxGTAXBgNVBAMMEGZlcnJpc2NkLXRlc3QtY2EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnhpGZMPGJjPp5bmH/n/06SxPn
c3SVSleCTLXImaOvNE9EKW+TqaNKP05MXrLKOWiLJ/29ypXFBODUA0rln/TkEEDi
/N0Wdl7LiWi4TeKFEcaiq8bwHsF2I7CMoMjMDqk9HOqUlfEPHBqejRonTBptbQQo
3ms+xcdjZMvZhhnu5NYVJz9jKQ8cImZDRtvG/5jIfy9wR5yobvVz8RisYm0mQA5G
P0Rq1A/BWZ3b8e9x+u+7QN/PEtOjKeYtO3mXfCad99DA0Uzy7LWVCY2La62+hWLk
KOK2vDJFWM8kKkg1ajyHoevJ5jzfpRG9f+9Zg1sOwyU1q4TRs54FR5poRgkBAgMB
AAGjMjAwMB0GA1UdDgQWBBS24qrqx3DwMC6fLIfaMrNGQ2gfRzAPBgNVHRMBAf8E
BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCrjkfyoSSGNEHWt5rnFGGfw954odba
PkGYxW53EpZGpFQwNtb2AAc2tgFkjN+0HwjKW8rnZ6RVgdaLM+nJ0yLdEIzyEwfm
EBnhz4hDfDYBWNdLHStbIr/0E6cD73ST/wzD4lRMn0E0MSFAooESrat4QfPCUlxY
0+NBuRThvbqakP0LAGeSPrerxIthl6X3acaJrAcigOUoiHH13C5FuRGOOGkP8Zqk
VvvhRCE9YVNC/nP/0IrzmyUJjadxsSjY9K50kjOxukR8diF5fBhlpWz5n11sh+Sw
1LBIlI+iyFqhgHE6LNdbkoYW6AoNDCplqSopRJobnqv5RRL+JgwckPxy
-----END CERTIFICATE-----
"#;

    fn secret(name: &str, data: &[(&str, &[u8])]) -> Secret {
        let mut secret = Secret {
            data: Some(
                data.iter()
                    .map(|(key, value)| ((*key).to_owned(), ByteString((*value).to_vec())))
                    .collect(),
            ),
            ..Secret::default()
        };
        secret.metadata.name = Some(name.to_owned());
        secret.metadata.namespace = Some(CONTROL_PLANE_NAMESPACE.to_owned());
        secret.metadata.labels = Some(BTreeMap::from([(
            SECRET_TYPE_LABEL.to_owned(),
            SECRET_TYPE_CLUSTER.to_owned(),
        )]));
        secret
    }

    fn token_secret(name: &str) -> Secret {
        secret(
            name,
            &[
                (KEY_SERVER, b"https://workload.example.com:6443"),
                (KEY_BEARER_TOKEN, TOKEN.as_bytes()),
                (KEY_CA_CRT, CA_PEM.as_bytes()),
            ],
        )
    }

    fn parse(secret: &Secret) -> Result<ClusterSecret, ClusterError> {
        ClusterSecret::parse(secret, ClusterOptions::strict())
    }

    fn with_data(mut secret: Secret, key: &str, value: &[u8]) -> Secret {
        secret
            .data
            .as_mut()
            .expect("the fixture Secret carries data")
            .insert(key.to_owned(), ByteString(value.to_vec()));
        secret
    }

    fn offline_client() -> Client {
        Client::new(
            tower::service_fn(|_request| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            CONTROL_PLANE_NAMESPACE,
        )
    }

    fn pool() -> Arc<ImpersonationPool> {
        crate::impersonation::ensure_crypto_provider();
        let config = Config::new("https://127.0.0.1:6443".parse().expect("cluster url"));
        Arc::new(ImpersonationPool::new(&config).expect("pool"))
    }

    /// A handle that never dials out and whose connector is a real (unused) pool.
    fn handle(name: ClusterName) -> Arc<ClusterHandle> {
        let client = offline_client();
        Arc::new(ClusterHandle::new(
            name,
            client.clone(),
            DiscoveryCache::new(client),
            pool(),
        ))
    }

    /// A builder that never builds a real client and counts what it was asked to build.
    #[derive(Default)]
    struct FakeBuilder {
        builds: AtomicUsize,
        fail: AtomicBool,
        /// Yields once before answering, so "the registry awaits the builder's future" is
        /// observable rather than implied (finding H1).
        yields: AtomicUsize,
    }

    impl ClusterHandleBuilder for FakeBuilder {
        fn build<'a>(
            &'a self,
            material: &'a ClusterSecret,
        ) -> BoxFuture<'a, Result<ClusterHandle, ClusterError>> {
            Box::pin(async move {
                self.builds.fetch_add(1, Ordering::SeqCst);
                // A real builder hands its blocking half to `spawn_blocking`, so its future is
                // never ready on the first poll.
                tokio::task::yield_now().await;
                self.yields.fetch_add(1, Ordering::SeqCst);
                if self.fail.load(Ordering::SeqCst) {
                    return Err(ClusterError::Transport {
                        secret: material.secret.clone(),
                        namespace: material.namespace.clone(),
                        reason: "scripted failure".to_owned(),
                    });
                }
                let client = offline_client();
                Ok(ClusterHandle::new(
                    material.name().clone(),
                    client.clone(),
                    DiscoveryCache::new(client),
                    pool(),
                ))
            })
        }
    }

    fn manager(builder: Arc<FakeBuilder>) -> ClusterManager {
        ClusterManager::new(
            handle(ClusterName::in_cluster()),
            CONTROL_PLANE_NAMESPACE,
            ClusterOptions::strict(),
            builder,
        )
    }

    // -----------------------------------------------------------------
    // Parsing and validation
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_bearer_token_registration_parses_into_strict_tls_material() {
        let parsed = parse(&token_secret("workload")).expect("a token registration must parse");
        assert_eq!(parsed.name().as_str(), "workload");
        assert_eq!(parsed.server(), Some("https://workload.example.com:6443"));
        assert_eq!(parsed.auth_kind(), "bearer-token");
        assert!(!parsed.insecure_skip_tls_verify());
        assert_eq!(parsed.secret_id(), "ferriscd-system/workload");

        // Trap T4: the token never appears in Debug; only the auth *kind* is printed.
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains(TOKEN), "{rendered}");
        assert!(rendered.contains("BearerToken(<redacted>)"), "{rendered}");
    }

    #[tokio::test]
    async fn a_client_certificate_registration_parses_and_requires_both_halves() {
        let parsed = parse(&secret(
            "workload",
            &[
                (KEY_SERVER, b"https://workload.example.com:6443"),
                (
                    KEY_TLS_CRT,
                    b"-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                ),
                (KEY_TLS_KEY, CLIENT_KEY.as_bytes()),
            ],
        ))
        .expect("a client-certificate registration must parse");
        assert_eq!(parsed.auth_kind(), "client-certificate");
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("not-a-real-key"), "{rendered}");

        let missing_key = secret(
            "workload",
            &[
                (KEY_SERVER, b"https://workload.example.com:6443"),
                (KEY_TLS_CRT, b"cert"),
            ],
        );
        let err = parse(&missing_key).expect_err("half a key pair must be refused");
        assert!(err.to_string().contains(KEY_TLS_KEY), "{err}");

        let missing_cert = secret(
            "workload",
            &[
                (KEY_SERVER, b"https://workload.example.com:6443"),
                (KEY_TLS_KEY, b"key"),
            ],
        );
        let err = parse(&missing_cert).expect_err("half a key pair must be refused");
        assert!(err.to_string().contains(KEY_TLS_CRT), "{err}");
    }

    /// **Trap guard:** TLS verification is the default, and skipping it needs the explicit opt-in.
    #[tokio::test]
    async fn insecure_skip_tls_verify_is_rejected_without_the_local_dev_opt_in() {
        let insecure = with_data(
            token_secret("workload"),
            KEY_INSECURE_SKIP_TLS_VERIFY,
            b"true",
        );

        let err = parse(&insecure).expect_err("insecure TLS must be refused by default");
        assert!(matches!(err, ClusterError::InsecureTls { .. }), "{err:?}");
        assert!(err.is_terminal());
        assert!(
            err.to_string().contains(KEY_INSECURE_SKIP_TLS_VERIFY),
            "the message must name the offending key: {err}"
        );
        assert!(!err.to_string().contains(TOKEN), "{err}");

        let opted_in = ClusterSecret::parse(&insecure, ClusterOptions::allowing_insecure())
            .expect("the local-dev opt-in accepts insecure TLS");
        assert!(opted_in.insecure_skip_tls_verify());

        // A plaintext API server is refused for exactly the same reason.
        let plaintext = with_data(
            token_secret("workload"),
            KEY_SERVER,
            b"http://workload.example.com:8080",
        );
        let err = parse(&plaintext).expect_err("http:// must be refused by default");
        assert!(matches!(err, ClusterError::InsecureTls { .. }), "{err:?}");
        let opted_in = ClusterSecret::parse(&plaintext, ClusterOptions::allowing_insecure())
            .expect("the opt-in is the only way to reach a plaintext API server");
        assert_eq!(opted_in.server(), Some("http://workload.example.com:8080"));
    }

    /// A kubeconfig that disables verification bypasses the explicit key, so it is refused too.
    #[tokio::test]
    async fn a_kubeconfig_cannot_smuggle_insecure_skip_tls_verify_past_the_opt_in() {
        let document = "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\n    insecure-skip-tls-verify: true\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: static-token\n";
        let material = secret("workload", &[(KEY_KUBECONFIG, document.as_bytes())]);
        let err = parse(&material).expect_err("a kubeconfig may not disable verification");
        assert!(matches!(err, ClusterError::InsecureTls { .. }), "{err:?}");
        assert!(
            ClusterSecret::parse(&material, ClusterOptions::allowing_insecure()).is_ok(),
            "with the local-dev opt-in the same kubeconfig is accepted"
        );
    }

    /// **Finding H3:** a kubeconfig's `clusters[].cluster.server` goes through exactly the same rule
    /// as the plain `server` key. `kube::Config::try_from` accepts `http://`, so validating only the
    /// explicit key would let a `Secret` author force plaintext credentials — and manifests —
    /// without the `--allow-insecure-cluster-tls` opt-in.
    #[tokio::test]
    async fn a_kubeconfig_cannot_smuggle_a_plaintext_api_server_past_the_opt_in() {
        let document = "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: http://workload:8080\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: static-token\n";
        let material = secret("workload", &[(KEY_KUBECONFIG, document.as_bytes())]);
        let err = parse(&material).expect_err("a kubeconfig may not force a plaintext API server");
        assert!(matches!(err, ClusterError::InsecureTls { .. }), "{err:?}");
        assert!(err.is_terminal());
        assert!(!err.to_string().contains("static-token"), "{err}");
        let opted_in = ClusterSecret::parse(&material, ClusterOptions::allowing_insecure())
            .expect("the local-dev opt-in is the only way to reach a plaintext API server");
        assert_eq!(opted_in.auth_kind(), "kubeconfig");

        // The plain `server` key takes the same path — the two ways in must not mean two policies.
        let plain = with_data(
            token_secret("workload"),
            KEY_SERVER,
            b"http://workload.example.com:8080",
        );
        let err = parse(&plain).expect_err("http:// must be refused by default");
        assert!(matches!(err, ClusterError::InsecureTls { .. }), "{err:?}");
        assert!(
            ClusterSecret::parse(&plain, ClusterOptions::allowing_insecure()).is_ok(),
            "the opt-in accepts the plaintext API server in both forms"
        );

        // Any other scheme, a relative path, or a URL with no host is refused rather than handed to
        // `kube`, which would treat several of them as usable.
        for server in [
            "ftp://workload:6443",
            "workload:6443",
            "/var/run/kubernetes/server",
            "https://",
        ] {
            let document = format!(
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: {server}\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: static-token\n"
            );
            let material = secret("workload", &[(KEY_KUBECONFIG, document.as_bytes())]);
            let err = parse(&material).expect_err("an unusable kubeconfig server must be refused");
            assert!(
                matches!(err, ClusterError::Malformed { .. }),
                "{server}: {err:?}"
            );
            assert!(
                err.to_string().contains("kubeconfig server of cluster"),
                "{server}: the refusal must name where the URL came from: {err}"
            );
        }
    }

    #[tokio::test]
    async fn a_registration_that_cannot_produce_a_client_is_rejected() {
        let no_server = secret("workload", &[(KEY_BEARER_TOKEN, b"token")]);
        let err = parse(&no_server).expect_err("a registration needs an API server");
        assert!(err.to_string().contains(KEY_SERVER), "{err}");

        let no_auth = secret("workload", &[(KEY_SERVER, b"https://workload:6443")]);
        let err = parse(&no_auth).expect_err("a registration needs credentials");
        assert!(err.to_string().contains(KEY_BEARER_TOKEN), "{err}");

        let ambiguous = secret(
            "workload",
            &[
                (KEY_SERVER, b"https://workload:6443"),
                (KEY_BEARER_TOKEN, b"token"),
                (KEY_TLS_CRT, b"cert"),
                (KEY_TLS_KEY, b"key"),
            ],
        );
        let err = parse(&ambiguous).expect_err("ambiguous auth must be refused");
        assert!(err.to_string().contains(KEY_BEARER_TOKEN), "{err}");

        let mixed = secret(
            "workload",
            &[
                (KEY_KUBECONFIG, b"apiVersion: v1\nkind: Config\n"),
                (KEY_SERVER, b"https://workload:6443"),
            ],
        );
        let err = parse(&mixed).expect_err("mixed auth must be refused");
        assert!(err.to_string().contains(KEY_KUBECONFIG), "{err}");

        let garbage = secret("workload", &[(KEY_KUBECONFIG, b"not: [valid: kubeconfig")]);
        let err = parse(&garbage).expect_err("an unparseable kubeconfig must be refused");
        assert!(
            err.to_string().contains("not valid YAML") || err.to_string().contains("unusable"),
            "{err}"
        );

        let bad_server = with_data(token_secret("workload"), KEY_SERVER, b"workload:6443");
        let err = parse(&bad_server).expect_err("a server must be an absolute URL");
        assert!(err.to_string().contains(KEY_SERVER), "{err}");
    }

    /// The CA bundle is parsed for real (by `kube`'s own PEM parser during seeding), so a
    /// placeholder cannot masquerade as a trusted CA.
    #[tokio::test]
    async fn an_unparseable_ca_bundle_is_rejected_when_the_secret_is_seeded() {
        let broken = with_data(
            token_secret("workload"),
            KEY_CA_CRT,
            b"-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n",
        );
        let err = parse(&broken).expect_err("an invalid CA must be rejected, not trusted blindly");
        assert!(
            matches!(err, ClusterError::MalformedKubeconfig { .. }),
            "{err:?}"
        );
        assert!(err.is_terminal());
        assert!(!err.to_string().contains(TOKEN), "{err}");
    }

    #[tokio::test]
    async fn a_secret_that_is_not_labeled_as_a_cluster_is_ignored_by_parsing() {
        let mut plain = token_secret("workload");
        plain.metadata.labels = Some(BTreeMap::from([(
            SECRET_TYPE_LABEL.to_owned(),
            "repository".to_owned(),
        )]));
        let err = parse(&plain).expect_err("an unlabeled Secret is not a cluster registration");
        assert!(
            matches!(err, ClusterError::NotAClusterSecret { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains(SECRET_TYPE_LABEL), "{err}");
    }

    #[tokio::test]
    async fn the_in_cluster_name_is_reserved_and_names_must_be_dns_labels() {
        assert!(matches!(
            ClusterName::parse("in-cluster"),
            Err(ClusterError::ReservedName { .. })
        ));
        for bad in ["", "  ", "Prod", "prod cluster", "-prod", "prod-", "a..b"] {
            assert!(ClusterName::parse(bad).is_err(), "{bad:?} must be rejected");
        }
        for good in ["prod", "eu-west-1", "prod.cluster.local", "a1"] {
            assert_eq!(ClusterName::parse(good).expect("valid").as_str(), good);
        }

        let reserved = with_data(token_secret("workload"), KEY_NAME, b"in-cluster");
        assert!(matches!(
            parse(&reserved),
            Err(ClusterError::ReservedName { .. })
        ));

        // An override is honoured.
        let renamed = with_data(token_secret("workload"), KEY_NAME, b"eu-prod");
        assert_eq!(parse(&renamed).expect("valid").name().as_str(), "eu-prod");
    }

    #[tokio::test]
    async fn a_kubeconfig_with_an_exec_plugin_or_a_certificate_path_is_refused() {
        for (field, document) in [
            (
                "exec",
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    exec:\n      command: /bin/sh\n      apiVersion: client.authentication.k8s.io/v1\n",
            ),
            (
                "tokenFile",
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token\n",
            ),
            (
                "certificate-authority",
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\n    certificate-authority: /etc/ssl/ca.crt\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: abc\n",
            ),
            (
                "auth-provider",
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    auth-provider:\n      name: gcp\n",
            ),
            // Finding M1: the four field kinds that were refused in code but never pinned by a
            // test. Each one is a path to "the `Secret` writer chooses where the controller's
            // traffic goes or what it reads".
            (
                "proxy-url",
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\n    proxy-url: http://proxy.example.com:3128\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: abc\n",
            ),
            (
                "client-certificate",
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    client-certificate: /var/run/secrets/client.crt\n",
            ),
            (
                "client-key",
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    client-key: /var/run/secrets/client.key\n",
            ),
            (
                "as / as-groups",
                "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: abc\n    as: system:admin\n",
            ),
        ] {
            let material = secret("workload", &[(KEY_KUBECONFIG, document.as_bytes())]);
            let err = parse(&material).expect_err(
                "a kubeconfig that runs a binary, reads a pod file, proxies, or delegates auth is \
                 refused",
            );
            assert!(
                matches!(err, ClusterError::UnsupportedKubeconfig { .. }),
                "{field}: {err:?}"
            );
            let message = err.to_string();
            assert!(message.contains(field), "{field}: {message}");
            assert!(
                !message.contains("/var/run/secrets"),
                "{field}: the refusal must not echo the path: {message}"
            );
        }

        // `as-groups` alone is refused too (FerrisCD owns impersonation, `T12.3`).
        let as_groups = secret(
            "workload",
            &[(
                KEY_KUBECONFIG,
                b"apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: abc\n    as-groups:\n      - system:masters\n",
            )],
        );
        let err = parse(&as_groups).expect_err("as-groups must be refused");
        assert!(
            matches!(err, ClusterError::UnsupportedKubeconfig { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("as / as-groups"), "{err}");

        let material = secret(
            "workload",
            &[(
                KEY_KUBECONFIG,
                b"apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: static-token\n",
            )],
        );
        let parsed = parse(&material).expect("a static-token kubeconfig must parse");
        assert_eq!(parsed.auth_kind(), "kubeconfig");
        // Finding M1: the client configuration never carries a proxy, not even one the ambient
        // environment (`HTTPS_PROXY`) or the kubeconfig might suggest — cluster traffic is direct.
        assert!(
            parsed
                .kube_config(ClusterOptions::strict())
                .expect("the kubeconfig builds a configuration")
                .proxy_url
                .is_none(),
            "a cluster registration must never inherit a proxy"
        );

        // A kubeconfig without a static credential can only ever be anonymous.
        let anonymous = secret(
            "workload",
            &[(
                KEY_KUBECONFIG,
                b"apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user: {}\n",
            )],
        );
        let err = parse(&anonymous).expect_err("a credential-less kubeconfig must be refused");
        assert!(
            matches!(err, ClusterError::MalformedKubeconfig { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("static credential"), "{err}");
    }

    /// The synthesized kubeconfig is assembled with escaped scalars, so a hostile token cannot
    /// inject another field into the document.
    #[tokio::test]
    async fn a_token_containing_yaml_metacharacters_cannot_inject_fields() {
        let hostile = "abc\n    insecure-skip-tls-verify: true\n# injected";
        let material = with_data(
            token_secret("workload"),
            KEY_BEARER_TOKEN,
            hostile.as_bytes(),
        );
        let parsed = parse(&material).expect("the material still parses");
        let config = parsed
            .kube_config(ClusterOptions::strict())
            .expect("the token is escaped into a single scalar");
        assert!(
            !config.accept_invalid_certs,
            "an injected insecure-skip-tls-verify must not take effect"
        );
        assert!(
            config.auth_info.token.is_some(),
            "the token still reaches the client configuration"
        );
    }

    /// **Finding M4:** the kubeconfig is written by whoever can create the `Secret`, so it goes
    /// through the same YAML budgets and alias-replay limits a rendered manifest does. A bomb here
    /// would otherwise expand on the watch task that observed it.
    #[tokio::test]
    async fn an_alias_bomb_kubeconfig_is_refused_before_it_can_expand() {
        let document = "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n    server: https://workload:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\nusers:\n- name: u\n  user:\n    token: static-token\n# An unknown top-level key lands in `Kubeconfig::other` as a `serde_json::Value`, so the\n# aliases below are expanded for real unless the replay limits stop them.\nextras:\n  a: &a [\"lol\", \"lol\", \"lol\", \"lol\", \"lol\", \"lol\", \"lol\", \"lol\", \"lol\"]\n  b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n  c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n  d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n  e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]\n  f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]\n  g: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]\n  h: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]\n";
        let material = secret("workload", &[(KEY_KUBECONFIG, document.as_bytes())]);
        let err = parse(&material).expect_err("an alias bomb must be refused");
        assert!(
            matches!(err, ClusterError::MalformedKubeconfig { .. }),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(
            !message.contains("lol"),
            "a refusal must not echo the YAML: {message}"
        );
    }

    /// **Finding M11:** an API server URL is written like a repository URL and routinely carries
    /// userinfo, so no refusal — and no log line — may echo it verbatim.
    #[tokio::test]
    async fn a_server_url_with_userinfo_is_redacted_in_every_refusal() {
        // A scheme FerrisCD refuses, with the userinfo intact, and a bare token used as userinfo
        // (the personal-access-token shape).
        for (server, credential) in [
            ("ftp://robot:s3cr3t-token@workload:6443", "s3cr3t-token"),
            ("ftp://ghp-token-value@workload:6443", "ghp-token-value"),
        ] {
            let material = with_data(token_secret("workload"), KEY_SERVER, server.as_bytes());
            let err = parse(&material).expect_err("a non-https API server must be refused");
            let rendered = format!("{err} {err:?}");
            assert!(
                !rendered.contains(credential),
                "the refusal must not echo the credential in {server:?}: {rendered}"
            );
            assert!(!rendered.contains(TOKEN), "{server:?}: {rendered}");
        }

        // What is left is the diagnostic an operator needs: the host and the account, never the
        // secret half.
        let material = with_data(
            token_secret("workload"),
            KEY_SERVER,
            b"ftp://robot:s3cr3t-token@workload:6443",
        );
        let err = parse(&material).expect_err("refused");
        assert!(
            err.to_string().contains("ftp://robot:***@workload:6443"),
            "{err}"
        );

        // Finding M-new-2: an *accepted* server with userinfo lands in `Debug` too (a `Secret` is
        // logged when it is seeded), so the parsed material is redacted the same way.
        let material = with_data(
            token_secret("workload"),
            KEY_SERVER,
            b"https://robot:s3cr3t-token@workload.example.com:6443",
        );
        let parsed = parse(&material).expect("an https server with userinfo is still usable");
        let rendered = format!("{parsed:?}");
        assert!(
            !rendered.contains("s3cr3t-token"),
            "the Debug impl must not print the userinfo password: {rendered}"
        );
        assert!(
            rendered.contains("https://robot:***@workload.example.com:6443"),
            "the host and the account stay readable: {rendered}"
        );
    }

    // -----------------------------------------------------------------
    // Registry behaviour
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn get_answers_the_in_cluster_handle_for_the_control_plane() {
        let builder = Arc::new(FakeBuilder::default());
        let manager = manager(builder.clone());
        assert!(manager.is_empty());

        let in_cluster = manager
            .get(IN_CLUSTER)
            .expect("in-cluster is always available");
        assert_eq!(in_cluster.name().as_str(), IN_CLUSTER);
        assert!(
            Arc::ptr_eq(&in_cluster, manager.in_cluster()),
            "the in-cluster handle is the control plane's own"
        );
        assert_eq!(builder.builds.load(Ordering::SeqCst), 0);
        // The `in-cluster` name never comes from a `Secret`.
        assert!(matches!(
            ClusterName::parse(IN_CLUSTER),
            Err(ClusterError::ReservedName { .. })
        ));
    }

    /// **Trap guard:** an unregistered cluster is a terminal error naming what to register.
    #[tokio::test]
    async fn an_unregistered_cluster_is_a_terminal_not_found() {
        let manager = manager(Arc::new(FakeBuilder::default()));
        let err = manager.get("prod").expect_err("nothing registers prod");
        assert!(matches!(err, ClusterError::NotFound { .. }), "{err:?}");
        assert!(err.is_not_found());
        assert!(err.is_terminal());
        assert!(err.to_string().contains("prod"), "{err}");
        assert!(err.to_string().contains(CONTROL_PLANE_NAMESPACE), "{err}");

        let reconcile = ReconcileError::from(err);
        assert_eq!(
            reconcile.failure_class(),
            crate::FailureClass::Terminal,
            "a missing cluster registration must never be retried"
        );
        assert!(!reconcile.is_already_deleted());
    }

    #[tokio::test]
    async fn seeding_a_cluster_reuses_an_unchanged_handle_and_rebuilds_a_changed_one() {
        let builder = Arc::new(FakeBuilder::default());
        let manager = manager(builder.clone());

        assert_eq!(
            manager.seed(&token_secret("workload")).await.expect("seed"),
            ClusterChange::Added
        );
        assert_eq!(manager.names(), vec!["workload".to_owned()]);
        assert_eq!(manager.len(), 1);
        let first = manager.get("workload").expect("registered");
        assert_eq!(builder.builds.load(Ordering::SeqCst), 1);

        // The same material again (a re-list after a reconnect): the handle is reused, so the
        // connector, its connection pool and every cached impersonated client survive.
        assert_eq!(
            manager
                .seed(&token_secret("workload"))
                .await
                .expect("re-seed"),
            ClusterChange::Unchanged
        );
        let again = manager.get("workload").expect("registered");
        assert!(
            Arc::ptr_eq(&first, &again),
            "an unchanged Secret must not rebuild the handle"
        );
        assert_eq!(manager.rebuilds(), 1);

        // A rotated token: the handle is rebuilt.
        let rotated = with_data(token_secret("workload"), KEY_BEARER_TOKEN, b"rotated-token");
        assert_eq!(
            manager.seed(&rotated).await.expect("rotate"),
            ClusterChange::Rebuilt
        );
        let rebuilt = manager.get("workload").expect("registered");
        assert!(
            !Arc::ptr_eq(&first, &rebuilt),
            "a changed Secret must invalidate the handle (its credentials are gone)"
        );
        assert_eq!(manager.rebuilds(), 2);
        assert_eq!(manager.len(), 1, "a rebuild never duplicates an entry");
    }

    #[tokio::test]
    async fn deleting_the_secret_removes_the_cluster_and_the_next_lookup_fails_closed() {
        let manager = manager(Arc::new(FakeBuilder::default()));
        manager.seed(&token_secret("workload")).await.expect("seed");
        assert!(manager.get("workload").is_ok());

        assert!(manager.forget("workload"));
        assert!(!manager.forget("workload"), "forgetting twice is a no-op");
        assert!(manager.is_empty());
        assert!(matches!(
            manager.get("workload"),
            Err(ClusterError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn a_builder_failure_never_registers_a_half_built_cluster() {
        let builder = Arc::new(FakeBuilder::default());
        let manager = manager(builder.clone());
        builder.fail.store(true, Ordering::SeqCst);
        let err = manager
            .seed(&token_secret("workload"))
            .await
            .expect_err("build fails");
        assert!(matches!(err, ClusterError::Transport { .. }), "{err:?}");
        assert!(manager.is_empty());
        assert_eq!(manager.rebuilds(), 0);
    }

    /// **Finding H1:** the blocking half of a build runs on a blocking worker, never on the async
    /// worker that observed the `Secret`. Loading a CA bundle into a `rustls` store stalls whatever
    /// thread it runs on, and that thread also drives the watch loop and every queued reconcile.
    #[tokio::test(flavor = "current_thread")]
    async fn the_blocking_half_of_a_build_runs_off_the_async_worker() {
        let caller = std::thread::current().id();
        let worker = KubeClusterBuilder::offload(
            "workload".to_owned(),
            CONTROL_PLANE_NAMESPACE.to_owned(),
            || Ok(std::thread::current().id()),
        )
        .await
        .expect("the blocking task answers");
        assert_ne!(
            worker, caller,
            "the blocking half of a cluster build must not run on the async worker"
        );
    }

    /// **Finding H1 (the seam):** the registry awaits the builder's future instead of calling a
    /// blocking `build`, and the production builder really produces a handle through that seam.
    #[tokio::test]
    async fn seeding_awaits_the_builders_future_and_the_production_builder_builds_a_handle() {
        let builder = Arc::new(FakeBuilder::default());
        let manager = manager(builder.clone());
        manager
            .seed(&token_secret("workload"))
            .await
            .expect("the registry awaits the builder");
        assert_eq!(
            builder.yields.load(Ordering::SeqCst),
            1,
            "the builder's future must be polled to completion"
        );

        crate::impersonation::ensure_crypto_provider();
        let production = KubeClusterBuilder::new(ClusterOptions::strict());
        let material = parse(&token_secret("workload")).expect("the material parses");
        let handle = production
            .build(&material)
            .await
            .expect("a token registration with a real CA builds a client");
        assert_eq!(handle.name().as_str(), "workload");
        assert_eq!(handle.target().name(), "workload");
        assert_eq!(
            handle.base_connector().connectors(),
            1,
            "one connector per cluster, shared by every impersonated identity on it"
        );
    }

    /// **Finding H1 (the proof):** the production builder's blocking half really runs on a blocking
    /// worker. The thread is recorded *inside* `build_blocking`, so inlining it into `build` later —
    /// the regression this guards — would run it on the current-thread runtime's own thread and fail
    /// here.
    #[tokio::test(flavor = "current_thread")]
    async fn the_production_builder_never_builds_on_the_async_worker() {
        crate::impersonation::ensure_crypto_provider();
        let caller = std::thread::current().id();
        BLOCKING_THREADS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();

        let material = parse(&token_secret("workload")).expect("the material parses");
        let handle = KubeClusterBuilder::new(ClusterOptions::strict())
            .build(&material)
            .await
            .expect("a token registration with a real CA builds a client");
        assert_eq!(handle.name().as_str(), "workload");

        let threads = BLOCKING_THREADS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert!(
            !threads.is_empty(),
            "the builder must reach `build_blocking`, not a reimplementation of it"
        );
        assert!(
            !threads.contains(&caller),
            "the blocking half of a cluster build must not run on the async worker (finding H1)"
        );
    }

    // -----------------------------------------------------------------
    // The watch seam (no cluster needed)
    // -----------------------------------------------------------------

    /// A scripted registration source: the whole add/change/delete behaviour without a cluster.
    struct ScriptedSource {
        events: Mutex<Option<Vec<Result<ClusterSecretEvent, ClusterWatchError>>>>,
    }

    impl ScriptedSource {
        fn new(events: Vec<Result<ClusterSecretEvent, ClusterWatchError>>) -> Self {
            Self {
                events: Mutex::new(Some(events)),
            }
        }
    }

    impl ClusterSecretSource for ScriptedSource {
        fn events(&self) -> BoxStream<'static, Result<ClusterSecretEvent, ClusterWatchError>> {
            let events = self
                .events
                .lock()
                .expect("scripted source lock")
                .take()
                .unwrap_or_default();
            futures::stream::iter(events).boxed()
        }
    }

    fn scripted(
        events: Vec<Result<ClusterSecretEvent, ClusterWatchError>>,
    ) -> Arc<dyn ClusterSecretSource> {
        Arc::new(ScriptedSource::new(events))
    }

    #[tokio::test]
    async fn the_watch_seeds_rebuilds_and_invalidates_registrations() {
        let builder = Arc::new(FakeBuilder::default());
        let manager = Arc::new(manager(builder.clone()));

        manager
            .clone()
            .run(
                scripted(vec![Ok(ClusterSecretEvent::Upsert(Box::new(
                    token_secret("workload"),
                )))]),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(manager.names(), vec!["workload".to_owned()]);
        let first = manager.get("workload").expect("registered");

        // A re-list with the same material reuses the handle.
        manager
            .clone()
            .run(
                scripted(vec![Ok(ClusterSecretEvent::Upsert(Box::new(
                    token_secret("workload"),
                )))]),
                CancellationToken::new(),
            )
            .await;
        assert!(Arc::ptr_eq(
            &first,
            &manager.get("workload").expect("registered")
        ));

        // A deletion invalidates it.
        manager
            .clone()
            .run(
                scripted(vec![Ok(ClusterSecretEvent::Deleted("workload".to_owned()))]),
                CancellationToken::new(),
            )
            .await;
        assert!(manager.is_empty());
        assert!(manager.get("workload").is_err());
    }

    /// **Finding H2:** a `Secret` deleted while the watch was reconnecting produces **no**
    /// `Delete`, so a completed re-list is what has to revoke it. A registration that survives that
    /// gap stays addressable with a credential the operator already deleted.
    ///
    /// The `Upsert`s inside the list stand for the watcher's `InitApply` events (the production
    /// source maps both onto the same variant).
    #[tokio::test]
    async fn a_re_list_that_omits_a_secret_forgets_that_registration() {
        let manager = Arc::new(manager(Arc::new(FakeBuilder::default())));

        // The initial list registers both clusters.
        manager
            .clone()
            .run(
                scripted(vec![
                    Ok(ClusterSecretEvent::Init),
                    Ok(ClusterSecretEvent::Upsert(Box::new(token_secret("a")))),
                    Ok(ClusterSecretEvent::Upsert(Box::new(token_secret("b")))),
                    Ok(ClusterSecretEvent::InitDone),
                ]),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(manager.names(), vec!["a".to_owned(), "b".to_owned()]);

        // `b`'s Secret was deleted while the watch was down: the re-list only reports `a`, and no
        // `Delete` is ever delivered for `b`.
        manager
            .clone()
            .run(
                scripted(vec![
                    Ok(ClusterSecretEvent::Init),
                    Ok(ClusterSecretEvent::Upsert(Box::new(token_secret("a")))),
                    Ok(ClusterSecretEvent::InitDone),
                ]),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(
            manager.names(),
            vec!["a".to_owned()],
            "the registration the re-list omitted must be forgotten"
        );
        assert!(
            matches!(manager.get("b"), Err(ClusterError::NotFound { .. })),
            "a revoked credential must stop being addressable"
        );
        assert!(manager.get("a").is_ok(), "the observed registration stays");

        // An empty list is the same rule taken to its limit: nothing is registered any more.
        manager
            .clone()
            .run(
                scripted(vec![
                    Ok(ClusterSecretEvent::Init),
                    Ok(ClusterSecretEvent::InitDone),
                ]),
                CancellationToken::new(),
            )
            .await;
        assert!(manager.is_empty());
    }

    /// The sweep only applies to a **completed** list: an `Init` on its own (a reconnect that has
    /// not listed anything yet) must never forget the registry.
    #[tokio::test]
    async fn an_unfinished_re_list_forgets_nothing() {
        let manager = Arc::new(manager(Arc::new(FakeBuilder::default())));
        manager.seed(&token_secret("workload")).await.expect("seed");

        manager
            .clone()
            .run(
                scripted(vec![
                    Ok(ClusterSecretEvent::Init),
                    Ok(ClusterSecretEvent::Upsert(Box::new(token_secret("other")))),
                ]),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(
            manager.names(),
            vec!["other".to_owned(), "workload".to_owned()],
            "an in-flight list must not revoke anything yet"
        );

        // A stray `InitDone` (no `Init` of ours) is not a snapshot either: the registry is a
        // fail-closed map only *after* a list it watched start.
        manager
            .clone()
            .run(
                scripted(vec![Ok(ClusterSecretEvent::InitDone)]),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(
            manager.names(),
            vec!["other".to_owned(), "workload".to_owned()],
            "an unbracketed InitDone must never empty the registry"
        );
    }

    /// **Trap guard:** a `Secret` that becomes unusable invalidates the previous handle instead of
    /// leaving an `Application` deploying with credentials the operator already revoked.
    #[tokio::test]
    async fn an_unusable_secret_invalidates_the_previous_registration() {
        let manager = Arc::new(manager(Arc::new(FakeBuilder::default())));
        manager.seed(&token_secret("workload")).await.expect("seed");
        assert!(manager.get("workload").is_ok());

        let mut broken = token_secret("workload");
        broken.data.as_mut().expect("data").remove(KEY_BEARER_TOKEN);
        manager
            .clone()
            .run(
                scripted(vec![Ok(ClusterSecretEvent::Upsert(Box::new(broken)))]),
                CancellationToken::new(),
            )
            .await;

        assert!(
            manager.is_empty(),
            "the unusable registration must be forgotten, never left half-usable"
        );
        assert!(matches!(
            manager.get("workload"),
            Err(ClusterError::NotFound { .. })
        ));
    }

    /// Renaming a registration with the `name` key moves it: the previous name is dropped, so no
    /// stale cluster stays addressable with the credential the `Secret` no longer holds.
    #[tokio::test]
    async fn renaming_a_registration_removes_the_previous_name() {
        let manager = manager(Arc::new(FakeBuilder::default()));
        manager.seed(&token_secret("workload")).await.expect("seed");
        assert_eq!(manager.names(), vec!["workload".to_owned()]);

        let renamed = with_data(token_secret("workload"), KEY_NAME, b"eu-prod");
        assert_eq!(
            manager.seed(&renamed).await.expect("rename"),
            ClusterChange::Added
        );
        assert_eq!(manager.names(), vec!["eu-prod".to_owned()]);
        assert!(matches!(
            manager.get("workload"),
            Err(ClusterError::NotFound { .. })
        ));
        assert!(manager.get("eu-prod").is_ok());
    }

    /// A registration may rename itself with the `name` key, so a deletion has to be resolved back
    /// through the `Secret` name — otherwise a deleted `Secret` would leave a stale handle (with a
    /// revoked credential) addressable.
    #[tokio::test]
    async fn deleting_a_renamed_secret_removes_its_registration() {
        let manager = Arc::new(manager(Arc::new(FakeBuilder::default())));
        let renamed = with_data(token_secret("workload-secret"), KEY_NAME, b"eu-prod");
        manager
            .clone()
            .run(
                scripted(vec![Ok(ClusterSecretEvent::Upsert(Box::new(renamed)))]),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(manager.names(), vec!["eu-prod".to_owned()]);

        manager
            .clone()
            .run(
                scripted(vec![Ok(ClusterSecretEvent::Deleted(
                    "workload-secret".to_owned(),
                ))]),
                CancellationToken::new(),
            )
            .await;
        assert!(
            manager.is_empty(),
            "the Secret's deletion must remove the cluster it registered"
        );
        assert!(manager.get("eu-prod").is_err());
        assert!(manager.forget_secret("workload-secret").is_empty());
    }

    #[tokio::test]
    async fn the_watch_stops_when_cancelled() {
        struct Silent;
        impl ClusterSecretSource for Silent {
            fn events(&self) -> BoxStream<'static, Result<ClusterSecretEvent, ClusterWatchError>> {
                futures::stream::pending().boxed()
            }
        }

        let manager = Arc::new(manager(Arc::new(FakeBuilder::default())));
        let stop = CancellationToken::new();
        let run = manager.run(Arc::new(Silent), stop.clone());
        stop.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), run)
            .await
            .expect("cancellation must end the watch loop");
    }

    #[tokio::test]
    async fn the_watch_is_namespaced_and_label_filtered_by_construction() {
        let source = SecretClusterSource::new(offline_client(), CONTROL_PLANE_NAMESPACE);
        assert_eq!(source.namespace(), CONTROL_PLANE_NAMESPACE);
        let debug = format!("{source:?}");
        assert!(debug.contains(CONTROL_PLANE_NAMESPACE), "{debug}");
        assert_eq!(
            SecretClusterSource::label_selector(),
            format!("{SECRET_TYPE_LABEL}={SECRET_TYPE_CLUSTER}")
        );
        assert!(
            debug.contains(&SecretClusterSource::label_selector()),
            "{debug}"
        );
    }

    /// A registered cluster's target wires **its own** client seams, never the control plane's.
    #[tokio::test]
    async fn a_registered_cluster_targets_its_own_client_and_discovery() {
        let manager = manager(Arc::new(FakeBuilder::default()));
        manager.seed(&token_secret("workload")).await.expect("seed");
        let handle = manager.get("workload").expect("registered");
        let target = handle.target();
        assert_eq!(target.name(), "workload");
        assert!(target.impersonation().is_some());
        assert_eq!(
            target.access().identity(),
            &ClusterIdentity::Controller,
            "without a serviceAccountName a pass runs as the Secret's credential"
        );
        // The target's discovery is the handle's own cache (not a fresh, empty one).
        assert_eq!(
            target.discovery().generation(),
            handle.discovery().generation()
        );
        assert_eq!(
            target.discovery().ttl(),
            handle.discovery().ttl(),
            "the remote cluster's discovery cache is the handle's, so its snapshot is shared"
        );

        let local = manager.in_cluster().target();
        assert_eq!(local.name(), IN_CLUSTER);
        let debug = format!("{target:?}");
        assert!(!debug.contains(TOKEN), "{debug}");
    }

    /// Nothing in this module prints a credential, including an error built from an unusable Secret.
    #[tokio::test]
    async fn no_error_carries_credential_material() {
        let broken = with_data(token_secret("workload"), KEY_TLS_KEY, CLIENT_KEY.as_bytes());
        let err = parse(&broken).expect_err("token + key is ambiguous");
        let rendered = format!("{err} {err:?}");
        assert!(!rendered.contains(TOKEN), "{rendered}");
        assert!(!rendered.contains("not-a-real-key"), "{rendered}");
    }
}

//! `AppProject` policy enforcement (`T12.1`, finding C8 / finding M6).
//!
//! This module replaces the Phase 05–11 `PermissivePolicy` stub (which allowed everything) with the
//! real multi-tenancy boundary. It answers two different questions, and both matter:
//!
//! * **Before rendering** ([`AppProjectPolicy::check_application`]): may this `Application`
//!   exist here at all? Its namespace, its repository, its destination, and the ServiceAccount it
//!   asks for must all be listed by the referenced `AppProject`. Checking the repository first is
//!   what keeps an unauthorized clone from ever happening.
//! * **After Stage-2 scope normalization** ([`AppProjectPolicy::check_resources`]): does every
//!   *rendered* object stay inside the project? Checking only `spec.destination.namespace` is
//!   trivially bypassed by a manifest that hardcodes `metadata.namespace: kube-system` or ships a
//!   `ClusterRoleBinding`, so each resource is checked on its **actual** namespace and its
//!   `(group, kind)`.
//!
//! The engine stays pure and offline: the caller (the controller) fetches the `AppProject` from the
//! control-plane namespace and hands the spec in. A project that does not exist is a terminal
//! [`PolicyError::ProjectNotFound`] instead of a silent "allow" (fail closed).
//!
//! Matching is deterministic glob matching ([`wildcard_matches`]): `*` matches any run of
//! characters (including none) and `?` matches exactly one, for group, kind, namespace, cluster,
//! repository, and ServiceAccount patterns. Kubernetes is case-sensitive here, so matching is too.

use ferriscd_crd::project::{AppProjectSpec, GroupKind, WILDCARD};
use ferriscd_crd::{AppProject, Application};
use kube::ResourceExt;

use crate::manifest::{DesiredResource, redact_repo_url};

use super::namespace_scope::ApplicationScope;

/// Matches `value` against a glob `pattern` where `*` matches any run of characters (including
/// none) and `?` matches exactly one.
///
/// The implementation is a single left-to-right scan with one backtrack point, so it is linear in
/// practice and — unlike a regex engine — has no catastrophic backtracking case. Matching is
/// case-sensitive and byte-for-byte otherwise: Kubernetes names, groups, and kinds are.
#[must_use]
pub fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0_usize, 0_usize);
    // Position of the last `*` and the value index it currently consumes up to.
    let mut star: Option<usize> = None;
    let mut resume = 0_usize;

    while v < value.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some(p);
                p += 1;
                resume = v;
            }
            Some(&expected) if expected == '?' || expected == value[v] => {
                p += 1;
                v += 1;
            }
            _ => match star {
                Some(position) => {
                    p = position + 1;
                    resume += 1;
                    v = resume;
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&'*') {
        p += 1;
    }
    p == pattern.len()
}

/// Policy violations raised while evaluating one `Application`.
///
/// Every variant is **terminal**: no amount of retrying changes the fact that the project does not
/// permit the `Application`, so the controller backs off on the terminal interval until the operand
/// (or the project) changes. Messages name the offending field and key, and never carry a
/// credential: repository URLs are printed with any `user:password@` userinfo stripped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The referenced `AppProject` does not exist in the control-plane namespace.
    #[error(
        "AppProject {project:?} was not found in namespace {namespace:?}: create it before \
         syncing {application} (a missing project is never treated as permissive)"
    )]
    ProjectNotFound {
        /// `spec.project` of the `Application`.
        project: String,
        /// Namespace the project was looked up in (the control-plane namespace).
        namespace: String,
        /// `<namespace>/<name>` of the `Application`.
        application: String,
    },

    /// The `Application` lives in a namespace the controller does not watch.
    #[error(
        "{application} lives in namespace {namespace:?}, which this controller does not reconcile \
         (allowed: {allowed}): widen --application-namespaces to include it"
    )]
    ApplicationNamespaceNotAllowed {
        /// `<namespace>/<name>` of the `Application`.
        application: String,
        /// The `Application`'s own namespace.
        namespace: String,
        /// The namespaces the controller does watch.
        allowed: String,
    },

    /// A tenant `Application` (outside the control-plane namespace) names no ServiceAccount.
    #[error(
        "{application} lives in tenant namespace {namespace:?} but sets no \
         spec.serviceAccountName: a tenant Application must name the ServiceAccount it deploys as, \
         so it is never reconciled with the controller's own ServiceAccount"
    )]
    TenantServiceAccountRequired {
        /// `<namespace>/<name>` of the `Application`.
        application: String,
        /// The tenant namespace.
        namespace: String,
    },

    /// The `Application`'s source URL (`spec.source.git.repoURL` or `spec.source.oci.url`) is not
    /// permitted by `spec.sourceRepos`.
    #[error(
        "{application}: source URL {repo_url:?} (spec.source.git.repoURL or spec.source.oci.url) \
         is not permitted by AppProject {project:?} spec.sourceRepos"
    )]
    SourceRepoNotAllowed {
        /// `<namespace>/<name>` of the `Application`.
        application: String,
        /// The referenced project.
        project: String,
        /// The rejected repository URL (credentials stripped).
        repo_url: String,
    },

    /// The `Application`'s namespace is not permitted by `spec.sourceNamespaces`.
    #[error(
        "{application} lives in namespace {namespace:?}, which AppProject {project:?} does not list \
         in spec.sourceNamespaces"
    )]
    SourceNamespaceNotAllowed {
        /// `<namespace>/<name>` of the `Application`.
        application: String,
        /// The `Application`'s own namespace.
        namespace: String,
        /// The referenced project.
        project: String,
    },

    /// `spec.destination` is not permitted by `spec.destinations`.
    #[error(
        "{application}: spec.destination (cluster {cluster:?}, namespace {namespace:?}) is not \
         permitted by AppProject {project:?} spec.destinations"
    )]
    DestinationNotAllowed {
        /// `<namespace>/<name>` of the `Application`.
        application: String,
        /// The referenced project.
        project: String,
        /// The destination cluster.
        cluster: String,
        /// The destination namespace.
        namespace: String,
    },

    /// `spec.serviceAccountName` is not permitted by `spec.allowedServiceAccounts`.
    #[error(
        "{application}: spec.serviceAccountName {service_account:?} in namespace {namespace:?} is \
         not permitted by AppProject {project:?} spec.allowedServiceAccounts"
    )]
    ServiceAccountNotAllowed {
        /// `<namespace>/<name>` of the `Application`.
        application: String,
        /// The referenced project.
        project: String,
        /// The destination namespace the ServiceAccount resolves in.
        namespace: String,
        /// The requested ServiceAccount name.
        service_account: String,
    },

    /// A rendered resource's resolved namespace and its `metadata.namespace` disagree.
    #[error(
        "{resource} resolves to namespace {resolved_namespace:?} but declares metadata.namespace \
         {metadata_namespace:?}: refusing to apply a resource with an ambiguous scope"
    )]
    NamespaceMismatch {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// The namespace the scope normalizer resolved.
        resolved_namespace: String,
        /// The namespace the manifest declares.
        metadata_namespace: String,
    },

    /// A rendered resource targets a namespace the project does not permit.
    #[error(
        "{resource} targets namespace {namespace:?}, which AppProject {project:?} does not permit \
         for cluster {cluster:?} (spec.destinations)"
    )]
    ResourceNamespaceNotAllowed {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// The referenced project.
        project: String,
        /// The destination cluster.
        cluster: String,
        /// The namespace the resource actually targets.
        namespace: String,
    },

    /// A cluster-scoped rendered resource is not in `spec.clusterResourceWhitelist`.
    #[error(
        "{resource}: cluster-scoped {group_kind} is not permitted by AppProject {project:?} \
         spec.clusterResourceWhitelist"
    )]
    ClusterResourceNotAllowed {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// The referenced project.
        project: String,
        /// API group (`core` for the core group).
        group_kind: String,
    },

    /// A namespaced rendered resource is not in `spec.namespaceResourceWhitelist`.
    #[error(
        "{resource}: {group_kind} is not permitted by AppProject {project:?} \
         spec.namespaceResourceWhitelist"
    )]
    NamespaceResourceNotAllowed {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// The referenced project.
        project: String,
        /// `group/kind` of the offending resource.
        group_kind: String,
    },

    /// A namespaced rendered resource is denied by `spec.namespaceResourceBlacklist`.
    #[error(
        "{resource}: {group_kind} is denied by AppProject {project:?} \
         spec.namespaceResourceBlacklist"
    )]
    NamespaceResourceBlacklisted {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// The referenced project.
        project: String,
        /// `group/kind` of the offending resource.
        group_kind: String,
    },
}

impl PolicyError {
    /// Always `false`: every policy violation is deterministic, so retrying cannot fix it.
    ///
    /// The controller therefore applies its terminal backoff and waits for the operator (or the
    /// `AppProject`) to change instead of spinning a work queue.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        false
    }
}

/// A validated `AppProject` used to enforce its allow-lists on one `Application`.
///
/// Cheap to clone and free of I/O: the fetched [`AppProject`] is reduced to its spec once per
/// reconcile, then every pre-render and per-resource check runs against that snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct AppProjectPolicy {
    name: String,
    spec: AppProjectSpec,
}

impl AppProjectPolicy {
    /// Builds a policy from a project name and spec.
    #[must_use]
    pub fn new(name: impl Into<String>, spec: AppProjectSpec) -> Self {
        Self {
            name: name.into(),
            spec,
        }
    }

    /// Builds a policy from a fetched [`AppProject`].
    #[must_use]
    pub fn from_project(project: &AppProject) -> Self {
        Self {
            name: project.name_any(),
            spec: project.spec.clone(),
        }
    }

    /// The `AppProject` name, used in every violation message.
    #[must_use]
    pub fn project_name(&self) -> &str {
        &self.name
    }

    /// The project spec this policy enforces.
    #[must_use]
    pub fn spec(&self) -> &AppProjectSpec {
        &self.spec
    }

    /// Whether `namespace` is listed by `spec.sourceNamespaces`.
    ///
    /// An **empty** list authorizes no namespace: like every other allow-list in a project, "not
    /// listed" is a denial, never "any" (finding M2). An *omitted* `sourceNamespaces` is a
    /// different thing — the CRD's schema default fills in the control-plane namespace.
    #[must_use]
    pub fn allows_source_namespace(&self, namespace: &str) -> bool {
        self.spec
            .source_namespaces
            .iter()
            .any(|pattern| wildcard_matches(pattern.trim(), namespace.trim()))
    }

    /// Whether `repo_url` is permitted by `spec.sourceRepos`.
    ///
    /// Entries are glob patterns; a leading `!` denies. A deny always wins, and an empty
    /// `sourceRepos` permits nothing — an unset repository list must never mean "any repository".
    #[must_use]
    pub fn allows_source_repo(&self, repo_url: &str) -> bool {
        let repo_url = repo_url.trim();
        let mut allowed = false;
        for entry in &self.spec.source_repos {
            let entry = entry.trim();
            if let Some(denied) = entry.strip_prefix('!') {
                if wildcard_matches(denied.trim(), repo_url) {
                    return false;
                }
            } else if wildcard_matches(entry, repo_url) {
                allowed = true;
            }
        }
        allowed
    }

    /// Whether `(cluster, namespace)` is permitted by `spec.destinations`.
    ///
    /// An **empty** `destinations` list permits no destination at all (finding M2): an
    /// `Application` that names no allowed `(cluster, namespace)` cannot be synced, and no rendered
    /// resource may target one.
    #[must_use]
    pub fn allows_destination(&self, cluster: &str, namespace: &str) -> bool {
        let cluster = cluster.trim();
        let namespace = namespace.trim();
        self.spec.destinations.iter().any(|destination| {
            wildcard_matches(destination.cluster.trim(), cluster)
                && wildcard_matches(destination.namespace.trim(), namespace)
        })
    }

    /// Whether `service_account` in `namespace` is permitted by `spec.allowedServiceAccounts`.
    ///
    /// Entries are `*`, `<namespace>/<name>`, `<namespace>:<name>`, or a wildcard form of those
    /// (`payments/*`). An entry without a namespace separator permits nothing: the ServiceAccount
    /// always resolves inside the destination namespace, so a bare name would be ambiguous and is
    /// therefore denied (fail closed). An **empty** list permits no impersonation at all
    /// (finding M2), which is the safe default for a project nobody has curated.
    #[must_use]
    pub fn allows_service_account(&self, namespace: &str, service_account: &str) -> bool {
        let namespace = namespace.trim();
        let service_account = service_account.trim();
        if service_account.is_empty() {
            return false;
        }
        self.spec.allowed_service_accounts.iter().any(|entry| {
            let entry = entry.trim();
            if entry == WILDCARD {
                return true;
            }
            let Some((namespace_pattern, name_pattern)) = split_service_account_entry(entry) else {
                return false;
            };
            wildcard_matches(namespace_pattern.trim(), namespace)
                && wildcard_matches(name_pattern.trim(), service_account)
        })
    }

    /// Whether the cluster-scoped `(group, kind)` is permitted by
    /// `spec.clusterResourceWhitelist`.
    ///
    /// An empty whitelist permits **no** cluster-scoped resource: a project that says nothing about
    /// cluster scope must not be able to create a `ClusterRole`.
    #[must_use]
    pub fn allows_cluster_resource(&self, group: &str, kind: &str) -> bool {
        self.spec
            .cluster_resource_whitelist
            .iter()
            .any(|allowed| group_kind_matches(allowed, group, kind))
    }

    /// Whether the namespaced `(group, kind)` is permitted by the project.
    ///
    /// Argo-compatible semantics: an empty `spec.namespaceResourceWhitelist` permits every
    /// namespaced GroupKind, while a non-empty one is an allow-list. The blacklist always wins over
    /// both.
    #[must_use]
    pub fn allows_namespace_resource(&self, group: &str, kind: &str) -> bool {
        if self
            .spec
            .namespace_resource_blacklist
            .iter()
            .any(|denied| group_kind_matches(denied, group, kind))
        {
            return false;
        }
        self.spec.namespace_resource_whitelist.is_empty()
            || self
                .spec
                .namespace_resource_whitelist
                .iter()
                .any(|allowed| group_kind_matches(allowed, group, kind))
    }

    /// Runs the pre-render checks for one `Application` (`T12.1` and the `T12.2` tenant guard).
    ///
    /// Order matters: the namespace-scope guard runs first (the controller must not reconcile an
    /// `Application` it does not watch, and a tenant `Application` must name its ServiceAccount),
    /// then the project allow-lists in the order the roadmap lists them — `sourceNamespaces`,
    /// `sourceRepos`, `destinations`, `allowedServiceAccounts`.
    ///
    /// # Errors
    ///
    /// See [`PolicyError`]; every variant is terminal.
    pub fn check_application(
        &self,
        app: &Application,
        scope: &ApplicationScope,
    ) -> Result<(), PolicyError> {
        let application = application_id(app);
        let app_namespace = app.namespace().unwrap_or_default();
        let app_namespace = app_namespace.trim();
        let service_account = app
            .spec
            .service_account_name
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();

        // `T12.2`: only a namespace this controller watches may host the `Application`, and a
        // tenant `Application` must never fall back to the controller's own identity (finding C8).
        if !scope.allows(app_namespace) {
            return Err(PolicyError::ApplicationNamespaceNotAllowed {
                application,
                namespace: app_namespace.to_owned(),
                allowed: scope.describe(),
            });
        }
        if scope.is_tenant(app_namespace) && service_account.is_empty() {
            return Err(PolicyError::TenantServiceAccountRequired {
                application,
                namespace: app_namespace.to_owned(),
            });
        }

        if !self.allows_source_namespace(app_namespace) {
            return Err(PolicyError::SourceNamespaceNotAllowed {
                application,
                namespace: app_namespace.to_owned(),
                project: self.name.clone(),
            });
        }
        // `T18.3`: whichever source the `Application` names — a Git remote or an `oci://`
        // reference — is matched against `spec.sourceRepos`. An OCI reference therefore has to be
        // granted explicitly (e.g. `oci://ghcr.io/payments/*`); it is never implied by a Git glob,
        // so evolving the schema cannot widen an existing project's tenancy.
        if !self.allows_source_repo(app.spec.source.repo_url()) {
            return Err(PolicyError::SourceRepoNotAllowed {
                application,
                project: self.name.clone(),
                repo_url: redact_repo_url(app.spec.source.repo_url()),
            });
        }
        if !self.allows_destination(
            &app.spec.destination.cluster,
            &app.spec.destination.namespace,
        ) {
            return Err(PolicyError::DestinationNotAllowed {
                application,
                project: self.name.clone(),
                cluster: app.spec.destination.cluster.trim().to_owned(),
                namespace: app.spec.destination.namespace.trim().to_owned(),
            });
        }
        if !service_account.is_empty()
            && !self.allows_service_account(&app.spec.destination.namespace, service_account)
        {
            return Err(PolicyError::ServiceAccountNotAllowed {
                application,
                project: self.name.clone(),
                namespace: app.spec.destination.namespace.trim().to_owned(),
                service_account: service_account.to_owned(),
            });
        }
        Ok(())
    }

    /// Runs the post-Stage-2 checks over every rendered resource.
    ///
    /// `resources` **must** be the set produced by the controller's Stage-2 scope normalization: the
    /// normalizer is what turns "namespaced or cluster-scoped" from a guess into a fact, and the
    /// actual namespace into `key.namespace`. The first violation is returned, in render order, so
    /// the message is stable between reconciles.
    ///
    /// # Errors
    ///
    /// See [`PolicyError`]; every variant is terminal.
    pub fn check_resources(
        &self,
        cluster: &str,
        resources: &[DesiredResource],
    ) -> Result<(), PolicyError> {
        for resource in resources {
            self.check_resource(cluster, resource)?;
        }
        Ok(())
    }

    /// Runs the post-Stage-2 checks for a single rendered resource.
    ///
    /// # Errors
    ///
    /// See [`PolicyError`]; every variant is terminal.
    pub fn check_resource(
        &self,
        cluster: &str,
        resource: &DesiredResource,
    ) -> Result<(), PolicyError> {
        let group = resource.gvk.group.as_str();
        let kind = resource.gvk.kind.as_str();
        let resolved = non_empty(resource.key.namespace.as_deref());
        let declared = non_empty(resource.object.metadata.namespace.as_deref());

        let namespace = match (resolved, declared) {
            (Some(resolved), Some(declared)) if resolved != declared => {
                return Err(PolicyError::NamespaceMismatch {
                    resource: resource.key.canonical(),
                    resolved_namespace: resolved.to_owned(),
                    metadata_namespace: declared.to_owned(),
                });
            }
            (Some(namespace), _) | (None, Some(namespace)) => namespace,
            (None, None) => {
                // Cluster-scoped: only an explicit `clusterResourceWhitelist` entry authorizes it.
                if self.allows_cluster_resource(group, kind) {
                    return Ok(());
                }
                return Err(PolicyError::ClusterResourceNotAllowed {
                    resource: resource.key.canonical(),
                    project: self.name.clone(),
                    group_kind: group_kind_label(group, kind),
                });
            }
        };

        if !self.allows_destination(cluster, namespace) {
            return Err(PolicyError::ResourceNamespaceNotAllowed {
                resource: resource.key.canonical(),
                project: self.name.clone(),
                cluster: cluster.trim().to_owned(),
                namespace: namespace.to_owned(),
            });
        }
        if self
            .spec
            .namespace_resource_blacklist
            .iter()
            .any(|denied| group_kind_matches(denied, group, kind))
        {
            return Err(PolicyError::NamespaceResourceBlacklisted {
                resource: resource.key.canonical(),
                project: self.name.clone(),
                group_kind: group_kind_label(group, kind),
            });
        }
        if !self.spec.namespace_resource_whitelist.is_empty()
            && !self.allows_namespace_resource(group, kind)
        {
            return Err(PolicyError::NamespaceResourceNotAllowed {
                resource: resource.key.canonical(),
                project: self.name.clone(),
                group_kind: group_kind_label(group, kind),
            });
        }
        Ok(())
    }
}

/// `<namespace>/<name>` identity of an `Application`, for messages.
fn application_id(app: &Application) -> String {
    format!("{}/{}", app.namespace().unwrap_or_default(), app.name_any())
}

/// Splits a `spec.allowedServiceAccounts` entry into its namespace and name patterns.
fn split_service_account_entry(entry: &str) -> Option<(&str, &str)> {
    entry
        .split_once('/')
        .or_else(|| entry.split_once(':'))
        .filter(|(namespace, name)| !namespace.trim().is_empty() && !name.trim().is_empty())
}

/// Matches a project `GroupKind` entry against a rendered resource's group and kind.
fn group_kind_matches(allowed: &GroupKind, group: &str, kind: &str) -> bool {
    wildcard_matches(allowed.group.trim(), group.trim())
        && wildcard_matches(allowed.kind.trim(), kind.trim())
}

/// `group/kind` label for messages, with the core group spelled `core`.
fn group_kind_label(group: &str, kind: &str) -> String {
    if group.trim().is_empty() {
        format!("core/{kind}")
    } else {
        format!("{group}/{kind}")
    }
}

/// Returns `value` unless it is missing or blank.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::manifest::{GroupVersionKind, ResourceKey};
    use crate::policy::ApplicationNamespaces;

    const PAYMENTS_PROJECT: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: payments
  namespace: ferriscd-system
spec:
  sourceRepos:
    - https://github.com/example/payments.git
    - https://github.com/example/shared-*
  sourceNamespaces:
    - ferriscd-system
    - payments-system
  destinations:
    - cluster: in-cluster
      namespace: payments
  clusterResourceWhitelist:
    - group: rbac.authorization.k8s.io
      kind: ClusterRole
  namespaceResourceWhitelist:
    - group: apps
      kind: Deployment
    - group: ""
      kind: ConfigMap
  namespaceResourceBlacklist:
    - group: ""
      kind: Secret
  allowedServiceAccounts:
    - payments/payments-sa
"#;

    const APPLICATION: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: payments-api
  namespace: ferriscd-system
spec:
  project: payments
  source:
    git:
      repoURL: https://github.com/example/payments.git
  destination:
    cluster: in-cluster
    namespace: payments
"#;

    fn project(yaml: &str) -> AppProjectPolicy {
        let project: AppProject = serde_saphyr::from_str(yaml).expect("test project must parse");
        AppProjectPolicy::from_project(&project)
    }

    fn payments_project() -> AppProjectPolicy {
        project(PAYMENTS_PROJECT)
    }

    fn application(yaml: &str) -> Application {
        serde_saphyr::from_str(yaml).expect("test application must parse")
    }

    fn desired(
        api_version: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
    ) -> DesiredResource {
        let gvk = GroupVersionKind::parse(api_version, kind).expect("test apiVersion");
        let mut metadata = json!({ "name": name });
        if let Some(namespace) = namespace {
            metadata["namespace"] = json!(namespace);
        }
        let object = serde_json::from_value(json!({
            "apiVersion": api_version,
            "kind": kind,
            "metadata": metadata,
        }))
        .expect("test object");
        let key = ResourceKey::new(
            gvk.group.clone(),
            gvk.kind.clone(),
            namespace.map(str::to_owned),
            name,
        );
        DesiredResource {
            key,
            gvk,
            object,
            source_file: "deploy.yaml".to_owned(),
        }
    }

    fn scope() -> ApplicationScope {
        ApplicationScope::default()
    }

    #[test]
    fn wildcard_matching_is_predictable() {
        // Exact, empty, and prefix/suffix/infix wildcards.
        assert!(wildcard_matches("payments", "payments"));
        assert!(!wildcard_matches("payments", "payments2"));
        assert!(wildcard_matches("*", ""));
        assert!(wildcard_matches("*", "anything"));
        assert!(wildcard_matches("pay*", "payments"));
        assert!(wildcard_matches("*ments", "payments"));
        assert!(wildcard_matches("pay*nts", "payments"));
        assert!(wildcard_matches("*y*", "payments"));
        assert!(!wildcard_matches("pay*nts", "payment"));
        // `?` is exactly one character.
        assert!(wildcard_matches("pay?ents", "payments"));
        assert!(!wildcard_matches("pay?ents", "paynts"));
        // Matching is case-sensitive, and backtracking terminates on pathological patterns.
        assert!(!wildcard_matches("Payments", "payments"));
        assert!(!wildcard_matches("*a*a*a*a*b", &"a".repeat(200)));
        assert!(wildcard_matches(
            "*a*a*a*b",
            &format!("{}b", "a".repeat(200))
        ));
        // The empty core API group is matched by `*`, never by a concrete group name.
        assert!(wildcard_matches("*", ""));
        assert!(!wildcard_matches("apps", ""));
    }

    #[test]
    fn source_repository_lists_are_globs_with_deny_precedence() {
        let policy = payments_project();
        assert!(policy.allows_source_repo("https://github.com/example/payments.git"));
        assert!(
            policy.allows_source_repo("https://github.com/example/shared-libs.git"),
            "a trailing wildcard must match"
        );
        assert!(!policy.allows_source_repo("https://github.com/evil/payments.git"));

        let deny = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: deny
spec:
  sourceRepos:
    - https://github.com/example/*
    - "!https://github.com/example/secret.git"
"#,
        );
        assert!(deny.allows_source_repo("https://github.com/example/shared.git"));
        assert!(
            !deny.allows_source_repo("https://github.com/example/secret.git"),
            "a deny pattern must win over an allow pattern"
        );

        // An unset repository list permits nothing.
        let empty = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: empty
spec: {}
"#,
        );
        assert!(!empty.allows_source_repo("https://github.com/example/payments.git"));
    }

    #[test]
    fn service_account_entries_require_a_namespace() {
        let policy = payments_project();
        assert!(policy.allows_service_account("payments", "payments-sa"));
        assert!(!policy.allows_service_account("other", "payments-sa"));
        assert!(!policy.allows_service_account("payments", "other-sa"));
        // A bare name is ambiguous (the SA resolves in the destination namespace) and denies.
        assert!(!policy.allows_service_account("payments", "payments-sa/../x"));

        let wildcard = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: wildcard
spec:
  allowedServiceAccounts:
    - "team-*:deployer"
    - payments/*
"#,
        );
        assert!(wildcard.allows_service_account("team-a", "deployer"));
        assert!(!wildcard.allows_service_account("team-a", "other"));
        assert!(wildcard.allows_service_account("payments", "any-sa"));

        let everything = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: everything
spec:
  allowedServiceAccounts:
    - "*"
"#,
        );
        assert!(everything.allows_service_account("any", "any"));
        assert!(!everything.allows_service_account("any", " "));
    }

    #[test]
    fn cluster_whitelist_is_strict_and_namespace_whitelist_is_permissive_when_empty() {
        let policy = payments_project();
        assert!(policy.allows_cluster_resource("rbac.authorization.k8s.io", "ClusterRole"));
        assert!(!policy.allows_cluster_resource("rbac.authorization.k8s.io", "ClusterRoleBinding"));
        assert!(policy.allows_namespace_resource("apps", "Deployment"));
        assert!(!policy.allows_namespace_resource("apps", "StatefulSet"));
        assert!(
            !policy.allows_namespace_resource("", "Secret"),
            "the blacklist must win over the whitelist"
        );

        // Empty lists: nothing cluster-scoped, everything namespaced.
        let open = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: open
spec: {}
"#,
        );
        assert!(!open.allows_cluster_resource("", "Namespace"));
        assert!(open.allows_namespace_resource("apps", "StatefulSet"));
        assert!(open.allows_namespace_resource("", "Secret"));
    }

    #[test]
    fn an_authorized_application_passes_the_pre_render_checks() {
        let policy = payments_project();
        let app = application(APPLICATION);
        assert_eq!(
            policy.check_application(&app, &scope()),
            Ok(()),
            "the payments project must accept its own application"
        );
    }

    /// **Trap guard (`T18.3`).** An `oci://` source is matched against `spec.sourceRepos` too, so
    /// evolving the schema cannot let a registry artifact bypass the tenancy boundary: a project
    /// that lists only Git repositories denies an OCI source, and one that lists `oci://…` allows
    /// exactly that registry.
    #[test]
    fn an_oci_source_is_checked_against_source_repos() {
        let policy = payments_project();
        let mut app = application(APPLICATION);
        app.spec.source.git = None;
        app.spec.source.oci = Some(ferriscd_crd::OciSourceSpec {
            url: "oci://ghcr.io/example/payments".to_owned(),
            tag: Some("1.4.2".to_owned()),
            digest: None,
            path: String::new(),
        });

        let err = policy
            .check_application(&app, &scope())
            .expect_err("a Git-only project must not allow an OCI source");
        assert!(
            matches!(err, PolicyError::SourceRepoNotAllowed { .. }),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("oci://ghcr.io/example/payments"),
            "{message}"
        );
        assert!(message.contains("spec.source.oci.url"), "{message}");

        // The same pattern vocabulary as Git: an `oci://` glob grants exactly that registry path.
        let oci_project = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: payments
  namespace: ferriscd-system
spec:
  sourceRepos:
    - oci://ghcr.io/example/payments*
  sourceNamespaces:
    - ferriscd-system
    - payments-system
  destinations:
    - cluster: in-cluster
      namespace: payments
  namespaceResourceWhitelist:
    - group: apps
      kind: Deployment
"#,
        );
        assert_eq!(
            oci_project.check_application(&app, &scope()),
            Ok(()),
            "an explicit oci:// allow-list entry must authorize the artifact"
        );
        // ...and a lookalike registry path is still denied.
        app.spec.source.oci = Some(ferriscd_crd::OciSourceSpec {
            url: "oci://ghcr.io/evil/payments".to_owned(),
            tag: Some("1.4.2".to_owned()),
            digest: None,
            path: String::new(),
        });
        assert!(matches!(
            oci_project.check_application(&app, &scope()),
            Err(PolicyError::SourceRepoNotAllowed { .. })
        ));
    }

    #[test]
    fn a_source_repository_mismatch_is_rejected_and_credentials_are_redacted() {
        let policy = payments_project();
        let mut app = application(APPLICATION);
        app.spec.source.git.as_mut().expect("git source").repo_url =
            "https://oauth2:s3cr3t-token@github.com/evil/payments.git".to_owned();

        let err = policy
            .check_application(&app, &scope())
            .expect_err("an unlisted repository must be rejected");
        assert!(matches!(err, PolicyError::SourceRepoNotAllowed { .. }));
        let message = err.to_string();
        assert!(message.contains("spec.source.git.repoURL"), "{message}");
        assert!(message.contains("payments.git"), "{message}");
        assert!(
            !message.contains("s3cr3t-token"),
            "the repository credential must never reach the message: {message}"
        );
        assert!(
            message.contains("github.com/evil/payments.git"),
            "the host and path must stay visible: {message}"
        );
        assert!(
            message.contains("oauth2:***@"),
            "the account name stays readable, the password never does: {message}"
        );
    }

    #[test]
    fn a_destination_mismatch_is_rejected() {
        let policy = payments_project();
        let mut app = application(APPLICATION);
        app.spec.destination.namespace = "kube-system".to_owned();
        let err = policy
            .check_application(&app, &scope())
            .expect_err("an unlisted destination namespace must be rejected");
        assert!(matches!(err, PolicyError::DestinationNotAllowed { .. }));
        assert!(err.to_string().contains("kube-system"), "{err}");

        let mut cluster = application(APPLICATION);
        cluster.spec.destination.cluster = "prod-west".to_owned();
        assert!(matches!(
            policy.check_application(&cluster, &scope()),
            Err(PolicyError::DestinationNotAllowed { .. })
        ));
    }

    #[test]
    fn an_unlisted_service_account_is_rejected() {
        let policy = payments_project();
        let mut app = application(APPLICATION);
        app.spec.service_account_name = Some("cluster-admin-sa".to_owned());
        let err = policy
            .check_application(&app, &scope())
            .expect_err("an unlisted ServiceAccount must be rejected");
        assert!(matches!(err, PolicyError::ServiceAccountNotAllowed { .. }));
        assert!(err.to_string().contains("allowedServiceAccounts"), "{err}");

        app.spec.service_account_name = Some("payments-sa".to_owned());
        assert_eq!(policy.check_application(&app, &scope()), Ok(()));
    }

    #[test]
    fn an_application_outside_the_project_source_namespaces_is_rejected() {
        let policy = payments_project();
        let mut app = application(APPLICATION);
        app.metadata.namespace = Some("team-a".to_owned());
        app.spec.service_account_name = Some("payments-sa".to_owned());

        let tenant_scope = ApplicationScope::new(
            "ferriscd-system",
            ApplicationNamespaces::Listed(vec!["team-a".to_owned(), "payments-system".to_owned()]),
        );
        let err = policy
            .check_application(&app, &tenant_scope)
            .expect_err("team-a is not in spec.sourceNamespaces");
        assert!(matches!(err, PolicyError::SourceNamespaceNotAllowed { .. }));
        assert!(err.to_string().contains("sourceNamespaces"), "{err}");

        // Listing the namespace in the project is what authorizes it.
        app.metadata.namespace = Some("payments-system".to_owned());
        assert_eq!(policy.check_application(&app, &tenant_scope), Ok(()));
    }

    #[test]
    fn a_manifest_hardcoding_an_unlisted_namespace_is_rejected() {
        // The classic bypass: `spec.destination.namespace` is `payments`, but the manifest itself
        // hardcodes `metadata.namespace: kube-system`. Scope normalization *preserves* an explicit
        // namespace, so this is exactly the case the post-render check has to catch (finding M6).
        let policy = payments_project();
        let resources = [desired("apps/v1", "Deployment", Some("kube-system"), "api")];
        let err = policy
            .check_resources("in-cluster", &resources)
            .expect_err("a hardcoded kube-system namespace must be rejected");
        assert!(matches!(
            err,
            PolicyError::ResourceNamespaceNotAllowed { .. }
        ));
        let message = err.to_string();
        assert!(
            message.contains("apps/Deployment/kube-system/api"),
            "{message}"
        );
        assert!(message.contains("kube-system"), "{message}");
        assert!(message.contains("spec.destinations"), "{message}");

        // The same manifest in the authorized namespace is accepted.
        let resources = [desired("apps/v1", "Deployment", Some("payments"), "api")];
        assert_eq!(policy.check_resources("in-cluster", &resources), Ok(()));
    }

    #[test]
    fn an_unauthorized_cluster_role_is_rejected() {
        let policy = payments_project();
        // `ClusterRole` *is* whitelisted by the payments project...
        let allowed = [desired(
            "rbac.authorization.k8s.io/v1",
            "ClusterRole",
            None,
            "payments-reader",
        )];
        assert_eq!(policy.check_resources("in-cluster", &allowed), Ok(()));

        // ...but a `ClusterRoleBinding` is not, and neither is any other cluster-scoped kind.
        for (api_version, kind) in [
            ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding"),
            ("v1", "Namespace"),
            ("apiextensions.k8s.io/v1", "CustomResourceDefinition"),
        ] {
            let resources = [desired(api_version, kind, None, "escalation")];
            let err = policy
                .check_resources("in-cluster", &resources)
                .expect_err("an unlisted cluster-scoped kind must be rejected");
            assert!(
                matches!(err, PolicyError::ClusterResourceNotAllowed { .. }),
                "{kind} produced {err:?}"
            );
            assert!(
                err.to_string().contains("clusterResourceWhitelist"),
                "{err}"
            );
            assert!(err.to_string().contains(kind), "{err}");
        }
    }

    #[test]
    fn namespaced_kinds_must_be_whitelisted_and_must_not_be_blacklisted() {
        let policy = payments_project();
        assert_eq!(
            policy.check_resources(
                "in-cluster",
                &[desired("v1", "ConfigMap", Some("payments"), "settings")]
            ),
            Ok(())
        );

        let err = policy
            .check_resources(
                "in-cluster",
                &[desired("v1", "Secret", Some("payments"), "credentials")],
            )
            .expect_err("the blacklist must reject a Secret");
        assert!(matches!(
            err,
            PolicyError::NamespaceResourceBlacklisted { .. }
        ));
        assert!(
            err.to_string().contains("namespaceResourceBlacklist"),
            "{err}"
        );

        let err = policy
            .check_resources(
                "in-cluster",
                &[desired("apps/v1", "StatefulSet", Some("payments"), "db")],
            )
            .expect_err("a non-empty whitelist must reject an unlisted kind");
        assert!(matches!(
            err,
            PolicyError::NamespaceResourceNotAllowed { .. }
        ));
        assert!(
            err.to_string().contains("namespaceResourceWhitelist"),
            "{err}"
        );
    }

    #[test]
    fn every_resource_is_checked_and_the_first_violation_wins() {
        let policy = payments_project();
        let resources = [
            desired("apps/v1", "Deployment", Some("payments"), "api"),
            desired("v1", "ConfigMap", Some("payments"), "settings"),
            desired("v1", "ConfigMap", Some("team-a"), "leak"),
            desired("v1", "Namespace", None, "escalation"),
        ];
        let err = policy
            .check_resources("in-cluster", &resources)
            .expect_err("the third resource targets an unlisted namespace");
        assert!(matches!(
            err,
            PolicyError::ResourceNamespaceNotAllowed { .. }
        ));
        assert!(err.to_string().contains("team-a"), "{err}");
    }

    #[test]
    fn a_namespace_that_disagrees_with_the_resolved_scope_is_rejected() {
        let policy = payments_project();
        let mut resource = desired("apps/v1", "Deployment", Some("payments"), "api");
        resource.object.metadata.namespace = Some("payments".to_owned());
        resource.key.namespace = Some("team-a".to_owned());
        let err = policy
            .check_resources("in-cluster", &[resource])
            .expect_err("a split between the key and metadata must fail closed");
        assert!(matches!(err, PolicyError::NamespaceMismatch { .. }));
        assert!(err.to_string().contains("team-a"), "{err}");
        assert!(err.to_string().contains("payments"), "{err}");
    }

    #[test]
    fn a_declared_metadata_namespace_counts_even_without_a_key_namespace() {
        // Defensive: after Stage 2 the two agree, but a namespace present only in the object must
        // never be treated as cluster-scoped (that would skip the destination check entirely).
        let policy = payments_project();
        let mut resource = desired("apps/v1", "Deployment", Some("kube-system"), "api");
        resource.key.namespace = None;
        let err = policy
            .check_resources("in-cluster", &[resource])
            .expect_err("metadata.namespace must be honored");
        assert!(matches!(
            err,
            PolicyError::ResourceNamespaceNotAllowed { .. }
        ));
    }

    #[test]
    fn wildcard_entries_allow_a_whole_slice_of_namespaces_and_kinds() {
        let policy = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: wildcards
spec:
  sourceRepos:
    - "*"
  sourceNamespaces:
    - "*"
  destinations:
    - cluster: "*"
      namespace: team-*
  clusterResourceWhitelist:
    - group: ""
      kind: Namespace
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
  namespaceResourceBlacklist:
    - group: apps
      kind: "*"
"#,
        );
        assert!(policy.allows_source_namespace("anywhere"));
        assert!(policy.allows_destination("prod-west", "team-a"));
        assert!(!policy.allows_destination("prod-west", "payments"));
        assert!(!policy.allows_cluster_resource("apps", "Deployment"));

        assert_eq!(
            policy.check_resources(
                "in-cluster",
                &[
                    desired("v1", "Namespace", None, "team-a"),
                    desired("v1", "ConfigMap", Some("team-b"), "settings"),
                ]
            ),
            Ok(())
        );

        let err = policy
            .check_resources(
                "in-cluster",
                &[desired("apps/v1", "Deployment", Some("team-a"), "api")],
            )
            .expect_err("`apps/*` is blacklisted");
        assert!(matches!(
            err,
            PolicyError::NamespaceResourceBlacklisted { .. }
        ));
    }

    /// Every policy violation is terminal, names what to fix, and cannot leak a credential.
    ///
    /// The check is exhaustive over [`PolicyError`] on purpose: a new variant that forgets
    /// `is_retryable` (or quotes a raw URL) is caught here instead of by an operator who watches a
    /// permanent denial retry every five seconds.
    #[test]
    fn policy_errors_are_never_retryable() {
        const TOKEN_URL: &str = "https://robot:s3cr3t-token@github.com/evil/payments.git";
        let errors = vec![
            PolicyError::ProjectNotFound {
                project: "payments".to_owned(),
                namespace: "ferriscd-system".to_owned(),
                application: "ferriscd-system/payments-api".to_owned(),
            },
            PolicyError::ApplicationNamespaceNotAllowed {
                application: "team-a/payments-api".to_owned(),
                namespace: "team-a".to_owned(),
                allowed: "ferriscd-system".to_owned(),
            },
            PolicyError::TenantServiceAccountRequired {
                application: "team-a/payments-api".to_owned(),
                namespace: "team-a".to_owned(),
            },
            PolicyError::SourceRepoNotAllowed {
                application: "ferriscd-system/payments-api".to_owned(),
                project: "payments".to_owned(),
                repo_url: redact_repo_url(TOKEN_URL),
            },
            PolicyError::SourceNamespaceNotAllowed {
                application: "team-a/payments-api".to_owned(),
                namespace: "team-a".to_owned(),
                project: "payments".to_owned(),
            },
            PolicyError::DestinationNotAllowed {
                application: "ferriscd-system/payments-api".to_owned(),
                project: "payments".to_owned(),
                cluster: "in-cluster".to_owned(),
                namespace: "kube-system".to_owned(),
            },
            PolicyError::ServiceAccountNotAllowed {
                application: "ferriscd-system/payments-api".to_owned(),
                project: "payments".to_owned(),
                namespace: "payments".to_owned(),
                service_account: "root".to_owned(),
            },
            PolicyError::NamespaceMismatch {
                resource: "apps/Deployment/payments/api".to_owned(),
                resolved_namespace: "payments".to_owned(),
                metadata_namespace: "kube-system".to_owned(),
            },
            PolicyError::ResourceNamespaceNotAllowed {
                resource: "/ConfigMap/kube-system/settings".to_owned(),
                project: "payments".to_owned(),
                cluster: "in-cluster".to_owned(),
                namespace: "kube-system".to_owned(),
            },
            PolicyError::ClusterResourceNotAllowed {
                resource: "rbac.authorization.k8s.io/ClusterRole//escalation".to_owned(),
                project: "payments".to_owned(),
                group_kind: "rbac.authorization.k8s.io/ClusterRole".to_owned(),
            },
            PolicyError::NamespaceResourceNotAllowed {
                resource: "apps/StatefulSet/payments/db".to_owned(),
                project: "payments".to_owned(),
                group_kind: "apps/StatefulSet".to_owned(),
            },
            PolicyError::NamespaceResourceBlacklisted {
                resource: "/Secret/payments/creds".to_owned(),
                project: "payments".to_owned(),
                group_kind: "core/Secret".to_owned(),
            },
        ];

        for err in &errors {
            assert!(!err.is_retryable(), "{err:?} must be terminal");
            let message = err.to_string();
            assert!(!message.trim().is_empty(), "{err:?} must explain itself");
            assert!(
                !message.contains("s3cr3t-token"),
                "a credential reached the message: {message}"
            );
            assert!(
                message.contains("payments"),
                "every message must name the Application, project, or resource: {message}"
            );
        }

        // The two messages an operator acts on most often name their remedy explicitly.
        let project = errors[0].to_string();
        assert!(project.contains("AppProject"), "{project}");
        assert!(project.contains("ferriscd-system"), "{project}");
        assert!(
            project.contains("never treated as permissive"),
            "a missing project must say what it is not: {project}"
        );
        let tenant = errors[2].to_string();
        assert!(tenant.contains("serviceAccountName"), "{tenant}");
        assert!(
            tenant.contains("controller's own ServiceAccount"),
            "the tenant guard must say why it refuses: {tenant}"
        );
    }

    /// A policy is an immutable snapshot of one fetched project.
    ///
    /// The controller reduces the CR to its spec once per reconcile, so a project edited *after*
    /// the fetch must not change the verdict of the pass that already read it (and a policy must
    /// never hold a `kube` handle).
    #[test]
    fn policy_is_built_from_a_fetched_project() {
        let project: AppProject = serde_saphyr::from_str(PAYMENTS_PROJECT).expect("project");
        let policy = AppProjectPolicy::from_project(&project);
        assert_eq!(policy.project_name(), "payments");
        assert_eq!(policy.spec(), &project.spec);
        assert_eq!(
            AppProjectPolicy::new("payments", project.spec.clone()),
            policy,
            "name + spec is the complete policy state"
        );

        // Editing the fetched CR afterwards cannot widen the snapshot.
        let mut edited = project.clone();
        edited.spec.source_repos = vec!["*".to_owned()];
        edited.spec.allowed_service_accounts = vec!["*".to_owned()];
        assert_eq!(policy.spec(), &project.spec, "the policy is a snapshot");
        assert!(
            !policy.allows_source_repo("https://github.com/evil/payments.git"),
            "the edited project must not affect the policy that already exists"
        );
        assert!(
            !policy.allows_service_account("payments", "root"),
            "the edited ServiceAccount list must not affect the policy either"
        );

        // ...and every denial it raises names the project, so `kubectl describe app` points at the
        // CR the operator has to change.
        let app = application(APPLICATION);
        let mut denied = app.clone();
        denied.spec.destination.namespace = "kube-system".to_owned();
        let message = policy
            .check_application(&denied, &scope())
            .expect_err("an unlisted destination is a denial")
            .to_string();
        assert!(message.contains("payments"), "{message}");
    }

    /// **Finding M2:** an empty allow-list permits **nothing** — an unset project list must never
    /// read as "any".
    ///
    /// The distinction the operator has to see: `sourceNamespaces` *omitted* takes the schema
    /// default (`["ferriscd-system"]`), while an explicitly empty list authorizes no namespace at
    /// all. The same holds for `destinations`, `clusterResourceWhitelist`, and
    /// `allowedServiceAccounts`; `namespaceResourceWhitelist` is the documented exception
    /// (Argo-compatible: empty means "every namespaced GroupKind", minus the blacklist).
    #[test]
    fn empty_allow_lists_deny_everything() {
        let empty = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: empty
spec:
  sourceRepos:
    - "*"
  sourceNamespaces: []
  destinations: []
  clusterResourceWhitelist: []
  namespaceResourceWhitelist: []
  allowedServiceAccounts: []
"#,
        );
        assert!(
            !empty.allows_source_namespace("ferriscd-system"),
            "an explicitly empty sourceNamespaces must authorize no namespace at all"
        );
        assert!(!empty.allows_source_namespace("team-a"));
        assert!(!empty.allows_destination("in-cluster", "payments"));
        assert!(!empty.allows_destination("in-cluster", "ferriscd-system"));
        assert!(!empty.allows_cluster_resource("", "Namespace"));
        assert!(!empty.allows_service_account("payments", "deployer"));

        // An Application therefore cannot pass the pre-render gate at all.
        let app = application(APPLICATION);
        let err = empty
            .check_application(&app, &scope())
            .expect_err("an empty project authorizes nothing");
        assert!(
            matches!(err, PolicyError::SourceNamespaceNotAllowed { .. }),
            "{err:?}"
        );

        // The omitted list is a different thing: it is the documented single-namespace default.
        let omitted = project(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: omitted
spec:
  sourceRepos:
    - "*"
  destinations:
    - cluster: in-cluster
      namespace: payments
"#,
        );
        assert!(
            omitted.allows_source_namespace("ferriscd-system"),
            "an omitted sourceNamespaces keeps the schema default"
        );
        assert!(!omitted.allows_source_namespace("team-a"));
        assert!(
            omitted.allows_namespace_resource("apps", "StatefulSet"),
            "an empty namespaceResourceWhitelist permits every namespaced GroupKind"
        );
        assert!(!omitted.allows_service_account("payments", "deployer"));
    }
}

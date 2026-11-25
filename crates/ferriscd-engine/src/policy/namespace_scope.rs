//! Apps-in-any-namespace scope configuration (`T12.2`, ADR-007).
//!
//! Through `v0.4` the controller watches exactly one namespace — the control-plane namespace
//! (`ferriscd-system` by default) — which is the safe default: a cluster-scoped `Application`
//! informer would let any namespace create an `Application` that the operator's own (privileged)
//! ServiceAccount then deploys. Phase 12 keeps that default and makes widening it an explicit,
//! reviewable opt-in via `--application-namespaces`:
//!
//! | `--application-namespaces` | [`ApplicationNamespaces`] | Watched namespaces |
//! |---|---|---|
//! | unset / blank | [`ApplicationNamespaces::ControlPlane`] | the control-plane namespace |
//! | `team-a,team-b` | [`ApplicationNamespaces::Listed`] | the control-plane namespace + both |
//! | `*` | [`ApplicationNamespaces::All`] | every namespace |
//!
//! The control-plane namespace is **never** dropped from the watch: it owns the `AppProject`s and
//! the platform's own `Application`s, so an operator who lists tenant namespaces without repeating
//! `ferriscd-system` must not silently stop reconciling the platform.
//!
//! Widening the scope is only half of the guard: an `Application` outside the control-plane
//! namespace is a *tenant* application and
//! [`AppProjectPolicy::check_application`](super::AppProjectPolicy::check_application) refuses to
//! reconcile it without a project-authorized `spec.serviceAccountName` (finding C8).
//!
//! **The identity (`T12.3`):** this module decides *which* `Application`s may reconcile and which
//! ServiceAccount they name; `ferriscd_controller::impersonation` then deploys such an
//! `Application` **as** that ServiceAccount (`Impersonate-User` + the three
//! `Impersonate-Group` headers) over the controller's pooled connector. Two consequences matter
//! here:
//!
//! * Without `spec.serviceAccountName` a tenant `Application` is **refused**
//!   ([`super::PolicyError::TenantServiceAccountRequired`]) — it is never deployed with the
//!   controller's own identity.
//! * Impersonation narrows what a tenant *can* do; it does not authorize anything. The project
//!   allow-lists remain the boundary: the watch scope decides what the controller *sees*, the
//!   project decides what it may *do*, and the ServiceAccount decides what the API server lets
//!   the write through.

use ferriscd_crd::CONTROL_PLANE_NAMESPACE;

/// Value of `applicationNamespaces` that selects every namespace.
pub const ALL_NAMESPACES: &str = "*";

/// Longest valid Kubernetes namespace name (RFC 1123 label).
const MAX_NAMESPACE_NAME_LEN: usize = 63;

/// Configuration failures for the Apps-in-any-namespace scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationScopeError {
    /// A comma-separated list contained an empty entry (`team-a,,team-b`).
    #[error(
        "applicationNamespaces value {value:?} contains an empty entry: list namespaces separated \
         by commas, or use {ALL_NAMESPACES:?} for every namespace"
    )]
    EmptyEntry {
        /// The rejected value.
        value: String,
    },

    /// `*` was combined with explicit namespaces, which is ambiguous.
    #[error(
        "applicationNamespaces value {value:?} mixes {ALL_NAMESPACES:?} with explicit namespaces: \
         use {ALL_NAMESPACES:?} alone to watch every namespace"
    )]
    WildcardWithNames {
        /// The rejected value.
        value: String,
    },

    /// An entry is not a valid Kubernetes namespace name.
    #[error(
        "applicationNamespaces entry {value:?} is not a valid Kubernetes namespace name (a \
         lowercase RFC 1123 label)"
    )]
    InvalidNamespace {
        /// The rejected entry.
        value: String,
    },
}

/// Raw `applicationNamespaces` configuration, before it is bound to a control-plane namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ApplicationNamespaces {
    /// The safe default: only the control-plane namespace hosts `Application` objects.
    #[default]
    ControlPlane,
    /// The control-plane namespace plus the listed tenant namespaces.
    Listed(Vec<String>),
    /// Every namespace (`*`): full self-service, guarded per `Application` by
    /// [`super::AppProjectPolicy`].
    All,
}

impl ApplicationNamespaces {
    /// Parses an `--application-namespaces` / `FERRISCD_APPLICATION_NAMESPACES` value.
    ///
    /// `None` and a blank value both mean [`Self::ControlPlane`]: an operator who passes an empty
    /// flag must not accidentally narrow the watch to nothing.
    ///
    /// # Errors
    ///
    /// See [`ApplicationScopeError`]; a malformed value fails loudly instead of silently watching
    /// the wrong namespaces.
    pub fn parse(value: Option<&str>) -> Result<Self, ApplicationScopeError> {
        let Some(raw) = value else {
            return Ok(Self::ControlPlane);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Self::ControlPlane);
        }
        if trimmed == ALL_NAMESPACES {
            return Ok(Self::All);
        }
        if trimmed.contains(ALL_NAMESPACES) {
            return Err(ApplicationScopeError::WildcardWithNames {
                value: trimmed.to_owned(),
            });
        }

        let mut namespaces: Vec<String> = Vec::new();
        for entry in trimmed.split(',') {
            let namespace = entry.trim();
            if namespace.is_empty() {
                return Err(ApplicationScopeError::EmptyEntry {
                    value: trimmed.to_owned(),
                });
            }
            if !is_valid_namespace_name(namespace) {
                return Err(ApplicationScopeError::InvalidNamespace {
                    value: namespace.to_owned(),
                });
            }
            if !namespaces.iter().any(|existing| existing == namespace) {
                namespaces.push(namespace.to_owned());
            }
        }
        Ok(Self::Listed(namespaces))
    }

    /// Returns whether this configuration is the safe single-namespace default.
    #[must_use]
    pub fn is_control_plane_only(&self) -> bool {
        matches!(self, Self::ControlPlane)
    }
}

/// Whether `value` is a valid Kubernetes namespace name (lowercase RFC 1123 label).
fn is_valid_namespace_name(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_NAMESPACE_NAME_LEN {
        return false;
    }
    let mut chars = value.chars();
    let first_ok = chars
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit());
    let last_ok = value
        .chars()
        .next_back()
        .is_some_and(|last| last.is_ascii_lowercase() || last.is_ascii_digit());
    first_ok
        && last_ok
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The resolved namespace scope: the configuration bound to a control-plane namespace.
///
/// This is what the controller watches and what
/// [`super::AppProjectPolicy::check_application`] enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationScope {
    control_plane: String,
    namespaces: ApplicationNamespaces,
}

impl Default for ApplicationScope {
    /// The safe default: `ferriscd-system` only.
    fn default() -> Self {
        Self::new(CONTROL_PLANE_NAMESPACE, ApplicationNamespaces::ControlPlane)
    }
}

impl ApplicationScope {
    /// Binds `namespaces` to `control_plane`.
    #[must_use]
    pub fn new(control_plane: impl Into<String>, namespaces: ApplicationNamespaces) -> Self {
        Self {
            control_plane: control_plane.into(),
            namespaces,
        }
    }

    /// The control-plane namespace: home of `AppProject` objects and of every platform
    /// `Application`. Its `Application`s reconcile with the controller's own identity.
    #[must_use]
    pub fn control_plane(&self) -> &str {
        &self.control_plane
    }

    /// The configured namespace selection.
    #[must_use]
    pub fn namespaces(&self) -> &ApplicationNamespaces {
        &self.namespaces
    }

    /// The namespaces to watch, or `None` for every namespace.
    ///
    /// The control-plane namespace is always first: it is never dropped from the watch.
    #[must_use]
    pub fn watch_namespaces(&self) -> Option<Vec<String>> {
        match &self.namespaces {
            ApplicationNamespaces::All => None,
            ApplicationNamespaces::ControlPlane => Some(vec![self.control_plane.clone()]),
            ApplicationNamespaces::Listed(listed) => {
                let mut namespaces = Vec::with_capacity(listed.len() + 1);
                namespaces.push(self.control_plane.clone());
                for namespace in listed {
                    if namespace != &self.control_plane {
                        namespaces.push(namespace.clone());
                    }
                }
                Some(namespaces)
            }
        }
    }

    /// Returns whether an `Application` in `namespace` may be reconciled at all.
    #[must_use]
    pub fn allows(&self, namespace: &str) -> bool {
        let namespace = namespace.trim();
        if namespace.is_empty() {
            // An `Application` with no namespace cannot be patched or finalized, so it can never
            // be reconciled (and must not be mistaken for a cluster-scoped resource).
            return false;
        }
        if namespace == self.control_plane {
            return true;
        }
        match &self.namespaces {
            ApplicationNamespaces::All => true,
            ApplicationNamespaces::ControlPlane => false,
            ApplicationNamespaces::Listed(listed) => {
                listed.iter().any(|allowed| allowed == namespace)
            }
        }
    }

    /// Returns whether `namespace` is a **tenant** namespace, i.e. outside the control plane.
    ///
    /// A tenant `Application` must never reconcile with the controller's own (privileged)
    /// identity (finding C8).
    #[must_use]
    pub fn is_tenant(&self, namespace: &str) -> bool {
        let namespace = namespace.trim();
        !namespace.is_empty() && namespace != self.control_plane
    }

    /// Returns whether the **effective** watched set is wider than the safe default.
    ///
    /// The default is "the control-plane namespace only". `--application-namespaces
    /// ferriscd-system` (or a list that repeats only the control-plane namespace) resolves to
    /// exactly the default set, so it must not be warned about: a warning that fires on a
    /// configuration which changes nothing trains operators to ignore warnings.
    #[must_use]
    pub fn watches_more_than_the_control_plane(&self) -> bool {
        match &self.namespaces {
            ApplicationNamespaces::ControlPlane => false,
            ApplicationNamespaces::All => true,
            ApplicationNamespaces::Listed(listed) => listed
                .iter()
                .any(|namespace| namespace.trim() != self.control_plane),
        }
    }

    /// Human-readable description of the allowed namespaces, for policy messages.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.namespaces {
            ApplicationNamespaces::All => ALL_NAMESPACES.to_owned(),
            ApplicationNamespaces::ControlPlane => self.control_plane.clone(),
            ApplicationNamespaces::Listed(listed) => {
                let mut parts = vec![self.control_plane.clone()];
                for namespace in listed {
                    if namespace != &self.control_plane {
                        parts.push(namespace.clone());
                    }
                }
                parts.join(", ")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_and_blank_values_keep_the_safe_default() {
        for value in [None, Some(""), Some("   ")] {
            let parsed = ApplicationNamespaces::parse(value).expect("blank means default");
            assert_eq!(parsed, ApplicationNamespaces::ControlPlane);
            assert!(parsed.is_control_plane_only());
        }
        assert_eq!(
            ApplicationScope::default(),
            ApplicationScope::new(CONTROL_PLANE_NAMESPACE, ApplicationNamespaces::ControlPlane)
        );
        assert_eq!(
            ApplicationScope::default().watch_namespaces(),
            Some(vec![CONTROL_PLANE_NAMESPACE.to_owned()])
        );
    }

    #[test]
    fn comma_separated_lists_are_trimmed_deduplicated_and_always_include_the_control_plane() {
        let parsed =
            ApplicationNamespaces::parse(Some(" team-a , team-b ,team-a,")).expect_err("empty");
        assert!(matches!(parsed, ApplicationScopeError::EmptyEntry { .. }));

        let parsed = ApplicationNamespaces::parse(Some(" team-a , team-b ,team-a"))
            .expect("valid namespace list");
        assert_eq!(
            parsed,
            ApplicationNamespaces::Listed(vec!["team-a".to_owned(), "team-b".to_owned()])
        );

        let scope = ApplicationScope::new("ferriscd-system", parsed);
        assert_eq!(
            scope.watch_namespaces(),
            Some(vec![
                "ferriscd-system".to_owned(),
                "team-a".to_owned(),
                "team-b".to_owned()
            ]),
            "the control-plane namespace is never dropped from the watch"
        );
        assert!(scope.allows("ferriscd-system"));
        assert!(scope.allows("team-a"));
        assert!(!scope.allows("team-c"));
        assert_eq!(scope.describe(), "ferriscd-system, team-a, team-b");

        // Listing the control plane explicitly must not duplicate it.
        let with_control_plane = ApplicationScope::new(
            "ferriscd-system",
            ApplicationNamespaces::parse(Some("ferriscd-system,team-a")).expect("valid"),
        );
        assert_eq!(
            with_control_plane.watch_namespaces(),
            Some(vec!["ferriscd-system".to_owned(), "team-a".to_owned()])
        );
    }

    #[test]
    fn wildcard_alone_watches_every_namespace() {
        let parsed = ApplicationNamespaces::parse(Some("*")).expect("wildcard");
        assert_eq!(parsed, ApplicationNamespaces::All);
        let scope = ApplicationScope::new("ferriscd-system", parsed);
        assert_eq!(scope.watch_namespaces(), None, "None means every namespace");
        assert!(scope.allows("team-a"));
        assert!(scope.allows("kube-system"));
        assert_eq!(scope.describe(), "*");
    }

    #[test]
    fn malformed_values_are_rejected_instead_of_watching_the_wrong_namespaces() {
        // A wildcard mixed with names is ambiguous.
        assert!(matches!(
            ApplicationNamespaces::parse(Some("team-a,*")),
            Err(ApplicationScopeError::WildcardWithNames { .. })
        ));
        // Glob patterns are not namespace names.
        assert!(matches!(
            ApplicationNamespaces::parse(Some("team-*")),
            Err(ApplicationScopeError::WildcardWithNames { .. })
        ));
        // Kubernetes namespace names are lowercase RFC 1123 labels.
        for invalid in ["Team-A", "team_a", "-team", "team-", "a/b"] {
            assert!(
                matches!(
                    ApplicationNamespaces::parse(Some(invalid)),
                    Err(ApplicationScopeError::InvalidNamespace { .. })
                ),
                "{invalid} must be rejected"
            );
        }
        let long = "a".repeat(MAX_NAMESPACE_NAME_LEN + 1);
        assert!(matches!(
            ApplicationNamespaces::parse(Some(long.as_str())),
            Err(ApplicationScopeError::InvalidNamespace { .. })
        ));
    }

    #[test]
    fn only_a_widened_watch_counts_as_apps_in_any_namespace() {
        // The default, and a list that merely repeats the control plane, resolve to the same
        // watched set — neither is Apps-in-any-namespace (finding M5).
        assert!(!ApplicationScope::default().watches_more_than_the_control_plane());
        let repeated = ApplicationScope::new(
            "ferriscd-system",
            ApplicationNamespaces::parse(Some("ferriscd-system")).expect("valid"),
        );
        assert_eq!(
            repeated.watch_namespaces(),
            ApplicationScope::default().watch_namespaces()
        );
        assert!(
            !repeated.watches_more_than_the_control_plane(),
            "listing only the control-plane namespace changes nothing"
        );

        // A tenant namespace, or `*`, really does widen the watch.
        assert!(
            ApplicationScope::new(
                "ferriscd-system",
                ApplicationNamespaces::parse(Some("ferriscd-system,team-a")).expect("valid"),
            )
            .watches_more_than_the_control_plane()
        );
        assert!(
            ApplicationScope::new("ferriscd-system", ApplicationNamespaces::All)
                .watches_more_than_the_control_plane()
        );
    }

    #[test]
    fn tenant_detection_is_relative_to_the_control_plane_namespace() {
        let scope = ApplicationScope::default();
        assert_eq!(scope.control_plane(), "ferriscd-system");
        assert!(!scope.is_tenant("ferriscd-system"));
        assert!(scope.is_tenant("team-a"));
        assert!(
            !scope.is_tenant("  "),
            "a missing namespace is not a tenant"
        );
        assert!(!scope.is_tenant(""));

        // The default scope watches nothing but the control plane, so a tenant
        // `Application` is refused even if it somehow reaches a reconcile.
        assert!(scope.allows("ferriscd-system"));
        assert!(!scope.allows("team-a"));
        assert!(!scope.allows(""));
        assert!(!scope.allows("   "));
    }
}

//! `ferriscd.io/tracking-id` ownership stamping and classification.
//!
//! `tracking-id` is the only ownership evidence FerrisCD trusts before it overwrites or
//! deletes an object it does not own. Two `Application`s pointing at the same manifest
//! would otherwise fight forever and could prune each other's workloads (trap T10).
//!
//! The identifier is deliberately **version-agnostic** and mirrors the GKNN identity of
//! [`ResourceKey`] (finding C2, ADR-003):
//!
//! ```text
//! <app-ns>/<app-name>:<group>/<kind>:<res-ns>/<res-name>
//! ```
//!
//! * `<group>` is empty for the core group, exactly as in [`ResourceKey::canonical`]:
//!   `ferriscd-system/platform:/Service:payments/api`.
//! * `<res-ns>` is empty for cluster-scoped resources; the trailing `:` keeps the
//!   two-segment `/` shape so the string stays unambiguous and still parses:
//!   `ferriscd-system/platform:rbac.authorization.k8s.io/ClusterRole:/ferriscd-admin`.
//! * No API version appears anywhere, so `networking.k8s.io/v1beta1` and
//!   `networking.k8s.io/v1` Ingresses share one `tracking-id` and an API upgrade can
//!   never make a live object look foreign.
//!
//! Control-plane object names, namespaces, groups, and kinds never contain `:` or `/`
//! (Kubernetes DNS/qualified-name rules), which is what makes the three-part split
//! unambiguous.
//!
//! # Opt-in ownership labels (`T18.1`)
//!
//! An annotation cannot be used in a Kubernetes **watch label selector**, so an on-demand
//! scoped fetch can never be accelerated by one: [`StampOptions::with_drift_labels`] additionally
//! stamps two bounded top-level labels, which is what lets the opt-in `DriftWatcher` (`T18.2`)
//! filter `ferriscd.io/managed-by=ferriscd` server-side and resolve
//! `ferriscd.io/app-hash` back to an `Application` without ever reading an object body:
//!
//! | Label | Value |
//! |---|---|
//! | [`annotations::LABEL_MANAGED_BY`] | [`annotations::MANAGED_BY_FERRISCD`] (a constant) |
//! | [`annotations::LABEL_APP_HASH`] | [`app_hash`]: first 16 lowercase hex chars of `SHA-256("<app-ns>/<app-name>")` |
//!
//! Stamping is **additive and idempotent**: it never removes a label, never rewrites an existing
//! label the user wrote, and re-stamping writes the same values. It is also strictly confined to
//! top-level `metadata.labels` — `spec.selector.matchLabels` and
//! `spec.template.metadata.labels` are immutable in `Deployment`/`StatefulSet`/`DaemonSet`, so
//! stamping them would turn every later apply into a `422 Immutable` failure (trap guard).

use std::collections::BTreeMap;
use std::fmt;

use ferriscd_crd::annotations;
use kube::api::DynamicObject;

use crate::manifest::types::{DesiredResource, ResourceKey};

/// Malformed `tracking-id` string.
///
/// Every variant is deterministic (terminal): re-running the same reconcile against the
/// same string can never succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrackingIdError {
    /// The string does not have exactly three `:`-separated parts.
    #[error(
        "malformed tracking-id: expected `<app-ns>/<app-name>:<group>/<kind>:<res-ns>/<res-name>` \
         (three `:`-separated parts)"
    )]
    PartCount,

    /// A part does not have exactly two `/`-separated segments.
    ///
    /// `part` is `0` for `<app-ns>/<app-name>`, `1` for `<group>/<kind>`, and `2` for
    /// `<res-ns>/<res-name>`.
    #[error("malformed tracking-id: part {part} must have exactly two `/`-separated segments")]
    SegmentCount {
        /// Zero-based index of the offending `:`-separated part.
        part: usize,
    },

    /// A segment that must carry a value is empty or whitespace-only.
    #[error("malformed tracking-id: the `{field}` segment must not be empty")]
    EmptySegment {
        /// Human-readable name of the mandatory segment.
        field: &'static str,
    },

    /// An optional segment (the resource group or the resource namespace) is whitespace-only.
    ///
    /// Those two segments may be empty (core group, cluster-scoped resource), but a blank value
    /// is never a real group/namespace, and letting it through would produce a key that renders
    /// back as a different string.
    #[error(
        "malformed tracking-id: the `{field}` segment must be empty or non-blank (whitespace-only \
         is not a valid value)"
    )]
    BlankOptionalSegment {
        /// Human-readable name of the optional segment.
        field: &'static str,
    },
}

impl TrackingIdError {
    /// Always `false`: a malformed identifier is a deterministic input error.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}

/// A parsed `ferriscd.io/tracking-id`.
///
/// Identity is the owning `Application` (`namespace`/`name`) plus the version-agnostic
/// GKNN [`ResourceKey`] of the managed resource.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrackingId {
    /// Namespace of the owning `Application`.
    pub app_namespace: String,

    /// Name of the owning `Application`.
    pub app_name: String,

    /// Version-agnostic identity of the managed resource.
    pub key: ResourceKey,
}

impl TrackingId {
    /// Builds a tracking id from its parts without validating them.
    ///
    /// Call [`TrackingId::validate`] before persisting the rendered string, or use
    /// [`stamp_tracking_id`], which validates for you.
    #[must_use]
    pub fn new(
        app_namespace: impl Into<String>,
        app_name: impl Into<String>,
        key: ResourceKey,
    ) -> Self {
        Self {
            app_namespace: app_namespace.into(),
            app_name: app_name.into(),
            key,
        }
    }

    /// Parses the documented `<app-ns>/<app-name>:<group>/<kind>:<res-ns>/<res-name>`
    /// format.
    ///
    /// The `<group>` and `<res-ns>` segments may be empty (core group, cluster-scoped
    /// resource) but must not be whitespace-only; every other segment must be non-empty. No API
    /// version is accepted or expected anywhere in the string.
    ///
    /// # Errors
    ///
    /// Returns [`TrackingIdError::PartCount`], [`TrackingIdError::SegmentCount`],
    /// [`TrackingIdError::EmptySegment`] or [`TrackingIdError::BlankOptionalSegment`]. Never
    /// panics on arbitrary input.
    pub fn parse(raw: &str) -> Result<Self, TrackingIdError> {
        let mut parts = raw.split(':');
        let (Some(app_part), Some(group_kind_part), Some(resource_part), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TrackingIdError::PartCount);
        };

        let (app_namespace, app_name) = split_pair(app_part, 0)?;
        let (group, kind) = split_pair(group_kind_part, 1)?;
        let (namespace, name) = split_pair(resource_part, 2)?;
        let group = reject_blank_optional(group, "resource group")?;
        let namespace = reject_blank_optional(namespace, "resource namespace")?;

        let parsed = Self::new(
            app_namespace,
            app_name,
            ResourceKey::new(
                group,
                kind,
                if namespace.is_empty() {
                    None
                } else {
                    Some(namespace.to_owned())
                },
                name,
            ),
        );
        parsed.validate()?;
        Ok(parsed)
    }

    /// Validates that every mandatory segment is non-empty (or not whitespace-only).
    ///
    /// The group (core group) and the resource namespace (cluster-scoped) are optional.
    ///
    /// # Errors
    ///
    /// Returns [`TrackingIdError::EmptySegment`] naming the first empty segment.
    pub fn validate(&self) -> Result<(), TrackingIdError> {
        for (field, value) in [
            ("application namespace", self.app_namespace.as_str()),
            ("application name", self.app_name.as_str()),
            ("resource kind", self.key.kind.as_str()),
            ("resource name", self.key.name.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(TrackingIdError::EmptySegment { field });
            }
        }
        Ok(())
    }
}

impl fmt::Display for TrackingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}:{}/{}:{}/{}",
            self.app_namespace,
            self.app_name,
            self.key.group,
            self.key.kind,
            self.key.namespace.as_deref().unwrap_or(""),
            self.key.name
        )
    }
}

/// Splits one `:`-separated part into exactly two `/`-separated segments.
fn split_pair(part: &str, index: usize) -> Result<(&str, &str), TrackingIdError> {
    let mut segments = part.split('/');
    let (Some(left), Some(right), None) = (segments.next(), segments.next(), segments.next())
    else {
        return Err(TrackingIdError::SegmentCount { part: index });
    };
    Ok((left, right))
}

/// Rejects a whitespace-only optional segment (`<group>`, `<res-ns>`).
///
/// An empty optional segment is meaningful (core group, cluster-scoped resource); a blank one is
/// not. [`TrackingId::validate`] rejects blank *mandatory* segments, so this keeps the whole
/// parser consistent instead of accepting a value that would render back differently.
fn reject_blank_optional<'a>(
    segment: &'a str,
    field: &'static str,
) -> Result<&'a str, TrackingIdError> {
    if !segment.is_empty() && segment.trim().is_empty() {
        return Err(TrackingIdError::BlankOptionalSegment { field });
    }
    Ok(segment)
}

/// Renders the `tracking-id` for `key` as owned by `app_namespace`/`app_name`.
///
/// The result always uses the documented version-agnostic format. Formatting itself does
/// not validate the application reference: an empty `app_namespace` or `app_name` yields
/// a string that [`TrackingId::parse`] rejects, so callers that mutate the cluster must go
/// through [`stamp_tracking_id`] (or call [`TrackingId::validate`] first).
#[must_use]
pub fn tracking_id_for(app_namespace: &str, app_name: &str, key: &ResourceKey) -> String {
    TrackingId::new(app_namespace, app_name, key.clone()).to_string()
}

/// Number of lowercase hex characters in [`app_hash`] (64 bits).
///
/// Fixed by contract, not a tuning knob: 16 hex characters can never exceed the 63-character
/// Kubernetes label-value limit, whatever the `Application` name and namespace length are.
pub const APP_HASH_HEX_CHARS: usize = 16;

/// The `ferriscd.io/app-hash` value of the `Application` named `app_namespace`/`app_name`.
///
/// The first [`APP_HASH_HEX_CHARS`] lowercase hex characters of
/// `SHA-256("<app-namespace>/<app-name>")`, computed with
/// [`sha256::digest`](crate::diff::sha256::digest) — the workspace's only SHA-256.
///
/// # Why hash at all (`T18.1`, Finding M5)
///
/// A label value must be a valid Kubernetes label values string of at most 63 characters, while
/// an `Application` name may be 253. Hashing both identity segments into one fixed-width value
/// solves the length problem and, because `/` cannot appear in either DNS segment, also keeps
/// `ns-a/app` and `ns-b/app` apart — a bare `ferriscd.io/app=<name>` label would collide across
/// namespaces under Apps-in-any-namespace.
///
/// The result is pure and deterministic (no clock, no allocation identity, no case folding), so
/// the same `Application` hashes identically on every replica and in every process. 64 bits is a
/// *hint*, never ownership: a `DriftWatcher` hit only triggers a reconcile, which still verifies
/// the exact [`TrackingId`] before touching anything.
///
/// # Examples
///
/// ```
/// # use ferriscd_engine::inventory::app_hash;
/// let hash = app_hash("ferriscd-system", "payments");
/// assert_eq!(hash, "056646ef98cff795");
/// assert_eq!(hash.len(), 16);
/// assert!(hash.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
/// ```
#[must_use]
pub fn app_hash(app_namespace: &str, app_name: &str) -> String {
    // `<ns>/<name>` is the hashed identity: the separator is unrepresentable in either DNS
    // segment, so the two-part identity cannot be re-split ambiguously.
    let identity = format!("{app_namespace}/{app_name}");
    crate::diff::sha256::hex_digest_prefix(identity.as_bytes(), APP_HASH_HEX_CHARS)
}

/// What [`stamp_tracking_id`] writes onto a managed resource.
///
/// The ownership **annotation** is always stamped; the `T18.1` label pair is opt-in, because it
/// is only useful (and only worth a label slot on every object in the fleet) once a
/// `DriftWatcher` selects on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StampOptions {
    stamp_drift_labels: bool,
}

impl StampOptions {
    /// Only `ferriscd.io/tracking-id` — the `v1.0` behaviour, and the default.
    #[must_use]
    pub const fn tracking_id_only() -> Self {
        Self {
            stamp_drift_labels: false,
        }
    }

    /// Also stamp `ferriscd.io/managed-by` and `ferriscd.io/app-hash`.
    #[must_use]
    pub const fn with_drift_labels() -> Self {
        Self {
            stamp_drift_labels: true,
        }
    }

    /// Maps an operator flag (`--enable-drift-watcher`, default `false`) onto the option.
    #[must_use]
    pub const fn from_flag(stamp_drift_labels: bool) -> Self {
        Self { stamp_drift_labels }
    }

    /// Whether the `T18.1` label pair is stamped.
    #[must_use]
    pub const fn stamps_drift_labels(&self) -> bool {
        self.stamp_drift_labels
    }
}

/// Stamps `ferriscd.io/tracking-id` (and, when opted in, the `T18.1` ownership labels) onto a
/// desired resource's `metadata`.
///
/// Lifecycle hooks (`PreSync`, `Sync`, `PostSync`, `SyncFail` — any non-empty
/// `ferriscd.io/hook`) are **never** stamped: hooks are created imperatively, never enter
/// `status.inventory`, and must not become prunable orphans. Other annotations and labels are
/// preserved byte-for-byte, and re-stamping is idempotent.
///
/// With [`StampOptions::with_drift_labels`] two top-level labels are added —
/// `ferriscd.io/managed-by=ferriscd` and `ferriscd.io/app-hash=<16 hex>` ([`app_hash`]) — which is
/// what a `DriftWatcher` can select on server-side (`T18.2`). Both live on the object's own
/// `metadata.labels` only: immutable `spec.selector.matchLabels` and
/// `spec.template.metadata.labels` are never touched (trap guard), and stamping is additive, so
/// turning the flag off never strips a label from the desired body (Self-Apply converges the
/// removal, once, on the next sync).
///
/// `resource.key` must already be the final, cluster-scope-normalized GKNN identity
/// (Phase 05's `ScopeNormalizer` mirrors the effective namespace onto both the key and
/// `metadata.namespace`), because the stamp is rendered from the key.
///
/// # Errors
///
/// Returns [`TrackingIdError::EmptySegment`] when `app_namespace` or `app_name` is empty;
/// stamping an unparseable identifier would silently disable ownership verification for
/// that object. Nothing is written when the call fails.
///
/// # Examples
///
/// ```
/// # use ferriscd_engine::inventory::{StampOptions, stamp_tracking_id};
/// # use ferriscd_engine::manifest::{DesiredResource, GroupVersionKind, ResourceKey};
/// let object: kube::api::DynamicObject = serde_json::from_value(serde_json::json!({
///     "apiVersion": "apps/v1",
///     "kind": "Deployment",
///     "metadata": { "name": "api", "namespace": "payments" },
/// }))
/// .expect("a valid DynamicObject");
/// let mut resource = DesiredResource {
///     key: ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api"),
///     gvk: GroupVersionKind::parse("apps/v1", "Deployment").expect("a valid apiVersion"),
///     object,
///     source_file: "fixture.yaml".to_owned(),
/// };
/// let stamped = stamp_tracking_id(
///     &mut resource,
///     "ferriscd-system",
///     "payments",
///     StampOptions::with_drift_labels(),
/// )
/// .expect("a named application stamps")
/// .expect("a plain resource is stamped");
/// assert_eq!(stamped, "ferriscd-system/payments:apps/Deployment:payments/api");
/// assert_eq!(
///     resource.object.metadata.labels.as_ref().expect("labels")["ferriscd.io/app-hash"],
///     "056646ef98cff795"
/// );
/// ```
pub fn stamp_tracking_id(
    resource: &mut DesiredResource,
    app_namespace: &str,
    app_name: &str,
    options: StampOptions,
) -> Result<Option<String>, TrackingIdError> {
    if is_hook(resource) {
        return Ok(None);
    }

    let tracking_id = TrackingId::new(app_namespace, app_name, resource.key.clone());
    tracking_id.validate()?;
    let rendered = tracking_id.to_string();
    resource
        .object
        .metadata
        .annotations
        .get_or_insert_with(BTreeMap::new)
        .insert(annotations::TRACKING_ID.to_owned(), rendered.clone());
    if options.stamps_drift_labels() {
        let labels = resource
            .object
            .metadata
            .labels
            .get_or_insert_with(BTreeMap::new);
        labels.insert(
            annotations::LABEL_MANAGED_BY.to_owned(),
            annotations::MANAGED_BY_FERRISCD.to_owned(),
        );
        labels.insert(
            annotations::LABEL_APP_HASH.to_owned(),
            app_hash(app_namespace, app_name),
        );
    }
    Ok(Some(rendered))
}

/// Returns whether the resource declares a lifecycle hook via `ferriscd.io/hook`.
fn is_hook(resource: &DesiredResource) -> bool {
    resource
        .object
        .metadata
        .annotations
        .as_ref()
        .and_then(|map| map.get(annotations::HOOK))
        .is_some_and(|phase| !phase.trim().is_empty())
}

/// Ownership of a live object, evaluated against the expected `tracking-id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ownership {
    /// The live object carries exactly the expected `tracking-id`.
    OwnedBySelf,

    /// The live object carries no (non-empty) `tracking-id`: it is either pre-existing or
    /// was created outside FerrisCD.
    Unmanaged,

    /// The live object carries a different `tracking-id`; the payload is the raw
    /// annotation value (which may itself be malformed — it is another application's
    /// object and must never be adopted or pruned).
    OwnedByForeign(String),
}

/// Classifies a live object's ownership by its `ferriscd.io/tracking-id` annotation.
///
/// The comparison is an exact byte comparison of the annotation value against `expected`:
/// no trimming, normalization, or parsing happens on the live value, so a value that only
/// *looks* like ours (extra whitespace, malformed segments) is always classified as
/// [`Ownership::OwnedByForeign`] and can never be hijacked or deleted. A missing,
/// empty, or whitespace-only annotation is [`Ownership::Unmanaged`].
#[must_use]
pub fn classify_ownership(live: &DynamicObject, expected: &str) -> Ownership {
    let Some(recorded) = live
        .metadata
        .annotations
        .as_ref()
        .and_then(|map| map.get(annotations::TRACKING_ID))
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ownership::Unmanaged;
    };

    if recorded == expected {
        Ownership::OwnedBySelf
    } else {
        Ownership::OwnedByForeign(recorded.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::manifest::types::GroupVersionKind;

    fn desired(
        group: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
        version: &str,
        annotations: Option<Value>,
    ) -> DesiredResource {
        let api_version = if group.is_empty() {
            version.to_owned()
        } else {
            format!("{group}/{version}")
        };

        let mut metadata = json!({ "name": name, "namespace": namespace });
        if let Some(annotations) = annotations {
            metadata["annotations"] = annotations;
        }

        let object = serde_json::from_value(json!({
            "apiVersion": api_version,
            "kind": kind,
            "metadata": metadata,
        }))
        .expect("valid DynamicObject");

        DesiredResource {
            key: ResourceKey::new(group, kind, namespace.map(str::to_owned), name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("valid apiVersion"),
            object,
            source_file: "fixture.yaml".to_owned(),
        }
    }

    fn live(annotations: Option<Value>) -> DynamicObject {
        let mut metadata = json!({ "name": "api", "namespace": "payments" });
        if let Some(annotations) = annotations {
            metadata["annotations"] = annotations;
        }
        serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": metadata,
        }))
        .expect("valid DynamicObject")
    }

    fn annotation(resource: &DesiredResource, key: &str) -> Option<String> {
        resource
            .object
            .metadata
            .annotations
            .as_ref()
            .and_then(|map| map.get(key))
            .cloned()
    }

    #[test]
    fn stamping_sets_the_tracking_id_and_preserves_other_annotations() {
        let mut resource = desired(
            "apps",
            "Deployment",
            Some("payments"),
            "api",
            "v1",
            Some(json!({
                "example.com/keep": "unchanged",
                "ferriscd.io/sync-wave": "3",
            })),
        );

        let stamped = stamp_tracking_id(
            &mut resource,
            "ferriscd-system",
            "payments",
            StampOptions::default(),
        )
        .expect("stamping must succeed")
        .expect("a non-hook resource is stamped");

        assert_eq!(
            stamped, "ferriscd-system/payments:apps/Deployment:payments/api",
            "the tracking-id format is `<app-ns>/<app-name>:<group>/<kind>:<res-ns>/<res-name>`"
        );
        assert_eq!(
            annotation(&resource, annotations::TRACKING_ID),
            Some(stamped.clone())
        );
        assert_eq!(
            annotation(&resource, "example.com/keep"),
            Some("unchanged".to_owned()),
            "unrelated annotations must survive stamping"
        );
        assert_eq!(
            annotation(&resource, annotations::SYNC_WAVE),
            Some("3".to_owned())
        );

        // Re-stamping is idempotent: same value, no duplicate annotation entries.
        let again = stamp_tracking_id(
            &mut resource,
            "ferriscd-system",
            "payments",
            StampOptions::default(),
        )
        .expect("re-stamping must succeed");
        assert_eq!(again, Some(stamped.clone()));
        let map = resource
            .object
            .metadata
            .annotations
            .as_ref()
            .expect("annotations");
        assert_eq!(map.len(), 3, "re-stamping must not add entries: {map:?}");
        assert_eq!(
            map.get(annotations::TRACKING_ID),
            Some(&stamped),
            "re-stamping must keep the same value"
        );
    }

    #[test]
    fn stamping_creates_the_annotation_map_when_absent() {
        let mut resource = desired("", "ConfigMap", Some("payments"), "cfg", "v1", None);
        let stamped = stamp_tracking_id(
            &mut resource,
            "ferriscd-system",
            "payments",
            StampOptions::default(),
        )
        .expect("stamping must succeed");
        assert_eq!(
            stamped.as_deref(),
            Some("ferriscd-system/payments:/ConfigMap:payments/cfg"),
            "the core group keeps an empty group segment"
        );
        assert_eq!(
            annotation(&resource, annotations::TRACKING_ID),
            stamped,
            "stamping must create metadata.annotations when it is missing"
        );
    }

    #[test]
    fn tracking_id_is_version_agnostic() {
        let key = ResourceKey::new(
            "networking.k8s.io",
            "Ingress",
            Some("payments".to_owned()),
            "web",
        );
        let beta = tracking_id_for("ferriscd-system", "payments", &key);
        assert_eq!(
            beta, "ferriscd-system/payments:networking.k8s.io/Ingress:payments/web",
            "no API version may appear in the tracking-id"
        );
        assert!(
            !beta.contains("v1beta1") && !beta.contains("/v1"),
            "tracking-id must not carry a version segment: {beta}"
        );

        // Two desired resources that differ only in apiVersion stamp identically.
        let mut v1beta1 = desired(
            "networking.k8s.io",
            "Ingress",
            Some("payments"),
            "web",
            "v1beta1",
            None,
        );
        let mut v1 = desired(
            "networking.k8s.io",
            "Ingress",
            Some("payments"),
            "web",
            "v1",
            None,
        );
        assert_eq!(
            stamp_tracking_id(
                &mut v1beta1,
                "ferriscd-system",
                "payments",
                StampOptions::default()
            )
            .expect("stamp"),
            stamp_tracking_id(
                &mut v1,
                "ferriscd-system",
                "payments",
                StampOptions::default()
            )
            .expect("stamp"),
        );
        assert_eq!(v1beta1.gvk.version, "v1beta1");
        assert_eq!(v1.gvk.version, "v1");
    }

    #[test]
    fn stamping_skips_every_lifecycle_hook() {
        for phase in ["PreSync", "Sync", "PostSync", "SyncFail"] {
            let mut resource = desired(
                "",
                "Job",
                Some("payments"),
                "migrate",
                "v1",
                Some(json!({
                    "ferriscd.io/hook": phase,
                    "example.com/keep": "unchanged",
                })),
            );

            let stamped = stamp_tracking_id(
                &mut resource,
                "ferriscd-system",
                "payments",
                StampOptions::default(),
            )
            .expect("hook stamping must not error");
            assert_eq!(stamped, None, "hook phase {phase} must not be stamped");
            assert_eq!(
                annotation(&resource, annotations::TRACKING_ID),
                None,
                "hook phase {phase} must stay untracked"
            );
            assert_eq!(
                annotation(&resource, "example.com/keep"),
                Some("unchanged".to_owned())
            );
        }

        // An empty hook annotation is not a hook (same convention as the YAML parser).
        let mut blank = desired(
            "",
            "Job",
            Some("payments"),
            "migrate",
            "v1",
            Some(json!({ "ferriscd.io/hook": "  " })),
        );
        assert!(
            stamp_tracking_id(
                &mut blank,
                "ferriscd-system",
                "payments",
                StampOptions::default()
            )
            .expect("stamp")
            .is_some(),
            "a blank hook annotation is not a hook"
        );

        // An unrelated ferriscd.io annotation does not make the resource a hook.
        let mut policy = desired(
            "",
            "Job",
            Some("payments"),
            "cleanup",
            "v1",
            Some(json!({ "ferriscd.io/hook-delete-policy": "hook-succeeded" })),
        );
        assert!(
            stamp_tracking_id(
                &mut policy,
                "ferriscd-system",
                "payments",
                StampOptions::default()
            )
            .expect("stamp")
            .is_some()
        );
    }

    #[test]
    fn stamping_rejects_an_empty_application_reference() {
        let mut resource = desired("apps", "Deployment", Some("payments"), "api", "v1", None);
        assert_eq!(
            stamp_tracking_id(&mut resource, "", "payments", StampOptions::default())
                .expect_err("empty app namespace"),
            TrackingIdError::EmptySegment {
                field: "application namespace"
            }
        );
        assert_eq!(
            stamp_tracking_id(
                &mut resource,
                "ferriscd-system",
                " ",
                StampOptions::default()
            )
            .expect_err("blank app name"),
            TrackingIdError::EmptySegment {
                field: "application name"
            }
        );
        assert_eq!(
            annotation(&resource, annotations::TRACKING_ID),
            None,
            "a rejected stamp must not write anything"
        );
        assert!(!TrackingIdError::PartCount.is_retryable());
    }

    #[test]
    fn parse_round_trips_cluster_scoped_core_group_and_namespaced_ids() {
        // Namespaced, grouped.
        let namespaced = TrackingId::new(
            "ferriscd-system",
            "payments",
            ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api"),
        );
        let rendered = namespaced.to_string();
        assert_eq!(
            rendered,
            "ferriscd-system/payments:apps/Deployment:payments/api"
        );
        assert_eq!(TrackingId::parse(&rendered).expect("parse"), namespaced);
        assert_eq!(
            tracking_id_for("ferriscd-system", "payments", &namespaced.key),
            rendered
        );

        // Cluster-scoped: the resource namespace segment is empty.
        let cluster = TrackingId::new(
            "ferriscd-system",
            "platform",
            ResourceKey::new(
                "rbac.authorization.k8s.io",
                "ClusterRole",
                None,
                "ferriscd-admin",
            ),
        );
        let rendered = cluster.to_string();
        assert_eq!(
            rendered,
            "ferriscd-system/platform:rbac.authorization.k8s.io/ClusterRole:/ferriscd-admin",
            "cluster-scoped resources keep an empty `<res-ns>` segment"
        );
        let parsed = TrackingId::parse(&rendered).expect("parse cluster-scoped");
        assert_eq!(parsed, cluster);
        assert_eq!(parsed.key.namespace, None);

        // Core group: the group segment is empty.
        let core = TrackingId::new(
            "ferriscd-system",
            "payments",
            ResourceKey::new("", "Service", Some("payments".to_owned()), "api"),
        );
        let rendered = core.to_string();
        assert_eq!(rendered, "ferriscd-system/payments:/Service:payments/api");
        assert_eq!(
            TrackingId::parse(&rendered).expect("parse core group"),
            core
        );

        // Core group + cluster-scoped (empty group and empty namespace).
        let core_cluster = TrackingId::new(
            "ferriscd-system",
            "platform",
            ResourceKey::new("", "Namespace", None, "team-a"),
        );
        let rendered = core_cluster.to_string();
        assert_eq!(rendered, "ferriscd-system/platform:/Namespace:/team-a");
        assert_eq!(
            TrackingId::parse(&rendered).expect("parse core cluster-scoped"),
            core_cluster
        );
    }

    #[test]
    fn parse_rejects_malformed_tracking_ids() {
        let cases: Vec<(&str, TrackingIdError)> = vec![
            ("", TrackingIdError::PartCount),
            ("ferriscd-system/payments", TrackingIdError::PartCount),
            ("a:b:c", TrackingIdError::SegmentCount { part: 0 }),
            (
                "ferriscd-system/payments:apps:payments/api",
                TrackingIdError::SegmentCount { part: 1 },
            ),
            (
                "ferriscd-system/payments:apps/Deployment:payments/api:extra",
                TrackingIdError::PartCount,
            ),
            (
                "ferriscd-system/payments:apps/Deployment/payments",
                TrackingIdError::PartCount,
            ),
            (
                "ferriscd-system/payments:apps/Deployment:payments/api/extra",
                TrackingIdError::SegmentCount { part: 2 },
            ),
            (
                "/payments:apps/Deployment:payments/api",
                TrackingIdError::EmptySegment {
                    field: "application namespace",
                },
            ),
            (
                "ferriscd-system/:apps/Deployment:payments/api",
                TrackingIdError::EmptySegment {
                    field: "application name",
                },
            ),
            (
                "ferriscd-system/ :apps/Deployment:payments/api",
                TrackingIdError::EmptySegment {
                    field: "application name",
                },
            ),
            (
                "ferriscd-system/payments:apps/:payments/api",
                TrackingIdError::EmptySegment {
                    field: "resource kind",
                },
            ),
            (
                "ferriscd-system/payments:apps/Deployment:payments/",
                TrackingIdError::EmptySegment {
                    field: "resource name",
                },
            ),
            // A versioned (GVKNN) identifier is malformed: identity must be version-agnostic.
            (
                "ferriscd-system/payments:apps/v1/Deployment:payments/api",
                TrackingIdError::SegmentCount { part: 1 },
            ),
            // The optional segments may be empty, never blank.
            (
                "ferriscd-system/payments: /Deployment:payments/api",
                TrackingIdError::BlankOptionalSegment {
                    field: "resource group",
                },
            ),
            (
                "ferriscd-system/payments:apps/Deployment: /api",
                TrackingIdError::BlankOptionalSegment {
                    field: "resource namespace",
                },
            ),
            // Non-ASCII input must never panic.
            ("☃:☃:☃", TrackingIdError::SegmentCount { part: 0 }),
        ];

        for (raw, expected) in cases {
            assert_eq!(
                TrackingId::parse(raw).expect_err("must reject malformed id"),
                expected,
                "raw = {raw:?}"
            );
        }
    }

    #[test]
    fn classify_ownership_covers_all_three_states() {
        let expected = "ferriscd-system/payments:apps/Deployment:payments/api";

        assert_eq!(
            classify_ownership(&live(None), expected),
            Ownership::Unmanaged,
            "no annotations => unmanaged"
        );
        assert_eq!(
            classify_ownership(&live(Some(json!({ "example.com/keep": "yes" }))), expected),
            Ownership::Unmanaged,
            "unrelated annotations => unmanaged"
        );
        assert_eq!(
            classify_ownership(
                &live(Some(json!({ "ferriscd.io/tracking-id": "" }))),
                expected
            ),
            Ownership::Unmanaged,
            "an empty tracking-id is not ownership"
        );
        assert_eq!(
            classify_ownership(
                &live(Some(json!({ "ferriscd.io/tracking-id": "  " }))),
                expected
            ),
            Ownership::Unmanaged,
            "a whitespace-only tracking-id is not ownership"
        );

        assert_eq!(
            classify_ownership(
                &live(Some(json!({ "ferriscd.io/tracking-id": expected }))),
                expected
            ),
            Ownership::OwnedBySelf
        );

        assert_eq!(
            classify_ownership(
                &live(Some(
                    json!({ "ferriscd.io/tracking-id": "ferriscd-system/other:apps/Deployment:payments/api" })
                )),
                expected
            ),
            Ownership::OwnedByForeign(
                "ferriscd-system/other:apps/Deployment:payments/api".to_owned()
            ),
            "a resource owned by a different app must never be adopted"
        );

        // A malformed foreign value is still foreign, never unmanaged and never ours.
        assert_eq!(
            classify_ownership(
                &live(Some(
                    json!({ "ferriscd.io/tracking-id": "not-a-tracking-id" })
                )),
                expected
            ),
            Ownership::OwnedByForeign("not-a-tracking-id".to_owned())
        );

        // Exact comparison: a value that only differs by whitespace is foreign.
        assert_eq!(
            classify_ownership(
                &live(Some(
                    json!({ "ferriscd.io/tracking-id": format!("{expected} ") })
                )),
                expected
            ),
            Ownership::OwnedByForeign(format!("{expected} "))
        );
    }

    #[test]
    fn stamped_resources_classify_as_owned_by_self() {
        let mut resource = desired(
            "networking.k8s.io",
            "Ingress",
            Some("payments"),
            "web",
            "v1beta1",
            None,
        );
        let stamped = stamp_tracking_id(
            &mut resource,
            "ferriscd-system",
            "payments",
            StampOptions::default(),
        )
        .expect("stamp")
        .expect("non-hook");

        // The applied object carries the stamped annotation; recovery compares it back.
        assert_eq!(
            classify_ownership(&resource.object, &stamped),
            Ownership::OwnedBySelf
        );
        assert_eq!(
            classify_ownership(
                &resource.object,
                &tracking_id_for(
                    "ferriscd-system",
                    "other",
                    &ResourceKey::new(
                        "networking.k8s.io",
                        "Ingress",
                        Some("payments".to_owned()),
                        "web"
                    )
                )
            ),
            Ownership::OwnedByForeign(stamped)
        );
    }

    // -----------------------------------------------------------------
    // `T18.1`: the opt-in ownership labels
    // -----------------------------------------------------------------

    /// A `Deployment` whose immutable `spec.selector.matchLabels` and pod-template labels mirror
    /// its own top-level labels — the trap guard's fixture.
    fn deployment_with_immutable_selectors() -> DesiredResource {
        let object = serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "api",
                "namespace": "payments",
                "labels": {
                    "app.kubernetes.io/name": "api",
                    "example.com/keep": "unchanged",
                },
            },
            "spec": {
                "replicas": 2,
                "selector": {
                    "matchLabels": { "app.kubernetes.io/name": "api" },
                },
                "template": {
                    "metadata": { "labels": { "app.kubernetes.io/name": "api" } },
                    "spec": { "containers": [ { "name": "api", "image": "ghcr.io/example/api:v1" } ] },
                },
            },
        }))
        .expect("valid DynamicObject");

        DesiredResource {
            key: ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api"),
            gvk: GroupVersionKind::parse("apps/v1", "Deployment").expect("valid apiVersion"),
            object,
            source_file: "fixture.yaml".to_owned(),
        }
    }

    fn label(resource: &DesiredResource, key: &str) -> Option<String> {
        resource
            .object
            .metadata
            .labels
            .as_ref()
            .and_then(|map| map.get(key))
            .cloned()
    }

    /// Stamping the label pair is **opt-in**: the default writes the annotation only, so a
    /// pre-`v1.2` `Application` applies a byte-identical body.
    #[test]
    fn drift_labels_are_opt_in_and_additive() {
        let mut resource = deployment_with_immutable_selectors();
        assert_eq!(label(&resource, annotations::LABEL_MANAGED_BY), None);

        stamp_tracking_id(
            &mut resource,
            "ferriscd-system",
            "payments",
            StampOptions::default(),
        )
        .expect("stamp")
        .expect("non-hook");
        assert!(
            resource.object.metadata.labels.as_ref().is_some_and(|map| {
                !map.contains_key(annotations::LABEL_MANAGED_BY)
                    && !map.contains_key(annotations::LABEL_APP_HASH)
            }),
            "the default must not stamp a label: {:?}",
            resource.object.metadata.labels
        );
        assert!(!StampOptions::default().stamps_drift_labels());
        assert!(!StampOptions::from_flag(false).stamps_drift_labels());
        assert!(StampOptions::from_flag(true).stamps_drift_labels());

        // Opting in adds exactly the two documented labels — never replaces the user's own.
        stamp_tracking_id(
            &mut resource,
            "ferriscd-system",
            "payments",
            StampOptions::with_drift_labels(),
        )
        .expect("stamp")
        .expect("non-hook");
        assert_eq!(
            label(&resource, annotations::LABEL_MANAGED_BY).as_deref(),
            Some(annotations::MANAGED_BY_FERRISCD)
        );
        assert_eq!(
            label(&resource, annotations::LABEL_APP_HASH).as_deref(),
            Some("056646ef98cff795"),
            "the hash of `<app-ns>/<app-name>` is pinned"
        );
        assert_eq!(
            label(&resource, "example.com/keep").as_deref(),
            Some("unchanged"),
            "a label FerrisCD does not own must survive stamping"
        );
        assert_eq!(
            resource
                .object
                .metadata
                .labels
                .as_ref()
                .expect("labels")
                .len(),
            4,
            "exactly two labels are added (re-stamping adds none)"
        );

        // Additive: switching the flag off never strips what an opted-in sync already applied (the
        // next Server-Side Apply owns the removal, so toggling cannot fight the cluster).
        stamp_tracking_id(
            &mut resource,
            "ferriscd-system",
            "payments",
            StampOptions::tracking_id_only(),
        )
        .expect("stamp");
        assert_eq!(
            label(&resource, annotations::LABEL_MANAGED_BY).as_deref(),
            Some(annotations::MANAGED_BY_FERRISCD)
        );
        assert_eq!(
            annotation(&resource, annotations::TRACKING_ID).as_deref(),
            Some("ferriscd-system/payments:apps/Deployment:payments/api"),
            "the ownership annotation is always stamped, whatever the label option is"
        );
    }

    /// **Acceptance criterion (1):** a 253-character `Application` name (and a 63-character
    /// namespace, the Kubernetes maxima) still produces exactly 16 lowercase hex characters, so the
    /// value is always valid under the 63-character label-value limit (Finding M5).
    #[test]
    fn app_hash_is_bounded_and_valid_for_the_longest_names() {
        let longest_name = "a".repeat(253);
        let longest_namespace = "n".repeat(63);

        for (namespace, name, expected) in [
            ("ferriscd-system", "payments", "056646ef98cff795"),
            ("ferriscd-system", longest_name.as_str(), "cc029a55ae61ef1e"),
            (
                longest_namespace.as_str(),
                longest_name.as_str(),
                "54001513e80cd734",
            ),
        ] {
            let hash = app_hash(namespace, name);
            assert_eq!(hash, expected, "hash for {namespace:?}/{name:?}");
            assert_eq!(hash.len(), APP_HASH_HEX_CHARS);
            assert!(
                hash.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "a label value must be lowercase hex, never upper case: {hash}"
            );
            assert!(
                hash.len() <= 63,
                "a Kubernetes label value is at most 63 characters: {hash}"
            );
            // Pure and deterministic: no clock, no per-process state.
            assert_eq!(hash, app_hash(namespace, name));
        }
    }

    /// **Acceptance criterion (2):** the hash binds the namespace and the name together, so
    /// `ns-a/app` and `ns-b/app` never collide (the Apps-in-any-namespace case Finding M5 names).
    #[test]
    fn app_hash_is_distinct_per_namespace() {
        assert_eq!(app_hash("ns-a", "app"), "245f1eab9952fdbe");
        assert_eq!(app_hash("ns-b", "app"), "0a84585af4bffa6f");
        assert_ne!(app_hash("ns-a", "app"), app_hash("ns-b", "app"));

        // The namespace and the name are hashed as one `<ns>/<name>` string, and `/` is not a legal
        // character in either DNS segment, so no two legal `(namespace, name)` pairs can produce
        // the same string. Two pairs built from the legal character set — dots included — therefore
        // hash differently.
        assert_ne!(app_hash("a.b", "c"), app_hash("a", "b.c"));
        assert_ne!(app_hash("a", "app"), app_hash("b", "app"));
        assert_ne!(app_hash("a", "app"), app_hash("a", "app2"));

        // Every resource of one `Application` carries the same hash, whatever it manages.
        let mut service = desired("", "Service", Some("payments"), "api", "v1", None);
        let mut deployment = deployment_with_immutable_selectors();
        for resource in [&mut service, &mut deployment] {
            stamp_tracking_id(
                resource,
                "ferriscd-system",
                "payments",
                StampOptions::with_drift_labels(),
            )
            .expect("stamp");
        }
        assert_eq!(
            label(&service, annotations::LABEL_APP_HASH),
            label(&deployment, annotations::LABEL_APP_HASH),
            "the hash identifies the Application, not the resource"
        );
    }

    /// **Acceptance criterion (3):** a lifecycle hook is never stamped — with the labels either.
    /// A hook that carried them would look managed to a `DriftWatcher` and prunable to the pruner.
    #[test]
    fn drift_labels_are_never_stamped_onto_a_lifecycle_hook() {
        for phase in ["PreSync", "Sync", "PostSync", "SyncFail"] {
            let mut hook = desired(
                "batch",
                "Job",
                Some("payments"),
                "migrate",
                "v1",
                Some(json!({ "ferriscd.io/hook": phase })),
            );
            assert_eq!(
                stamp_tracking_id(
                    &mut hook,
                    "ferriscd-system",
                    "payments",
                    StampOptions::with_drift_labels()
                )
                .expect("a hook is not an error"),
                None,
                "hook phase {phase} must not be stamped"
            );
            assert_eq!(hook.object.metadata.labels, None, "hook phase {phase}");
            assert_eq!(
                hook.object.metadata.annotations.as_ref().map(BTreeMap::len),
                Some(1),
                "hook phase {phase} keeps only the annotation the manifest itself declared"
            );
        }
    }

    /// **Acceptance criterion (4) / trap guard:** only the top-level `metadata.labels` are written.
    /// `spec.selector.matchLabels` and `spec.template.metadata.labels` are immutable on
    /// `Deployment`/`StatefulSet`/`DaemonSet`, so a label there would turn every later apply into a
    /// `422 Immutable` failure.
    #[test]
    fn drift_labels_never_reach_a_selector_or_a_pod_template() {
        let mut resource = deployment_with_immutable_selectors();
        let before = serde_json::to_value(&resource.object).expect("serialize");

        stamp_tracking_id(
            &mut resource,
            "ferriscd-system",
            "payments",
            StampOptions::with_drift_labels(),
        )
        .expect("stamp")
        .expect("non-hook");

        let after = serde_json::to_value(&resource.object).expect("serialize");
        assert_eq!(
            after["spec"], before["spec"],
            "the whole spec — selector.matchLabels and the pod template included — must be \
             byte-identical after stamping"
        );
        let spec = serde_json::to_string(&after["spec"]).expect("serialize spec");
        for key in annotations::MANAGED_RESOURCE_LABELS {
            assert!(
                !spec.contains(key),
                "{key} must never appear anywhere under /spec: {spec}"
            );
        }
        // The labels land where a watch label selector can filter on them: the object's own
        // metadata.
        assert_eq!(
            after["metadata"]["labels"][annotations::LABEL_MANAGED_BY],
            json!(annotations::MANAGED_BY_FERRISCD)
        );
        assert_eq!(
            after["metadata"]["labels"][annotations::LABEL_APP_HASH],
            json!("056646ef98cff795")
        );
    }

    /// A rejected stamp writes nothing at all — not the annotation, and not the label pair.
    #[test]
    fn a_rejected_stamp_never_writes_a_drift_label() {
        let mut resource = deployment_with_immutable_selectors();
        let labels_before = resource.object.metadata.labels.clone();

        assert_eq!(
            stamp_tracking_id(
                &mut resource,
                "",
                "payments",
                StampOptions::with_drift_labels()
            )
            .expect_err("an empty namespace cannot be stamped"),
            TrackingIdError::EmptySegment {
                field: "application namespace"
            }
        );
        assert_eq!(
            resource.object.metadata.labels, labels_before,
            "a failed stamp must not add a label"
        );
        assert_eq!(
            resource.object.metadata.annotations, None,
            "a failed stamp must not add an annotation"
        );
    }
}

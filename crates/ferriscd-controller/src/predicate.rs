//! Composite watch predicate for `Application`.
//!
//! `kube_runtime::predicates::generation` is a trap (review finding C4): it hashes only
//! `metadata.generation`, which
//!
//! * never changes when a finalizer or a control annotation is added — so a refresh
//!   request or a delete-time cleanup signal is silently dropped, and
//! * never changes for status-only writes — which is the *only* thing this predicate
//!   actually needs to suppress.
//!
//! [`composite_hash`] therefore hashes exactly the fields FerrisCD reacts to:
//! `(metadata.generation, metadata.deletion_timestamp, metadata.finalizers,
//! annotations{refresh, operation, cascade-delete, force-delete})`. Status writes, labels,
//! and unrelated annotations produce an unchanged hash, so patching `/status` from the
//! always-update-status wrapper can never re-trigger a reconcile (Trap T2).

use std::collections::HashMap;

use ferriscd_crd::{Application, annotations};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::ResourceExt;
use kube::runtime::Predicate;

/// Control annotations whose value changes must always trigger a reconcile.
///
/// Deliberately a subset of [`annotations::CONTROL_ANNOTATIONS`]: the remaining keys
/// (`sync-wave`, `hook`, `prune`, `tracking-id`, ...) only matter for resources FerrisCD
/// *manages*, never for the `Application` object itself.
pub const TRACKED_ANNOTATIONS: [&str; 4] = [
    annotations::REFRESH,
    annotations::OPERATION,
    annotations::CASCADE_DELETE,
    annotations::FORCE_DELETE,
];

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Absorbs `bytes` into a running FNV-1a hash.
///
/// A hand-rolled, documented hash is used instead of `DefaultHasher` so the value stays
/// stable across toolchains and processes: the predicate cache survives restarts only if
/// the same object always hashes to the same number.
fn absorb(state: u64, bytes: &[u8]) -> u64 {
    let mut hash = state;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Hashes the fields that make an `Application` change meaningful.
#[must_use]
pub fn composite_hash(meta: &ObjectMeta) -> u64 {
    let mut hash = absorb(FNV_OFFSET_BASIS, b"ferriscd/application-predicate/v1");

    hash = absorb(hash, &meta.generation.unwrap_or_default().to_le_bytes());

    match &meta.deletion_timestamp {
        Some(timestamp) => {
            hash = absorb(hash, b"\x01");
            // `Time` wraps a `jiff::Timestamp`; its RFC 3339 rendering is stable.
            hash = absorb(hash, timestamp.0.to_string().as_bytes());
        }
        None => hash = absorb(hash, b"\x00"),
    }

    let finalizers = meta.finalizers.as_deref().unwrap_or_default();
    hash = absorb(hash, &(finalizers.len() as u64).to_le_bytes());
    for finalizer in finalizers {
        hash = absorb(hash, finalizer.as_bytes());
        hash = absorb(hash, b"\x1f");
    }

    for key in TRACKED_ANNOTATIONS {
        hash = absorb(hash, key.as_bytes());
        match meta
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(key))
        {
            Some(value) => {
                hash = absorb(hash, b"\x01");
                hash = absorb(hash, value.as_bytes());
            }
            None => hash = absorb(hash, b"\x00"),
        }
    }

    hash
}

/// `kube_runtime` adapter around [`composite_hash`].
///
/// Pass this to `predicate_filter` when building the controller's watch stream.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApplicationPredicate;

impl Predicate<Application> for ApplicationPredicate {
    fn hash_property(&self, app: &Application) -> Option<u64> {
        Some(composite_hash(&app.metadata))
    }
}

/// Returns the predicate usable with `kube_runtime::WatchStreamExt::predicate_filter`.
#[must_use]
pub fn predicate() -> ApplicationPredicate {
    ApplicationPredicate
}

/// Per-object memory of the last observed composite hash for `ApplicationSet` (`T19.3`).
///
/// The `ApplicationSet` loop consumes a raw watch (`Apply`/`Delete`/`InitDone`), not a
/// `kube::runtime::Controller`, so nothing else suppresses a self-triggered pass. That matters more
/// here than for `Application`: **every** pass patches `/status`, the API server reports the patch
/// as another `Apply` event, and without this guard the loop reconciles back-to-back forever (a live
/// `kind` run measured about ten passes per second, each listing the namespace's `Application`s and
/// re-running the generators).
///
/// The hash is the shared [`composite_hash`], so a spec change, `metadata.finalizers` (the deletion
/// hook), a `metadata.deletionTimestamp`, or a control annotation still triggers a pass, while a
/// status-only, label-only, or `resourceVersion`-only update does not — the periodic requeue covers
/// anything else.
#[derive(Debug, Default)]
pub struct ApplicationSetChangeTracker {
    seen: HashMap<String, u64>,
}

impl ApplicationSetChangeTracker {
    /// Builds an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `appset` and returns whether the observation must trigger a pass.
    ///
    /// The first observation of a name always triggers, so a controller that starts mid-flight (or
    /// a watch reconnect, which replays every object) still reconciles.
    pub fn observe(&mut self, appset: &ferriscd_crd::ApplicationSet) -> bool {
        let hash = composite_hash(&appset.metadata);
        match self.seen.insert(appset.name_any(), hash) {
            Some(previous) => previous != hash,
            None => true,
        }
    }

    /// Forgets a deleted object, so a later re-creation always triggers.
    pub fn forget(&mut self, name: &str) {
        self.seen.remove(name);
    }
}

/// Per-object memory of the last observed hash.
///
/// Mirrors what `kube`'s `PredicateFilter` does internally (cache keyed by
/// namespace/name) so the "does this change reconcile?" decision is unit-testable without
/// a cluster: the first observation always reconciles, then only hash changes do.
#[derive(Debug, Default)]
pub struct PredicateTracker {
    seen: HashMap<(Option<String>, String), u64>,
}

impl PredicateTracker {
    /// Builds an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `app` and returns whether the observation must trigger a reconcile.
    pub fn observe(&mut self, app: &Application) -> bool {
        let key = (
            app.metadata.namespace.clone(),
            app.metadata.name.clone().unwrap_or_default(),
        );
        let hash = composite_hash(&app.metadata);
        match self.seen.insert(key, hash) {
            Some(previous) => previous != hash,
            None => true,
        }
    }

    /// Forgets a deleted object, so a re-created object of the same name always reconciles.
    pub fn forget(&mut self, namespace: Option<&str>, name: &str) {
        self.seen
            .remove(&(namespace.map(str::to_owned), name.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{
        ApplicationStatus, HealthState, HealthStatus, SyncState, SyncStatus,
    };
    use ferriscd_crd::{
        ApplicationSpec, DEFAULT_PROJECT_NAME, DestinationSpec, GitSourceSpec, RendererSpec,
        SourceSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    use super::*;

    fn timestamp(rfc3339: &str) -> Time {
        Time(rfc3339.parse().expect("test timestamp must be RFC 3339"))
    }

    fn application() -> Application {
        let spec = ApplicationSpec {
            project: DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: SourceSpec {
                git: GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                },
                renderer: RendererSpec::default(),
            },
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut app = Application::new("demo-app", spec);
        app.metadata.namespace = Some("ferriscd-system".to_owned());
        app.metadata.generation = Some(1);
        app
    }

    fn annotate(app: &mut Application, key: &str, value: &str) {
        app.metadata
            .annotations
            .get_or_insert_with(std::collections::BTreeMap::new)
            .insert(key.to_owned(), value.to_owned());
    }

    /// A status-only write is the one thing the predicate must suppress: the
    /// always-update-status wrapper patches `/status` after every reconcile, and a
    /// status bump that re-triggered a reconcile would loop forever (Trap T2).
    #[test]
    fn status_only_changes_do_not_trigger() {
        let before = application();
        let mut after = before.clone();

        after.status = Some(ApplicationStatus {
            observed_generation: Some(1),
            sync: Some(SyncState::new(
                SyncStatus::Synced,
                Some("abc1234".to_owned()),
            )),
            health: Some(HealthState::new(HealthStatus::Healthy)),
            ..ApplicationStatus::default()
        });
        after.metadata.resource_version = Some("4242".to_owned());
        after
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                "kubectl.kubernetes.io/last-applied-configuration".to_owned(),
                "{}".to_owned(),
            );
        after
            .metadata
            .labels
            .get_or_insert_with(Default::default)
            .insert("unrelated.example.com/label".to_owned(), "value".to_owned());

        let mut tracker = PredicateTracker::new();
        assert!(
            tracker.observe(&before),
            "the first sighting must reconcile"
        );
        assert!(
            !tracker.observe(&after),
            "a status-only (or label/unrelated-annotation) change must not reconcile"
        );
        assert_eq!(
            composite_hash(&before.metadata),
            composite_hash(&after.metadata)
        );
    }

    #[test]
    fn generation_bumps_trigger() {
        let before = application();
        let mut after = before.clone();
        after.metadata.generation = Some(2);

        let mut tracker = PredicateTracker::new();
        assert!(tracker.observe(&before));
        assert!(
            tracker.observe(&after),
            "spec generation change must reconcile"
        );
        assert_ne!(
            composite_hash(&before.metadata),
            composite_hash(&after.metadata)
        );
    }

    #[test]
    fn finalizer_changes_trigger() {
        let before = application();
        let mut after = before.clone();
        // Adding a finalizer does not bump `generation`; a generation-only predicate
        // would drop this event and the finalizer would never be observed.
        after.metadata.finalizers = Some(vec![crate::reconcile::FINALIZER.to_owned()]);

        let mut tracker = PredicateTracker::new();
        assert!(tracker.observe(&before));
        assert!(tracker.observe(&after), "finalizer add must reconcile");
        assert_eq!(after.metadata.generation, before.metadata.generation);

        let mut removed = after.clone();
        removed.metadata.finalizers = None;
        assert!(
            tracker.observe(&removed),
            "finalizer removal must reconcile"
        );
    }

    #[test]
    fn deletion_timestamp_changes_trigger() {
        let before = application();
        let mut after = before.clone();
        after.metadata.deletion_timestamp = Some(timestamp("2026-11-24T12:00:00Z"));

        let mut tracker = PredicateTracker::new();
        assert!(tracker.observe(&before));
        assert!(tracker.observe(&after), "deletion must trigger cleanup");

        // Two distinct deletion timestamps must not collapse into one hash.
        let mut later = after.clone();
        later.metadata.deletion_timestamp = Some(timestamp("2026-11-24T12:00:01Z"));
        assert_ne!(
            composite_hash(&after.metadata),
            composite_hash(&later.metadata)
        );
    }

    #[test]
    fn every_control_annotation_triggers() {
        for key in TRACKED_ANNOTATIONS {
            let before = application();
            let mut after = before.clone();
            annotate(&mut after, key, "true");
            assert_eq!(
                after.metadata.generation, before.metadata.generation,
                "control annotations must be tracked independently of generation"
            );

            let mut tracker = PredicateTracker::new();
            assert!(tracker.observe(&before));
            assert!(tracker.observe(&after), "annotation {key} must reconcile");

            // Changing an existing value (not just adding the key) must also reconcile.
            let mut changed = after.clone();
            annotate(&mut changed, key, "false");
            assert!(
                tracker.observe(&changed),
                "changing the value of {key} must reconcile"
            );
        }
    }

    #[test]
    fn tracked_annotations_are_the_documented_control_set() {
        assert_eq!(
            TRACKED_ANNOTATIONS,
            [
                annotations::REFRESH,
                annotations::OPERATION,
                annotations::CASCADE_DELETE,
                annotations::FORCE_DELETE,
            ]
        );
        // `tracking-id` is not hashed for Applications: it is stamped on managed child
        // resources, and hashing it here would reconcile on every re-stamp.
        assert!(!TRACKED_ANNOTATIONS.contains(&annotations::TRACKING_ID));
    }

    #[test]
    fn kube_predicate_exposes_the_composite_hash() {
        let app = application();
        let expected = composite_hash(&app.metadata);
        assert_eq!(predicate().hash_property(&app), Some(expected));
        assert_eq!(ApplicationPredicate.hash_property(&app), Some(expected));
    }

    /// **`T19.3`:** the `ApplicationSet` change tracker suppresses the pass's own `/status` patch —
    /// otherwise the loop re-triggers itself on every status write — while still reacting to a
    /// spec bump, the finalizer we add, the deletion we must act on, and a refresh annotation.
    #[test]
    fn the_applicationset_tracker_ignores_status_and_reacts_to_everything_that_matters() {
        let spec: ferriscd_crd::ApplicationSetSpec = serde_saphyr::from_str(
            r#"
generators:
  - list:
      elements:
        - env: prod
template:
  metadata:
    name: api-{{env}}
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
    destination:
      cluster: in-cluster
      namespace: payments
"#,
        )
        .expect("the fixture spec must parse");
        let appset = ferriscd_crd::ApplicationSet::new("fleet", spec);
        let mut tracker = ApplicationSetChangeTracker::new();
        assert!(
            tracker.observe(&appset),
            "the first observation always runs"
        );

        // A status-only write (what every pass does) must NOT re-trigger the loop.
        let mut status_only = appset.clone();
        status_only.status = Some(ferriscd_crd::ApplicationSetStatus {
            observed_generation: Some(1),
            generated_count: 2,
            ..ferriscd_crd::ApplicationSetStatus::default()
        });
        status_only.metadata.resource_version = Some("999".to_owned());
        status_only
            .metadata
            .labels
            .get_or_insert_with(std::collections::BTreeMap::new)
            .insert("team".to_owned(), "payments".to_owned());
        assert!(
            !tracker.observe(&status_only),
            "a /status patch, a label edit, or a resourceVersion bump must not reconcile"
        );
        assert!(
            !tracker.observe(&status_only),
            "and it must stay suppressed on every later identical observation"
        );

        // Every field the loop reads from the object must trigger a pass.
        let mut spec_changed = appset.clone();
        spec_changed.metadata.generation = Some(2);
        assert!(
            tracker.observe(&spec_changed),
            "a spec change must reconcile"
        );

        let mut finalized = appset.clone();
        finalized
            .metadata
            .finalizers
            .get_or_insert_with(Vec::new)
            .push(ferriscd_crd::APPLICATIONSET_FINALIZER.to_owned());
        assert!(
            tracker.observe(&finalized),
            "our finalizer is the deletion hook and must reconcile"
        );

        let mut deleted = appset.clone();
        deleted.metadata.deletion_timestamp = Some(timestamp("2026-11-28T00:00:00Z"));
        assert!(tracker.observe(&deleted), "a deletion must reconcile");

        let mut refreshed = appset.clone();
        refreshed
            .metadata
            .annotations
            .get_or_insert_with(std::collections::BTreeMap::new)
            .insert(annotations::REFRESH.to_owned(), "now".to_owned());
        assert!(
            tracker.observe(&refreshed),
            "a ferriscd.io/refresh annotation must force a pass"
        );

        // A deletion forgets the object, so a re-created `ApplicationSet` of the same name with the
        // same generation always reconciles again.
        tracker.forget("fleet");
        assert!(
            tracker.observe(&appset),
            "a re-created object must reconcile even with an unchanged hash"
        );
    }

    #[test]
    fn distinct_objects_are_tracked_separately() {
        let mut first = application();
        first.metadata.name = Some("first".to_owned());
        let mut second = application();
        second.metadata.name = Some("second".to_owned());

        let mut tracker = PredicateTracker::new();
        assert!(tracker.observe(&first));
        assert!(
            tracker.observe(&second),
            "a different object must reconcile even with an identical hash"
        );
        assert!(!tracker.observe(&second));
    }
}

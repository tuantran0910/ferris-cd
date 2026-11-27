//! Recovering from the two Server-Side Apply pain points that block real teams: immutable
//! fields and brownfield field-manager ownership (T08.4).
//!
//! # 1. Immutable fields (`422 Invalid`)
//!
//! `Job`, `StatefulSet` (most of its `spec`), and `immutable: true` `ConfigMap`/`Secret` objects
//! cannot be patched. Kubernetes answers `422 Invalid` with a message that contains
//! "field is immutable" (or "… are forbidden" for `StatefulSet`).
//!
//! The **safe** default is to fail with an actionable message: a controller that silently deletes
//! and recreates a `StatefulSet` (`volumeClaimTemplates` included) because somebody edited a
//! template annotation is far worse than a red `Ready=False`. The operator opts in per resource:
//!
//! ```yaml
//! metadata:
//!   annotations:
//!     ferriscd.io/sync-options: Replace=true
//! ```
//!
//! With the opt-in the planner emits [`SyncAction::Replace`](ferriscd_engine::sync::SyncAction)
//! and [`ReplaceRecovery`] performs the *only* race-free sequence:
//!
//! ```text
//! DELETE  ->  poll GET until 404 NotFound  ->  SSA apply
//! ```
//!
//! The poll is the whole point (finding M3): an asynchronous `Delete` leaves the object present
//! for a while (finalizers!), and re-applying immediately answers `409 AlreadyExists`. The wait is
//! bounded; when it expires the pass returns a **retryable** error instead of hammering the API
//! server, and the next reconcile simply re-reads live state and continues.
//!
//! # 2. Brownfield takeover (`409 Conflict`)
//!
//! An object created by `kubectl apply` (manager `kubectl-client-side-apply`) or `helm` owns its
//! fields, so an SSA apply that touches them answers `409 Conflict` naming the managers. FerrisCD
//! only takes those fields over when the operator lists **every** conflicting manager:
//!
//! ```yaml
//! syncPolicy:
//!   syncOptions:
//!     takeoverFieldManagers: ["kubectl-client-side-apply"]
//! ```
//!
//! The retry is then a single, logged (`Normal`) forced apply of that one resource. If any
//! conflicting manager is *not* listed — `kube-controller-manager`, an HPA, another operator — the
//! apply is not forced at all: an HPA's `spec.replicas` must never be clobbered (trap T5), and the
//! failure names the manager so the operator can decide.

use std::time::Duration;

use ferriscd_engine::inventory::Ownership;
use ferriscd_engine::manifest::{DesiredResource, ResourceKey};
use kube::api::ApiResource;
use kube::core::Status;
use tracing::info;

use crate::discovery::DiscoveryCache;
use crate::dry_run::parse_conflict_status;
use crate::live_state::{ClusterStateReader, LiveState, TrackingOwner};
use crate::reconcile::ReconcileError;
use crate::sync::{Applier, ApplyRequest, DeleteRequest};

/// The per-resource annotation that opts into delete-and-recreate.
pub const REPLACE_ANNOTATION: &str = "ferriscd.io/sync-options";
/// The exact annotation fragment the failure message suggests.
pub const REPLACE_HINT: &str = "`ferriscd.io/sync-options: Replace=true`";
/// The `syncPolicy.syncOptions` field that opts into field-manager takeover.
pub const TAKEOVER_FIELD: &str = "syncOptions.takeoverFieldManagers";

/// How long [`ReplaceRecovery`] waits for a deleted object to disappear.
pub const DEFAULT_REPLACE_TIMEOUT: Duration = Duration::from_secs(30);
/// Poll interval used while waiting for the `404`.
pub const DEFAULT_REPLACE_INTERVAL: Duration = Duration::from_millis(500);

/// Message fragments that identify an immutable-field rejection.
///
/// Documented, not guessed: `Job`/`StatefulSet` reject `spec` edits with "field is immutable" /
/// "updates to … are forbidden", and an `immutable: true` `ConfigMap`/`Secret` reports "field is
/// immutable when `immutable` is set". Matching is case-insensitive and only ever applied to a
/// `422`, so it can never misclassify a `403` or a transient failure.
pub const IMMUTABLE_MESSAGE_MARKERS: [&str; 3] =
    ["field is immutable", "is immutable", "are forbidden"];

/// What to do about a failed Server-Side Apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// Nothing special: the original API error stands (transport, `403`, `5xx`, …).
    Propagate,
    /// Every conflicting field manager is opted in: retry that one resource with `force: true`.
    Takeover {
        /// The managers that will be taken over (sorted, de-duplicated).
        managers: Vec<String>,
    },
    /// Refuse with an actionable, terminal message (immutable field, unlisted manager, …).
    Fail {
        /// Actionable, secret-free explanation.
        message: String,
    },
}

/// Classifies a failed apply.
///
/// `takeover_field_managers` is `syncPolicy.syncOptions.takeoverFieldManagers`.
#[must_use]
pub fn classify_apply_failure(error: &kube::Error, takeover_field_managers: &[String]) -> Recovery {
    let kube::Error::Api(status) = error else {
        return Recovery::Propagate;
    };

    if is_immutable_field_error(status) {
        // Put the actionable `Replace=true` guidance before the server's message so the 200-char
        // `/status` condition cap (`reconcile::bounded`) never slices off the operator hint.
        return Recovery::Fail {
            message: format!(
                "immutable field cannot be patched in place; annotate with {REPLACE_HINT} to \
                 delete and recreate ({})",
                quoted_server_message(status)
            ),
        };
    }

    if status.code != 409 {
        return Recovery::Propagate;
    }

    let managers = conflicting_managers(status);
    if managers.is_empty() {
        // A `409` whose `details.causes` and message name nobody: never force blindly.
        return Recovery::Fail {
            message: format!(
                "server-side apply was rejected with a field-ownership conflict that does not name \
                 its manager ({}); resolve it by hand or list the manager in {TAKEOVER_FIELD}",
                quoted_server_message(status)
            ),
        };
    }

    let unlisted: Vec<&str> = managers
        .iter()
        .filter(|manager| {
            !takeover_field_managers
                .iter()
                .any(|allowed| allowed == *manager)
        })
        .map(String::as_str)
        .collect();
    if unlisted.is_empty() {
        return Recovery::Takeover { managers };
    }

    Recovery::Fail {
        message: format!(
            "fields are owned by field manager(s) {} which are not listed in {TAKEOVER_FIELD}; \
             FerrisCD never forces those (an HPA or another controller owns them). Add the \
             manager(s) to {TAKEOVER_FIELD} to adopt the object",
            unlisted.join(", ")
        ),
    }
}

/// Returns whether `status` is Kubernetes rejecting an immutable field.
#[must_use]
pub fn is_immutable_field_error(status: &Status) -> bool {
    if status.code != 422 {
        return false;
    }
    let message = status.message.to_ascii_lowercase();
    IMMUTABLE_MESSAGE_MARKERS
        .iter()
        .any(|marker| message.contains(marker))
}

/// The distinct field managers named by a `409 Conflict`, sorted.
#[must_use]
pub fn conflicting_managers(status: &Status) -> Vec<String> {
    let mut managers: Vec<String> = parse_conflict_status(status)
        .into_iter()
        .filter_map(|conflict| conflict.manager)
        .collect();
    managers.sort();
    managers.dedup();
    managers
}

/// Returns the server's message, quoted safely for an error that reaches `/status`.
///
/// A `422`/`400` can quote the value it rejected (a `Secret` payload), and an error message ends up
/// in `Application.status` (readable by anyone with `get` on the CR), so the quote is redacted and
/// length-bounded first (trap T4, finding on Secret safety).
fn quoted_server_message(status: &Status) -> String {
    crate::reconcile::bounded(status.message.trim())
}

/// Bounded wait for a deleted object to disappear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplacePolicy {
    /// Total time the pruner/executor waits for the `404`.
    pub timeout: Duration,
    /// Delay between two `GET`s. `Duration::ZERO` polls without sleeping (tests).
    pub interval: Duration,
}

impl Default for ReplacePolicy {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_REPLACE_TIMEOUT,
            interval: DEFAULT_REPLACE_INTERVAL,
        }
    }
}

/// Delete → wait for `404` → re-apply, the only race-free way to replace an object.
pub struct ReplaceRecovery<'a> {
    applier: &'a dyn Applier,
    reader: &'a ClusterStateReader,
    discovery: &'a DiscoveryCache,
    owner: &'a TrackingOwner,
    policy: ReplacePolicy,
}

impl std::fmt::Debug for ReplaceRecovery<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplaceRecovery")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<'a> ReplaceRecovery<'a> {
    /// Builds a recovery for one pass.
    #[must_use]
    pub fn new(
        applier: &'a dyn Applier,
        reader: &'a ClusterStateReader,
        discovery: &'a DiscoveryCache,
        owner: &'a TrackingOwner,
        policy: ReplacePolicy,
    ) -> Self {
        Self {
            applier,
            reader,
            discovery,
            owner,
            policy,
        }
    }

    /// Replaces `resource` in `namespace`, returning the freshly applied object.
    ///
    /// The delete is guarded by the same re-read that guards a prune (finding H2): the live object
    /// is re-fetched and its `ferriscd.io/tracking-id` re-verified immediately before the delete,
    /// so a `Replace` can never delete an object another `Application` took over between the
    /// pass-level read and this call.
    ///
    /// # Errors
    ///
    /// * the delete or the re-apply failed (classified like any other API failure),
    /// * the object is owned by somebody else (terminal: never delete it),
    /// * the object was still present when the bounded wait expired:
    ///   [`ReconcileError::SyncRetry`] — retryable, because the next pass re-reads live state and
    ///   continues instead of re-applying into an existing object (finding M3).
    pub async fn replace(
        &self,
        key: &ResourceKey,
        resource: &DesiredResource,
        api_resource: &ApiResource,
        namespace: Option<&str>,
    ) -> Result<kube::api::DynamicObject, ReconcileError> {
        if self
            .delete_verified(key, resource, api_resource, namespace)
            .await?
        {
            self.await_gone(key, resource).await?;
        }

        // Delete-recreate race closed (or the name was already free): the apply cannot answer
        // `409 AlreadyExists` (finding M3).
        self.applier
            .apply(ApplyRequest {
                resource,
                api_resource,
                namespace,
                force: false,
            })
            .await
    }

    /// Re-reads the live object and deletes it only when it is verifiably ours.
    ///
    /// Returns whether a delete was issued: a confirmed absence (`404`/`410`, or a kind the
    /// cluster no longer serves) needs none, the object is already free for the re-apply.
    async fn delete_verified(
        &self,
        key: &ResourceKey,
        resource: &DesiredResource,
        api_resource: &ApiResource,
        namespace: Option<&str>,
    ) -> Result<bool, ReconcileError> {
        match self.recheck(key, resource).await? {
            LiveState::Missing | LiveState::OrphanGvkGone => Ok(false),
            LiveState::Present(_, Ownership::OwnedBySelf) => {
                self.applier
                    .delete(DeleteRequest {
                        key,
                        api_resource,
                        namespace,
                    })
                    .await?;
                Ok(true)
            }
            LiveState::Present(_, Ownership::OwnedByForeign(owner)) => {
                Err(ReconcileError::Invalid {
                    message: format!(
                        "refusing to replace {}: its ferriscd.io/tracking-id belongs to another \
                     Application ({owner}). A Replace deletes and recreates, so it is only ever \
                     allowed on an object FerrisCD owns",
                        key.canonical()
                    ),
                })
            }
            LiveState::Present(_, Ownership::Unmanaged) => Err(ReconcileError::Invalid {
                message: format!(
                    "refusing to replace {}: the live object carries no ferriscd.io/tracking-id, \
                     so FerrisCD cannot prove it created it",
                    key.canonical()
                ),
            }),
            LiveState::DeferredPendingCrd | LiveState::DeferredPendingNamespace => {
                Err(ReconcileError::SyncRetry {
                    message: format!(
                        "{} cannot be replaced yet: its live state is still deferred on a \
                         CustomResourceDefinition or namespace",
                        key.canonical()
                    ),
                })
            }
        }
    }

    /// Re-reads and re-classifies one key.
    async fn recheck(
        &self,
        key: &ResourceKey,
        resource: &DesiredResource,
    ) -> Result<LiveState, ReconcileError> {
        Ok(self
            .reader
            .recheck(
                key,
                Some(resource.gvk.version.as_str()),
                self.discovery,
                &[],
                &[],
                self.owner,
            )
            .await?)
    }

    /// Polls until the object is gone (or the bounded wait expires).
    async fn await_gone(
        &self,
        key: &ResourceKey,
        resource: &DesiredResource,
    ) -> Result<(), ReconcileError> {
        let deadline = std::time::Instant::now() + self.policy.timeout;
        loop {
            if self.recheck(key, resource).await?.is_gone() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(ReconcileError::SyncRetry {
                    message: format!(
                        "{} was deleted but is still present after {:?}; retrying on the next \
                         reconcile instead of re-applying into an existing object",
                        key.canonical(),
                        self.policy.timeout
                    ),
                });
            }
            if !self.policy.interval.is_zero() {
                tokio::time::sleep(self.policy.interval).await;
            }
        }
    }
}

/// Logs a successful takeover as a `Normal`-style event (a structured log line with a stable
/// `reason`, since this phase does not emit Kubernetes Events yet).
pub fn log_takeover(key: &ResourceKey, managers: &[String]) {
    info!(
        resource = %key.canonical(),
        managers = ?managers,
        reason = "FieldManagerTakeover",
        event_type = "Normal",
        "taking over field ownership for one resource: every conflicting manager is listed in \
         {TAKEOVER_FIELD}"
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use ferriscd_engine::manifest::GroupVersionKind;
    use kube::api::ApiResource;
    use kube::core::GroupVersionKind as KubeGvk;
    use kube::discovery::{ApiCapabilities, Scope};
    use serde_json::json;

    use futures::future::BoxFuture;

    use super::*;
    use crate::discovery::{DiscoveryFuture, DiscoverySnapshot, DiscoverySource};
    use crate::live_state::{FetchTarget, LiveFuture, LiveObjectSource};
    use crate::sync::DeleteOutcome;

    const NAMESPACE: &str = "payments";

    fn status(value: serde_json::Value) -> Status {
        serde_json::from_value(value).expect("valid kube Status")
    }

    fn conflict_status(message: &str, causes: serde_json::Value) -> Status {
        status(json!({
            "status": "Failure",
            "message": message,
            "reason": "Conflict",
            "details": { "causes": causes },
            "code": 409,
        }))
    }

    fn api_error(value: serde_json::Value) -> kube::Error {
        kube::Error::Api(status(value).boxed())
    }

    // ------------------------------------------------------------------
    // Structuring the failures into actionable decisions
    // ------------------------------------------------------------------

    /// A `409` whose conflicting managers are all opted in means "take them over".
    #[test]
    fn a_fully_opted_in_conflict_is_a_takeover() {
        let error = api_error(json!({
            "status": "Failure",
            "message": "Apply failed with 1 conflict: conflict with \"kubectl-client-side-apply\": .data",
            "reason": "Conflict",
            "details": { "causes": [ {
                "reason": "FieldManagerConflict",
                "message": "conflict with \"kubectl-client-side-apply\"",
                "field": "data",
            } ] },
            "code": 409,
        }));

        assert_eq!(
            classify_apply_failure(&error, &["kubectl-client-side-apply".to_owned()]),
            Recovery::Takeover {
                managers: vec!["kubectl-client-side-apply".to_owned()]
            }
        );

        // Multiple managers, all listed, in any order.
        let two = conflict_status(
            "Apply failed with 2 conflicts",
            json!([
                { "reason": "FieldManagerConflict", "message": "conflict with \"helm\"", "field": "data" },
                { "reason": "FieldManagerConflict", "message": "conflict with \"kubectl-client-side-apply\"", "field": "metadata.labels" },
            ]),
        );
        assert_eq!(
            classify_apply_failure(
                &kube::Error::Api(two.boxed()),
                &["kubectl-client-side-apply".to_owned(), "helm".to_owned()]
            ),
            Recovery::Takeover {
                managers: vec!["helm".to_owned(), "kubectl-client-side-apply".to_owned()]
            }
        );
    }

    /// **Trap guard (T5/H6):** one unlisted manager (an HPA, `kube-controller-manager`) blocks the
    /// takeover, and the failure names it.
    #[test]
    fn an_unlisted_conflicting_manager_is_never_forced() {
        let error = kube::Error::Api(
            conflict_status(
                "Apply failed with 2 conflicts",
                json!([
                    { "reason": "FieldManagerConflict", "message": "conflict with \"kubectl-client-side-apply\"", "field": "data" },
                    { "reason": "FieldManagerConflict", "message": "conflict with \"horizontal-pod-autoscaler\"", "field": "spec.replicas" },
                ]),
            )
            .boxed(),
        );

        let Recovery::Fail { message } =
            classify_apply_failure(&error, &["kubectl-client-side-apply".to_owned()])
        else {
            panic!("an unlisted manager must never be forced");
        };
        assert!(
            message.contains("horizontal-pod-autoscaler"),
            "the unlisted manager must be named: {message}"
        );
        assert!(
            !message.contains("kubectl-client-side-apply,"),
            "a listed manager is not the problem: {message}"
        );
        assert!(message.contains(TAKEOVER_FIELD), "{message}");
    }

    #[test]
    fn a_conflict_without_a_named_manager_is_refused() {
        let error = api_error(json!({
            "status": "Failure",
            "message": "the server rejected the request",
            "reason": "Conflict",
            "code": 409,
        }));
        let Recovery::Fail { message } = classify_apply_failure(&error, &[]) else {
            panic!("a nameless conflict must not be forced");
        };
        assert!(message.contains(TAKEOVER_FIELD), "{message}");
    }

    /// **Trap guard (T7):** an immutable field fails cleanly and tells the operator exactly which
    /// annotation opts in.
    #[test]
    fn an_immutable_field_failure_suggests_replace() {
        for message in [
            "Job.batch \"migrate\" is invalid: spec.template: Invalid value: ...: field is immutable",
            "ConfigMap \"settings\" is invalid: data: Invalid value: ...: field is immutable when `immutable` is set",
            "StatefulSet.apps \"db\" is invalid: spec: Forbidden: updates to statefulset spec for fields other than 'replicas' are forbidden",
        ] {
            let error = api_error(json!({
                "status": "Failure",
                "message": message,
                "reason": "Invalid",
                "code": 422,
            }));
            let Recovery::Fail {
                message: explanation,
            } = classify_apply_failure(&error, &[])
            else {
                panic!("an immutable field must fail cleanly: {message}");
            };
            assert!(
                explanation.contains("Replace=true"),
                "the message must name the opt-in: {explanation}"
            );
            assert!(
                explanation.contains("ferriscd.io/sync-options"),
                "{explanation}"
            );
        }
    }

    #[test]
    fn unrelated_api_failures_are_propagated_untouched() {
        // A 422 that is *not* about immutability (an ordinary validation error).
        let validation = api_error(json!({
            "status": "Failure",
            "message": "ConfigMap \"x\" is invalid: data[foo]: Invalid value: must be a string",
            "reason": "Invalid",
            "code": 422,
        }));
        assert_eq!(
            classify_apply_failure(&validation, &[]),
            Recovery::Propagate
        );

        for code in [403, 404, 500, 503] {
            let error = api_error(json!({
                "status": "Failure",
                "message": "nope",
                "code": code,
            }));
            assert_eq!(
                classify_apply_failure(&error, &["anything".to_owned()]),
                Recovery::Propagate,
                "code {code} needs no recovery"
            );
        }

        // A transport-level error is never a recovery case either.
        assert_eq!(
            classify_apply_failure(&kube::Error::Service("boom".into()), &[]),
            Recovery::Propagate
        );
    }

    #[test]
    fn immutable_detection_requires_a_422() {
        let conflict_immutable = status(json!({
            "status": "Failure",
            "message": "field is immutable",
            "code": 409,
        }));
        assert!(
            !is_immutable_field_error(&conflict_immutable),
            "only a 422 is an immutable-field rejection"
        );
        let invalid = status(json!({
            "status": "Failure",
            "message": "FIELD IS IMMUTABLE",
            "code": 422,
        }));
        assert!(
            is_immutable_field_error(&invalid),
            "matching is case-insensitive"
        );
        assert_eq!(
            conflicting_managers(&conflict_status(
                "conflict",
                json!([
                    { "reason": "FieldManagerConflict", "message": "conflict with \"b\"", "field": "x" },
                    { "reason": "FieldManagerConflict", "message": "conflict with \"a\"", "field": "y" },
                    { "reason": "FieldManagerConflict", "message": "conflict with \"b\"", "field": "z" },
                ])
            )),
            vec!["a".to_owned(), "b".to_owned()],
            "managers are sorted and de-duplicated"
        );
    }

    // ------------------------------------------------------------------
    // Replace: delete -> wait for 404 -> apply
    // ------------------------------------------------------------------

    /// One recorded mutation, so ordering (`delete` before `apply`) is assertable.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        Delete(String),
        Apply { key: String, force: bool },
    }

    #[derive(Default)]
    struct FakeCluster {
        /// Objects served by GET, keyed by canonical GKNN.
        objects: StdMutex<BTreeMap<String, kube::api::DynamicObject>>,
        calls: StdMutex<Vec<Call>>,
        /// Deletes that are accepted but do not remove the object (a finalizer holds it).
        held: StdMutex<Vec<String>>,
        fail_apply: StdMutex<bool>,
    }

    impl FakeCluster {
        fn with_object(self, object: kube::api::DynamicObject) -> Self {
            self.objects.lock().unwrap().insert(gknn(&object), object);
            self
        }

        /// The next delete of this key is accepted but leaves the object present.
        fn held(self, gknn: &str) -> Self {
            self.held.lock().unwrap().push(gknn.to_owned());
            self
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
    }

    /// Canonical GKNN of a live object.
    fn gknn(object: &kube::api::DynamicObject) -> String {
        let api_version = object
            .types
            .as_ref()
            .map(|types| types.api_version.clone())
            .unwrap_or_default();
        let kind = object
            .types
            .as_ref()
            .map(|types| types.kind.clone())
            .unwrap_or_default();
        let group = api_version
            .split_once('/')
            .map(|(group, _)| group)
            .unwrap_or("");
        format!(
            "{group}/{kind}/{}/{}",
            object.metadata.namespace.as_deref().unwrap_or_default(),
            object.metadata.name.as_deref().unwrap_or_default()
        )
    }

    /// A live `Job` carrying `tracking_id`.
    fn live_job(tracking_id: &str) -> kube::api::DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "migrate",
                "namespace": NAMESPACE,
                "annotations": { ferriscd_crd::annotations::TRACKING_ID: tracking_id },
            },
        }))
        .expect("object")
    }

    impl LiveObjectSource for FakeCluster {
        fn get<'a>(
            &'a self,
            target: FetchTarget<'a>,
        ) -> LiveFuture<'a, Option<kube::api::DynamicObject>> {
            let wanted = format!(
                "{}/{}/{}/{}",
                target.api_resource.group,
                target.api_resource.kind,
                target.namespace.unwrap_or_default(),
                target.name
            );
            let object = self.objects.lock().unwrap().get(&wanted).cloned();
            Box::pin(async move { Ok(object) })
        }

        fn namespace_exists<'a>(&'a self, _namespace: &'a str) -> LiveFuture<'a, bool> {
            Box::pin(async { Ok(true) })
        }
    }

    impl Applier for FakeCluster {
        fn apply<'a>(
            &'a self,
            request: ApplyRequest<'a>,
        ) -> BoxFuture<'a, Result<kube::api::DynamicObject, ReconcileError>> {
            let key = request.resource.key.canonical();
            let force = request.force;
            let body = request.resource.object.clone();
            Box::pin(async move {
                if *self.fail_apply.lock().unwrap() {
                    return Err(ReconcileError::Api(kube::Error::Api(
                        Status::failure("still immutable", "Invalid")
                            .with_code(422)
                            .boxed(),
                    )));
                }
                self.calls.lock().unwrap().push(Call::Apply { key, force });
                Ok(body)
            })
        }

        fn delete<'a>(
            &'a self,
            request: DeleteRequest<'a>,
        ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>> {
            let key = request.key.canonical();
            Box::pin(async move {
                self.calls.lock().unwrap().push(Call::Delete(key.clone()));
                if !self.held.lock().unwrap().iter().any(|held| held == &key) {
                    self.objects.lock().unwrap().remove(&key);
                }
                Ok(DeleteOutcome::Deleted)
            })
        }
    }

    /// Discovery source serving a fixed snapshot.
    struct FakeDiscovery {
        snapshot: StdMutex<DiscoverySnapshot>,
    }

    impl FakeDiscovery {
        fn new() -> Self {
            let mut snapshot = DiscoverySnapshot::new("v1.35.0");
            for (group, kind, scope) in [
                ("", "ConfigMap", Scope::Namespaced),
                ("batch", "Job", Scope::Namespaced),
                ("", "Namespace", Scope::Cluster),
            ] {
                let mut resource = ApiResource::from_gvk(&KubeGvk::gvk(group, "v1", kind));
                resource.plural = format!("{}s", kind.to_ascii_lowercase());
                snapshot = snapshot.with_resource(
                    resource,
                    ApiCapabilities {
                        scope,
                        subresources: Vec::new(),
                        operations: vec!["get".to_owned(), "patch".to_owned()],
                    },
                );
            }
            Self {
                snapshot: StdMutex::new(snapshot),
            }
        }
    }

    impl DiscoverySource for FakeDiscovery {
        fn fetch(&self) -> DiscoveryFuture<'_> {
            Box::pin(async move { Ok(self.snapshot.lock().unwrap().clone()) })
        }
    }

    fn resource(kind: &str, group: &str, name: &str) -> DesiredResource {
        let api_version = if group.is_empty() {
            "v1".to_owned()
        } else {
            format!("{group}/v1")
        };
        DesiredResource {
            key: ResourceKey::new(group, kind, Some(NAMESPACE.to_owned()), name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("gvk"),
            object: serde_json::from_value(json!({
                "apiVersion": api_version,
                "kind": kind,
                "metadata": { "name": name, "namespace": NAMESPACE },
            }))
            .expect("object"),
            source_file: "fixture.yaml".to_owned(),
        }
    }

    fn api_resource(kind: &str, group: &str) -> ApiResource {
        let mut resource = ApiResource::from_gvk(&KubeGvk::gvk(group, "v1", kind));
        resource.plural = format!("{}s", kind.to_ascii_lowercase());
        resource
    }

    fn recovery<'a>(
        cluster: &'a FakeCluster,
        reader: &'a ClusterStateReader,
        cache: &'a DiscoveryCache,
        owner: &'a TrackingOwner,
        policy: ReplacePolicy,
    ) -> ReplaceRecovery<'a> {
        ReplaceRecovery::new(cluster, reader, cache, owner, policy)
    }

    /// **Verification:** the sequence is `re-verify ownership` → `delete` → wait for `404` →
    /// `apply`, never a bare re-apply into the still-present object (findings H2/M3).
    #[tokio::test]
    async fn replace_deletes_waits_for_the_404_then_applies_once() {
        let cluster = FakeCluster::default().with_object(live_job(
            "ferriscd-system/payments:batch/Job:payments/migrate",
        ));
        let discovery = Arc::new(FakeDiscovery::new());
        let cache = DiscoveryCache::with_source(discovery, Duration::from_secs(3600));
        let bucket = Arc::new(cluster);
        let reader = ClusterStateReader::new(bucket.clone());
        let owner = TrackingOwner::new("ferriscd-system", "payments");
        let job = resource("Job", "batch", "migrate");

        // The fake delete really removes the object, so the `404` wait completes without a sleep.
        let applied = recovery(
            Arc::as_ref(&bucket),
            &reader,
            &cache,
            &owner,
            ReplacePolicy {
                timeout: Duration::ZERO,
                interval: Duration::ZERO,
            },
        )
        .replace(
            &job.key,
            &job,
            &api_resource("Job", "batch"),
            Some(NAMESPACE),
        )
        .await
        .expect("replace must succeed");

        assert_eq!(applied.metadata.name.as_deref(), Some("migrate"));
        assert_eq!(
            bucket.calls(),
            vec![
                Call::Delete("batch/Job/payments/migrate".to_owned()),
                Call::Apply {
                    key: "batch/Job/payments/migrate".to_owned(),
                    force: false,
                },
            ],
            "delete first, then a non-forced apply"
        );
    }

    /// **Trap guard (H2):** a `Replace` re-verifies `tracking-id` on the freshly read object and
    /// refuses to delete an object another `Application` took over.
    #[tokio::test]
    async fn replace_never_deletes_another_applications_object() {
        for (live, needle) in [
            (
                live_job("ferriscd-system/other:batch/Job:payments/migrate"),
                "another Application",
            ),
            (
                // No tracking-id at all: created outside FerrisCD.
                serde_json::from_value::<kube::api::DynamicObject>(json!({
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "metadata": { "name": "migrate", "namespace": NAMESPACE },
                }))
                .expect("object"),
                "no ferriscd.io/tracking-id",
            ),
        ] {
            let bucket = Arc::new(FakeCluster::default().with_object(live));
            let discovery = Arc::new(FakeDiscovery::new());
            let cache = DiscoveryCache::with_source(discovery, Duration::from_secs(3600));
            let reader = ClusterStateReader::new(bucket.clone());
            let owner = TrackingOwner::new("ferriscd-system", "payments");
            let job = resource("Job", "batch", "migrate");

            let err = recovery(
                Arc::as_ref(&bucket),
                &reader,
                &cache,
                &owner,
                ReplacePolicy {
                    timeout: Duration::ZERO,
                    interval: Duration::ZERO,
                },
            )
            .replace(
                &job.key,
                &job,
                &api_resource("Job", "batch"),
                Some(NAMESPACE),
            )
            .await
            .expect_err("an object FerrisCD does not own must never be replaced");

            assert_eq!(err.failure_class(), crate::FailureClass::Terminal, "{err}");
            assert!(err.to_string().contains(needle), "{err}");
            assert!(
                bucket.calls().is_empty(),
                "no delete and no apply may be issued: {:?}",
                bucket.calls()
            );
        }
    }

    /// A `Replace` of an object that is already gone applies without a pointless delete.
    #[tokio::test]
    async fn replace_of_an_absent_object_applies_without_a_delete() {
        let bucket = Arc::new(FakeCluster::default());
        let discovery = Arc::new(FakeDiscovery::new());
        let cache = DiscoveryCache::with_source(discovery, Duration::from_secs(3600));
        let reader = ClusterStateReader::new(bucket.clone());
        let owner = TrackingOwner::new("ferriscd-system", "payments");
        let job = resource("Job", "batch", "migrate");

        recovery(
            Arc::as_ref(&bucket),
            &reader,
            &cache,
            &owner,
            ReplacePolicy {
                timeout: Duration::ZERO,
                interval: Duration::ZERO,
            },
        )
        .replace(
            &job.key,
            &job,
            &api_resource("Job", "batch"),
            Some(NAMESPACE),
        )
        .await
        .expect("a 404 at replace time is not an error");

        assert_eq!(
            bucket.calls(),
            vec![Call::Apply {
                key: "batch/Job/payments/migrate".to_owned(),
                force: false,
            }],
            "a confirmed absence needs no delete"
        );
    }

    /// The bounded wait must not loop forever when the object does not disappear.
    #[tokio::test]
    async fn replace_requeues_when_the_object_never_disappears() {
        // A finalizer holds the object: the delete is accepted but the name stays taken.
        let bucket = Arc::new(
            FakeCluster::default()
                .with_object(live_job(
                    "ferriscd-system/payments:batch/Job:payments/migrate",
                ))
                .held("batch/Job/payments/migrate"),
        );
        let discovery = Arc::new(FakeDiscovery::new());
        let cache = DiscoveryCache::with_source(discovery, Duration::from_secs(3600));
        let reader = ClusterStateReader::new(bucket.clone());
        let owner = TrackingOwner::new("ferriscd-system", "payments");
        let job = resource("Job", "batch", "migrate");

        let err = recovery(
            Arc::as_ref(&bucket),
            &reader,
            &cache,
            &owner,
            ReplacePolicy {
                timeout: Duration::ZERO,
                interval: Duration::ZERO,
            },
        )
        .replace(
            &job.key,
            &job,
            &api_resource("Job", "batch"),
            Some(NAMESPACE),
        )
        .await
        .expect_err("an unfinished delete must requeue");

        assert!(
            matches!(err, ReconcileError::SyncRetry { .. }),
            "the pass must requeue rather than fail terminally: {err}"
        );
        assert_eq!(err.failure_class(), crate::FailureClass::Retryable);
        assert_eq!(
            bucket.calls(),
            vec![Call::Delete("batch/Job/payments/migrate".to_owned())],
            "no apply may be attempted while the name is still taken"
        );
    }

    #[tokio::test]
    async fn replace_propagates_an_apply_failure() {
        let cluster = FakeCluster::default();
        *cluster.fail_apply.lock().unwrap() = true;
        let discovery = Arc::new(FakeDiscovery::new());
        let cache = DiscoveryCache::with_source(discovery, Duration::from_secs(3600));
        let bucket = Arc::new(cluster);
        let reader = ClusterStateReader::new(bucket.clone());
        let owner = TrackingOwner::new("ferriscd-system", "payments");
        let job = resource("Job", "batch", "migrate");

        let err = recovery(
            Arc::as_ref(&bucket),
            &reader,
            &cache,
            &owner,
            ReplacePolicy {
                timeout: Duration::ZERO,
                interval: Duration::ZERO,
            },
        )
        .replace(
            &job.key,
            &job,
            &api_resource("Job", "batch"),
            Some(NAMESPACE),
        )
        .await
        .expect_err("a failing re-apply must surface");

        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Terminal,
            "a 422 on the re-apply is still terminal: {err}"
        );
    }

    #[test]
    fn gone_classification_matches_the_live_state_contract() {
        assert!(LiveState::Missing.is_gone());
        assert!(LiveState::OrphanGvkGone.is_gone());
        assert!(!LiveState::DeferredPendingCrd.is_gone());

        let key = ResourceKey::new("", "ConfigMap", Some(NAMESPACE.to_owned()), "x");
        // The takeover log helper must be callable without a subscriber.
        log_takeover(&key, &["kubectl-client-side-apply".to_owned()]);
        assert_eq!(REPLACE_ANNOTATION, "ferriscd.io/sync-options");
        assert!(REPLACE_HINT.contains("Replace=true"));
    }

    /// **Secret safety (trap T4):** a server message that quotes a rejected `Secret` value never
    /// reaches the actionable failure verbatim.
    #[test]
    fn a_quoted_secret_payload_is_redacted_from_the_failure_message() {
        let payload = "c3VwZXItc2VjcmV0LXZhbHVlLXdpdGgtbG90cy1vZi1ieXRlcw==";
        assert!(payload.chars().count() >= 40);
        let error = api_error(json!({
            "status": "Failure",
            "message": format!(
                "Secret \"db\" is invalid: data[password]: Invalid value: \"{payload}\": \
                 field is immutable"
            ),
            "reason": "Invalid",
            "code": 422,
        }));

        let Recovery::Fail { message } = classify_apply_failure(&error, &[]) else {
            panic!("an immutable field must fail cleanly");
        };
        assert!(!message.contains(payload), "the payload leaked: {message}");
        assert!(
            message.contains("redacted"),
            "the redaction must be visible: {message}"
        );
        assert!(
            message.contains("Replace=true"),
            "the advice must survive the redaction: {message}"
        );
        // The `Ready` condition truncates messages at 200 chars (`reconcile::bounded`); putting
        // the `Replace=true` hint before the server text ensures operators still see the fix.
        let condition = crate::reconcile::bounded(&format!(
            "/ConfigMap/ferriscd-crd-and-cr/immutable: {message}"
        ));
        assert!(
            condition.contains("Replace=true"),
            "the Replace=true hint must survive Ready-condition truncation: {condition}"
        );
    }
}

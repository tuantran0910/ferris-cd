//! The `AppProject` fetch seam (`T12.1`).
//!
//! `AppProject` objects live in the control-plane namespace — never next to the `Application`
//! (ADR-007) — and the sync pipeline needs exactly one of them per reconcile. The engine stays
//! pure, so the fetch is modelled here as a narrow trait: the wired implementation is a single
//! `Api::get` (a scoped read on requeue, never a cluster-wide informer), and hermetic tests
//! substitute a map.
//!
//! Two different "not found"s have to stay distinguishable (finding M3), because the operator's
//! remedy is different for each:
//!
//! | API server answer | Meaning | Raised as |
//! |---|---|---|
//! | `404` + `details{kind: AppProject, name: ...}` | the project is missing | `Ok(None)` → [`PolicyError::ProjectNotFound`](ferriscd_engine::policy::PolicyError::ProjectNotFound) |
//! | `404` with no `details` ("the server could not find the requested resource") | the CRD is not installed | [`ReconcileError::Invalid`] naming `deploy/crds/appprojects.ferriscd.io.yaml` |
//!
//! A missing project permits nothing (fail closed); an uninstalled CRD is reported as the
//! deployment problem it is instead of as a project somebody forgot to create.
//!
//! # `T17.4`: reporting an unusable `syncWindows` entry
//!
//! A malformed window must fail **closed** at runtime, and the operator has to be able to see why
//! with `kubectl describe appproject`. [`ProjectStatusSink`] is that write: the sync pipeline calls
//! it only for a project that declares windows, and [`ApiProjectStatusSink`] only patches when the
//! recorded condition differs, so neither a permanently broken project nor a healthy one turns
//! every reconcile into an API write.
//!
//! The write is bidirectional. Reporting an unusable entry sets `Ready=False/SyncWindowInvalid`;
//! reporting `None` **removes** it, which is what happens as soon as the windows evaluate again
//! (finding H2). Without the removal a `kubectl describe appproject` would keep announcing a change
//! freeze for a typo the operator fixed minutes ago.
//!
//! The `observedGeneration` on that condition is the **project's** own `metadata.generation`,
//! stamped by [`ApiProjectStatusSink::report`] from the object it reads (finding H1): the
//! `Application`'s generation numbers a different object and never belongs here.

use ferriscd_crd::status::CONDITION_READY;
use ferriscd_crd::{
    AppProject, AppProjectStatus, CONTROL_PLANE_NAMESPACE, Condition, ConditionStatus,
};
use ferriscd_engine::policy::InvalidSyncWindow;
use futures::future::BoxFuture;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::Api;
use kube::api::{Patch, PatchParams};

use crate::reconcile::ReconcileError;

/// Reads the `AppProject` an `Application` references.
pub trait ProjectSource: Send + Sync + 'static {
    /// Returns the named project, or `Ok(None)` when it does not exist.
    fn get<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<AppProject>, ReconcileError>>;
}

/// [`ProjectSource`] backed by `Api<AppProject>` in the control-plane namespace.
#[derive(Clone)]
pub struct ApiProjectSource {
    api: Api<AppProject>,
    namespace: String,
}

impl ApiProjectSource {
    /// Builds a source reading projects from `namespace` (the control-plane namespace).
    ///
    /// `namespace` is the controller's `--namespace`, which defaults to `ferriscd-system`: project
    /// lookups follow the control plane, they are never cluster-wide.
    #[must_use]
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            namespace: namespace.to_owned(),
        }
    }

    /// Builds a source reading projects from [`CONTROL_PLANE_NAMESPACE`].
    #[must_use]
    pub fn in_control_plane(client: kube::Client) -> Self {
        Self::new(client, CONTROL_PLANE_NAMESPACE)
    }

    /// The namespace projects are read from.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

impl std::fmt::Debug for ApiProjectSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiProjectSource")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl ProjectSource for ApiProjectSource {
    fn get<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<AppProject>, ReconcileError>> {
        Box::pin(async move {
            match self.api.get(name).await {
                Ok(project) => Ok(Some(project)),
                Err(kube::Error::Api(status)) if status.code == 404 => {
                    // `Api::get` (rather than `get_opt`) is what keeps the two `404`s apart: only
                    // this form of the call carries the `Status` the discrimination needs.
                    if is_missing_project(&status) {
                        Ok(None)
                    } else {
                        Err(crd_not_installed(&self.namespace, name))
                    }
                }
                // Every other failure (auth, transport, apiserver outage) stays an API error so the
                // reconcile retries instead of silently denying.
                Err(err) => Err(ReconcileError::Api(err)),
            }
        })
    }
}

/// Writes the `AppProject` `Ready` condition that describes an unusable `syncWindows` entry.
///
/// A thin seam on purpose: the pipeline owns the *policy* verdict, this owns the one `/status`
/// write, and a hermetic test can observe the write without an API server.
pub trait ProjectStatusSink: Send + Sync + 'static {
    /// Records `condition` on the named project's `/status`, or clears the
    /// `Ready=False/SyncWindowInvalid` condition when `condition` is `None`.
    ///
    /// Both directions live in one method because they answer one question — "does this project's
    /// `spec.syncWindows` evaluate?" — and because the clearing write is what stops
    /// `kubectl describe appproject` from announcing a change freeze the operator already fixed
    /// (finding H2). Clearing is a no-op when the project records no such condition, so a healthy
    /// project costs no write.
    ///
    /// # Errors
    ///
    /// Any API failure of the read or the patch (retryable by classification). The caller logs it:
    /// the sync it belongs to is already denied, so a failed *report* must not escalate.
    fn report<'a>(
        &'a self,
        name: &'a str,
        condition: Option<Condition>,
    ) -> BoxFuture<'a, Result<(), ReconcileError>>;
}

/// [`ProjectStatusSink`] backed by `Api<AppProject>` in the control-plane namespace.
#[derive(Clone)]
pub struct ApiProjectStatusSink {
    api: Api<AppProject>,
    namespace: String,
}

impl ApiProjectStatusSink {
    /// Builds a sink writing to `namespace` (the control-plane namespace).
    #[must_use]
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            namespace: namespace.to_owned(),
        }
    }

    /// The namespace the sink writes to.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

impl std::fmt::Debug for ApiProjectStatusSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiProjectStatusSink")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl ProjectStatusSink for ApiProjectStatusSink {
    fn report<'a>(
        &'a self,
        name: &'a str,
        condition: Option<Condition>,
    ) -> BoxFuture<'a, Result<(), ReconcileError>> {
        Box::pin(async move {
            // Read first: the patch is skipped entirely when the recorded condition already
            // matches (and when there is nothing to clear), so a project that stays broken — or
            // one that is healthy — costs one GET per reconcile, not one write.
            let project = match self.api.get_opt(name).await {
                Ok(Some(project)) => project,
                // A project deleted between the policy read and here: nothing to report on.
                Ok(None) => return Ok(()),
                Err(err) => return Err(ReconcileError::Api(err)),
            };
            let current = project.status.clone().unwrap_or_default();
            // Finding H1: the observed generation is the **project's** own `metadata.generation`,
            // read from the object this write is about. Passing the `Application`'s generation
            // made the condition claim to describe a revision of the project that never existed.
            let condition = condition.map(|condition| for_project(condition, &project));
            let Some(body) = status_patch(&current, condition.as_ref()) else {
                return Ok(());
            };
            self.api
                .patch_status(
                    name,
                    &PatchParams::default(),
                    &Patch::Merge(serde_json::json!({
                        "status": {
                            "observedGeneration": project.metadata.generation,
                            "conditions": body,
                        }
                    })),
                )
                .await
                .map(|_| ())
                .map_err(ReconcileError::Api)
        })
    }
}

/// Stamps `condition` with the project's own `metadata.generation` (finding H1).
fn for_project(condition: Condition, project: &AppProject) -> Condition {
    condition.with_observed_generation(project.metadata.generation)
}

/// The new condition list, or `None` when the patch would change nothing.
///
/// Pure, so both "report once per distinct message" and "clear once" are testable without an API
/// server.
///
/// * `Some(condition)` — the existing list is kept as-is except for the entry of the same `type`,
///   which is replaced (a condition list is a *set* keyed on `type`). `None` when that exact
///   condition is already recorded: a project that stays broken must not cost a write per
///   reconcile.
/// * `None` — the `SyncWindowInvalid` condition is removed, because the windows evaluate again
///   (finding H2). `None` when the project does not record it, so a healthy project never costs a
///   write either.
///
/// `lastTransitionTime` is deliberately not compared: the message is what the operator reads, and
/// re-writing an identical message every reconcile is exactly the churn this guard prevents.
/// `observedGeneration` **is** compared (finding M-C): it is the one field that says *which revision
/// of the project* the condition describes, so a generation bump — the operator edited the project
/// but the message happened to read the same, e.g. two different windows both failing to parse —
/// must still rewrite the condition instead of leaving a stale generation on it.
pub(crate) fn status_patch(
    current: &AppProjectStatus,
    condition: Option<&Condition>,
) -> Option<Vec<Condition>> {
    match condition {
        Some(condition) => {
            let unchanged = current.conditions.iter().any(|existing| {
                existing.type_ == condition.type_
                    && existing.status == condition.status
                    && existing.reason == condition.reason
                    && existing.message == condition.message
                    && existing.observed_generation == condition.observed_generation
            });
            if unchanged {
                return None;
            }
            let mut conditions: Vec<Condition> = current
                .conditions
                .iter()
                .filter(|existing| existing.type_ != condition.type_)
                .cloned()
                .collect();
            conditions.push(condition.clone());
            Some(conditions)
        }
        None => {
            let conditions: Vec<Condition> = current
                .conditions
                .iter()
                .filter(|existing| {
                    !(existing.type_ == CONDITION_READY
                        && existing.reason == REASON_SYNC_WINDOW_INVALID)
                })
                .cloned()
                .collect();
            (conditions.len() != current.conditions.len()).then_some(conditions)
        }
    }
}

/// The `Ready=False` condition for a project with an unusable `syncWindows` entry.
///
/// `observedGeneration` is left empty here: [`ApiProjectStatusSink::report`] stamps it from the
/// project it reads (finding H1), so no caller has to know which generation to claim.
///
/// `None` when `invalid` is empty — the list that *proves* the windows cannot be evaluated is also
/// what the message is built from, so the one function cannot be called without a finding to report
/// (finding M-1: the previous `invalid[0]` indexed an unchecked slice and panicked on the empty
/// case). The caller passes the verdict's `invalid()` straight through, which is exactly the value
/// the condition is cleared on, so returning `Option` here is what makes `None` mean "clear".
#[must_use]
pub fn sync_window_condition(invalid: &[InvalidSyncWindow], now: Time) -> Option<Condition> {
    let (first, rest) = invalid.split_first()?;
    let message = if rest.is_empty() {
        format!(
            "spec.syncWindows cannot be evaluated (fail closed), so every sync of this project is \
             denied: {first}"
        )
    } else {
        format!(
            "spec.syncWindows cannot be evaluated (fail closed), so every sync of this project is \
             denied: {first} (and {} more)",
            rest.len()
        )
    };
    Some(Condition::new(
        CONDITION_READY,
        ConditionStatus::False,
        REASON_SYNC_WINDOW_INVALID,
        message,
        now,
    ))
}

/// Condition reason recorded when `spec.syncWindows` cannot be evaluated (`T17.4`).
///
/// `Ready=False` on the **project** (never on the `Application`): the project is the operand the
/// operator has to fix, and a `Ready=False` `Application` would also trip the `on-sync-failed`
/// notification for a governance decision that is not a sync failure.
///
/// Defined by the CRD crate and re-exported here, because the engine's policy snapshot reads the
/// same condition back to decide whether there is one left to clear (finding H-A).
pub use ferriscd_crd::project::REASON_SYNC_WINDOW_INVALID;

/// Whether a `404` from an `AppProject` `GET` means "this project does not exist".
///
/// The API server attaches `details` (with the object's `name`/`kind`/`group`) when a *named*
/// object is missing, and returns a bare "the server could not find the requested resource" — no
/// `details` — when the resource **type** is not served at all, i.e. when the `AppProject` CRD was
/// never installed (finding M3).
fn is_missing_project(status: &kube::core::Status) -> bool {
    status
        .details
        .as_ref()
        .is_some_and(|details| !details.name.trim().is_empty() || !details.kind.trim().is_empty())
}

/// Builds the terminal error for "this cluster does not serve `AppProject`".
///
/// Terminal on purpose: no reconcile can install a CRD, so retrying forever would hide a
/// deployment mistake behind an unexplained `Ready=False`.
fn crd_not_installed(namespace: &str, name: &str) -> ReconcileError {
    ReconcileError::Invalid {
        message: format!(
            "this cluster does not serve ferriscd.io/v1alpha1 AppProject, so the project {name:?} \
             referenced by the Application cannot be read: install the CRDs first \
             (`kubectl apply -f deploy/crds/appprojects.ferriscd.io.yaml`). A missing project \
             permits nothing, and an uninstalled CRD is not the same as a missing project \
             (searched namespace: {namespace:?})"
        ),
    }
}

#[cfg(test)]
mod tests {
    use futures::future::BoxFuture;
    use kube::ResourceExt as _;
    use serde_json::json;

    use super::*;

    fn status(value: serde_json::Value) -> kube::core::Status {
        serde_json::from_value(value).expect("a valid kube Status")
    }

    /// **Finding M3:** the two `404`s an `AppProject` lookup can produce must not be conflated.
    #[test]
    fn a_missing_project_is_distinguished_from_a_missing_crd() {
        // A named object that does not exist: the API server names it in `details`.
        let missing_object = status(json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": "appprojects.ferriscd.io \"payments\" not found",
            "reason": "NotFound",
            "details": { "name": "payments", "group": "ferriscd.io", "kind": "appprojects" },
            "code": 404,
        }));
        assert!(
            is_missing_project(&missing_object),
            "an absent AppProject must be reported as ProjectNotFound"
        );

        // The whole resource type is unknown: no `details`, which is the CRD-is-not-installed case.
        let missing_crd = status(json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": "the server could not find the requested resource",
            "reason": "NotFound",
            "code": 404,
        }));
        assert!(
            !is_missing_project(&missing_crd),
            "an unserved kind must not be reported as a missing project"
        );

        // A `details` entry with neither a name nor a kind is not an object verdict either.
        let details_but_empty = status(json!({
            "status": "Failure",
            "message": "not found",
            "details": {},
            "code": 404,
        }));
        assert!(!is_missing_project(&details_but_empty));

        let crd_error = crd_not_installed("ferriscd-system", "payments").to_string();
        assert!(
            crd_error.contains("deploy/crds/appprojects.ferriscd.io.yaml"),
            "the message must name the manifest to apply: {crd_error}"
        );
        assert!(crd_error.contains("payments"), "{crd_error}");
        assert!(
            crd_error.contains("not the same as a missing project"),
            "the operator must be able to tell the two apart: {crd_error}"
        );
        assert_eq!(
            crd_not_installed("ferriscd-system", "payments").failure_class(),
            crate::FailureClass::Terminal,
            "no reconcile can install a CRD"
        );
    }

    /// The trait object must stay object-safe: the pipeline holds `Arc<dyn ProjectSource>`.
    #[test]
    fn project_source_is_object_safe() {
        fn assert_object_safe(_: &dyn ProjectSource) {}
        struct Empty;
        impl ProjectSource for Empty {
            fn get<'a>(
                &'a self,
                _name: &'a str,
            ) -> BoxFuture<'a, Result<Option<AppProject>, ReconcileError>> {
                Box::pin(async { Ok(None) })
            }
        }
        assert_object_safe(&Empty);
    }

    /// A scripted source (what the sync-pipeline tests substitute) really does answer per name, and
    /// the wired source really does read from the control-plane namespace.
    #[test]
    fn a_source_answers_per_project_name() {
        struct Scripted(Vec<(&'static str, AppProject)>);
        impl ProjectSource for Scripted {
            fn get<'a>(
                &'a self,
                name: &'a str,
            ) -> BoxFuture<'a, Result<Option<AppProject>, ReconcileError>> {
                let own = self
                    .0
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, pro)| pro.clone());
                Box::pin(async move { Ok(own) })
            }
        }

        let project: AppProject = serde_saphyr::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/manifests/default-project.yaml"
        )))
        .expect("the shipped default project must parse");
        let source = Scripted(vec![("default", project.clone())]);

        let found = futures::executor::block_on(source.get("default"))
            .expect("lookup")
            .expect("the scripted project must be returned");
        assert_eq!(found.name_any(), "default");
        assert_eq!(found.spec, project.spec);
        assert!(
            futures::executor::block_on(source.get("payments"))
                .expect("lookup")
                .is_none(),
            "an unknown project must answer None, never a different project"
        );
    }

    /// A project fixture with the given `metadata.generation`.
    fn project_at_generation(generation: i64) -> AppProject {
        serde_saphyr::from_str(&format!(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: payments
  namespace: ferriscd-system
  generation: {generation}
spec:
  sourceRepos:
    - "*"
  sourceNamespaces:
    - ferriscd-system
  destinations:
    - cluster: in-cluster
      namespace: payments
"#
        ))
        .expect("the fixture project must parse")
    }

    fn invalid_window() -> InvalidSyncWindow {
        InvalidSyncWindow {
            index: 0,
            schedule: "every weekday at nine".to_owned(),
            message: "not a cron expression".to_owned(),
        }
    }

    fn now() -> Time {
        Time(
            "2026-01-07T12:00:00Z"
                .parse()
                .expect("a valid RFC 3339 timestamp"),
        )
    }

    /// **Finding H1:** the recorded condition names the **project's** `metadata.generation`.
    ///
    /// The pipeline used to hand `report` the `Application`'s generation, so the project's
    /// `Ready=False` condition claimed to describe a revision of the *project* that never existed
    /// (the two objects number their generations independently). The generation is now read from
    /// the project object inside the sink, and nothing else supplies it.
    #[test]
    fn the_project_condition_names_the_projects_own_generation() {
        let condition =
            sync_window_condition(&[invalid_window()], now()).expect("a broken window reports");
        assert_eq!(
            condition.observed_generation, None,
            "the caller must not supply a generation: the sink reads the project's own"
        );
        assert_eq!(
            for_project(condition.clone(), &project_at_generation(11)).observed_generation,
            Some(11)
        );
        // A different generation of the same project restamps the condition, so the operator can
        // tell whether the recorded verdict is about the spec they are reading.
        assert_eq!(
            for_project(condition, &project_at_generation(12)).observed_generation,
            Some(12)
        );
    }

    /// **Finding H2:** clearing is a real write the first time and a no-op afterwards.
    #[test]
    fn the_invalid_window_condition_is_removed_when_the_windows_evaluate_again() {
        let condition = for_project(
            sync_window_condition(&[invalid_window()], now()).expect("a broken window reports"),
            &project_at_generation(3),
        );
        let recorded = AppProjectStatus {
            observed_generation: Some(3),
            conditions: vec![condition],
        };
        // Nothing else in the list: clearing empties it.
        assert_eq!(status_patch(&recorded, None), Some(Vec::new()));
        // Already cleared (or never set): no write at all.
        assert_eq!(status_patch(&AppProjectStatus::default(), None), None);
        // Another condition is preserved; only the invalid-window `Ready` entry goes.
        let other = Condition::ready(ConditionStatus::True, "SomeOtherReason", "kept", now());
        let mixed = AppProjectStatus {
            observed_generation: Some(4),
            conditions: vec![other.clone(), recorded.conditions[0].clone()],
        };
        assert_eq!(status_patch(&mixed, None), Some(vec![other]));
        // Setting the identical condition again is free: the recorded message is what matters.
        assert_eq!(
            status_patch(&recorded, Some(&recorded.conditions[0].clone())),
            None
        );
        // A different message replaces the `Ready` entry instead of appending a second one.
        let changed = sync_window_condition(
            &[InvalidSyncWindow {
                index: 1,
                schedule: "0 0 * * *".to_owned(),
                message: "duration \"8 days\": longer than the 7d cap".to_owned(),
            }],
            now(),
        )
        .expect("a broken window reports");
        let conditions = status_patch(&recorded, Some(&changed)).expect("a change writes");
        assert_eq!(conditions.len(), 1, "the list is a set keyed on `type`");
        assert!(conditions[0].message.contains("spec.syncWindows[1]"));
    }

    /// **Finding M-1:** an empty `invalid` list is answered, not indexed.
    ///
    /// The function used to read `invalid[0]` unconditionally, so the one call that means "the
    /// windows evaluate again" (`None` = clear) was the call that panicked. It now answers `None`
    /// for the same input, which is also the value the caller hands the sink to clear the condition.
    #[test]
    fn no_invalid_window_yields_no_condition() {
        assert_eq!(sync_window_condition(&[], now()), None);
        assert!(
            sync_window_condition(&[invalid_window()], now()).is_some(),
            "a non-empty list still reports, so the `None` above is the empty-list answer"
        );
    }

    /// A `kube::Client` over a service that never dials out: enough to build the `Api` whose
    /// namespace the source reports.
    fn offline_client() -> kube::Client {
        kube::Client::new(
            tower::service_fn(|_request| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            CONTROL_PLANE_NAMESPACE,
        )
    }
    #[tokio::test]
    async fn projects_are_read_from_the_control_plane_namespace_by_default() {
        // Project lookups follow the control plane; they are never cluster-wide, and they follow
        // `--namespace` when the operator moves it.
        assert_eq!(
            ApiProjectSource::in_control_plane(offline_client()).namespace(),
            CONTROL_PLANE_NAMESPACE
        );
        assert_eq!(
            ApiProjectSource::new(offline_client(), "apps").namespace(),
            "apps",
            "the control-plane namespace follows --namespace"
        );
        assert!(
            format!("{:?}", ApiProjectSource::in_control_plane(offline_client()))
                .contains(CONTROL_PLANE_NAMESPACE),
            "Debug must name the namespace the projects are read from"
        );
    }
}

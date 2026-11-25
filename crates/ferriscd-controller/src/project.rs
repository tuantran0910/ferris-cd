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

use ferriscd_crd::{AppProject, CONTROL_PLANE_NAMESPACE};
use futures::future::BoxFuture;
use kube::Api;

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

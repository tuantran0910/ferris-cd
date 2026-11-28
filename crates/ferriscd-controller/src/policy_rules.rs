//! Cluster-wide policy rules: `ConfigMap/ferriscd-policies-cm` (`T20.2`).
//!
//! `AppProject.spec.policyRules[]` is per-project and tenant-visible; a security team also needs
//! rules that apply to *every* `Application` without editing each project. Those live in one
//! `ConfigMap` in the control-plane namespace, read on demand per reconcile (a scoped `GET`, never a
//! cluster-wide informer) — exactly like the `AppProject` and repository-credential reads.
//!
//! The engine stays pure: this module only *fetches* the `data` map and hands it to
//! [`rules_from_configmap_data`], which parses each entry under the YAML budgets. Three failure
//! modes are deliberately distinguishable:
//!
//! | API server answer | Meaning | Raised as |
//! |---|---|---|
//! | `200` | rules in force | `Ok(rules)` |
//! | `404` | no cluster-wide rules configured | `Ok(vec![])` (the normal, documented state) |
//! | anything else | the read failed | [`ReconcileError::Api`] — retryable, never "no rules" |
//!
//! A `ConfigMap` that exists but does not parse is a **terminal** [`ReconcileError::Invalid`]: a
//! policy set the controller cannot read must never silently become "no policy".

use ferriscd_crd::CONTROL_PLANE_NAMESPACE;
use ferriscd_engine::policy::{POLICY_CONFIGMAP_NAME, PolicyRule, rules_from_configmap_data};
use futures::future::BoxFuture;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::Api;

use crate::reconcile::ReconcileError;

/// Reads the cluster-wide policy rules.
pub trait PolicyRuleSource: Send + Sync + 'static {
    /// Returns the rules in force, in `ConfigMap` key order.
    fn rules(&self) -> BoxFuture<'_, Result<Vec<PolicyRule>, ReconcileError>>;
}

/// [`PolicyRuleSource`] backed by `Api<ConfigMap>` in the control-plane namespace.
#[derive(Clone)]
pub struct ApiPolicyRuleSource {
    api: Api<ConfigMap>,
    namespace: String,
    name: String,
}

impl ApiPolicyRuleSource {
    /// Builds a source reading `ConfigMap/ferriscd-policies-cm` from `namespace`.
    #[must_use]
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            namespace: namespace.to_owned(),
            name: POLICY_CONFIGMAP_NAME.to_owned(),
        }
    }

    /// Builds a source reading from [`CONTROL_PLANE_NAMESPACE`].
    #[must_use]
    pub fn in_control_plane(client: kube::Client) -> Self {
        Self::new(client, CONTROL_PLANE_NAMESPACE)
    }

    /// The namespace the `ConfigMap` is read from.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The `ConfigMap` name.
    #[must_use]
    pub fn configmap_name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Debug for ApiPolicyRuleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiPolicyRuleSource")
            .field("namespace", &self.namespace)
            .field("configmap", &self.name)
            .finish_non_exhaustive()
    }
}

impl PolicyRuleSource for ApiPolicyRuleSource {
    fn rules(&self) -> BoxFuture<'_, Result<Vec<PolicyRule>, ReconcileError>> {
        Box::pin(async move {
            // `get_opt` (not `get`): "there is no cluster-wide policy ConfigMap" is the documented,
            // normal state, while an unreadable one stays an error.
            let configmap = match self.api.get_opt(&self.name).await {
                Ok(configmap) => configmap,
                Err(err) => return Err(ReconcileError::Api(err)),
            };
            let Some(configmap) = configmap else {
                return Ok(Vec::new());
            };
            let data = configmap.data.unwrap_or_default();
            rules_from_configmap_data(&self.name, &data).map_err(|err| ReconcileError::Invalid {
                message: format!(
                    "{} in namespace {:?} cannot be read as a policy rule set ({err}); fix or \
                     delete the ConfigMap — policy rules that cannot be parsed are never treated \
                     as absent",
                    self.name, self.namespace
                ),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use kube::ResourceExt as _;
    use serde_json::json;

    use super::*;

    /// A `kube::Client` that records request URIs and answers every call with `body`/`status`.
    fn recording_client(
        status: u16,
        body: serde_json::Value,
    ) -> (kube::Client, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let body = serde_json::to_vec(&body).expect("a serializable body");
        let client = kube::Client::new(
            tower::service_fn(move |request: http::Request<kube::client::Body>| {
                let recorder = recorder.clone();
                let body = body.clone();
                async move {
                    recorder
                        .lock()
                        .expect("the recorder lock is never poisoned in a test")
                        .push(request.uri().to_string());
                    let response = http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body))
                        .expect("a valid response");
                    Ok::<_, std::convert::Infallible>(response)
                }
            }),
            CONTROL_PLANE_NAMESPACE,
        );
        (client, seen)
    }

    fn configmap(data: serde_json::Value) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": POLICY_CONFIGMAP_NAME, "namespace": CONTROL_PLANE_NAMESPACE },
            "data": data,
        })
    }

    #[tokio::test]
    async fn the_rules_are_read_from_one_namespaced_configmap() {
        let (client, seen) = recording_client(
            200,
            configmap(json!({
                "no-privileged": "enforcement: Enforce\nexpression: \"true\"\n\
                                  message: privileged containers are forbidden",
                "advisory": "enforcement: Warn\nexpression: \"true\"",
            })),
        );
        let source = ApiPolicyRuleSource::in_control_plane(client);
        assert_eq!(source.namespace(), CONTROL_PLANE_NAMESPACE);
        assert_eq!(source.configmap_name(), POLICY_CONFIGMAP_NAME);

        let rules = source.rules().await.expect("the rules must parse");
        assert_eq!(rules.len(), 2);
        // `BTreeMap` ordering: the rule order — and every violation message — is deterministic.
        assert_eq!(rules[0].name, "advisory");
        assert_eq!(rules[1].name, "no-privileged");

        let requests = seen
            .lock()
            .expect("the recorder lock is never poisoned in a test")
            .clone();
        assert_eq!(
            requests.len(),
            1,
            "one scoped GET per reconcile: {requests:?}"
        );
        assert!(
            requests[0].starts_with("/api/v1/namespaces/ferriscd-system/configmaps/"),
            "the read must be namespaced and name the ConfigMap: {requests:?}"
        );
        assert!(requests[0].contains(POLICY_CONFIGMAP_NAME), "{requests:?}");
    }

    #[tokio::test]
    async fn a_missing_configmap_means_no_cluster_wide_rules() {
        let (client, _seen) = recording_client(
            404,
            json!({
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "message": format!("configmaps \"{POLICY_CONFIGMAP_NAME}\" not found"),
                "reason": "NotFound",
                "details": { "name": POLICY_CONFIGMAP_NAME, "kind": "configmaps" },
                "code": 404,
            }),
        );
        let source = ApiPolicyRuleSource::in_control_plane(client);
        assert!(
            source
                .rules()
                .await
                .expect("a missing ConfigMap is not an error")
                .is_empty(),
            "no cluster-wide rules must stay the normal state"
        );
    }

    #[tokio::test]
    async fn an_unparseable_configmap_is_a_terminal_refusal_not_an_empty_rule_set() {
        let (client, _seen) =
            recording_client(200, configmap(json!({ "broken": "expression: [" })));
        let source = ApiPolicyRuleSource::in_control_plane(client);
        let err = source
            .rules()
            .await
            .expect_err("an unparseable rule set must refuse");
        let message = err.to_string();
        assert!(message.contains(POLICY_CONFIGMAP_NAME), "{message}");
        assert!(
            message.contains("never treated as absent"),
            "the operator must understand why the sync stopped: {message}"
        );
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Terminal,
            "retrying cannot fix a malformed ConfigMap"
        );
    }

    /// The trait object must stay object-safe: the pipeline holds `Arc<dyn PolicyRuleSource>`.
    #[test]
    fn policy_rule_source_is_object_safe() {
        fn assert_object_safe(_: &dyn PolicyRuleSource) {}
        struct Empty;
        impl PolicyRuleSource for Empty {
            fn rules(&self) -> BoxFuture<'_, Result<Vec<PolicyRule>, ReconcileError>> {
                Box::pin(async { Ok(Vec::new()) })
            }
        }
        assert_object_safe(&Empty);
    }

    #[tokio::test]
    async fn debug_names_the_namespace_and_configmap_without_a_client() {
        let (client, _seen) = recording_client(404, json!({}));
        let debug = format!("{:?}", ApiPolicyRuleSource::new(client, "apps"));
        assert!(debug.contains("apps"), "{debug}");
        assert!(debug.contains(POLICY_CONFIGMAP_NAME), "{debug}");
    }

    /// The fixture really is a `ConfigMap` in the control-plane namespace.
    #[test]
    fn configmap_fixture_names_the_control_plane_namespace() {
        let value: ConfigMap = serde_json::from_value(configmap(json!({}))).expect("valid");
        assert_eq!(value.namespace(), Some(CONTROL_PLANE_NAMESPACE.to_owned()));
    }
}

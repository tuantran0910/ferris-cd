use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args;
use kube::api::{Api, DynamicObject, GroupVersionKind, Patch, PatchParams};
use kube::discovery::{Discovery, Scope};

/// Arguments for `ferriscd apply-file`.
#[derive(Debug, Args)]
pub struct ApplyFileArgs {
    /// Path to a single Kubernetes YAML manifest file.
    pub path: PathBuf,
    /// Target namespace for namespaced resources (defaults to manifest namespace or "default").
    #[arg(short = 'n', long = "namespace")]
    pub namespace: Option<String>,
}

/// Parsed and validated manifest ready for discovery and SSA apply.
#[derive(Debug)]
pub struct PreparedManifest {
    pub object: DynamicObject,
    pub gvk: GroupVersionKind,
    pub name: String,
}

/// Executes the `apply-file` command against the active Kubernetes cluster.
pub async fn run(args: ApplyFileArgs) -> Result<()> {
    let contents = tokio::fs::read_to_string(&args.path)
        .await
        .with_context(|| format!("failed to read manifest file '{}'", args.path.display()))?;

    let mut prepared = parse_and_prepare_manifest(&contents)?;

    let client = kube::Client::try_default().await.context(
        "failed to initialize Kubernetes client from default kubeconfig/in-cluster config",
    )?;

    let discovery = Discovery::new(client.clone())
        .run()
        .await
        .context("failed to run Kubernetes API discovery")?;

    let (ar, caps) = discovery.resolve_gvk(&prepared.gvk).ok_or_else(|| {
        anyhow::anyhow!(
            "resource type {}/{} (version '{}') not found in cluster discovery",
            prepared.gvk.group,
            prepared.gvk.kind,
            prepared.gvk.version
        )
    })?;

    let target_ns = resolve_target_namespace(
        &mut prepared.object,
        caps.scope,
        args.namespace.as_deref(),
        &prepared.gvk,
    )?;

    let api = match target_ns.as_deref() {
        Some(ns) => Api::<DynamicObject>::namespaced_with(client, ns, &ar),
        None => Api::<DynamicObject>::all_with(client, &ar),
    };

    let params = apply_patch_params();
    let gknn_before = format_gknn(&prepared.gvk, target_ns.as_deref(), &prepared.name);
    let applied = api
        .patch(&prepared.name, &params, &Patch::Apply(&prepared.object))
        .await
        .with_context(|| format!("server-side apply failed for {gknn_before}"))?;

    let applied_name = applied.metadata.name.as_deref().unwrap_or(&prepared.name);
    let gknn = format_gknn(
        &prepared.gvk,
        applied.metadata.namespace.as_deref(),
        applied_name,
    );
    let resource_version = applied
        .metadata
        .resource_version
        .as_deref()
        .unwrap_or("<none>");
    let managers = extract_managed_field_managers(&applied);
    let managers_display = if managers.is_empty() {
        "<none>".to_owned()
    } else {
        managers.join(", ")
    };

    println!("applied: {gknn}");
    println!("resourceVersion: {resource_version}");
    println!("managedFields managers: {managers_display}");

    Ok(())
}

/// Parses a single YAML manifest into a [`DynamicObject`], validates required metadata,
/// derives its [`GroupVersionKind`], and strips any top-level `status` field.
pub fn parse_and_prepare_manifest(yaml: &str) -> Result<PreparedManifest> {
    let mut object: DynamicObject =
        serde_saphyr::from_str(yaml).context("failed to parse YAML manifest into DynamicObject")?;

    let tm = object
        .types
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("manifest is missing apiVersion and kind"))?
        .clone();

    if tm.api_version.trim().is_empty() {
        bail!("manifest apiVersion must not be empty");
    }
    if tm.kind.trim().is_empty() {
        bail!("manifest kind must not be empty");
    }

    let gvk = GroupVersionKind::try_from(tm)
        .context("manifest apiVersion/kind could not be converted to GroupVersionKind")?;

    let name = object
        .metadata
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("manifest metadata.name must be present and non-empty"))?
        .to_owned();

    if let Some(map) = object.data.as_object_mut() {
        map.remove("status");
    }

    Ok(PreparedManifest { object, gvk, name })
}

/// Resolves the target namespace for the resource based on discovery scope, manifest metadata,
/// and optional `--namespace` CLI flag.
pub fn resolve_target_namespace(
    object: &mut DynamicObject,
    scope: Scope,
    cli_namespace: Option<&str>,
    gvk: &GroupVersionKind,
) -> Result<Option<String>> {
    let cli_ns = match cli_namespace {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                bail!("--namespace must not be empty");
            }
            Some(trimmed)
        }
        None => None,
    };

    let manifest_ns = object
        .metadata
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match scope {
        Scope::Namespaced => {
            let resolved = match (cli_ns, manifest_ns) {
                (Some(cli), Some(manifest)) if cli != manifest => {
                    bail!(
                        "namespace conflict: --namespace is '{cli}', but manifest metadata.namespace is '{manifest}'"
                    );
                }
                (Some(cli), _) => cli.to_owned(),
                (None, Some(manifest)) => manifest.to_owned(),
                (None, None) => "default".to_owned(),
            };
            object.metadata.namespace = Some(resolved.clone());
            Ok(Some(resolved))
        }
        Scope::Cluster => {
            if let Some(manifest) = manifest_ns {
                bail!(
                    "cluster-scoped resource {}/{} cannot specify metadata.namespace ('{manifest}')",
                    gvk.group,
                    gvk.kind
                );
            }
            if let Some(cli) = cli_ns {
                bail!(
                    "cannot specify --namespace ('{cli}') for cluster-scoped resource {}/{}",
                    gvk.group,
                    gvk.kind
                );
            }
            object.metadata.namespace = None;
            Ok(None)
        }
    }
}

/// Builds FerrisCD's default SSA [`PatchParams`] (`force: false`).
#[must_use]
pub fn apply_patch_params() -> PatchParams {
    PatchParams::apply(ferriscd_engine::default_field_manager())
}

/// Formats a canonical GKNN identifier (`<group>/<kind>/<namespace>/<name>`).
#[must_use]
pub fn format_gknn(gvk: &GroupVersionKind, namespace: Option<&str>, name: &str) -> String {
    let ns = namespace.unwrap_or("");
    format!("{}/{}/{ns}/{name}", gvk.group, gvk.kind)
}

/// Extracts `managedFields` manager names, deduplicated while preserving order.
#[must_use]
pub fn extract_managed_field_managers(object: &DynamicObject) -> Vec<String> {
    let mut managers = Vec::new();
    if let Some(entries) = object.metadata.managed_fields.as_deref() {
        for entry in entries {
            if let Some(manager) = entry.manager.as_deref().filter(|m| !m.is_empty())
                && !managers.iter().any(|existing| existing == manager)
            {
                managers.push(manager.to_owned());
            }
        }
    }
    managers
}

#[cfg(test)]
mod tests {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry;
    use kube::api::TypeMeta;

    use super::*;

    #[test]
    fn parses_example_configmap() {
        let yaml = include_str!("../../../../examples/basic/configmap.yaml");
        let prepared = parse_and_prepare_manifest(yaml).expect("configmap example should parse");

        assert_eq!(prepared.gvk.group, "");
        assert_eq!(prepared.gvk.version, "v1");
        assert_eq!(prepared.gvk.kind, "ConfigMap");
        assert_eq!(prepared.name, "demo-config");
        assert_eq!(prepared.object.metadata.namespace, None);
    }

    #[test]
    fn parses_example_namespace() {
        let yaml = include_str!("../../../../examples/basic/namespace.yaml");
        let prepared = parse_and_prepare_manifest(yaml).expect("namespace example should parse");

        assert_eq!(prepared.gvk.group, "");
        assert_eq!(prepared.gvk.version, "v1");
        assert_eq!(prepared.gvk.kind, "Namespace");
        assert_eq!(prepared.name, "ferriscd-demo");
        assert_eq!(prepared.object.metadata.namespace, None);
    }

    #[test]
    fn rejects_missing_api_version_or_kind_or_name() {
        let missing_kind = r#"
apiVersion: v1
metadata:
  name: test-cm
"#;
        assert!(parse_and_prepare_manifest(missing_kind).is_err());

        let missing_api_version = r#"
kind: ConfigMap
metadata:
  name: test-cm
"#;
        assert!(parse_and_prepare_manifest(missing_api_version).is_err());

        let empty_kind = r#"
apiVersion: v1
kind: ""
metadata:
  name: test-cm
"#;
        assert!(parse_and_prepare_manifest(empty_kind).is_err());

        let missing_name = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app: demo
"#;
        assert!(parse_and_prepare_manifest(missing_name).is_err());

        let empty_name = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: "   "
"#;
        assert!(parse_and_prepare_manifest(empty_name).is_err());
    }

    #[test]
    fn strips_top_level_status_before_apply() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-deploy
spec:
  replicas: 1
status:
  availableReplicas: 1
  readyReplicas: 1
"#;
        let prepared = parse_and_prepare_manifest(yaml).expect("deployment manifest should parse");

        assert_eq!(prepared.gvk.group, "apps");
        assert_eq!(prepared.gvk.version, "v1");
        assert_eq!(prepared.gvk.kind, "Deployment");
        assert!(prepared.object.data.get("spec").is_some());
        assert!(prepared.object.data.get("status").is_none());
    }

    #[test]
    fn resolves_namespaced_with_default_when_omitted() {
        let yaml = include_str!("../../../../examples/basic/configmap.yaml");
        let mut prepared = parse_and_prepare_manifest(yaml).expect("configmap should parse");

        let resolved =
            resolve_target_namespace(&mut prepared.object, Scope::Namespaced, None, &prepared.gvk)
                .expect("default namespace should resolve");

        assert_eq!(resolved.as_deref(), Some("default"));
        assert_eq!(
            prepared.object.metadata.namespace.as_deref(),
            Some("default")
        );
    }

    #[test]
    fn resolves_namespaced_with_explicit_cli_override() {
        let yaml = include_str!("../../../../examples/basic/configmap.yaml");
        let mut prepared = parse_and_prepare_manifest(yaml).expect("configmap should parse");

        let resolved = resolve_target_namespace(
            &mut prepared.object,
            Scope::Namespaced,
            Some("ferriscd-demo"),
            &prepared.gvk,
        )
        .expect("explicit CLI namespace should resolve");

        assert_eq!(resolved.as_deref(), Some("ferriscd-demo"));
        assert_eq!(
            prepared.object.metadata.namespace.as_deref(),
            Some("ferriscd-demo")
        );
    }

    #[test]
    fn allows_matching_cli_and_manifest_namespace() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo-config
  namespace: ferriscd-demo
"#;
        let mut prepared = parse_and_prepare_manifest(yaml).expect("configmap should parse");

        let resolved = resolve_target_namespace(
            &mut prepared.object,
            Scope::Namespaced,
            Some("ferriscd-demo"),
            &prepared.gvk,
        )
        .expect("matching namespaces should succeed");

        assert_eq!(resolved.as_deref(), Some("ferriscd-demo"));
    }

    #[test]
    fn rejects_conflicting_manifest_and_cli_namespace() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo-config
  namespace: ns-manifest
"#;
        let mut prepared = parse_and_prepare_manifest(yaml).expect("configmap should parse");

        let err = resolve_target_namespace(
            &mut prepared.object,
            Scope::Namespaced,
            Some("ns-cli"),
            &prepared.gvk,
        )
        .expect_err("conflicting namespaces must be rejected");

        assert!(err.to_string().contains("namespace conflict"));
    }

    #[test]
    fn cluster_scoped_rejects_namespace_in_manifest_or_cli() {
        let ns_in_manifest = r#"
apiVersion: v1
kind: Namespace
metadata:
  name: ferriscd-demo
  namespace: unexpected
"#;
        let mut prepared = parse_and_prepare_manifest(ns_in_manifest).expect("manifest parses");
        let err =
            resolve_target_namespace(&mut prepared.object, Scope::Cluster, None, &prepared.gvk)
                .expect_err("cluster-scoped resource with metadata.namespace must fail");
        assert!(err.to_string().contains("cluster-scoped"));

        let clean_ns = include_str!("../../../../examples/basic/namespace.yaml");
        let mut prepared_clean = parse_and_prepare_manifest(clean_ns).expect("manifest parses");
        let err_cli = resolve_target_namespace(
            &mut prepared_clean.object,
            Scope::Cluster,
            Some("default"),
            &prepared_clean.gvk,
        )
        .expect_err("cluster-scoped resource with --namespace must fail");
        assert!(err_cli.to_string().contains("cluster-scoped"));

        let ok = resolve_target_namespace(
            &mut prepared_clean.object,
            Scope::Cluster,
            None,
            &prepared_clean.gvk,
        )
        .expect("cluster-scoped resource without namespace succeeds");
        assert_eq!(ok, None);
    }

    #[test]
    fn formats_gknn_for_namespaced_and_cluster_scoped() {
        let cm_gvk = GroupVersionKind::try_from(TypeMeta::resource::<
            k8s_openapi::api::core::v1::ConfigMap,
        >())
        .expect("valid ConfigMap GVK");
        assert_eq!(
            format_gknn(&cm_gvk, Some("default"), "demo-config"),
            "/ConfigMap/default/demo-config"
        );

        let ns_gvk = GroupVersionKind::try_from(TypeMeta::resource::<
            k8s_openapi::api::core::v1::Namespace,
        >())
        .expect("valid Namespace GVK");
        assert_eq!(
            format_gknn(&ns_gvk, None, "ferriscd-demo"),
            "/Namespace//ferriscd-demo"
        );

        let deploy_gvk = GroupVersionKind::try_from(TypeMeta::resource::<
            k8s_openapi::api::apps::v1::Deployment,
        >())
        .expect("valid Deployment GVK");
        assert_eq!(
            format_gknn(&deploy_gvk, Some("prod"), "api"),
            "apps/Deployment/prod/api"
        );
    }

    #[test]
    fn extracts_deduplicated_managed_field_managers_in_order() {
        let yaml = include_str!("../../../../examples/basic/configmap.yaml");
        let mut prepared = parse_and_prepare_manifest(yaml).expect("configmap should parse");

        prepared.object.metadata.managed_fields = Some(vec![
            ManagedFieldsEntry {
                manager: Some("ferriscd".to_owned()),
                ..Default::default()
            },
            ManagedFieldsEntry {
                manager: Some("kubectl".to_owned()),
                ..Default::default()
            },
            ManagedFieldsEntry {
                manager: Some("ferriscd".to_owned()),
                ..Default::default()
            },
            ManagedFieldsEntry {
                manager: None,
                ..Default::default()
            },
            ManagedFieldsEntry {
                manager: Some("kube-controller-manager".to_owned()),
                ..Default::default()
            },
        ]);

        assert_eq!(
            extract_managed_field_managers(&prepared.object),
            vec!["ferriscd", "kubectl", "kube-controller-manager"]
        );
    }

    #[test]
    fn patch_params_defaults_force_to_false() {
        let params = apply_patch_params();
        assert!(!params.force);
        assert_eq!(params.field_manager.as_deref(), Some("ferriscd"));
    }
}

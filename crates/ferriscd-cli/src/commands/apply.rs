//! `ferriscd apply` — the standalone `v0.1` GitOps engine: Git -> YAML 1.2 ->
//! offline normalization -> Discovery-aware scope injection -> ordered SSA apply.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Args;
use ferriscd_engine::graph::sort_by_tier;
use ferriscd_engine::manifest::{self, DesiredResource, GroupVersionKind, ManifestLoaderConfig};
use ferriscd_engine::repo::{
    GitSource, GixGitClient, GixGitClientConfig, RepoCache, RepoCacheConfig, RepoCredentials,
    RepoUrlPolicy,
};
use kube::api::{Api, DynamicObject, Patch};
use kube::discovery::{Discovery, Scope};

use super::apply_file::{apply_patch_params, format_gknn};

/// Arguments for `ferriscd apply`.
#[derive(Debug, Args)]
pub struct ApplyArgs {
    /// Git repository URL or local path.
    #[arg(long)]
    pub repo: String,

    /// Branch, tag, or commit SHA to check out.
    #[arg(long)]
    pub rev: String,

    /// Manifest file or directory inside the repository.
    #[arg(long)]
    pub path: String,

    /// Target namespace for namespaced resources that do not declare one.
    #[arg(short = 'n', long = "namespace")]
    pub namespace: String,
}

/// Executes the standalone `apply` pipeline against the active Kubernetes cluster.
pub async fn run(args: ApplyArgs) -> Result<()> {
    // One short-lived scratch root backs both the gix worktrees and the repo cache so
    // the final cache publish is a same-filesystem atomic rename.
    let scratch = tempfile::tempdir().context("creating apply scratch directory")?;
    let work_root = scratch.path().to_path_buf();

    let client = GixGitClient::new(
        GixGitClientConfig::new()
            .with_url_policy(RepoUrlPolicy::AllowLocal)
            .with_work_root(work_root.clone()),
    );
    let cache = RepoCache::new(Arc::new(client), RepoCacheConfig::new(work_root));

    let src = GitSource::new(args.repo.clone(), args.rev.clone(), args.path.clone());
    let creds = RepoCredentials::Anonymous;

    let resolved = cache.resolve_revision(&src, &creds).await?;
    let checkout = cache.checkout(&src, &resolved.commit_sha, &creds).await?;

    // All manifest file I/O and YAML parsing runs off the Tokio worker pool.
    let source_path = args.path.clone();
    let resources =
        tokio::task::spawn_blocking(move || build_desired_resources(&checkout, &source_path))
            .await
            .context("manifest loading task failed")??;

    let kube_client = kube::Client::try_default().await.context(
        "failed to initialize Kubernetes client from default kubeconfig/in-cluster config",
    )?;
    let discovery = Discovery::new(kube_client.clone())
        .run()
        .await
        .context("failed to run Kubernetes API discovery")?;

    let namespace = args.namespace.clone();
    let mut prepared: Vec<(
        DesiredResource,
        kube::api::ApiResource,
        kube::discovery::ApiCapabilities,
    )> = Vec::with_capacity(resources.len());
    for mut resource in resources {
        let kube_gvk = to_kube_gvk(&resource.gvk);
        let (ar, caps) = discovery.resolve_gvk(&kube_gvk).ok_or_else(|| {
            anyhow::anyhow!(
                "resource type {} not found in cluster discovery",
                resource.gvk
            )
        })?;

        if resource.object.metadata.generate_name.is_some() {
            bail!(
                "{} uses metadata.generateName (lifecycle hooks); ferriscd apply does not \
                 support hooks",
                resource.key.canonical()
            );
        }

        inject_namespace(&mut resource, caps.scope.clone(), &namespace)?;
        prepared.push((resource, ar, caps));
    }

    // Namespace injection can make two formerly distinct objects collide (e.g. a manifest
    // that already namespaces an object plus one that relies on `--namespace`); detect that
    // before applying anything instead of letting the last SSA call silently win.
    manifest::check_duplicate_keys(prepared.iter().map(|(resource, _, _)| resource))
        .context("duplicate resource key after namespace injection")?;

    for (resource, ar, caps) in prepared {
        let kube_gvk = to_kube_gvk(&resource.gvk);
        let name = resource
            .object
            .metadata
            .name
            .as_deref()
            .unwrap_or(&resource.key.name)
            .to_owned();

        let api = match caps.scope {
            Scope::Namespaced => {
                let ns = resource
                    .object
                    .metadata
                    .namespace
                    .as_deref()
                    .map(str::to_owned)
                    .unwrap_or_else(|| namespace.clone());
                Api::<DynamicObject>::namespaced_with(kube_client.clone(), &ns, &ar)
            }
            Scope::Cluster => Api::<DynamicObject>::all_with(kube_client.clone(), &ar),
        };

        let applied = api
            .patch(
                &name,
                &apply_patch_params(),
                &Patch::Apply(&resource.object),
            )
            .await
            .with_context(|| {
                format!("server-side apply failed for {}", resource.key.canonical())
            })?;

        let applied_name = applied.metadata.name.as_deref().unwrap_or(&name);
        let applied_ns = applied.metadata.namespace.as_deref();
        println!(
            "applied: {}",
            format_gknn(&kube_gvk, applied_ns, applied_name)
        );
    }

    Ok(())
}

/// Loads, parses, normalizes, and tier-sorts desired resources (blocking).
fn build_desired_resources(
    checkout: &ferriscd_engine::repo::RepoCheckout,
    source_path: &str,
) -> Result<Vec<DesiredResource>, manifest::ManifestError> {
    let config = ManifestLoaderConfig::default();
    let files = manifest::load(checkout.root_dir(), source_path, &config)?;

    let mut resources = Vec::new();
    for file in files {
        let parsed = manifest::parse_file(&file.source_file, &file.contents)?;
        resources.extend(parsed);
    }

    let resources = manifest::normalize(resources)?;
    Ok(sort_by_tier(resources))
}

/// Converts FerrisCD's version-agnostic GVK into kube's discovery GVK.
#[must_use]
pub fn to_kube_gvk(gvk: &GroupVersionKind) -> kube::api::GroupVersionKind {
    kube::api::GroupVersionKind::gvk(&gvk.group, &gvk.version, &gvk.kind)
}

/// Injects `namespace` onto a namespaced object that does not declare one.
///
/// Cluster-scoped objects are left untouched, and an existing namespace is never
/// overwritten. The [`DesiredResource::key`] namespace is updated in lockstep so
/// callers observe the same identity the API server will see.
pub fn inject_namespace(
    resource: &mut DesiredResource,
    scope: Scope,
    namespace: &str,
) -> Result<()> {
    match scope {
        Scope::Namespaced => {
            let trimmed = namespace.trim();
            if trimmed.is_empty() {
                bail!("--namespace must not be empty");
            }
            let has_namespace = resource
                .object
                .metadata
                .namespace
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_some();
            if !has_namespace {
                resource.object.metadata.namespace = Some(trimmed.to_owned());
                resource.key.namespace = Some(trimmed.to_owned());
            }
        }
        Scope::Cluster => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferriscd_engine::manifest::{ResourceKey, types};

    fn resource() -> DesiredResource {
        let object: DynamicObject = serde_saphyr::from_str(
            r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-app
"#,
        )
        .expect("valid object");
        DesiredResource {
            key: ResourceKey::new("apps", "Deployment", None, "demo-app"),
            gvk: types::GroupVersionKind::parse("apps/v1", "Deployment").expect("gvk"),
            object,
            source_file: "deploy.yaml".to_owned(),
        }
    }

    #[test]
    fn injects_namespace_only_when_namespaced_and_missing() {
        let mut namespaced = resource();
        inject_namespace(&mut namespaced, Scope::Namespaced, "payments").expect("inject");
        assert_eq!(
            namespaced.object.metadata.namespace.as_deref(),
            Some("payments")
        );
        assert_eq!(namespaced.key.namespace.as_deref(), Some("payments"));
    }

    #[test]
    fn preserves_an_existing_namespace() {
        let mut namespaced = resource();
        namespaced.object.metadata.namespace = Some("existing".to_owned());
        namespaced.key.namespace = Some("existing".to_owned());
        inject_namespace(&mut namespaced, Scope::Namespaced, "override").expect("inject");
        assert_eq!(
            namespaced.object.metadata.namespace.as_deref(),
            Some("existing")
        );
    }

    #[test]
    fn cluster_scoped_objects_are_never_injected() {
        let mut cluster = resource();
        inject_namespace(&mut cluster, Scope::Cluster, "payments").expect("inject");
        assert_eq!(cluster.object.metadata.namespace, None);
        assert_eq!(cluster.key.namespace, None);
    }

    #[test]
    fn duplicate_gknn_after_namespace_injection_is_rejected() {
        let mut first = resource();
        first.source_file = "deploy-a.yaml".to_owned();
        let mut second = resource();
        second.source_file = "deploy-b.yaml".to_owned();

        inject_namespace(&mut first, Scope::Namespaced, "payments").expect("inject first");
        inject_namespace(&mut second, Scope::Namespaced, "payments").expect("inject second");

        let err = manifest::check_duplicate_keys([&first, &second])
            .expect_err("post-injection GKNN collision must fail");
        let text = err.to_string();
        assert!(text.contains("deploy-a.yaml"), "{text}");
        assert!(text.contains("deploy-b.yaml"), "{text}");
    }

    #[test]
    fn empty_namespace_is_rejected() {
        let mut namespaced = resource();
        let err = inject_namespace(&mut namespaced, Scope::Namespaced, "  ")
            .expect_err("empty namespace");
        assert!(err.to_string().contains("--namespace"), "{err}");
    }

    #[test]
    fn to_kube_gvk_preserves_group_version_kind() {
        let gvk = types::GroupVersionKind::parse("apps/v1", "Deployment").expect("gvk");
        let kube_gvk = to_kube_gvk(&gvk);
        assert_eq!(kube_gvk.group, "apps");
        assert_eq!(kube_gvk.version, "v1");
        assert_eq!(kube_gvk.kind, "Deployment");
    }
}

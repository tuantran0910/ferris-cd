//! Deterministic `CustomResourceDefinition` manifest generation.
//!
//! The CRD YAML under `deploy/crds/` is a build artifact of this crate: it is generated
//! from the Rust types with `kube::CustomResourceExt` and committed so cluster installs
//! never depend on a running `ferriscd` binary. Generation is byte-deterministic —
//! serialization order comes from the type definitions and no timestamps or unordered
//! maps are involved — so drift is a pure string equality check.
//!
//! This module deliberately performs no I/O: it renders strings, and the CLI (or a test)
//! owns file access.

use std::path::{Path, PathBuf};

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::CustomResourceExt;

use crate::application::Application;
use crate::project::AppProject;

/// Repository-relative directory holding the generated CRD manifests.
pub const CRD_DIRECTORY: &str = "deploy/crds";

/// File name of the generated `Application` CRD.
pub const APPLICATION_CRD_FILE_NAME: &str = "applications.ferriscd.io.yaml";

/// File name of the generated `AppProject` CRD.
pub const APPPROJECT_CRD_FILE_NAME: &str = "appprojects.ferriscd.io.yaml";

/// One generated manifest, ready to be written to `<dir>/<file_name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdDocument {
    /// File name (never contains a directory separator).
    pub file_name: &'static str,
    /// Rendered YAML manifest.
    pub manifest: String,
}

impl CrdDocument {
    /// Returns the path of this document inside `dir`.
    #[must_use]
    pub fn path_in(&self, dir: &Path) -> PathBuf {
        dir.join(self.file_name)
    }
}

/// Failure while rendering a CRD manifest.
#[derive(Debug, thiserror::Error)]
pub enum CrdGenerationError {
    /// The CRD could not be converted to JSON (never expected; kept for completeness).
    #[error("failed to encode the {file} CRD as JSON: {source}")]
    Encode {
        /// File being rendered.
        file: &'static str,
        /// Underlying serialization error.
        #[source]
        source: serde_json::Error,
    },

    /// The CRD could not be rendered to YAML.
    #[error("failed to render the {file} CRD as YAML: {source}")]
    Render {
        /// File being rendered.
        file: &'static str,
        /// Underlying serialization error.
        #[source]
        source: serde_saphyr::SerializeError,
    },
}

/// Returns the generated `Application` CRD object.
#[must_use]
pub fn application_crd() -> CustomResourceDefinition {
    Application::crd()
}

/// Returns the generated `AppProject` CRD object.
#[must_use]
pub fn appproject_crd() -> CustomResourceDefinition {
    AppProject::crd()
}

/// Renders both CRD manifests in a stable order (`Application`, then `AppProject`).
pub fn crd_documents() -> Result<Vec<CrdDocument>, CrdGenerationError> {
    Ok(vec![
        CrdDocument {
            file_name: APPLICATION_CRD_FILE_NAME,
            manifest: render_crd(APPLICATION_CRD_FILE_NAME, &application_crd())?,
        },
        CrdDocument {
            file_name: APPPROJECT_CRD_FILE_NAME,
            manifest: render_crd(APPPROJECT_CRD_FILE_NAME, &appproject_crd())?,
        },
    ])
}

/// Renders a single CRD as YAML.
///
/// The server-populated `status` stanza is dropped so the committed manifest is a pure
/// input object.
pub fn render_crd(
    file_name: &'static str,
    crd: &CustomResourceDefinition,
) -> Result<String, CrdGenerationError> {
    let mut value = serde_json::to_value(crd).map_err(|source| CrdGenerationError::Encode {
        file: file_name,
        source,
    })?;
    if let Some(object) = value.as_object_mut() {
        object.remove("status");
    }
    serde_saphyr::to_string(&value).map_err(|source| CrdGenerationError::Render {
        file: file_name,
        source,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn parse_crd(manifest: &str) -> CustomResourceDefinition {
        serde_saphyr::from_str(manifest).expect("generated CRD must parse as YAML")
    }

    #[test]
    fn generated_documents_are_deterministic() {
        let first = crd_documents().expect("generation must succeed");
        let second = crd_documents().expect("generation must succeed");
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].file_name, APPLICATION_CRD_FILE_NAME);
        assert_eq!(first[1].file_name, APPPROJECT_CRD_FILE_NAME);

        let value: Value = serde_saphyr::from_str(&first[0].manifest).expect("manifest must parse");
        let metadata = value["metadata"]
            .as_object()
            .expect("metadata must be an object");
        assert_eq!(
            metadata.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["name"],
            "CRD manifests must not carry server-populated metadata"
        );
    }

    #[test]
    fn application_crd_is_structurally_complete() {
        let manifest = render_crd(APPLICATION_CRD_FILE_NAME, &application_crd())
            .expect("rendering must succeed");
        let value: Value = serde_saphyr::from_str(&manifest).expect("manifest must parse");
        assert_eq!(value["apiVersion"], "apiextensions.k8s.io/v1");
        assert_eq!(value["kind"], "CustomResourceDefinition");
        assert!(
            value.get("status").is_none(),
            "committed CRD must not carry a status"
        );

        let crd = parse_crd(&manifest);
        assert_eq!(crd.spec.group, "ferriscd.io");
        assert_eq!(crd.spec.scope, "Namespaced");
        assert_eq!(crd.spec.names.kind, "Application");
        assert_eq!(crd.spec.names.plural, "applications");
        assert_eq!(
            crd.spec.names.short_names.as_deref(),
            Some(&["app".to_owned(), "apps".to_owned()][..]),
            "`kubectl get app`/`kubectl get apps` must resolve to Application"
        );
        assert_eq!(
            crd.metadata.name.as_deref(),
            Some("applications.ferriscd.io")
        );
        assert!(
            crd.status.is_none(),
            "committed CRD must not carry a status"
        );

        assert_eq!(crd.spec.versions.len(), 1);
        let version = &crd.spec.versions[0];
        assert_eq!(version.name, "v1alpha1");
        assert!(version.served);
        assert!(version.storage);

        // Trap T2: the status subresource must be enabled, otherwise `patch_status`
        // silently rewrites the whole object (and bumps `metadata.generation`).
        let subresources = version
            .subresources
            .as_ref()
            .expect("Application CRD must declare subresources");
        assert!(
            subresources.status.is_some(),
            "Application CRD must enable the status subresource"
        );

        let columns = version
            .additional_printer_columns
            .as_ref()
            .expect("Application CRD must declare printer columns");
        let names: Vec<&str> = columns.iter().map(|column| column.name.as_str()).collect();
        assert_eq!(names, vec!["SYNC", "HEALTH", "REVISION", "AGE"]);
        let paths: Vec<&str> = columns
            .iter()
            .map(|column| column.json_path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                ".status.sync.status",
                ".status.health.status",
                ".status.sync.revision",
                ".metadata.creationTimestamp",
            ]
        );
        assert_eq!(columns[3].type_, "date");

        // The text-level YAML must really contain the subresource stanza.
        assert!(manifest.contains("subresources:"), "{manifest}");
        assert!(manifest.contains("status: {}"), "{manifest}");
    }

    #[test]
    fn application_crd_schema_bounds_revision_history_limit() {
        let value = serde_json::to_value(application_crd()).expect("crd must serialize");
        let limit = &value["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"]["revisionHistoryLimit"];
        assert_eq!(limit["minimum"].as_f64(), Some(1.0));
        assert_eq!(limit["maximum"].as_f64(), Some(20.0));
        assert_eq!(limit["type"], "integer");

        let sync_options = &value["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
            ["spec"]["properties"]["syncPolicy"]["properties"]["syncOptions"]["properties"];
        for option in [
            "pruneCRDs",
            "pruneNamespaces",
            "serverSideForce",
            "applyOutOfSyncOnly",
        ] {
            assert!(
                sync_options.get(option).is_some(),
                "generated schema is missing syncOptions.{option}"
            );
        }
    }

    #[test]
    fn appproject_crd_is_structurally_complete() {
        let manifest = render_crd(APPPROJECT_CRD_FILE_NAME, &appproject_crd())
            .expect("rendering must succeed");
        let crd = parse_crd(&manifest);

        assert_eq!(crd.spec.group, "ferriscd.io");
        assert_eq!(crd.spec.scope, "Namespaced");
        assert_eq!(crd.spec.names.kind, "AppProject");
        assert_eq!(crd.spec.names.plural, "appprojects");
        assert_eq!(
            crd.metadata.name.as_deref(),
            Some("appprojects.ferriscd.io")
        );

        let version = &crd.spec.versions[0];
        assert_eq!(version.name, "v1alpha1");
        assert!(version.served);
        assert!(version.storage);
        assert!(
            version
                .subresources
                .as_ref()
                .is_some_and(|subresources| subresources.status.is_some()),
            "AppProject CRD must enable the status subresource"
        );

        let value: Value = serde_json::to_value(&crd).expect("crd must serialize");
        let properties = &value["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"];
        for expected in [
            "sourceRepos",
            "sourceNamespaces",
            "destinations",
            "clusterResourceWhitelist",
            "namespaceResourceWhitelist",
            "namespaceResourceBlacklist",
            "allowedServiceAccounts",
        ] {
            assert!(
                properties.get(expected).is_some(),
                "generated schema is missing {expected}"
            );
        }
    }

    #[test]
    fn committed_manifests_match_generated_output() {
        let directory = repository_root().join(CRD_DIRECTORY);
        for document in crd_documents().expect("generation must succeed") {
            let path = document.path_in(&directory);
            let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "failed to read committed CRD manifest '{}': {error}",
                    path.display()
                )
            });
            assert_eq!(
                committed,
                document.manifest,
                "committed manifest '{}' drifted from the generated schema; run `ferriscd crd generate`",
                path.display()
            );
        }
    }
}

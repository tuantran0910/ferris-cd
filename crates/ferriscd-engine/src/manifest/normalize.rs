//! Offline manifest normalization.
//!
//! This stage runs before any cluster interaction, so it deliberately does **not**
//! inject `destination.namespace`: offline code cannot know whether a custom CRD is
//! cluster-scoped or namespaced (Finding H1). Cluster-aware scope normalization is
//! a separate, later stage.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kube::api::DynamicObject;
use serde_json::{Map, Value};

use super::error::ManifestError;
use super::types::{DesiredResource, ResourceKey};

/// Normalizes a set of desired resources in place and rejects duplicate GKNN keys.
///
/// * strips top-level `.status`,
/// * strips server-owned metadata fields,
/// * converts `v1/Secret.stringData` into base64 `.data` (stringData wins),
/// * rejects two resources with the same [`ResourceKey`] (both source files named).
///
/// # Errors
///
/// Returns [`ManifestError::DuplicateResourceKey`] on a GKNN collision and
/// [`ManifestError::Normalization`] on malformed Secret fields.
pub fn normalize(resources: Vec<DesiredResource>) -> Result<Vec<DesiredResource>, ManifestError> {
    let mut normalized = Vec::with_capacity(resources.len());
    for mut resource in resources {
        normalize_one(&mut resource)?;
        normalized.push(resource);
    }
    check_duplicate_keys(&normalized)?;
    Ok(normalized)
}

/// Rejects two resources sharing the same version-agnostic [`ResourceKey`].
///
/// Normalization calls this after stripping fields; `ferriscd apply` also calls it again
/// after cluster-aware namespace injection, which can create GKNN collisions that were
/// not present in the raw manifest set (e.g. a pre-namespaced object plus an injected one).
pub fn check_duplicate_keys<'a>(
    resources: impl IntoIterator<Item = &'a DesiredResource>,
) -> Result<(), ManifestError> {
    let mut seen: HashMap<ResourceKey, String> = HashMap::new();
    for resource in resources {
        if let Some(previous) = seen.get(&resource.key) {
            return Err(ManifestError::DuplicateResourceKey {
                key: resource.key.canonical(),
                file_a: previous.clone(),
                file_b: resource.source_file.clone(),
            });
        }
        seen.insert(resource.key.clone(), resource.source_file.clone());
    }
    Ok(())
}

fn normalize_one(resource: &mut DesiredResource) -> Result<(), ManifestError> {
    // Strip the top-level `.status` field from the dynamic payload.
    if let Some(map) = resource.object.data.as_object_mut() {
        map.remove("status");
    }

    // Strip server-managed metadata fields before diffing/applying.
    let metadata = &mut resource.object.metadata;
    metadata.uid = None;
    metadata.resource_version = None;
    metadata.generation = None;
    metadata.creation_timestamp = None;
    metadata.managed_fields = None;
    metadata.self_link = None;

    if resource.gvk.group.is_empty() && resource.gvk.kind == "Secret" {
        normalize_secret(&mut resource.object, &resource.source_file)?;
    }

    Ok(())
}

/// Merges base64-encoded `stringData` into `.data` and removes `stringData`.
///
/// `stringData` entries take precedence over same-named `.data` entries, matching
/// the Kubernetes API server's write-only semantics.
fn normalize_secret(object: &mut DynamicObject, source_file: &str) -> Result<(), ManifestError> {
    let Some(root) = object.data.as_object_mut() else {
        return Ok(());
    };

    let Some(string_data) = root.get("stringData") else {
        return Ok(());
    };

    let string_data = string_data
        .as_object()
        .ok_or_else(|| ManifestError::Normalization {
            file: source_file.to_owned(),
            message: "Secret.stringData must be a mapping".to_owned(),
        })?;

    // `data` must be a mapping when present; otherwise start from an empty map.
    let mut data = match root.get("data") {
        Some(existing) => {
            existing
                .as_object()
                .cloned()
                .ok_or_else(|| ManifestError::Normalization {
                    file: source_file.to_owned(),
                    message: "Secret.data must be a mapping".to_owned(),
                })?
        }
        None => Map::new(),
    };

    for (key, value) in string_data {
        let plaintext = value.as_str().ok_or_else(|| ManifestError::Normalization {
            file: source_file.to_owned(),
            message: format!("Secret.stringData[{key}] must be a string"),
        })?;
        // stringData wins over any pre-existing `.data` entry with the same key.
        data.insert(
            key.clone(),
            Value::String(STANDARD.encode(plaintext.as_bytes())),
        );
    }

    root.remove("stringData");
    if !data.is_empty() {
        root.insert("data".to_owned(), Value::Object(data));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::manifest::types::GroupVersionKind;

    fn secret() -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "app-secret",
                "uid": "should-be-removed",
                "resourceVersion": "123",
                "generation": 2,
                "creationTimestamp": "2026-01-01T00:00:00Z",
                "managedFields": [{"manager": "kubectl"}],
                "selfLink": "/api/v1/namespaces/default/secrets/app-secret"
            },
            "data": {
                "keep": "a2VlcC12YWx1ZQ==",
                "overridden": "b2xkLXZhbHVl"
            },
            "stringData": {
                "overridden": "new-value",
                "added": "plain-text"
            },
            "status": {
                "phase": "Active"
            }
        }))
        .expect("valid DynamicObject")
    }

    fn resource(object: DynamicObject) -> DesiredResource {
        let name = object.metadata.name.clone().expect("name");
        let namespace = object.metadata.namespace.clone();
        DesiredResource {
            key: ResourceKey::new("", "Secret", namespace, name),
            gvk: GroupVersionKind::parse("v1", "Secret").expect("parse"),
            object,
            source_file: "secrets.yaml".to_owned(),
        }
    }

    #[test]
    fn string_data_wins_and_is_base64_encoded_then_removed() {
        let normalized = normalize(vec![resource(secret())]).expect("normalize");

        let data = normalized[0]
            .object
            .data
            .get("data")
            .and_then(Value::as_object)
            .expect("data map");

        // Pre-existing data entry preserved.
        assert_eq!(
            data.get("keep").and_then(Value::as_str),
            Some("a2VlcC12YWx1ZQ==")
        );
        // stringData overrides same-named `.data` entry and is base64 encoded.
        assert_eq!(
            data.get("overridden").and_then(Value::as_str),
            Some("bmV3LXZhbHVl")
        );
        // New stringData entry is base64 encoded.
        assert_eq!(
            data.get("added").and_then(Value::as_str),
            Some("cGxhaW4tdGV4dA==")
        );
        // stringData is removed.
        assert!(
            normalized[0].object.data.get("stringData").is_none(),
            "stringData must be removed"
        );
    }

    #[test]
    fn strips_status_and_server_metadata() {
        let normalized = normalize(vec![resource(secret())]).expect("normalize");

        assert!(normalized[0].object.data.get("status").is_none());
        let metadata = &normalized[0].object.metadata;
        assert!(metadata.uid.is_none());
        assert!(metadata.resource_version.is_none());
        assert!(metadata.generation.is_none());
        assert!(metadata.creation_timestamp.is_none());
        assert!(metadata.managed_fields.is_none());
        assert!(metadata.self_link.is_none());
    }

    #[test]
    fn duplicate_gknn_names_both_source_files() {
        let mut first = resource(secret());
        first.source_file = "a.yaml".to_owned();
        let mut second = resource(secret());
        second.source_file = "b.yaml".to_owned();

        let err = normalize(vec![first, second]).expect_err("duplicate key must fail");
        let text = err.to_string();
        assert!(text.contains("a.yaml"), "{text}");
        assert!(text.contains("b.yaml"), "{text}");
        assert!(text.contains("/Secret/"), "{text}");
        assert!(!err.is_retryable());
    }

    #[test]
    fn distinct_namespaces_are_not_duplicates() {
        let mut first = resource(secret());
        first.object.metadata.namespace = Some("ns-a".to_owned());
        first.key.namespace = Some("ns-a".to_owned());

        let mut second = resource(secret());
        second.object.metadata.namespace = Some("ns-b".to_owned());
        second.key.namespace = Some("ns-b".to_owned());

        let normalized = normalize(vec![first, second]).expect("distinct namespaces");
        assert_eq!(normalized.len(), 2);
    }
}

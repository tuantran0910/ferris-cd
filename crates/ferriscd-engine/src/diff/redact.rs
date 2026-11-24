//! Mandatory `Secret` redaction (trap T4 / Security).
//!
//! A Server-Side Apply `dryRun=All` response is a **full live object**, so for a `v1/Secret`
//! it contains every base64 value in `.data` (and any `.stringData` the caller supplied).
//! Without redaction, plaintext credentials leak into diff previews, controller logs, and the
//! `GET /diff` API response.
//!
//! The redactor replaces every value in `.data` and `.stringData` with
//!
//! ```text
//! ***REDACTED(sha256:<first-8-hex>)***
//! ```
//!
//! Hashing the value (instead of a constant placeholder) is what keeps redacted diffs
//! *useful*: an unchanged key produces an identical placeholder on both sides and the
//! resource stays `Synced`, while a changed key produces a different placeholder and the
//! resource reports `OutOfSync` — without either side ever holding the plaintext.
//!
//! [`redact_document`] is invoked by [`ResourceDiff::compare`](crate::diff::ResourceDiff::compare)
//! *before* the field diff runs, so a `ResourceDiff` can never be constructed from unredacted
//! `Secret` payloads (see `redact::tests` for the leakage assertions).
//!
//! # Finding H1: `kubectl.kubernetes.io/last-applied-configuration`
//!
//! `.data` is not the only place a `Secret` payload hides. `kubectl apply` stores the **whole
//! applied document** — base64 `.data` included — in the
//! [`LAST_APPLIED_CONFIGURATION_ANNOTATION`] annotation, so a redactor that only walked `.data`
//! still handed the entire `Secret` to every diff preview and log line. That annotation embeds
//! a document of *any* kind (a `ConfigMap`, a `Deployment`, anything a kubectl user applied), so
//! it is fingerprinted for every kind, not just for `v1/Secret`.
//!
//! # Which identity decides
//!
//! [`redact_document`] reads `apiVersion`/`kind` from the object itself and only falls back to
//! the caller's `ResourceKey` when the document carries no identity. A `ResourceKey` built from
//! a mis-grouped manifest would otherwise silently disable redaction; the object's own identity
//! (or, failing that, the key) keeps it redacted either way.
//!
//! Note the deliberate limitation: the fingerprint is a truncated digest of the *observed*
//! value, so it reveals "changed" vs "unchanged" plus a 32-bit digest prefix. It is a diff
//! fingerprint, never a password hash, and must not be used to derive or verify secrets.

use serde_json::Value;

use crate::diff::sha256;

/// Prefix of a redacted value.
pub const REDACTION_PREFIX: &str = "***REDACTED(sha256:";

/// Suffix of a redacted value.
pub const REDACTION_SUFFIX: &str = ")***";

/// Number of hexadecimal digest characters kept in a redacted value.
pub const FINGERPRINT_HEX_CHARS: usize = 8;

/// Fields whose values are secret: every entry in both maps is redacted.
pub const SECRET_VALUE_FIELDS: [&str; 2] = ["data", "stringData"];

/// The annotation `kubectl apply` uses to stash the whole applied document (finding H1).
///
/// Its value is a JSON document — for a `Secret` that means every base64 value in `.data` — so
/// it must be redacted for **every** kind, not only for `v1/Secret`.
pub const LAST_APPLIED_CONFIGURATION_ANNOTATION: &str =
    "kubectl.kubernetes.io/last-applied-configuration";

/// Returns whether `group`/`kind` identifies a `v1/Secret` (the only redacted kind).
#[must_use]
pub fn is_secret(group: &str, kind: &str) -> bool {
    group.is_empty() && kind == "Secret"
}

/// Returns the deterministic fingerprint of `raw` (the first
/// [`FINGERPRINT_HEX_CHARS`] hex characters of its SHA-256 digest).
///
/// `raw` is the value exactly as it appears in the object: the base64 text for `.data`, the
/// literal for `.stringData`. Hashing the encoded form keeps the fingerprint stable across a
/// `stringData` -> `data` normalization round trip only if the values agree, which is the
/// behaviour a diff wants.
#[must_use]
pub fn fingerprint(raw: &str) -> String {
    sha256::hex_digest_prefix(raw.as_bytes(), FINGERPRINT_HEX_CHARS)
}

/// Returns the redacted placeholder for `raw`.
#[must_use]
pub fn redacted_value(raw: &str) -> String {
    format!("{REDACTION_PREFIX}{}{REDACTION_SUFFIX}", fingerprint(raw))
}

/// Replaces every value in `.data` and `.stringData` with its redacted placeholder.
///
/// Returns the number of values that were replaced. A missing, `null`, or non-object
/// `.data`/`.stringData` is a no-op: redaction never fails and never rejects an object, it
/// only removes the payload (a malformed `Secret` must not break a reconcile).
pub fn redact_secret(object: &mut Value) -> usize {
    let mut redacted = 0;
    for field in SECRET_VALUE_FIELDS {
        let Some(Value::Object(values)) = object.get_mut(field) else {
            continue;
        };
        for value in values.values_mut() {
            // A non-string entry is not a legal `Secret` value, but it must still be
            // redacted rather than passed through: use its compact JSON text as the input.
            let raw = match &*value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            *value = Value::String(redacted_value(&raw));
            redacted += 1;
        }
    }
    redacted
}

/// Returns the `(group, kind)` a document claims for itself.
///
/// `None` unless both `apiVersion` and a non-empty `kind` are present as strings. The group is
/// the `apiVersion` prefix (`apps/v1` -> `apps`, `v1` -> the core group `""`).
#[must_use]
pub fn object_identity(object: &Value) -> Option<(String, String)> {
    let kind = object.get("kind")?.as_str()?;
    if kind.is_empty() {
        return None;
    }
    let api_version = object.get("apiVersion")?.as_str()?;
    let group = api_version
        .split_once('/')
        .map_or("", |(group, _version)| group);
    Some((group.to_owned(), kind.to_owned()))
}

/// Replaces the `last-applied-configuration` annotation of `object` with its fingerprint.
///
/// Returns the number of annotations that were replaced (`0` when absent). Redaction is
/// hash-based, so the annotation still reports *whether* it changed without exposing the applied
/// document it embeds (finding H1).
pub fn redact_last_applied_annotation(object: &mut Value) -> usize {
    let Some(Value::Object(annotations)) = object
        .get_mut("metadata")
        .and_then(|metadata| metadata.get_mut("annotations"))
    else {
        return 0;
    };
    let Some(value) = annotations.get_mut(LAST_APPLIED_CONFIGURATION_ANNOTATION) else {
        return 0;
    };
    let raw = match &*value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    *value = Value::String(redacted_value(&raw));
    1
}

/// Redacts `object` for the given `group`/`kind`: the `v1/Secret` payload when it is one, plus
/// the [`LAST_APPLIED_CONFIGURATION_ANNOTATION`] annotation for every kind.
///
/// Returns the number of redacted values.
pub fn redact_object(group: &str, kind: &str, object: &mut Value) -> usize {
    let mut redacted = if is_secret(group, kind) {
        redact_secret(object)
    } else {
        0
    };
    redacted += redact_last_applied_annotation(object);
    redacted
}

/// Redacts one object **document** as it is about to be compared.
///
/// The identity is taken from the document's own `apiVersion`/`kind` and only falls back to the
/// caller's `(fallback_group, fallback_kind)` (the `ResourceKey` of the desired resource) when the
/// document carries none — `DynamicObject::data` used to be handed to the comparison without any
/// identity at all, which is how a mis-grouped key could disable redaction. Redaction is also
/// applied when *either* identity says `v1/Secret`, so a key/object disagreement redacts rather
/// than leaks.
///
/// Returns the number of redacted values.
pub fn redact_document(object: &mut Value, fallback_group: &str, fallback_kind: &str) -> usize {
    let identity = object_identity(object);
    let (group, kind) = identity
        .as_ref()
        .map_or((fallback_group, fallback_kind), |(group, kind)| {
            (group.as_str(), kind.as_str())
        });
    let mut redacted = if is_secret(group, kind) || is_secret(fallback_group, fallback_kind) {
        redact_secret(object)
    } else {
        0
    };
    redacted += redact_last_applied_annotation(object);
    redacted
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::diff::ignore::IgnoreRuleSet;
    use crate::diff::types::{ChangeKind, DiffStatus, ResourceDiff};
    use crate::manifest::ResourceKey;

    fn secret_key() -> ResourceKey {
        ResourceKey::new("", "Secret", Some("payments".to_owned()), "creds")
    }

    fn secret(data: Value) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "creds", "namespace": "payments" },
            "type": "Opaque",
            "data": data,
        })
    }

    #[test]
    fn redaction_replaces_every_data_and_string_data_value() {
        let mut object = secret(json!({ "username": "YWRtaW4=", "password": "czNjcjN0IQ==" }));
        object["stringData"] = json!({ "token": "plain-token" });

        assert_eq!(redact_secret(&mut object), 3);
        for (field, key) in [
            ("data", "username"),
            ("data", "password"),
            ("stringData", "token"),
        ] {
            let value = object[field][key].as_str().unwrap_or_default().to_owned();
            assert!(
                value.starts_with(REDACTION_PREFIX),
                "every value must be redacted: {value}"
            );
            assert!(value.ends_with(REDACTION_SUFFIX), "{value}");
        }
        let serialized = object.to_string();
        for leaked in ["YWRtaW4=", "czNjcjN0IQ==", "admin", "plain-token"] {
            assert!(
                !serialized.contains(leaked),
                "the serialized Secret must not contain {leaked}: {serialized}"
            );
        }
    }

    #[test]
    fn fingerprints_are_deterministic_and_differ_per_value() {
        assert_eq!(fingerprint("same"), fingerprint("same"));
        assert_ne!(fingerprint("same"), fingerprint("different"));
        assert_eq!(fingerprint("same").len(), FINGERPRINT_HEX_CHARS);
        assert!(fingerprint("same").chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(redacted_value("same"), redacted_value("same"));
        assert!(redacted_value("same").contains("sha256:"));
    }

    #[test]
    fn redaction_tolerates_missing_and_malformed_data() {
        let mut object = json!({ "apiVersion": "v1", "kind": "Secret" });
        assert_eq!(redact_secret(&mut object), 0, "a missing .data is a no-op");

        let mut null_data = json!({ "kind": "Secret", "data": null });
        assert_eq!(redact_secret(&mut null_data), 0);

        let mut scalar_data = json!({ "kind": "Secret", "data": "not-a-map" });
        assert_eq!(redact_secret(&mut scalar_data), 0);

        // Non-string entries are still removed from the object.
        let mut odd = json!({ "data": { "port": 5432 } });
        assert_eq!(redact_secret(&mut odd), 1);
        assert!(
            odd["data"]["port"]
                .as_str()
                .is_some_and(|value| value.starts_with(REDACTION_PREFIX)),
            "a non-string value must be redacted too: {odd}"
        );
    }

    #[test]
    fn only_core_v1_secrets_are_redacted() {
        assert!(is_secret("", "Secret"));
        assert!(!is_secret("", "ConfigMap"));
        assert!(!is_secret("example.com", "Secret"));

        let mut config_map = json!({ "data": { "config.yaml": "debug: true" } });
        assert_eq!(redact_object("", "ConfigMap", &mut config_map), 0);
        assert_eq!(
            config_map["data"]["config.yaml"], "debug: true",
            "a ConfigMap must never be redacted: its values are part of the diff"
        );

        let mut secret = secret(json!({ "k": "v" }));
        assert_eq!(redact_object("", "Secret", &mut secret), 1);
    }

    /// The `(group, kind)` a document claims for itself.
    #[test]
    fn object_identity_reads_api_version_and_kind() {
        assert_eq!(
            object_identity(&json!({ "apiVersion": "v1", "kind": "Secret" })),
            Some((String::new(), "Secret".to_owned()))
        );
        assert_eq!(
            object_identity(&json!({ "apiVersion": "apps/v1", "kind": "Deployment" })),
            Some(("apps".to_owned(), "Deployment".to_owned()))
        );
        assert_eq!(object_identity(&json!({ "kind": "Secret" })), None);
        assert_eq!(object_identity(&json!({ "apiVersion": "v1" })), None);
        assert_eq!(
            object_identity(&json!({ "apiVersion": "v1", "kind": "" })),
            None
        );
        assert_eq!(
            object_identity(&json!({ "apiVersion": 1, "kind": "Secret" })),
            None
        );
    }

    /// Finding H1 (second half): redaction follows the object's own `apiVersion`/`kind`, so a
    /// mis-grouped `ResourceKey` cannot silently disable it — and the key is still the fallback
    /// when the document carries no identity at all.
    #[test]
    fn redaction_follows_the_documents_identity_with_the_key_as_fallback() {
        const ENCODED: &str = "czNjcjN0LXBAc3N3MHJk";

        // A key that does *not* identify a core Secret (a mis-grouped manifest).
        let mis_grouped = ResourceKey::new(
            "example.com",
            "Secret",
            Some("payments".to_owned()),
            "creds".to_owned(),
        );
        assert!(!is_secret(&mis_grouped.group, &mis_grouped.kind));

        let live = secret(json!({ "password": ENCODED }));
        let predicted = secret(json!({ "password": "ZGlmZmVyZW50" }));
        let diff =
            ResourceDiff::compare(&mis_grouped, &live, &predicted, &IgnoreRuleSet::default());
        assert_eq!(diff.status(), &DiffStatus::OutOfSync);
        let rendered = format!("{diff:?}");
        assert!(
            !rendered.contains(ENCODED) && !rendered.contains("ZGlmZmVyZW50"),
            "the object's own identity must drive redaction: {rendered}"
        );
        assert!(
            rendered.contains(REDACTION_PREFIX),
            "the recorded value must be a fingerprint: {rendered}"
        );

        // The key is still required to redact when the document carries no identity.
        let mut anonymous = json!({ "data": { "password": ENCODED } });
        assert_eq!(object_identity(&anonymous), None);
        assert_eq!(redact_document(&mut anonymous, "", "Secret"), 1);
        assert!(
            !anonymous.to_string().contains(ENCODED),
            "the key must still be the fallback: {anonymous}"
        );

        // A key/object disagreement redacts rather than leaking.
        let mut disagreed = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "data": { "password": ENCODED },
        });
        assert_eq!(redact_document(&mut disagreed, "", "Secret"), 1);
        assert!(!disagreed.to_string().contains(ENCODED));
    }

    /// Finding H1: `kubectl.kubernetes.io/last-applied-configuration` embeds a whole document for
    /// *any* kind, so it is fingerprinted even for a non-`Secret`.
    #[test]
    fn the_last_applied_configuration_annotation_is_redacted_for_every_kind() {
        let embedded =
            r#"{"apiVersion":"v1","kind":"ConfigMap","data":{"token":"secret-inside-annotation"}}"#;
        let mut config_map = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "annotations": {
                "example.com/keep": "visible",
                LAST_APPLIED_CONFIGURATION_ANNOTATION: embedded,
            } },
            "data": { "token": "plain-text-token" },
        });

        assert_eq!(
            redact_object("", "ConfigMap", &mut config_map),
            1,
            "only the annotation is redacted for a non-Secret"
        );
        let annotation = config_map["metadata"]["annotations"]
            [LAST_APPLIED_CONFIGURATION_ANNOTATION]
            .as_str()
            .unwrap_or_default();
        assert!(annotation.starts_with(REDACTION_PREFIX), "{annotation}");
        assert!(
            !config_map.to_string().contains("secret-inside-annotation"),
            "the embedded document must be gone: {config_map}"
        );
        assert_eq!(
            config_map["data"]["token"],
            json!("plain-text-token"),
            "a ConfigMap's own data stays readable"
        );
        assert_eq!(
            config_map["metadata"]["annotations"]["example.com/keep"],
            json!("visible"),
            "other annotations must survive"
        );

        // A missing annotation (or a non-object `metadata`) is a no-op.
        let mut untouched = json!({ "metadata": { "name": "x" } });
        assert_eq!(redact_last_applied_annotation(&mut untouched), 0);
        assert_eq!(untouched, json!({ "metadata": { "name": "x" } }));
        let mut scalar_metadata = json!({ "metadata": "nope" });
        assert_eq!(redact_last_applied_annotation(&mut scalar_metadata), 0);

        // The fingerprint is stable, so an unchanged annotation stays `Synced`.
        let annotated = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "annotations": {
                LAST_APPLIED_CONFIGURATION_ANNOTATION: embedded,
            } },
        });
        let diff = ResourceDiff::compare(
            &ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings"),
            &annotated,
            &annotated,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(diff.status(), &DiffStatus::Synced);
    }

    /// T07.3 verification (1): a changed `Secret` key still marks the resource `OutOfSync`,
    /// even though neither side's value survives redaction.
    #[test]
    fn a_changed_secret_key_is_out_of_sync() {
        let live = secret(json!({ "username": "YWRtaW4=", "password": "b2xk" }));
        let predicted = secret(json!({ "username": "YWRtaW4=", "password": "bmV3" }));

        let diff =
            ResourceDiff::compare(&secret_key(), &live, &predicted, &IgnoreRuleSet::default());

        assert_eq!(diff.status(), &DiffStatus::OutOfSync);
        let changed: Vec<&str> = diff
            .changes()
            .iter()
            .map(|change| change.path.as_str())
            .collect();
        assert_eq!(
            changed,
            vec!["/data/password"],
            "only the changed key must be reported"
        );
        assert_eq!(diff.changes()[0].kind, ChangeKind::Modified);
    }

    /// T07.3 verification (2): an unchanged `Secret` is `Synced`.
    #[test]
    fn an_unchanged_secret_is_synced() {
        let live = secret(json!({ "username": "YWRtaW4=" }));
        let predicted = secret(json!({ "username": "YWRtaW4=" }));
        let diff =
            ResourceDiff::compare(&secret_key(), &live, &predicted, &IgnoreRuleSet::default());
        assert_eq!(diff.status(), &DiffStatus::Synced);
        assert!(diff.changes().is_empty());
    }

    /// T07.3 verification (3): the raw value, its base64 encoding, and the plaintext never
    /// appear in `Debug`, `Display`, or the JSON serialization of the diff.
    #[test]
    fn secret_values_never_appear_in_debug_display_or_json() {
        const PLAINTEXT: &str = "s3cr3t-p@ssw0rd";
        // base64("s3cr3t-p@ssw0rd")
        const ENCODED: &str = "czNjcjN0LXBAc3N3MHJk";

        let live = secret(json!({ "password": ENCODED }));
        let predicted = secret(json!({ "password": "ZGlmZmVyZW50" }));
        let diff =
            ResourceDiff::compare(&secret_key(), &live, &predicted, &IgnoreRuleSet::default());

        let representations = [
            format!("{diff:?}"),
            format!("{diff}"),
            serde_json::to_string(&diff).expect("the diff must serialize"),
        ];
        for representation in representations {
            for leaked in [PLAINTEXT, ENCODED, "ZGlmZmVyZW50"] {
                assert!(
                    !representation.contains(leaked),
                    "a secret value leaked into the diff: {representation}"
                );
            }
        }

        // `Debug` and the JSON form carry the change values, so they must show the marker
        // (proving the recorded value is the placeholder, not the payload). `Display` is a
        // count-only one-liner and carries no values at all.
        for representation in [
            format!("{diff:?}"),
            serde_json::to_string(&diff).expect("json"),
        ] {
            assert!(
                representation.contains("REDACTED"),
                "the redaction marker must remain visible: {representation}"
            );
            assert!(
                !representation.contains(ENCODED),
                "the base64 value must be gone: {representation}"
            );
        }
        assert!(!diff.to_string().contains("REDACTED"));
    }

    /// A `stringData` payload is redacted exactly like `.data` (both may be present).
    #[test]
    fn string_data_is_redacted_as_well() {
        let mut live = secret(json!({ "password": "b2xk" }));
        live["stringData"] = json!({ "password": "old-plain" });
        let mut predicted = secret(json!({ "password": "b2xk" }));
        predicted["stringData"] = json!({ "password": "new-plain" });

        let diff =
            ResourceDiff::compare(&secret_key(), &live, &predicted, &IgnoreRuleSet::default());
        assert_eq!(diff.status(), &DiffStatus::OutOfSync);
        assert_eq!(
            diff.changes()
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/stringData/password"]
        );
        let json = serde_json::to_string(&diff).expect("serialize");
        assert!(
            !json.contains("old-plain") && !json.contains("new-plain"),
            "{json}"
        );
    }
}

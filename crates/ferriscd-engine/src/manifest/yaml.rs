//! Multi-document YAML 1.2 parsing, `v1/List` flattening, and Kubernetes object
//! validation.
//!
//! # Why not `serde_saphyr::from_multiple`?
//!
//! `serde_saphyr::from_multiple` silently skips null/empty documents, which makes
//! it impossible to report an accurate **1-based document index** for validation
//! errors in a stream that mixes real and empty documents. We therefore:
//!
//! 1. run the public whole-stream [`serde_saphyr::budget::check_yaml_budget`] pass
//!    so budgets (aliases/depth/nodes/bytes/documents) are enforced over the entire
//!    file exactly like `from_multiple` would,
//! 2. split documents on column-0 `---` markers (document starts), and
//! 3. parse each document individually with [`serde_saphyr::from_str_with_options`].
//!
//! Splitting only treats a line starting at column 0 with `---` followed by
//! whitespace, a comment, or end-of-line as a marker. In valid YAML, block-scalar
//! and plain-scalar continuation lines are always indented, so they can never
//! start a column-0 `---`; the documented limitation is a pathological multi-line
//! quoted scalar whose continuation happens to begin with `---` at column 0, which
//! is rejected (fail-closed) rather than silently mis-parsed.

use kube::api::DynamicObject;
use serde_json::{Map, Value};

use super::error::ManifestError;
use super::types::{DesiredResource, GroupVersionKind, ResourceKey};

/// Maximum replayed alias events during deserialization (anti billion-laughs).
const MAX_REPLAYED_EVENTS: usize = 10_000;
/// Maximum alias replay stack depth.
const MAX_REPLAY_STACK_DEPTH: usize = 32;
/// Maximum expansions of any single anchor.
const MAX_EXPANSIONS_PER_ANCHOR: usize = 100;

/// Returns the whole-stream YAML budget.
///
/// Structural limits (aliases/anchors/nodes/depth/bytes/documents) use the parser's
/// library defaults so legitimate vendored CRD bundles are not rejected by FerrisCD's
/// own tightening. The bomb defense is the alias-replay limits below, which operate on
/// expanded events rather than raw token counts.
fn whole_stream_budget() -> serde_saphyr::Budget {
    serde_saphyr::Budget::default()
}

/// Returns per-document deserialization options: duplicate-key rejection,
/// YAML 1.2 scalar semantics, and tight alias-replay limits.
pub(crate) fn parse_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        strict_booleans: true,
        leading_zero_numbers_as_strings: true,
        with_snippet: false,
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: MAX_REPLAYED_EVENTS,
            max_replay_stack_depth: MAX_REPLAY_STACK_DEPTH,
            max_alias_expansions_per_anchor: MAX_EXPANSIONS_PER_ANCHOR,
        },
    }
}

/// Why an operator-supplied YAML document was refused by [`parse_document`].
///
/// Deliberately **content-free**: the document may itself be a credential (the kubeconfig of a
/// `ferriscd.io/secret-type=cluster` `Secret`, `T13.1`), and a YAML parser error routinely quotes
/// the offending line — which would be the token or the private key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum YamlGuardError {
    /// A whole-document parser budget (aliases, anchors, nodes, depth, bytes, documents) was
    /// exceeded. The breached limit is named; the document is not.
    #[error("the document exceeds a YAML parser budget: {limit}")]
    Budget {
        /// Which budget was breached.
        limit: String,
    },

    /// The document is not valid YAML for the requested type.
    #[error("the document is not valid YAML for the requested type")]
    Parse,
}

/// Parses a **single** YAML document into `T` under FerrisCD's own parser budgets.
///
/// This is the guarded entry point for YAML that does not come from a rendered manifest but is
/// still written by whoever can create an object in the cluster — today the kubeconfig carried by
/// a `ferriscd.io/secret-type=cluster` `Secret` (`T13.1`). It applies exactly the defenses the
/// render pipeline applies: the whole-stream [`serde_saphyr::budget::check_yaml_budget`] pass plus
/// [`parse_options`] (duplicate-key rejection, YAML 1.2 scalars, and the alias-replay limits). A
/// billion-laughs bomb in a `Secret` would otherwise expand on the controller's watch task and
/// exhaust its memory — the same trap `T03.2` guards a rendered manifest against.
///
/// # Errors
///
/// [`YamlGuardError`] — never a message quoting the document, because the input may be a
/// credential.
pub fn parse_document<T>(document: &str) -> Result<T, YamlGuardError>
where
    T: serde::de::DeserializeOwned,
{
    let report = serde_saphyr::budget::check_yaml_budget(
        document,
        whole_stream_budget(),
        serde_saphyr::budget::EnforcingPolicy::AllContent,
    )
    .map_err(|_| YamlGuardError::Parse)?;
    if let Some(breach) = report.breached {
        return Err(YamlGuardError::Budget {
            limit: format!("{breach:?}"),
        });
    }
    serde_saphyr::from_str_with_options(document, parse_options())
        .map_err(|_| YamlGuardError::Parse)
}

/// Parses a single manifest file into zero or more validated [`DesiredResource`]s.
///
/// # Errors
///
/// Returns a terminal [`ManifestError`] naming `source_file` and (where applicable)
/// the 1-based document index.
pub fn parse_file(
    source_file: &str,
    contents: &str,
) -> Result<Vec<DesiredResource>, ManifestError> {
    // Whole-stream budget enforcement, matching `from_multiple` semantics.
    let report = serde_saphyr::budget::check_yaml_budget(
        contents,
        whole_stream_budget(),
        serde_saphyr::budget::EnforcingPolicy::AllContent,
    )
    .map_err(|err| ManifestError::YamlParse {
        file: source_file.to_owned(),
        doc: 1,
        message: err.to_string(),
    })?;
    if let Some(breach) = report.breached {
        return Err(ManifestError::YamlBudget {
            file: source_file.to_owned(),
            message: format!("{breach:?}"),
        });
    }

    let options = parse_options();
    let mut documents: Vec<(usize, Value)> = Vec::new();
    for (doc, body) in split_yaml_documents(contents) {
        let body = strip_leading_doc_marker(body);
        let value: Option<Value> = serde_saphyr::from_str_with_options(body, options.clone())
            .map_err(|err| ManifestError::YamlParse {
                file: source_file.to_owned(),
                doc,
                message: err.to_string(),
            })?;
        if let Some(value) = value
            && !value.is_null()
        {
            documents.push((doc, value));
        }
    }

    let mut resources = Vec::new();
    for (doc, value) in flatten_documents(source_file, documents)? {
        resources.push(build_resource(source_file, doc, value)?);
    }
    Ok(resources)
}

/// Recursively flattens `v1/List` and typed `*List` wrappers into their items.
///
/// A list kind without an `items` array is a clear error rather than a silent drop
/// (core `List`) or a confusing "missing metadata.name" validation (typed `*List`).
fn flatten_documents(
    source_file: &str,
    documents: Vec<(usize, Value)>,
) -> Result<Vec<(usize, Value)>, ManifestError> {
    let mut flattened = Vec::new();
    for (doc, value) in documents {
        flatten_into(source_file, doc, value, &mut flattened)?;
    }
    Ok(flattened)
}

fn flatten_into(
    source_file: &str,
    doc: usize,
    value: Value,
    out: &mut Vec<(usize, Value)>,
) -> Result<(), ManifestError> {
    if let Some(object) = value.as_object() {
        let kind = object.get("kind").and_then(Value::as_str);
        if let Some(kind) = kind
            && (kind == "List" || kind.ends_with("List"))
        {
            let items = object
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    validation_error(
                        source_file,
                        doc,
                        format!("kind '{kind}' requires an 'items' array"),
                    )
                })?;
            for item in items {
                flatten_into(source_file, doc, item.clone(), out)?;
            }
            return Ok(());
        }
    }
    out.push((doc, value));
    Ok(())
}

/// Validates one flattened object and converts it into a [`DesiredResource`].
fn build_resource(
    source_file: &str,
    doc: usize,
    value: Value,
) -> Result<DesiredResource, ManifestError> {
    let object = value.as_object().ok_or_else(|| {
        validation_error(
            source_file,
            doc,
            "document root must be a mapping (object), not a scalar or sequence",
        )
    })?;

    let api_version = required_string(object, "apiVersion", source_file, doc)?;
    let kind = required_string(object, "kind", source_file, doc)?;

    let gvk = GroupVersionKind::parse(api_version, kind).ok_or_else(|| {
        validation_error(
            source_file,
            doc,
            format!("invalid apiVersion '{api_version}'"),
        )
    })?;

    let metadata = object
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| validation_error(source_file, doc, "metadata must be a mapping"))?;

    let name = resolve_object_name(metadata, source_file, doc)?;
    let namespace = extract_namespace(metadata, source_file, doc)?;

    let key = ResourceKey::new(gvk.group.clone(), gvk.kind.clone(), namespace, name);

    let object: DynamicObject =
        serde_json::from_value(value).map_err(|err| ManifestError::Validation {
            file: source_file.to_owned(),
            doc,
            message: format!("failed to convert manifest into a Kubernetes object: {err}"),
        })?;

    Ok(DesiredResource {
        key,
        gvk,
        object,
        source_file: source_file.to_owned(),
    })
}

/// Extracts a required non-empty string field, mapping failure to a validation error.
fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    source_file: &str,
    doc: usize,
) -> Result<&'a str, ManifestError> {
    non_empty_str(object.get(field)).ok_or_else(|| {
        validation_error(
            source_file,
            doc,
            format!("{field} must be present and non-empty"),
        )
    })
}

/// Resolves the object name: `metadata.name`, or `metadata.generateName` when (and only
/// when) the resource carries the `ferriscd.io/hook` annotation.
///
/// Surrounding whitespace is rejected rather than trimmed: a GitOps engine must not
/// silently rename an object whose manifest author typed ` name: " app " `.
fn resolve_object_name(
    metadata: &Map<String, Value>,
    source_file: &str,
    doc: usize,
) -> Result<String, ManifestError> {
    const MISSING_NAME: &str =
        "metadata.name is required (or metadata.generateName on hook resources)";

    if metadata.contains_key("name") {
        return reject_padded_string(
            metadata.get("name"),
            "metadata.name",
            source_file,
            doc,
            MISSING_NAME,
        );
    }

    if let Some(generate_name) = metadata.get("generateName") {
        let generate_name = reject_padded_string(
            Some(generate_name),
            "metadata.generateName",
            source_file,
            doc,
            MISSING_NAME,
        )?;
        if has_hook_annotation(metadata) {
            return Ok(generate_name);
        }
        return Err(validation_error(
            source_file,
            doc,
            "metadata.generateName is only allowed on resources annotated with \
             'ferriscd.io/hook'",
        ));
    }

    Err(validation_error(source_file, doc, MISSING_NAME))
}

/// Extracts `metadata.namespace`, rejecting surrounding whitespace while treating an
/// empty or whitespace-only value as "not set" (matching the prior loader behavior).
fn extract_namespace(
    metadata: &Map<String, Value>,
    source_file: &str,
    doc: usize,
) -> Result<Option<String>, ManifestError> {
    let Some(value) = metadata.get("namespace") else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(validation_error(
            source_file,
            doc,
            "metadata.namespace must be a string",
        ));
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    if raw != raw.trim() {
        return Err(validation_error(
            source_file,
            doc,
            "metadata.namespace must not have surrounding whitespace",
        ));
    }
    Ok(Some(raw.to_owned()))
}

/// Rejects a missing/empty string or one padded with surrounding whitespace.
fn reject_padded_string(
    value: Option<&Value>,
    field: &str,
    source_file: &str,
    doc: usize,
    missing_message: &str,
) -> Result<String, ManifestError> {
    let raw = value
        .and_then(Value::as_str)
        .ok_or_else(|| validation_error(source_file, doc, missing_message))?;
    if raw.trim().is_empty() {
        return Err(validation_error(source_file, doc, missing_message));
    }
    if raw != raw.trim() {
        return Err(validation_error(
            source_file,
            doc,
            format!("{field} must not have surrounding whitespace"),
        ));
    }
    Ok(raw.to_owned())
}

/// Returns `true` when `metadata.annotations["ferriscd.io/hook"]` is a non-empty string.
fn has_hook_annotation(metadata: &Map<String, Value>) -> bool {
    metadata
        .get("annotations")
        .and_then(Value::as_object)
        .and_then(|annotations| annotations.get(ferriscd_crd::annotations::HOOK))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn non_empty_str(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn validation_error(source_file: &str, doc: usize, message: impl Into<String>) -> ManifestError {
    ManifestError::Validation {
        file: source_file.to_owned(),
        doc,
        message: message.into(),
    }
}

/// Splits a YAML stream into `(1-based index, body)` pairs at column-0 `---` markers.
///
/// Each body includes its leading `---` marker line (when present); the caller strips
/// it before parsing. This keeps the 1-based index correct even when the stream begins
/// with a `---` marker.
fn split_yaml_documents(source: &str) -> Vec<(usize, &str)> {
    let mut documents: Vec<(usize, &str)> = Vec::new();
    let bytes = source.as_bytes();
    let mut line_start = 0usize;
    let mut doc_start = 0usize;
    let mut doc_index = 1usize;
    let mut started = false;

    while line_start < bytes.len() {
        let line_end = next_line_end(bytes, line_start);
        let content = &source[line_start..line_end];
        let content = content.strip_suffix('\n').unwrap_or(content);
        let content = content.strip_suffix('\r').unwrap_or(content);

        if is_doc_start_marker(content) {
            if started {
                documents.push((doc_index, &source[doc_start..line_start]));
                doc_index += 1;
            }
            doc_start = line_start;
            started = true;
        } else {
            started = true;
        }
        line_start = line_end;
    }

    if started {
        documents.push((doc_index, &source[doc_start..]));
    }
    documents
}

fn next_line_end(bytes: &[u8], start: usize) -> usize {
    match bytes[start..].iter().position(|&b| b == b'\n') {
        Some(offset) => start + offset + 1,
        None => bytes.len(),
    }
}

/// Returns `true` for a column-0 `---` document-start marker followed only by
/// whitespace, a comment, or end-of-line.
fn is_doc_start_marker(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("---") else {
        return false;
    };
    rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') || rest.starts_with('#')
}

/// Removes a single leading `---` marker token from a document body.
///
/// Only the 3-character `---` token is removed; any inline content on the same line
/// (e.g. `--- {apiVersion: v1, ...}`) is preserved so it still parses as a document.
fn strip_leading_doc_marker(body: &str) -> &str {
    let first_line_end = body.find('\n').unwrap_or(body.len());
    let first_line = body[..first_line_end].trim_end_matches('\r');
    if is_doc_start_marker(first_line) {
        &body[3..]
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn parse_docs(contents: &str) -> Vec<DesiredResource> {
        parse_file("fixture.yaml", contents).expect("manifest should parse")
    }

    #[test]
    fn parses_multi_document_stream_with_trailing_separator() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: first
data:
  key: value
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: second
---
"#;
        let resources = parse_docs(yaml);
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].key.name, "first");
        assert_eq!(resources[1].key.name, "second");
    }

    #[test]
    fn skips_comment_only_and_null_documents() {
        let yaml = r#"
# just a comment
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: real
---
null
---
~ 
"#;
        let resources = parse_docs(yaml);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].key.name, "real");
    }

    #[test]
    fn flattens_v1_list_and_nested_typed_lists() {
        let yaml = r#"
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: List
    items:
      - apiVersion: v1
        kind: ConfigMap
        metadata:
          name: cm-a
  - apiVersion: apps/v1
    kind: DeploymentList
    items:
      - apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: deploy-a
"#;
        let resources = parse_docs(yaml);
        let names: BTreeMap<String, String> = resources
            .iter()
            .map(|resource| (resource.key.kind.clone(), resource.key.name.clone()))
            .collect();
        assert_eq!(names.get("ConfigMap").map(String::as_str), Some("cm-a"));
        assert_eq!(
            names.get("Deployment").map(String::as_str),
            Some("deploy-a")
        );
        assert_eq!(resources.len(), 2);
    }

    #[test]
    fn preserves_yaml_12_scalars_as_strings() {
        // The unquoted variants are the interesting YAML 1.2 cases.
        let yaml_unquoted = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: scalars
data:
  on: on
  off: off
  oct: 0123
"#;
        let resource = parse_docs(yaml_unquoted).remove(0);
        let data = resource
            .object
            .data
            .get("data")
            .and_then(Value::as_object)
            .expect("data map");
        assert_eq!(data.get("on").and_then(Value::as_str), Some("on"));
        assert_eq!(data.get("off").and_then(Value::as_str), Some("off"));
        assert_eq!(data.get("oct").and_then(Value::as_str), Some("0123"));
    }

    #[test]
    fn duplicate_yaml_key_is_rejected_with_document_index() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: dup
metadata:
  name: dup-again
"#;
        let err = parse_file("dup.yaml", yaml).expect_err("duplicate key must fail");
        let text = err.to_string();
        assert!(text.contains("dup.yaml"), "{text}");
        assert!(text.contains("document 1"), "{text}");
    }

    #[test]
    fn validation_error_names_file_and_document_index() {
        // Second document is missing `kind`.
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: good
---
apiVersion: v1
metadata:
  name: bad
"#;
        let err = parse_file("multi.yaml", yaml).expect_err("missing kind must fail");
        let text = err.to_string();
        assert!(text.contains("multi.yaml"), "{text}");
        assert!(text.contains("document 2"), "{text}");
        assert!(text.contains("kind"), "{text}");
    }

    #[test]
    fn generate_name_requires_hook_annotation() {
        let without_hook = r#"
apiVersion: batch/v1
kind: Job
metadata:
  generateName: pre-sync-
"#;
        let err = parse_file("hook.yaml", without_hook).expect_err("generateName without hook");
        assert!(err.to_string().contains("ferriscd.io/hook"), "{err}");

        let with_hook = r#"
apiVersion: batch/v1
kind: Job
metadata:
  generateName: pre-sync-
  annotations:
    ferriscd.io/hook: PreSync
"#;
        let resource = parse_docs(with_hook).remove(0);
        assert_eq!(resource.key.name, "pre-sync-");
        assert_eq!(resource.gvk.kind, "Job");
    }

    #[test]
    fn non_string_map_keys_are_coerced_to_their_string_spelling() {
        // serde-saphyr preserves the original spelling when a non-string YAML key is
        // deserialized into a `serde_json::Value` map (which requires string keys), so
        // `1` and `true` become `"1"` and `"true"` rather than being dropped or failing.
        let yaml =
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: n\n1: int-key\ntrue: bool-key\n";
        let resources = parse_docs(yaml);
        assert_eq!(resources.len(), 1);
        let data = &resources[0].object.data;
        assert_eq!(data.get("1").and_then(Value::as_str), Some("int-key"));
        assert_eq!(data.get("true").and_then(Value::as_str), Some("bool-key"));
    }

    #[test]
    fn non_string_document_root_is_rejected() {
        let yaml = "42\n";
        let err = parse_file("scalar.yaml", yaml).expect_err("scalar root must fail");
        assert!(err.to_string().contains("must be a mapping"), "{err}");
    }

    #[test]
    fn missing_api_version_kind_and_name_are_rejected() {
        for (label, yaml) in [
            (
                "missing apiVersion",
                "kind: ConfigMap\nmetadata:\n  name: a\n",
            ),
            ("missing kind", "apiVersion: v1\nmetadata:\n  name: a\n"),
            (
                "missing name",
                "apiVersion: v1\nkind: ConfigMap\nmetadata: {}\n",
            ),
        ] {
            let err = parse_file("x.yaml", yaml).expect_err(label);
            assert!(err.to_string().contains("document 1"), "{label}: {err}");
        }
    }

    #[test]
    fn billion_laughs_alias_bomb_is_rejected_by_replay_limits() {
        // The bomb sits under a *valid* resource root, so a parser that survived the
        // expansion would succeed — the only thing stopping it is the alias-replay limit.
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: bomb
data:
  a: &a ["lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol"]
  b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]
  c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]
  d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]
  e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]
  f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]
  g: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]
  h: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]
  i: &i [*h, *h, *h, *h, *h, *h, *h, *h, *h]
"#;
        let err = parse_file("bomb.yaml", yaml).expect_err("alias bomb must fail");
        let text = err.to_string();
        assert!(!err.is_retryable(), "replay breach must be terminal: {err}");
        assert!(
            text.contains("replay"),
            "expected the replay-limit message, got: {text}"
        );
        assert!(
            matches!(err, ManifestError::YamlParse { .. }),
            "expected the replay-limit parse error, got: {err:?}"
        );
    }

    #[test]
    fn parse_document_reports_budget_breach_before_deserialization() {
        // `parse_document` must surface the whole-stream budget verdict (not a generic parse
        // error): exceed the 1_024-document stream budget with well-formed documents.
        let mut stream = String::new();
        for _ in 0..1_025 {
            stream.push_str("---\na: 1\n");
        }
        let err = parse_document::<serde_json::Value>(&stream)
            .expect_err("the document budget must reject the stream");
        assert!(
            matches!(err, YamlGuardError::Budget { .. }),
            "expected a budget-specific guard error, got: {err:?}"
        );
    }

    #[test]
    fn whole_stream_budget_breach_is_reported_as_yaml_budget() {
        // 1_025 documents exceed the library default per-stream document budget (1_024).
        let mut stream = String::new();
        for _ in 0..1_025 {
            stream.push_str("---\na: 1\n");
        }
        let err = parse_file("many.yaml", &stream).expect_err("document budget must trip");
        let text = err.to_string();
        assert!(!err.is_retryable());
        assert!(text.contains("many.yaml"), "{text}");
        assert!(text.contains("budget"), "{text}");
        assert!(
            matches!(err, ManifestError::YamlBudget { .. }),
            "expected a budget-specific error, got: {err:?}"
        );
    }

    /// **`T13.1` finding M4:** operator-supplied YAML (a cluster-registration kubeconfig) goes
    /// through the same budgets and alias-replay limits as a rendered manifest, and a refusal
    /// never quotes the document.
    #[test]
    fn the_guarded_single_document_parser_enforces_budgets_without_quoting_the_document() {
        let value: Value = parse_document("apiVersion: v1\nkind: ConfigMap\n")
            .expect("a valid single document parses");
        assert_eq!(value["kind"], "ConfigMap");

        // `parse_options` rejects duplicate keys.
        let err = parse_document::<Value>("kind: a\nkind: b\n")
            .expect_err("a duplicate key must be refused");
        assert_eq!(err, YamlGuardError::Parse);
        assert!(
            !err.to_string().contains("kind: b"),
            "a refusal must never quote the document: {err}"
        );

        // The whole-stream document budget is reported as such (and names only the limit).
        let mut stream = String::new();
        for _ in 0..1_025 {
            stream.push_str("---\na: 1\n");
        }
        let err = parse_document::<Value>(&stream).expect_err("the document budget must trip");
        assert!(
            matches!(err, YamlGuardError::Budget { .. }),
            "expected a budget breach, got: {err:?}"
        );

        // The alias-replay limit is what stops a billion-laughs bomb here; without it the
        // controller would expand it while watching cluster `Secret`s.
        let bomb = r#"
a: &a ["lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol"]
b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]
d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]
e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]
f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]
g: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]
h: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]
"#;
        let err = parse_document::<Value>(bomb).expect_err("an alias bomb must be refused");
        assert_eq!(err, YamlGuardError::Parse);
        assert!(!err.to_string().contains("lol"), "{err}");
    }

    #[test]
    fn document_splitter_keeps_index_for_leading_separator() {
        let yaml = "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].0, 1);
        assert!(
            strip_leading_doc_marker(docs[0].1)
                .trim_start()
                .starts_with("apiVersion: v1")
        );
    }

    #[test]
    fn document_splitter_does_not_split_dashed_scalar_content() {
        // "---foo" is not a document marker.
        let yaml = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  k: ---foo\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn inline_document_marker_content_is_preserved() {
        let yaml = "--- {apiVersion: v1, kind: ConfigMap, metadata: {name: inline}}\n";
        let resources = parse_docs(yaml);
        assert_eq!(
            resources.len(),
            1,
            "inline marker content must not be dropped"
        );
        assert_eq!(resources[0].gvk.kind, "ConfigMap");
        assert_eq!(resources[0].key.name, "inline");
    }

    #[test]
    fn list_without_items_is_a_clear_error() {
        for (label, yaml) in [
            (
                "core List",
                "apiVersion: v1\nkind: List\nmetadata:\n  name: ignored\n",
            ),
            (
                "typed List",
                "apiVersion: apps/v1\nkind: DeploymentList\nmetadata:\n  name: ignored\n",
            ),
        ] {
            let err = parse_file("list.yaml", yaml).expect_err(label);
            let text = err.to_string();
            assert!(text.contains("items"), "{label}: {text}");
            assert!(text.contains("document 1"), "{label}: {text}");
        }
    }

    #[test]
    fn parse_produces_version_agnostic_keys_across_api_versions() {
        let v1beta1 = "apiVersion: networking.k8s.io/v1beta1\nkind: Ingress\nmetadata:\n  name: web\n  namespace: payments\n";
        let v1 = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\n  namespace: payments\n";

        let beta = parse_docs(v1beta1).remove(0);
        let stable = parse_docs(v1).remove(0);

        assert_eq!(beta.key, stable.key);
        assert_eq!(beta.gvk.version, "v1beta1");
        assert_eq!(stable.gvk.version, "v1");
        assert_ne!(beta.gvk.version, stable.gvk.version);
    }

    #[test]
    fn surrounding_whitespace_in_name_and_namespace_is_rejected() {
        let padded_name = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ' app '\n";
        let err = parse_file("padded.yaml", padded_name).expect_err("padded name must fail");
        assert!(err.to_string().contains("whitespace"), "{err}");

        let padded_ns =
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n  namespace: '  ns '\n";
        let err = parse_file("padded-ns.yaml", padded_ns).expect_err("padded namespace must fail");
        assert!(err.to_string().contains("whitespace"), "{err}");
    }
}

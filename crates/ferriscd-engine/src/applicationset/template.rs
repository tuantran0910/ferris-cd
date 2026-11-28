//! Flat `{{key}}` template rendering for `ApplicationSet` (`T19.3`).
//!
//! # Deliberately not a template language
//!
//! The renderer recognizes exactly one construct: `{{key}}`, where `key` is a literal lookup in the
//! parameter map the generator produced. There are no loops, conditionals, functions, filters,
//! pipelines, or expressions, so an `ApplicationSet` author cannot execute anything — the worst a
//! typo can do is fail the pass. That is a hard requirement of the task (`T19.3` Trap Guard):
//! Argo's Go `text/template` is Turing-complete, and a fleet generator that can compute is a fleet
//! generator that can be abused.
//!
//! Three further details matter for safety:
//!
//! * **Unknown keys fail.** A `{{clustr.name}}` typo is a terminal error naming the key, never a
//!   silent empty string that would generate an `Application` pointed at the wrong place.
//! * **Substitution is single-pass.** A parameter *value* that itself contains `{{...}}` is inserted
//!   literally and is never re-expanded, so a Git-controlled parameter file cannot inject a second
//!   round of placeholders (`{{a}}` = `"{{b}}"` stays `{{b}}`).
//! * **Only the generated `Application` name is DNS-1123 sanitized.** It is the one field with a
//!   strict Kubernetes constraint that generators routinely fill from a path (`apps/Payments_API`
//!   → `payments-api`). Every other string is substituted verbatim and validated by
//!   [`ferriscd_crd::ApplicationSpec::validate`], so a repository URL or path is never mangled.

use std::collections::BTreeMap;

use ferriscd_crd::applicationset::{ApplicationSet, ApplicationSetTemplate};
use ferriscd_crd::{APPLICATIONSET_LABEL, Application, ApplicationSpec};
use kube::ResourceExt;
use serde_json::Value;

use super::ApplicationSetError;

/// Maximum length of a generated `Application` name (RFC 1123 label limit).
pub const MAX_APPLICATION_NAME_LENGTH: usize = 63;

/// Rendered `Application` name plus its parameter map.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedApplication {
    /// The `Application` the parameter set rendered into.
    pub application: Application,
    /// The parameter map that produced it (kept for status reporting and tests).
    pub params: BTreeMap<String, String>,
}

/// Why a template could not be rendered.
///
/// Every variant is **terminal**: the spec (or the parameter data) has to change. Messages never
/// quote a parameter *value* that could be a credential — only the key name and the template field.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    /// A placeholder named a key the generator did not produce.
    #[error(
        "the template uses {{{{{key}}}}} but the generator produced no such parameter (available: \
         {available})"
    )]
    UnknownPlaceholder {
        /// The unknown key.
        key: String,
        /// The keys that were available, comma-separated and sorted.
        available: String,
    },
    /// A `{{` had no matching `}}`.
    #[error("the template contains an unterminated `{{{{` placeholder")]
    UnterminatedPlaceholder,
    /// A `{{}}` (or whitespace-only) placeholder carried no key.
    #[error("the template contains an empty `{{{{}}}}` placeholder")]
    EmptyPlaceholder,
    /// A placeholder existed but its key is not a plain lookup.
    #[error(
        "the template placeholder {raw:?} is not a flat `{{{{key}}}}` lookup: only literal \
         parameter names are supported (no expressions, functions, or filters)"
    )]
    InvalidPlaceholder {
        /// The rejected placeholder body.
        raw: String,
    },
    /// The rendered `metadata.name` was empty (or only separators) after sanitization.
    #[error("the template metadata.name {template:?} renders to an empty DNS-1123 name")]
    EmptyName {
        /// The unrendered template name.
        template: String,
    },
    /// The rendered `Application` spec is invalid.
    #[error("generated Application {name:?} has an invalid spec: {message}")]
    InvalidSpec {
        /// The rendered name.
        name: String,
        /// The validation message.
        message: String,
    },
    /// A rendered label/annotation key or label value is not a Kubernetes-valid one.
    ///
    /// The generated `Application` would be rejected by the API server with a message that does not
    /// say which template entry produced it, so the field is named here instead.
    #[error(
        "the template entry {field} is not a valid Kubernetes metadata entry: {message} (the value \
         is not quoted: it may come from a repository parameter)"
    )]
    InvalidMetadataEntry {
        /// Dotted path of the offending entry (`template.metadata.labels["team"]`).
        field: String,
        /// What is wrong with it.
        message: String,
    },
}

/// Renders `appset.spec.template` for one parameter map.
///
/// The generated `Application` lives in the `ApplicationSet`'s own namespace, carries a
/// same-namespace `ownerReference` to it, and is stamped with
/// `ferriscd.io/applicationset: <name>`.
///
/// # Errors
///
/// [`TemplateError`] for an unknown/unterminated placeholder, an empty rendered name, or an invalid
/// generated spec. The `ApplicationSet`'s own spec must already be validated by the caller.
pub fn render_template(
    appset: &ApplicationSet,
    params: &BTreeMap<String, String>,
) -> Result<RenderedApplication, ApplicationSetError> {
    let namespace = appset.namespace().unwrap_or_default();
    let appset_name = appset.name_any();

    // Serialize the typed template and substitute into its string leaves. Going through JSON keeps
    // "which fields are strings" a property of the schema instead of a hand-maintained field list.
    let serialized = serde_json::to_value(&appset.spec.template).map_err(|err| {
        ApplicationSetError::Template(TemplateError::InvalidSpec {
            name: appset_name.clone(),
            message: format!("the template is not representable as JSON: {err}"),
        })
    })?;
    let rendered = render_value(serialized, params)?;
    let template: ApplicationSetTemplate = serde_json::from_value(rendered).map_err(|err| {
        ApplicationSetError::Template(TemplateError::InvalidSpec {
            name: appset_name.clone(),
            message: format!("the rendered template is not a valid Application template: {err}"),
        })
    })?;

    let raw_name = template.metadata.name.clone();
    let name = sanitize_dns1123(&raw_name);
    if name.is_empty() {
        return Err(ApplicationSetError::Template(TemplateError::EmptyName {
            template: raw_name,
        }));
    }

    let spec: ApplicationSpec = template.spec;
    spec.validate().map_err(|err| {
        ApplicationSetError::Template(TemplateError::InvalidSpec {
            name: name.clone(),
            message: err.to_string(),
        })
    })?;

    let mut application = Application::new(&name, spec);
    application.metadata.namespace = Some(namespace.clone());
    let labels = application
        .metadata
        .labels
        .get_or_insert_with(BTreeMap::new);
    for (key, value) in template.metadata.labels {
        validate_label(&key, &value)?;
        labels.insert(key, value);
    }
    // Ours always wins: a template cannot opt itself out of being identified as generated, and it
    // cannot impersonate another `ApplicationSet`.
    labels.insert(APPLICATIONSET_LABEL.to_owned(), appset_name.clone());
    if !template.metadata.annotations.is_empty() {
        for key in template.metadata.annotations.keys() {
            validate_annotation_key(key)?;
        }
        application.metadata.annotations = Some(template.metadata.annotations);
    }
    if let Some(uid) = appset.metadata.uid.clone() {
        application.metadata.owner_references = Some(vec![owner_reference(&appset_name, &uid)]);
    }

    Ok(RenderedApplication {
        application,
        params: params.clone(),
    })
}

/// Validates one rendered template label (key and value) against the Kubernetes rules.
///
/// Only the *generated* `Application` name is sanitized (see the module docs); a label is a user's
/// data, so the honest answer is to name the offending template entry instead of silently rewriting
/// it. Kubernetes would otherwise reject the whole `Application` with a message that does not say
/// which entry came from which parameter.
fn validate_label(key: &str, value: &str) -> Result<(), ApplicationSetError> {
    let field = format!("template.metadata.labels[{key:?}]");
    if !is_qualified_name(key) {
        return Err(ApplicationSetError::Template(
            TemplateError::InvalidMetadataEntry {
                field,
                message: "a label key must be a name of at most 63 characters (optionally prefixed \
                          with a DNS subdomain), starting and ending with an alphanumeric character \
                          and containing only alphanumerics, `-`, `_`, or `.`"
                    .to_owned(),
            },
        ));
    }
    if !value.is_empty() && !is_label_value(value) {
        return Err(ApplicationSetError::Template(
            TemplateError::InvalidMetadataEntry {
                field,
                message: format!(
                    "a label value must be empty or at most 63 characters, starting and ending with \
                     an alphanumeric character and containing only alphanumerics, `-`, `_`, or `.` \
                     (the rendered value is {} characters)",
                    value.chars().count()
                ),
            },
        ));
    }
    Ok(())
}

/// Validates one rendered template annotation key (the value is arbitrary).
fn validate_annotation_key(key: &str) -> Result<(), ApplicationSetError> {
    if is_qualified_name(key) {
        return Ok(());
    }
    Err(ApplicationSetError::Template(
        TemplateError::InvalidMetadataEntry {
            field: format!("template.metadata.annotations[{key:?}]"),
            message: "an annotation key must be a name of at most 63 characters (optionally prefixed \
                      with a DNS subdomain), starting and ending with an alphanumeric character and \
                      containing only alphanumerics, `-`, `_`, or `.`"
                .to_owned(),
        },
    ))
}

/// Whether `key` is a Kubernetes-qualified name (`[prefix/]name`).
fn is_qualified_name(key: &str) -> bool {
    let name = match key.split_once('/') {
        Some((prefix, name)) => {
            if !is_dns_subdomain(prefix) {
                return false;
            }
            name
        }
        None => key,
    };
    is_short_name(name, 63)
}

/// Whether `value` satisfies the label-value grammar (empty is valid, and checked by the caller).
fn is_label_value(value: &str) -> bool {
    is_short_name(value, 63)
}

/// A name of at most `max` characters: alphanumerics at both ends, `[-_.]` inside.
fn is_short_name(name: &str, max: usize) -> bool {
    let length = name.chars().count();
    if length == 0 || length > max {
        return false;
    }
    let mut characters = name.chars();
    let first = characters.next().unwrap_or('-');
    let last = name.chars().next_back().unwrap_or('-');
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return false;
    }
    name.chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
}

/// A DNS subdomain (the `prefix` half of a qualified metadata key).
fn is_dns_subdomain(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.chars().count() <= 253
        && prefix
            .split('.')
            .all(|label| is_short_name(label, 63) && !label.contains('_'))
}

/// Builds the same-namespace controller `ownerReference` for an `ApplicationSet`.
#[must_use]
pub fn owner_reference(
    appset_name: &str,
    uid: &str,
) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
    k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
        api_version: format!("{}/v1alpha1", ferriscd_crd::API_GROUP),
        kind: "ApplicationSet".to_owned(),
        name: appset_name.to_owned(),
        uid: uid.to_owned(),
        // `controller: true` is what makes the reference unique and lets garbage collection treat
        // the generated object as owned; `blockOwnerDeletion` keeps the `ApplicationSet` deletion
        // (and therefore the finalizer that may orphan the children) honest.
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Recursively renders every JSON string leaf.
fn render_value(
    value: Value,
    params: &BTreeMap<String, String>,
) -> Result<Value, ApplicationSetError> {
    match value {
        Value::String(text) => render_placeholders(&text, params).map(Value::String),
        Value::Array(items) => items
            .into_iter()
            .map(|item| render_value(item, params))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(entries) => entries
            .into_iter()
            .map(|(key, item)| render_value(item, params).map(|rendered| (key, rendered)))
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(Value::Object),
        // Numbers, booleans, and null cannot carry a placeholder.
        other => Ok(other),
    }
}

/// Substitutes every `{{key}}` in `text`, in a single left-to-right pass.
///
/// # Errors
///
/// [`TemplateError::UnterminatedPlaceholder`], [`TemplateError::EmptyPlaceholder`],
/// [`TemplateError::InvalidPlaceholder`], or [`TemplateError::UnknownPlaceholder`].
pub fn render_placeholders(
    text: &str,
    params: &BTreeMap<String, String>,
) -> Result<String, ApplicationSetError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err(ApplicationSetError::Template(
                TemplateError::UnterminatedPlaceholder,
            ));
        };
        let raw = &after[..end];
        let key = raw.trim();
        if key.is_empty() {
            return Err(ApplicationSetError::Template(
                TemplateError::EmptyPlaceholder,
            ));
        }
        if !is_placeholder_key(key) {
            return Err(ApplicationSetError::Template(
                TemplateError::InvalidPlaceholder {
                    raw: raw.to_owned(),
                },
            ));
        }
        let Some(value) = params.get(key) else {
            let available = params.keys().cloned().collect::<Vec<_>>().join(", ");
            return Err(ApplicationSetError::Template(
                TemplateError::UnknownPlaceholder {
                    key: key.to_owned(),
                    available,
                },
            ));
        };
        // Single pass: the *value* is inserted literally and never scanned again.
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Whether `key` is a plain lookup name (no expressions/functions/filters).
///
/// `[`, `]`, and `.` are allowed because the Git generator synthesizes `path[1]` and
/// `path.basename`; everything else — whitespace, braces, quotes, `|`, `(`, `)` — is refused so the
/// syntax can never grow into a language.
#[must_use]
pub fn is_placeholder_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '[' | ']'))
        && !key.starts_with('[')
        && !key.ends_with('[')
}

/// Sanitizes `raw` into an RFC 1123 DNS label.
///
/// Lowercase, `[a-z0-9-]` only, runs of separators collapsed, no leading/trailing `-`, and at most
/// [`MAX_APPLICATION_NAME_LENGTH`] characters. Returns an empty string when nothing usable is left,
/// which the caller turns into [`TemplateError::EmptyName`].
#[must_use]
pub fn sanitize_dns1123(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_dash = false;
    for c in raw.chars() {
        let mapped = if c.is_ascii_alphanumeric() {
            c.to_ascii_lowercase()
        } else {
            '-'
        };
        if mapped == '-' {
            if last_dash {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        out.push(mapped);
    }
    let trimmed = out.trim_matches('-');
    let truncated: String = trimmed.chars().take(MAX_APPLICATION_NAME_LENGTH).collect();
    truncated.trim_end_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ferriscd_crd::applicationset::{
        ApplicationSet, ApplicationSetSyncPolicy, ApplicationSetTemplateMetadata, ListGenerator,
        MAX_GENERATED_APPLICATIONS,
    };
    use ferriscd_crd::{SourceSpec, application::DestinationSpec, application::GitSourceSpec};
    use kube::ResourceExt;

    use super::*;

    fn template_appset(name: &str) -> ApplicationSet {
        let spec: ferriscd_crd::ApplicationSetSpec = serde_saphyr::from_str(&format!(
            r#"
generators:
  - list:
      elements:
        - cluster: dev
template:
  metadata:
    name: "{name}"
    labels:
      team: payments
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
        path: "apps/{{{{cluster}}}}"
    destination:
      cluster: "{{{{cluster}}}}"
      namespace: payments
syncPolicy:
  preserveResourcesOnDeletion: true
"#
        ))
        .expect("the test template must parse");
        let mut appset = ApplicationSet::new("payments-fleet", spec);
        appset.metadata.namespace = Some("ferriscd-system".to_owned());
        appset.metadata.uid = Some("uid-1234".to_owned());
        appset
    }

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn placeholders_are_substituted_single_pass() {
        let map = params(&[("cluster", "prod"), ("evil", "{{cluster}}")]);
        assert_eq!(
            render_placeholders("api-{{cluster}}", &map).expect("renders"),
            "api-prod"
        );
        // A value that *looks* like a placeholder is inserted literally: no second pass.
        assert_eq!(
            render_placeholders("x-{{evil}}", &map).expect("renders"),
            "x-{{cluster}}"
        );
        // Whitespace inside the braces is tolerated; the lookup key is trimmed.
        assert_eq!(
            render_placeholders("a-{{ cluster }}-b", &map).expect("renders"),
            "a-prod-b"
        );
        // A single brace is literal text, not a placeholder.
        assert_eq!(
            render_placeholders("{not-a-placeholder}", &map).expect("renders"),
            "{not-a-placeholder}"
        );
        assert_eq!(render_placeholders("", &map).expect("renders"), "");
    }

    #[test]
    fn template_syntax_is_not_a_language() {
        let map = params(&[("cluster", "prod")]);
        for (text, expected) in [
            ("{{cluster", "unterminated"),
            ("tail-{{", "unterminated"),
            ("{{}}", "empty"),
            ("{{   }}", "empty"),
            ("{{cluster | upper}}", "not a flat"),
            ("{{printf \"%s\" .cluster}}", "not a flat"),
            ("{{cluster.name(1)}}", "not a flat"),
            ("{{cluster name}}", "not a flat"),
            ("{{cluster}{{cluster}}", "not a flat"),
        ] {
            let error = render_placeholders(text, &map)
                .expect_err("must be refused")
                .to_string();
            assert!(
                error.contains(expected),
                "{text:?} should fail with {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn an_unknown_parameter_is_an_error_not_an_empty_string() {
        let map = params(&[("cluster", "prod")]);
        let error = render_placeholders("{{clustr}}", &map).expect_err("must be refused");
        let message = error.to_string();
        assert!(message.contains("clustr"), "{message}");
        assert!(
            message.contains("cluster"),
            "the available keys are named: {message}"
        );
        assert!(matches!(
            error,
            ApplicationSetError::Template(TemplateError::UnknownPlaceholder { .. })
        ));
        assert!(!error.is_retryable(), "a typo cannot be fixed by retrying");
    }

    #[test]
    fn dns1123_sanitization_is_stable_and_bounded() {
        assert_eq!(sanitize_dns1123("Payments_API"), "payments-api");
        assert_eq!(sanitize_dns1123("apps/API/v1"), "apps-api-v1");
        assert_eq!(sanitize_dns1123("--Payments--API--"), "payments-api");
        assert_eq!(sanitize_dns1123(""), "");
        assert_eq!(sanitize_dns1123("___"), "");
        assert_eq!(sanitize_dns1123("a..b"), "a-b");
        let long = "a".repeat(100);
        assert_eq!(sanitize_dns1123(&long).len(), MAX_APPLICATION_NAME_LENGTH);
        let long_dashed = format!("{}-", "a".repeat(MAX_APPLICATION_NAME_LENGTH));
        assert_eq!(
            sanitize_dns1123(&long_dashed).len(),
            MAX_APPLICATION_NAME_LENGTH,
            "a trailing separator must not survive truncation"
        );
        assert!(!sanitize_dns1123("Apps Ünicode").contains('Ü'));
    }

    #[test]
    fn rendering_builds_a_same_namespace_owned_application() {
        let appset = template_appset("api-{{cluster}}");
        let rendered = render_template(&appset, &params(&[("cluster", "prod")]))
            .expect("the template must render");

        assert_eq!(rendered.application.name_any(), "api-prod");
        assert_eq!(
            rendered.application.namespace().as_deref(),
            Some("ferriscd-system"),
            "a generated Application must live in the ApplicationSet's own namespace"
        );
        assert_eq!(
            rendered.application.spec.destination.cluster, "prod",
            "placeholders must reach nested spec fields"
        );
        let git = rendered
            .application
            .spec
            .source
            .as_ref()
            .expect("the template carries a source")
            .git
            .as_ref()
            .expect("a rendered Application keeps the Git source the template carries");
        assert_eq!(
            git.path, "apps/prod",
            "placeholders must reach the repository path"
        );
        let labels = rendered.application.labels();
        assert_eq!(
            labels.get(APPLICATIONSET_LABEL).map(String::as_str),
            Some("payments-fleet")
        );
        assert_eq!(labels.get("team").map(String::as_str), Some("payments"));

        let owners = rendered
            .application
            .metadata
            .owner_references
            .as_ref()
            .expect("an owner reference is required for garbage collection");
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].kind, "ApplicationSet");
        assert_eq!(owners[0].name, "payments-fleet");
        assert_eq!(owners[0].uid, "uid-1234");
        assert_eq!(owners[0].api_version, "ferriscd.io/v1alpha1");
        assert_eq!(owners[0].controller, Some(true));
        assert_eq!(owners[0].block_owner_deletion, Some(true));
    }

    #[test]
    fn a_template_cannot_opt_out_of_the_generated_label() {
        let mut appset = template_appset("api");
        appset
            .spec
            .template
            .metadata
            .labels
            .insert(APPLICATIONSET_LABEL.to_owned(), "someone-else".to_owned());
        let rendered =
            render_template(&appset, &params(&[("cluster", "dev")])).expect("must render");
        assert_eq!(
            rendered
                .application
                .labels()
                .get(APPLICATIONSET_LABEL)
                .map(String::as_str),
            Some("payments-fleet"),
            "the engine's own label always wins"
        );
    }

    #[test]
    fn an_empty_rendered_name_is_refused() {
        let appset = template_appset("{{cluster}}");
        let error = render_template(&appset, &params(&[("cluster", "___")]))
            .expect_err("a separator-only name has no DNS form");
        assert!(matches!(
            error,
            ApplicationSetError::Template(TemplateError::EmptyName { .. })
        ));
    }

    #[test]
    fn an_invalid_generated_spec_is_refused() {
        // `destination.namespace` renders empty: `ApplicationSpec::validate` must catch it before
        // anything is created.
        let mut appset = template_appset("api");
        appset.spec.template.spec.destination = DestinationSpec {
            cluster: "in-cluster".to_owned(),
            namespace: "{{missing}}".to_owned(),
        };
        let error = render_template(&appset, &params(&[("cluster", "dev")]))
            .expect_err("the placeholder is unknown");
        assert!(matches!(
            error,
            ApplicationSetError::Template(TemplateError::UnknownPlaceholder { .. })
        ));

        appset.spec.template.spec.destination = DestinationSpec {
            cluster: "  ".to_owned(),
            namespace: "payments".to_owned(),
        };
        let error = render_template(&appset, &params(&[("cluster", "dev")]))
            .expect_err("a blank cluster is invalid");
        assert!(
            error.to_string().contains("invalid spec"),
            "the message must name the generated Application and the reason: {error}"
        );
    }

    /// A rendered label is *user data*, not a field this engine may silently rewrite: a parameter
    /// such as `apps/api` is a perfectly good repository path and a perfectly invalid label value.
    /// The refusal must therefore name the template entry, and must not quote the value (it may come
    /// from a repository file).
    #[test]
    fn an_invalid_rendered_label_or_annotation_names_the_template_field() {
        let mut appset = template_appset("api");
        appset
            .spec
            .template
            .metadata
            .labels
            .insert("path".to_owned(), "{{cluster}}".to_owned());
        let error = render_template(&appset, &params(&[("cluster", "apps/api")]))
            .expect_err("a slash is not a label value character");
        let message = error.to_string();
        assert!(
            message.contains("template.metadata.labels[\"path\"]"),
            "the error must name the offending entry: {message}"
        );
        assert!(
            !message.contains("apps/api"),
            "the error must not quote the value: {message}"
        );
        assert!(matches!(
            error,
            ApplicationSetError::Template(TemplateError::InvalidMetadataEntry { .. })
        ));
        assert!(!error.is_retryable());

        // A value over the 63-character label limit is the same class of error.
        let too_long = "a".repeat(64);
        let error = render_template(&appset, &params(&[("cluster", &too_long)]))
            .expect_err("a label value is limited to 63 characters");
        assert!(
            error.to_string().contains("64 characters"),
            "the refusal reports the rendered length, not the value: {error}"
        );
        assert!(!error.to_string().contains(&too_long), "{error}");

        // An invalid *key* (a rendered prefix is not one) is caught too.
        let mut bad_key = template_appset("api");
        bad_key
            .spec
            .template
            .metadata
            .labels
            .insert("{{cluster}}".to_owned(), "x".to_owned());
        let error = render_template(&bad_key, &params(&[("cluster", "bad key")]))
            .expect_err("a key with a space is invalid");
        assert!(
            error.to_string().contains("template.metadata.labels"),
            "{error}"
        );

        // A valid qualified key and an arbitrary annotation value are accepted.
        let mut valid = template_appset("api");
        valid
            .spec
            .template
            .metadata
            .labels
            .insert("example.com/team".to_owned(), "payments-eu".to_owned());
        valid.spec.template.metadata.annotations.insert(
            "example.com/note".to_owned(),
            "a value with spaces, and: punctuation".to_owned(),
        );
        let rendered = render_template(&valid, &params(&[("cluster", "dev")]))
            .expect("a valid qualified key and free-form annotation value are accepted");
        assert_eq!(
            rendered
                .application
                .labels()
                .get("example.com/team")
                .map(String::as_str),
            Some("payments-eu")
        );
        assert!(is_qualified_name("ferriscd.io/applicationset"));
        assert!(!is_qualified_name("/name"));
        assert!(!is_qualified_name("bad_prefix/name"));
    }

    #[test]
    fn template_types_are_defaultable_and_the_sync_policy_defaults_are_safe() {
        let metadata = ApplicationSetTemplateMetadata::default();
        assert!(metadata.name.is_empty());
        assert!(
            ApplicationSetSyncPolicy::default().preserve_resources_on_deletion,
            "deleting an ApplicationSet must not delete generated Applications by default"
        );
        assert!(!ApplicationSetSyncPolicy::default().prune);
        let list = ListGenerator::default();
        assert!(list.elements.is_empty());
        assert_eq!(MAX_GENERATED_APPLICATIONS, 200);
        // Keep the constants honest: the CRD ceiling and the engine's cap are one number.
        assert_eq!(
            super::super::MAX_GENERATED_APPS,
            usize::try_from(MAX_GENERATED_APPLICATIONS).expect("positive")
        );
        let _: SourceSpec = SourceSpec {
            git: Some(GitSourceSpec {
                repo_url: "https://github.com/example/x.git".to_owned(),
                target_revision: "HEAD".to_owned(),
                path: String::new(),
            }),
            oci: None,
            renderer: ferriscd_crd::RendererSpec::default(),
        };
    }
}

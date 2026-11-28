//! Redacted notification context and the flat `{{placeholder}}` templates (`T19.4`).
//!
//! # Why the context is a closed struct instead of the `Application` object
//!
//! A notification payload leaves the cluster and lands in a third-party service, so it is the last
//! place a `Secret` value, a `repoUrl` with an embedded token, or a diff body may travel to. The
//! template renderer therefore never sees an `Application` or an `ApplicationStatus`: it sees a
//! [`NotificationContext`], whose fields are exactly what the roadmap allows — the redacted
//! `ApplicationStatus` (`sync`, `health`, `conditions`, `history`) plus
//! [`redact_repo_url`](ferriscd_engine::manifest::redact_repo_url). There is no field an
//! operator-supplied template could use to reach anything else.
//!
//! # What the context deliberately does *not* carry (`conditions`, `history`)
//!
//! `T19.4` allows the redacted `ApplicationStatus`, whose `conditions` and `history` lists are among
//! the fields it names. This context exposes neither as a template field, and the narrowing is
//! deliberate rather than an omission:
//!
//! * `conditions[]` is an **unbounded, controller-written bag** whose `message`/`reason` strings are
//!   whatever the API server, a Git server or a hook returned. That is the one place a repository
//!   URL with an embedded credential, a rejected object's body, or a 500-character server message
//!   could reach a third-party receiver — and unlike `app.message` (one `Ready` summary, already
//!   bounded and [`sanitize_note`]d by the status writer) there is no single field to bound.
//!   `conditions` therefore travels only as that one `Ready` summary in `{{app.message}}`.
//! * `history[]` grows to `spec.revisionHistoryLimit` entries (10 by default, up to 100) and can be
//!   several KiB; a notification is not a status dump, and a payload that large is rejected by more
//!   than one receiver.
//!
//! Everything a page actually needs is a scalar in the allow-list below (`sync`, `health`, the
//! revision, the generation, the redacted repo URL), so no delivery loses information an operator
//! acts on. Adding one of these fields is a deliberate change: give it a bound, a sanitiser and a
//! redaction test first.
//!
//! # Why the templates are not a template engine
//!
//! The template text comes from a `ConfigMap`, so it is operator input. Only flat
//! `{{app.name}}`-style placeholders are recognised: a placeholder is either one of the fixed
//! allow-list keys or the document is refused ([`TemplateError::UnknownField`]). That keeps
//! rendering total (no loops, no function calls, no recursion: a template can neither hang the
//! delivery worker nor be tricked into reading a field), and it means a typo fails loudly at load
//! time — where [`NotificationConfig::parse`](crate::notifications::NotificationConfig::parse)
//! falls back to the built-in default — instead of shipping an empty alert to PagerDuty at 3 a.m.

/// Longest `{{app.repoUrl}}` this context carries, in bytes.
///
/// A multi-source `Application` reports **every** declared source (`spec.sources` is capped at 16),
/// so the joined value has to be bounded like every other field that reaches a third-party receiver:
/// a notification is not a status dump, and an oversized POST is rejected by more than one service.
pub const MAX_REPO_URL_BYTES: usize = 1024;

/// The source URLs a notification reports: **every** declared source (`T20.1`), in declaration
/// order and comma-joined — `spec.source`'s URL alone for a `v1.0` `Application`, exactly as before.
///
/// Joining is what makes the field honest: a split chart/values `Application` deploys *both*
/// repositories, so naming only the first one (or the first declared entry) would tell an on-call
/// engineer to look at half the deployment. Every URL is redacted here — the caller must not have to
/// remember — and the result is length-bounded ([`MAX_REPO_URL_BYTES`]).
fn source_urls(app: &Application) -> String {
    let described: Vec<String> = declared_sources(&app.spec)
        .iter()
        .map(|source| redact_repo_url(source.spec.repo_url()))
        .filter(|url| !url.is_empty())
        .collect();
    truncate_utf8_bytes(&described.join(", "), MAX_REPO_URL_BYTES)
}

use ferriscd_crd::status::{ApplicationStatus, HealthStatus, SyncStatus};
use ferriscd_crd::{Application, annotations};
use ferriscd_engine::manifest::{declared_sources, redact_repo_url};
use kube::ResourceExt as _;

use crate::events::{sanitize_note, truncate_utf8_bytes};

/// Longest rendered Slack/Teams/generic message body, in bytes.
///
/// A `ConfigMap` template is bounded by the YAML parser budgets (1 MiB), so the *rendered* message
/// is bounded here as well: a webhook receiver is not a log sink, and an oversized POST is both a
/// bandwidth amplifier and a way to make a receiver reject every alert.
pub const MAX_RENDERED_MESSAGE_BYTES: usize = 8 * 1024;

/// Every placeholder a template may reference, in documentation order.
///
/// `conditions` and `history` are intentionally absent: see the module docs for why the roadmap's
/// "redacted `ApplicationStatus`" is narrowed to scalars plus the bounded `app.message`.
pub const ALLOWED_FIELDS: [&str; 12] = [
    "app.name",
    "app.namespace",
    "app.project",
    "app.repoUrl",
    "app.revision",
    "app.syncStatus",
    "app.healthStatus",
    "app.message",
    "app.observedGeneration",
    "trigger",
    "service",
    "recipient",
];

/// The redacted, allow-listed facts one notification may carry.
///
/// Constructed only by [`NotificationContext::from_status`], which applies
/// [`redact_repo_url`] and [`sanitize_note`] to every free-form value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NotificationContext {
    app_name: String,
    app_namespace: String,
    project: String,
    repo_url: String,
    revision: String,
    sync_status: &'static str,
    health_status: &'static str,
    message: String,
    observed_generation: String,
    trigger: &'static str,
    service: &'static str,
    recipient: String,
}

impl NotificationContext {
    /// Builds the context of one notification from a persisted status.
    ///
    /// Every free-form field is sanitised here — the one constructor — so no caller can hand the
    /// renderer an unsanitised string:
    ///
    /// * `app.repoUrl` carries **every** declared source URL (`T20.1`), each one through
    ///   [`redact_repo_url`] (embedded `user:token@` credentials and SCP style remotes are stripped)
    ///   and the joined result is length-bounded,
    /// * `app.message` is the `Ready` condition's message (already bounded by the status writer) and
    ///   is then [`sanitize_note`]d, which redacts base64-shaped payload runs and URL credentials,
    /// * nothing else is copied: no `Secret`, no diff, no rendered manifest, no inventory body.
    #[must_use]
    pub fn from_status(
        app: &Application,
        status: &ApplicationStatus,
        trigger: &'static str,
        service: &'static str,
        recipient: &str,
    ) -> Self {
        let sync = status.sync.as_ref();
        let sync_status = match sync.map(|sync| sync.status) {
            Some(SyncStatus::Synced) => "Synced",
            Some(SyncStatus::OutOfSync) => "OutOfSync",
            Some(SyncStatus::Unknown) | None => "Unknown",
        };
        let health_status = match status.health.as_ref().map(|health| health.status) {
            Some(HealthStatus::Healthy) => "Healthy",
            Some(HealthStatus::Progressing) => "Progressing",
            Some(HealthStatus::Degraded) => "Degraded",
            Some(HealthStatus::Suspended) => "Suspended",
            Some(HealthStatus::Missing) => "Missing",
            Some(HealthStatus::Unknown) | None => "Unknown",
        };
        let revision = sync
            .and_then(|sync| {
                sync.revision
                    .clone()
                    .or_else(|| sync.last_synced_revision.clone())
            })
            .unwrap_or_default();
        let message = status
            .condition(ferriscd_crd::status::CONDITION_READY)
            .map(|condition| {
                if condition.message.trim().is_empty() {
                    condition.reason.clone()
                } else {
                    format!("{}: {}", condition.reason, condition.message)
                }
            })
            .unwrap_or_default();

        Self {
            // Identity fields are Kubernetes-validated names and a controller-written revision, none
            // of which can carry secret material; they are only length-bounded. Running the
            // payload redactor over them would be *over*-redaction with a real cost: a 40-character
            // commit SHA is exactly a "payload-shaped run" and would be printed as
            // `<redacted 40 char(s)>`, deleting the most useful fact in a sync notification.
            app_name: bounded_identity(&app.name_any()),
            app_namespace: bounded_identity(&app.namespace().unwrap_or_default()),
            project: bounded_identity(&app.spec.project),
            // `T20.1`: an `Application` that declares `spec.sources` reports **every** declared
            // source, redacted; a `v1.0` one reports exactly the URL it always did.
            repo_url: source_urls(app),
            revision: bounded_identity(&revision),
            sync_status,
            health_status,
            message: sanitize_note(&message),
            observed_generation: status
                .observed_generation
                .or(app.metadata.generation)
                .map(|generation| generation.to_string())
                .unwrap_or_default(),
            trigger,
            service,
            recipient: bounded_identity(recipient),
        }
    }

    /// Resolves one allow-listed placeholder key, or `None` for anything else.
    #[must_use]
    pub fn resolve(&self, key: &str) -> Option<&str> {
        match key {
            "app.name" => Some(&self.app_name),
            "app.namespace" => Some(&self.app_namespace),
            "app.project" => Some(&self.project),
            "app.repoUrl" => Some(&self.repo_url),
            "app.revision" => Some(&self.revision),
            "app.syncStatus" => Some(self.sync_status),
            "app.healthStatus" => Some(self.health_status),
            "app.message" => Some(&self.message),
            "app.observedGeneration" => Some(&self.observed_generation),
            "trigger" => Some(self.trigger),
            "service" => Some(self.service),
            "recipient" => Some(&self.recipient),
            _ => None,
        }
    }

    /// The `(namespace, name)` identity, for logs and the deduplication key.
    #[must_use]
    pub fn app(&self) -> (&str, &str) {
        (&self.app_namespace, &self.app_name)
    }

    /// The trigger this notification reports (always one of
    /// [`TRIGGER_NAMES`](ferriscd_crd::annotations::TRIGGER_NAMES)).
    #[must_use]
    pub fn trigger(&self) -> &'static str {
        self.trigger
    }

    /// The service this notification is delivered to.
    #[must_use]
    pub fn service(&self) -> &'static str {
        self.service
    }
}

/// Length-bounds an identity value (`metadata.name` is at most 253 characters by the API server's own
/// validation, but a notification payload should not be able to grow with it).
fn bounded_identity(value: &str) -> String {
    truncate_utf8_bytes(value.trim(), MAX_IDENTITY_BYTES)
}

/// Upper bound on any identity field copied into a notification (256 bytes).
pub const MAX_IDENTITY_BYTES: usize = 256;

/// One parsed template: literal text interleaved with allow-listed field references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Field(&'static str),
}

/// Errors raised while parsing an operator-supplied template.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemplateError {
    /// A `{{` without a matching `}}`.
    #[error("unterminated {{{{ placeholder in the notification template")]
    Unterminated,
    /// An empty placeholder (`{{}}`).
    #[error("empty {{{{}}}} placeholder in the notification template")]
    EmptyPlaceholder,
    /// A placeholder naming something the notification context does not carry.
    #[error("unknown notification template field {field:?}: allowed fields are {allowed:?}")]
    UnknownField {
        /// The rejected placeholder.
        field: String,
        /// The closed allow-list.
        allowed: &'static [&'static str],
    },
}

impl Template {
    /// Parses `raw` into literal and field segments.
    ///
    /// `{{ app.name }}`, `{{app.name}}` and `{{ .app.name }}` are all accepted (`Argo CD` and
    /// `Go` habits differ); leading/trailing whitespace inside the braces is ignored.
    ///
    /// # Errors
    ///
    /// [`TemplateError`] for an unterminated or empty placeholder, or one naming a field outside
    /// [`ALLOWED_FIELDS`].
    pub fn parse(raw: &str) -> Result<Self, TemplateError> {
        let mut segments = Vec::new();
        let mut rest = raw;
        while let Some(open) = rest.find("{{") {
            if open > 0 {
                segments.push(Segment::Literal(rest[..open].to_owned()));
            }
            let after = &rest[open + 2..];
            let Some(close) = after.find("}}") else {
                return Err(TemplateError::Unterminated);
            };
            let field = after[..close].trim();
            let field = field.strip_prefix('.').unwrap_or(field);
            if field.is_empty() {
                return Err(TemplateError::EmptyPlaceholder);
            }
            let Some(allowed) = ALLOWED_FIELDS.iter().find(|allowed| **allowed == field) else {
                return Err(TemplateError::UnknownField {
                    field: field.to_owned(),
                    allowed: &ALLOWED_FIELDS,
                });
            };
            segments.push(Segment::Field(allowed));
            rest = &after[close + 2..];
        }
        if !rest.is_empty() {
            segments.push(Segment::Literal(rest.to_owned()));
        }
        Ok(Self { segments })
    }

    /// Parses a template that must be non-blank (a `ConfigMap` may not blank out an alert title).
    ///
    /// # Errors
    ///
    /// [`TemplateError`] as [`Self::parse`], plus [`TemplateError::EmptyPlaceholder`] for a blank
    /// template.
    pub fn parse_non_empty(raw: &str) -> Result<Self, TemplateError> {
        if raw.trim().is_empty() {
            return Err(TemplateError::EmptyPlaceholder);
        }
        Self::parse(raw)
    }

    /// Renders the template against `context`.
    ///
    /// The result is redaction-clean by construction and bounded to
    /// [`MAX_RENDERED_MESSAGE_BYTES`]: a huge literal in the `ConfigMap` template is truncated rather
    /// than sent, so a misconfiguration cannot turn every alert into a multi-megabyte POST.
    #[must_use]
    pub fn render(&self, context: &NotificationContext) -> String {
        let mut out = String::new();
        for segment in &self.segments {
            match segment {
                Segment::Literal(literal) => out.push_str(literal),
                Segment::Field(field) => {
                    out.push_str(context.resolve(field).unwrap_or_default());
                }
            }
        }
        truncate_utf8_bytes(&out, MAX_RENDERED_MESSAGE_BYTES)
    }

    /// The allow-listed fields this template references, in document order.
    #[must_use]
    pub fn fields(&self) -> Vec<&'static str> {
        self.segments
            .iter()
            .filter_map(|segment| match segment {
                Segment::Field(field) => Some(*field),
                Segment::Literal(_) => None,
            })
            .collect()
    }
}

/// The title and body of one notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageTemplate {
    title: Template,
    body: Template,
}

impl MessageTemplate {
    /// Builds a template from operator-supplied text.
    ///
    /// # Errors
    ///
    /// [`TemplateError`] when either half is blank or references an unknown field.
    pub fn parse(title: &str, body: &str) -> Result<Self, TemplateError> {
        Ok(Self {
            title: Template::parse_non_empty(title)?,
            body: Template::parse_non_empty(body)?,
        })
    }

    /// Renders `(title, body)`.
    #[must_use]
    pub fn render(&self, context: &NotificationContext) -> (String, String) {
        (self.title.render(context), self.body.render(context))
    }

    /// The built-in template of one trigger.
    #[must_use]
    pub fn default_for(trigger: &'static str) -> Self {
        // Built from constants, so parsing cannot fail; the fallback keeps this total without an
        // `unwrap` (`Template::parse` of a literal with no braces is infallible in practice).
        let title = Template::parse(trigger_title(trigger)).unwrap_or_else(|_| Template {
            segments: Vec::new(),
        });
        let body = Template::parse(trigger_body(trigger)).unwrap_or_else(|_| Template {
            segments: Vec::new(),
        });
        Self { title, body }
    }
}

fn trigger_title(trigger: &str) -> &'static str {
    match trigger {
        annotations::TRIGGER_SYNC_SUCCEEDED => "FerrisCD: sync succeeded",
        annotations::TRIGGER_SYNC_FAILED => "FerrisCD: sync failed",
        annotations::TRIGGER_HEALTH_DEGRADED => "FerrisCD: health degraded",
        annotations::TRIGGER_OUT_OF_SYNC => "FerrisCD: application out of sync",
        _ => "FerrisCD notification",
    }
}

fn trigger_body(trigger: &str) -> &'static str {
    match trigger {
        annotations::TRIGGER_SYNC_SUCCEEDED => {
            "{{app.namespace}}/{{app.name}} synced revision {{app.revision}} (health {{app.healthStatus}})"
        }
        annotations::TRIGGER_SYNC_FAILED => {
            "{{app.namespace}}/{{app.name}} failed at revision {{app.revision}}: {{app.message}}"
        }
        annotations::TRIGGER_HEALTH_DEGRADED => {
            "{{app.namespace}}/{{app.name}} is {{app.healthStatus}}: {{app.message}}"
        }
        annotations::TRIGGER_OUT_OF_SYNC => {
            "{{app.namespace}}/{{app.name}} is out of sync at revision {{app.revision}}"
        }
        _ => "{{app.namespace}}/{{app.name}} ({{trigger}})",
    }
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{Condition, ConditionStatus, HealthState, SyncState};
    use ferriscd_crd::{ApplicationSpec, DestinationSpec, GitSourceSpec, RendererSpec, SourceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    use super::*;

    fn app(repo_url: &str) -> Application {
        let spec = ApplicationSpec {
            project: "payments".to_owned(),
            service_account_name: None,
            source: Some(SourceSpec {
                git: Some(GitSourceSpec {
                    repo_url: repo_url.to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: RendererSpec::default(),
            }),
            sources: Vec::new(),
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut application = Application::new("demo-app", spec);
        application.metadata.namespace = Some("ferriscd-system".to_owned());
        application.metadata.generation = Some(7);
        application
    }

    fn status(message: &str) -> ApplicationStatus {
        ApplicationStatus {
            observed_generation: Some(7),
            sync: Some(SyncState::new(
                SyncStatus::Synced,
                Some("abc1234".to_owned()),
            )),
            health: Some(HealthState::new(HealthStatus::Healthy)),
            conditions: vec![Condition::ready(
                ConditionStatus::True,
                "SyncSucceeded",
                message,
                Time("2026-11-24T12:00:00Z".parse().expect("timestamp")),
            )],
            ..ApplicationStatus::default()
        }
    }

    fn context(repo_url: &str, message: &str) -> NotificationContext {
        NotificationContext::from_status(
            &app(repo_url),
            &status(message),
            annotations::TRIGGER_SYNC_SUCCEEDED,
            "slack",
            "payments-oncall",
        )
    }

    #[test]
    fn every_built_in_template_parses_and_renders_its_trigger() {
        for trigger in annotations::TRIGGER_NAMES {
            let template = MessageTemplate::default_for(trigger);
            let (title, body) = template.render(&context("https://example.com/repo.git", "ok"));
            assert!(title.starts_with("FerrisCD:"), "{trigger}: {title}");
            assert!(
                body.contains("ferriscd-system/demo-app"),
                "{trigger}: {body}"
            );
        }
    }

    /// **Verification bullet (5), template half:** nothing secret survives into the rendered
    /// message — not the Git token in the repository URL, not a base64 payload quoted by the API
    /// server in a condition message.
    #[test]
    fn rendered_messages_never_carry_secret_material() {
        let base64_blob = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==";
        let ctx = context(
            "https://bot:ghp_SuperSecretToken123@git.example.com/org/repo.git?access_token=abc",
            &format!("rejected value {base64_blob} for key password=s3cr3t-value"),
        );
        let template = MessageTemplate::default_for(annotations::TRIGGER_SYNC_FAILED);
        let rendered = format!("{}{}", template.render(&ctx).0, template.render(&ctx).1);

        assert!(
            !rendered.contains("ghp_SuperSecretToken123"),
            "the repository token must be redacted: {rendered}"
        );
        assert!(
            !rendered.contains("access_token=abc"),
            "query credentials must be redacted: {rendered}"
        );
        assert!(
            !rendered.contains(base64_blob),
            "payload-shaped runs must be redacted: {rendered}"
        );
        // The identity and the revision stay: an alert that names nothing is useless.
        assert!(rendered.contains("ferriscd-system/demo-app"), "{rendered}");
        assert!(rendered.contains("abc1234"), "{rendered}");
    }

    /// **`T20.1` finding (M5).** `app.repoUrl` names **every** declared source of a multi-source
    /// `Application`, each redacted — not just the first one, and not the first declared entry.
    #[test]
    fn the_repo_url_field_names_every_declared_source() {
        let mut multi = app("https://example.com/chart.git");
        multi.spec.source = None;
        multi.spec.sources = vec![
            ferriscd_crd::MultiSourceEntry {
                ref_name: Some("chart".to_owned()),
                git: None,
                oci: Some(ferriscd_crd::OciSourceSpec {
                    url: "oci://ghcr.io/example/payments".to_owned(),
                    tag: Some("1.4.2".to_owned()),
                    digest: None,
                    path: String::new(),
                }),
                renderer: None,
            },
            ferriscd_crd::MultiSourceEntry {
                ref_name: Some("values".to_owned()),
                git: Some(GitSourceSpec {
                    repo_url: "https://bot:ghp_SecretValuesToken@git.example.com/org/values.git"
                        .to_owned(),
                    target_revision: "main".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: None,
            },
        ];
        let ctx = NotificationContext::from_status(
            &multi,
            &status("ok"),
            annotations::TRIGGER_SYNC_SUCCEEDED,
            "slack",
            "payments-oncall",
        );
        let repo_url = ctx.resolve("app.repoUrl").expect("the field resolves");
        assert!(
            repo_url.contains("oci://ghcr.io/example/payments"),
            "the chart source must be reported: {repo_url}"
        );
        assert!(
            repo_url.contains("git.example.com/org/values.git"),
            "the values source must be reported too: {repo_url}"
        );
        assert!(
            repo_url.contains(", "),
            "the sources are comma-joined in declaration order: {repo_url}"
        );
        assert!(
            !repo_url.contains("ghp_SecretValuesToken"),
            "every joined URL is redacted, not only the first: {repo_url}"
        );

        // A `v1.0` single-source Application still reports exactly its one URL.
        let single = context("https://example.com/repo.git", "ok");
        assert_eq!(
            single.resolve("app.repoUrl"),
            Some("https://example.com/repo.git")
        );
    }

    /// A `ConfigMap` template may only reference the closed allow-list; a typo is refused at load
    /// time instead of rendering an empty alert.
    #[test]
    fn unknown_or_malformed_placeholders_are_refused() {
        assert!(Template::parse("{{app.name}}").is_ok());
        assert!(Template::parse("{{ .app.name }}").is_ok());
        assert_eq!(
            Template::parse("{{app.status.sync.status}}"),
            Err(TemplateError::UnknownField {
                field: "app.status.sync.status".to_owned(),
                allowed: &ALLOWED_FIELDS,
            })
        );
        // The documented narrowing (see the module docs): `conditions` and `history` are *not*
        // addressable, so a template cannot pull a raw condition message or the revision history
        // into a payload that leaves the cluster. `app.message` is the one bounded substitute.
        for refused in ["app.conditions", "app.history", "app.status.conditions"] {
            assert_eq!(
                Template::parse(&format!("{{{{{refused}}}}}")),
                Err(TemplateError::UnknownField {
                    field: refused.to_owned(),
                    allowed: &ALLOWED_FIELDS,
                }),
                "{refused:?} must not be a template field"
            );
        }
        assert_eq!(
            Template::parse("{{app.name"),
            Err(TemplateError::Unterminated)
        );
        assert_eq!(
            Template::parse("{{}}"),
            Err(TemplateError::EmptyPlaceholder)
        );
        assert_eq!(
            Template::parse_non_empty("   "),
            Err(TemplateError::EmptyPlaceholder)
        );
        assert_eq!(
            MessageTemplate::parse("title", ""),
            Err(TemplateError::EmptyPlaceholder)
        );

        let template = Template::parse("{{app.name}}@{{app.revision}}/{{trigger}}").expect("valid");
        assert_eq!(
            template.fields(),
            vec!["app.name", "app.revision", "trigger"]
        );
    }

    #[test]
    fn literal_text_is_preserved_and_an_unknown_key_never_renders() {
        let template = Template::parse("a {{app.name}} b {{recipient}} c").expect("valid");
        let rendered = template.render(&context("https://example.com/repo.git", "ok"));
        assert_eq!(rendered, "a demo-app b payments-oncall c");

        // A literal that looks like a placeholder needs the closing braces to be parsed as one; an
        // unmatched `}` is literal text.
        let literal = Template::parse("100}}% {{app.name}}").expect("valid");
        assert_eq!(
            literal.render(&context("https://example.com/repo.git", "ok")),
            "100}}% demo-app"
        );
    }

    /// **Regression guard:** a 40-character commit SHA is a "payload-shaped run" to the generic
    /// redactor, so the identity fields must not go through it — a notification that says
    /// `<redacted 40 char(s)>` instead of the revision is useless.
    #[test]
    fn a_real_commit_sha_survives_into_the_message() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(sha.len(), 40);
        let ctx = NotificationContext::from_status(
            &app("https://example.com/repo.git"),
            &status("applied 3 of 3 resources"),
            annotations::TRIGGER_SYNC_SUCCEEDED,
            "slack",
            "payments-oncall",
        );
        assert_eq!(ctx.resolve("app.revision"), Some("abc1234"));
        let long_sha = NotificationContext::from_status(
            &app("https://example.com/repo.git"),
            &ApplicationStatus {
                observed_generation: Some(7),
                sync: Some(SyncState::new(SyncStatus::Synced, Some(sha.to_owned()))),
                health: Some(HealthState::new(HealthStatus::Healthy)),
                ..ApplicationStatus::default()
            },
            annotations::TRIGGER_SYNC_SUCCEEDED,
            "slack",
            "payments-oncall",
        );
        assert_eq!(long_sha.resolve("app.revision"), Some(sha));
        let (_, body) =
            MessageTemplate::default_for(annotations::TRIGGER_SYNC_SUCCEEDED).render(&long_sha);
        assert!(body.contains(sha), "{body}");
        assert!(!body.contains("<redacted"), "{body}");

        // The *condition message* still goes through the redactor (the API server can quote a value).
        let with_secret = NotificationContext::from_status(
            &app("https://example.com/repo.git"),
            &status("rejected value QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"),
            annotations::TRIGGER_SYNC_FAILED,
            "slack",
            "payments-oncall",
        );
        assert!(
            with_secret
                .resolve("app.message")
                .is_some_and(|message| message.contains("<redacted")),
            "{:?}",
            with_secret.resolve("app.message")
        );
    }

    /// A pathological `ConfigMap` template cannot produce an unbounded body.
    #[test]
    fn rendered_messages_are_bounded() {
        let long = format!(
            "{{{{app.name}}}}{}",
            "x".repeat(MAX_RENDERED_MESSAGE_BYTES * 2)
        );
        let template = Template::parse(&long).expect("valid");
        let rendered = template.render(&context("https://example.com/repo.git", "ok"));
        assert!(
            rendered.len() <= MAX_RENDERED_MESSAGE_BYTES,
            "rendered {} bytes",
            rendered.len()
        );
        assert!(rendered.starts_with("demo-app"), "{rendered}");
    }

    /// `from_status` is the only constructor, and it fills every allow-listed field.
    #[test]
    fn the_context_exposes_exactly_the_allow_listed_fields() {
        let ctx = context("https://example.com/repo.git", "applied 2 of 2 resources");
        for field in ALLOWED_FIELDS {
            assert!(
                ctx.resolve(field).is_some(),
                "field {field} must be resolved by the context"
            );
        }
        assert_eq!(ctx.resolve("app.name"), Some("demo-app"));
        assert_eq!(ctx.resolve("app.namespace"), Some("ferriscd-system"));
        assert_eq!(ctx.resolve("app.project"), Some("payments"));
        assert_eq!(ctx.resolve("app.revision"), Some("abc1234"));
        assert_eq!(ctx.resolve("app.syncStatus"), Some("Synced"));
        assert_eq!(ctx.resolve("app.healthStatus"), Some("Healthy"));
        assert_eq!(ctx.resolve("app.observedGeneration"), Some("7"));
        assert_eq!(ctx.resolve("trigger"), Some("on-sync-succeeded"));
        assert_eq!(ctx.resolve("service"), Some("slack"));
        assert_eq!(ctx.resolve("recipient"), Some("payments-oncall"));
        assert!(ctx.resolve("app.inventory").is_none());
        assert!(ctx.resolve("secret").is_none());
        assert_eq!(ctx.app(), ("ferriscd-system", "demo-app"));
    }
}

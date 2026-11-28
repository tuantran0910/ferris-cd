//! `Application` custom resource: the user-facing declaration of a GitOps workload.
//!
//! The schema is deliberately built so invalid states are unrepresentable:
//! [`SyncPolicy::automated`] is an `Option`, therefore `automated: false` combined with
//! `selfHeal: true` cannot be expressed at all (review finding P1-06 / trap M5-class bug).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::DEFAULT_PROJECT_NAME;
use crate::status::ApplicationStatus;

/// Revision used when `spec.source.git.targetRevision` is omitted (matches Argo CD).
pub const DEFAULT_TARGET_REVISION: &str = "HEAD";

/// Destination cluster used when `spec.destination.cluster` is omitted.
pub const DEFAULT_DESTINATION_CLUSTER: &str = "in-cluster";

/// Default reconcile requeue interval in seconds when `spec.requeueAfterSeconds` is omitted.
pub const DEFAULT_REQUEUE_AFTER_SECONDS: u32 = 180;

/// Lowest accepted `spec.revisionHistoryLimit`.
pub const MIN_REVISION_HISTORY_LIMIT: i32 = 1;

/// Highest accepted `spec.revisionHistoryLimit` (keeps `status.history` bounded).
pub const MAX_REVISION_HISTORY_LIMIT: i32 = 20;

/// Default `spec.revisionHistoryLimit` when omitted.
pub const DEFAULT_REVISION_HISTORY_LIMIT: i32 = 10;

/// Default `spec.syncPolicy.retry.limit`.
pub const DEFAULT_RETRY_LIMIT: u32 = 5;

/// Default initial retry backoff duration in seconds.
pub const DEFAULT_RETRY_BACKOFF_DURATION_SECONDS: u32 = 5;

/// Default retry backoff factor.
pub const DEFAULT_RETRY_BACKOFF_FACTOR: u32 = 2;

/// Default maximum retry backoff duration in seconds.
pub const DEFAULT_RETRY_BACKOFF_MAX_DURATION_SECONDS: u32 = 180;

/// `Application` custom resource (`ferriscd.io/v1alpha1`).
///
/// The generated `CustomResourceDefinition` carries the `status` subresource plus the
/// `SYNC` / `HEALTH` / `REVISION` / `AGE` printer columns.
// `kube` takes one `printcolumn(...)` attribute per column, so repeated keys such as
// `type_ = "string"` are intentional and must not be de-duplicated.
#[allow(clippy::duplicated_attributes)]
#[derive(CustomResource, Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[kube(
    group = "ferriscd.io",
    version = "v1alpha1",
    kind = "Application",
    namespaced,
    status = "ApplicationStatus",
    shortname = "app",
    shortname = "apps",
    doc = "Declarative GitOps application: render a Git source and sync it to a destination cluster namespace",
    derive = "PartialEq",
    printcolumn(
        name = "SYNC",
        type_ = "string",
        json_path = ".status.sync.status",
        description = "Current sync status (Synced, OutOfSync, Unknown)"
    ),
    printcolumn(
        name = "HEALTH",
        type_ = "string",
        json_path = ".status.health.status",
        description = "Aggregated health of the managed resources"
    ),
    printcolumn(
        name = "REVISION",
        type_ = "string",
        json_path = ".status.sync.revision",
        description = "Git revision currently deployed"
    ),
    printcolumn(
        name = "AGE",
        type_ = "date",
        json_path = ".metadata.creationTimestamp",
        description = "Age of the Application"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSpec {
    /// `AppProject` this application belongs to; checked on every rendered resource.
    ///
    /// Defaults to [`DEFAULT_PROJECT_NAME`].
    #[serde(default = "default_project")]
    pub project: String,

    /// ServiceAccount (in the destination namespace) used for impersonation.
    ///
    /// Only honored when the referenced `AppProject` lists it in `allowedServiceAccounts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,

    /// Where the desired manifests come from and how they are rendered.
    pub source: SourceSpec,

    /// Target cluster and namespace.
    pub destination: DestinationSpec,

    /// Automated sync policy, sync options, and retry behaviour.
    ///
    /// Omitted entirely for manual-only sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_policy: Option<SyncPolicy>,

    /// Field-level drift suppressions applied before diffing.
    #[serde(default)]
    pub ignore_differences: Vec<IgnoreDifference>,

    /// Periodic reconcile interval in seconds (default [`DEFAULT_REQUEUE_AFTER_SECONDS`]).
    #[serde(default = "default_requeue_after_seconds")]
    #[schemars(range(min = 1, max = 86_400))]
    pub requeue_after_seconds: u32,

    /// Hard cap on `status.history` entries, validated to `1..=20`
    /// (default [`DEFAULT_REVISION_HISTORY_LIMIT`]).
    #[serde(default = "default_revision_history_limit")]
    #[schemars(range(min = 1, max = 20))]
    pub revision_history_limit: i32,
}

fn default_project() -> String {
    DEFAULT_PROJECT_NAME.to_owned()
}

fn default_requeue_after_seconds() -> u32 {
    DEFAULT_REQUEUE_AFTER_SECONDS
}

fn default_revision_history_limit() -> i32 {
    DEFAULT_REVISION_HISTORY_LIMIT
}

/// Source of the desired state: exactly one Git repository **or** one OCI artifact, plus its
/// renderer.
///
/// `T18.3` evolved this type **additively**: `git` became optional and `oci` was added, so every
/// `v1alpha1` `Application` already stored in `etcd` keeps validating and round-tripping
/// byte-identically (both fields are `skip_serializing_if = "Option::is_none"`, and a Git
/// application never gains an `oci` key). Exactly-one-of is enforced twice: server-side by the
/// CEL rule this crate injects into the generated CRD (`x-kubernetes-validations`), and offline by
/// [`ApplicationSpec::validate`] with the same verdicts.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceSpec {
    /// Git repository, revision, and manifest sub-path. Mutually exclusive with `oci`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitSourceSpec>,

    /// OCI artifact (Helm chart or Kustomize/manifest bundle). Mutually exclusive with `git`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci: Option<OciSourceSpec>,

    /// Renderer used to turn the checked-out path into Kubernetes manifests.
    #[serde(default)]
    pub renderer: RendererSpec,
}

impl SourceSpec {
    /// The Git source, when this `Application` is Git-backed.
    #[must_use]
    pub fn git_source(&self) -> Option<&GitSourceSpec> {
        self.git.as_ref()
    }

    /// The OCI source, when this `Application` is registry-backed.
    #[must_use]
    pub fn oci_source(&self) -> Option<&OciSourceSpec> {
        self.oci.as_ref()
    }

    /// The source URL (`git.repoURL` or `oci.url`; `""` when neither is set).
    ///
    /// Callers that log or report this must still pass it through
    /// `ferriscd_engine::manifest::redact_repo_url`: a Git remote routinely embeds a token.
    #[must_use]
    pub fn repo_url(&self) -> &str {
        match (&self.git, &self.oci) {
            (Some(git), _) => &git.repo_url,
            (None, Some(oci)) => &oci.url,
            (None, None) => "",
        }
    }

    /// The manifest sub-path inside the source (`""` means the source root).
    #[must_use]
    pub fn source_path(&self) -> &str {
        match (&self.git, &self.oci) {
            (Some(git), _) => &git.path,
            (None, Some(oci)) => &oci.path,
            (None, None) => "",
        }
    }

    /// The revision the caller asked for: `git.targetRevision`, else `oci.tag`, else
    /// `oci.digest`, else `""`.
    #[must_use]
    pub fn requested_revision(&self) -> &str {
        match (&self.git, &self.oci) {
            (Some(git), _) => &git.target_revision,
            (None, Some(oci)) => oci
                .tag
                .as_deref()
                .or(oci.digest.as_deref())
                .unwrap_or_default(),
            (None, None) => "",
        }
    }
}

/// Git repository coordinates for an [`Application`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitSourceSpec {
    /// Repository clone URL (`https://`, `ssh://`, SCP-style SSH, or a local test path).
    #[serde(rename = "repoURL")]
    pub repo_url: String,

    /// Branch, tag, `HEAD`, or full 40-character commit SHA.
    #[serde(default = "default_target_revision")]
    pub target_revision: String,

    /// Relative sub-directory inside the repository (`""` means repository root).
    #[serde(default)]
    pub path: String,
}

fn default_target_revision() -> String {
    DEFAULT_TARGET_REVISION.to_owned()
}

/// OCI artifact coordinates for an [`Application`] (`T18.3`).
///
/// The artifact is a single layer of a Helm chart (`application/vnd.cncf.helm.chart.content.v1.tar+gzip`)
/// or a manifest bundle (`application/vnd.oci.image.layer.v1.tar+gzip`,
/// `application/vnd.cncf.flux.content.v1.tar+gzip`). Exactly one of `tag`/`digest` is required by
/// the injected CEL rule (and by [`ApplicationSpec::validate`]); pinning `digest` is the immutable
/// reference and, when both are set, the resolved manifest digest must equal it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OciSourceSpec {
    /// Artifact reference: `oci://<registry>/<repository>` (HTTPS-only registry transport).
    pub url: String,

    /// Tag to resolve (a plain tag, never a SemVer range: resolution stays a digest lookup).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Immutable manifest digest (`sha256:<64 lowercase hex>`).
    ///
    /// When both `tag` and `digest` are set the resolved manifest must match `digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// Relative sub-directory inside the extracted artifact (`""` means the artifact root).
    #[serde(default)]
    pub path: String,
}

/// Digest algorithm prefix of every accepted OCI digest (`sha256:<64-hex>`).
pub const OCI_DIGEST_PREFIX: &str = "sha256:";

/// Number of lowercase hexadecimal characters in an accepted OCI digest.
pub const OCI_DIGEST_HEX_LEN: usize = 64;

/// Longest accepted `spec.source.oci.tag` (the OCI distribution tag grammar allows 128).
pub const MAX_OCI_TAG_LEN: usize = 128;

impl OciSourceSpec {
    /// Validates the reference against the invariants the CRD schema enforces.
    ///
    /// The structural checks mirror the injected CEL rules
    /// (`self.?tag.hasValue() || self.?digest.hasValue()` — the null half matters: an explicit
    /// `tag: null` is "no tag" here and "no value" to `hasValue()`, while a bare `has()` would be
    /// true for it); URL *transport* policy (HTTPS-only in production) is the engine's job, exactly
    /// like `RepoUrlPolicy` for `spec.source.git.repoURL`.
    pub fn validate(&self) -> Result<(), SpecValidationError> {
        validate_oci_reference_url(&self.url)?;
        if let Some(tag) = self.tag.as_deref() {
            validate_oci_tag(tag)?;
        }
        if let Some(digest) = self.digest.as_deref() {
            validate_oci_digest(digest)?;
        }
        if self.tag.is_none() && self.digest.is_none() {
            return Err(SpecValidationError::MissingOciReference);
        }
        Ok(())
    }
}

/// Validates the structural shape of `spec.source.oci.url`.
///
/// Only the parts the offline check can be certain about are enforced: a supported scheme
/// (`oci://`, `https://`, `http://` — the engine then refuses plaintext under its production
/// policy), a non-empty host, a non-empty repository path, and no embedded credentials. A
/// credential in a source URL would end up in `status` and in logs, so it is refused here exactly
/// as the Git path refuses it — and the URL echoed into the rejection goes through
/// [`redact_url_userinfo`] first, so refusing it is not itself the disclosure.
///
/// ## The asymmetry with the engine is deliberate and one-directional
///
/// The set of URLs this check accepts is a strict **superset** of the set the engine accepts
/// (`ferriscd_engine::repo::oci::OciSource::validate`): every reference the engine accepts passes
/// here, and some that pass here are refused there. The engine additionally enforces
///
/// * the transport policy (`http://` only under the explicit local-development opt-in — this crate
///   cannot know the controller's flag, so the scheme is accepted here);
/// * `validate_authority_host`: no leading `-`, a well-formed `host[:port]` (no malformed IPv6
///   brackets, no port `0`), which needs the engine's shared host parser;
/// * no `.`/`..` segments in the repository path (this check rejects empty segments only).
///
/// So `validate()` passing is necessary but not sufficient: a reference accepted offline can still
/// be refused by the engine, which is where the error belongs (the engine is the component that
/// dials the registry, and `T18.4` — not this schema — owns the transport flag). The direction
/// matters: the reverse (offline refusing what the engine accepts) would make a valid stored
/// `Application` unusable, and the schema must never do that without a version bump.
fn validate_oci_reference_url(url: &str) -> Result<(), SpecValidationError> {
    let invalid = |reason: &str| SpecValidationError::InvalidOciUrl {
        url: redact_url_userinfo(url),
        reason: reason.to_owned(),
    };

    if url.trim().is_empty() {
        return Err(invalid("the reference must not be empty"));
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid(
            "the reference must not contain whitespace or control characters",
        ));
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(invalid(
            "the reference must be an absolute URL, e.g. oci://ghcr.io/org/chart",
        ));
    };
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "oci" | "https" | "http") {
        return Err(invalid(
            "the reference scheme must be oci://, https://, or http://",
        ));
    }
    let (authority, path) = rest
        .split_once('/')
        .ok_or_else(|| invalid("the reference must be oci://<registry>/<repository>"))?;
    if authority.is_empty() {
        return Err(invalid("the reference must name a registry host"));
    }
    if authority.contains('@') {
        return Err(invalid(
            "the reference must not embed credentials; use a ferriscd.io/secret-type=repository \
             Secret",
        ));
    }
    if path.is_empty() || path.ends_with('/') {
        return Err(invalid(
            "the reference must name a repository (no empty or trailing-slash path)",
        ));
    }
    if path.split('/').any(|segment| segment.is_empty()) {
        return Err(invalid(
            "the reference repository path must not contain empty segments",
        ));
    }
    Ok(())
}

/// Returns `url` with any embedded `user:password@`/`token@` userinfo replaced by `[REDACTED]`.
///
/// `ferriscd_engine` has an equivalent rule in `repo::types`, but this crate cannot depend on it
/// (the engine depends on the CRD types, not the other way round), so the rule is duplicated here.
/// It is not optional: a rejected `spec.source.oci.url` is echoed into
/// [`SpecValidationError::InvalidOciUrl`], which reaches `Application.status`, Events, and logs —
/// and the *only* references that carry userinfo are precisely the ones being rejected, so an
/// unredacted echo would publish the credential as part of refusing it.
///
/// The redaction is **scheme-agnostic** (finding H-A): a caller that forgets the scheme still
/// writes `user:token@ghcr.io/org/chart`, and "there is no `://`, so there is no userinfo" was
/// exactly the assumption that echoed that token. The rule is therefore: split an optional
/// `scheme://`, take everything up to the first `/`, `?`, or `#` as the authority, and redact the
/// **last** `@` inside it (userinfo may itself contain an unescaped `@`; the host cannot).
///
/// Unlike the Git spelling this never has to keep a bare `user@host`: an OCI reference has no
/// SCP-style form (`git@github.com:org/repo.git`), so every `@` before the authority's end is a
/// credential. Only that userinfo is a secret; the rest is kept so the error still names the
/// offending reference.
fn redact_url_userinfo(url: &str) -> String {
    let (prefix, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_end);
    match authority.rsplit_once('@') {
        Some((_, host_part)) => format!("{prefix}[REDACTED]@{host_part}{suffix}"),
        None => url.to_owned(),
    }
}

/// Validates `spec.source.oci.tag` against the OCI distribution tag grammar.
fn validate_oci_tag(tag: &str) -> Result<(), SpecValidationError> {
    let invalid = |reason: &str| SpecValidationError::InvalidOciTag {
        tag: tag.to_owned(),
        reason: reason.to_owned(),
    };
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return Err(invalid("the tag must not be empty"));
    };
    if tag.len() > MAX_OCI_TAG_LEN {
        return Err(invalid("the tag must be at most 128 characters"));
    }
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return Err(invalid(
            "the tag must start with an alphanumeric character or '_'",
        ));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(invalid(
            "the tag must contain only alphanumeric characters, '.', '_', and '-'",
        ));
    }
    Ok(())
}

/// Validates `spec.source.oci.digest` as `sha256:<64 lowercase hex>`.
fn validate_oci_digest(digest: &str) -> Result<(), SpecValidationError> {
    let invalid = || SpecValidationError::InvalidOciDigest {
        digest: digest.to_owned(),
    };
    let Some((algorithm, hex)) = digest.split_once(':') else {
        return Err(invalid());
    };
    if algorithm != "sha256"
        || hex.len() != OCI_DIGEST_HEX_LEN
        || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Manifest renderer selection.
///
/// Exactly one renderer is representable, so a source can never request both
/// `plainYaml` and `helm`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum RendererSpec {
    /// Automatic renderer detection based on the files present in the source path.
    Auto(AutoRenderer),
    /// Literal multi-document YAML/JSON manifests.
    PlainYaml(PlainYamlRenderer),
    /// Kustomize overlay (remote resources are rejected).
    Kustomize(KustomizeRenderer),
    /// Helm chart rendering (CRDs are not installed unless `includeCRDs` is set).
    Helm(HelmRenderer),
}

impl Default for RendererSpec {
    fn default() -> Self {
        Self::Auto(AutoRenderer {})
    }
}

/// Automatic renderer detection (empty marker object: `renderer: {auto: {}}`).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct AutoRenderer {}

/// Plain YAML/JSON manifest renderer.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct PlainYamlRenderer {
    /// Recurse into sub-directories of the source path (`spec.source.git.path` /
    /// `spec.source.oci.path`) (default `true`).
    #[serde(default = "default_true")]
    pub recursive: bool,
}

/// Kustomize renderer.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct KustomizeRenderer {
    /// Overlay directory (relative to the source path (`spec.source.git.path` /
    /// `spec.source.oci.path`)); defaults to the source path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kustomization_path: Option<String>,

    /// Image overrides applied to the rendered output (`name=newImage:tag`).
    #[serde(default)]
    pub images: Vec<String>,
}

/// Helm renderer.
///
/// Deliberately minimal for `v1alpha1`: arbitrary chart value maps are added with the
/// Helm integration (Phase 11) instead of leaking an untyped schema into the CRD now.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct HelmRenderer {
    /// Release name used for rendering; defaults to the `Application` name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_name: Option<String>,

    /// Additional values files, relative to the source path (`spec.source.git.path` /
    /// `spec.source.oci.path`).
    #[serde(default)]
    pub value_files: Vec<String>,

    /// Install CRDs shipped in the chart's `crds/` directory (default `false`).
    #[serde(default, rename = "includeCRDs")]
    pub include_crds: bool,
}

/// Target cluster and namespace for rendered resources.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DestinationSpec {
    /// Target cluster: `in-cluster` or a FerrisCD cluster Secret name.
    #[serde(default = "default_destination_cluster")]
    pub cluster: String,

    /// Namespace injected onto namespaced resources that do not set one explicitly.
    pub namespace: String,
}

fn default_destination_cluster() -> String {
    DEFAULT_DESTINATION_CLUSTER.to_owned()
}

/// Sync policy: automation, per-sync options, and retry behaviour.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncPolicy {
    /// Automated sync policy.
    ///
    /// `None` means manual-only sync. Because this is an `Option` of a struct, the
    /// invalid combination `automated: false` + `selfHeal: true` cannot be expressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automated: Option<AutomatedSyncPolicy>,

    /// Sync options applied to every sync (safe defaults: no forced apply, no CRD/namespace pruning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_options: Option<SyncOptions>,

    /// Bounded retry policy for failed sync operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryPolicy>,
}

impl SyncPolicy {
    /// Returns whether automated sync is enabled.
    #[must_use]
    pub fn is_automated(&self) -> bool {
        self.automated.is_some()
    }

    /// Returns whether automated self-healing (drift correction) is enabled.
    ///
    /// Always `false` when [`Self::automated`] is `None`.
    #[must_use]
    pub fn self_heal_enabled(&self) -> bool {
        self.automated
            .as_ref()
            .is_some_and(|automated| automated.self_heal)
    }

    /// Returns whether automated pruning of removed resources is enabled.
    #[must_use]
    pub fn prune_enabled(&self) -> bool {
        self.automated
            .as_ref()
            .is_some_and(|automated| automated.prune)
    }
}

/// Automated sync policy.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct AutomatedSyncPolicy {
    /// Prune resources removed from Git (never CRDs/Namespaces unless explicitly opted in).
    #[serde(default)]
    pub prune: bool,

    /// Re-apply live drift automatically.
    #[serde(default)]
    pub self_heal: bool,
}

/// Per-sync behaviour flags.
///
/// Safety defaults: `pruneCRDs`/`pruneNamespaces`/`serverSideForce` are `false`, so a
/// misconfigured `Application` can never clobber HPA-managed fields or delete cluster
/// infrastructure.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct SyncOptions {
    /// Create `spec.destination.namespace` when it does not exist.
    pub create_namespace: bool,

    /// Apply pruning last, after every other resource converged.
    pub prune_last: bool,

    /// Allow pruning `CustomResourceDefinition` objects (safety rail: default `false`).
    #[serde(rename = "pruneCRDs")]
    pub prune_crds: bool,

    /// Allow pruning `Namespace` objects (safety rail: default `false`).
    #[serde(rename = "pruneNamespaces")]
    pub prune_namespaces: bool,

    /// Send `force: true` in Server-Side Apply patches (default `false`).
    pub server_side_force: bool,

    /// Only apply resources that are actually out of sync (default `true`).
    pub apply_out_of_sync_only: bool,

    /// Field managers whose ownership FerrisCD may take over (brownfield adoption).
    pub takeover_field_managers: Vec<String>,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            create_namespace: false,
            prune_last: true,
            prune_crds: false,
            prune_namespaces: false,
            server_side_force: false,
            apply_out_of_sync_only: true,
            takeover_field_managers: Vec::new(),
        }
    }
}

/// Field-level drift suppression for one Group/Kind (optionally narrowed by name/namespace).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreDifference {
    /// API group (`""` for the core group); omitted means "any group".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Kind the suppression applies to.
    pub kind: String,

    /// Resource name the suppression applies to; omitted means "any name".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Resource namespace the suppression applies to; omitted means "any namespace".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// RFC 6901 JSON Pointers whose live/desired values are ignored during diffing.
    #[serde(default)]
    pub json_pointers: Vec<String>,

    /// Field managers whose owned fields are ignored during diffing.
    #[serde(default)]
    pub managed_fields_managers: Vec<String>,
}

/// Bounded retry policy for sync operations.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (default [`DEFAULT_RETRY_LIMIT`]).
    #[serde(default = "default_retry_limit")]
    pub limit: u32,

    /// Exponential backoff parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff: Option<RetryBackoff>,
}

fn default_retry_limit() -> u32 {
    DEFAULT_RETRY_LIMIT
}

/// Exponential backoff parameters for sync retries.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RetryBackoff {
    /// Initial backoff duration in seconds.
    pub duration_seconds: u32,

    /// Multiplier applied after every failed attempt.
    pub factor: u32,

    /// Upper bound for a single backoff duration in seconds.
    pub max_duration_seconds: u32,
}

impl Default for RetryBackoff {
    fn default() -> Self {
        Self {
            duration_seconds: DEFAULT_RETRY_BACKOFF_DURATION_SECONDS,
            factor: DEFAULT_RETRY_BACKOFF_FACTOR,
            max_duration_seconds: DEFAULT_RETRY_BACKOFF_MAX_DURATION_SECONDS,
        }
    }
}

/// Validation failure for an [`ApplicationSpec`].
///
/// The generated CRD schema rejects the same violations server-side (422); this type
/// gives the controller and CLI an offline, equally strict check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecValidationError {
    /// `spec.project` was empty.
    #[error("spec.project must not be empty")]
    EmptyProject,
    /// `spec.destination.namespace` was empty.
    #[error("spec.destination.namespace must not be empty")]
    EmptyDestinationNamespace,
    /// `spec.destination.cluster` was present but blank.
    #[error(
        "spec.destination.cluster must not be blank: omit the field to mean `in-cluster`, or name \
         a registered cluster"
    )]
    EmptyDestinationCluster,
    /// `spec.source.git.repoURL` was empty.
    #[error("spec.source.git.repoURL must not be empty")]
    EmptyRepoUrl,
    /// `spec.source.git.targetRevision` was empty.
    #[error("spec.source.git.targetRevision must not be empty")]
    EmptyTargetRevision,
    /// Neither `spec.source.git` nor `spec.source.oci` was set.
    #[error(
        "exactly one of spec.source.git or spec.source.oci must be specified: neither is set, so \
         there is nothing to render"
    )]
    MissingSource,
    /// Both `spec.source.git` and `spec.source.oci` were set.
    #[error(
        "exactly one of spec.source.git or spec.source.oci must be specified: both are set, and \
         choosing one would silently ignore the other"
    )]
    AmbiguousSource,
    /// `spec.source.oci.url` was empty, malformed, or not an OCI reference.
    #[error("spec.source.oci.url {url:?} is not a usable OCI artifact reference: {reason}")]
    InvalidOciUrl {
        /// The rejected URL, with any embedded userinfo redacted — scheme or no scheme.
        ///
        /// Not "credential-free because an OCI reference cannot carry userinfo": it can, that is
        /// one of the shapes rejected here, and this value reaches `Application.status`, Events,
        /// and logs. `redact_url_userinfo` is what makes the echoed form safe, and it must stay
        /// scheme-agnostic: a reference that forgot the scheme is still an echo of the token.
        url: String,
        /// Why it was rejected.
        reason: String,
    },
    /// `spec.source.oci.digest` was not a `sha256:<64 lowercase hex>` digest.
    #[error(
        "spec.source.oci.digest {digest:?} is not a usable OCI digest: expected sha256: followed by \
         64 lowercase hexadecimal characters"
    )]
    InvalidOciDigest {
        /// The rejected digest.
        digest: String,
    },
    /// `spec.source.oci.tag` was present but blank (or not a valid tag).
    #[error("spec.source.oci.tag {tag:?} is not a usable OCI tag: {reason}")]
    InvalidOciTag {
        /// The rejected tag.
        tag: String,
        /// Why it was rejected.
        reason: String,
    },
    /// Neither `spec.source.oci.tag` nor `spec.source.oci.digest` was set.
    ///
    /// The CRD enforces the same rule with CEL
    /// (`self.?tag.hasValue() || self.?digest.hasValue()`); a floating artifact would make "which
    /// artifact did this revision come from?" unanswerable.
    #[error(
        "at least one of spec.source.oci.tag or spec.source.oci.digest must be specified: an OCI \
         artifact reference must name an immutable artifact"
    )]
    MissingOciReference,
    /// `spec.requeueAfterSeconds` was zero.
    #[error("spec.requeueAfterSeconds must be greater than zero")]
    ZeroRequeueAfter,
    /// `spec.revisionHistoryLimit` was outside `1..=20`.
    #[error("spec.revisionHistoryLimit must be between 1 and 20, got {value}")]
    RevisionHistoryLimitOutOfRange {
        /// The rejected value.
        value: i32,
    },
}

impl ApplicationSpec {
    /// Validates the spec against the invariants the CRD schema enforces.
    ///
    /// This mirrors the OpenAPI `minimum`/`maximum` bounds so a spec is rejected
    /// identically offline (CLI/controller) and online (API server 422).
    pub fn validate(&self) -> Result<(), SpecValidationError> {
        if self.project.trim().is_empty() {
            return Err(SpecValidationError::EmptyProject);
        }
        if self.destination.namespace.trim().is_empty() {
            return Err(SpecValidationError::EmptyDestinationNamespace);
        }
        // A *blank* cluster is not the default: `serde(default)` only applies when the field is
        // absent, so `cluster: "  "` is a typo that would otherwise be silently read as
        // `in-cluster` by some call paths (which trim) and as `""` by others (finding M11).
        if self.destination.cluster.trim().is_empty() {
            return Err(SpecValidationError::EmptyDestinationCluster);
        }
        // `T18.3`: exactly one source. This mirrors the CEL rule on `SourceSpec`, so an
        // `Application` rejected by the API server (422) is rejected identically by the CLI and by
        // the controller before anything is fetched.
        match (&self.source.git, &self.source.oci) {
            (None, None) => return Err(SpecValidationError::MissingSource),
            (Some(_), Some(_)) => return Err(SpecValidationError::AmbiguousSource),
            (Some(git), None) => {
                if git.repo_url.trim().is_empty() {
                    return Err(SpecValidationError::EmptyRepoUrl);
                }
                if git.target_revision.trim().is_empty() {
                    return Err(SpecValidationError::EmptyTargetRevision);
                }
            }
            (None, Some(oci)) => oci.validate()?,
        }
        if self.requeue_after_seconds == 0 {
            return Err(SpecValidationError::ZeroRequeueAfter);
        }
        if !(MIN_REVISION_HISTORY_LIMIT..=MAX_REVISION_HISTORY_LIMIT)
            .contains(&self.revision_history_limit)
        {
            return Err(SpecValidationError::RevisionHistoryLimitOutOfRange {
                value: self.revision_history_limit,
            });
        }
        Ok(())
    }

    /// Returns the effective sync options (`SyncOptions::default()` when unspecified).
    #[must_use]
    pub fn sync_options(&self) -> SyncOptions {
        self.sync_policy
            .as_ref()
            .and_then(|policy| policy.sync_options.clone())
            .unwrap_or_default()
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const MINIMAL_APPLICATION: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: payment-service
  namespace: ferriscd-system
spec:
  source:
    git:
      repoURL: https://github.com/example/payment-service.git
  destination:
    namespace: payments
"#;

    const FULL_APPLICATION: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: payment-service
  namespace: ferriscd-system
spec:
  project: payments
  serviceAccountName: payments-sa
  source:
    git:
      repoURL: https://github.com/example/payment-service.git
      targetRevision: main
      path: deploy/production
    renderer:
      kustomize:
        kustomizationPath: overlays/prod
        images:
          - payment-api=ghcr.io/example/payment-api:v2
  destination:
    cluster: in-cluster
    namespace: payments
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      createNamespace: true
      pruneLast: true
      pruneCRDs: false
      pruneNamespaces: false
      serverSideForce: false
      applyOutOfSyncOnly: true
      takeoverFieldManagers:
        - kubectl-client-side-apply
    retry:
      limit: 3
      backoff:
        durationSeconds: 5
        factor: 2
        maxDurationSeconds: 120
  ignoreDifferences:
    - group: apps
      kind: Deployment
      jsonPointers:
        - /spec/replicas
  requeueAfterSeconds: 60
  revisionHistoryLimit: 20
"#;

    fn parse(yaml: &str) -> Application {
        serde_saphyr::from_str(yaml).expect("application yaml must parse")
    }

    #[test]
    fn application_yaml_round_trips_with_camel_case_field_names() {
        let app = parse(FULL_APPLICATION);
        assert_eq!(app.spec.project, "payments");
        assert_eq!(
            app.spec.service_account_name.as_deref(),
            Some("payments-sa")
        );
        let git = app.spec.source.git_source().expect("git source");
        assert_eq!(
            git.repo_url,
            "https://github.com/example/payment-service.git"
        );
        assert_eq!(git.target_revision, "main");
        assert!(
            app.spec.source.oci_source().is_none(),
            "a Git application must never carry an OCI source"
        );
        assert_eq!(app.spec.revision_history_limit, 20);

        let serialized = serde_saphyr::to_string(&app).expect("application must serialize");
        let rehydrated = parse(&serialized);
        assert_eq!(rehydrated, app);

        let value: Value = serde_json::to_value(&app).expect("application must serialize to json");
        let spec = &value["spec"];
        assert_eq!(spec["serviceAccountName"], json!("payments-sa"));
        assert_eq!(spec["requeueAfterSeconds"], json!(60));
        assert_eq!(spec["revisionHistoryLimit"], json!(20));
        assert_eq!(
            spec["ignoreDifferences"][0]["jsonPointers"][0],
            json!("/spec/replicas")
        );
        assert_eq!(spec["syncPolicy"]["automated"]["selfHeal"], json!(true));
        assert_eq!(
            spec["syncPolicy"]["syncOptions"]["takeoverFieldManagers"][0],
            json!("kubectl-client-side-apply")
        );
        assert_eq!(
            spec["source"]["git"]["repoURL"],
            json!("https://github.com/example/payment-service.git")
        );
        // snake_case keys must never leak onto the wire.
        assert!(spec.get("service_account_name").is_none());
        assert!(spec.get("revision_history_limit").is_none());
        // `T18.3`: a Git application never gains an `oci` key on the wire, which is what keeps
        // every stored `v1alpha1` object byte-identical after the schema evolution.
        assert!(
            spec["source"].get("oci").is_none(),
            "an absent oci source must not be serialized: {spec}"
        );
    }

    #[test]
    fn defaults_are_applied_for_omitted_fields() {
        let app = parse(MINIMAL_APPLICATION);
        let spec = &app.spec;
        assert_eq!(spec.project, DEFAULT_PROJECT_NAME);
        assert_eq!(spec.requeue_after_seconds, 180);
        assert_eq!(spec.revision_history_limit, 10);
        let git = spec.source.git_source().expect("git source");
        assert_eq!(git.target_revision, DEFAULT_TARGET_REVISION);
        assert_eq!(git.path, "");
        assert_eq!(spec.source.renderer, RendererSpec::Auto(AutoRenderer {}));
        assert_eq!(spec.destination.cluster, DEFAULT_DESTINATION_CLUSTER);
        assert!(spec.sync_policy.is_none());
        assert!(spec.ignore_differences.is_empty());
        assert!(spec.validate().is_ok());
        // The accessors describe a Git application exactly as the fields do.
        assert_eq!(spec.source.repo_url(), git.repo_url);
        assert_eq!(spec.source.source_path(), "");
        assert_eq!(spec.source.requested_revision(), DEFAULT_TARGET_REVISION);

        // Manual-only sync: no automation, no self-heal, no pruning.
        let policy = SyncPolicy::default();
        assert!(!policy.is_automated());
        assert!(!policy.self_heal_enabled());
        assert!(!policy.prune_enabled());

        // Sync option safety rails.
        let options = spec.sync_options();
        assert!(!options.server_side_force);
        assert!(!options.prune_crds);
        assert!(!options.prune_namespaces);
        assert!(options.apply_out_of_sync_only);
        assert!(options.prune_last);
    }

    #[test]
    fn partial_sync_options_keep_safety_defaults_and_wire_names() {
        // Only one option is set; every other option must fall back to its safe default
        // rather than to `false`, so a half-written syncOptions block cannot enable
        // forced applies or CRD pruning.
        let app = parse(&MINIMAL_APPLICATION.replace(
            "  destination:",
            "  syncPolicy:\n    syncOptions:\n      createNamespace: true\n  destination:",
        ));
        let options = app.spec.sync_options();
        assert!(options.create_namespace);
        assert!(options.prune_last);
        assert!(options.apply_out_of_sync_only);
        assert!(!options.prune_crds);
        assert!(!options.prune_namespaces);
        assert!(!options.server_side_force);
        assert!(options.takeover_field_managers.is_empty());

        // Acronym-bearing fields must keep their Kubernetes spelling on the wire.
        let value = serde_json::to_value(SyncOptions::default()).expect("options must serialize");
        for expected in [
            "createNamespace",
            "pruneLast",
            "pruneCRDs",
            "pruneNamespaces",
            "serverSideForce",
            "applyOutOfSyncOnly",
            "takeoverFieldManagers",
        ] {
            assert!(
                value.get(expected).is_some(),
                "serialized syncOptions is missing {expected}: {value}"
            );
        }
        assert!(value.get("prune_crds").is_none());
        assert!(value.get("prune_namespaces").is_none());
    }

    #[test]
    fn automated_sync_policy_cannot_be_false() {
        // `automated: false` (or a bare boolean) is not expressible: the field is an
        // optional struct, so the invalid `automated: false, selfHeal: true` state is
        // impossible to write instead of being silently accepted (Finding P1-06).
        let with_false_automated = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: broken
spec:
  source:
    git:
      repoURL: https://github.com/example/repo.git
  destination:
    namespace: payments
  syncPolicy:
    automated: false
    selfHeal: true
"#;
        let err = serde_saphyr::from_str::<Application>(with_false_automated)
            .expect_err("`automated: false` must not deserialize");
        let message = err.to_string();
        assert!(
            message.contains("automated") || message.contains("invalid type"),
            "unexpected error message: {message}"
        );

        // A struct form is the only way to enable automation, and self-heal tracks it.
        let with_policy = parse(&MINIMAL_APPLICATION.replace(
            "  destination:",
            "  syncPolicy:\n    automated:\n      selfHeal: true\n  destination:",
        ));
        let policy = with_policy.spec.sync_policy.expect("syncPolicy present");
        assert!(policy.is_automated());
        assert!(policy.self_heal_enabled());
        assert!(!policy.prune_enabled());
    }

    #[test]
    fn revision_history_limit_is_validated_to_bounds() {
        for accepted in [MIN_REVISION_HISTORY_LIMIT, MAX_REVISION_HISTORY_LIMIT] {
            let yaml = MINIMAL_APPLICATION.replace(
                "  destination:",
                &format!("  revisionHistoryLimit: {accepted}\n  destination:"),
            );
            let app = parse(&yaml);
            assert_eq!(app.spec.revision_history_limit, accepted);
            assert!(app.spec.validate().is_ok());
        }

        for rejected in [0, MAX_REVISION_HISTORY_LIMIT + 1, -1] {
            let yaml = MINIMAL_APPLICATION.replace(
                "  destination:",
                &format!("  revisionHistoryLimit: {rejected}\n  destination:"),
            );
            let app = parse(&yaml);
            assert_eq!(
                app.spec.validate(),
                Err(SpecValidationError::RevisionHistoryLimitOutOfRange { value: rejected })
            );
        }
    }

    #[test]
    fn validate_rejects_empty_required_values() {
        let mut spec = parse(MINIMAL_APPLICATION).spec;
        assert!(spec.validate().is_ok());

        let mut empty_project = spec.clone();
        empty_project.project = "  ".to_owned();
        assert_eq!(
            empty_project.validate(),
            Err(SpecValidationError::EmptyProject)
        );

        let mut empty_ns = spec.clone();
        empty_ns.destination.namespace.clear();
        assert_eq!(
            empty_ns.validate(),
            Err(SpecValidationError::EmptyDestinationNamespace)
        );

        // A blank cluster is refused; an *omitted* one already defaulted to `in-cluster`, so this
        // can only be a typo (`destination.cluster: "  "`), never the safe default (finding M11).
        let mut blank_cluster = spec.clone();
        blank_cluster.destination.cluster = "   ".to_owned();
        assert_eq!(
            blank_cluster.validate(),
            Err(SpecValidationError::EmptyDestinationCluster)
        );
        // A registered cluster name, padded or not, is accepted: callers trim consistently.
        let mut remote = spec.clone();
        remote.destination.cluster = "  prod-eu  ".to_owned();
        assert!(remote.validate().is_ok());
        assert_eq!(
            parse(MINIMAL_APPLICATION).spec.destination.cluster,
            DEFAULT_DESTINATION_CLUSTER,
            "omitting the field still means `in-cluster`"
        );

        let mut empty_url = spec.clone();
        empty_url
            .source
            .git
            .as_mut()
            .expect("git source")
            .repo_url
            .clear();
        assert_eq!(empty_url.validate(), Err(SpecValidationError::EmptyRepoUrl));

        let mut empty_revision = spec.clone();
        empty_revision
            .source
            .git
            .as_mut()
            .expect("git source")
            .target_revision
            .clear();
        assert_eq!(
            empty_revision.validate(),
            Err(SpecValidationError::EmptyTargetRevision)
        );

        spec.requeue_after_seconds = 0;
        assert_eq!(spec.validate(), Err(SpecValidationError::ZeroRequeueAfter));
    }

    // ---------------------------------------------------------------------
    // `T18.3`: additive OCI source
    // ---------------------------------------------------------------------

    /// A complete, already-deployed `v1.0` Git `Application` fixture: the exact wire form the
    /// committed CRD accepted before `spec.source.oci` existed (every field a `v1.0` client
    /// serialized, including the empty `ignoreDifferences` list).
    const V1_GIT_JSON: &str = r#"{"apiVersion":"ferriscd.io/v1alpha1","kind":"Application","metadata":{"name":"payments","namespace":"ferriscd-system"},"spec":{"project":"default","source":{"git":{"repoURL":"https://github.com/example/payment-service.git","targetRevision":"main","path":"deploy/prod"},"renderer":{"helm":{"releaseName":"payments","valueFiles":["values-prod.yaml"],"includeCRDs":true}}},"destination":{"cluster":"in-cluster","namespace":"payments"},"ignoreDifferences":[],"requeueAfterSeconds":180,"revisionHistoryLimit":10}}"#;

    /// **Acceptance criterion (1).** A stored `v1.0` Git `Application` survives the schema
    /// evolution byte-identically: the JSON round-trip is an exact string match (no `oci` key is
    /// invented, field order is unchanged) and the YAML form is stable across parses.
    #[test]
    fn v1_git_application_round_trips_byte_identically() {
        let app: Application = serde_json::from_str(V1_GIT_JSON).expect("v1.0 JSON must parse");
        assert!(app.spec.validate().is_ok());
        assert!(app.spec.source.git_source().is_some());
        assert!(app.spec.source.oci_source().is_none());

        let reserialized = serde_json::to_string(&app).expect("must serialize");
        assert_eq!(
            reserialized, V1_GIT_JSON,
            "a v1.0 Git Application must re-serialize byte-identically"
        );

        // The same object through YAML: parse → serialize → parse must be stable, and the absent
        // `oci` field must stay absent.
        let yaml = serde_saphyr::to_string(&app).expect("must serialize to yaml");
        assert!(!yaml.contains("oci"), "absent oci source leaked: {yaml}");
        let reparsed = parse(&yaml);
        assert_eq!(reparsed, app);
        assert_eq!(
            serde_saphyr::to_string(&reparsed).expect("must serialize"),
            yaml,
            "YAML output must be stable across round-trips"
        );
    }

    const OCI_APPLICATION: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: payments
  namespace: ferriscd-system
spec:
  source:
    oci:
      url: oci://ghcr.io/example/payments
      tag: 1.4.2
      path: ""
    renderer:
      helm:
        releaseName: payments
  destination:
    namespace: payments
"#;

    #[test]
    fn oci_application_parses_serializes_and_validates() {
        let app = parse(OCI_APPLICATION);
        let oci = app.spec.source.oci_source().expect("oci source");
        assert_eq!(oci.url, "oci://ghcr.io/example/payments");
        assert_eq!(oci.tag.as_deref(), Some("1.4.2"));
        assert_eq!(oci.digest, None);
        assert_eq!(oci.path, "");
        assert!(app.spec.source.git_source().is_none());
        assert!(app.spec.validate().is_ok());

        // The wire form keeps the Kubernetes spellings and never emits an empty `tag`/`digest`.
        let value = serde_json::to_value(&app).expect("must serialize");
        let oci_json = &value["spec"]["source"]["oci"];
        assert_eq!(oci_json["url"], json!("oci://ghcr.io/example/payments"));
        assert_eq!(oci_json["tag"], json!("1.4.2"));
        assert!(oci_json.get("digest").is_none(), "{oci_json}");
        assert!(value["spec"]["source"].get("git").is_none());

        // The accessors report the OCI source, so downstream code never has to branch on `git`.
        assert_eq!(app.spec.source.repo_url(), "oci://ghcr.io/example/payments");
        assert_eq!(app.spec.source.source_path(), "");
        assert_eq!(app.spec.source.requested_revision(), "1.4.2");

        // A digest pin wins over the tag for `requested_revision` only when no tag is set.
        let digest_pinned: Application = serde_json::from_value(json!({
            "apiVersion": "ferriscd.io/v1alpha1",
            "kind": "Application",
            "metadata": {"name": "payments", "namespace": "ferriscd-system"},
            "spec": {
                "source": {"oci": {
                    "url": "oci://ghcr.io/example/payments",
                    "digest": format!("sha256:{}", "a".repeat(64)),
                }},
                "destination": {"namespace": "payments"},
            },
        }))
        .expect("a digest-pinned OCI application must parse");
        assert!(digest_pinned.spec.validate().is_ok());
        assert_eq!(
            digest_pinned.spec.source.requested_revision(),
            format!("sha256:{}", "a".repeat(64))
        );
    }

    /// **Acceptance criterion (2).** Both-set and neither-set `(git, oci)` fail with the exact
    /// errors the injected CEL rule reports, so the offline check and the API server agree.
    #[test]
    fn exactly_one_source_is_required() {
        let mut neither = parse(MINIMAL_APPLICATION).spec;
        neither.source.git = None;
        neither.source.oci = None;
        let err = neither
            .validate()
            .expect_err("neither source must be refused");
        assert_eq!(err, SpecValidationError::MissingSource);
        assert_eq!(
            err.to_string(),
            "exactly one of spec.source.git or spec.source.oci must be specified: neither is set, \
             so there is nothing to render"
        );

        let mut both = parse(OCI_APPLICATION).spec;
        both.source.git = Some(GitSourceSpec {
            repo_url: "https://github.com/example/payment-service.git".to_owned(),
            target_revision: "main".to_owned(),
            path: String::new(),
        });
        let err = both.validate().expect_err("both sources must be refused");
        assert_eq!(err, SpecValidationError::AmbiguousSource);
        assert!(err.to_string().contains("both are set"), "{err}");

        // A source block that names neither field is not silently accepted either.
        let empty_source = parse(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: empty
spec:
  source:
    renderer: {auto: {}}
  destination:
    namespace: payments
"#,
        );
        assert_eq!(
            empty_source.spec.validate(),
            Err(SpecValidationError::MissingSource)
        );
    }

    /// CEL's view of one object property.
    ///
    /// The distinction that matters is three-way, not two-way: `Absent` is a missing key, `Null` is
    /// an explicit `x: null`, and `Set` is a usable value. `serde` collapses the first two into
    /// `None`, so a rule written with `has()` alone (true for `Null`, false for `Absent`) disagrees
    /// with `validate()` exactly on the `Null` column — which is finding M1.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Field {
        /// The key is not present at all (`has(self.x)` is false).
        Absent,
        /// The key is present with an explicit `null` (`has(self.x)` is true, `self.x != null` false).
        Null,
        /// The key carries a usable value (both halves of the predicate are true).
        Set,
    }

    impl Field {
        /// `has(self.x)`: true for an explicit `null`, which is what finding M1 is about.
        fn has(self) -> bool {
            !matches!(self, Self::Absent)
        }

        /// `self.x != null`: only a real value satisfies it.
        fn non_null(self) -> bool {
            matches!(self, Self::Set)
        }
    }

    /// **Acceptance criterion (2), parity half.** The offline checker and the CEL rules injected
    /// into the CRD (`crate::generate`) must agree on every presence combination — including an
    /// explicitly null source (`git: null`, `tag: null`) — so a spec the API server rejects is
    /// rejected here, and vice versa.
    ///
    /// The mirrors below follow the expressions *verbatim* over [`Field`]; the assertions above them
    /// pin the injected rule strings, so changing either side alone breaks this test.
    #[test]
    fn offline_validation_agrees_with_the_injected_cel_rules() {
        assert_eq!(
            crate::generate::SOURCE_EXCLUSIVE_RULE,
            "(has(self.git) && self.git != null && !(has(self.oci) && self.oci != null)) || (!(has(self.git) && self.git != null) && has(self.oci) && self.oci != null)"
        );
        assert_eq!(
            crate::generate::OCI_REFERENCE_RULE,
            // `T18.4`: the `has(self.tag) && self.tag != null` spelling is a **static CEL error** —
            // a `nullable: true` *string* is typed `string`, and `string != null` has no overload —
            // so the API server refused the entire CRD. `self.?tag.hasValue()` is the same
            // "present and not null" predicate with the right static types.
            "self.?tag.hasValue() || self.?digest.hasValue()"
        );

        // CEL mirror, spelled exactly like the rule: `has(self.x) && self.x != null`.
        let source_exclusive = |git: Field, oci: Field| {
            (git.has() && git.non_null() && !(oci.has() && oci.non_null()))
                || (!(git.has() && git.non_null()) && oci.has() && oci.non_null())
        };
        // `self.?x.hasValue()`: true only for `Field::Set` — present *and* not null.
        let oci_reference = |tag: Field, digest: Field| tag.non_null() || digest.non_null();

        let fields = [Field::Absent, Field::Null, Field::Set];

        // The raw YAML each `Field` spells: this is what the API server evaluates CEL against.
        let git_yaml = |field: Field| match field {
            Field::Absent => String::new(),
            Field::Null => "    git: null\n".to_owned(),
            Field::Set => {
                "    git:\n      repoURL: https://github.com/example/payments.git\n".to_owned()
            }
        };
        let oci_yaml = |field: Field| match field {
            Field::Absent => String::new(),
            Field::Null => "    oci: null\n".to_owned(),
            Field::Set => {
                "    oci:\n      url: oci://ghcr.io/example/payments\n      tag: 1.4.2\n".to_owned()
            }
        };
        let document = |source: String| {
            // `source` with neither arm set is an empty *mapping* (`source: {}`), which is the
            // shape a client produces for `SourceSpec::default()`; a bare `source:` key would be a
            // null, i.e. a different (and unparseable) object.
            let block = if source.is_empty() {
                "  source: {}\n".to_owned()
            } else {
                format!("  source:\n{source}")
            };
            format!(
                "apiVersion: ferriscd.io/v1alpha1\nkind: Application\nmetadata:\n  name: parity\n  \
                 namespace: ferriscd-system\nspec:\n{block}  destination:\n    namespace: \
                 payments\n"
            )
        };

        for git in fields {
            for oci in fields {
                let spec = parse(&document(format!("{}{}", git_yaml(git), oci_yaml(oci)))).spec;
                assert_eq!(
                    spec.validate().is_ok(),
                    source_exclusive(git, oci),
                    "git={git:?} oci={oci:?} must be judged identically by CEL and by validate()"
                );
            }
        }

        // The same three-way parity for the OCI reference rule.
        let tag_yaml = |field: Field| match field {
            Field::Absent => String::new(),
            Field::Null => "      tag: null\n".to_owned(),
            Field::Set => "      tag: 1.4.2\n".to_owned(),
        };
        let digest_yaml = |field: Field| match field {
            Field::Absent => String::new(),
            Field::Null => "      digest: null\n".to_owned(),
            Field::Set => format!("      digest: sha256:{}\n", "a".repeat(64)),
        };
        for tag in fields {
            for digest in fields {
                let source = format!(
                    "    oci:\n      url: oci://ghcr.io/example/payments\n{}{}",
                    tag_yaml(tag),
                    digest_yaml(digest)
                );
                let oci = parse(&document(source))
                    .spec
                    .source
                    .oci_source()
                    .cloned()
                    .expect("the oci source must parse");
                assert_eq!(
                    oci.validate().is_ok(),
                    oci_reference(tag, digest),
                    "tag={tag:?} digest={digest:?} must be judged identically by CEL and by validate()"
                );
            }
        }
    }

    #[test]
    fn oci_source_is_validated_offline_with_the_cel_rules_parity() {
        let base = parse(OCI_APPLICATION).spec;
        let oci_spec = |mutate: &dyn Fn(&mut OciSourceSpec)| {
            let mut spec = base.clone();
            let oci = spec.source.oci.as_mut().expect("oci source");
            mutate(oci);
            spec.validate()
        };

        // `self.?tag.hasValue() || self.?digest.hasValue()`: a floating reference is refused.
        assert_eq!(
            oci_spec(&|oci| {
                oci.tag = None;
                oci.digest = None;
            }),
            Err(SpecValidationError::MissingOciReference)
        );

        // Digest shape: `sha256:` + 64 lowercase hex, nothing else.
        for rejected in [
            "",
            "sha256",
            "sha256:",
            "sha256:abc",
            "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // 63, 65 hex characters, and uppercase hex.
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            let expected = SpecValidationError::InvalidOciDigest {
                digest: rejected.to_owned(),
            };
            assert_eq!(
                oci_spec(&|oci| {
                    oci.tag = None;
                    oci.digest = Some(rejected.to_owned());
                }),
                Err(expected),
                "{rejected:?} must be an invalid digest"
            );
        }
        let accepted_digest = format!("sha256:{}", "0123456789abcdef".repeat(4));
        assert_eq!(
            oci_spec(&|oci| {
                oci.tag = None;
                oci.digest = Some(accepted_digest.clone());
            }),
            Ok(())
        );
        // Both set is allowed: the tag is resolved and must match the pinned digest.
        assert_eq!(
            oci_spec(&|oci| oci.digest = Some(accepted_digest.clone())),
            Ok(())
        );

        // Tag grammar (OCI distribution reference spec).
        for rejected in [
            "",
            " ",
            "^1.4.0",
            "1.4.2+build",
            "sha256:abc",
            "-1.0",
            ".1.0",
            "v1/2",
            "1.4 2",
        ] {
            match oci_spec(&|oci| oci.tag = Some(rejected.to_owned())) {
                Err(SpecValidationError::InvalidOciTag { tag, reason }) => {
                    assert_eq!(tag, rejected, "{rejected:?}");
                    assert!(
                        !reason.is_empty(),
                        "{rejected:?} must explain the rejection"
                    );
                }
                other => panic!("{rejected:?} must be an invalid tag, got {other:?}"),
            }
        }
        let too_long = "a".repeat(MAX_OCI_TAG_LEN + 1);
        assert!(matches!(
            oci_spec(&|oci| oci.tag = Some(too_long.clone())),
            Err(SpecValidationError::InvalidOciTag { .. })
        ));
        assert_eq!(
            oci_spec(&|oci| oci.tag = Some("a".repeat(MAX_OCI_TAG_LEN))),
            Ok(())
        );

        // Reference shape: absolute, no embedded credentials, a host and a repository.
        //
        // H-2: the rejected reference is echoed into the error, and that error reaches
        // `Application.status`, Events, and logs — so a userinfo-carrying URL must be echoed in its
        // **redacted** form. `(rejected, echoed)`: the two differ exactly for the credential case.
        for (rejected, echoed) in [
            ("", ""),
            ("   ", "   "),
            ("ghcr.io/example/payments", "ghcr.io/example/payments"),
            (
                "ssh://ghcr.io/example/payments",
                "ssh://ghcr.io/example/payments",
            ),
            ("file:///tmp/payments", "file:///tmp/payments"),
            ("oci://", "oci://"),
            ("oci://ghcr.io", "oci://ghcr.io"),
            ("oci://ghcr.io/", "oci://ghcr.io/"),
            ("oci://ghcr.io/example/", "oci://ghcr.io/example/"),
            ("oci://ghcr.io//payments", "oci://ghcr.io//payments"),
            (
                "oci://user:token@ghcr.io/example/payments",
                "oci://[REDACTED]@ghcr.io/example/payments",
            ),
            (
                "oci://token@ghcr.io/example/payments",
                "oci://[REDACTED]@ghcr.io/example/payments",
            ),
            (
                "https://user:token@ghcr.io/example/payments",
                "https://[REDACTED]@ghcr.io/example/payments",
            ),
            // **Finding H-A.** A reference that forgot the scheme is still a reference with
            // userinfo in it. The old rule ("no `://`, so there is no authority to redact") echoed
            // these verbatim; the redaction is scheme-agnostic now.
            (
                "user:token@ghcr.io/example/payments",
                "[REDACTED]@ghcr.io/example/payments",
            ),
            (
                "token@ghcr.io/example/payments",
                "[REDACTED]@ghcr.io/example/payments",
            ),
            (
                "user:token@ghcr.io/example/payments ",
                "[REDACTED]@ghcr.io/example/payments ",
            ),
            (
                "oci://ghcr.io/example/payments ",
                "oci://ghcr.io/example/payments ",
            ),
            (
                "oci://ghcr.io/example/pay\nments",
                "oci://ghcr.io/example/pay\nments",
            ),
        ] {
            match oci_spec(&|oci| oci.url = rejected.to_owned()) {
                Err(
                    ref err @ SpecValidationError::InvalidOciUrl {
                        ref url,
                        ref reason,
                    },
                ) => {
                    assert_eq!(url, echoed, "{rejected:?}: the echo must be redacted");
                    assert!(
                        !reason.is_empty(),
                        "{rejected:?} must explain the rejection"
                    );
                    // The credential never appears in any rendering of the error.
                    let display = err.to_string();
                    let debug = format!("{err:?}");
                    for rendered in [&display, &debug] {
                        assert!(
                            !rendered.contains("token"),
                            "{rejected:?} leaked the credential into {rendered:?}"
                        );
                    }
                }
                other => panic!("{rejected:?} must be an invalid reference, got {other:?}"),
            }
        }
        for accepted in [
            "oci://ghcr.io/example/payments",
            "oci://localhost:5000/payments",
            "https://ghcr.io/example/payments",
            // Plaintext is a *transport* policy question, decided by the engine
            // (`OciUrlPolicy`), not by the schema: `kind` registries are `http://localhost:5000`.
            "http://localhost:5000/example/payments",
        ] {
            assert_eq!(
                oci_spec(&|oci| oci.url = accepted.to_owned()),
                Ok(()),
                "{accepted:?} must be a usable reference"
            );
        }
    }

    #[test]
    fn schema_declares_both_sources_without_requiring_either() {
        let schema =
            serde_json::to_value(schemars::schema_for!(SourceSpec)).expect("schema must serialize");
        let properties = schema["properties"]
            .as_object()
            .expect("properties must be an object");
        for expected in ["git", "oci", "renderer"] {
            assert!(
                properties.contains_key(expected),
                "source schema is missing {expected}: {schema}"
            );
        }
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let required: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        assert!(
            !required.contains(&"git"),
            "git must no longer be required: {schema}"
        );
        assert!(
            !required.contains(&"oci"),
            "oci must not be required: {schema}"
        );

        // `oci.url` is required *inside* `oci`; `tag`/`digest`/`path` are additive optional
        // fields. schemars 1 emits nested types into `$defs` (`$ref`ed from `properties.oci`), so
        // the inner shape is asserted on the inlined CRD schema in `generate.rs`.
        let oci = &schema["properties"]["oci"];
        assert!(oci.is_object(), "oci must be a schema: {oci}");
        let oci_defs = &schema["$defs"]["OciSourceSpec"];
        let oci_required: Vec<&str> = oci_defs["required"]
            .as_array()
            .map(|values| values.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert_eq!(oci_required, vec!["url"], "{oci_defs}");
        assert!(oci_defs["properties"].get("tag").is_some(), "{oci_defs}");
        assert!(oci_defs["properties"].get("digest").is_some(), "{oci_defs}");
        assert!(oci_defs["properties"].get("path").is_some(), "{oci_defs}");
    }

    #[test]
    fn schema_bounds_revision_history_limit_and_requires_source_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(ApplicationSpec))
            .expect("schema must serialize");
        let limit = &schema["properties"]["revisionHistoryLimit"];
        assert_eq!(limit["minimum"], json!(1));
        assert_eq!(limit["maximum"], json!(20));

        let required = schema["required"]
            .as_array()
            .expect("required must be an array")
            .clone();
        let required: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        assert!(required.contains(&"source"));
        assert!(required.contains(&"destination"));
        assert!(!required.contains(&"project"));
        assert!(!required.contains(&"revisionHistoryLimit"));
    }
}

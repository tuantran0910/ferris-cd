//! Server-Side Apply `dryRun=All` evaluator: the impure half of Phase 07 drift detection.
//!
//! For every **desired** resource the evaluator produces exactly one
//! [`ResourceDiff`](ferriscd_engine::diff::ResourceDiff). The interesting part is what it
//! deliberately does *not* do:
//!
//! | `LiveState` | Classification | Dry-run? |
//! |---|---|---|
//! | [`LiveState::Missing`], [`LiveState::OrphanGvkGone`] | `DiffStatus::Missing` | **no** |
//! | [`LiveState::DeferredPendingCrd`], [`LiveState::DeferredPendingNamespace`] | `DiffStatus::Missing` | **no** |
//! | [`LiveState::Present`] with [`Ownership::OwnedByForeign`] | `DiffStatus::OwnershipConflict` | **no** |
//! | [`LiveState::Present`] otherwise | `Synced`/`OutOfSync` from the prediction | yes |
//!
//! Skipping the dry-run for `Missing`/deferred resources is finding C3: a commit that creates a
//! `CustomResourceDefinition` and a custom resource together (or `createNamespace: true`) would
//! otherwise fail in the diff phase, because the API server cannot dry-run-apply an object whose
//! kind or namespace does not exist yet. A brand-new resource is `Missing`, i.e. "apply it", and
//! the deferral already tells the controller to requeue.
//!
//! # Conflicting field managers (finding H6)
//!
//! `dryRun` still evaluates field ownership, so a field owned by another manager (an HPA's
//! `spec.replicas`, a `kubectl apply` from last year) answers `409 Conflict`. That is a
//! *classification*, not an error: the conflicts are parsed out of `Status.details.causes` into
//! structured [`FieldConflict`] entries, the resource is reported `OutOfSync`, and the operator
//! sees which manager owns which field instead of an opaque API error.
//!
//! # What is compared (finding C1)
//!
//! The live object and the prediction are compared as **full documents**
//! (`apiVersion`/`kind`/`metadata`/`spec`/…), not as `DynamicObject::data`. `data` deliberately
//! excludes `metadata` and the type fields, so diffing it made every label/annotation edit look
//! `Synced`. `ResourceDiff::compare` strips the volatile metadata (`resourceVersion`, `uid`,
//! `managedFields`, …) and `.status` from both sides itself, so comparing the whole document adds
//! no noise.
//!
//! # The desired-body contract
//!
//! Because the comparison is a full-document one, `metadata` is part of the diff — and so is the
//! `ferriscd.io/tracking-id` annotation FerrisCD stamps on every object it owns. The caller's
//! contract is therefore exact: **the desired body handed to
//! [`DryRunEvaluator::evaluate`] must be the very stamped body that will be applied — the same
//! slice the applier receives, including `ferriscd.io/tracking-id`.**
//!
//! Handing the evaluator a *pre-stamp* body while the applier gets the stamped one would make the
//! dry-run predict the removal of an annotation the apply actually keeps: the resource would be
//! permanently `OutOfSync` and self-heal forever without converging. Stamp first, then diff.
//!
//! # Force
//!
//! `force` follows `syncOptions.serverSideForce` and defaults to `false` (trap T5). Forcing a
//! dry-run would silently hide exactly the conflicts the diff exists to report.
//!
//! # Async hygiene
//!
//! Every dry-run is a plain async `kube` request (no blocking I/O, no `spawn_blocking` needed),
//! executed with at most [`DRY_RUN_CONCURRENCY`] in flight. The JSON comparison itself happens in
//! `ferriscd-engine` and is CPU-only (no I/O), so it never blocks a Tokio worker on a syscall.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ferriscd_engine::diff::ignore::IgnoreRuleSet;
use ferriscd_engine::diff::types::{FieldConflict, ResourceDiff};
use ferriscd_engine::inventory::Ownership;
use ferriscd_engine::manifest::{DesiredResource, ResourceKey};
use futures::TryStreamExt;
use futures::stream::{self, StreamExt};
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, Patch, PatchParams};
use kube::core::Status;
use kube::discovery::Scope;

use crate::discovery::{DiscoveryCache, DiscoveryError};
use crate::live_state::{LiveState, LiveStateMap};
use crate::sync::apply_body;

/// Maximum number of SSA dry-runs in flight during one evaluation pass.
///
/// Mirrors [`crate::live_state::LIVE_FETCH_CONCURRENCY`]: enough that a 500-resource bundle is a
/// handful of round trips, low enough that a diff pass can never flood the API server or starve
/// the connection pool.
pub const DRY_RUN_CONCURRENCY: usize = 16;

/// Maximum number of [`FieldConflict`] entries reported for one resource.
///
/// A `Status.details.causes` list is attacker-controllable in size; the conflicts end up in
/// `Application.status`, which must stay small (trap T9).
pub const MAX_FIELD_CONFLICTS: usize = 16;

/// Replacement for an API server message that may quote secret material.
///
/// A `400 BadRequest`/`422 Invalid` for a `Secret` echoes the offending input (a decode error
/// names the value it could not decode), and such a message is logged and can reach
/// `Application.status`. It is therefore never carried verbatim for `v1/Secret`.
pub const REDACTED_SERVER_MESSAGE: &str =
    "<server message redacted: a Secret request may quote secret values>";

/// One dry-run request, already resolved to a concrete `ApiResource`.
#[derive(Clone, Copy)]
pub struct DryRunTarget<'a> {
    /// Version-agnostic identity of the object.
    pub key: &'a ResourceKey,
    /// Discovered resource (carries the real plural name and served version).
    pub api_resource: &'a ApiResource,
    /// Namespace for a namespaced resource; `None` for a cluster-scoped one.
    pub namespace: Option<&'a str>,
    /// The apply body (`.status` already stripped).
    ///
    /// This must be the **exact stamped body the applier receives**, including the
    /// `ferriscd.io/tracking-id` annotation: the prediction is compared against the live object
    /// as a full document, so a pre-stamp body would look like a request to remove that
    /// annotation (see the module-level "desired-body contract").
    pub object: &'a DynamicObject,
    /// `force` for the apply patch (`syncOptions.serverSideForce`, default `false`).
    pub force: bool,
}

impl std::fmt::Debug for DryRunTarget<'_> {
    /// Deliberately omits the apply body: it may be a `Secret` (trap T4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DryRunTarget")
            .field("key", &self.key.canonical())
            .field("api_version", &self.api_resource.api_version)
            .field("namespace", &self.namespace)
            .field("force", &self.force)
            .finish_non_exhaustive()
    }
}

/// Result of one Server-Side Apply dry-run.
#[derive(Clone)]
pub enum DryRunOutcome {
    /// The API server predicted the post-default, post-webhook object.
    Predicted(Box<DynamicObject>),
    /// The apply would fail with `409 Conflict`: structured field-ownership conflicts.
    Conflict {
        /// Parsed conflicts, never empty (an unparseable `409` yields one unknown entry).
        conflicts: Vec<FieldConflict>,
    },
    /// The API server rejected the dry-run with `422 Invalid` because an immutable field changed
    /// (`immutable: true` `ConfigMap`/`Secret`, `Job.spec.template`, `StatefulSet.spec.*`).
    ///
    /// Falling back to a local canonical diff against the desired body keeps `GET .../diff` usable
    /// (with full `Secret` redaction) and lets the sync stage either execute `SyncAction::Replace`
    /// when `ferriscd.io/sync-options: Replace=true` is set, or fail cleanly during apply with the
    /// actionable `Replace=true` guidance.
    ImmutableField,
}

impl std::fmt::Debug for DryRunOutcome {
    /// Deliberately omits the predicted object: it is a full live object, which for a `Secret`
    /// carries every value (trap T4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Predicted(_) => f.write_str("DryRunOutcome::Predicted(<redacted object>)"),
            Self::Conflict { conflicts } => f
                .debug_struct("DryRunOutcome::Conflict")
                .field("conflicts", conflicts)
                .finish(),
            Self::ImmutableField => f.write_str("DryRunOutcome::ImmutableField"),
        }
    }
}

/// Boxed result of one [`DryRunApi::dry_run`] call.
pub type DryRunFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DryRunOutcome, DryRunError>> + Send + 'a>>;

/// Cluster dry-run seam, so the diff pass is testable without an API server.
pub trait DryRunApi: Send + Sync + 'static {
    /// Server-Side Applies one object with `dryRun=All` and reports the prediction or the
    /// field-ownership conflicts.
    fn dry_run<'a>(&'a self, target: DryRunTarget<'a>) -> DryRunFuture<'a>;
}

/// Errors raised while evaluating a dry-run.
#[derive(Debug, thiserror::Error)]
pub enum DryRunError {
    /// A Kubernetes API call failed with something other than a parseable `409 Conflict`.
    #[error("kubernetes API error {code} during the SSA dry-run of {resource}: {message}")]
    Api {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// HTTP status code (`0` for transport/decode failures).
        code: u16,
        /// Server-provided message. For a `v1/Secret` this is replaced by a fixed placeholder
        /// (see [`DryRunError::api`]): a `400`/`422` message can quote the offending value, so
        /// the text is not safe to log verbatim for secret-bearing kinds. For every other kind it
        /// is the API server's text unchanged.
        message: String,
    },

    /// The live or predicted object could not be serialized for comparison.
    #[error("cannot serialize {resource} for comparison: {message}")]
    Serialization {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// The underlying serialization failure.
        message: String,
    },

    /// API discovery failed (or does not serve the kind).
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),

    /// The kind's scope contradicts the resource key.
    #[error("cannot dry-run {resource}: {message}")]
    ScopeMismatch {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// What is inconsistent.
        message: String,
    },
}

impl DryRunError {
    /// Builds [`DryRunError::Api`] from a `kube` error.
    ///
    /// For a `v1/Secret` the server message is replaced by
    /// [`REDACTED_SERVER_MESSAGE`]: a `422 Invalid`/`400 BadRequest` for a Secret can echo the
    /// offending (secret) value — base64 data or a `last-applied-configuration` document — and an
    /// error may be logged or surfaced in `Application.status`.
    fn api(key: &ResourceKey, err: &kube::Error) -> Self {
        let code = match err {
            kube::Error::Api(status) => status.code,
            _ => 0,
        };
        let message = if ferriscd_engine::diff::is_secret(&key.group, &key.kind) {
            let rendered = err.to_string();
            format!(
                "{REDACTED_SERVER_MESSAGE} ({} character(s) withheld)",
                rendered.chars().count()
            )
        } else {
            err.to_string()
        };
        Self::Api {
            resource: key.canonical(),
            code,
            message,
        }
    }

    /// Builds [`DryRunError::Serialization`] from a serialization failure.
    fn serialization(key: &ResourceKey, err: &serde_json::Error) -> Self {
        Self::Serialization {
            resource: key.canonical(),
            message: err.to_string(),
        }
    }

    /// Returns whether retrying the same dry-run can plausibly succeed.
    ///
    /// A `409` is normally a classification ([`DryRunOutcome::Conflict`]), not a failure — but if
    /// one does reach this error type it is retried exactly like the apply path's
    /// [`ReconcileError::failure_class`](crate::reconcile::ReconcileError::failure_class) treats
    /// it: a field-ownership conflict is a transient condition that must back off, not a terminal
    /// verdict with a 10-minute delay. `408`/`425`/`429`/`5xx`/transport failures are transient
    /// too; a `4xx` such as `403`/`404`/`422`, an unserved kind, an inconsistent key, or an
    /// unserializable document is terminal.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Api { code, .. } => matches!(*code, 0 | 408 | 409 | 425 | 429) || *code >= 500,
            Self::Discovery(err) => !err.is_no_matches_for_kind(),
            Self::ScopeMismatch { .. } | Self::Serialization { .. } => false,
        }
    }
}

/// [`DryRunApi`] backed by the Kubernetes API server through dynamic `Api` clients.
#[derive(Clone)]
pub struct DynamicDryRunApi {
    client: kube::Client,
    field_manager: String,
}

impl std::fmt::Debug for DynamicDryRunApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicDryRunApi")
            .field("field_manager", &self.field_manager)
            .finish_non_exhaustive()
    }
}

impl DynamicDryRunApi {
    /// Builds a dry-run client that evaluates against the FerrisCD field manager.
    #[must_use]
    pub fn new(client: kube::Client) -> Self {
        Self {
            client,
            field_manager: Self::field_manager(),
        }
    }

    /// The field manager every dry-run uses.
    ///
    /// It must be [`ferriscd_engine::default_field_manager`] — the same identity the real apply
    /// uses — otherwise a dry-run would report a conflict against FerrisCD itself.
    #[must_use]
    fn field_manager() -> String {
        ferriscd_engine::default_field_manager().to_owned()
    }
}

/// Builds the `PatchParams` of one SSA dry-run.
///
/// `dry_run()` sets `dryRun=All`; `force` follows `serverSideForce` and stays `false` by default
/// (trap T5: forcing hides the very conflicts the diff must report).
#[must_use]
fn apply_patch_params(field_manager: &str, force: bool) -> PatchParams {
    let mut params = PatchParams::apply(field_manager).dry_run();
    params.force = force;
    params
}

impl DryRunApi for DynamicDryRunApi {
    fn dry_run<'a>(&'a self, target: DryRunTarget<'a>) -> DryRunFuture<'a> {
        let client = self.client.clone();
        let field_manager = self.field_manager.clone();
        Box::pin(async move {
            let api: Api<DynamicObject> = match target.namespace {
                Some(namespace) => Api::namespaced_with(client, namespace, target.api_resource),
                None => Api::all_with(client, target.api_resource),
            };
            let params = apply_patch_params(&field_manager, target.force);

            let result = api
                .patch(&target.key.name, &params, &Patch::Apply(target.object))
                .await;
            classify_result(result, target.key)
        })
    }
}

/// Classifies the result of one `dryRun=All` `Patch::Apply` (finding H6).
///
/// A `409 Conflict` is a *result*, not a failure: the API server refused the apply because
/// another field manager owns one of the fields, which is exactly what the diff exists to
/// report, so it becomes a [`DryRunOutcome::Conflict`] with the parsed managers. Everything else
/// is a [`DryRunError`] (with the message redacted for `Secret` keys).
fn classify_result(
    result: Result<DynamicObject, kube::Error>,
    key: &ResourceKey,
) -> Result<DryRunOutcome, DryRunError> {
    match result {
        Ok(predicted) => Ok(DryRunOutcome::Predicted(Box::new(predicted))),
        Err(kube::Error::Api(status)) if status.code == 409 => Ok(DryRunOutcome::Conflict {
            conflicts: parse_conflict_status(&status),
        }),
        Err(kube::Error::Api(status))
            if crate::sync_recovery::is_immutable_field_error(&status) =>
        {
            Ok(DryRunOutcome::ImmutableField)
        }
        Err(err) => Err(DryRunError::api(key, &err)),
    }
}

/// Serializes one object into the **full document** the comparison needs.
///
/// [`DynamicObject::data`] is *not* the object: `metadata` and the type fields are separate struct
/// fields, so diffing `data` reported every label/annotation edit as `Synced` (finding C1).
/// Serializing the whole object re-emits `apiVersion`, `kind`, and `metadata`, and the engine then
/// strips the volatile parts itself.
///
/// # Errors
///
/// [`DryRunError::Serialization`] if the object cannot be represented as JSON. `DynamicObject`
/// round-trips through `serde_json` by construction, so this is a defensive branch rather than an
/// expected one — but swallowing it (`Value::Null`) would silently turn a drifted resource into a
/// `Synced` one, and `unwrap` is forbidden in runtime code.
fn document(object: &DynamicObject, key: &ResourceKey) -> Result<serde_json::Value, DryRunError> {
    serde_json::to_value(object).map_err(|err| DryRunError::serialization(key, &err))
}

/// Parses the field-ownership conflicts out of a `409 Conflict` `Status`.
///
/// The API server provides `details.causes` for SSA conflicts, each naming the field and the
/// manager (`conflict with "kubectl-client-side-apply"`). When a server (or a proxy) omits the
/// causes, the same information is recovered from `message`, pairing the managers and fields in
/// the order they appear. The result is never empty, sorted, and de-duplicated, so an
/// unparseable `409` still produces one structured (if empty) conflict instead of an opaque
/// error string.
#[must_use]
pub fn parse_conflict_status(status: &Status) -> Vec<FieldConflict> {
    let mut conflicts: Vec<FieldConflict> = Vec::new();
    if let Some(details) = &status.details {
        for cause in &details.causes {
            conflicts.push(FieldConflict::new(
                normalize_field(&cause.field),
                manager_in(&cause.message),
            ));
        }
    }
    if conflicts.is_empty() {
        conflicts = conflicts_from_message(&status.message);
    }
    if conflicts.is_empty() {
        conflicts.push(FieldConflict::unknown());
    }
    conflicts.sort();
    conflicts.dedup();
    conflicts.truncate(MAX_FIELD_CONFLICTS);
    conflicts
}

/// Strips the leading `.`/`/` a Kubernetes field path may carry (`".spec.replicas"`).
fn normalize_field(field: &str) -> Option<String> {
    let trimmed = field.trim().trim_start_matches(['.', '/']);
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Extracts the manager name from the text that follows `conflict with `.
///
/// The API server quotes the name (`"kubectl-client-side-apply"`); an unquoted name is read up
/// to the next `:` (the field separator) or `,` (the next conflict).
fn manager_token(text: &str) -> Option<String> {
    let text = text.trim_start();
    let token = match text.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().map_or("", str::trim),
        None => text.split([':', ',']).next().map_or("", str::trim),
    };
    (!token.is_empty()).then(|| token.to_owned())
}

/// Extracts the manager name from one `conflict with "<manager>"` fragment.
fn manager_in(fragment: &str) -> Option<String> {
    let (_, rest) = fragment
        .split_once("conflict with ")
        .or_else(|| fragment.split_once("conflicts with "))?;
    manager_token(rest)
}

/// Every distinct manager named in `message`, in order of appearance.
fn managers_in(message: &str) -> Vec<String> {
    let mut managers: Vec<String> = Vec::new();
    let mut cursor = message;
    while let Some(index) = cursor.find("conflict") {
        let after_keyword = &cursor[index + "conflict".len()..];
        // Tolerate the plural spelling (`conflicts with "x"`).
        let after_keyword = after_keyword.strip_prefix('s').unwrap_or(after_keyword);
        let Some((_, candidate)) = after_keyword.split_once(" with ") else {
            cursor = after_keyword;
            continue;
        };
        if let Some(manager) = manager_token(candidate)
            && !managers.contains(&manager)
        {
            managers.push(manager);
        }
        cursor = candidate;
    }
    managers
}

/// Every distinct field path mentioned in `message`, in order of appearance.
///
/// SSA lists them as `.spec.replicas` (dotted, leading dot), which is normalized to the
/// `spec.replicas` form used by [`FieldConflict::field`].
fn fields_in(message: &str) -> Vec<String> {
    let mut fields: Vec<String> = Vec::new();
    for token in message.split([' ', ',']) {
        let token = token.trim();
        if !(token.starts_with('.') || token.starts_with('/')) {
            continue;
        }
        if let Some(field) = normalize_field(token)
            && !fields.contains(&field)
        {
            fields.push(field);
        }
    }
    fields
}

/// Best-effort extraction of conflicts from a `409` message whose `details.causes` is absent.
fn conflicts_from_message(message: &str) -> Vec<FieldConflict> {
    let managers = managers_in(message);
    let fields = fields_in(message);
    let mut conflicts = Vec::new();
    for (index, manager) in managers.iter().enumerate() {
        conflicts.push(FieldConflict::new(
            fields.get(index).cloned(),
            Some(manager.clone()),
        ));
    }
    for field in fields.iter().skip(managers.len()) {
        conflicts.push(FieldConflict::new(Some(field.clone()), None));
    }
    conflicts
}

/// The SSA dry-run diff pass.
pub struct DryRunEvaluator {
    api: Arc<dyn DryRunApi>,
    discovery: DiscoveryCache,
    force: bool,
}

impl std::fmt::Debug for DryRunEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DryRunEvaluator")
            .field("force", &self.force)
            .field("concurrency", &DRY_RUN_CONCURRENCY)
            .finish_non_exhaustive()
    }
}

impl DryRunEvaluator {
    /// Builds an evaluator against the live API server.
    #[must_use]
    pub fn new(client: kube::Client, discovery: DiscoveryCache) -> Self {
        Self::with_api(Arc::new(DynamicDryRunApi::new(client)), discovery)
    }

    /// Builds an evaluator over a custom dry-run seam (tests, alternate clients).
    #[must_use]
    pub fn with_api(api: Arc<dyn DryRunApi>, discovery: DiscoveryCache) -> Self {
        Self {
            api,
            discovery,
            force: false,
        }
    }

    /// Sets `force` from `spec.syncPolicy.syncOptions.serverSideForce` (default `false`).
    #[must_use]
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Returns the configured `force` flag.
    #[must_use]
    pub fn force(&self) -> bool {
        self.force
    }

    /// Evaluates the whole desired set (plus any orphans) into per-resource diffs.
    ///
    /// `desired` must be the **stamped** desired set — each object carrying the
    /// `ferriscd.io/tracking-id` FerrisCD stamps, i.e. the exact body the applier will receive.
    /// Diffing a pre-stamp body would report the annotation as drift on every pass and pin the
    /// resource `OutOfSync` forever (see the module-level "desired-body contract").
    ///
    /// `orphans` are the keys from `prev_inventory \ desired` (see
    /// [`ferriscd_engine::inventory::orphans`]); they are classified as
    /// [`DiffStatus::Orphaned`](ferriscd_engine::diff::DiffStatus::Orphaned) without any API
    /// call. The result is sorted by [`ResourceKey`] and is byte-identical across runs.
    ///
    /// # Errors
    ///
    /// Fails fast on the first [`DryRunError`]: a diff pass that cannot read the API server must
    /// retry rather than guess (a guessed `Synced` would silently skip a needed apply). A
    /// `409 Conflict` never produces an error — it is reported as a classified diff.
    pub async fn evaluate(
        &self,
        desired: &[DesiredResource],
        orphans: &[ResourceKey],
        live: &LiveStateMap,
        rules: &IgnoreRuleSet,
    ) -> Result<Vec<ResourceDiff>, DryRunError> {
        // The per-resource futures are materialized eagerly into a plain `Vec` instead of being
        // produced by a closure inside a `stream::iter`/`map` chain: a closure that captures
        // `&self`, `live` and `rules` and returns an `async` block leaves the compiler unable to
        // infer a `Send` outer future with a single lifetime, and `futures::stream` needs the
        // element type to be nameable. Collecting the futures first pins both, and `buffered`
        // below still gives the concurrency bound.
        let pending: Vec<_> = desired
            .iter()
            .map(|resource| self.evaluate_one(resource, live, rules))
            .collect();
        let mut diffs: Vec<ResourceDiff> = stream::iter(pending)
            .buffered(DRY_RUN_CONCURRENCY)
            .try_collect()
            .await?;

        diffs.extend(
            orphans
                .iter()
                .map(|key| ResourceDiff::orphaned(key.clone())),
        );

        // `buffered` preserves the input order, which is not necessarily key order; sort so the
        // report (and therefore `/status`) never churns on input ordering.
        diffs.sort_by(|left, right| left.key().cmp(right.key()));
        Ok(diffs)
    }

    /// Classifies one desired resource.
    async fn evaluate_one(
        &self,
        resource: &DesiredResource,
        live: &LiveStateMap,
        rules: &IgnoreRuleSet,
    ) -> Result<ResourceDiff, DryRunError> {
        let key = &resource.key;
        match live.get(key) {
            // Never touch another Application's object (trap T10), and never dry-run it: a
            // successful prediction would only tempt the sync into an apply that must not happen.
            Some(LiveState::Present(_, Ownership::OwnedByForeign(owner))) => {
                Ok(ResourceDiff::ownership_conflict(key.clone(), owner.clone()))
            }
            Some(LiveState::Present(object, _)) => {
                self.dry_run_present(resource, object.as_ref(), rules).await
            }
            // `Missing`, `DeferredPendingCrd`, `DeferredPendingNamespace`, `OrphanGvkGone`, and
            // (defensively) a key the live pass never classified: all "apply this, do not
            // dry-run it" (finding C3 — a brand-new CRD/CR or namespace must never fail here).
            _ => Ok(ResourceDiff::missing(key.clone())),
        }
    }

    /// Runs one dry-run against an existing object and diffs the prediction.
    async fn dry_run_present(
        &self,
        resource: &DesiredResource,
        live_object: &DynamicObject,
        rules: &IgnoreRuleSet,
    ) -> Result<ResourceDiff, DryRunError> {
        let key = &resource.key;
        let gvk = GroupVersionKind::gvk(
            &resource.gvk.group,
            &resource.gvk.version,
            &resource.gvk.kind,
        );
        let (api_resource, capabilities) = self.discovery.resolve(&gvk).await?;
        let namespace = match capabilities.scope {
            Scope::Namespaced => match key.namespace.as_deref() {
                Some(namespace) if !namespace.trim().is_empty() => Some(namespace),
                _ => {
                    return Err(DryRunError::ScopeMismatch {
                        resource: key.canonical(),
                        message: "discovery reports a namespaced kind but the resource key \
                                  carries no namespace"
                            .to_owned(),
                    });
                }
            },
            Scope::Cluster => None,
        };

        // `.status` is never part of an SSA body (`apply_body` is idempotent).
        let body = apply_body(&resource.object);
        let outcome = self
            .api
            .dry_run(DryRunTarget {
                key,
                api_resource: &api_resource,
                namespace,
                object: &body,
                force: self.force,
            })
            .await?;

        Ok(match outcome {
            DryRunOutcome::Predicted(predicted) => {
                // Finding C1: compare the **full documents**. `DynamicObject::data` excludes
                // `metadata` (and the type fields), so diffing it reported every label/annotation
                // edit as `Synced`. `ResourceDiff::compare` strips the volatile metadata and
                // `.status` itself.
                let live_document = document(live_object, key)?;
                let predicted_document = document(&predicted, key)?;
                ResourceDiff::compare(key, &live_document, &predicted_document, rules)
            }
            DryRunOutcome::Conflict { conflicts } => {
                ResourceDiff::conflicted(key.clone(), conflicts)
            }
            DryRunOutcome::ImmutableField => {
                // Kubernetes rejected the in-place SSA dry-run because an immutable field changed
                // (`422 Invalid`). Compare live against the desired apply body locally so the diff
                // stays visible (and Secret-redacted) and the sync executor can either run
                // `Replace=true` or report the actionable immutable-field guidance.
                let live_document = document(live_object, key)?;
                let desired_document = document(&body, key)?;
                let diff = ResourceDiff::compare(key, &live_document, &desired_document, rules);
                if diff.is_synced()
                    && ResourceDiff::compare(
                        key,
                        &live_document,
                        &desired_document,
                        &IgnoreRuleSet::default(),
                    )
                    .is_synced()
                {
                    // No local field diff existed (and `ignoreDifferences` did not suppress one),
                    // yet Kubernetes rejected the SSA dry-run as immutable (for example, a mutating
                    // admission webhook modified an immutable field). Never masquerade as `Synced`.
                    ResourceDiff::immutable(key.clone())
                } else {
                    diff
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ferriscd_engine::diff::ignore::IgnoreRuleSet;
    use ferriscd_engine::diff::types::{DiffStatus, DiffSummary};
    use ferriscd_engine::manifest::GroupVersionKind as EngineGvk;
    use kube::discovery::ApiCapabilities;
    use serde_json::json;

    use super::*;
    use crate::discovery::{DiscoveryFuture, DiscoverySnapshot, DiscoverySource};

    // ---------------------------------------------------------------------
    // Fakes
    // ---------------------------------------------------------------------

    /// One recorded dry-run call.
    #[derive(Clone, Debug, PartialEq)]
    struct Call {
        api_version: String,
        kind: String,
        namespace: Option<String>,
        name: String,
        force: bool,
        body: serde_json::Value,
    }

    #[derive(Default)]
    struct FakeDryRun {
        responses: StdMutex<BTreeMap<String, DryRunOutcome>>,
        failures: StdMutex<BTreeMap<String, (u16, String)>>,
        calls: StdMutex<Vec<Call>>,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        yields: usize,
    }

    impl FakeDryRun {
        fn with_yields(yields: usize) -> Self {
            Self {
                yields,
                ..Self::default()
            }
        }

        fn predicted(&self, key: &ResourceKey, object: DynamicObject) -> &Self {
            self.responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key.canonical(), DryRunOutcome::Predicted(Box::new(object)));
            self
        }

        fn conflicted(&self, key: &ResourceKey, conflicts: Vec<FieldConflict>) -> &Self {
            self.responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key.canonical(), DryRunOutcome::Conflict { conflicts });
            self
        }

        fn failing(&self, key: &ResourceKey, code: u16, message: &str) -> &Self {
            self.failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key.canonical(), (code, message.to_owned()));
            self
        }

        fn calls(&self) -> Vec<Call> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn call_count(&self) -> usize {
            self.calls().len()
        }

        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(Ordering::SeqCst)
        }
    }

    impl DryRunApi for FakeDryRun {
        fn dry_run<'a>(&'a self, target: DryRunTarget<'a>) -> DryRunFuture<'a> {
            let call = Call {
                api_version: target.api_resource.api_version.clone(),
                kind: target.api_resource.kind.clone(),
                namespace: target.namespace.map(str::to_owned),
                name: target.key.name.clone(),
                force: target.force,
                body: serde_json::to_value(target.object).unwrap_or(serde_json::Value::Null),
            };
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(call);
            let key = target.key.canonical();
            // An unscripted dry-run echoes the apply body, which is the "nothing else manages
            // this and the API server defaulted nothing" case.
            let echoed = target.object.clone();
            Box::pin(async move {
                let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
                for _ in 0..self.yields {
                    tokio::task::yield_now().await;
                }
                self.in_flight.fetch_sub(1, Ordering::SeqCst);

                if let Some((code, message)) = self
                    .failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&key)
                    .cloned()
                {
                    return Err(DryRunError::Api {
                        resource: key.clone(),
                        code,
                        message,
                    });
                }

                let outcome = self
                    .responses
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&key)
                    .cloned()
                    .unwrap_or(DryRunOutcome::Predicted(Box::new(echoed)));
                Ok(outcome)
            })
        }
    }

    #[derive(Default)]
    struct FakeDiscovery {
        snapshot: StdMutex<DiscoverySnapshot>,
    }

    impl FakeDiscovery {
        fn new() -> Self {
            Self {
                snapshot: StdMutex::new(DiscoverySnapshot::new("v1.35.0")),
            }
        }

        fn with(self, group: &str, version: &str, kind: &str, scope: Scope) -> Self {
            {
                let mut snapshot = self
                    .snapshot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *snapshot = snapshot
                    .clone()
                    .with_resource(api_resource(group, version, kind), capabilities(scope));
            }
            self
        }
    }

    impl DiscoverySource for FakeDiscovery {
        fn fetch(&self) -> DiscoveryFuture<'_> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                Ok(self
                    .snapshot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone())
            })
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    fn api_version(group: &str, version: &str) -> String {
        if group.is_empty() {
            version.to_owned()
        } else {
            format!("{group}/{version}")
        }
    }

    fn api_resource(group: &str, version: &str, kind: &str) -> ApiResource {
        let mut resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind));
        resource.plural = format!("{}s", kind.to_ascii_lowercase());
        resource
    }

    fn capabilities(scope: Scope) -> ApiCapabilities {
        ApiCapabilities {
            scope,
            subresources: Vec::new(),
            operations: vec!["get".to_owned(), "patch".to_owned()],
        }
    }

    fn cache(discovery: FakeDiscovery) -> DiscoveryCache {
        DiscoveryCache::with_source(Arc::new(discovery), Duration::from_secs(3600))
    }

    /// Discovery that serves the kinds used by the common tests.
    fn standard_cache() -> DiscoveryCache {
        cache(
            FakeDiscovery::new()
                .with("apps", "v1", "Deployment", Scope::Namespaced)
                .with("", "v1", "ConfigMap", Scope::Namespaced)
                .with("", "v1", "Secret", Scope::Namespaced)
                .with(
                    "rbac.authorization.k8s.io",
                    "v1",
                    "ClusterRole",
                    Scope::Cluster,
                ),
        )
    }

    fn key(group: &str, kind: &str, namespace: Option<&str>, name: &str) -> ResourceKey {
        ResourceKey::new(group, kind, namespace.map(str::to_owned), name)
    }

    fn desired(
        group: &str,
        version: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
        data: serde_json::Value,
    ) -> DesiredResource {
        DesiredResource {
            key: key(group, kind, namespace, name),
            gvk: EngineGvk::parse(&api_version(group, version), kind).expect("gvk"),
            object: serde_json::from_value(data).expect("valid DynamicObject"),
            source_file: "deployment.yaml".to_owned(),
        }
    }

    fn deployment_object(replicas: i64) -> serde_json::Value {
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "api", "namespace": "payments" },
            "spec": {
                "replicas": replicas,
                "template": { "spec": { "containers": [ { "name": "api", "image": "api:v1" } ] } },
            },
        })
    }

    fn desired_deployment(replicas: i64) -> DesiredResource {
        desired(
            "apps",
            "v1",
            "Deployment",
            Some("payments"),
            "api",
            deployment_object(replicas),
        )
    }

    fn object(data: serde_json::Value) -> DynamicObject {
        serde_json::from_value(data).expect("valid DynamicObject")
    }

    fn live_map(entries: Vec<(ResourceKey, LiveState)>) -> LiveStateMap {
        entries.into_iter().collect()
    }

    fn present(data: serde_json::Value, ownership: Ownership) -> LiveState {
        LiveState::Present(Box::new(object(data)), ownership)
    }

    async fn evaluate(
        fake: &Arc<FakeDryRun>,
        desired: &[DesiredResource],
        orphans: &[ResourceKey],
        live: &LiveStateMap,
    ) -> Vec<ResourceDiff> {
        DryRunEvaluator::with_api(fake.clone(), standard_cache())
            .evaluate(desired, orphans, live, &IgnoreRuleSet::default())
            .await
            .expect("the diff pass must succeed")
    }

    /// The same pass with explicit `ignoreDifferences`.
    async fn evaluate_with_rules(
        fake: &Arc<FakeDryRun>,
        desired: &[DesiredResource],
        live: &LiveStateMap,
        rules: &IgnoreRuleSet,
    ) -> Vec<ResourceDiff> {
        DryRunEvaluator::with_api(fake.clone(), standard_cache())
            .evaluate(desired, &[], live, rules)
            .await
            .expect("the diff pass must succeed")
    }

    // ---------------------------------------------------------------------
    // Patch parameters
    // ---------------------------------------------------------------------

    #[test]
    fn ssa_patch_params_are_a_dry_run_with_force_false_by_default() {
        // Trap T5: forcing a dry-run hides the conflicts the diff exists to report.
        let field_manager = DynamicDryRunApi::field_manager();
        assert_eq!(
            field_manager,
            ferriscd_engine::default_field_manager(),
            "the dry-run must use the same manager identity as the apply, never a literal"
        );

        let params = apply_patch_params(&field_manager, false);
        assert!(params.dry_run, "every diff pass must use dryRun=All");
        assert!(!params.force, "force must default to false");
        assert_eq!(params.field_manager.as_deref(), Some("ferriscd"));

        let forced = apply_patch_params(&field_manager, true);
        assert!(forced.dry_run);
        assert!(forced.force, "serverSideForce: true must pass force");
        assert_eq!(
            forced.field_manager, params.field_manager,
            "the field manager must never change"
        );
    }

    // ---------------------------------------------------------------------
    // Classification without a dry-run (trap C3)
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn missing_and_deferred_resources_skip_the_dry_run() {
        // Trap C3: a brand-new CRD+CR bundle, or a namespace created by this sync, must never
        // fail in the diff phase. Every one of these classifications is decided locally.
        let deployment = desired_deployment(2);
        let states = live_map(vec![
            (deployment.key.clone(), LiveState::Missing),
            (
                key("example.com", "Widget", Some("payments"), "one"),
                LiveState::DeferredPendingCrd,
            ),
            (
                key("", "ConfigMap", Some("payments"), "settings"),
                LiveState::DeferredPendingNamespace,
            ),
            (
                key("", "ConfigMap", Some("payments"), "gone"),
                LiveState::OrphanGvkGone,
            ),
        ]);

        let widgets = [
            desired(
                "example.com",
                "v1",
                "Widget",
                Some("payments"),
                "one",
                json!({ "apiVersion": "example.com/v1", "kind": "Widget",
                        "metadata": { "name": "one", "namespace": "payments" } }),
            ),
            desired(
                "",
                "v1",
                "ConfigMap",
                Some("payments"),
                "settings",
                json!({ "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": { "name": "settings", "namespace": "payments" } }),
            ),
            desired(
                "",
                "v1",
                "ConfigMap",
                Some("payments"),
                "gone",
                json!({ "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": { "name": "gone", "namespace": "payments" } }),
            ),
        ];

        let fake = Arc::new(FakeDryRun::default());
        let mut resources = vec![deployment];
        resources.extend(widgets);
        // A key the live pass never classified is still "apply it", never an error.
        resources.push(desired(
            "",
            "v1",
            "Secret",
            Some("payments"),
            "unfetched",
            json!({ "apiVersion": "v1", "kind": "Secret",
                    "metadata": { "name": "unfetched", "namespace": "payments" } }),
        ));

        let diffs = evaluate(&fake, &resources, &[], &states).await;

        assert_eq!(diffs.len(), 5);
        for diff in &diffs {
            assert_eq!(
                diff.status(),
                &DiffStatus::Missing,
                "{} must be classified Missing without a dry-run",
                diff.key()
            );
        }
        assert_eq!(
            fake.call_count(),
            0,
            "no dry-run may be issued for a resource that does not exist yet"
        );
        assert!(DiffSummary::from_diffs(&diffs).has_drift());
    }

    #[tokio::test]
    async fn a_foreign_owner_is_an_ownership_conflict_without_a_dry_run() {
        let deployment = desired_deployment(2);
        let foreign = live_map(vec![(
            deployment.key.clone(),
            present(
                deployment_object(2),
                Ownership::OwnedByForeign("ferriscd-system/other".to_owned()),
            ),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &foreign).await;

        assert_eq!(diffs.len(), 1);
        assert_eq!(
            diffs[0].status(),
            &DiffStatus::OwnershipConflict {
                owner: "ferriscd-system/other".to_owned()
            }
        );
        assert_eq!(
            fake.call_count(),
            0,
            "another Application's object must never be dry-run"
        );
        let summary = DiffSummary::from_diffs(&diffs);
        assert_eq!(summary.ownership_conflicts, 1);
        assert!(
            !summary.has_drift(),
            "an ownership conflict is terminal (finding M4): self-healing it would loop forever"
        );
        assert!(summary.has_ownership_conflicts());
        assert_eq!(
            summary.sync_status(),
            ferriscd_crd::status::SyncStatus::OutOfSync,
            "the conflict must still be reported"
        );
    }

    // ---------------------------------------------------------------------
    // The dry-run itself
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn a_matching_prediction_is_synced() {
        let deployment = desired_deployment(2);
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        fake.predicted(
            &deployment.key,
            object(json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "api",
                    "namespace": "payments",
                    "resourceVersion": "999",
                    "managedFields": [ { "manager": "ferriscd" } ],
                },
                "spec": {
                    "replicas": 2,
                    "template": { "spec": { "containers": [ { "name": "api", "image": "api:v1" } ] } },
                },
                "status": { "replicas": 2 },
            })),
        );

        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;

        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].status(), &DiffStatus::Synced);
        assert!(diffs[0].changes().is_empty());
        assert_eq!(
            DiffSummary::from_diffs(&diffs).sync_status(),
            ferriscd_crd::status::SyncStatus::Synced
        );

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].api_version, "apps/v1");
        assert_eq!(calls[0].kind, "Deployment");
        assert_eq!(calls[0].namespace.as_deref(), Some("payments"));
        assert_eq!(calls[0].name, "api");
        assert!(
            !calls[0].force,
            "force must default to false (trap T5: never clobber a foreign field manager)"
        );
    }

    #[tokio::test]
    async fn the_apply_body_never_carries_a_status() {
        let mut deployment = desired_deployment(2);
        // A renderer or a previous pass may leave `.status` behind; the dry-run body must not
        // contain it (SSA safety default).
        deployment.object.data["status"] = json!({ "replicas": 7 });
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;
        assert_eq!(diffs[0].status(), &DiffStatus::Synced);

        let body = &fake.calls()[0].body;
        assert!(
            body.get("status").is_none(),
            "the dry-run body must not carry .status: {body}"
        );
        assert_eq!(body["spec"]["replicas"], json!(2));
    }

    #[tokio::test]
    async fn a_differing_prediction_is_out_of_sync() {
        let deployment = desired_deployment(5);
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        // The prediction is the *desired* payload after the API server's evaluation, so it
        // carries `replicas: 5`; the live object still says 2 — someone edited it outside Git.
        fake.predicted(&deployment.key, object(deployment_object(5)));

        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;
        assert_eq!(diffs[0].status(), &DiffStatus::OutOfSync);
        let changes: Vec<(&str, Option<serde_json::Value>, Option<serde_json::Value>)> = diffs[0]
            .changes()
            .iter()
            .map(|change| {
                (
                    change.path.as_str(),
                    change.live.clone(),
                    change.predicted.clone(),
                )
            })
            .collect();
        assert_eq!(
            changes,
            vec![("/spec/replicas", Some(json!(2)), Some(json!(5)))],
            "the change must show live vs the value FerrisCD wants"
        );
    }

    // ---------------------------------------------------------------------
    // Metadata drift (finding C1)
    // ---------------------------------------------------------------------

    /// Finding C1 regression: `DynamicObject::data` excludes `metadata`, so a label or an
    /// annotation that drifted between live and the prediction was reported `Synced`.
    #[tokio::test]
    async fn a_label_or_annotation_change_is_out_of_sync() {
        let deployment = desired_deployment(2);

        // (1) Only `metadata.labels.tier` differs.
        let mut live_object = deployment_object(2);
        live_object["metadata"]["labels"] = json!({ "app": "api", "tier": "backend" });
        let live = live_map(vec![(
            deployment.key.clone(),
            present(live_object, Ownership::OwnedBySelf),
        )]);
        let mut predicted_object = deployment_object(2);
        predicted_object["metadata"]["labels"] = json!({ "app": "api", "tier": "frontend" });

        let fake = Arc::new(FakeDryRun::default());
        fake.predicted(&deployment.key, object(predicted_object));
        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;
        assert_eq!(
            diffs[0].status(),
            &DiffStatus::OutOfSync,
            "label drift must never be reported Synced: {:?}",
            diffs[0].changes()
        );
        assert_eq!(
            diffs[0]
                .changes()
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/metadata/labels/tier"]
        );
        assert_eq!(diffs[0].changes()[0].live, Some(json!("backend")));
        assert_eq!(diffs[0].changes()[0].predicted, Some(json!("frontend")));

        // (2) Only `metadata.annotations["example.com/owner"]` differs.
        let mut live_object = deployment_object(2);
        live_object["metadata"]["annotations"] = json!({ "example.com/owner": "platform" });
        let live = live_map(vec![(
            deployment.key.clone(),
            present(live_object, Ownership::OwnedBySelf),
        )]);
        let mut predicted_object = deployment_object(2);
        predicted_object["metadata"]["annotations"] = json!({ "example.com/owner": "payments" });

        let fake = Arc::new(FakeDryRun::default());
        fake.predicted(&deployment.key, object(predicted_object));
        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;
        assert_eq!(diffs[0].status(), &DiffStatus::OutOfSync);
        assert_eq!(
            diffs[0]
                .changes()
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/metadata/annotations/example.com~1owner"],
            "the annotation path must be an escaped JSON Pointer"
        );

        // (3) An `ignoreDifferences` rule for that escaped pointer really removes the change:
        //     metadata pointers are no longer no-ops.
        let rules = IgnoreRuleSet::from_ignore_differences(&[ferriscd_crd::IgnoreDifference {
            group: Some("apps".to_owned()),
            kind: "Deployment".to_owned(),
            json_pointers: vec!["/metadata/annotations/example.com~1owner".to_owned()],
            ..ferriscd_crd::IgnoreDifference::default()
        }]);
        let ignored =
            evaluate_with_rules(&fake, std::slice::from_ref(&deployment), &live, &rules).await;
        assert_eq!(ignored[0].status(), &DiffStatus::Synced);
        assert_eq!(
            ignored[0].changes().len(),
            0,
            "the ignored metadata change must disappear: {:?}",
            ignored[0].changes()
        );
    }

    /// The desired-body contract: the evaluator compares full documents, so it must be handed the
    /// **stamped** body the applier receives. A `ferriscd.io/tracking-id` present on both sides is
    /// zero drift; a live object missing it is real drift at the escaped annotation pointer.
    #[tokio::test]
    async fn a_stamped_desired_body_is_diffed_as_the_applier_would_see_it() {
        const TRACKING_ID: &str = "ferriscd-system/payments:apps/Deployment:payments/api";
        assert_eq!(
            ferriscd_crd::annotations::TRACKING_ID,
            "ferriscd.io/tracking-id",
            "the pointer below is the escaped form of this annotation key"
        );

        // The body a T07.5 caller must pass: already stamped by `stamp_tracking_id`, i.e. the
        // exact slice the applier will send.
        let mut stamped = deployment_object(2);
        stamped["metadata"]["annotations"] = json!({ "ferriscd.io/tracking-id": TRACKING_ID });
        let deployment = desired(
            "apps",
            "v1",
            "Deployment",
            Some("payments"),
            "api",
            stamped.clone(),
        );

        // (1) Live carries the same annotation and the same spec: zero changes, so no self-heal
        //     loop. The unscripted fake echoes the apply body, which is exactly what an API
        //     server with nothing to default would predict.
        let live = live_map(vec![(
            deployment.key.clone(),
            present(stamped.clone(), Ownership::OwnedBySelf),
        )]);
        let fake = Arc::new(FakeDryRun::default());
        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;
        assert_eq!(
            diffs[0].status(),
            &DiffStatus::Synced,
            "the stamped tracking-id must never be reported as drift: {:?}",
            diffs[0].changes()
        );
        assert!(diffs[0].changes().is_empty());
        assert_eq!(
            fake.calls()[0].body["metadata"]["annotations"]["ferriscd.io/tracking-id"],
            json!(TRACKING_ID),
            "the dry-run must receive the stamped body, never a pre-stamp one"
        );

        // (2) A live object that lacks the annotation while carrying one of its own: the API
        //     server keeps the foreign annotation and adds FerrisCD's, so the prediction is the
        //     stamped body plus that annotation, and the added tracking-id is genuine drift at the
        //     escaped JSON Pointer for the annotation key.
        let mut unstamped_live = deployment_object(2);
        unstamped_live["metadata"]["annotations"] = json!({ "example.com/owner": "platform" });
        let live = live_map(vec![(
            deployment.key.clone(),
            present(unstamped_live, Ownership::OwnedBySelf),
        )]);
        let mut predicted = stamped.clone();
        predicted["metadata"]["annotations"]["example.com/owner"] = json!("platform");
        let fake = Arc::new(FakeDryRun::default());
        fake.predicted(&deployment.key, object(predicted));
        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;
        assert_eq!(diffs[0].status(), &DiffStatus::OutOfSync);
        assert_eq!(
            diffs[0]
                .changes()
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/metadata/annotations/ferriscd.io~1tracking-id"],
            "an unstamped live object must be reported at the escaped annotation pointer: {:?}",
            diffs[0].changes()
        );
        assert_eq!(diffs[0].changes()[0].live, None);
        assert_eq!(diffs[0].changes()[0].predicted, Some(json!(TRACKING_ID)));
    }

    #[tokio::test]
    async fn server_side_force_is_opt_in() {
        let deployment = desired_deployment(2);
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);
        let fake = Arc::new(FakeDryRun::default());

        let default_evaluator = DryRunEvaluator::with_api(fake.clone(), standard_cache());
        assert!(!default_evaluator.force());
        default_evaluator
            .evaluate(
                std::slice::from_ref(&deployment),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect("diff pass");
        assert!(!fake.calls()[0].force);

        fake.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();

        let forced = DryRunEvaluator::with_api(fake.clone(), standard_cache()).with_force(true);
        assert!(forced.force());
        forced
            .evaluate(
                std::slice::from_ref(&deployment),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect("diff pass");
        assert!(
            fake.calls()[0].force,
            "syncOptions.serverSideForce: true must be honored"
        );
    }

    #[tokio::test]
    async fn an_unmanaged_live_object_is_still_diffed() {
        // Brownfield adoption (T08.4): the object exists, nobody tracks it. The dry-run is a
        // read-only prediction, so diffing it is safe and tells the operator what would change.
        let deployment = desired_deployment(3);
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(1), Ownership::Unmanaged),
        )]);
        let fake = Arc::new(FakeDryRun::default());
        fake.predicted(&deployment.key, object(deployment_object(3)));

        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;
        assert_eq!(diffs[0].status(), &DiffStatus::OutOfSync);
        assert_eq!(fake.call_count(), 1);
    }

    #[tokio::test]
    async fn cluster_scoped_resources_are_dry_run_without_a_namespace() {
        let cluster_role = desired(
            "rbac.authorization.k8s.io",
            "v1",
            "ClusterRole",
            None,
            "reader",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": { "name": "reader" },
                "rules": [],
            }),
        );
        let live = live_map(vec![(
            cluster_role.key.clone(),
            present(
                json!({
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": { "name": "reader" },
                    "rules": [],
                }),
                Ownership::OwnedBySelf,
            ),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        let diffs = evaluate(&fake, std::slice::from_ref(&cluster_role), &[], &live).await;
        assert_eq!(diffs[0].status(), &DiffStatus::Synced);
        assert_eq!(
            fake.calls()[0].namespace,
            None,
            "a cluster-scoped object must never be dry-run through a namespace"
        );
    }

    // ---------------------------------------------------------------------
    // Conflicts and errors
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn a_409_conflict_becomes_structured_field_conflicts() {
        let deployment = desired_deployment(5);
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        fake.conflicted(
            &deployment.key,
            vec![FieldConflict::new(
                Some("spec.replicas".to_owned()),
                Some("horizontal-pod-autoscaler".to_owned()),
            )],
        );

        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &[], &live).await;
        assert_eq!(
            diffs[0].status(),
            &DiffStatus::OutOfSync,
            "a conflict is drift, not an opaque error"
        );
        assert_eq!(
            diffs[0].conflicts(),
            [FieldConflict::new(
                Some("spec.replicas".to_owned()),
                Some("horizontal-pod-autoscaler".to_owned()),
            )]
        );
        let summary = DiffSummary::from_diffs(&diffs);
        assert_eq!(summary.out_of_sync, 1);
        assert_eq!(summary.field_conflicts, 1);
    }

    #[tokio::test]
    async fn a_non_conflict_api_error_is_typed_and_classified() {
        let deployment = desired_deployment(2);
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        fake.failing(&deployment.key, 500, "internal error");
        let err = DryRunEvaluator::with_api(fake.clone(), standard_cache())
            .evaluate(
                std::slice::from_ref(&deployment),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect_err("a 500 must fail the diff pass");
        assert!(matches!(err, DryRunError::Api { code: 500, .. }), "{err}");
        assert!(err.is_retryable(), "a 500 is transient");
        assert!(err.to_string().contains("apps/Deployment/payments/api"));

        let fake = Arc::new(FakeDryRun::default());
        fake.failing(&deployment.key, 403, "deployments \"api\" is forbidden");
        let err = DryRunEvaluator::with_api(fake, standard_cache())
            .evaluate(
                std::slice::from_ref(&deployment),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect_err("a 403 must fail the diff pass");
        assert!(matches!(err, DryRunError::Api { code: 403, .. }), "{err}");
        assert!(!err.is_retryable(), "a 403 is terminal");
    }

    /// Finding M1: the `409` mapping is a pure function, unit-tested without an API server.
    #[test]
    fn classify_result_turns_a_409_into_structured_conflicts() {
        let config_map_key = key("", "ConfigMap", Some("payments"), "settings");
        let status = status_from(json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": "Apply failed with 1 conflict: conflict with \"kubectl-client-side-apply\": .data.owner",
            "reason": "Conflict",
            "details": { "causes": [ {
                "reason": "FieldManagerConflict",
                "message": "conflict with \"kubectl-client-side-apply\"",
                "field": "data.owner",
            } ] },
            "code": 409,
        }));
        assert_eq!(status.code, 409);

        let outcome = classify_result(Err(kube::Error::Api(Box::new(status))), &config_map_key)
            .expect("a 409 is a classification, not a failure");
        match outcome {
            DryRunOutcome::Conflict { conflicts } => assert_eq!(
                conflicts,
                vec![FieldConflict::new(
                    Some("data.owner".to_owned()),
                    Some("kubectl-client-side-apply".to_owned())
                )]
            ),
            other => panic!("a 409 must become a Conflict, got {other:?}"),
        }

        // A success becomes the prediction, and every other status stays an error.
        let predicted = classify_result(
            Ok(object(deployment_object(2))),
            &key("apps", "Deployment", Some("payments"), "api"),
        )
        .expect("a success is a prediction");
        assert!(matches!(predicted, DryRunOutcome::Predicted(_)));

        let status = status_from(json!({ "status": "Failure", "message": "boom", "code": 500 }));
        let err = classify_result(Err(kube::Error::Api(Box::new(status))), &config_map_key)
            .expect_err("a 500 is a failure");
        assert!(matches!(err, DryRunError::Api { code: 500, .. }), "{err}");
        assert!(err.is_retryable());
    }

    #[test]
    fn classify_result_turns_an_immutable_422_into_immutable_field_outcome() {
        let config_map_key = key("", "ConfigMap", Some("payments"), "immutable");
        let immutable = status_from(json!({
            "status": "Failure",
            "message": "ConfigMap \"immutable\" is invalid: data: Forbidden: field is immutable when `immutable` is set",
            "reason": "Invalid",
            "code": 422,
        }));
        let outcome = classify_result(Err(kube::Error::Api(Box::new(immutable))), &config_map_key)
            .expect("immutable-field 422 must classify instead of aborting dry-run");
        assert!(matches!(outcome, DryRunOutcome::ImmutableField));

        // Non-immutable 422s remain terminal API errors.
        let other_invalid = status_from(json!({
            "status": "Failure",
            "message": "ConfigMap \"settings\" is invalid: data[bad]: Invalid value",
            "reason": "Invalid",
            "code": 422,
        }));
        let err = classify_result(
            Err(kube::Error::Api(Box::new(other_invalid))),
            &config_map_key,
        )
        .expect_err("non-immutable 422 must remain a DryRunError");
        assert!(matches!(err, DryRunError::Api { code: 422, .. }), "{err}");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn immutable_field_dry_run_falls_back_to_redacted_local_diff() {
        let cm_key = key("", "ConfigMap", Some("payments"), "immutable");
        let desired_cm = desired(
            "",
            "v1",
            "ConfigMap",
            Some("payments"),
            "immutable",
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": "immutable", "namespace": "payments" },
                "immutable": true,
                "data": { "key": "b" },
            }),
        );
        let live_cm = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "immutable",
                "namespace": "payments",
                "resourceVersion": "42",
                "uid": "abc",
            },
            "immutable": true,
            "data": { "key": "a" },
        });
        let fake = Arc::new(FakeDryRun::default());
        fake.responses
            .lock()
            .unwrap()
            .insert(cm_key.canonical(), DryRunOutcome::ImmutableField);

        let live = live_map(vec![(
            cm_key.clone(),
            present(live_cm, Ownership::OwnedBySelf),
        )]);
        let diffs = evaluate(&fake, std::slice::from_ref(&desired_cm), &[], &live).await;
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].status(), &DiffStatus::OutOfSync);
        assert!(
            diffs[0].changes().iter().any(|c| c.path == "/data/key"),
            "expected /data/key diff, got: {:?}",
            diffs[0].changes()
        );
    }

    /// Trap T4: an immutable `v1/Secret` falling back to local diff must redact all `.data` /
    /// `.stringData` values from `changes()`, `Debug`, and JSON serialization.
    #[tokio::test]
    async fn immutable_field_dry_run_redacts_secret_values() {
        const OLD_B64: &str = "b2xkLXNlY3JldC10b2tlbi12YWx1ZQ==";
        const NEW_B64: &str = "bmV3LXNlY3JldC10b2tlbi12YWx1ZQ==";

        let secret_key = key("", "Secret", Some("payments"), "immutable-creds");
        let desired_secret = desired(
            "",
            "v1",
            "Secret",
            Some("payments"),
            "immutable-creds",
            json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "immutable-creds", "namespace": "payments" },
                "immutable": true,
                "data": { "token": NEW_B64 },
            }),
        );
        let live_secret = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "immutable-creds",
                "namespace": "payments",
                "resourceVersion": "9",
                "uid": "sec-uid",
            },
            "immutable": true,
            "data": { "token": OLD_B64 },
        });
        let fake = Arc::new(FakeDryRun::default());
        fake.responses
            .lock()
            .unwrap()
            .insert(secret_key.canonical(), DryRunOutcome::ImmutableField);

        let live = live_map(vec![(
            secret_key.clone(),
            present(live_secret, Ownership::OwnedBySelf),
        )]);
        let diffs = evaluate(&fake, std::slice::from_ref(&desired_secret), &[], &live).await;
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].status(), &DiffStatus::OutOfSync);
        assert!(
            diffs[0].changes().iter().any(|c| {
                c.path == "/data/token"
                    && c.live
                        .as_ref()
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|v| v.starts_with("***REDACTED(sha256:"))
                    && c.predicted
                        .as_ref()
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|v| v.starts_with("***REDACTED(sha256:"))
            }),
            "Secret diff must carry redacted sha256 placeholders: {:?}",
            diffs[0].changes()
        );
        let debug_rendered = format!("{:?}", diffs[0]);
        let json_rendered = serde_json::to_string(&diffs[0]).expect("serialize diff");
        for needle in [OLD_B64, NEW_B64] {
            assert!(
                !debug_rendered.contains(needle),
                "Secret value leaked in Debug: {debug_rendered}"
            );
            assert!(
                !json_rendered.contains(needle),
                "Secret value leaked in JSON: {json_rendered}"
            );
        }
    }

    #[tokio::test]
    async fn immutable_field_dry_run_never_silently_reports_synced_without_ignore_rule() {
        let cm_key = key("", "ConfigMap", Some("payments"), "webhook-immutable");
        let same_doc = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "webhook-immutable", "namespace": "payments" },
            "immutable": true,
            "data": { "key": "same" },
        });
        let desired_cm = desired(
            "",
            "v1",
            "ConfigMap",
            Some("payments"),
            "webhook-immutable",
            same_doc.clone(),
        );
        let fake = Arc::new(FakeDryRun::default());
        fake.responses
            .lock()
            .unwrap()
            .insert(cm_key.canonical(), DryRunOutcome::ImmutableField);

        let live = live_map(vec![(
            cm_key.clone(),
            present(same_doc, Ownership::OwnedBySelf),
        )]);
        let diffs = evaluate(&fake, std::slice::from_ref(&desired_cm), &[], &live).await;
        assert_eq!(
            diffs[0].status(),
            &DiffStatus::OutOfSync,
            "an unexplained immutable 422 must stay OutOfSync so Replace/guidance still runs"
        );

        // Contrast: when `ignoreDifferences` explicitly suppresses the changed immutable field,
        // the diff legitimately stays `Synced`.
        let mut modified = desired_cm.clone();
        modified.object.data["data"]["key"] = json!("ignored-change");
        let rules = IgnoreRuleSet::from_ignore_differences(&[ferriscd_crd::IgnoreDifference {
            kind: "ConfigMap".to_owned(),
            name: Some("webhook-immutable".to_owned()),
            namespace: Some("payments".to_owned()),
            json_pointers: vec!["/data/key".to_owned()],
            ..ferriscd_crd::IgnoreDifference::default()
        }]);
        let ignored =
            evaluate_with_rules(&fake, std::slice::from_ref(&modified), &live, &rules).await;
        assert_eq!(
            ignored[0].status(),
            &DiffStatus::Synced,
            "an explicitly ignored field difference stays Synced"
        );
    }

    /// Finding M2: a `400`/`422` message for a `Secret` can quote the offending value, so it is
    /// never carried verbatim. Every other kind keeps the actionable server text.
    #[test]
    fn a_secret_error_message_is_redacted() {
        const ENCODED: &str = "czNjcjN0LXBAc3N3MHJk";
        let secret_key = key("", "Secret", Some("payments"), "creds");
        let status = status_from(json!({
            "status": "Failure",
            "message": format!(
                "Secret \"creds\" is invalid: data[password]: Invalid value: {ENCODED:?}"
            ),
            "reason": "Invalid",
            "code": 422,
        }));

        let err = DryRunError::api(&secret_key, &kube::Error::Api(Box::new(status)));
        let rendered = err.to_string();
        assert!(matches!(err, DryRunError::Api { code: 422, .. }), "{err}");
        assert!(!rendered.contains(ENCODED), "{rendered}");
        assert!(rendered.contains(REDACTED_SERVER_MESSAGE), "{rendered}");
        assert!(
            rendered.contains("character(s) withheld"),
            "the redaction must still say something happened: {rendered}"
        );
        assert!(!err.is_retryable(), "a 422 is terminal");

        // A ConfigMap message names the offending field and stays readable.
        let config_map_key = key("", "ConfigMap", Some("payments"), "settings");
        let status = status_from(json!({
            "message": "ConfigMap \"settings\" is invalid: data[bad]: Invalid value",
            "code": 422,
        }));
        let err = DryRunError::api(&config_map_key, &kube::Error::Api(Box::new(status)));
        assert!(err.to_string().contains("data[bad]"), "{err}");
    }

    /// The new serialization failure is terminal, never retryable.
    #[test]
    fn a_serialization_failure_is_typed_and_terminal() {
        let err = DryRunError::Serialization {
            resource: "apps/Deployment/payments/api".to_owned(),
            message: "nope".to_owned(),
        };
        assert!(!err.is_retryable());
        assert!(
            err.to_string().contains("apps/Deployment/payments/api"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_unknown_kind_is_a_terminal_discovery_error() {
        let deployment = desired_deployment(2);
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);

        // Discovery that serves nothing at all.
        let fake = Arc::new(FakeDryRun::default());
        let err = DryRunEvaluator::with_api(fake.clone(), cache(FakeDiscovery::new()))
            .evaluate(
                std::slice::from_ref(&deployment),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect_err("an unserved kind must fail");
        assert!(matches!(err, DryRunError::Discovery(_)), "{err}");
        assert!(!err.is_retryable());
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn a_namespaced_kind_without_a_namespace_is_a_scope_mismatch() {
        let namespaceless = desired(
            "apps",
            "v1",
            "Deployment",
            None,
            "api",
            deployment_object(2),
        );
        let live = live_map(vec![(
            namespaceless.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        let err = DryRunEvaluator::with_api(fake.clone(), standard_cache())
            .evaluate(
                std::slice::from_ref(&namespaceless),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect_err("a namespaced kind must carry a namespace");
        assert!(matches!(err, DryRunError::ScopeMismatch { .. }), "{err}");
        assert!(!err.is_retryable());
        assert_eq!(fake.call_count(), 0);
    }

    // ---------------------------------------------------------------------
    // Orphans, ordering, boundedness
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn orphans_are_classified_without_any_api_call() {
        let deployment = desired_deployment(2);
        let live = live_map(vec![(
            deployment.key.clone(),
            present(deployment_object(2), Ownership::OwnedBySelf),
        )]);
        let orphans = vec![
            key("", "ConfigMap", Some("payments"), "old"),
            key("", "Service", Some("payments"), "api"),
        ];

        let fake = Arc::new(FakeDryRun::default());
        let diffs = evaluate(&fake, std::slice::from_ref(&deployment), &orphans, &live).await;

        assert_eq!(diffs.len(), 3);
        let orphaned: Vec<&ResourceKey> = diffs
            .iter()
            .filter(|diff| diff.status().is_orphaned())
            .map(ResourceDiff::key)
            .collect();
        assert_eq!(
            orphaned,
            vec![&orphans[0], &orphans[1]],
            "both orphans must be classified as Orphaned"
        );
        assert_eq!(fake.call_count(), 1, "only the desired resource is dry-run");

        let summary = DiffSummary::from_diffs(&diffs);
        assert_eq!(summary.orphaned, 2);
        assert_eq!(summary.synced, 1);
    }

    #[tokio::test]
    async fn results_are_sorted_by_key_and_stable_across_runs() {
        let resources = vec![
            desired(
                "",
                "v1",
                "ConfigMap",
                Some("payments"),
                "settings",
                json!({ "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": { "name": "settings", "namespace": "payments" } }),
            ),
            desired_deployment(2),
            desired(
                "",
                "v1",
                "Secret",
                Some("payments"),
                "creds",
                json!({ "apiVersion": "v1", "kind": "Secret",
                        "metadata": { "name": "creds", "namespace": "payments" },
                        "data": { "password": "b2xk" } }),
            ),
        ];

        let fake = Arc::new(FakeDryRun::default());
        let first = evaluate(&fake, &resources, &[], &LiveStateMap::new()).await;
        let second = evaluate(&fake, &resources, &[], &LiveStateMap::new()).await;

        let keys: Vec<String> = first.iter().map(|diff| diff.key().canonical()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "the diff must be ordered by ResourceKey");
        assert_eq!(
            first
                .iter()
                .map(|diff| diff.key().clone())
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|diff| diff.key().clone())
                .collect::<Vec<_>>()
        );
        // All three are `Missing` (no live state) and none was dry-run.
        assert!(first.iter().all(|diff| diff.status().is_missing()));
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn concurrency_is_bounded_by_the_documented_limit() {
        const RESOURCES: usize = 64;

        let fake = Arc::new(FakeDryRun::with_yields(3));
        let mut resources = Vec::new();
        let mut live = BTreeMap::new();
        for index in 0..RESOURCES {
            let name = format!("api-{index}");
            let resource = desired(
                "apps",
                "v1",
                "Deployment",
                Some("payments"),
                &name,
                deployment_object(1),
            );
            live.insert(
                resource.key.clone(),
                present(deployment_object(1), Ownership::OwnedBySelf),
            );
            resources.push(resource);
        }

        let diffs = evaluate(&fake, &resources, &[], &live).await;
        assert_eq!(diffs.len(), RESOURCES);
        assert_eq!(fake.call_count(), RESOURCES);
        assert_eq!(
            fake.max_in_flight(),
            DRY_RUN_CONCURRENCY,
            "the evaluator must saturate exactly {DRY_RUN_CONCURRENCY} in-flight dry-runs: \
             fewer means it serializes, more means the bound leaked"
        );
    }

    // ---------------------------------------------------------------------
    // Conflict parsing
    // ---------------------------------------------------------------------

    fn status_from(value: serde_json::Value) -> Status {
        serde_json::from_value(value).expect("valid kube Status")
    }

    #[test]
    fn parse_conflict_status_reads_status_details_causes() {
        let status = status_from(json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": "Apply failed with 2 conflicts: conflicts with \"kubectl-client-side-apply\": .spec.replicas, conflicts with \"horizontal-pod-autoscaler\": .spec.template.spec.containers[0].image",
            "reason": "Conflict",
            "details": {
                "causes": [
                    {
                        "reason": "FieldManagerConflict",
                        "message": "conflict with \"kubectl-client-side-apply\"",
                        "field": "spec.replicas",
                    },
                    {
                        "reason": "FieldManagerConflict",
                        "message": "conflict with \"horizontal-pod-autoscaler\"",
                        "field": ".spec.template.spec.containers[0].image",
                    },
                ],
            },
            "code": 409,
        }));
        assert_eq!(status.code, 409);

        let conflicts = parse_conflict_status(&status);
        assert_eq!(
            conflicts,
            vec![
                FieldConflict::new(
                    Some("spec.replicas".to_owned()),
                    Some("kubectl-client-side-apply".to_owned()),
                ),
                FieldConflict::new(
                    Some("spec.template.spec.containers[0].image".to_owned()),
                    Some("horizontal-pod-autoscaler".to_owned()),
                ),
            ],
            "every cause must become a named conflict"
        );
        assert_eq!(
            conflicts[0].to_string(),
            "field 'spec.replicas' is owned by manager 'kubectl-client-side-apply'"
        );
    }

    #[test]
    fn parse_conflict_status_falls_back_to_the_message() {
        // No `details`, e.g. behind a proxy that strips it: the message still names the manager.
        let status = status_from(json!({
            "status": "Failure",
            "message": "Apply failed with 1 conflict: conflict with \"helm\": .spec.replicas",
            "reason": "Conflict",
            "code": 409,
        }));
        assert_eq!(
            parse_conflict_status(&status),
            vec![FieldConflict::new(
                Some("spec.replicas".to_owned()),
                Some("helm".to_owned())
            )]
        );

        // Two conflicts, plural spelling: managers and fields pair up positionally.
        let status = status_from(json!({
            "status": "Failure",
            "message": "Apply failed with 2 conflicts: conflicts with \"helm\": .spec.a, conflicts with kubectl-client-side-apply: .spec.b",
            "code": 409,
        }));
        assert_eq!(
            parse_conflict_status(&status),
            vec![
                FieldConflict::new(Some("spec.a".to_owned()), Some("helm".to_owned())),
                FieldConflict::new(
                    Some("spec.b".to_owned()),
                    Some("kubectl-client-side-apply".to_owned())
                ),
            ],
            "managers and fields are paired positionally, then sorted by field"
        );

        // A message naming only a manager still names it.
        let status = status_from(json!({
            "message": "Apply failed with 1 conflict: conflict with \"argo-cd\"",
            "code": 409,
        }));
        assert_eq!(
            parse_conflict_status(&status),
            vec![FieldConflict::new(None, Some("argo-cd".to_owned()))]
        );

        // A message naming only a field is still structured.
        let status = status_from(json!({
            "message": "Apply failed with 1 conflict: .spec.replicas",
            "code": 409,
        }));
        assert_eq!(
            parse_conflict_status(&status),
            vec![FieldConflict::new(Some("spec.replicas".to_owned()), None)]
        );
    }

    #[test]
    fn parse_conflict_status_without_any_detail_is_still_structured() {
        let status = status_from(json!({ "status": "Failure", "code": 409 }));
        let conflicts = parse_conflict_status(&status);
        assert_eq!(conflicts, vec![FieldConflict::unknown()]);
        assert!(conflicts[0].is_unknown());
    }

    #[test]
    fn parse_conflict_status_is_deduplicated_and_bounded() {
        let causes: Vec<serde_json::Value> = (0..(MAX_FIELD_CONFLICTS * 2))
            .map(|index| {
                json!({
                    "reason": "FieldManagerConflict",
                    "message": "conflict with \"manager\"",
                    "field": format!("spec.field{index}"),
                })
            })
            .collect();
        let status = status_from(json!({ "details": { "causes": causes }, "code": 409 }));

        let conflicts = parse_conflict_status(&status);
        assert_eq!(conflicts.len(), MAX_FIELD_CONFLICTS);

        // Duplicate causes collapse.
        let status = status_from(json!({
            "details": {
                "causes": [
                    { "message": "conflict with \"hpa\"", "field": "spec.replicas" },
                    { "message": "conflict with \"hpa\"", "field": ".spec.replicas" },
                ],
            },
            "code": 409,
        }));
        assert_eq!(
            parse_conflict_status(&status),
            vec![FieldConflict::new(
                Some("spec.replicas".to_owned()),
                Some("hpa".to_owned())
            )]
        );
    }

    // ---------------------------------------------------------------------
    // Secret hygiene through the controller boundary
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn a_secret_diff_never_leaks_its_value() {
        let secret = desired(
            "",
            "v1",
            "Secret",
            Some("payments"),
            "creds",
            json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "creds", "namespace": "payments" },
                "data": { "password": "b2xkLXBhc3N3b3Jk" },
            }),
        );
        let live = live_map(vec![(
            secret.key.clone(),
            present(
                json!({
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": { "name": "creds", "namespace": "payments" },
                    "data": { "password": "b2xkLXBhc3N3b3Jk" },
                }),
                Ownership::OwnedBySelf,
            ),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        // The prediction carries a different value: someone rotated the password by hand.
        fake.predicted(
            &secret.key,
            object(json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "creds", "namespace": "payments" },
                "data": { "password": "bmV3LXBhc3N3b3Jk" },
            })),
        );

        let diffs = evaluate(&fake, std::slice::from_ref(&secret), &[], &live).await;
        assert_eq!(diffs[0].status(), &DiffStatus::OutOfSync);

        let rendered = format!(
            "{:?}{}{}",
            diffs[0],
            diffs[0],
            serde_json::to_string(&diffs[0]).expect("serialize")
        );
        for leaked in ["b2xkLXBhc3N3b3Jk", "bmV3LXBhc3N3b3Jk", "old-password"] {
            assert!(
                !rendered.contains(leaked),
                "a secret value leaked: {rendered}"
            );
        }
        assert!(rendered.contains("REDACTED"));

        // The engine's own `Debug` impls must not become the leak either: a predicted object and
        // a dry-run target are both full objects.
        let secret_object = object(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "creds", "namespace": "payments" },
            "data": { "password": "b2xkLXBhc3N3b3Jk" },
        }));
        let outcome = DryRunOutcome::Predicted(Box::new(secret_object.clone()));
        assert!(
            !format!("{outcome:?}").contains("b2xkLXBhc3N3b3Jk"),
            "DryRunOutcome::Debug must not print a secret payload"
        );
        let api_resource = api_resource("", "v1", "Secret");
        let target = DryRunTarget {
            key: &secret.key,
            api_resource: &api_resource,
            namespace: Some("payments"),
            object: &secret_object,
            force: false,
        };
        let target_debug = format!("{target:?}");
        assert!(!target_debug.contains("b2xkLXBhc3N3b3Jk"));
        assert!(target_debug.contains("payments"), "{target_debug}");
    }

    /// Finding H1: `kubectl apply` stashes the whole applied document — base64 `.data`
    /// included — in `metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]`,
    /// which `redact_secret` never touched.
    #[tokio::test]
    async fn a_last_applied_configuration_annotation_never_leaks_a_secret() {
        const PLAINTEXT: &str = "s3cr3t-p@ssw0rd";
        // base64("s3cr3t-p@ssw0rd")
        const ENCODED: &str = "czNjcjN0LXBAc3N3MHJk";
        // A second, different value that must not leak either.
        const ROTATED: &str = "bmV3LXNlY3JldA==";

        let applied = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "creds", "namespace": "payments" },
            "data": { "password": ENCODED },
        })
        .to_string();

        let secret = desired(
            "",
            "v1",
            "Secret",
            Some("payments"),
            "creds",
            json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "creds",
                    "namespace": "payments",
                    "annotations": {
                        "kubectl.kubernetes.io/last-applied-configuration": applied.clone(),
                    },
                },
                "data": { "password": ENCODED },
            }),
        );
        let live = live_map(vec![(
            secret.key.clone(),
            present(
                json!({
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": "creds",
                        "namespace": "payments",
                        "annotations": {
                            "kubectl.kubernetes.io/last-applied-configuration": applied,
                        },
                    },
                    "data": { "password": ENCODED },
                }),
                Ownership::OwnedBySelf,
            ),
        )]);

        // The prediction rotates the password: a changed key must still be drift.
        let fake = Arc::new(FakeDryRun::default());
        fake.predicted(
            &secret.key,
            object(json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "creds",
                    "namespace": "payments",
                    "annotations": {
                        "kubectl.kubernetes.io/last-applied-configuration":
                            r#"{"apiVersion":"v1","kind":"Secret","data":{"password":"bmV3LXNlY3JldA=="}}"#,
                    },
                },
                "data": { "password": ROTATED },
            })),
        );

        let diffs = evaluate(&fake, std::slice::from_ref(&secret), &[], &live).await;
        assert_eq!(
            diffs[0].status(),
            &DiffStatus::OutOfSync,
            "a changed Secret key must still be reported"
        );

        let representations = [
            format!("{:?}", diffs[0]),
            diffs[0].to_string(),
            serde_json::to_string(&diffs[0]).expect("the diff must serialize"),
        ];
        for representation in representations {
            for leaked in [PLAINTEXT, ENCODED, ROTATED] {
                assert!(
                    !representation.contains(leaked),
                    "{leaked} leaked into the Secret diff: {representation}"
                );
            }
        }

        // Both payload sites — the annotation document and the `.data` value — must be
        // fingerprinted, while the *change* stays visible (which is what keeps drift detection
        // useful).
        let json = serde_json::to_value(&diffs[0]).expect("the diff must serialize");
        let changes = json["changes"]
            .as_array()
            .expect("changes must be an array");
        assert_eq!(
            changes
                .iter()
                .map(|change| change["path"].as_str().unwrap_or_default())
                .collect::<Vec<_>>(),
            vec![
                "/data/password",
                "/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration",
            ],
            "the rotations must be reported (a changed key is still drift)"
        );
        for change in changes {
            for side in ["live", "predicted"] {
                let value = change[side].as_str().unwrap_or_default();
                assert!(
                    value.starts_with("***REDACTED(sha256:") && value.ends_with(")***"),
                    "{} must be a fingerprint, not a payload: {value}",
                    change["path"]
                );
            }
        }
    }

    /// The same annotation embeds a whole document for any kind, so it is redacted for
    /// non-`Secret` objects too.
    #[tokio::test]
    async fn a_last_applied_configuration_annotation_is_redacted_for_every_kind() {
        let applied = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "settings", "namespace": "payments" },
            "data": { "token": "secret-in-desired-annotation" },
        })
        .to_string();

        let config_map = desired(
            "",
            "v1",
            "ConfigMap",
            Some("payments"),
            "settings",
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "settings",
                    "namespace": "payments",
                    "annotations": {
                        "kubectl.kubernetes.io/last-applied-configuration": applied.clone(),
                    },
                },
                "data": { "token": "shared-config-value" },
            }),
        );
        let live = live_map(vec![(
            config_map.key.clone(),
            present(
                json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": "settings",
                        "namespace": "payments",
                        "annotations": {
                            "kubectl.kubernetes.io/last-applied-configuration":
                                r#"{"apiVersion":"v1","kind":"ConfigMap","data":{"token":"secret-in-live-annotation"}}"#,
                        },
                    },
                    "data": { "token": "shared-config-value" },
                }),
                Ownership::OwnedBySelf,
            ),
        )]);

        let fake = Arc::new(FakeDryRun::default());
        let diffs = evaluate(&fake, std::slice::from_ref(&config_map), &[], &live).await;
        assert_eq!(
            diffs[0].status(),
            &DiffStatus::OutOfSync,
            "the changed annotation is still drift"
        );

        let rendered = format!(
            "{:?}{}",
            diffs[0],
            serde_json::to_string(&diffs[0]).expect("json")
        );
        for leaked in ["secret-in-live-annotation", "secret-in-desired-annotation"] {
            assert!(
                !rendered.contains(leaked),
                "{leaked} leaked from the last-applied-configuration annotation: {rendered}"
            );
        }
        // A ConfigMap's own `.data` is *not* redacted (it is part of the diff); only the embedded
        // document is. The one change is therefore the annotation, and its values are fingerprints.
        assert_eq!(
            diffs[0]
                .changes()
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration"],
            "the `.data` value is identical on both sides, so only the annotation may differ"
        );
        for side in [
            &diffs[0].changes()[0].live,
            &diffs[0].changes()[0].predicted,
        ] {
            assert!(
                side.as_ref()
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.starts_with("***REDACTED(sha256:")),
                "the embedded document must be a fingerprint: {side:?}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Live `kind` smoke test (ignored by default; see `make test-integration`)
    // ---------------------------------------------------------------------

    /// T07.1 verification against a **real** cluster: API-defaulted fields produce zero diff and
    /// a field owned by another manager produces a structured [`FieldConflict`].
    ///
    /// Ignored by default and guarded by a `kind-` context assertion, so it can never touch a
    /// shared cluster: `kubectl config use-context kind-ferriscd-dev` first.
    #[tokio::test]
    #[ignore = "requires a live `kind` cluster (make kind-up); asserts the kubectl context starts with `kind-`"]
    async fn live_kind_defaulted_fields_and_foreign_manager_conflicts() {
        use std::process::Command;

        // Safety rail (AGENTS.md): never run a live test against a non-`kind` context.
        let output = Command::new("kubectl")
            .args(["config", "current-context"])
            .output()
            .expect("kubectl must be installed for the live kind test");
        let context = String::from_utf8(output.stdout).expect("context is utf-8");
        assert!(
            context.trim().starts_with("kind-"),
            "refusing to run against the non-kind context '{context}'"
        );

        crate::impersonation::ensure_crypto_provider();
        let client = kube::Client::try_default()
            .await
            .expect("kubeconfig must point at the kind cluster");
        let discovery = DiscoveryCache::new(client.clone());
        let config_map_key = key("", "ConfigMap", Some("default"), "ferriscd-diff-smoke");

        // Create the ConfigMap as *another* Server-Side Apply manager, so it owns `data.owner`.
        // Only apply-managed fields produce `409 Conflict`, so a client-side create would not
        // reproduce the real HPA/`kubectl apply` situation.
        let config_maps: Api<DynamicObject> = Api::namespaced_with(
            client.clone(),
            "default",
            &api_resource("", "v1", "ConfigMap"),
        );
        // Clean up any leftover smoke ConfigMap from a previously aborted run.
        let _ = config_maps
            .delete("ferriscd-diff-smoke", &kube::api::DeleteParams::default())
            .await;
        let initial_manifest = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "ferriscd-diff-smoke", "namespace": "default" },
            "data": { "owner": "kubectl" },
        });
        let created = config_maps
            .patch(
                "ferriscd-diff-smoke",
                &PatchParams::apply("kubectl-client-side-apply"),
                &Patch::Apply(initial_manifest.clone()),
            )
            .await
            .expect("the smoke-test ConfigMap must be created");

        // (1) A desired object identical to live (the API server defaulted nothing else here)
        //     must produce zero diff.
        let created_json = serde_json::to_value(&created).expect("serialize live ConfigMap");
        let live = live_map(vec![(
            config_map_key.clone(),
            present(created_json, Ownership::OwnedBySelf),
        )]);
        let matching = desired(
            "",
            "v1",
            "ConfigMap",
            Some("default"),
            "ferriscd-diff-smoke",
            initial_manifest.clone(),
        );
        let evaluator = DryRunEvaluator::new(client.clone(), discovery);
        let diffs = evaluator
            .evaluate(
                std::slice::from_ref(&matching),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect("the dry-run must succeed");
        assert_eq!(
            diffs[0].status(),
            &DiffStatus::Synced,
            "API-defaulted fields must produce zero diff: {:?}",
            diffs[0].changes()
        );

        // (2) Changing a field another manager owns must be reported as a structured conflict.
        let mut conflicting = initial_manifest;
        conflicting["data"]["owner"] = json!("ferriscd");
        let conflicting = desired(
            "",
            "v1",
            "ConfigMap",
            Some("default"),
            "ferriscd-diff-smoke",
            conflicting,
        );
        let diffs = evaluator
            .evaluate(
                std::slice::from_ref(&conflicting),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect("a conflict must not be an error");
        assert_eq!(diffs[0].status(), &DiffStatus::OutOfSync);
        assert!(
            diffs[0].conflicts().iter().any(|conflict| conflict
                .manager
                .as_deref()
                .is_some_and(|manager| manager.contains("kubectl"))),
            "the conflicting manager must be named: {:?}",
            diffs[0].conflicts()
        );

        // (3) An `ignoreDifferences` rule must remove an HPA-style difference cleanly: the same
        //     field manager applied `data.tuning`, so the dry-run predicts the *new* value
        //     (no conflict) and only the comparison decides.
        let tuned_manifest = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "ferriscd-diff-smoke", "namespace": "default" },
            "data": { "tuning": "a" },
        });
        let tuned = config_maps
            .patch(
                "ferriscd-diff-smoke",
                &PatchParams::apply("ferriscd"),
                &Patch::Apply(tuned_manifest.clone()),
            )
            .await
            .expect("applying the tuned key as `ferriscd` must succeed");
        let tuned_json = serde_json::to_value(&tuned).expect("serialize tuned ConfigMap");
        let live = live_map(vec![(
            config_map_key.clone(),
            present(tuned_json, Ownership::OwnedBySelf),
        )]);
        let mut retuned = tuned_manifest;
        retuned["data"]["tuning"] = json!("b");
        let retuned = desired(
            "",
            "v1",
            "ConfigMap",
            Some("default"),
            "ferriscd-diff-smoke",
            retuned,
        );

        let strict = evaluator
            .evaluate(
                std::slice::from_ref(&retuned),
                &[],
                &live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect("the dry-run must succeed");
        assert_eq!(
            strict[0].status(),
            &DiffStatus::OutOfSync,
            "without an ignore rule the retuned key is real drift"
        );

        let ignore_rules =
            IgnoreRuleSet::from_ignore_differences(&[ferriscd_crd::IgnoreDifference {
                kind: "ConfigMap".to_owned(),
                name: Some("ferriscd-diff-smoke".to_owned()),
                namespace: Some("default".to_owned()),
                json_pointers: vec!["/data/tuning".to_owned()],
                ..ferriscd_crd::IgnoreDifference::default()
            }]);
        let ignored = evaluator
            .evaluate(std::slice::from_ref(&retuned), &[], &live, &ignore_rules)
            .await
            .expect("the dry-run must succeed");
        assert_eq!(
            ignored[0].status(),
            &DiffStatus::Synced,
            "ignoreDifferences must remove the HPA-style field: {:?}",
            ignored[0].changes()
        );

        // (4) T07.1 verification (3) / finding C3: a brand-new CRD and its custom resource in the
        //     same commit must not error in the diff phase. The CRD is not in the cluster, so
        //     discovery cannot resolve the CR's kind either — and neither is dry-run at all.
        let crd_key = key(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.diff-smoke.ferriscd.io",
        );
        let crd = desired(
            "apiextensions.k8s.io",
            "v1",
            "CustomResourceDefinition",
            None,
            "widgets.diff-smoke.ferriscd.io",
            json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.diff-smoke.ferriscd.io" },
                "spec": {
                    "group": "diff-smoke.ferriscd.io",
                    "scope": "Namespaced",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                    },
                    "versions": [ {
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": { "openAPIV3Schema": {
                            "type": "object",
                            "properties": { "spec": {
                                "type": "object",
                                "properties": { "size": { "type": "integer" } },
                            } },
                        } },
                    } ],
                },
            }),
        );
        let widget_key = key(
            "diff-smoke.ferriscd.io",
            "Widget",
            Some("default"),
            "brand-new",
        );
        let widget = desired(
            "diff-smoke.ferriscd.io",
            "v1",
            "Widget",
            Some("default"),
            "brand-new",
            json!({
                "apiVersion": "diff-smoke.ferriscd.io/v1",
                "kind": "Widget",
                "metadata": { "name": "brand-new", "namespace": "default" },
                "spec": { "size": 3 },
            }),
        );
        let brand_new_live = live_map(vec![
            (crd_key.clone(), LiveState::Missing),
            // The CR's kind does not exist until the CRD is established: the live pass defers it.
            (widget_key.clone(), LiveState::DeferredPendingCrd),
        ]);
        let brand_new = evaluator
            .evaluate(
                &[crd, widget],
                &[],
                &brand_new_live,
                &IgnoreRuleSet::default(),
            )
            .await
            .expect("a brand-new CRD + CR must never fail the diff phase");
        assert_eq!(brand_new.len(), 2);
        for diff in &brand_new {
            assert_eq!(
                diff.status(),
                &DiffStatus::Missing,
                "{} must be Missing (apply it), never an error",
                diff.key()
            );
        }

        // Cleanup.
        config_maps
            .delete("ferriscd-diff-smoke", &kube::api::DeleteParams::default())
            .await
            .expect("cleanup must succeed");
    }
}

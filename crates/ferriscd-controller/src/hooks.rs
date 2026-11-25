//! Lifecycle-hook **execution** (`T10.3`, `T10.4`).
//!
//! [`ferriscd_engine::graph::hooks`] owns the pure half: which rendered resources are hooks, which
//! phases they run in, and which deletion policy applies. This module owns the impure half, and it
//! is deliberately the *only* place in the controller that creates or deletes a hook object.
//!
//! ```text
//! operationState.activeHooks  ──┐
//! HookPartition (engine)      ──┼──> run_step() ──> HookCluster (create / delete / read health)
//! the current SyncStep        ──┘        │
//!                                       └──> HookRun { records, observed, deleted }
//!                                                 │
//!                            status.operationState.activeHooks (upsert by Hook::id)
//! ```
//!
//! # Why hooks are tracked, not re-applied
//!
//! A hook is created **imperatively** (`Api::create`, so `metadata.generateName` works — finding
//! H2) and is never part of the desired state, `status.inventory` or the pruner's universe. That
//! makes tracking the only thing standing between a requeue and a second database migration: the
//! created object's real name is recorded in `status.operationState.activeHooks`, keyed by the
//! hook's stable [`Hook::id`] (`<source file>#<ordinal>`), because a `generateName` hook has no
//! `metadata.name` to key on. A requeue therefore observes *that* `Job` instead of creating
//! another one.
//!
//! # Deletion policies (`T10.4`)
//!
//! | policy | when the object is deleted |
//! |---|---|
//! | `BeforeHookCreation` (default, named hooks only) | a previous run is deleted **before** the hook is (re)created, and the create waits for `404` |
//! | `HookSucceeded` | as soon as the hook is observed `Healthy` |
//! | `HookFailed` | as soon as the hook is observed `Degraded` |
//!
//! `BeforeHookCreation` never deletes and creates in one pass: `Delete` is asynchronous in
//! Kubernetes, so re-creating immediately answers `409 AlreadyExists` (finding M3). The pass that
//! deleted returns [`HookRun::pending_delete`], and the next pass sees `404` and creates.
//!
//! # Failure semantics
//!
//! A hook that reports `Degraded` is observed as `Degraded`, which makes the wave state machine
//! enter `SyncFail` (`T10.1`). A failing **`SyncFail`** hook can never hang an operation: the
//! machine turns it into the terminal `Failed` phase (`SyncFail hooks did not complete`), so the
//! cleanup path is best-effort by construction.

use std::collections::BTreeMap;

use ferriscd_crd::status::{ActiveHook, HealthStatus, SyncPhase};
use ferriscd_engine::graph::hooks::{Hook, HookDeletePolicy, HookPartition, HookPhase};
use ferriscd_engine::manifest::{DesiredResource, ResourceKey};
use ferriscd_engine::sync::SyncStep;
use futures::future::BoxFuture;
use kube::api::DynamicObject;

use crate::reconcile::ReconcileError;
use crate::sync::DeleteOutcome;

/// The three cluster side effects a hook needs, as a seam.
///
/// Production is the pipeline itself ([`crate::sync::InventorySyncPipeline`], which implements this
/// for its `Applier`/`ClusterStateReader`/`DiscoveryCache`); tests script every verdict, so the
/// hook lifecycle — including the async `404` wait — is provable without a cluster.
pub trait HookCluster: Send + Sync + 'static {
    /// Creates the hook object, returning the object the API server persisted.
    ///
    /// Must be `Api::create` (never a Server-Side Apply): only a create honours
    /// `metadata.generateName`, and a hook is not part of the desired state.
    fn create_hook<'a>(
        &'a self,
        resource: &'a DesiredResource,
    ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>>;

    /// Deletes one hook object.
    ///
    /// `AlreadyGone` means the API server reports `404`/`410`, which is the "safe to re-create"
    /// signal of `BeforeHookCreation`.
    fn delete_hook<'a>(
        &'a self,
        key: &'a ResourceKey,
        version_hint: &'a str,
    ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>>;

    /// Reads one hook object and evaluates its health (`None` when it no longer exists).
    fn hook_health<'a>(
        &'a self,
        key: &'a ResourceKey,
        version_hint: &'a str,
    ) -> BoxFuture<'a, Result<Option<HealthStatus>, ReconcileError>>;
}

/// What running the hooks of one step produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookRun {
    /// Records to upsert into `status.operationState.activeHooks` (keyed by [`Hook::id`]).
    pub records: Vec<ActiveHook>,
    /// Health observed for each *created* hook object, keyed by its live [`ResourceKey`].
    ///
    /// The caller merges these into the step's health set (`T10.1`): a `ferriscd.io/hook: Sync`
    /// `Job` that is still `Progressing` must keep its wave open (finding M-2).
    pub observed: BTreeMap<ResourceKey, HealthStatus>,
    /// Names of hook objects whose delete this pass confirmed (metrics/log seam).
    pub deleted: Vec<String>,
    /// Number of hook objects created this pass.
    pub created: usize,
    /// A named hook whose previous run is still being deleted (`BeforeHookCreation`).
    ///
    /// The step must requeue instead of creating: the delete is asynchronous (finding M3). Its
    /// presence also means "the phase is not satisfied yet", which is what the caller reports.
    pub pending_delete: Option<String>,
}

impl HookRun {
    /// Returns whether the phase made progress that the operator should see in a log line.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.records.is_empty() && self.deleted.is_empty() && self.pending_delete.is_none()
    }
}

/// What one hook pass produced, **including** the records accumulated before a failure.
///
/// The partial run is not an afterthought: the record of a hook created before the error is the
/// only thing that keeps the retry from creating a second `generateName` object (a second database
/// migration, finding H-NEW). Returning the error alone would throw that record away, so the caller
/// must merge [`Self::run`] into `status.operationState.activeHooks` *before* it looks at
/// [`Self::error`].
#[derive(Debug, Default)]
pub struct HookStep {
    /// The records, observed health and confirmed deletes, up to the failure (or the whole pass).
    pub run: HookRun,
    /// The API/policy failure that stopped the pass, if any.
    pub error: Option<ReconcileError>,
}

/// The hooks that belong to one step, in execution order.
///
/// * `PreSync` / `PostSync` / `SyncFail` own *every* hook of that phase, sorted by wave (the
///   partition already sorted them by `(wave, tier, key)`).
/// * `Sync` owns only the hooks that share the step's wave number: a `Sync` hook runs *inside* its
///   wave, so wave `-1`'s hooks must not run while wave `0` is being applied.
/// * The terminal phases own no hooks at all.
#[must_use]
pub fn hooks_for_step(partition: &HookPartition, step: SyncStep) -> Vec<&Hook> {
    let Some(phase) = hook_phase(step.phase) else {
        return Vec::new();
    };
    partition
        .hooks_in(phase)
        .into_iter()
        .filter(|hook| phase != HookPhase::Sync || hook.wave() == step.wave)
        .collect()
}

/// Maps a wire [`SyncPhase`] onto the annotation [`HookPhase`] it runs hooks for.
#[must_use]
pub const fn hook_phase(phase: SyncPhase) -> Option<HookPhase> {
    match phase {
        SyncPhase::PreSync => Some(HookPhase::PreSync),
        SyncPhase::Sync => Some(HookPhase::Sync),
        SyncPhase::PostSync => Some(HookPhase::PostSync),
        SyncPhase::SyncFail => Some(HookPhase::SyncFail),
        SyncPhase::Succeeded | SyncPhase::Failed => None,
    }
}

/// Runs the hooks of `step`: create what is missing, observe what is tracked, reap per policy.
///
/// `tracked` is `status.operationState.activeHooks` as persisted by the previous pass; `records`
/// on the result must be upserted into it (never appended blindly: [`ActiveHook::hook_id`] is the
/// identity).
///
/// A failure never discards what the pass already did: [`HookStep::run`] carries the records of
/// every hook created before the error, and the caller persists them (finding H-NEW).
///
/// A *hook verdict* is never an error: a `Degraded` hook is data that the state machine turns into
/// `SyncFail`; only an API/policy failure lands in [`HookStep::error`].
pub async fn run_step(
    cluster: &dyn HookCluster,
    step: SyncStep,
    partition: &HookPartition,
    tracked: &[ActiveHook],
) -> HookStep {
    let mut run = HookRun::default();
    // The fallible body writes into `run` as it goes, so a `?` never throws the partial result away.
    let error = run_step_into(&mut run, cluster, step, partition, tracked)
        .await
        .err();
    HookStep { run, error }
}

/// The fallible body of [`run_step`]: every `?` is a cluster call that stops the pass.
async fn run_step_into(
    run: &mut HookRun,
    cluster: &dyn HookCluster,
    step: SyncStep,
    partition: &HookPartition,
    tracked: &[ActiveHook],
) -> Result<(), ReconcileError> {
    let Some(phase) = hook_phase(step.phase) else {
        return Ok(());
    };

    for hook in hooks_for_step(partition, step) {
        let version = hook.resource().gvk.version.as_str();
        let existing = tracked.iter().find(|entry| entry.hook_id == hook.id());

        // A hook that already reached `Healthy` is done for this operation: its object may have
        // been reaped by `HookSucceeded` (so a health read would answer `404`) and re-creating it
        // would re-run a migration that already ran.
        if existing.is_some_and(ActiveHook::is_healthy) {
            continue;
        }

        let Some(tracked_hook) = existing else {
            // Not created yet by this operation. Only a hook with an explicit `metadata.name` can
            // collide with a previous run: a `generateName` hook's rendered key carries the prefix
            // (the loader resolves the identity from `metadata.generateName`), so deleting "the
            // hook with that name" would delete nothing and then create — or, worse, delete an
            // object that merely shares the prefix.
            if hook.is_named()
                && !hook.uses_generate_name()
                && hook
                    .delete_policies()
                    .contains(&HookDeletePolicy::BeforeHookCreation)
            {
                // Delete a previous run first, and never create in the same pass: the delete is
                // asynchronous, so an immediate re-create answers `409 AlreadyExists` (finding M3).
                if let DeleteOutcome::Deleted = cluster.delete_hook(hook.key(), version).await? {
                    run.pending_delete = Some(hook.key().name.clone());
                    return Ok(());
                }
            }

            let created = cluster.create_hook(hook.resource()).await?;
            let name = created
                .metadata
                .name
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| ReconcileError::Invalid {
                    message: format!(
                        "{}: the API server created the hook without metadata.name, so the next \
                         reconcile could not track it and would run it again",
                        hook.id()
                    ),
                })?
                .to_owned();
            let key = hook_key(hook, &name);
            run.created = run.created.saturating_add(1);
            // Freshly created: the pass observed it *before* writing, so it is `Progressing` (the
            // `T09.5` rule) — never `Healthy`, which would advance the wave on a Job that has not
            // even started.
            run.observed.insert(key, HealthStatus::Progressing);
            run.records
                .push(record(hook, phase, &name, HealthStatus::Progressing)?);
            continue;
        };

        let name = tracked_hook.generated_name.trim();
        if name.is_empty() {
            return Err(ReconcileError::Invalid {
                message: format!(
                    "{}: status.operationState.activeHooks tracks the hook without a generated \
                     name, so the created object cannot be observed",
                    hook.id()
                ),
            });
        }

        let key = hook_key(hook, name);
        let observed = cluster
            .hook_health(&key, version)
            .await?
            // A hook object that vanished mid-operation (a TTL controller, an operator deleting it)
            // must fail the step instead of waiting for the wave timeout: nothing will bring it
            // back, and a silent 10-minute stall looks like a hung controller.
            .unwrap_or(HealthStatus::Degraded);

        let reap = match observed {
            HealthStatus::Healthy => hook
                .delete_policies()
                .contains(&HookDeletePolicy::HookSucceeded),
            HealthStatus::Degraded => hook
                .delete_policies()
                .contains(&HookDeletePolicy::HookFailed),
            _ => false,
        };
        if reap && let DeleteOutcome::Deleted = cluster.delete_hook(&key, version).await? {
            run.deleted.push(name.to_owned());
        }

        run.observed.insert(key, observed);
        run.records.push(record(hook, phase, name, observed)?);
    }

    Ok(())
}

/// Builds the [`ActiveHook`] record of one run of `hook`.
fn record(
    hook: &Hook,
    phase: HookPhase,
    name: &str,
    health: HealthStatus,
) -> Result<ActiveHook, ReconcileError> {
    hook.active_hook(phase, name, health)
        .ok_or_else(|| ReconcileError::Invalid {
            message: format!(
                "{}: {phase} is not an executable hook phase, so it has no operationState record",
                hook.id()
            ),
        })
}

/// The live [`ResourceKey`] of a created hook object.
///
/// A `generateName` hook's rendered key has an empty name, so the created name is what identifies
/// the object — and it is the version-agnostic GKNN the health read and the delete use.
#[must_use]
pub fn hook_key(hook: &Hook, created_name: &str) -> ResourceKey {
    let mut key = hook.key().clone();
    key.name = created_name.to_owned();
    key
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use ferriscd_crd::annotations;
    use ferriscd_engine::graph::hooks::partition;
    use ferriscd_engine::manifest::GroupVersionKind;
    use serde_json::json;

    use super::*;

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    fn hook_resource(
        kind: &str,
        name: &str,
        generate_name: Option<&str>,
        annotations: &[(&str, &str)],
    ) -> DesiredResource {
        let (group, version) = match kind {
            "Job" => ("batch", "v1"),
            _ => ("", "v1"),
        };
        let api_version = format!("{group}/{version}");
        let mut metadata = json!({ "name": name, "namespace": "payments" });
        if let Some(generate_name) = generate_name {
            metadata["generateName"] = json!(generate_name);
        }
        let map: serde_json::Map<String, serde_json::Value> = annotations
            .iter()
            .map(|(key, value)| ((*key).to_owned(), json!(value)))
            .collect();
        if !map.is_empty() {
            metadata["annotations"] = serde_json::Value::Object(map);
        }

        DesiredResource {
            key: ResourceKey::new(group, kind, Some("payments".to_owned()), name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("valid apiVersion"),
            object: serde_json::from_value(json!({
                "apiVersion": api_version,
                "kind": kind,
                "metadata": metadata,
            }))
            .expect("valid DynamicObject"),
            source_file: format!("{kind}-{name}.yaml"),
        }
    }

    fn hook(name: &str, phases: &str, policies: Option<&str>) -> DesiredResource {
        let mut annotations = vec![(annotations::HOOK, phases)];
        if let Some(policies) = policies {
            annotations.push((annotations::HOOK_DELETE_POLICY, policies));
        }
        hook_resource("Job", name, None, &annotations)
    }

    fn generate_name_hook(generate_name: &str, phases: &str) -> DesiredResource {
        hook_resource(
            "Job",
            "",
            Some(generate_name),
            &[(annotations::HOOK, phases)],
        )
    }

    /// A scripted cluster: records every call and answers from a script.
    #[derive(Default)]
    struct FakeCluster {
        /// Names the create answers with (falls back to `generateName` + a counter).
        next_names: StdMutex<Vec<String>>,
        /// Health verdicts by object name (`None` = the object is gone).
        health: StdMutex<BTreeMap<String, Option<HealthStatus>>>,
        /// Delete verdicts by object name (`AlreadyGone` once a delete consumed the entry).
        present: StdMutex<Vec<String>>,
        creates: StdMutex<Vec<String>>,
        deletes: StdMutex<Vec<String>>,
        health_reads: StdMutex<Vec<String>>,
        /// `generateName` prefixes whose *next* create the API server rejects with a retryable `500`
        /// (each entry is consumed by the failing call, so the retry succeeds).
        fail_creates: StdMutex<Vec<String>>,
    }

    impl FakeCluster {
        fn with_health(self, name: &str, status: Option<HealthStatus>) -> Self {
            self.health.lock().unwrap().insert(name.to_owned(), status);
            self
        }

        fn with_present(self, name: &str) -> Self {
            self.present.lock().unwrap().push(name.to_owned());
            self
        }

        /// The next create of a hook whose `generateName` is `prefix` answers a retryable `500`.
        fn failing_create(self, prefix: &str) -> Self {
            self.fail_creates.lock().unwrap().push(prefix.to_owned());
            self
        }

        fn creates(&self) -> Vec<String> {
            self.creates.lock().unwrap().clone()
        }

        fn deletes(&self) -> Vec<String> {
            self.deletes.lock().unwrap().clone()
        }

        fn health_reads(&self) -> Vec<String> {
            self.health_reads.lock().unwrap().clone()
        }
    }

    impl HookCluster for FakeCluster {
        fn create_hook<'a>(
            &'a self,
            resource: &'a DesiredResource,
        ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
            Box::pin(async move {
                let generated = resource.object.metadata.generate_name.clone();
                if let Some(prefix) = generated.as_deref() {
                    let mut failing = self.fail_creates.lock().unwrap();
                    if let Some(index) = failing.iter().position(|failed| failed == prefix) {
                        failing.remove(index);
                        return Err(transient_api_error());
                    }
                }
                let name = match self.next_names.lock().unwrap().pop() {
                    Some(name) => name,
                    None => generated
                        .clone()
                        .map(|prefix| format!("{prefix}abcde"))
                        .unwrap_or_else(|| resource.key.name.clone()),
                };
                self.creates.lock().unwrap().push(name.clone());
                let mut object = resource.object.clone();
                object.metadata.name = Some(name);
                Ok(object)
            })
        }

        fn delete_hook<'a>(
            &'a self,
            key: &'a ResourceKey,
            _version_hint: &'a str,
        ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>> {
            Box::pin(async move {
                self.deletes.lock().unwrap().push(key.name.clone());
                let mut present = self.present.lock().unwrap();
                if let Some(index) = present.iter().position(|name| *name == key.name) {
                    present.remove(index);
                    return Ok(DeleteOutcome::Deleted);
                }
                Ok(DeleteOutcome::AlreadyGone)
            })
        }

        fn hook_health<'a>(
            &'a self,
            key: &'a ResourceKey,
            _version_hint: &'a str,
        ) -> BoxFuture<'a, Result<Option<HealthStatus>, ReconcileError>> {
            Box::pin(async move {
                self.health_reads.lock().unwrap().push(key.name.clone());
                Ok(self
                    .health
                    .lock()
                    .unwrap()
                    .get(&key.name)
                    .copied()
                    .flatten())
            })
        }
    }

    fn pre_sync_step() -> SyncStep {
        SyncStep::pre_sync()
    }

    /// The API server's `500` (a transient failure the next pass retries).
    fn transient_api_error() -> ReconcileError {
        ReconcileError::Api(kube::Error::Api(
            serde_json::from_value::<kube::core::Status>(json!({
                "status": "Failure",
                "message": "the server is currently unable to handle the request",
                "reason": "InternalError",
                "code": 500,
            }))
            .expect("a valid kube Status")
            .boxed(),
        ))
    }

    /// A pass that is expected to complete: the partial run only matters on the error path.
    fn completed(step: HookStep) -> HookRun {
        assert!(
            step.error.is_none(),
            "the hook pass must not fail: {:?}",
            step.error
        );
        step.run
    }

    // ---------------------------------------------------------------------
    // T10.3: creation, `generateName`, tracking
    // ---------------------------------------------------------------------

    /// Finding H2: a `generateName` hook is created exactly once, and its generated name is what
    /// the following requeues observe — never a second `Job`.
    #[test]
    fn a_generate_name_hook_is_created_once_and_tracked_by_its_generated_name() {
        let partition = partition(vec![generate_name_hook("migrate-", "PreSync")])
            .expect("valid hook partition");
        let cluster = FakeCluster::default().with_health("migrate-abcde", None);

        // Pass 1: nothing tracked yet -> created, and observed as Progressing (not Healthy).
        let first = completed(block_on(run_step(
            &cluster,
            pre_sync_step(),
            &partition,
            &[],
        )));
        assert_eq!(cluster.creates(), vec!["migrate-abcde".to_owned()]);
        assert_eq!(first.created, 1);
        assert_eq!(first.records.len(), 1);
        let record = &first.records[0];
        assert_eq!(record.hook_id, "Job-.yaml#0");
        assert_eq!(record.generated_name, "migrate-abcde");
        assert_eq!(record.phase, SyncPhase::PreSync);
        assert_eq!(record.health, HealthStatus::Progressing);
        assert!(
            first.observed.contains_key(&ResourceKey::new(
                "batch",
                "Job",
                Some("payments".to_owned()),
                "migrate-abcde"
            )),
            "the step sees the created hook as an observed resource"
        );
        assert!(first.pending_delete.is_none());
        assert_eq!(
            cluster.deletes(),
            Vec::<String>::new(),
            "a generateName hook has no previous run to delete"
        );

        // Pass 2: the record survives (it is what a requeue reads) -> observed, never re-created.
        cluster
            .health
            .lock()
            .unwrap()
            .insert("migrate-abcde".to_owned(), Some(HealthStatus::Healthy));
        let second = completed(block_on(run_step(
            &cluster,
            pre_sync_step(),
            &partition,
            &first.records,
        )));
        assert_eq!(
            cluster.creates(),
            vec!["migrate-abcde".to_owned()],
            "a requeue must never create the hook twice"
        );
        assert_eq!(cluster.health_reads(), vec!["migrate-abcde".to_owned()]);
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].health, HealthStatus::Healthy);
        assert_eq!(second.created, 0);
    }

    /// A hook that already reached `Healthy` is never read or created again: its object may have
    /// been reaped by `HookSucceeded`, and re-running a migration is far worse than a stale record.
    #[test]
    fn a_completed_hook_is_never_recreated_or_re_observed() {
        let partition = partition(vec![hook("migrate", "PreSync", Some("HookSucceeded"))])
            .expect("valid hook partition");
        let cluster = FakeCluster::default();
        let tracked = vec![ActiveHook::new(
            SyncPhase::PreSync,
            0,
            "Job-migrate.yaml#0",
            "migrate",
            HealthStatus::Healthy,
        )];

        let run = completed(block_on(run_step(
            &cluster,
            pre_sync_step(),
            &partition,
            &tracked,
        )));
        assert!(run.is_noop(), "{run:?}");
        assert_eq!(cluster.creates(), Vec::<String>::new());
        assert_eq!(cluster.health_reads(), Vec::<String>::new());
        assert_eq!(cluster.deletes(), Vec::<String>::new());
    }

    #[test]
    fn pre_sync_hooks_run_in_wave_order_and_sync_fail_hooks_only_in_their_phase() {
        let partition = partition(vec![
            hook_resource(
                "Job",
                "smoke",
                None,
                &[
                    (annotations::HOOK, "PreSync"),
                    (annotations::SYNC_WAVE, "1"),
                ],
            ),
            hook_resource(
                "Job",
                "migrate",
                None,
                &[
                    (annotations::HOOK, "PreSync"),
                    (annotations::SYNC_WAVE, "-1"),
                ],
            ),
            hook("alert", "SyncFail", None),
        ])
        .expect("valid hook partition");

        assert_eq!(
            hooks_for_step(&partition, pre_sync_step())
                .iter()
                .map(|hook| hook.key().name.clone())
                .collect::<Vec<_>>(),
            vec!["migrate".to_owned(), "smoke".to_owned()],
            "T10.3: PreSync hooks run sorted by wave"
        );
        assert_eq!(
            hooks_for_step(&partition, SyncStep::sync_fail(0))
                .iter()
                .map(|hook| hook.key().name.clone())
                .collect::<Vec<_>>(),
            vec!["alert".to_owned()]
        );
        assert!(hooks_for_step(&partition, SyncStep::sync(0)).is_empty());
        assert!(hooks_for_step(&partition, SyncStep::post_sync()).is_empty());
        assert!(
            hooks_for_step(&partition, SyncStep::new(SyncPhase::Succeeded, 0)).is_empty(),
            "a terminal phase owns no hooks"
        );
        assert!(
            hooks_for_step(&partition, SyncStep::new(SyncPhase::Failed, 0)).is_empty(),
            "a terminal phase owns no hooks"
        );
    }

    /// Finding M-2: a `ferriscd.io/hook: Sync` hook belongs to the wave it shares a number with,
    /// and to no other wave.
    #[test]
    fn sync_hooks_belong_to_their_own_wave_only() {
        let partition = partition(vec![
            hook_resource(
                "Job",
                "inline",
                None,
                &[(annotations::HOOK, "Sync"), (annotations::SYNC_WAVE, "0")],
            ),
            hook_resource(
                "Job",
                "early",
                None,
                &[(annotations::HOOK, "Sync"), (annotations::SYNC_WAVE, "-1")],
            ),
        ])
        .expect("valid hook partition");

        assert_eq!(
            hooks_for_step(&partition, SyncStep::sync(-1))
                .iter()
                .map(|hook| hook.key().name.clone())
                .collect::<Vec<_>>(),
            vec!["early".to_owned()]
        );
        assert_eq!(
            hooks_for_step(&partition, SyncStep::sync(0))
                .iter()
                .map(|hook| hook.key().name.clone())
                .collect::<Vec<_>>(),
            vec!["inline".to_owned()]
        );
        assert!(hooks_for_step(&partition, SyncStep::sync(1)).is_empty());
    }

    // ---------------------------------------------------------------------
    // T10.4: delete policies
    // ---------------------------------------------------------------------

    /// Finding M3: `BeforeHookCreation` deletes the previous run and *does not* create in the same
    /// pass; the next pass sees `404` and creates.
    #[test]
    fn before_hook_creation_deletes_then_waits_for_404_before_recreating() {
        let partition =
            partition(vec![hook("migrate", "PreSync", None)]).expect("valid hook partition");
        let cluster = FakeCluster::default()
            .with_present("migrate")
            .with_health("migrate", None);

        // Pass 1: the previous run exists -> deleted, nothing created.
        let first = completed(block_on(run_step(
            &cluster,
            pre_sync_step(),
            &partition,
            &[],
        )));
        assert_eq!(cluster.deletes(), vec!["migrate".to_owned()]);
        assert_eq!(
            cluster.creates(),
            Vec::<String>::new(),
            "creating in the same pass as the delete answers 409 AlreadyExists (finding M3)"
        );
        assert_eq!(first.pending_delete.as_deref(), Some("migrate"));
        assert!(first.records.is_empty());
        assert!(first.observed.is_empty(), "the phase is not satisfied yet");

        // Pass 2: the API server now reports 404 -> the hook is created.
        let second = completed(block_on(run_step(
            &cluster,
            pre_sync_step(),
            &partition,
            &[],
        )));
        assert_eq!(second.pending_delete, None);
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].generated_name, "migrate");
        assert_eq!(second.records[0].health, HealthStatus::Progressing);
        assert_eq!(cluster.creates(), vec!["migrate".to_owned()]);
        assert_eq!(
            cluster.deletes().len(),
            2,
            "the first pass deleted and the second confirmed the object was gone"
        );
    }

    #[test]
    fn hook_succeeded_deletes_the_job_once_it_is_healthy() {
        let partition = partition(vec![hook("smoke", "PostSync", Some("HookSucceeded"))])
            .expect("valid hook partition");
        let cluster = FakeCluster::default()
            .with_present("smoke")
            .with_health("smoke", Some(HealthStatus::Healthy));
        let tracked = vec![ActiveHook::new(
            SyncPhase::PostSync,
            0,
            "Job-smoke.yaml#0",
            "smoke",
            HealthStatus::Progressing,
        )];

        let run = completed(block_on(run_step(
            &cluster,
            SyncStep::post_sync(),
            &partition,
            &tracked,
        )));
        assert_eq!(cluster.deletes(), vec!["smoke".to_owned()]);
        assert_eq!(run.deleted, vec!["smoke".to_owned()]);
        assert_eq!(run.records.len(), 1);
        assert_eq!(
            run.records[0].health,
            HealthStatus::Healthy,
            "the record stays Healthy so the reaped object is never re-created"
        );
        assert_eq!(
            run.observed.values().copied().collect::<Vec<_>>(),
            vec![HealthStatus::Healthy],
            "the phase is satisfied by the hook that just completed"
        );
    }

    #[test]
    fn hook_failed_deletes_the_job_once_it_is_degraded() {
        let partition = partition(vec![hook("alert", "SyncFail", Some("HookFailed"))])
            .expect("valid hook partition");
        let cluster = FakeCluster::default()
            .with_present("alert")
            .with_health("alert", Some(HealthStatus::Degraded));
        let tracked = vec![ActiveHook::new(
            SyncPhase::SyncFail,
            0,
            "Job-alert.yaml#0",
            "alert",
            HealthStatus::Progressing,
        )];

        let run = completed(block_on(run_step(
            &cluster,
            SyncStep::sync_fail(-1),
            &partition,
            &tracked,
        )));
        assert_eq!(run.deleted, vec!["alert".to_owned()]);
        assert_eq!(
            run.observed.values().copied().collect::<Vec<_>>(),
            vec![HealthStatus::Degraded]
        );
        assert_eq!(run.records[0].health, HealthStatus::Degraded);
    }

    #[test]
    fn a_hook_is_kept_when_its_policy_does_not_match_its_verdict() {
        // `HookSucceeded` on a Degraded hook: nothing is deleted (the operator asked to keep it).
        let partition = partition(vec![hook("smoke", "PostSync", Some("HookSucceeded"))])
            .expect("valid hook partition");
        let cluster = FakeCluster::default().with_health("smoke", Some(HealthStatus::Degraded));
        let tracked = vec![ActiveHook::new(
            SyncPhase::PostSync,
            0,
            "Job-smoke.yaml#0",
            "smoke",
            HealthStatus::Progressing,
        )];

        let run = completed(block_on(run_step(
            &cluster,
            SyncStep::post_sync(),
            &partition,
            &tracked,
        )));
        assert_eq!(cluster.deletes(), Vec::<String>::new());
        assert_eq!(
            run.observed.values().copied().collect::<Vec<_>>(),
            vec![HealthStatus::Degraded],
            "a Degraded hook fails the phase (the machine enters SyncFail)"
        );
    }

    // ---------------------------------------------------------------------
    // Failure semantics
    // ---------------------------------------------------------------------

    /// A `SyncFail` hook that itself fails is data, never an error: the state machine turns the
    /// `Degraded` verdict into terminal `Failed`, so a broken cleanup can never hang a sync.
    #[test]
    fn a_degraded_sync_fail_hook_is_reported_as_data_not_an_error() {
        let partition = partition(vec![hook("alert", "SyncFail", None)]).expect("valid hook");
        let cluster = FakeCluster::default().with_health("alert", Some(HealthStatus::Degraded));
        let tracked = vec![ActiveHook::new(
            SyncPhase::SyncFail,
            0,
            "Job-alert.yaml#0",
            "alert",
            HealthStatus::Progressing,
        )];

        let run = completed(block_on(run_step(
            &cluster,
            SyncStep::sync_fail(0),
            &partition,
            &tracked,
        )));
        assert_eq!(run.pending_delete, None);
        assert_eq!(
            run.observed.values().copied().collect::<Vec<_>>(),
            vec![HealthStatus::Degraded]
        );
        assert_eq!(
            cluster.deletes(),
            Vec::<String>::new(),
            "the default policy is BeforeHookCreation, which does not reap on failure"
        );
    }

    /// A tracked hook whose object disappeared must fail the step: waiting for the wave timeout
    /// would look like a hung controller, and nothing will bring the object back.
    #[test]
    fn a_vanished_hook_fails_the_step_instead_of_waiting_for_the_timeout() {
        let partition = partition(vec![hook("migrate", "PreSync", None)]).expect("valid hook");
        let cluster = FakeCluster::default().with_health("migrate", None);
        let tracked = vec![ActiveHook::new(
            SyncPhase::PreSync,
            0,
            "Job-migrate.yaml#0",
            "migrate",
            HealthStatus::Progressing,
        )];

        let run = completed(block_on(run_step(
            &cluster,
            pre_sync_step(),
            &partition,
            &tracked,
        )));
        assert_eq!(
            run.observed.values().copied().collect::<Vec<_>>(),
            vec![HealthStatus::Degraded]
        );
        assert_eq!(run.records[0].health, HealthStatus::Degraded);
    }

    /// **Finding H-NEW:** a step that fails on the *second* hook still reports what it created, so
    /// the caller can persist it and the retry observes hook #1 instead of creating a duplicate
    /// `generateName` object (a second migration).
    #[test]
    fn a_failing_hook_step_keeps_the_records_it_created() {
        let partition = partition(vec![
            hook_resource(
                "Job",
                "",
                Some("seed-"),
                &[
                    (annotations::HOOK, "PreSync"),
                    (annotations::SYNC_WAVE, "-1"),
                ],
            ),
            generate_name_hook("migrate-", "PreSync"),
        ])
        .expect("valid hook partition");
        let cluster = FakeCluster::default()
            .failing_create("migrate-")
            .with_health("seed-abcde", Some(HealthStatus::Progressing));

        // Pass 1: `seed-` is created, the create of `migrate-` fails with a retryable `500`.
        let first = block_on(run_step(&cluster, pre_sync_step(), &partition, &[]));
        let error = first.error.as_ref().expect("the second create must fail");
        assert_eq!(
            error.failure_class(),
            crate::FailureClass::Retryable,
            "a 500 must be retryable: {error:?}"
        );
        assert_eq!(
            cluster.creates(),
            vec!["seed-abcde".to_owned()],
            "only the first hook was created"
        );
        assert_eq!(
            first.run.created, 1,
            "the partial run must not be thrown away by the `?`"
        );
        assert_eq!(first.run.records.len(), 1);
        assert_eq!(first.run.records[0].generated_name, "seed-abcde");
        assert_eq!(first.run.records[0].health, HealthStatus::Progressing);

        // Pass 2: with the records the failed pass persisted, the retry observes `seed-abcde` and
        // creates only the hook that failed — never a second `migrate-*`.
        let second = block_on(run_step(
            &cluster,
            pre_sync_step(),
            &partition,
            &first.run.records,
        ));
        assert!(second.error.is_none(), "{:?}", second.error);
        assert_eq!(
            cluster.creates(),
            vec!["seed-abcde".to_owned(), "migrate-abcde".to_owned()],
            "a retry must create the missing hook once, never a duplicate of the tracked one"
        );
        assert_eq!(second.run.created, 1);
        assert_eq!(
            cluster.health_reads(),
            vec!["seed-abcde".to_owned()],
            "the tracked hook is observed instead of created again"
        );
    }

    #[test]
    fn hook_health_and_delete_target_the_created_name() {
        let partition = partition(vec![generate_name_hook("migrate-", "PreSync")])
            .expect("valid hook partition");
        let hook = hooks_for_step(&partition, pre_sync_step())[0];
        let key = hook_key(hook, "migrate-7f9c2");
        assert_eq!(key.canonical(), "batch/Job/payments/migrate-7f9c2");
        assert_eq!(
            hook.key().canonical(),
            "batch/Job/payments/",
            "the rendered key of a generateName hook has no name to track"
        );
    }

    /// A hook phase without hooks is a no-op that issues no API call at all.
    #[test]
    fn a_phase_without_hooks_touches_no_object() {
        let partition = partition(vec![hook("migrate", "PreSync", None)]).expect("valid hook");
        let cluster = FakeCluster::default();

        let run = completed(block_on(run_step(
            &cluster,
            SyncStep::post_sync(),
            &partition,
            &[],
        )));
        assert!(run.is_noop());
        assert!(cluster.creates().is_empty());
        assert!(cluster.deletes().is_empty());
        assert!(cluster.health_reads().is_empty());
    }

    /// Runs a hook pass to completion.
    ///
    /// The fake cluster answers every call immediately, so this never blocks on I/O: it only drives
    /// the future to `Ready`.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }
}

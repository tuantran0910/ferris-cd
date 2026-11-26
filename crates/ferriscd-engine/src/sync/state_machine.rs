//! Re-entrant, non-blocking sync-operation state machine (`T10.1`).
//!
//! A wave `-1` database-migration `Job` can take minutes. A reconcile worker must **never** sleep
//! on it: blocking would starve every other `Application`, and a pod restart would lose all
//! progress. Instead the progress of a multi-wave sync lives in `Application.status.operationState`
//! (`syncPhase`, `currentWave`, `phaseStartedAt`) and every reconcile *re-derives* the next step
//! from (persisted state, wave schedule, observed health):
//!
//! ```text
//! PreSync -> Sync(wave) -> PostSync -> Succeeded
//!                |
//!                +------> SyncFail -> Failed
//! ```
//!
//! | persisted | observed | next |
//! |---|---|---|
//! | any running step | all resources `Healthy` | the next step of the schedule (`Execute`) |
//! | any running step | some resource `Progressing`/`Missing`/`Unknown` | same step (`Wait`, requeue hint) |
//! | any running step | some expected resource not observed yet (nothing, or a partial wave) | same step (`Execute`, apply is idempotent) |
//! | any running step | any resource `Degraded` | `SyncFail` (hooks), then `Failed` |
//! | any running step | step or operation elapsed >= timeout | `SyncFail`, then `Failed` |
//! | `SyncFail` | `SyncFail` hooks done (or failed/absent) | `Failed` |
//! | any running step | the resolved revision moved | `PreSync` of the new revision (`Execute`) |
//!
//! # Why "nothing observed" re-executes
//!
//! A pass observes live state **before** it writes, so on the pass that dispatches a step nothing
//! exists yet. Treating "no observation" as "converging" would deadlock the very first wave;
//! treating it as "execute" is both safe (Server-Side Apply and hook creation are idempotent) and
//! crash-safe (a worker killed after persisting `operationState` but before writing simply writes
//! on the next pass).
//!
//! That re-dispatch is a *property of the same step*, not a new attempt (finding H-1): it keeps the
//! existing `phaseStartedAt` (otherwise every unobserved pass would reset the wave timeout and a
//! wave that is legitimately taking minutes could never time out) and the existing `message`
//! (otherwise the recorded `SyncFail` reason would be replaced by a generic "running SyncFail hooks"
//! before it ever reached `/status`).
//!
//! # `Sync` hooks are part of the wave (finding M-2)
//!
//! A `ferriscd.io/hook: Sync` hook runs next to the wave it shares a number with, so its health
//! belongs in that wave's expected set: the caller must merge it into the [`StepHealth`] it passes
//! for a `Sync` step (using the created name recorded in `status.operationState.activeHooks` for a
//! `generateName` hook). The machine itself only sees the merged set — it cannot read the hook
//! partition, and it must not guess.
//!
//! # Purity
//!
//! [`SyncMachine::step`] takes the persisted state, the schedule, the observed health and the
//! current time, and returns the state to persist plus a [`StepAction`] describing the requeue hint
//! **as data**. It reads no clock, performs no I/O, and never sleeps, so the whole contract is
//! provable hermetically — including "restart" (round-trip the state through `serde_json` between
//! steps) and timeouts (pass a later `now`).
//!
//! `SyncPhase` is re-exported from [`ferriscd_crd::status`] (there is exactly one wire type, so the
//! CRD schema and the machine can never drift apart), mirroring how [`crate::health`] re-exports
//! `HealthStatus`.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use ferriscd_crd::status::{OperationPhase, OperationState};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

use crate::graph::waves::WavePlan;
use crate::health::{HealthStatus, aggregate, truncate_message};
use crate::manifest::ResourceKey;

pub use ferriscd_crd::status::SyncPhase;

/// Requeue delay after every non-terminal pass (the roadmap's `Action::requeue(5s)`).
pub const DEFAULT_REQUEUE_AFTER: Duration = Duration::from_secs(5);

/// Default per-wave/step timeout: a stuck wave becomes `SyncFail` after ten minutes.
pub const DEFAULT_WAVE_TIMEOUT: Duration = Duration::from_secs(600);

/// Default whole-operation timeout (measured from `operationState.startedAt`).
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(600);

/// How many failing resource keys a failure message names before eliding the rest.
pub const MAX_FAILING_KEYS_IN_MESSAGE: usize = 5;

/// Stable rank of a phase, used to order [`SyncStep`]s.
///
/// `PreSync < Sync < PostSync < Succeeded < SyncFail < Failed`, i.e. the graph in the module docs.
#[must_use]
pub const fn phase_rank(phase: SyncPhase) -> u8 {
    match phase {
        SyncPhase::PreSync => 0,
        SyncPhase::Sync => 1,
        SyncPhase::PostSync => 2,
        SyncPhase::Succeeded => 3,
        SyncPhase::SyncFail => 4,
        SyncPhase::Failed => 5,
    }
}

/// Returns whether `phase` is terminal, i.e. the operation has finished and must not be restarted.
///
/// `SyncFail` is **not** terminal: it is the phase that runs the failure hooks before `Failed`.
#[must_use]
pub const fn is_terminal(phase: SyncPhase) -> bool {
    matches!(phase, SyncPhase::Succeeded | SyncPhase::Failed)
}

/// How a wave's resources are judged when deciding whether the wave is done.
///
/// `Suspended` is a judgement call: a `Deployment` with `spec.paused: true` is intentionally idle
/// and will never become `Healthy`, so [`WaveGate::HealthyOnly`] (the roadmap's literal
/// "advance only when all are `Healthy`") makes such a wave fail on the wave timeout.
///
/// The trade-off is exposed as an explicit enum instead of a hidden rule, and is opt-in per
/// [`SyncMachine`]: `v1alpha1` has **no `spec` field** for it, so the controller always uses the
/// default [`WaveGate::HealthyOnly`] unless a caller deliberately overrides it (finding M-8 —
/// this is not a user-configurable setting yet; adding one is a future `spec` change).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WaveGate {
    /// Only `Healthy` satisfies the gate (default; the `T10.1` contract).
    #[default]
    HealthyOnly,
    /// `Healthy` **or** `Suspended` satisfies the gate (paused workloads stay syncable).
    ///
    /// Machine-level opt-in for callers that consider a paused workload settled; it is not
    /// reachable from an `Application` spec in `v1alpha1`.
    HealthyOrSuspended,
}

/// Timeouts that bound a sync operation (`T10.1`).
///
/// Both default to ten minutes, as the roadmap specifies. The operation timeout is the outer bound
/// (measured from `startedAt`); the wave timeout is the inner one (measured from
/// `phaseStartedAt`). A multi-wave rollout that legitimately needs longer must raise the operation
/// timeout, otherwise it fires first even though every single wave was making progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncTimeouts {
    /// Maximum time a single phase/wave may take before the operation enters `SyncFail`.
    pub wave: Duration,
    /// Maximum time the whole operation may take (from `operationState.startedAt`).
    pub operation: Duration,
}

impl Default for SyncTimeouts {
    fn default() -> Self {
        Self {
            wave: DEFAULT_WAVE_TIMEOUT,
            operation: DEFAULT_OPERATION_TIMEOUT,
        }
    }
}

/// One executable step of a sync operation.
///
/// `wave` is only meaningful for [`SyncPhase::Sync`] steps; the other phases are single steps and
/// carry the wave that was in progress when they started (informational).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SyncStep {
    /// The sync phase this step runs.
    pub phase: SyncPhase,
    /// The wave this step applies (`Sync` only).
    pub wave: i32,
}

impl SyncStep {
    /// Builds a step.
    #[must_use]
    pub const fn new(phase: SyncPhase, wave: i32) -> Self {
        Self { phase, wave }
    }

    /// The `PreSync` hook step.
    #[must_use]
    pub const fn pre_sync() -> Self {
        Self::new(SyncPhase::PreSync, 0)
    }

    /// The step that applies `wave`.
    #[must_use]
    pub const fn sync(wave: i32) -> Self {
        Self::new(SyncPhase::Sync, wave)
    }

    /// The `PostSync` hook step.
    #[must_use]
    pub const fn post_sync() -> Self {
        Self::new(SyncPhase::PostSync, 0)
    }

    /// The `SyncFail` hook step.
    #[must_use]
    pub const fn sync_fail(wave: i32) -> Self {
        Self::new(SyncPhase::SyncFail, wave)
    }

    /// The ordering key: `(phase rank, wave)`.
    #[must_use]
    pub const fn rank(&self) -> (u8, i32) {
        (phase_rank(self.phase), self.wave)
    }
}

impl fmt::Display for SyncStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.phase {
            SyncPhase::Sync => write!(f, "Sync(wave {})", self.wave),
            other => write!(f, "{other:?}"),
        }
    }
}

/// The ordered steps of one sync operation: `PreSync`, `Sync(wave)` ascending, `PostSync`.
///
/// `SyncFail` is deliberately not a schedule member: it is a failure path, not progress.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncSchedule {
    steps: Vec<SyncStep>,
}

impl SyncSchedule {
    /// Builds the schedule for the given wave numbers (sorted, de-duplicated, ascending).
    #[must_use]
    pub fn from_waves(waves: impl IntoIterator<Item = i32>) -> Self {
        let mut sorted: Vec<i32> = waves.into_iter().collect();
        sorted.sort_unstable();
        sorted.dedup();

        let mut steps = Vec::with_capacity(sorted.len() + 2);
        steps.push(SyncStep::pre_sync());
        steps.extend(sorted.into_iter().map(SyncStep::sync));
        steps.push(SyncStep::post_sync());
        Self { steps }
    }

    /// Builds the schedule of a wave plan (`T10.2` -> `T10.1` seam).
    #[must_use]
    pub fn from_plan(plan: &WavePlan) -> Self {
        Self::from_waves(plan.wave_numbers())
    }

    /// The steps in execution order.
    #[must_use]
    pub fn steps(&self) -> &[SyncStep] {
        &self.steps
    }

    /// Returns whether the schedule has no steps (never the case for a `from_waves` schedule).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The first step (`PreSync`).
    #[must_use]
    pub fn first(&self) -> Option<SyncStep> {
        self.steps.first().copied()
    }

    /// The wave-bearing (`Sync`) steps in execution order.
    #[must_use]
    pub fn wave_numbers(&self) -> Vec<i32> {
        self.steps
            .iter()
            .filter(|step| step.phase == SyncPhase::Sync)
            .map(|step| step.wave)
            .collect()
    }

    /// The next step strictly after `step` (`None` when `step` is the last one).
    ///
    /// A step that is not part of the schedule — a wave that disappeared from the desired set
    /// between requeues — simply skips forward, so a changed commit never strands an operation.
    #[must_use]
    pub fn next_after(&self, step: SyncStep) -> Option<SyncStep> {
        let rank = step.rank();
        self.steps
            .iter()
            .copied()
            .find(|candidate| candidate.rank() > rank)
    }
}

/// Observed health of exactly the resources belonging to one step.
///
/// Both halves matter: `expected` is what the step *must* bring to `Healthy` (the wave's resources,
/// or the phase's hooks), and `observed` is what the pass saw. A resource that is expected but not
/// observed has not been written yet, which is why [`SyncMachine`] re-dispatches the step instead of
/// waiting for a health read that will never come.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StepHealth {
    expected: Vec<ResourceKey>,
    observed: BTreeMap<ResourceKey, HealthStatus>,
}

impl StepHealth {
    /// No resources at all: the step is trivially satisfied (a phase without hooks).
    ///
    /// Only valid for a **hook** phase. A `Sync` wave with no expected resource is trivially
    /// satisfied too, which would advance the wave without applying anything — use
    /// [`StepHealth::wave`] for a wave step, which rejects that (finding M-1).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The resources of a `Sync` wave, none observed yet: the wiring-facing wave constructor.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `expected` is non-empty. An empty expected set makes the step trivially
    /// satisfied ([`StepHealth::verdict`]), so a mis-wired wave would be "applied" and reported
    /// `Healthy` without a single write (finding M-1). A legitimately empty desired set is a
    /// decision for the caller — it must not start an operation at all — not a wave step.
    #[must_use]
    pub fn wave(expected: impl IntoIterator<Item = ResourceKey>) -> Self {
        let health = Self::unobserved(expected);
        debug_assert!(
            !health.expected.is_empty(),
            "a Sync wave step must expect at least one resource; use StepHealth::empty() only for \
             a hook phase"
        );
        health
    }

    /// The resources of the step, none observed yet (the step has not been written).
    #[must_use]
    pub fn unobserved(expected: impl IntoIterator<Item = ResourceKey>) -> Self {
        let expected: Vec<ResourceKey> = expected.into_iter().collect();
        Self {
            expected,
            observed: BTreeMap::new(),
        }
    }

    /// The resources of the step, all sharing one verdict.
    #[must_use]
    pub fn uniform(expected: impl IntoIterator<Item = ResourceKey>, status: HealthStatus) -> Self {
        let mut health = Self::unobserved(expected);
        for key in health.expected.clone() {
            health.observed.insert(key, status);
        }
        health
    }

    /// The resources of the step together with their observed verdicts.
    #[must_use]
    pub fn new(
        expected: impl IntoIterator<Item = ResourceKey>,
        observed: impl IntoIterator<Item = (ResourceKey, HealthStatus)>,
    ) -> Self {
        Self {
            expected: expected.into_iter().collect(),
            observed: observed.into_iter().collect(),
        }
    }

    /// Records the observed verdict of one resource.
    pub fn observe(&mut self, key: ResourceKey, status: HealthStatus) {
        self.observed.insert(key, status);
    }

    /// The resources this step must bring to `Healthy`.
    #[must_use]
    pub fn expected(&self) -> &[ResourceKey] {
        &self.expected
    }

    /// The observed verdicts.
    #[must_use]
    pub fn observed(&self) -> &BTreeMap<ResourceKey, HealthStatus> {
        &self.observed
    }

    /// Returns whether **any** expected resource has not been observed yet.
    ///
    /// An expected-but-unobserved resource has not been written (a live read of an absent object
    /// yields no observation), so the step must be re-dispatched. Checking only "nothing observed
    /// at all" misses a *partially applied* wave — resource #1 landed, then the pass failed or the
    /// worker was killed before resource #2 — and would wait on health that can never arrive until
    /// the wave timeout. Re-dispatching is safe: Server-Side Apply is idempotent, and the re-dispatch
    /// keeps `phaseStartedAt`, so the wave timeout still bounds the step.
    ///
    /// A step that expects nothing is trivially satisfied, hence never unobserved.
    #[must_use]
    pub fn is_unobserved(&self) -> bool {
        self.expected
            .iter()
            .any(|key| !self.observed.contains_key(key))
    }

    /// The known-failing (`Degraded`) resources, sorted by [`ResourceKey`].
    #[must_use]
    pub fn degraded(&self) -> Vec<ResourceKey> {
        self.observed
            .iter()
            .filter(|(_, status)| **status == HealthStatus::Degraded)
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// The worst verdict across every observed resource (an empty set is `Healthy`).
    #[must_use]
    pub fn aggregate(&self) -> HealthStatus {
        aggregate(self.observed.values().copied())
    }

    /// Evaluates the wave gate.
    fn verdict(&self, gate: WaveGate) -> Gate {
        // A `Degraded` resource fails the step even when the caller passed more observations than
        // the step strictly owns: a broken resource must never be ignored.
        if self
            .observed
            .values()
            .any(|status| *status == HealthStatus::Degraded)
        {
            return Gate::Failed;
        }

        let satisfied = self
            .expected
            .iter()
            .all(|key| match self.observed.get(key) {
                Some(HealthStatus::Healthy) => true,
                Some(HealthStatus::Suspended) => gate == WaveGate::HealthyOrSuspended,
                // Progressing/Missing/Unknown, or not observed at all: keep waiting.
                Some(_) | None => false,
            });
        if satisfied {
            // Also covers the trivially satisfied step (a phase with no hooks).
            return Gate::Satisfied;
        }

        if self.is_unobserved() {
            // Nothing was written yet (or the write was never observed): re-issue the step.
            return Gate::Unobserved;
        }
        Gate::Converging
    }
}

/// Internal gate verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    /// Every expected resource is healthy (or trivially satisfied: no expected resources).
    Satisfied,
    /// At least one expected resource is still converging.
    Converging,
    /// Nothing has been written/observed yet: re-dispatch the step.
    Unobserved,
    /// At least one resource is `Degraded`.
    Failed,
}

/// Why an operation entered `SyncFail`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncFailureReason {
    /// At least one resource of `step` reported `Degraded`.
    Degraded {
        /// The failing step.
        step: SyncStep,
        /// The `Degraded` resources (bounded by the message, not by the vector).
        resources: Vec<ResourceKey>,
    },
    /// `step` exceeded the per-wave timeout.
    WaveTimeout {
        /// The stuck step.
        step: SyncStep,
        /// How long the step had been running.
        elapsed: Duration,
    },
    /// The whole operation exceeded the operation timeout.
    OperationTimeout {
        /// How long the operation had been running.
        elapsed: Duration,
    },
}

impl SyncFailureReason {
    /// Bounded, operator-facing explanation (persisted in `operationState.message`).
    #[must_use]
    pub fn message(&self) -> String {
        let message = match self {
            Self::Degraded { step, resources } => {
                if resources.is_empty() {
                    format!("{step} reported a Degraded resource")
                } else {
                    format!(
                        "{step} failed: {} resource(s) Degraded ({})",
                        resources.len(),
                        describe_keys(resources)
                    )
                }
            }
            Self::WaveTimeout { step, elapsed } => format!(
                "{step} timed out after {}s (wave timeout)",
                elapsed.as_secs()
            ),
            Self::OperationTimeout { elapsed } => {
                format!("operation timed out after {}s", elapsed.as_secs())
            }
        };
        truncate_message(&message)
    }
}

impl fmt::Display for SyncFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

/// Renders up to [`MAX_FAILING_KEYS_IN_MESSAGE`] keys, eliding the rest.
fn describe_keys(keys: &[ResourceKey]) -> String {
    let mut described: Vec<String> = keys
        .iter()
        .take(MAX_FAILING_KEYS_IN_MESSAGE)
        .map(ResourceKey::canonical)
        .collect();
    if keys.len() > MAX_FAILING_KEYS_IN_MESSAGE {
        described.push(format!(
            "and {} more",
            keys.len() - MAX_FAILING_KEYS_IN_MESSAGE
        ));
    }
    described.join(", ")
}

/// What the controller should do with the pass's outcome (a requeue hint, as data).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepAction {
    /// Write the step's resources (apply the wave / create the hooks), then requeue.
    Execute {
        /// The step to write.
        step: SyncStep,
        /// How long the controller should wait before observing again.
        requeue_after: Duration,
    },
    /// Nothing to write: the step has been dispatched and is converging. Requeue and re-observe.
    Wait {
        /// The step being waited on.
        step: SyncStep,
        /// How long the controller should wait before observing again.
        requeue_after: Duration,
    },
    /// The operation is terminal: stop requeueing.
    Finished,
}

impl StepAction {
    /// The step this action refers to (`None` when finished).
    #[must_use]
    pub fn step(&self) -> Option<SyncStep> {
        match self {
            Self::Execute { step, .. } | Self::Wait { step, .. } => Some(*step),
            Self::Finished => None,
        }
    }

    /// The requeue hint (`None` when finished).
    #[must_use]
    pub fn requeue_after(&self) -> Option<Duration> {
        match self {
            Self::Execute { requeue_after, .. } | Self::Wait { requeue_after, .. } => {
                Some(*requeue_after)
            }
            Self::Finished => None,
        }
    }

    /// Returns whether the operation has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        matches!(self, Self::Finished)
    }
}

/// The result of one pure state-machine step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepOutcome {
    /// The state to persist into `status.operationState`.
    pub state: OperationState,
    /// What the controller must do next (including its requeue hint).
    pub action: StepAction,
}

impl StepOutcome {
    /// Returns whether the operation is terminal.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.action.is_finished()
    }

    /// The sync phase of the state to persist.
    #[must_use]
    pub fn phase(&self) -> SyncPhase {
        phase_of(&self.state)
    }

    /// The step the action refers to.
    #[must_use]
    pub fn step(&self) -> Option<SyncStep> {
        self.action.step()
    }
}

/// The pure, re-entrant sync-operation state machine.
///
/// Cheap to construct (three copyable fields) and shareable across threads; the controller may keep
/// one instance per worker for the lifetime of the process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncMachine {
    timeouts: SyncTimeouts,
    wave_gate: WaveGate,
    requeue_after: Duration,
}

impl Default for SyncMachine {
    fn default() -> Self {
        Self {
            timeouts: SyncTimeouts::default(),
            wave_gate: WaveGate::default(),
            requeue_after: DEFAULT_REQUEUE_AFTER,
        }
    }
}

impl SyncMachine {
    /// Builds a machine from explicit tunables.
    #[must_use]
    pub fn new(timeouts: SyncTimeouts, wave_gate: WaveGate, requeue_after: Duration) -> Self {
        Self {
            timeouts,
            wave_gate,
            requeue_after,
        }
    }

    /// The configured timeouts.
    #[must_use]
    pub fn timeouts(&self) -> SyncTimeouts {
        self.timeouts
    }

    /// The configured wave gate.
    #[must_use]
    pub fn wave_gate(&self) -> WaveGate {
        self.wave_gate
    }

    /// The configured requeue hint.
    #[must_use]
    pub fn requeue_after(&self) -> Duration {
        self.requeue_after
    }

    /// The step a persisted state is currently on.
    ///
    /// The controller needs it **before** it steps the machine: the hooks and the live health it
    /// must feed into [`SyncMachine::step`] belong to the persisted step, not to the step the
    /// machine is about to dispatch. Reading it through the same private [`phase_of`] mapping means
    /// the wiring can never disagree with the machine about where an operation resumed.
    #[must_use]
    pub fn current_step(&self, persisted: &OperationState) -> SyncStep {
        SyncStep::new(phase_of(persisted), persisted.current_wave)
    }

    /// Starts an operation at `PreSync` and returns the state to persist.
    ///
    /// The returned action is `Execute(PreSync)`: the controller creates the `PreSync` hooks (or
    /// does nothing when there are none) and requeues.
    #[must_use]
    pub fn start(&self, revision: Option<String>, now: &Time) -> StepOutcome {
        let state = OperationState {
            phase: OperationPhase::Running,
            sync_phase: Some(SyncPhase::PreSync),
            current_wave: 0,
            phase_started_at: Some(now.clone()),
            revision,
            // A new operation starts with no tracked hooks: the previous operation's records are
            // not the hooks of this revision (their deletion policy owns the old objects).
            active_hooks: Vec::new(),
            message: Some(dispatch_message(SyncStep::pre_sync())),
            started_at: now.clone(),
            finished_at: None,
        };
        StepOutcome {
            state,
            action: StepAction::Execute {
                step: SyncStep::pre_sync(),
                requeue_after: self.requeue_after,
            },
        }
    }

    /// Advances one pass. Pure: no clock, no I/O, no sleeps.
    ///
    /// `health` must describe exactly the resources of the persisted step (the wave's resources —
    /// including its `ferriscd.io/hook: Sync` hooks, see the module docs — or the phase's hooks);
    /// see [`StepHealth`].
    ///
    /// `revision` is the revision the caller just resolved for this pass (normally the commit SHA
    /// `spec.source` resolves to, `None` when it could not be resolved). When it differs from
    /// `persisted.revision` the operation is **restarted at `PreSync` for the new revision**
    /// (finding H-3): continuing would judge the already-applied waves of the old commit, skip the
    /// waves of the new one that happen to be "done", and report `Succeeded` for resources that were
    /// never applied. `None` means "unknown this pass" and never triggers a restart, while a state
    /// that recorded **no** revision counts as differing the first time one is resolved (it cannot
    /// prove which commit it is applying, and re-applying from `PreSync` is idempotent).
    #[must_use]
    pub fn step(
        &self,
        persisted: &OperationState,
        schedule: &SyncSchedule,
        health: &StepHealth,
        revision: Option<&str>,
        now: &Time,
    ) -> StepOutcome {
        let phase = phase_of(persisted);
        let step = SyncStep::new(phase, persisted.current_wave);

        // A finished operation is stable: re-running it never resurrects a sync. The stored
        // `phase`/`syncPhase` pair is normalized first, because a hand-patched status can pair a
        // terminal sync phase with `phase: Running` (finding M-3) — a `Running` operation that the
        // controller was told is `Finished` would stay `Running` in `/status` forever.
        if is_terminal(phase) {
            return StepOutcome {
                state: normalize_terminal(persisted, phase),
                action: StepAction::Finished,
            };
        }

        // The desired commit moved while this operation was running (finding H-3). A state that
        // records no revision at all (`v0.2`/legacy, or an operation started before the commit could
        // be resolved) cannot prove it is operating on the commit this pass resolved, so it is
        // restarted too — re-applying from `PreSync` is idempotent, skipping forward is not.
        if let Some(resolved) = revision
            && persisted.revision.as_deref() != Some(resolved)
        {
            return self.restart(persisted, resolved, now);
        }

        if let Some(reason) = self.timeout(persisted, step, now) {
            return self.fail(persisted, &reason, now);
        }

        match health.verdict(self.wave_gate) {
            Gate::Failed => self.fail(
                persisted,
                &SyncFailureReason::Degraded {
                    step,
                    resources: health.degraded(),
                },
                now,
            ),
            Gate::Unobserved => self.dispatch(persisted, step, None, now),
            Gate::Converging => StepOutcome {
                state: persisted.clone(),
                action: StepAction::Wait {
                    step,
                    requeue_after: self.requeue_after,
                },
            },
            Gate::Satisfied => {
                if phase == SyncPhase::SyncFail {
                    // The failure hooks ran (or there were none): the operation is over.
                    return self.finish_failed(persisted, None, now);
                }
                match schedule.next_after(step) {
                    Some(next) => self.dispatch(persisted, next, None, now),
                    None => self.finish_succeeded(persisted, now),
                }
            }
        }
    }

    /// Moves to `step` and returns `Execute` for it.
    ///
    /// A dispatch of the **same** step (the `Unobserved` re-dispatch) keeps the existing
    /// `phaseStartedAt` and `message` (finding H-1): it is the same attempt, not a new one, so it
    /// must neither reset the wave timeout nor overwrite the recorded failure reason. A dispatch of
    /// a *different* step stamps a fresh phase start (the timeout base moves with the step).
    fn dispatch(
        &self,
        persisted: &OperationState,
        step: SyncStep,
        message: Option<String>,
        now: &Time,
    ) -> StepOutcome {
        let mut state = persisted.clone();
        let same_step = phase_of(persisted) == step.phase && persisted.current_wave == step.wave;

        state.phase = OperationPhase::Running;
        state.sync_phase = Some(step.phase);
        state.current_wave = step.wave;
        state.finished_at = None;
        if !same_step || state.phase_started_at.is_none() {
            state.phase_started_at = Some(now.clone());
        }
        state.message = match message {
            Some(message) => Some(message),
            // Re-dispatching the same step keeps whatever the operation already recorded.
            None if same_step => persisted
                .message
                .clone()
                .or_else(|| Some(dispatch_message(step))),
            None => Some(dispatch_message(step)),
        };
        StepOutcome {
            state,
            action: StepAction::Execute {
                step,
                requeue_after: self.requeue_after,
            },
        }
    }

    /// Restarts the operation at `PreSync` for `revision` (finding H-3).
    ///
    /// The operation timeout clock restarts with the revision: the operation now running is the new
    /// commit's, and a commit pushed shortly before the deadline must not fail before its first
    /// wave could converge. Already-applied resources are re-applied idempotently (Server-Side
    /// Apply), `PreSync` hooks re-run, and the tracked hooks of the previous revision are dropped
    /// (their objects are owned by their delete policy, and their rendered `hookId`s may not even
    /// exist in the new commit).
    fn restart(&self, persisted: &OperationState, revision: &str, now: &Time) -> StepOutcome {
        let mut state = persisted.clone();
        let previous = persisted
            .revision
            .clone()
            .unwrap_or_else(|| "<unknown>".to_owned());

        state.phase = OperationPhase::Running;
        state.sync_phase = Some(SyncPhase::PreSync);
        state.current_wave = 0;
        state.phase_started_at = Some(now.clone());
        state.revision = Some(revision.to_owned());
        state.active_hooks.clear();
        state.message = Some(truncate_message(&format!(
            "revision changed from {previous} to {revision} while the operation was running; \
             restarting at PreSync"
        )));
        state.started_at = now.clone();
        state.finished_at = None;
        StepOutcome {
            state,
            action: StepAction::Execute {
                step: SyncStep::pre_sync(),
                requeue_after: self.requeue_after,
            },
        }
    }

    /// Enters `SyncFail` (dispatching its hooks), or `Failed` when already there.
    fn fail(
        &self,
        persisted: &OperationState,
        reason: &SyncFailureReason,
        now: &Time,
    ) -> StepOutcome {
        let phase = phase_of(persisted);
        if phase == SyncPhase::SyncFail {
            // The failure hooks themselves failed or timed out: never let cleanup hang a sync.
            return self.finish_failed(
                persisted,
                Some(format!("SyncFail hooks did not complete ({reason})")),
                now,
            );
        }

        let message = reason.message();
        self.dispatch(
            persisted,
            SyncStep::sync_fail(persisted.current_wave),
            Some(message),
            now,
        )
    }

    /// Terminal success.
    fn finish_succeeded(&self, persisted: &OperationState, now: &Time) -> StepOutcome {
        let mut state = persisted.clone();
        state.phase = OperationPhase::Succeeded;
        state.sync_phase = Some(SyncPhase::Succeeded);
        state.finished_at = Some(now.clone());
        state.message = Some(truncate_message(
            "sync completed: every wave and hook is Healthy",
        ));
        StepOutcome {
            state,
            action: StepAction::Finished,
        }
    }

    /// Terminal failure, keeping the recorded failure reason as the `/status` message.
    fn finish_failed(
        &self,
        persisted: &OperationState,
        note: Option<String>,
        now: &Time,
    ) -> StepOutcome {
        let mut state = persisted.clone();
        state.phase = OperationPhase::Failed;
        state.sync_phase = Some(SyncPhase::Failed);
        state.finished_at = Some(now.clone());
        let message = match (persisted.message.as_deref(), note) {
            (Some(existing), Some(note)) => Some(format!("{existing}; {note}")),
            (Some(existing), None) => Some(existing.to_owned()),
            (None, Some(note)) => Some(note),
            (None, None) => Some("sync failed".to_owned()),
        };
        state.message = message.map(|message| truncate_message(&message));
        StepOutcome {
            state,
            action: StepAction::Finished,
        }
    }

    /// Returns the failure to record when a timeout has elapsed.
    fn timeout(
        &self,
        persisted: &OperationState,
        step: SyncStep,
        now: &Time,
    ) -> Option<SyncFailureReason> {
        let operation_elapsed = elapsed_seconds(now, &persisted.started_at);
        if operation_elapsed >= self.timeouts.operation.as_secs() {
            return Some(SyncFailureReason::OperationTimeout {
                elapsed: Duration::from_secs(operation_elapsed),
            });
        }

        // A pre-Phase-10 state has no `phaseStartedAt`; the operation start is the safe base.
        let base = persisted
            .phase_started_at
            .as_ref()
            .unwrap_or(&persisted.started_at);
        let step_elapsed = elapsed_seconds(now, base);
        if step_elapsed >= self.timeouts.wave.as_secs() {
            return Some(SyncFailureReason::WaveTimeout {
                step,
                elapsed: Duration::from_secs(step_elapsed),
            });
        }
        None
    }
}

/// The message persisted when a step is dispatched.
fn dispatch_message(step: SyncStep) -> String {
    truncate_message(&match step.phase {
        SyncPhase::PreSync => "running PreSync hooks".to_owned(),
        SyncPhase::Sync => format!("applying {}", step),
        SyncPhase::PostSync => "running PostSync hooks".to_owned(),
        SyncPhase::SyncFail => "running SyncFail hooks".to_owned(),
        SyncPhase::Succeeded => "sync completed".to_owned(),
        SyncPhase::Failed => "sync failed".to_owned(),
    })
}

/// Decodes the sync phase of a persisted state.
///
/// `OperationPhase` wins whenever it is terminal, so a hand-patched or half-written status can
/// never resurrect a finished operation. While `Running`, the persisted `syncPhase` decides —
/// `OperationPhase::Running` alone covers `PreSync`, `Sync`, `PostSync`, **and** `SyncFail`.
/// States written before Phase 10 carry no `syncPhase`; a `Running` operation was then applying
/// waves, so it resumes at `Sync(currentWave)`.
fn phase_of(state: &OperationState) -> SyncPhase {
    match state.phase {
        OperationPhase::Succeeded => SyncPhase::Succeeded,
        OperationPhase::Failed | OperationPhase::Error => SyncPhase::Failed,
        OperationPhase::Running => state.sync_phase.unwrap_or(SyncPhase::Sync),
    }
}

/// Whole seconds elapsed between `then` and `now`, saturating at `0` for a backwards clock.
fn elapsed_seconds(now: &Time, then: &Time) -> u64 {
    u64::try_from(now.0.duration_since(then.0).as_secs()).unwrap_or(0)
}

/// Rewrites a terminal state so `phase` and `syncPhase` agree (finding M-3).
///
/// [`phase_of`] can report a terminal sync phase while the stored `phase` is `Running` (a
/// hand-patched or half-written status) or `Error` (an aborted operation). A `Finished` outcome must
/// never leave `/status` saying `Running`, so the terminal branch of [`SyncMachine::step`] normalizes
/// the pair before returning it. `finishedAt` is deliberately left untouched: inventing a timestamp
/// for a state that never recorded one would misreport when the operation finished.
fn normalize_terminal(state: &OperationState, phase: SyncPhase) -> OperationState {
    let (operation_phase, sync_phase) = if phase == SyncPhase::Succeeded {
        (OperationPhase::Succeeded, SyncPhase::Succeeded)
    } else {
        (OperationPhase::Failed, SyncPhase::Failed)
    };
    if state.phase == operation_phase && state.sync_phase == Some(sync_phase) {
        return state.clone();
    }

    let mut normalized = state.clone();
    normalized.phase = operation_phase;
    normalized.sync_phase = Some(sync_phase);
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rfc3339: &str) -> Time {
        Time(rfc3339.parse().expect("valid RFC 3339 timestamp"))
    }

    fn key(kind: &str, name: &str) -> ResourceKey {
        let group = match kind {
            "Deployment" | "StatefulSet" => "apps",
            "Job" => "batch",
            _ => "",
        };
        ResourceKey::new(group, kind, Some("payments".to_owned()), name)
    }

    /// Simulates a controller pod restart: the persisted state survives only through `/status`.
    fn restart(state: &OperationState) -> OperationState {
        let json = serde_json::to_value(state).expect("operationState must serialize");
        serde_json::from_value(json).expect("operationState must deserialize")
    }

    fn execute_step(action: StepAction) -> SyncStep {
        match action {
            StepAction::Execute {
                step,
                requeue_after,
            } => {
                assert_eq!(
                    requeue_after, DEFAULT_REQUEUE_AFTER,
                    "every non-terminal action carries the requeue hint as data"
                );
                step
            }
            other => panic!("expected Execute, got {other:?}"),
        }
    }

    fn wait_step(action: StepAction) -> SyncStep {
        match action {
            StepAction::Wait {
                step,
                requeue_after,
            } => {
                assert_eq!(requeue_after, DEFAULT_REQUEUE_AFTER);
                step
            }
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    fn three_wave_schedule() -> SyncSchedule {
        SyncSchedule::from_waves([1, -1, 0])
    }

    /// One pass that **did not** resolve a revision (`SyncMachine::step` with `revision: None`).
    ///
    /// Most scenarios only care about `(persisted, schedule, health)`, and `None` is exactly the
    /// "this pass knows nothing about the revision" contract: it never restarts the operation. The
    /// revision-change tests below call [`SyncMachine::step`] directly instead.
    fn step(
        machine: &SyncMachine,
        persisted: &OperationState,
        schedule: &SyncSchedule,
        health: &StepHealth,
        now: &Time,
    ) -> StepOutcome {
        machine.step(persisted, schedule, health, None, now)
    }

    #[test]
    fn defaults_are_pinned() {
        let machine = SyncMachine::default();
        assert_eq!(machine.requeue_after(), Duration::from_secs(5));
        assert_eq!(
            machine.timeouts(),
            SyncTimeouts {
                wave: Duration::from_secs(600),
                operation: Duration::from_secs(600),
            }
        );
        assert_eq!(machine.wave_gate(), WaveGate::HealthyOnly);
        assert_eq!(SyncTimeouts::default().wave, DEFAULT_WAVE_TIMEOUT);
        assert_eq!(SyncTimeouts::default().operation, DEFAULT_OPERATION_TIMEOUT);
    }

    #[test]
    fn phase_rank_and_terminal_classification_match_the_documented_graph() {
        let ordered = [
            SyncPhase::PreSync,
            SyncPhase::Sync,
            SyncPhase::PostSync,
            SyncPhase::Succeeded,
            SyncPhase::SyncFail,
            SyncPhase::Failed,
        ];
        for (index, phase) in ordered.iter().enumerate() {
            assert_eq!(phase_rank(*phase), index as u8, "{phase:?}");
        }
        assert!(!is_terminal(SyncPhase::PreSync));
        assert!(!is_terminal(SyncPhase::Sync));
        assert!(!is_terminal(SyncPhase::PostSync));
        assert!(is_terminal(SyncPhase::Succeeded));
        assert!(
            !is_terminal(SyncPhase::SyncFail),
            "SyncFail still runs the failure hooks"
        );
        assert!(is_terminal(SyncPhase::Failed));
    }

    #[test]
    fn the_schedule_is_pre_sync_then_ascending_waves_then_post_sync() {
        let schedule = three_wave_schedule();
        assert_eq!(
            schedule.steps(),
            &[
                SyncStep::pre_sync(),
                SyncStep::sync(-1),
                SyncStep::sync(0),
                SyncStep::sync(1),
                SyncStep::post_sync(),
            ]
        );
        assert_eq!(schedule.wave_numbers(), vec![-1, 0, 1]);
        assert_eq!(schedule.first(), Some(SyncStep::pre_sync()));
        assert_eq!(
            schedule.next_after(SyncStep::pre_sync()),
            Some(SyncStep::sync(-1))
        );
        assert_eq!(
            schedule.next_after(SyncStep::sync(1)),
            Some(SyncStep::post_sync())
        );
        assert_eq!(schedule.next_after(SyncStep::post_sync()), None);

        // Duplicates and unsorted input still yield one ordered schedule.
        assert_eq!(
            SyncSchedule::from_waves([0, -1, 0, 1, -1]).steps(),
            schedule.steps()
        );

        // A schedule with no waves still runs both hook phases.
        let no_waves = SyncSchedule::from_waves(Vec::<i32>::new());
        assert_eq!(
            no_waves.steps(),
            &[SyncStep::pre_sync(), SyncStep::post_sync()]
        );
        assert!(SyncSchedule::default().is_empty());
    }

    #[test]
    fn the_schedule_can_be_built_from_a_wave_plan() {
        let plan = crate::graph::waves::partition(Vec::new()).expect("empty plan");
        assert_eq!(
            SyncSchedule::from_plan(&plan).wave_numbers(),
            Vec::<i32>::new()
        );
    }

    #[test]
    fn step_labels_are_readable() {
        assert_eq!(SyncStep::sync(-1).to_string(), "Sync(wave -1)");
        assert_eq!(SyncStep::pre_sync().to_string(), "PreSync");
        assert_eq!(SyncStep::post_sync().to_string(), "PostSync");
        assert_eq!(SyncStep::sync_fail(3).to_string(), "SyncFail");
    }

    /// The `T10.1` headline contract: a 3-wave rollout resumed from persisted state after every
    /// single pass (i.e. across controller restarts) converges to `Succeeded`.
    #[test]
    fn three_wave_happy_path_survives_a_restart_between_every_pass() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let migration = key("Job", "migrate");
        let api = key("Deployment", "api");
        let smoke = key("Job", "smoke");

        let t0 = at("2026-11-24T12:00:00Z");
        let t1 = at("2026-11-24T12:00:05Z");
        let t2 = at("2026-11-24T12:00:10Z");
        let t3 = at("2026-11-24T12:00:15Z");

        // Pass 1: start -> PreSync is dispatched.
        let started = machine.start(Some("rev-a".to_owned()), &t0);
        assert_eq!(started.phase(), SyncPhase::PreSync);
        assert_eq!(execute_step(started.action), SyncStep::pre_sync());
        let mut state = restart(&started.state);
        assert_eq!(state.phase, OperationPhase::Running);
        assert_eq!(state.current_wave, 0);

        // Pass 2: a PreSync phase without hooks is trivially satisfied -> Sync(-1).
        let outcome = step(&machine, &state, &schedule, &StepHealth::empty(), &t0);
        assert_eq!(execute_step(outcome.action), SyncStep::sync(-1));
        state = restart(&outcome.state);
        assert_eq!(state.sync_phase, Some(SyncPhase::Sync));
        assert_eq!(state.current_wave, -1);

        // Pass 3: wave -1 was never observed (the pass observes before it writes) -> re-dispatch.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::unobserved(vec![migration.clone()]),
            &t1,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync(-1));
        state = restart(&outcome.state);

        // Pass 4: the migration Job is still running -> wait, then observe again.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![migration.clone()], HealthStatus::Progressing),
            &t1,
        );
        assert_eq!(wait_step(outcome.action), SyncStep::sync(-1));
        state = restart(&outcome.state);

        // Pass 5: the migration is Healthy -> wave 0.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![migration], HealthStatus::Healthy),
            &t2,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync(0));
        state = restart(&outcome.state);
        assert_eq!(state.current_wave, 0);

        // Pass 6: wave 0 converges, then wave 1.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![api.clone()], HealthStatus::Healthy),
            &t2,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync(1));
        state = restart(&outcome.state);

        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![smoke], HealthStatus::Healthy),
            &t3,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::post_sync());
        state = restart(&outcome.state);

        // Pass 7: PostSync without hooks -> Succeeded, and the operation is terminal.
        let outcome = step(&machine, &state, &schedule, &StepHealth::empty(), &t3);
        assert!(outcome.is_finished(), "{:?}", outcome.action);
        assert_eq!(outcome.phase(), SyncPhase::Succeeded);
        state = restart(&outcome.state);
        assert_eq!(state.phase, OperationPhase::Succeeded);
        assert_eq!(state.sync_phase, Some(SyncPhase::Succeeded));
        assert_eq!(state.finished_at, Some(t3.clone()));
        assert_eq!(state.revision.as_deref(), Some("rev-a"));
        assert!(state.message.is_some());

        // A finished operation is stable: no requeue, no state churn, no resurrection.
        let again = step(&machine, &state, &schedule, &StepHealth::empty(), &t3);
        assert!(again.is_finished());
        assert_eq!(again.state, state);
        assert_eq!(again.action.requeue_after(), None);
    }

    #[test]
    fn a_progressing_resource_keeps_the_wave_open_until_every_resource_is_healthy() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let api = key("Deployment", "api");
        let service = key("Service", "api");
        let now = at("2026-11-24T12:00:00Z");

        // Park the state machine inside wave 0.
        let mut state = machine.start(None, &now).state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = 0;
        state.phase_started_at = Some(now.clone());

        // One Healthy + one Progressing: the wave must stay open (never "mostly healthy => advance").
        let mixed = StepHealth::new(
            [api.clone(), service.clone()],
            [
                (api.clone(), HealthStatus::Healthy),
                (service.clone(), HealthStatus::Progressing),
            ],
        );
        let outcome = step(&machine, &state, &schedule, &mixed, &now);
        assert_eq!(wait_step(outcome.action), SyncStep::sync(0));

        // Missing / Unknown also keep the wave open.
        for status in [HealthStatus::Missing, HealthStatus::Unknown] {
            let outcome = step(
                &machine,
                &state,
                &schedule,
                &StepHealth::uniform([api.clone(), service.clone()], status),
                &now,
            );
            assert_eq!(wait_step(outcome.action), SyncStep::sync(0), "{status:?}");
        }

        // Both Healthy: advance to wave 1.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform([api.clone(), service], HealthStatus::Healthy),
            &now,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync(1));
        state = outcome.state;
        assert_eq!(state.current_wave, 1);
        assert_eq!(
            state.phase_started_at,
            Some(now.clone()),
            "the wave timeout base moves with the wave"
        );
    }

    #[test]
    fn a_degraded_wave_enters_sync_fail_then_failed() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let api = key("Deployment", "api");
        let now = at("2026-11-24T12:00:00Z");

        let mut state = machine.start(Some("rev-b".to_owned()), &now).state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = 0;
        state.phase_started_at = Some(now.clone());

        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![api.clone()], HealthStatus::Degraded),
            &now,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync_fail(0));
        assert_eq!(outcome.phase(), SyncPhase::SyncFail);
        assert_eq!(outcome.state.phase, OperationPhase::Running);
        let message = outcome.state.message.clone().expect("message");
        assert!(
            message.contains("apps/Deployment/payments/api") && message.contains("Degraded"),
            "the failure message must name the resource and the verdict: {message}"
        );
        state = restart(&outcome.state);

        // SyncFail without failure hooks is trivially satisfied -> Failed (terminal).
        let outcome = step(&machine, &state, &schedule, &StepHealth::empty(), &now);
        assert!(outcome.is_finished());
        assert_eq!(outcome.state.phase, OperationPhase::Failed);
        assert_eq!(outcome.state.sync_phase, Some(SyncPhase::Failed));
        assert_eq!(outcome.state.finished_at, Some(now.clone()));
        assert!(
            outcome
                .state
                .message
                .as_deref()
                .is_some_and(|message| message.contains("Degraded")),
            "the failure reason must survive into /status: {:?}",
            outcome.state.message
        );

        // Terminal failure is stable.
        let again = step(
            &machine,
            &outcome.state,
            &schedule,
            &StepHealth::empty(),
            &now,
        );
        assert!(again.is_finished());
        assert_eq!(again.state, outcome.state);
    }

    #[test]
    fn failing_sync_fail_hooks_never_hang_the_operation() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let alert = key("Job", "alert");
        let now = at("2026-11-24T12:00:00Z");

        let mut state = machine.start(None, &now).state;
        state.sync_phase = Some(SyncPhase::SyncFail);
        state.current_wave = -1;
        state.phase_started_at = Some(now.clone());
        state.message = Some("wave -1 failed: 1 resource(s) Degraded".to_owned());

        // The failure hook is dispatched first (it must get the chance to run).
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::unobserved(vec![alert.clone()]),
            &now,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync_fail(-1));

        // Waiting on it keeps the original failure message intact.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![alert.clone()], HealthStatus::Progressing),
            &now,
        );
        assert_eq!(wait_step(outcome.action), SyncStep::sync_fail(-1));
        assert_eq!(
            outcome.state.message.as_deref(),
            Some("wave -1 failed: 1 resource(s) Degraded")
        );

        // A Degraded failure hook still ends the operation (best-effort cleanup).
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![alert], HealthStatus::Degraded),
            &now,
        );
        assert!(outcome.is_finished());
        assert_eq!(outcome.state.phase, OperationPhase::Failed);
        assert!(
            outcome
                .state
                .message
                .as_deref()
                .is_some_and(|message| message.contains("SyncFail hooks did not complete")),
            "{:?}",
            outcome.state.message
        );
    }

    #[test]
    fn a_stuck_wave_becomes_sync_fail_on_the_wave_timeout() {
        let machine = SyncMachine::new(
            SyncTimeouts {
                wave: Duration::from_secs(600),
                // Long enough that the operation timeout cannot fire first in this scenario.
                operation: Duration::from_secs(3600),
            },
            WaveGate::HealthyOnly,
            DEFAULT_REQUEUE_AFTER,
        );
        let schedule = three_wave_schedule();
        let migration = key("Job", "migrate");

        let mut state = machine.start(None, &at("2026-11-24T12:00:00Z")).state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = -1;
        state.phase_started_at = Some(at("2026-11-24T12:05:00Z"));

        // One second short of the wave timeout: still waiting.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![migration.clone()], HealthStatus::Progressing),
            &at("2026-11-24T12:14:59Z"),
        );
        assert_eq!(wait_step(outcome.action), SyncStep::sync(-1));

        // At the timeout: SyncFail (which then runs the failure hooks and finishes as Failed).
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform(vec![migration], HealthStatus::Progressing),
            &at("2026-11-24T12:15:00Z"),
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync_fail(-1));
        assert_eq!(outcome.phase(), SyncPhase::SyncFail);
        let message = outcome.state.message.clone().expect("message");
        assert!(message.contains("timed out after 600s"), "{message}");
        assert!(message.contains("Sync(wave -1)"), "{message}");

        state = outcome.state;
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::empty(),
            &at("2026-11-24T12:15:05Z"),
        );
        assert!(outcome.is_finished());
        assert_eq!(outcome.phase(), SyncPhase::Failed);
    }

    #[test]
    fn a_stuck_operation_becomes_sync_fail_on_the_operation_timeout() {
        let machine = SyncMachine::new(
            SyncTimeouts {
                wave: Duration::from_secs(3600),
                operation: Duration::from_secs(600),
            },
            WaveGate::HealthyOnly,
            DEFAULT_REQUEUE_AFTER,
        );
        let schedule = three_wave_schedule();

        let mut state = machine.start(None, &at("2026-11-24T12:00:00Z")).state;
        state.sync_phase = Some(SyncPhase::PostSync);
        state.current_wave = 0;
        // A freshly restarted wave is nowhere near its own timeout; only the operation elapsed.
        state.phase_started_at = Some(at("2026-11-24T12:09:00Z"));

        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::uniform([key("Job", "smoke")], HealthStatus::Progressing),
            &at("2026-11-24T12:10:00Z"),
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync_fail(0));
        assert_eq!(outcome.phase(), SyncPhase::SyncFail);
        assert!(
            outcome
                .state
                .message
                .as_deref()
                .is_some_and(|message| message.contains("operation timed out after 600s")),
            "{:?}",
            outcome.state.message
        );
    }

    #[test]
    fn suspended_resources_follow_the_configured_wave_gate() {
        let strict = SyncMachine::default();
        let relaxed = SyncMachine::new(
            SyncTimeouts::default(),
            WaveGate::HealthyOrSuspended,
            DEFAULT_REQUEUE_AFTER,
        );
        let schedule = three_wave_schedule();
        let api = key("Deployment", "api");
        let now = at("2026-11-24T12:00:00Z");

        let mut state = strict.start(None, &now).state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = 0;
        state.phase_started_at = Some(now.clone());
        let paused = StepHealth::uniform(vec![api], HealthStatus::Suspended);

        // The roadmap's literal contract: only Healthy advances.
        let outcome = step(&strict, &state, &schedule, &paused, &now);
        assert_eq!(wait_step(outcome.action), SyncStep::sync(0));

        // The opt-in production policy advances (a paused Deployment will never become Healthy).
        let outcome = step(&relaxed, &state, &schedule, &paused, &now);
        assert_eq!(execute_step(outcome.action), SyncStep::sync(1));
    }

    #[test]
    fn a_legacy_state_without_a_sync_phase_resumes_at_its_wave() {
        // A status written by `v0.2`/Phase 07 carries `phase: Running` + `currentWave` only.
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let now = at("2026-11-24T12:00:00Z");
        let legacy = restart(&OperationState {
            phase: OperationPhase::Running,
            sync_phase: None,
            current_wave: 1,
            phase_started_at: None,
            revision: Some("rev-legacy".to_owned()),
            active_hooks: Vec::new(),
            message: None,
            started_at: now.clone(),
            finished_at: None,
        });
        assert_eq!(legacy.sync_phase, None);

        let outcome = step(
            &machine,
            &legacy,
            &schedule,
            &StepHealth::uniform([key("Job", "smoke")], HealthStatus::Healthy),
            &now,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::post_sync());
        assert_eq!(outcome.state.current_wave, 0, "the phase owns the step now");
        assert_eq!(outcome.state.revision.as_deref(), Some("rev-legacy"));
    }

    #[test]
    fn a_wave_that_disappeared_from_the_schedule_is_skipped_not_failed() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let now = at("2026-11-24T12:00:00Z");

        let mut state = machine.start(None, &now).state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = 42; // a wave that existed in the previous commit
        state.phase_started_at = Some(now.clone());

        let outcome = step(&machine, &state, &schedule, &StepHealth::empty(), &now);
        assert_eq!(execute_step(outcome.action), SyncStep::post_sync());
        assert_eq!(outcome.phase(), SyncPhase::PostSync);
    }

    #[test]
    fn the_machine_is_pure_and_never_mutates_the_persisted_state() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let now = at("2026-11-24T12:00:00Z");

        let mut state = machine.start(Some("rev-c".to_owned()), &now).state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = 0;
        state.phase_started_at = Some(now.clone());
        let frozen = state.clone();

        let health = StepHealth::uniform([key("Deployment", "api")], HealthStatus::Progressing);
        let first = step(&machine, &state, &schedule, &health, &now);
        let second = step(&machine, &state, &schedule, &health, &now);

        assert_eq!(state, frozen, "the persisted state must not be mutated");
        assert_eq!(first, second, "the same inputs must yield the same outcome");
        assert_eq!(first.action, second.action);
    }

    #[test]
    fn a_started_operation_never_uses_the_wall_clock() {
        // `start` records the caller's timestamp, never `Time::now()`, so a restart produces a
        // byte-identical state and the timeout tests can move time by data alone.
        let machine = SyncMachine::default();
        let now = at("2026-11-24T12:00:00Z");
        let first = machine.start(None, &now);
        let second = machine.start(None, &now);
        assert_eq!(first, second);
        assert_eq!(first.state.started_at, now);
        assert_eq!(first.state.phase_started_at, Some(now));
        assert_eq!(first.state.finished_at, None);
    }

    #[test]
    fn failure_messages_are_bounded_and_elide_the_tail_of_a_large_wave() {
        let keys: Vec<ResourceKey> = (0..20)
            .map(|index| key("Deployment", &format!("api-{index}")))
            .collect();

        // The key list itself is elided rather than silently dropped.
        let described = describe_keys(&keys);
        assert!(
            described.contains("and 15 more"),
            "the tail must be elided, not silently dropped: {described}"
        );
        assert_eq!(
            described.matches(", ").count(),
            MAX_FAILING_KEYS_IN_MESSAGE,
            "at most {MAX_FAILING_KEYS_IN_MESSAGE} keys are named: {described}"
        );

        // The persisted message stays inside the `/status` message budget (trap T9).
        let reason = SyncFailureReason::Degraded {
            step: SyncStep::sync(0),
            resources: keys,
        };
        let message = reason.message();
        assert!(
            message.chars().count() <= ferriscd_crd::status::MAX_STATUS_MESSAGE_CHARS + 1,
            "{} chars",
            message.chars().count()
        );
        assert!(message.contains("20 resource(s) Degraded"), "{message}");
        assert_eq!(reason.to_string(), message);

        assert_eq!(
            SyncFailureReason::OperationTimeout {
                elapsed: Duration::from_secs(601)
            }
            .message(),
            "operation timed out after 601s"
        );
    }

    #[test]
    fn a_terminal_operation_phase_wins_over_a_stale_sync_phase() {
        // A hand-patched or half-written status can pair a terminal `phase` with a running
        // `syncPhase`; the operation must stay finished instead of restarting a wave.
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let now = at("2026-11-24T12:00:00Z");

        for (phase, expected) in [
            (OperationPhase::Succeeded, OperationPhase::Succeeded),
            (OperationPhase::Failed, OperationPhase::Failed),
            // `Error` is terminal too, and is normalized onto the documented wire pair (M-3).
            (OperationPhase::Error, OperationPhase::Failed),
        ] {
            let state = OperationState {
                phase,
                sync_phase: Some(SyncPhase::Sync),
                current_wave: 0,
                phase_started_at: Some(now.clone()),
                revision: None,
                active_hooks: Vec::new(),
                message: None,
                started_at: now.clone(),
                finished_at: Some(now.clone()),
            };
            let outcome = step(&machine, &state, &schedule, &StepHealth::empty(), &now);
            assert!(outcome.is_finished(), "{phase:?} must stay finished");
            assert_eq!(
                outcome.state.phase, expected,
                "{phase:?} must be normalized, never left as it was"
            );
            assert_eq!(
                outcome.state.sync_phase,
                Some(match expected {
                    OperationPhase::Succeeded => SyncPhase::Succeeded,
                    _ => SyncPhase::Failed,
                }),
                "{phase:?} must carry a terminal syncPhase"
            );
            assert_eq!(
                outcome.state.current_wave, state.current_wave,
                "{phase:?} must not restart a wave"
            );
            assert_eq!(outcome.state.finished_at, state.finished_at);

            // Normalization is idempotent: the second pass rewrites nothing.
            let again = step(
                &machine,
                &outcome.state,
                &schedule,
                &StepHealth::empty(),
                &now,
            );
            assert_eq!(again.state, outcome.state);
        }
    }

    /// Finding M-3: `phase: Running` + `syncPhase: Succeeded` (a half-written status, or a controller
    /// killed between the two writes) must not stay `Running` in `/status` once the machine reports
    /// `Finished` — nothing would ever requeue it again.
    #[test]
    fn a_running_phase_with_a_terminal_sync_phase_is_normalized_not_left_running() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let now = at("2026-11-24T12:00:00Z");

        for (sync_phase, expected) in [
            (SyncPhase::Succeeded, OperationPhase::Succeeded),
            (SyncPhase::Failed, OperationPhase::Failed),
        ] {
            let state = OperationState {
                phase: OperationPhase::Running,
                sync_phase: Some(sync_phase),
                current_wave: 2,
                phase_started_at: Some(now.clone()),
                revision: Some("rev-a".to_owned()),
                active_hooks: Vec::new(),
                message: Some("sync completed".to_owned()),
                started_at: now.clone(),
                finished_at: Some(now.clone()),
            };

            let outcome = step(&machine, &state, &schedule, &StepHealth::empty(), &now);
            assert!(outcome.is_finished());
            assert_eq!(
                outcome.state.phase, expected,
                "{sync_phase:?} must not leave phase Running"
            );
            assert_eq!(outcome.state.sync_phase, Some(sync_phase));
            assert_eq!(
                outcome.state.message.as_deref(),
                Some("sync completed"),
                "normalization must not rewrite the recorded message"
            );

            // The persisted state round-trips and stays terminal on the next pass.
            let persisted = restart(&outcome.state);
            let again = step(&machine, &persisted, &schedule, &StepHealth::empty(), &now);
            assert_eq!(again.action, StepAction::Finished);
            assert_eq!(again.state, persisted);
        }
    }

    #[test]
    fn step_health_reports_what_is_missing_and_degraded() {
        let api = key("Deployment", "api");
        let service = key("Service", "api");
        let mut health = StepHealth::unobserved([api.clone(), service.clone()]);
        assert!(health.is_unobserved());
        assert!(health.degraded().is_empty());
        assert_eq!(health.aggregate(), HealthStatus::Healthy);

        health.observe(api.clone(), HealthStatus::Degraded);
        // `service` has still not been observed, so the step is still partially unwritten.
        assert!(health.is_unobserved());
        assert_eq!(health.degraded(), vec![api.clone()]);
        assert_eq!(health.aggregate(), HealthStatus::Degraded);
        assert_eq!(health.expected().len(), 2);
        assert_eq!(health.observed().len(), 1);
        health.observe(service.clone(), HealthStatus::Healthy);
        assert!(!health.is_unobserved());

        // An empty step is trivially healthy (a hook phase with no hooks).
        assert!(!StepHealth::empty().is_unobserved());
        assert_eq!(StepHealth::empty().expected().len(), 0);

        // The wave constructor is the wiring-facing one: it really is unobserved (so the first
        // pass executes the wave) instead of silently satisfied.
        let wave = StepHealth::wave([api.clone(), service]);
        assert!(wave.is_unobserved());
        assert_eq!(wave.expected().len(), 2);
    }

    /// Chaos finding (`T15.4`): a wave whose resource #1 landed but whose resource #2 was never
    /// written (transient failure, or a `SIGKILL` between the two applies) must be re-dispatched,
    /// not waited on until the wave timeout.
    #[test]
    fn a_partially_applied_wave_is_redispatched_not_waited_on() {
        let machine = SyncMachine::default();
        let schedule = SyncSchedule::from_waves([0]);
        let settings = key("ConfigMap", "settings");
        let api = key("Deployment", "api");
        let t0 = at("2026-11-24T12:00:00Z");
        let t1 = at("2026-11-24T12:00:05Z");

        let started = machine.start(Some("rev-a".to_owned()), &t0);
        let outcome = step(
            &machine,
            &restart(&started.state),
            &schedule,
            &StepHealth::empty(),
            &t0,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync(0));
        let state = restart(&outcome.state);

        // Only `settings` exists; `api` was never written.
        let mut partial = StepHealth::wave([settings.clone(), api.clone()]);
        partial.observe(settings.clone(), HealthStatus::Healthy);
        assert!(partial.is_unobserved());

        let outcome = step(&machine, &state, &schedule, &partial, &t1);
        assert_eq!(execute_step(outcome.action), SyncStep::sync(0));
        assert_eq!(
            outcome.state.phase_started_at, state.phase_started_at,
            "a re-dispatch is the same step: it must not reset the wave timeout"
        );

        // A mixed `Progressing` + not-yet-written wave is also re-dispatched.
        let mut mixed = StepHealth::wave([settings.clone(), api.clone()]);
        mixed.observe(settings.clone(), HealthStatus::Progressing);
        assert_eq!(
            execute_step(step(&machine, &state, &schedule, &mixed, &t1).action),
            SyncStep::sync(0)
        );

        // Once every expected resource is observed and still converging, the machine waits.
        let converging =
            StepHealth::uniform([settings.clone(), api.clone()], HealthStatus::Progressing);
        assert_eq!(
            wait_step(step(&machine, &state, &schedule, &converging, &t1).action),
            SyncStep::sync(0)
        );

        // A known-`Degraded` resource still fails the step even though another is unwritten.
        let mut degraded = StepHealth::wave([settings.clone(), api]);
        degraded.observe(settings, HealthStatus::Degraded);
        assert_eq!(
            step(&machine, &state, &schedule, &degraded, &t1).phase(),
            SyncPhase::SyncFail
        );
    }

    /// Re-dispatching a partial wave must not make it immortal: the wave timeout still fires.
    #[test]
    fn a_partially_applied_wave_still_times_out() {
        let machine = SyncMachine::default();
        let schedule = SyncSchedule::from_waves([0]);
        let settings = key("ConfigMap", "settings");
        let api = key("Deployment", "api");
        let t0 = at("2026-11-24T12:00:00Z");
        let late = at("2026-11-24T12:11:00Z");

        let started = machine.start(Some("rev-a".to_owned()), &t0);
        let outcome = step(
            &machine,
            &restart(&started.state),
            &schedule,
            &StepHealth::empty(),
            &t0,
        );
        let state = restart(&outcome.state);

        let mut partial = StepHealth::wave([settings.clone(), api]);
        partial.observe(settings, HealthStatus::Healthy);
        assert_eq!(
            step(&machine, &state, &schedule, &partial, &late).phase(),
            SyncPhase::SyncFail
        );
    }

    /// Finding M-1: an empty expected set is trivially satisfied, so a `Sync` wave must never be
    /// wired through it — the constructor rejects an empty wave in debug builds.
    #[test]
    #[should_panic(expected = "a Sync wave step must expect at least one resource")]
    fn a_wave_step_must_expect_at_least_one_resource() {
        let _ = StepHealth::wave(Vec::<ResourceKey>::new());
    }

    /// Finding H-1: re-dispatching the *same* step on `Unobserved` is not a new attempt, so it must
    /// not move `phaseStartedAt`. Otherwise every pass would restart the wave timeout and a wave
    /// that never converges could never time out.
    #[test]
    fn an_unobserved_redispatch_keeps_the_wave_timer_running() {
        let machine = SyncMachine::new(
            SyncTimeouts {
                wave: Duration::from_secs(600),
                // Long enough that only the wave timeout can fire in this scenario.
                operation: Duration::from_secs(3600),
            },
            WaveGate::HealthyOnly,
            DEFAULT_REQUEUE_AFTER,
        );
        let schedule = three_wave_schedule();
        let migration = key("Job", "migrate");
        let dispatched_at = at("2026-11-24T12:00:00Z");

        let mut state = machine
            .start(Some("rev-a".to_owned()), &dispatched_at)
            .state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = -1;
        state.phase_started_at = Some(dispatched_at.clone());
        state.message = Some("applying Sync(wave -1)".to_owned());
        let recorded = state.clone();

        // Two consecutive unobserved passes: both re-dispatch, neither restarts the clock.
        for now in [at("2026-11-24T12:00:05Z"), at("2026-11-24T12:09:59Z")] {
            let outcome = step(
                &machine,
                &state,
                &schedule,
                &StepHealth::wave([migration.clone()]),
                &now,
            );
            assert_eq!(execute_step(outcome.action), SyncStep::sync(-1));
            assert_eq!(
                outcome.state.phase_started_at,
                Some(dispatched_at.clone()),
                "an Unobserved re-dispatch must keep phaseStartedAt (at {now:?})"
            );
            assert_eq!(
                outcome.state.message, recorded.message,
                "an Unobserved re-dispatch must keep the recorded message"
            );
            assert_eq!(outcome.state, recorded, "the same attempt, unchanged");
        }

        // The timeout therefore fires 600s after the *original* dispatch.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::wave([migration]),
            &at("2026-11-24T12:10:00Z"),
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync_fail(-1));
        let message = outcome.state.message.clone().expect("message");
        assert!(
            message.contains("Sync(wave -1) timed out after 600s"),
            "the timer must measure the original dispatch: {message}"
        );
    }

    /// Finding H-1: the `SyncFail` reason is the operator's only explanation of a failed sync, so it
    /// must survive the `Unobserved` passes and become the terminal `/status` message.
    #[test]
    fn a_sync_fail_reason_survives_an_unobserved_pass_and_reaches_status() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let alert = key("Job", "alert");
        let now = at("2026-11-24T12:00:00Z");

        // Wave 0 reports `Degraded` -> `SyncFail`, recording the reason.
        let mut state = machine.start(Some("rev-a".to_owned()), &now).state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = 0;
        state.phase_started_at = Some(now.clone());
        let failed = machine.step(
            &state,
            &schedule,
            &StepHealth::uniform([key("Deployment", "api")], HealthStatus::Degraded),
            None,
            &now,
        );
        assert_eq!(execute_step(failed.action), SyncStep::sync_fail(0));
        let reason = failed.state.message.clone().expect("failure reason");
        assert!(reason.contains("Degraded"), "{reason}");
        state = restart(&failed.state);
        assert_eq!(state.message.as_deref(), Some(reason.as_str()));

        // The failure hook was created but not observed yet: the reason must not be replaced by the
        // generic "running SyncFail hooks" dispatch message.
        let outcome = step(
            &machine,
            &state,
            &schedule,
            &StepHealth::wave([alert.clone()]),
            &now,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::sync_fail(0));
        assert_eq!(
            outcome.state.message.as_deref(),
            Some(reason.as_str()),
            "an Unobserved pass must not wipe the SyncFail reason"
        );

        // Still converging: the reason stays.
        let outcome = step(
            &machine,
            &outcome.state,
            &schedule,
            &StepHealth::uniform([alert.clone()], HealthStatus::Progressing),
            &now,
        );
        assert_eq!(wait_step(outcome.action), SyncStep::sync_fail(0));
        assert_eq!(outcome.state.message.as_deref(), Some(reason.as_str()));

        // The hook completed: the operation is terminal and `/status` keeps the reason.
        let outcome = step(
            &machine,
            &outcome.state,
            &schedule,
            &StepHealth::uniform([alert], HealthStatus::Healthy),
            &now,
        );
        assert!(outcome.is_finished());
        assert_eq!(outcome.state.phase, OperationPhase::Failed);
        assert_eq!(outcome.state.sync_phase, Some(SyncPhase::Failed));
        assert_eq!(
            outcome.state.message.as_deref(),
            Some(reason.as_str()),
            "the terminal /status message must be the failure reason"
        );
    }

    /// The controller asks the machine where it is *before* it steps (it has to: the hooks and the
    /// health it feeds in belong to the persisted step), so `current_step` must agree with the
    /// private resume mapping for every shape of persisted state.
    #[test]
    fn current_step_matches_how_the_machine_resumes() {
        let machine = SyncMachine::default();
        let now = at("2026-11-24T12:00:00Z");

        for (sync_phase, wave, expected) in [
            (Some(SyncPhase::PreSync), 0, SyncStep::pre_sync()),
            (Some(SyncPhase::Sync), -1, SyncStep::sync(-1)),
            (Some(SyncPhase::Sync), 3, SyncStep::sync(3)),
            (Some(SyncPhase::PostSync), 0, SyncStep::post_sync()),
            (Some(SyncPhase::SyncFail), 2, SyncStep::sync_fail(2)),
            // A state written before Phase 10 carries no `syncPhase`; a `Running` operation was
            // then applying waves, so it resumes at `Sync(currentWave)`.
            (None, 1, SyncStep::sync(1)),
        ] {
            let state = OperationState {
                phase: OperationPhase::Running,
                sync_phase,
                current_wave: wave,
                phase_started_at: Some(now.clone()),
                revision: Some("rev-a".to_owned()),
                active_hooks: Vec::new(),
                message: None,
                started_at: now.clone(),
                finished_at: None,
            };
            assert_eq!(
                machine.current_step(&state),
                expected,
                "{sync_phase:?}/{wave}"
            );
        }

        // A terminal operation phase wins over a stale `syncPhase`, exactly like `step` does.
        let terminal = OperationState {
            phase: OperationPhase::Succeeded,
            sync_phase: Some(SyncPhase::Sync),
            current_wave: 0,
            phase_started_at: None,
            revision: None,
            active_hooks: Vec::new(),
            message: None,
            started_at: now.clone(),
            finished_at: Some(now.clone()),
        };
        assert_eq!(machine.current_step(&terminal).phase, SyncPhase::Succeeded);
    }

    /// Finding H-3: a commit that lands mid-operation may not contain the wave the operation is on.
    /// Skipping forward would report `Succeeded` for resources that were never applied, so the
    /// operation restarts at `PreSync` for the new revision instead.
    #[test]
    fn a_revision_change_restarts_the_operation_at_pre_sync() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule(); // waves -1, 0, 1 — commit B has no wave 42
        let now = at("2026-11-24T12:00:00Z");
        let later = at("2026-11-24T12:00:30Z");

        let mut state = machine.start(Some("commit-a".to_owned()), &now).state;
        state.sync_phase = Some(SyncPhase::Sync);
        state.current_wave = 42; // a wave that only exists in commit A
        state.phase_started_at = Some(now.clone());
        assert!(
            state.record_active_hook(ferriscd_crd::status::ActiveHook::new(
                SyncPhase::PreSync,
                -1,
                "migrations.yaml#0",
                "migrate-7f9c2",
                HealthStatus::Healthy,
            ))
        );

        // A pass that resolved no revision keeps the documented "skip forward" behaviour.
        let unchanged = step(&machine, &state, &schedule, &StepHealth::empty(), &later);
        assert_eq!(execute_step(unchanged.action), SyncStep::post_sync());
        assert_eq!(unchanged.state.revision.as_deref(), Some("commit-a"));

        // Commit B: restart at PreSync instead of skipping to PostSync/Succeeded.
        let outcome = machine.step(
            &state,
            &schedule,
            &StepHealth::empty(),
            Some("commit-b"),
            &later,
        );
        assert_eq!(
            execute_step(outcome.action),
            SyncStep::pre_sync(),
            "a moved revision must restart the operation, never skip forward"
        );
        assert_eq!(outcome.phase(), SyncPhase::PreSync);
        assert_eq!(outcome.state.phase, OperationPhase::Running);
        assert_eq!(outcome.state.current_wave, 0);
        assert_eq!(outcome.state.revision.as_deref(), Some("commit-b"));
        assert_eq!(outcome.state.phase_started_at, Some(later.clone()));
        assert_eq!(
            outcome.state.started_at, later,
            "the operation clock restarts with the revision, or a commit pushed near the deadline \
             would time out before its first wave could converge"
        );
        assert_eq!(outcome.state.finished_at, None);
        assert!(
            outcome.state.active_hooks.is_empty(),
            "the previous revision's hooks are not this operation's hooks"
        );
        let message = outcome.state.message.clone().expect("message");
        assert!(message.contains("commit-a"), "{message}");
        assert!(message.contains("commit-b"), "{message}");

        // Idempotent: the same revision on the next pass restarts nothing.
        let next = machine.step(
            &outcome.state,
            &schedule,
            &StepHealth::empty(),
            Some("commit-b"),
            &later,
        );
        assert_eq!(execute_step(next.action), SyncStep::sync(-1));
        assert_eq!(next.state.revision.as_deref(), Some("commit-b"));
        assert_eq!(next.state.started_at, later);
        assert_eq!(next.state.phase_started_at, Some(later.clone()));

        // A terminal operation is never resurrected by a later commit: the controller starts a new
        // operation for that, and this state must stay stable.
        let mut finished = outcome.state.clone();
        finished.phase = OperationPhase::Succeeded;
        finished.sync_phase = Some(SyncPhase::Succeeded);
        finished.finished_at = Some(later.clone());
        let frozen = finished.clone();
        let outcome = machine.step(
            &finished,
            &schedule,
            &StepHealth::empty(),
            Some("commit-c"),
            &later,
        );
        assert_eq!(outcome.action, StepAction::Finished);
        assert_eq!(outcome.state, frozen);
    }

    /// A legacy state with no recorded revision cannot prove it is operating on the resolved commit,
    /// so the first pass that does resolve one restarts it at `PreSync` (idempotent, never skipped).
    #[test]
    fn a_state_without_a_revision_restarts_once_the_revision_is_known() {
        let machine = SyncMachine::default();
        let schedule = three_wave_schedule();
        let now = at("2026-11-24T12:00:00Z");

        let mut state = machine.start(None, &now).state;
        state.sync_phase = Some(SyncPhase::PostSync);
        state.phase_started_at = Some(now.clone());

        let outcome = machine.step(
            &state,
            &schedule,
            &StepHealth::empty(),
            Some("commit-a"),
            &now,
        );
        assert_eq!(execute_step(outcome.action), SyncStep::pre_sync());
        assert_eq!(outcome.state.revision.as_deref(), Some("commit-a"));

        let again = machine.step(
            &outcome.state,
            &schedule,
            &StepHealth::empty(),
            Some("commit-a"),
            &now,
        );
        assert_eq!(execute_step(again.action), SyncStep::sync(-1));
    }
}

//! Native `coordination.k8s.io/v1` `Lease` leader election (`T13.2`, finding H4).
//!
//! A FerrisCD control plane may run more than one replica, but only **one** may reconcile at a
//! time: two reconcilers would fight over `ferriscd.io/tracking-id` ownership and could both prune
//! the same objects. This module implements active/standby election with the Kubernetes primitive
//! designed for it — a `coordination.k8s.io/v1` `Lease` — in ~300 lines, instead of depending on a
//! third-party crate that lags behind `kube 5.x`.
//!
//! ## How it works
//!
//! * One `Lease` (`ferriscd-controller-leader` in the control-plane namespace) records
//!   `spec.holderIdentity`, `spec.renewTime`, `spec.leaseDurationSeconds`, and
//!   `spec.leaseTransitions`.
//! * A standby **acquires** by writing its own identity: it creates the `Lease` when absent, or
//!   takes over one whose holder is gone or whose `renewTime` is older than
//!   `leaseDurationSeconds`. Every write carries the `resourceVersion` it read, so the API server
//!   rejects a *stale* write with `409 Conflict` — that is what makes split-brain impossible rather
//!   than merely unlikely ([`LeaseElector::renew`] re-reads a conflicted lease and gives up if the
//!   holder is no longer itself).
//! * The leader **renews** every `renew_interval` (< `lease_duration / 3`, validated), and the
//!   renewal is what a standby watches: a leader that dies (`SIGKILL`) stops renewing, and its
//!   lease expires within `lease_duration`.
//! * [`Leadership::token`] is a [`CancellationToken`] that is cancelled the moment leadership is
//!   lost, so the controller set stops scheduling work immediately instead of serving stale
//!   authority. In-flight passes drain through the controller's normal graceful shutdown.
//! * On `SIGTERM` the leader **releases voluntarily** (holder cleared, duration reduced to a
//!   second), so the standby takes over at once instead of waiting for the lease to expire.
//!
//! ## Defaults and safety
//!
//! Leader election is **opt-in** ([`LeaderElectionConfig`] is only built when the operator asks for
//! it): a single-replica controller behaves exactly as it did before Phase 13, and no cluster needs
//! `leases` RBAC it did not have. Turning it on for more than one replica is what the flag is for —
//! two replicas without it would both reconcile.
//!
//! The controller's `ClusterRole` then needs:
//!
//! ```yaml
//! - apiGroups: ["coordination.k8s.io"]
//!   resources: ["leases"]
//!   verbs: ["get", "create", "update"]
//! ```
//!
//! (A namespaced `Role` in the control-plane namespace is enough: the `Lease` never leaves it.)

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::api::{Api, PostParams};
use kube::{Client, ResourceExt};
use tokio_util::sync::CancellationToken;

/// Default `Lease` name (matches the roadmap).
pub const DEFAULT_LEASE_NAME: &str = "ferriscd-controller-leader";

/// Default lease duration.
pub const DEFAULT_LEASE_DURATION: Duration = Duration::from_secs(15);

/// Default renewal interval.
///
/// Strictly less than `lease_duration / 3` (a third of 15 s would be exactly 5 s, which the strict
/// rule in [`LeaderElectionConfig::validate`] refuses): four renewals fit inside every lease, so a
/// single slow API call never costs leadership.
pub const DEFAULT_RENEW_INTERVAL: Duration = Duration::from_secs(4);

/// Default delay between acquisition attempts while standing by.
pub const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Cap for the acquisition backoff ("bounded retries").
pub const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Shortest lease duration the elector accepts.
///
/// A one-second lease is already aggressive (the production default is fifteen): anything shorter
/// turns every API-server hiccup into a leadership change, and leaves no room for the
/// `renew_interval < lease_duration / 3` rule.
pub const MIN_LEASE_DURATION: Duration = Duration::from_secs(1);

/// How many times one acquisition call retries after a `409 Conflict`.
///
/// Bounded on purpose: contention is expected (every standby writes), but a pathological race must
/// end in a retryable error instead of an unbounded loop inside one reconcile tick.
pub const MAX_ACQUIRE_ATTEMPTS: usize = 3;

/// `spec.holderIdentity` a released lease leaves behind (cleared, so nobody is the holder).
pub const RELEASED: &str = "";

/// Leader-election tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderElectionConfig {
    lease_name: String,
    namespace: String,
    identity: String,
    lease_duration: Duration,
    renew_interval: Duration,
    retry_interval: Duration,
}

impl LeaderElectionConfig {
    /// Builds the production defaults for `namespace` with this replica's `identity`.
    ///
    /// `identity` must be unique per replica (the pod name is the natural choice): it is what the
    /// `Lease` records as the holder.
    #[must_use]
    pub fn new(namespace: impl Into<String>, identity: impl Into<String>) -> Self {
        Self {
            lease_name: DEFAULT_LEASE_NAME.to_owned(),
            namespace: namespace.into(),
            identity: identity.into(),
            lease_duration: DEFAULT_LEASE_DURATION,
            renew_interval: DEFAULT_RENEW_INTERVAL,
            retry_interval: DEFAULT_RETRY_INTERVAL,
        }
    }

    /// Overrides the `Lease` name.
    ///
    /// The name is trimmed on the way in (finding M2): validation and use must agree, and a
    /// `--leader-election-lease-name " ferriscd-leader "` would otherwise validate as a DNS
    /// subdomain while every API call asked for a name with spaces in it — a `404` that looks like
    /// a missing `Lease` and silently costs leadership.
    #[must_use]
    pub fn with_lease_name(mut self, lease_name: impl Into<String>) -> Self {
        self.lease_name = lease_name.into().trim().to_owned();
        self
    }

    /// Overrides the lease duration.
    #[must_use]
    pub fn with_lease_duration(mut self, lease_duration: Duration) -> Self {
        self.lease_duration = lease_duration;
        self
    }

    /// Overrides the renewal interval.
    #[must_use]
    pub fn with_renew_interval(mut self, renew_interval: Duration) -> Self {
        self.renew_interval = renew_interval;
        self
    }

    /// Overrides the standby retry interval.
    #[must_use]
    pub fn with_retry_interval(mut self, retry_interval: Duration) -> Self {
        self.retry_interval = retry_interval;
        self
    }

    /// The `Lease` name.
    #[must_use]
    pub fn lease_name(&self) -> &str {
        &self.lease_name
    }

    /// The namespace the `Lease` lives in (the control-plane namespace).
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// This replica's identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The lease duration.
    #[must_use]
    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    /// The renewal interval.
    #[must_use]
    pub fn renew_interval(&self) -> Duration {
        self.renew_interval
    }

    /// The standby retry interval.
    #[must_use]
    pub fn retry_interval(&self) -> Duration {
        self.retry_interval
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// [`LeaderElectionConfigError`] for an empty/invalid name or namespace, a zero duration, a
    /// lease shorter than [`MIN_LEASE_DURATION`], or a renewal interval that is not strictly less
    /// than a third of the lease duration (which would make a healthy leader lose its lease between
    /// renewals).
    pub fn validate(&self) -> Result<(), LeaderElectionConfigError> {
        if self.identity.trim().is_empty() {
            return Err(LeaderElectionConfigError::EmptyIdentity);
        }
        if self.namespace.trim().is_empty() {
            return Err(LeaderElectionConfigError::EmptyNamespace);
        }
        if !is_dns_subdomain(self.lease_name.trim()) {
            return Err(LeaderElectionConfigError::InvalidLeaseName {
                name: self.lease_name.clone(),
            });
        }
        if self.lease_duration < MIN_LEASE_DURATION {
            return Err(LeaderElectionConfigError::LeaseDurationTooShort {
                lease_duration: self.lease_duration,
                minimum: MIN_LEASE_DURATION,
            });
        }
        if self.renew_interval.is_zero() {
            return Err(LeaderElectionConfigError::ZeroRenewInterval);
        }
        // The roadmap rule, enforced structurally: `renew_interval < lease_duration / 3`.
        if self.renew_interval.saturating_mul(3) >= self.lease_duration {
            return Err(LeaderElectionConfigError::RenewIntervalTooLong {
                renew_interval: self.renew_interval,
                lease_duration: self.lease_duration,
            });
        }
        if self.retry_interval.is_zero() {
            return Err(LeaderElectionConfigError::ZeroRetryInterval);
        }
        Ok(())
    }

    /// The delay before acquisition attempt `attempt` (0-based): a bounded exponential backoff.
    ///
    /// The delay doubles per attempt and is capped at [`MAX_RETRY_INTERVAL`] — raised to the
    /// configured `retry_interval` when that is already larger, so the cap never *shrinks* the
    /// interval the operator asked for. Either way the backoff is bounded, so a standby of a
    /// long-lived leader costs a handful of `GET`s per minute instead of a hot loop, and it never
    /// grows into an hours-long silence.
    #[must_use]
    pub fn retry_delay(&self, attempt: u32) -> Duration {
        let factor = 1_u32.checked_shl(attempt.min(4)).unwrap_or(u32::MAX);
        self.retry_interval
            .saturating_mul(factor)
            .min(MAX_RETRY_INTERVAL.max(self.retry_interval))
    }

    /// The deadline after which a leader that has not renewed since `last_ok` must consider its
    /// lease lost.
    ///
    /// One renewal interval of slack is subtracted: the standby may take the lease over at
    /// `lease_duration`, so stopping a little earlier is what keeps two leaders from overlapping.
    #[must_use]
    pub fn lost_deadline(&self) -> Duration {
        self.lease_duration.saturating_sub(self.renew_interval)
    }
}

/// Whether `name` is an RFC 1123 subdomain.
fn is_dns_subdomain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Leader-election configuration errors (all terminal: the process cannot start).
#[derive(Debug, thiserror::Error)]
pub enum LeaderElectionConfigError {
    /// No identity was configured, so the `Lease` could not distinguish this replica.
    #[error("leader election needs a unique identity (usually the pod name)")]
    EmptyIdentity,

    /// No namespace was configured.
    #[error("leader election needs the control-plane namespace that holds the Lease")]
    EmptyNamespace,

    /// The `Lease` name is not a DNS subdomain.
    #[error("leader election lease name {name:?} is not a valid DNS subdomain")]
    InvalidLeaseName {
        /// The rejected name.
        name: String,
    },

    /// The lease duration is too short to be safe.
    #[error(
        "lease duration {lease_duration:?} is too short: use at least {minimum:?} so a healthy \
         leader is not evicted by one slow API call"
    )]
    LeaseDurationTooShort {
        /// The configured duration.
        lease_duration: Duration,
        /// The minimum accepted duration.
        minimum: Duration,
    },

    /// The renewal interval is not strictly less than a third of the lease duration.
    #[error(
        "renew interval {renew_interval:?} must be less than a third of lease duration \
         {lease_duration:?}: the leader must renew several times per lease so a single failed \
         renewal never hands the lease to a standby"
    )]
    RenewIntervalTooLong {
        /// The configured interval.
        renew_interval: Duration,
        /// The configured duration.
        lease_duration: Duration,
    },

    /// The renewal interval is zero.
    #[error("renew interval must be greater than zero")]
    ZeroRenewInterval,

    /// The standby retry interval is zero.
    #[error("retry interval must be greater than zero")]
    ZeroRetryInterval,
}

/// Errors a lease acquisition, renewal, or release can raise.
#[derive(Debug, thiserror::Error)]
pub enum LeaderElectionError {
    /// The API server could not be reached or answered with an unexpected error.
    ///
    /// Retryable: leader election never fails permanently on a transient API failure — it just has
    /// to keep trying (or, if it is the leader, keep trying before declaring the lease lost).
    #[error("leader election API failure: {message}")]
    Api {
        /// The underlying failure, redacted.
        message: String,
    },

    /// Another replica holds the lease.
    ///
    /// Returned by [`LeaseElector::renew`] when the lease is no longer ours. Terminal for the
    /// leader term: the controller set must stop.
    #[error(
        "leadership was lost: the Lease {lease} in namespace {namespace:?} is held by {holder:?}"
    )]
    Lost {
        /// The `Lease` name.
        lease: String,
        /// The namespace it lives in.
        namespace: String,
        /// The current holder (empty when the lease was released).
        holder: String,
    },

    /// Acquisition kept losing the optimistic-concurrency race.
    ///
    /// Retryable: the standby waits one backoff and tries again.
    #[error(
        "lease {lease} in namespace {namespace:?} was updated by another replica on every attempt: \
         staying a standby"
    )]
    Contended {
        /// The `Lease` name.
        lease: String,
        /// The namespace it lives in.
        namespace: String,
    },

    /// The configuration is invalid.
    #[error(transparent)]
    Config(#[from] LeaderElectionConfigError),
}

impl LeaderElectionError {
    /// Whether the leader term is over (no retry can restore it).
    #[must_use]
    pub fn is_lost(&self) -> bool {
        matches!(self, Self::Lost { .. })
    }

    /// Whether retrying the same operation can succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Api { .. } | Self::Contended { .. })
    }
}

/// The `Lease` operations the elector needs.
///
/// A trait rather than a raw `Api<Lease>` so the whole acquire/renew/lose/release contract is
/// testable against an in-memory `Lease`, with no API server and no timing sleeps. Production uses
/// [`KubeLeaseApi`], which is a thin `Api<Lease>` wrapper.
pub trait LeaseApi: Send + Sync + 'static {
    /// Reads the lease, answering `Ok(None)` for `404`.
    fn get<'a>(
        &'a self,
        name: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Option<Lease>, kube::Error>>;

    /// Creates the lease.
    fn create<'a>(
        &'a self,
        lease: Lease,
    ) -> futures::future::BoxFuture<'a, Result<Lease, kube::Error>>;

    /// Replaces the lease (optimistic concurrency via `metadata.resourceVersion`).
    fn replace<'a>(
        &'a self,
        name: &'a str,
        lease: Lease,
    ) -> futures::future::BoxFuture<'a, Result<Lease, kube::Error>>;
}

/// The production [`LeaseApi`]: `Api<Lease>` in the control-plane namespace.
#[derive(Clone)]
pub struct KubeLeaseApi {
    api: Api<Lease>,
}

impl KubeLeaseApi {
    /// Builds the API for `namespace` (the control-plane namespace).
    #[must_use]
    pub fn new(client: Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
        }
    }
}

impl fmt::Debug for KubeLeaseApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KubeLeaseApi")
            .field("namespaced", &true)
            .finish_non_exhaustive()
    }
}

impl LeaseApi for KubeLeaseApi {
    fn get<'a>(
        &'a self,
        name: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Option<Lease>, kube::Error>> {
        Box::pin(async move {
            match self.api.get_opt(name).await {
                Ok(lease) => Ok(lease),
                Err(err) => Err(err),
            }
        })
    }

    fn create<'a>(
        &'a self,
        lease: Lease,
    ) -> futures::future::BoxFuture<'a, Result<Lease, kube::Error>> {
        Box::pin(async move { self.api.create(&PostParams::default(), &lease).await })
    }

    fn replace<'a>(
        &'a self,
        name: &'a str,
        lease: Lease,
    ) -> futures::future::BoxFuture<'a, Result<Lease, kube::Error>> {
        Box::pin(async move { self.api.replace(name, &PostParams::default(), &lease).await })
    }
}

/// What one acquisition attempt found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireOutcome {
    /// The lease is now ours.
    Acquired,
    /// Another replica holds a live lease.
    Held {
        /// The current holder's identity.
        holder: String,
    },
}

/// The state of a lease this replica holds.
#[derive(Debug, Clone)]
struct Held {
    resource_version: String,
    transitions: i32,
    acquire_time: MicroTime,
}

/// The local monotonic clock an elector measures elapsed lease time with (finding M3).
///
/// The timestamps in a `Lease` are written by **another** process, so they must never be compared
/// against this replica's wall clock to decide expiry: two nodes' clocks drift, and a leader whose
/// clock runs ahead would keep its lease looking alive — a *negative* age — long after it stopped
/// renewing, so a dead leader could never be replaced. Every expiry decision therefore measures
/// elapsed **local** time from the moment the lease was observed.
///
/// The seam exists so the elapsed-time arithmetic is testable without sleeping.
#[derive(Clone)]
struct MonotonicClock(Arc<dyn Fn() -> Instant + Send + Sync>);

impl MonotonicClock {
    /// The process clock.
    fn system() -> Self {
        let now: Arc<dyn Fn() -> Instant + Send + Sync> = Arc::new(Instant::now);
        Self(now)
    }

    /// The current local monotonic instant.
    fn now(&self) -> Instant {
        (self.0)()
    }
}

impl fmt::Debug for MonotonicClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MonotonicClock")
    }
}

/// One observation of a lease held by somebody else.
///
/// `remaining` is how long the lease still had to run **when it was read**, measured off the local
/// clock; from then on expiry is `elapsed local time >= remaining`, which no clock skew can defeat.
#[derive(Debug, Clone)]
struct Observation {
    /// The identity the lease recorded.
    holder: String,
    /// The timestamp the lease recorded (`renewTime`, falling back to `acquireTime`).
    renew_time: Option<MicroTime>,
    /// When this replica read that timestamp (local monotonic).
    observed_at: Instant,
    /// How much of the lease was left at that moment.
    remaining: Duration,
}

/// One `Lease`-backed elector.
///
/// Cheap to share (`Arc`): the held-lease state is behind a `Mutex`, so a renewing task and a
/// shutdown path can both observe it.
pub struct LeaseElector {
    api: Arc<dyn LeaseApi>,
    config: LeaderElectionConfig,
    held: Mutex<Option<Held>>,
    /// The last foreign lease this replica read (finding M3).
    observation: Mutex<Option<Observation>>,
    clock: MonotonicClock,
}

impl fmt::Debug for LeaseElector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseElector")
            .field("lease", &self.config.lease_name)
            .field("namespace", &self.config.namespace)
            .field("identity", &self.config.identity)
            .field("lease_duration", &self.config.lease_duration)
            .field("renew_interval", &self.config.renew_interval)
            .field("leader", &self.is_leader())
            .finish()
    }
}

impl LeaseElector {
    /// Builds an elector over `api`.
    ///
    /// # Errors
    ///
    /// [`LeaderElectionConfigError`] when the configuration is invalid — a misconfigured elector
    /// must never start, because a lease shorter than its renewal interval silently oscillates
    /// between leaders.
    pub fn new(
        api: Arc<dyn LeaseApi>,
        config: LeaderElectionConfig,
    ) -> Result<Self, LeaderElectionConfigError> {
        config.validate()?;
        Ok(Self {
            api,
            config,
            held: Mutex::new(None),
            observation: Mutex::new(None),
            clock: MonotonicClock::system(),
        })
    }

    /// Replaces the monotonic clock (tests: elapsed-time decisions without sleeping).
    #[cfg(test)]
    #[must_use]
    fn with_clock(mut self, clock: MonotonicClock) -> Self {
        self.clock = clock;
        self
    }

    /// Builds an elector over the live API server.
    ///
    /// # Errors
    ///
    /// See [`Self::new`].
    pub fn from_client(
        client: Client,
        config: LeaderElectionConfig,
    ) -> Result<Self, LeaderElectionConfigError> {
        let api: Arc<dyn LeaseApi> = Arc::new(KubeLeaseApi::new(client, config.namespace()));
        Self::new(api, config)
    }

    /// The configured tuning.
    #[must_use]
    pub fn config(&self) -> &LeaderElectionConfig {
        &self.config
    }

    /// Whether this replica currently holds the lease.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.lock().is_some()
    }

    /// Acquires the lease, or reports who holds it.
    ///
    /// # Errors
    ///
    /// [`LeaderElectionError::Api`] and [`LeaderElectionError::Contended`] are retryable;
    /// [`LeaderElectionError::Lost`] is not raised here (nothing is held yet).
    pub async fn try_acquire(&self) -> Result<AcquireOutcome, LeaderElectionError> {
        let name = self.config.lease_name.clone();
        for _ in 0..MAX_ACQUIRE_ATTEMPTS {
            let current = self
                .api
                .get(&name)
                .await
                .map_err(|err| self.api_error(&err))?;
            // The instant the observation belongs to: everything after this is decided on elapsed
            // local time, never on the leader's clock (finding M3).
            let observed_at = self.clock.now();
            let Some(current) = current else {
                let body = self.lease_body(0, now(), now(), None);
                return match self.api.create(body).await {
                    Ok(created) => {
                        self.remember(&created);
                        Ok(AcquireOutcome::Acquired)
                    }
                    // Somebody created it between our GET and our POST: re-read, never assume.
                    Err(err) if is_conflict(&err) => continue,
                    Err(err) => Err(self.api_error(&err)),
                };
            };
            let spec = current.spec.clone().unwrap_or_default();
            let holder = spec.holder_identity.clone().unwrap_or_default();
            if holder == self.config.identity {
                // A restart of this replica's own process: reclaim what is already ours.
                self.remember(&current);
                return Ok(AcquireOutcome::Acquired);
            }
            if holder.is_empty() || self.lease_expired(&holder, &spec, observed_at) {
                let transitions = spec.lease_transitions.unwrap_or_default().saturating_add(1);
                let acquire_time = now();
                let body = self.lease_body(
                    transitions,
                    acquire_time.clone(),
                    acquire_time,
                    current.metadata.resource_version.as_deref(),
                );
                return match self.api.replace(&name, body).await {
                    Ok(updated) => {
                        self.remember(&updated);
                        Ok(AcquireOutcome::Acquired)
                    }
                    // The stale `resourceVersion` was rejected: another replica wrote first, so
                    // re-read instead of forcing our identity over theirs (no split-brain).
                    Err(err) if is_conflict(&err) => continue,
                    Err(err) => Err(self.api_error(&err)),
                };
            }
            return Ok(AcquireOutcome::Held { holder });
        }
        Err(LeaderElectionError::Contended {
            lease: self.config.lease_name.clone(),
            namespace: self.config.namespace.clone(),
        })
    }

    /// Renews the lease this replica holds.
    ///
    /// # Errors
    ///
    /// [`LeaderElectionError::Lost`] the moment the lease is no longer ours (including a `409` that
    /// re-reads into another holder), and [`LeaderElectionError::Api`] for a transient failure —
    /// which the caller tolerates until [`LeaderElectionConfig::lost_deadline`] passes.
    pub async fn renew(&self) -> Result<(), LeaderElectionError> {
        let Some(held) = self.held() else {
            return Err(self.lost(RELEASED));
        };
        let name = self.config.lease_name.clone();
        let body = self.lease_body(
            held.transitions,
            held.acquire_time.clone(),
            now(),
            Some(&held.resource_version),
        );
        match self.api.replace(&name, body).await {
            Ok(updated) => {
                self.remember(&updated);
                Ok(())
            }
            Err(err) if is_conflict(&err) => {
                // The resourceVersion moved. Re-read and *decide*; never blindly retry, because
                // the write that moved it may have been another replica taking the lease over.
                let current = self
                    .api
                    .get(&name)
                    .await
                    .map_err(|err| self.api_error(&err))?
                    .ok_or_else(|| self.lost(RELEASED))?;
                let spec = current.spec.clone().unwrap_or_default();
                let holder = spec.holder_identity.clone().unwrap_or_default();
                if holder != self.config.identity {
                    self.forget();
                    return Err(self.lost(&holder));
                }
                // Ours, renewed by an attempt whose response we never observed: adopt its
                // `resourceVersion` and retry exactly once.
                self.remember(&current);
                let Some(held) = self.held() else {
                    return Err(self.lost(RELEASED));
                };
                let body = self.lease_body(
                    held.transitions,
                    held.acquire_time.clone(),
                    now(),
                    Some(&held.resource_version),
                );
                match self.api.replace(&name, body).await {
                    Ok(updated) => {
                        self.remember(&updated);
                        Ok(())
                    }
                    Err(err) if is_conflict(&err) => {
                        self.forget();
                        Err(self.lost(RELEASED))
                    }
                    Err(err) => Err(self.api_error(&err)),
                }
            }
            Err(err) => Err(self.api_error(&err)),
        }
    }

    /// Voluntarily releases the lease (graceful `SIGTERM`).
    ///
    /// Clears `spec.holderIdentity` and shortens the duration to one second, so a standby takes
    /// over on its next attempt instead of waiting out the full lease.
    ///
    /// # Errors
    ///
    /// [`LeaderElectionError::Api`] for a failed write. A `409` is **not** an error: it means a
    /// standby already took the lease over, which is the outcome releasing wanted.
    pub async fn release(&self) -> Result<(), LeaderElectionError> {
        let Some(held) = self.held() else {
            return Ok(());
        };
        let name = self.config.lease_name.clone();
        let mut body = self.lease_body(
            held.transitions,
            held.acquire_time,
            now(),
            Some(&held.resource_version),
        );
        if let Some(spec) = &mut body.spec {
            spec.holder_identity = None;
            spec.lease_duration_seconds = Some(1);
        }
        let result = match self.api.replace(&name, body).await {
            Ok(_) => Ok(()),
            Err(err) if is_conflict(&err) => Ok(()),
            Err(err) => Err(self.api_error(&err)),
        };
        self.forget();
        result
    }

    /// Builds the `Lease` this replica would write.
    fn lease_body(
        &self,
        transitions: i32,
        acquire_time: MicroTime,
        renew_time: MicroTime,
        resource_version: Option<&str>,
    ) -> Lease {
        let mut metadata = ObjectMeta {
            name: Some(self.config.lease_name.clone()),
            namespace: Some(self.config.namespace.clone()),
            ..ObjectMeta::default()
        };
        if let Some(resource_version) = resource_version {
            metadata.resource_version = Some(resource_version.to_owned());
        }
        Lease {
            metadata,
            spec: Some(LeaseSpec {
                holder_identity: Some(self.config.identity.clone()),
                lease_duration_seconds: Some(duration_seconds(self.config.lease_duration)),
                acquire_time: Some(acquire_time),
                renew_time: Some(renew_time),
                lease_transitions: Some(transitions),
                ..LeaseSpec::default()
            }),
        }
    }

    /// Records the lease the API server just confirmed.
    fn remember(&self, lease: &Lease) {
        let spec = lease.spec.clone().unwrap_or_default();
        let held = Held {
            resource_version: lease.resource_version().unwrap_or_default(),
            transitions: spec.lease_transitions.unwrap_or_default(),
            acquire_time: spec.acquire_time.or(spec.renew_time).unwrap_or_else(now),
        };
        *self.lock() = Some(held);
    }

    /// Drops the held-lease state (leadership ended).
    fn forget(&self) {
        *self.lock() = None;
    }

    fn held(&self) -> Option<Held> {
        self.lock().clone()
    }

    /// Whether the lease `holder` holds — observed at `observed_at` — may be taken over now.
    ///
    /// The **first** sight of a given `(holder, renewTime)` is judged on that timestamp; every later
    /// sight of the same renewal is judged on elapsed **local** time against the remaining lifetime
    /// recorded then. A `renewTime` in the future (the leader's clock runs ahead of ours) therefore
    /// costs at most one lease duration of local waiting instead of blocking takeover for the whole
    /// skew — the failure finding M3 identified (a dead leader whose clock was ahead could never be
    /// replaced).
    fn lease_expired(&self, holder: &str, spec: &LeaseSpec, observed_at: Instant) -> bool {
        let renew_time = spec
            .renew_time
            .clone()
            .or_else(|| spec.acquire_time.clone());
        let mut observation = self.lock_observation();
        if let Some(seen) = observation.as_ref()
            && seen.holder == holder
            && seen.renew_time == renew_time
        {
            return observed_at.saturating_duration_since(seen.observed_at) >= seen.remaining;
        }
        let remaining = remaining_at(spec, now());
        let expired = remaining.is_zero();
        *observation = Some(Observation {
            holder: holder.to_owned(),
            renew_time,
            observed_at,
            remaining,
        });
        expired
    }

    /// Locks the foreign-lease observation, recovering from poisoning (see [`Self::lock`]).
    fn lock_observation(&self) -> MutexGuard<'_, Option<Observation>> {
        self.observation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Locks the state, recovering from poisoning: leader-election bookkeeping must never take the
    /// process down (and a poisoned lock still holds `Option<Held>`, which is trivially valid).
    fn lock(&self) -> MutexGuard<'_, Option<Held>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Builds the "leadership lost" error for `holder`.
    fn lost(&self, holder: &str) -> LeaderElectionError {
        LeaderElectionError::Lost {
            lease: self.config.lease_name.clone(),
            namespace: self.config.namespace.clone(),
            holder: holder.to_owned(),
        }
    }

    /// Builds the redacted API error.
    fn api_error(&self, err: &kube::Error) -> LeaderElectionError {
        LeaderElectionError::Api {
            message: crate::reconcile::bounded(&err.to_string()),
        }
    }
}

/// How a leader term ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldOutcome {
    /// `SIGTERM` (or the caller's stop token): the lease was released voluntarily.
    Released,
    /// Leadership was lost; the replica is a standby again.
    Lost,
}

/// The leadership one holds while its controller set runs.
///
/// The token is cancelled **the moment** leadership ends — on a lost renewal or on a graceful stop
/// — so nothing keeps scheduling work under an authority this replica no longer has.
pub struct Leadership {
    elector: Arc<LeaseElector>,
    token: CancellationToken,
}

impl fmt::Debug for Leadership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leadership")
            .field("lease", &self.elector.config.lease_name)
            .field("identity", &self.elector.config.identity)
            .field("cancelled", &self.token.is_cancelled())
            .finish()
    }
}

impl Leadership {
    /// The cancellation token that ends the leader's work.
    #[must_use]
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// The elector backing this term.
    #[must_use]
    pub fn elector(&self) -> &Arc<LeaseElector> {
        &self.elector
    }

    /// Renews the lease until `stop` fires (graceful release) or leadership is lost.
    ///
    /// Run this **concurrently** with the controller set: it is what keeps the lease alive, and
    /// cancelling [`Self::token`] is how it stops that set.
    ///
    /// # Errors
    ///
    /// [`LeaderElectionError::Api`] when the lease cannot be released on the way out (logged by the
    /// caller); leadership loss itself is reported as [`HoldOutcome::Lost`].
    pub async fn hold(&self, stop: &CancellationToken) -> Result<HoldOutcome, LeaderElectionError> {
        let mut ticker = tokio::time::interval(self.elector.config.renew_interval);
        // A slow API must not turn into a burst of queued renewals.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick completes immediately; the first renewal happens after one interval.
        ticker.tick().await;
        let mut last_ok = Instant::now();
        loop {
            tokio::select! {
                () = stop.cancelled() => {
                    // Stop reconciling first, then tell the API server: a standby must be able to
                    // take over as soon as this process stops writing.
                    self.token.cancel();
                    let released = self.elector.release().await;
                    if let Err(err) = &released {
                        tracing::warn!(
                            lease = %self.elector.config.lease_name,
                            error = %err,
                            "failed to release the leader lease; the standby will wait for it to expire"
                        );
                    } else {
                        tracing::info!(
                            lease = %self.elector.config.lease_name,
                            identity = %self.elector.config.identity,
                            "leader lease released voluntarily"
                        );
                    }
                    return Ok(HoldOutcome::Released);
                }
                _ = ticker.tick() => {
                    match self.elector.renew().await {
                        Ok(()) => last_ok = Instant::now(),
                        Err(err) if err.is_lost() => {
                            tracing::warn!(
                                lease = %self.elector.config.lease_name,
                                error = %err,
                                "lost the leader lease; stopping reconciliation and standing by"
                            );
                            self.token.cancel();
                            return Ok(HoldOutcome::Lost);
                        }
                        Err(err) => {
                            // Tolerate transient API failures, but only until the lease could be
                            // taken over: after that this replica must stop.
                            if last_ok.elapsed() >= self.elector.config.lost_deadline() {
                                tracing::warn!(
                                    lease = %self.elector.config.lease_name,
                                    error = %err,
                                    waited = ?last_ok.elapsed(),
                                    "leader lease could not be renewed before its deadline; \
                                     stopping reconciliation and standing by"
                                );
                                self.token.cancel();
                                self.elector.forget();
                                return Ok(HoldOutcome::Lost);
                            }
                            tracing::warn!(
                                lease = %self.elector.config.lease_name,
                                error = %err,
                                "leader lease renewal failed; retrying before the lease expires"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// The election entry point: stands by until it holds the lease, then hands out [`Leadership`].
pub struct LeaderElection {
    elector: Arc<LeaseElector>,
}

impl fmt::Debug for LeaderElection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaderElection")
            .field("elector", &self.elector)
            .finish()
    }
}

impl LeaderElection {
    /// Wraps an elector.
    #[must_use]
    pub fn new(elector: Arc<LeaseElector>) -> Self {
        Self { elector }
    }

    /// Builds the election over the live API server.
    ///
    /// # Errors
    ///
    /// See [`LeaseElector::from_client`].
    pub fn from_client(
        client: Client,
        config: LeaderElectionConfig,
    ) -> Result<Self, LeaderElectionConfigError> {
        Ok(Self::new(Arc::new(LeaseElector::from_client(
            client, config,
        )?)))
    }

    /// The elector behind this election.
    #[must_use]
    pub fn elector(&self) -> &Arc<LeaseElector> {
        &self.elector
    }

    /// Waits until this replica holds the lease.
    ///
    /// Returns `Ok(None)` when `stop` fires before leadership was acquired (a standby that is shut
    /// down while waiting). Acquisition retries are bounded per call
    /// ([`MAX_ACQUIRE_ATTEMPTS`]) and backed off across calls
    /// ([`LeaderElectionConfig::retry_delay`]).
    ///
    /// # Errors
    ///
    /// [`LeaderElectionError::Api`] for a non-retryable API failure (only reachable if the elector
    /// is misconfigured, e.g. the `Lease` namespace does not exist — which is reported, not
    /// hidden).
    pub async fn campaign(
        &self,
        stop: &CancellationToken,
    ) -> Result<Option<Leadership>, LeaderElectionError> {
        self.campaign_with(stop, || {}).await
    }

    /// [`Self::campaign`] with a callback invoked every time a **healthy foreign leader** is
    /// observed holding the lease.
    ///
    /// The HA active/standby loop uses this to mark the `standby_serving` readiness gate: a
    /// standby must report ready to serve stateless API traffic, but only once it has seen a live
    /// leader (candidacy alone must not flip `/readyz`).
    pub async fn campaign_with(
        &self,
        stop: &CancellationToken,
        on_standby: impl Fn(),
    ) -> Result<Option<Leadership>, LeaderElectionError> {
        let mut attempt = 0_u32;
        loop {
            if stop.is_cancelled() {
                return Ok(None);
            }
            match self.elector.try_acquire().await {
                Ok(AcquireOutcome::Acquired) => {
                    tracing::info!(
                        lease = %self.elector.config.lease_name,
                        namespace = %self.elector.config.namespace,
                        identity = %self.elector.config.identity,
                        "acquired the leader lease: this replica reconciles"
                    );
                    return Ok(Some(Leadership {
                        elector: self.elector.clone(),
                        token: CancellationToken::new(),
                    }));
                }
                Ok(AcquireOutcome::Held { holder }) => {
                    on_standby();
                    tracing::debug!(
                        lease = %self.elector.config.lease_name,
                        holder = %holder,
                        "another replica holds the leader lease; standing by"
                    );
                }
                Err(err) if err.is_retryable() => {
                    tracing::warn!(
                        lease = %self.elector.config.lease_name,
                        error = %err,
                        "leader election attempt failed; standing by"
                    );
                }
                Err(err) => return Err(err),
            }
            let delay = self.elector.config.retry_delay(attempt);
            attempt = attempt.saturating_add(1);
            tokio::select! {
                () = stop.cancelled() => return Ok(None),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }
}

/// Whether a `kube` error is an optimistic-concurrency conflict (`409`).
fn is_conflict(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(status) if status.code == 409)
}

/// How much of a foreign lease is still to run, seen from `observed_wall`.
///
/// A `renewTime` **in the future** — the leader's clock runs ahead of this replica's — is treated
/// as "renewed just now", never as a negative age: a negative age is exactly what used to make a
/// lease look alive for the whole skew, so a dead leader whose clock was ahead could not be replaced
/// (finding M3). A lease with no duration, or with no timestamp at all, has nothing left: it cannot
/// be shown to be alive.
fn remaining_at(spec: &LeaseSpec, observed_wall: MicroTime) -> Duration {
    let Some(duration) = spec.lease_duration_seconds.filter(|seconds| *seconds > 0) else {
        return Duration::ZERO;
    };
    let Some(last) = spec.renew_time.as_ref().or(spec.acquire_time.as_ref()) else {
        return Duration::ZERO;
    };
    let duration = Duration::from_secs(u64::from(duration.unsigned_abs()));
    let age = observed_wall.0.duration_since(last.0);
    let age = if age < SignedDuration::ZERO {
        Duration::ZERO
    } else {
        age.unsigned_abs()
    };
    duration.saturating_sub(age)
}

/// The current wall clock as a `MicroTime`.
fn now() -> MicroTime {
    MicroTime(Timestamp::now())
}

/// `duration` in whole seconds, saturating into `i32`.
fn duration_seconds(duration: Duration) -> i32 {
    i32::try_from(duration.as_secs().max(1)).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use kube::core::Status;

    use super::*;

    /// An in-memory `Lease` "API server": it enforces `resourceVersion` the way the real one does,
    /// so a stale write is a `409` and never silently overwrites another replica.
    #[derive(Default)]
    struct FakeLeaseApi {
        lease: Mutex<Option<Lease>>,
        version: AtomicUsize,
        /// Every `replace` that was attempted, for assertions.
        replaces: Mutex<Vec<String>>,
        /// When set, every call fails with this status code.
        fail_with: AtomicUsize,
    }

    impl FakeLeaseApi {
        fn holder(&self) -> Option<String> {
            let lease = self.lock();
            lease
                .as_ref()
                .and_then(|lease| lease.spec.as_ref())
                .and_then(|spec| spec.holder_identity.clone())
        }

        fn transitions(&self) -> i32 {
            let lease = self.lock();
            lease
                .as_ref()
                .and_then(|lease| lease.spec.as_ref())
                .and_then(|spec| spec.lease_transitions)
                .unwrap_or_default()
        }

        fn duration(&self) -> Option<i32> {
            let lease = self.lock();
            lease
                .as_ref()
                .and_then(|lease| lease.spec.as_ref())
                .and_then(|spec| spec.lease_duration_seconds)
        }

        /// The name the stored `Lease` carries.
        fn name(&self) -> Option<String> {
            self.lock()
                .as_ref()
                .and_then(|lease| lease.metadata.name.clone())
        }

        fn replaces(&self) -> usize {
            self.replaces.lock().expect("replaces lock").len()
        }

        fn lock(&self) -> MutexGuard<'_, Option<Lease>> {
            self.lease.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Installs a lease held by `holder`, renewed `age` ago.
        fn seed(&self, holder: &str, age: Duration, duration_seconds: i32) {
            self.install(
                holder,
                -i64::try_from(age.as_secs()).unwrap_or(i64::MAX),
                duration_seconds,
            );
        }

        /// Installs a lease held by `holder`, renewed `ahead` in the **future** (a leader whose
        /// clock runs ahead of this replica's).
        fn seed_ahead(&self, holder: &str, ahead: Duration, duration_seconds: i32) {
            self.install(
                holder,
                i64::try_from(ahead.as_secs()).unwrap_or(i64::MAX),
                duration_seconds,
            );
        }

        /// Installs a lease whose `renewTime` is `offset` seconds away from now.
        fn install(&self, holder: &str, offset: i64, duration_seconds: i32) {
            let renew = MicroTime(Timestamp::now() + SignedDuration::from_secs(offset));
            let lease = Lease {
                metadata: ObjectMeta {
                    name: Some(DEFAULT_LEASE_NAME.to_owned()),
                    namespace: Some(ferriscd_crd::CONTROL_PLANE_NAMESPACE.to_owned()),
                    resource_version: Some(self.next_version()),
                    ..ObjectMeta::default()
                },
                spec: Some(LeaseSpec {
                    holder_identity: Some(holder.to_owned()),
                    lease_duration_seconds: Some(duration_seconds),
                    acquire_time: Some(renew.clone()),
                    renew_time: Some(renew),
                    lease_transitions: Some(1),
                    ..LeaseSpec::default()
                }),
            };
            *self.lock() = Some(lease);
        }

        /// Sum of the codes configured for the next responses.
        fn code(&self) -> usize {
            self.fail_with.load(Ordering::SeqCst)
        }

        fn next_version(&self) -> String {
            self.version.fetch_add(1, Ordering::SeqCst).to_string()
        }
    }

    /// A `kube::Error` carrying `code`.
    fn api_error(code: u16) -> kube::Error {
        kube::Error::Api(Box::new(Status {
            code,
            message: format!("scripted {code}"),
            reason: "Conflict".to_owned(),
            ..Status::default()
        }))
    }

    impl LeaseApi for FakeLeaseApi {
        fn get<'a>(
            &'a self,
            _name: &'a str,
        ) -> futures::future::BoxFuture<'a, Result<Option<Lease>, kube::Error>> {
            Box::pin(async move {
                match self.code() {
                    0 => Ok(self.lock().clone()),
                    code => Err(api_error(code as u16)),
                }
            })
        }

        fn create<'a>(
            &'a self,
            mut lease: Lease,
        ) -> futures::future::BoxFuture<'a, Result<Lease, kube::Error>> {
            Box::pin(async move {
                match self.code() {
                    0 => {}
                    code => return Err(api_error(code as u16)),
                }
                let mut current = self.lock();
                if current.is_some() {
                    // `AlreadyExists` (409, as the API server reports it).
                    return Err(api_error(409));
                }
                lease.metadata.resource_version = Some(self.next_version());
                *current = Some(lease.clone());
                Ok(lease)
            })
        }

        fn replace<'a>(
            &'a self,
            _name: &'a str,
            mut lease: Lease,
        ) -> futures::future::BoxFuture<'a, Result<Lease, kube::Error>> {
            Box::pin(async move {
                match self.code() {
                    0 => {}
                    code => return Err(api_error(code as u16)),
                }
                self.replaces
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(lease.resource_version().unwrap_or_default());
                let mut current = self.lock();
                let Some(existing) = current.as_ref() else {
                    return Err(api_error(404));
                };
                // Optimistic concurrency, exactly like the API server.
                if existing.resource_version() != lease.resource_version() {
                    return Err(api_error(409));
                }
                lease.metadata.resource_version = Some(self.next_version());
                *current = Some(lease.clone());
                Ok(lease)
            })
        }
    }

    fn config(identity: &str) -> LeaderElectionConfig {
        LeaderElectionConfig::new(ferriscd_crd::CONTROL_PLANE_NAMESPACE, identity)
    }

    /// The shortest legal configuration, so a test observes a lease expiry in under a second
    /// instead of sleeping through the production fifteen.
    fn fast_config(identity: &str) -> LeaderElectionConfig {
        config(identity)
            .with_lease_duration(MIN_LEASE_DURATION)
            .with_renew_interval(Duration::from_millis(100))
            .with_retry_interval(Duration::from_millis(20))
    }

    // -----------------------------------------------------------------
    // Configuration validation
    // -----------------------------------------------------------------

    #[test]
    fn the_defaults_satisfy_the_renewal_rule() {
        let config = config("pod-0");
        config.validate().expect("the defaults must be valid");
        assert_eq!(config.lease_name(), DEFAULT_LEASE_NAME);
        assert_eq!(config.namespace(), ferriscd_crd::CONTROL_PLANE_NAMESPACE);
        assert!(
            config.renew_interval() * 3 < config.lease_duration(),
            "renew_interval must be strictly less than a third of the lease duration"
        );
    }

    /// **Trap guard:** a renewal interval that is not well inside the lease duration would make a
    /// healthy leader oscillate between leadership and standby.
    #[test]
    fn a_renewal_interval_that_is_not_inside_the_lease_is_rejected() {
        for renew in [
            Duration::from_secs(5),
            Duration::from_secs(6),
            Duration::from_secs(50),
        ] {
            let config = config("pod-0").with_renew_interval(renew);
            let err = config.validate().expect_err("must be rejected");
            assert!(
                matches!(err, LeaderElectionConfigError::RenewIntervalTooLong { .. }),
                "{renew:?}: {err:?}"
            );
            assert!(err.to_string().contains("third"), "{err}");
        }
        // Exactly a third is still refused (strictly less is required).
        let boundary = config("pod-0")
            .with_lease_duration(Duration::from_secs(6))
            .with_renew_interval(Duration::from_secs(2));
        assert!(boundary.validate().is_err());
    }

    #[test]
    fn an_invalid_lease_configuration_is_rejected() {
        assert!(matches!(
            config("  ").validate(),
            Err(LeaderElectionConfigError::EmptyIdentity)
        ));
        assert!(matches!(
            LeaderElectionConfig::new("  ", "pod-0").validate(),
            Err(LeaderElectionConfigError::EmptyNamespace)
        ));
        assert!(matches!(
            config("pod-0").with_lease_name("Not A Name").validate(),
            Err(LeaderElectionConfigError::InvalidLeaseName { .. })
        ));
        assert!(
            config("pod-0")
                .with_lease_duration(Duration::from_millis(500))
                .validate()
                .is_err(),
            "a sub-second lease has no room for three renewals"
        );
        assert!(
            config("pod-0")
                .with_renew_interval(Duration::ZERO)
                .validate()
                .is_err()
        );
        assert!(
            config("pod-0")
                .with_retry_interval(Duration::ZERO)
                .validate()
                .is_err()
        );
        // The elector refuses to be built from an invalid configuration at all.
        let api = Arc::new(FakeLeaseApi::default());
        let err = LeaseElector::new(api, config("pod-0").with_lease_duration(Duration::ZERO))
            .expect_err("an invalid config must not build an elector");
        assert!(matches!(
            err,
            LeaderElectionConfigError::LeaseDurationTooShort { .. }
        ));
    }

    #[test]
    fn the_acquisition_backoff_is_bounded() {
        let config = config("pod-0");
        assert_eq!(config.retry_delay(0), DEFAULT_RETRY_INTERVAL);
        let delays: Vec<Duration> = (0..40).map(|attempt| config.retry_delay(attempt)).collect();
        assert!(
            delays.iter().all(|delay| *delay <= MAX_RETRY_INTERVAL),
            "the backoff must never exceed {MAX_RETRY_INTERVAL:?}: {delays:?}"
        );
        assert_eq!(
            *delays.last().expect("non-empty"),
            MAX_RETRY_INTERVAL,
            "it must actually saturate"
        );
        assert!(
            delays[2] > delays[0],
            "it must grow before it saturates: {delays:?}"
        );
    }

    // -----------------------------------------------------------------
    // Acquire / renew / lose / release
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn the_first_replica_acquires_an_absent_lease() {
        let api = Arc::new(FakeLeaseApi::default());
        let elector = LeaseElector::new(api.clone(), config("pod-0")).expect("valid config");

        assert_eq!(
            elector.try_acquire().await.expect("acquire"),
            AcquireOutcome::Acquired
        );
        assert!(elector.is_leader());
        assert_eq!(api.holder().as_deref(), Some("pod-0"));
        assert_eq!(
            api.duration(),
            Some(duration_seconds(config("pod-0").lease_duration())),
            "the configured duration is written"
        );
        assert_eq!(
            api.transitions(),
            0,
            "the first acquisition creates the lease with zero transitions"
        );

        // Renewing keeps the same identity and bumps the resourceVersion.
        elector.renew().await.expect("renew");
        assert_eq!(api.holder().as_deref(), Some("pod-0"));
        assert!(elector.is_leader());
    }

    /// **No split-brain on a stale `resourceVersion`:** the second replica's write is rejected, and
    /// it becomes a standby instead of overwriting the live holder.
    #[tokio::test]
    async fn a_second_replica_with_a_stale_resource_version_never_takes_a_live_lease() {
        let api = Arc::new(FakeLeaseApi::default());
        let leader = LeaseElector::new(api.clone(), config("pod-0")).expect("config");
        leader.try_acquire().await.expect("acquire");

        // A write by a replica that read the lease *before* the leader's last renewal: exactly the
        // shape the API server rejects with `409 Conflict`.
        let mut stale = api.lock().clone().expect("a lease exists");
        stale.spec.as_mut().expect("spec").holder_identity = Some("pod-1".to_owned());
        stale.metadata.resource_version = Some("stale-resource-version".to_owned());
        let err = api
            .replace(DEFAULT_LEASE_NAME, stale)
            .await
            .expect_err("a stale resourceVersion must be rejected");
        assert!(is_conflict(&err), "{err:?}");

        // Through the elector: the standby is told who holds the lease and writes nothing.
        let standby = LeaseElector::new(api.clone(), config("pod-1")).expect("config");
        assert_eq!(
            standby.try_acquire().await.expect("acquire attempt"),
            AcquireOutcome::Held {
                holder: "pod-0".to_owned()
            }
        );
        assert!(!standby.is_leader());
        assert!(leader.is_leader());
        assert_eq!(api.holder().as_deref(), Some("pod-0"));

        // And a conflicted renewal from a *former* holder reports the loss rather than forcing the
        // write through: the re-read finds another holder.
        api.seed("pod-1", Duration::from_secs(0), 15);
        let err = leader.renew().await.expect_err("the lease is not ours");
        assert!(err.is_lost(), "{err:?}");
        assert!(!leader.is_leader());
        assert_eq!(api.holder().as_deref(), Some("pod-1"));
    }

    #[tokio::test]
    async fn an_expired_lease_is_taken_over_by_a_standby() {
        let api = Arc::new(FakeLeaseApi::default());
        // The previous holder renewed 10s ago and had a 5s lease: expired.
        api.seed("pod-dead", Duration::from_secs(10), 5);

        let standby = LeaseElector::new(api.clone(), fast_config("pod-1")).expect("config");
        assert_eq!(
            standby.try_acquire().await.expect("takeover"),
            AcquireOutcome::Acquired
        );
        assert_eq!(api.holder().as_deref(), Some("pod-1"));
        assert_eq!(
            api.transitions(),
            2,
            "a takeover increments leaseTransitions, so an operator can see the failover"
        );
    }

    #[tokio::test]
    async fn a_live_lease_is_never_stolen() {
        let api = Arc::new(FakeLeaseApi::default());
        // A fresh lease with a 15s duration: not expired.
        api.seed("pod-0", Duration::from_secs(1), 15);
        let standby = LeaseElector::new(api.clone(), fast_config("pod-1")).expect("config");
        assert_eq!(
            standby.try_acquire().await.expect("attempt"),
            AcquireOutcome::Held {
                holder: "pod-0".to_owned()
            }
        );
        assert!(
            api.replaces() == 0,
            "a live lease must not receive a single write"
        );
        assert_eq!(api.holder().as_deref(), Some("pod-0"));
    }

    #[tokio::test]
    async fn renewal_fails_lost_when_another_replica_took_the_lease() {
        let api = Arc::new(FakeLeaseApi::default());
        let elector = LeaseElector::new(api.clone(), config("pod-0")).expect("config");
        elector.try_acquire().await.expect("acquire");

        // Another replica takes the lease over (it expired from *its* point of view).
        api.seed("pod-1", Duration::from_secs(0), 15);

        let err = elector.renew().await.expect_err("the lease is not ours");
        assert!(err.is_lost(), "{err:?}");
        assert!(!err.is_retryable());
        assert!(!elector.is_leader(), "the local state must clear on loss");
        assert!(
            err.to_string().contains("pod-1"),
            "the error names the new holder: {err}"
        );
    }

    #[tokio::test]
    async fn a_graceful_release_clears_the_holder_for_a_fast_takeover() {
        let api = Arc::new(FakeLeaseApi::default());
        let leader = LeaseElector::new(api.clone(), config("pod-0")).expect("config");
        leader.try_acquire().await.expect("acquire");

        leader.release().await.expect("release");
        assert!(!leader.is_leader());
        assert_eq!(
            api.holder(),
            None,
            "the holder is cleared, so no replica has to wait for the lease to expire"
        );
        assert_eq!(
            api.duration(),
            Some(1),
            "the duration is shortened so a standby can take over immediately"
        );

        // The standby takes over without waiting for the old duration.
        let standby = LeaseElector::new(api.clone(), fast_config("pod-1")).expect("config");
        assert_eq!(
            standby.try_acquire().await.expect("takeover"),
            AcquireOutcome::Acquired
        );
        assert_eq!(api.holder().as_deref(), Some("pod-1"));

        // Releasing again (nothing held) is a no-op, never an error.
        leader.release().await.expect("release is idempotent");
    }

    #[tokio::test]
    async fn an_api_failure_is_retryable_and_never_lost() {
        let api = Arc::new(FakeLeaseApi::default());
        let elector = LeaseElector::new(api.clone(), config("pod-0")).expect("config");
        elector.try_acquire().await.expect("acquire");

        api.fail_with.store(500, Ordering::SeqCst);
        let err = elector.renew().await.expect_err("the API server is down");
        assert!(err.is_retryable(), "{err:?}");
        assert!(!err.is_lost());
        assert!(
            elector.is_leader(),
            "a transient failure is not yet a lost lease (the deadline decides)"
        );

        // The acquire path is retryable too.
        let standby = LeaseElector::new(api.clone(), fast_config("pod-1")).expect("config");
        let err = standby
            .try_acquire()
            .await
            .expect_err("the API server is down");
        assert!(err.is_retryable(), "{err:?}");
    }

    // -----------------------------------------------------------------
    // The token / leadership contract
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn the_leadership_token_is_cancelled_when_the_lease_is_lost() {
        let api = Arc::new(FakeLeaseApi::default());
        let election = LeaderElection::new(Arc::new(
            LeaseElector::new(api.clone(), fast_config("pod-0")).expect("config"),
        ));
        let stop = CancellationToken::new();
        let leadership = election
            .campaign(&stop)
            .await
            .expect("campaign")
            .expect("leadership is available");

        // Someone else takes the lease: the renewal fails immediately.
        api.seed("pod-1", Duration::from_secs(0), 15);
        let outcome = tokio::time::timeout(Duration::from_secs(5), leadership.hold(&stop))
            .await
            .expect("hold must return once the lease is lost")
            .expect("hold");
        assert_eq!(outcome, HoldOutcome::Lost);
        assert!(
            leadership.token().is_cancelled(),
            "losing the lease must cancel reconciliation immediately"
        );
        stop.cancel();
    }

    /// **`T17.1`:** the HA readiness shortcut is signalled only after a *healthy foreign leader* is
    /// observed, and never while this replica itself holds the lease.
    #[tokio::test]
    async fn a_standby_observer_fires_only_while_a_healthy_foreign_leader_holds_the_lease() {
        let api = Arc::new(FakeLeaseApi::default());
        api.seed("pod-0", Duration::from_secs(0), 30);
        let election = Arc::new(LeaderElection::new(Arc::new(
            LeaseElector::new(api.clone(), fast_config("pod-1")).expect("config"),
        )));
        let stop = CancellationToken::new();
        let observed = Arc::new(AtomicUsize::new(0));

        let campaign = {
            let election = election.clone();
            let stop = stop.clone();
            let observed = observed.clone();
            tokio::spawn(async move {
                election
                    .campaign_with(&stop, move || {
                        observed.fetch_add(1, Ordering::SeqCst);
                    })
                    .await
            })
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        while observed.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            observed.load(Ordering::SeqCst) >= 1,
            "the standby must observe the healthy foreign leader"
        );

        // The leader's lease expires: this replica acquires it and must not keep the standby
        // shortcut armed while its own controller watches are cold.
        api.seed("pod-0", Duration::from_secs(30), 30);
        let leadership = tokio::time::timeout(Duration::from_secs(5), campaign)
            .await
            .expect("campaign must finish once the lease is available")
            .expect("campaign task must not panic")
            .expect("campaign must not fail")
            .expect("this replica must acquire the lease");
        stop.cancel();
        drop(leadership);

        assert_eq!(
            observed.load(Ordering::SeqCst),
            1,
            "the standby observer must not fire for this replica's own leadership"
        );
    }

    #[tokio::test]
    async fn a_graceful_stop_cancels_the_token_and_releases_the_lease() {
        let api = Arc::new(FakeLeaseApi::default());
        let election = LeaderElection::new(Arc::new(
            LeaseElector::new(api.clone(), fast_config("pod-0")).expect("config"),
        ));
        let stop = CancellationToken::new();
        let leadership = election
            .campaign(&stop)
            .await
            .expect("campaign")
            .expect("leadership");
        assert_eq!(api.holder().as_deref(), Some("pod-0"));

        stop.cancel();
        let outcome = tokio::time::timeout(Duration::from_secs(5), leadership.hold(&stop))
            .await
            .expect("hold returns on stop")
            .expect("hold");
        assert_eq!(outcome, HoldOutcome::Released);
        assert!(leadership.token().is_cancelled());
        assert_eq!(
            api.holder(),
            None,
            "a graceful stop releases the lease instead of leaving it to expire"
        );
    }

    /// A standby takes over when the leader is gone (its lease expired), and a cancel while standing
    /// by does not pretend to be leadership.
    #[tokio::test]
    async fn a_standby_takes_over_after_the_leader_expires() {
        let api = Arc::new(FakeLeaseApi::default());
        // The dead leader's lease expires 20ms from now.
        api.seed("pod-dead", Duration::from_millis(0), 0);

        let election = LeaderElection::new(Arc::new(
            LeaseElector::new(api.clone(), fast_config("pod-1")).expect("config"),
        ));
        let stop = CancellationToken::new();
        let leadership = tokio::time::timeout(Duration::from_secs(5), election.campaign(&stop))
            .await
            .expect("campaign must resolve")
            .expect("campaign")
            .expect("a dead leader's lease is taken over");
        assert_eq!(api.holder().as_deref(), Some("pod-1"));
        assert!(!leadership.token().is_cancelled());
        stop.cancel();
    }

    #[tokio::test]
    async fn a_cancelled_campaign_returns_without_leadership() {
        let api = Arc::new(FakeLeaseApi::default());
        // A live lease held by somebody else: acquisition can only time out or be cancelled.
        api.seed("pod-0", Duration::from_secs(0), 3600);
        let election = LeaderElection::new(Arc::new(
            LeaseElector::new(api.clone(), fast_config("pod-1")).expect("config"),
        ));
        let stop = CancellationToken::new();
        let campaign = election.campaign(&stop);
        stop.cancel();
        let outcome = tokio::time::timeout(Duration::from_secs(5), campaign)
            .await
            .expect("a cancelled campaign returns")
            .expect("campaign");
        assert!(
            outcome.is_none(),
            "a cancelled standby never claims leadership"
        );
        assert_eq!(api.holder().as_deref(), Some("pod-0"));
    }

    /// The whole point of `Leadership::hold`: an unrenewable lease ends the term once the lease
    /// could have been taken over, rather than continuing to reconcile without authority.
    #[tokio::test]
    async fn an_unrenewable_lease_ends_the_term_at_its_deadline() {
        let api = Arc::new(FakeLeaseApi::default());
        let config = fast_config("pod-0");
        let deadline = config.lost_deadline();
        let election = LeaderElection::new(Arc::new(
            LeaseElector::new(api.clone(), config).expect("config"),
        ));
        let stop = CancellationToken::new();
        let leadership = election
            .campaign(&stop)
            .await
            .expect("campaign")
            .expect("leadership");

        api.fail_with.store(503, Ordering::SeqCst);
        let started = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(10), leadership.hold(&stop))
            .await
            .expect("hold must give up at the deadline")
            .expect("hold");
        assert_eq!(outcome, HoldOutcome::Lost);
        assert!(leadership.token().is_cancelled());
        assert!(
            started.elapsed() >= deadline,
            "the term must last until the lease could be taken over ({deadline:?}), not longer"
        );
        stop.cancel();
    }

    /// Two electors over the same store: exactly one ends up leading, and the other keeps standing
    /// by — the split-brain shape this module exists to prevent.
    #[tokio::test]
    async fn only_one_of_two_replicas_leads() {
        let api = Arc::new(FakeLeaseApi::default());
        let first = LeaderElection::new(Arc::new(
            LeaseElector::new(api.clone(), fast_config("pod-0")).expect("config"),
        ));
        let second = LeaderElection::new(Arc::new(
            LeaseElector::new(api.clone(), fast_config("pod-1")).expect("config"),
        ));
        let stop = CancellationToken::new();

        let leader = first
            .campaign(&stop)
            .await
            .expect("campaign")
            .expect("the first replica leads");
        // The second replica cannot acquire: `campaign` would block, so the elector is asked
        // directly (bounded, no sleeping loop).
        let outcome = second.elector().try_acquire().await.expect("attempt");
        assert_eq!(
            outcome,
            AcquireOutcome::Held {
                holder: "pod-0".to_owned()
            }
        );
        assert!(!second.elector().is_leader());
        assert_eq!(api.holder().as_deref(), Some("pod-0"));
        drop(leader);
        stop.cancel();
    }

    #[test]
    fn the_error_and_debug_surfaces_stay_operator_readable() {
        let err = LeaderElectionError::Lost {
            lease: DEFAULT_LEASE_NAME.to_owned(),
            namespace: ferriscd_crd::CONTROL_PLANE_NAMESPACE.to_owned(),
            holder: "pod-1".to_owned(),
        };
        assert!(err.to_string().contains(DEFAULT_LEASE_NAME), "{err}");
        assert!(err.to_string().contains("pod-1"), "{err}");
        assert!(err.is_lost());

        let api = Arc::new(FakeLeaseApi::default());
        let elector = LeaseElector::new(api, config("pod-0")).expect("config");
        let debug = format!("{elector:?}");
        assert!(debug.contains("pod-0"), "{debug}");
        assert!(debug.contains("leader: false"), "{debug}");
        assert!(
            remaining_at(&LeaseSpec::default(), now()).is_zero(),
            "a lease with no timestamps cannot be shown to be alive"
        );
    }

    /// **Finding M2:** validation and use must agree — the `Lease` name is trimmed where it is set,
    /// so a padded flag value validates *and* addresses the same `Lease`.
    #[tokio::test]
    async fn the_lease_name_is_trimmed_where_it_is_set() {
        let padded = config("pod-0").with_lease_name("  ferriscd-leader-custom  ");
        assert_eq!(padded.lease_name(), "ferriscd-leader-custom");
        padded.validate().expect("the trimmed name is valid");

        let api = Arc::new(FakeLeaseApi::default());
        let elector = LeaseElector::new(api.clone(), padded).expect("config");
        elector.try_acquire().await.expect("acquire");
        assert_eq!(
            api.name().as_deref(),
            Some("ferriscd-leader-custom"),
            "the written Lease carries the trimmed name, not the padded flag value"
        );

        // Whitespace-only is still invalid (trimming must not turn it into a usable name).
        assert!(matches!(
            config("pod-0").with_lease_name("   ").validate(),
            Err(LeaderElectionConfigError::InvalidLeaseName { .. })
        ));
    }

    /// **Finding M3:** expiry is measured on the local monotonic clock, so a leader whose
    /// `renewTime` is in the *future* (its clock runs ahead) cannot keep its lease alive forever.
    #[tokio::test]
    async fn a_future_renew_time_does_not_block_takeover() {
        // The dead leader's clock is an hour ahead of ours, so a wall-clock comparison would see a
        // negative age and never expire the lease.
        let ahead = Duration::from_secs(3600);
        let api = Arc::new(FakeLeaseApi::default());
        api.seed_ahead("pod-dead", ahead, 3);

        let base = Instant::now();
        let now = Arc::new(Mutex::new(base));
        let clock = MonotonicClock({
            let now = now.clone();
            Arc::new(move || *now.lock().unwrap_or_else(PoisonError::into_inner))
        });
        let standby = LeaseElector::new(api.clone(), fast_config("pod-1"))
            .expect("config")
            .with_clock(clock);

        // The first observation records the lease: one full duration of local time is left.
        assert_eq!(
            standby.try_acquire().await.expect("attempt"),
            AcquireOutcome::Held {
                holder: "pod-dead".to_owned()
            },
            "a lease renewed in the future is not taken over on sight"
        );
        assert_eq!(api.replaces(), 0, "a live-looking lease is never written");

        // One lease duration of local time later, the same `renewTime` is expired: the takeover
        // does not wait for the leader's clock to catch up with ours.
        let duration = Duration::from_secs(3);
        *now.lock().unwrap_or_else(PoisonError::into_inner) = base + duration;
        assert_eq!(
            standby.try_acquire().await.expect("takeover"),
            AcquireOutcome::Acquired
        );
        assert_eq!(api.holder().as_deref(), Some("pod-1"));

        // A *new* `renewTime` (a live leader renewing) resets the local window instead of
        // inheriting the elapsed time of the previous observation.
        let api = Arc::new(FakeLeaseApi::default());
        api.seed_ahead("pod-0", ahead, 3);
        let now = Arc::new(Mutex::new(base));
        let clock = MonotonicClock({
            let now = now.clone();
            Arc::new(move || *now.lock().unwrap_or_else(PoisonError::into_inner))
        });
        let standby = LeaseElector::new(api.clone(), fast_config("pod-1"))
            .expect("config")
            .with_clock(clock);
        assert!(matches!(
            standby.try_acquire().await.expect("attempt"),
            AcquireOutcome::Held { .. }
        ));
        *now.lock().unwrap_or_else(PoisonError::into_inner) = base + duration;
        // The leader renewed 2 s into that window.
        api.seed_ahead("pod-0", ahead - Duration::from_secs(2), 3);
        assert!(
            matches!(
                standby.try_acquire().await.expect("attempt"),
                AcquireOutcome::Held { .. }
            ),
            "a fresh renewal restarts the local window"
        );
        assert_eq!(api.holder().as_deref(), Some("pod-0"));
    }

    /// The wall-clock half of the same rule: a future `renewTime` leaves a full duration to run,
    /// never a negative (i.e. infinite) one.
    #[test]
    fn a_future_renew_time_leaves_a_full_duration() {
        let ahead = MicroTime(Timestamp::now() + SignedDuration::from_secs(600));
        let spec = LeaseSpec {
            lease_duration_seconds: Some(15),
            renew_time: Some(ahead),
            ..LeaseSpec::default()
        };
        assert_eq!(
            remaining_at(&spec, now()),
            Duration::from_secs(15),
            "a clock-skewed renewTime is clamped to \"renewed just now\""
        );

        // An expired lease has nothing left, and a duration-less lease is never alive.
        let stale = MicroTime(Timestamp::now() - SignedDuration::from_secs(60));
        let expired = LeaseSpec {
            lease_duration_seconds: Some(15),
            renew_time: Some(stale),
            ..LeaseSpec::default()
        };
        assert!(remaining_at(&expired, now()).is_zero());
        let no_duration = LeaseSpec {
            lease_duration_seconds: Some(0),
            renew_time: Some(MicroTime(Timestamp::now())),
            ..LeaseSpec::default()
        };
        assert!(remaining_at(&no_duration, now()).is_zero());
        assert!(remaining_at(&LeaseSpec::default(), now()).is_zero());
    }
}

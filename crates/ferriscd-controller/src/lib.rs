//! FerrisCD Kubernetes controller runtime: reconciliation loop, watch predicates,
//! dynamic discovery cache, finalizer lifecycle, and graceful shutdown.

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use ferriscd_crd::Application;
use kube::{Api, Client, ResourceExt};

pub mod cluster_manager;
pub mod controller;
pub mod credentials;
pub mod discovery;
pub mod dry_run;
pub mod hooks;
pub mod impersonation;
pub mod leader_election;
pub mod live_state;
pub mod predicate;
pub mod project;
pub mod prune;
pub mod reconcile;
pub mod scope;
pub mod sharding;
pub mod sync;
pub mod sync_executor;
pub mod sync_recovery;
pub mod waves;

pub use cluster_manager::{
    ClusterAuth, ClusterChange, ClusterError, ClusterHandle, ClusterHandleBuilder, ClusterManager,
    ClusterName, ClusterOptions, ClusterSecret, ClusterSecretEvent, ClusterSecretSource,
    ClusterSource, ClusterTarget, ClusterWatchError, IN_CLUSTER, KEY_BEARER_TOKEN, KEY_CA_CRT,
    KEY_INSECURE_SKIP_TLS_VERIFY, KEY_KUBECONFIG, KEY_SERVER, KEY_TLS_CRT, KEY_TLS_KEY,
    KubeClusterBuilder, SECRET_TYPE_CLUSTER, SecretClusterSource,
};
pub use controller::{
    APPLICATION_NAMESPACES_ENV, ApplicationControllers, BackoffTracker, ConfigError,
    ControllerConfig, DEFAULT_CONCURRENCY, DEFAULT_DRAIN_TIMEOUT, FailureClass,
    NamespacedController, RETRY_BASE_DELAY, RETRY_MAX_DELAY, ReadinessError, TERMINAL_DELAY,
    build_controllers,
};
pub use credentials::{
    CredentialError, CredentialSource, CredentialTemplate, KEY_KNOWN_HOSTS, KEY_PASSWORD,
    KEY_SSH_PRIVATE_KEY, KEY_TOKEN, KEY_URL, KEY_USERNAME, SECRET_TYPE_LABEL,
    SECRET_TYPE_REPOSITORY, SecretCredentialStore, match_credentials, normalize_repo_url,
    templates_from_secrets,
};
pub use discovery::{CachedDiscovery, DiscoveryCache, DiscoveryError, ScopeLookup};
pub use dry_run::{
    DRY_RUN_CONCURRENCY, DryRunApi, DryRunError, DryRunEvaluator, DryRunFuture, DryRunOutcome,
    DryRunTarget, DynamicDryRunApi, MAX_FIELD_CONFLICTS, parse_conflict_status,
};
pub use ferriscd_engine::policy::{
    ALL_NAMESPACES, AppProjectPolicy, ApplicationNamespaces, ApplicationScope,
    ApplicationScopeError, PolicyError,
};
pub use hooks::{HookCluster, HookRun, hooks_for_step, run_step};
pub use impersonation::{
    ClusterAccess, ClusterIdentity, FORBIDDEN_GROUP, GROUP_AUTHENTICATED, GROUP_SERVICE_ACCOUNTS,
    IMPERSONATE_EXTRA_PREFIX, IMPERSONATE_GROUP_HEADER, IMPERSONATE_UID_HEADER,
    IMPERSONATE_USER_HEADER, ImpersonatingAccess, Impersonation, ImpersonationError,
    ImpersonationLayer, ImpersonationPool, ImpersonationService, ImpersonationSource,
    MAX_CACHED_IDENTITIES,
};
pub use leader_election::{
    AcquireOutcome, DEFAULT_LEASE_DURATION, DEFAULT_LEASE_NAME, DEFAULT_RENEW_INTERVAL,
    DEFAULT_RETRY_INTERVAL, HoldOutcome, KubeLeaseApi, LeaderElection, LeaderElectionConfig,
    LeaderElectionConfigError, LeaderElectionError, Leadership, LeaseApi, LeaseElector,
    MAX_RETRY_INTERVAL, MIN_LEASE_DURATION,
};
pub use live_state::{
    ClusterStateReader, DynamicApiSource, FetchRequest, LiveObjectSource, LiveState,
    LiveStateError, TrackingOwner,
};
pub use predicate::{ApplicationPredicate, PredicateTracker, composite_hash};
pub use project::{ApiProjectSource, ProjectSource};
pub use prune::{
    OwnershipVerifiedPruner, PruneResult, ResourcePruner, RetainReason, prune_opted_out, prune_rail,
};
pub use reconcile::{
    ApiStatusWriter, ApplyOutcome, CleanupDisposition, CleanupMode, CleanupOutcome,
    ControllerError, DiffPreview, FINALIZER, ReconcileContext, ReconcileError, StatusWriter,
    SyncPipeline,
};
pub use scope::{ClusterNamespacePolicy, InBundleCrd, ScopeError, normalize_scopes};
pub use sharding::{
    SHARD_ID_ENV, SHARD_LEASE_PREFIX, ShardOptions, ShardPredicate, Sharding, ShardingConfigError,
    TOTAL_SHARDS_ENV, from_env_values, from_values, shard_lease_name, shard_of, shard_predicate,
};
pub use sync::{
    ApplicationPatch, Applier, ApplyRequest, CreateRequest, DeleteOutcome, DeleteRequest,
    DynamicApiApplier, InventorySyncPipeline, PENDING_REQUEUE, PROGRESSING_REQUEUE,
    REASON_SYNC_IN_PROGRESS,
};
pub use sync_executor::{
    ActionFailure, CrdReadiness, CrdStatusReader, DEFAULT_CRD_ESTABLISH_TIMEOUT,
    DEFAULT_CRD_POLL_INTERVAL, ESTABLISHED_CONDITION, ExecutionPolicy, ExecutionReport,
    LiveCrdStatusReader, NAMES_ACCEPTED_CONDITION, SyncExecutor, crd_readiness, is_established,
    namespace_resource, resolve_desired_target, resolve_key_target,
};
pub use sync_recovery::{
    DEFAULT_REPLACE_INTERVAL, DEFAULT_REPLACE_TIMEOUT, IMMUTABLE_MESSAGE_MARKERS,
    REPLACE_ANNOTATION, REPLACE_HINT, Recovery, ReplacePolicy, ReplaceRecovery, TAKEOVER_FIELD,
    classify_apply_failure, conflicting_managers, is_immutable_field_error, log_takeover,
};
pub use waves::{BundleWaves, merge_hook_records, step_health};

/// Environment variable selecting the log format (`json` or `pretty`).
pub const LOG_FORMAT_ENV: &str = "FERRISCD_LOG_FORMAT";

/// Returns the controller identifier string.
#[must_use]
pub fn controller_name() -> &'static str {
    ferriscd_engine::default_field_manager()
}

/// Runtime options for [`run_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// Namespace whose `Application` objects this controller owns.
    ///
    /// `None` falls back to `FERRISCD_NAMESPACE`, then `ferriscd-system`.
    pub namespace: Option<String>,

    /// Namespaces allowed to host `Application` objects (`T12.2`).
    ///
    /// `None` falls back to `FERRISCD_APPLICATION_NAMESPACES`, then to the control-plane
    /// namespace only (the safe default). Accepts a comma-separated list or `*` for every
    /// namespace; the control-plane namespace is always watched.
    pub application_namespaces: Option<String>,

    /// Accept `file://` URLs and local filesystem paths as Git sources.
    ///
    /// Off by default: production only allows `https://`/`ssh://`/SCP-style remotes, so an
    /// `Application` can never read the controller pod's filesystem. Tests and local `kind`
    /// demos must opt in explicitly (see `docs/lessons/06-inventory-tracking-and-live-state.md`).
    pub allow_local_repos: bool,

    /// Directory holding the Git mirror cache and materialized worktrees.
    ///
    /// `None` uses `<system temp dir>/ferriscd-repos`. In a cluster this should be an
    /// `emptyDir` mounted by the Deployment.
    pub work_root: Option<std::path::PathBuf>,

    /// Accept `insecureSkipTLSVerify` / plaintext `http://` cluster registrations (`T13.1`).
    ///
    /// Off by default: a remote cluster's manifests and credentials would otherwise cross an
    /// unverified connection, where anything on the path can read and rewrite them.
    pub allow_insecure_clusters: bool,

    /// Run `coordination.k8s.io/v1` `Lease` leader election (`T13.2`).
    ///
    /// `None` (the default) keeps the pre-Phase-13 single-replica behaviour: exactly one controller
    /// replica may run. Setting it makes this replica an active/standby candidate, which is what
    /// allows `replicas: 2` without two reconcilers fighting over the same objects.
    pub leader_election: Option<LeaderElectionOptions>,

    /// Deterministic `Application` sharding (`T13.3`).
    ///
    /// Both halves unset (the default) means "no sharding": this replica reconciles every
    /// `Application` in its watched namespaces, exactly as before Phase 13. When both are set the
    /// replica reconciles only its shard, and it **must** also enable leader election — see
    /// [`RunOptions::shard_config`].
    pub shard: ShardOptions,
}

/// The `T13.2` knobs [`RunOptions::leader_election`] carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaderElectionOptions {
    /// `Lease` name (`ferriscd-controller-leader` by default).
    pub lease_name: Option<String>,
    /// Lease duration; `None` keeps [`leader_election::DEFAULT_LEASE_DURATION`].
    pub lease_duration: Option<Duration>,
    /// Renewal interval; `None` keeps [`leader_election::DEFAULT_RENEW_INTERVAL`].
    pub renew_interval: Option<Duration>,
    /// This replica's identity (`HOSTNAME`, then the pid, by default).
    pub identity: Option<String>,
}

/// The validated `T13.2`/`T13.3` startup plan for this replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaPlan {
    /// The leader-election configuration, or `None` when election is disabled.
    pub leader_election: Option<LeaderElectionConfig>,
    /// This replica's shard, or `None` when sharding is off.
    pub shard: Option<Sharding>,
}

/// Errors raised while resolving a [`RunOptions::ha_plan`].
///
/// Both halves are terminal: a controller that switched on with an unusable lease/shard
/// configuration would either oscillate between leaders or reconcile the wrong slice of the fleet.
#[derive(Debug, thiserror::Error)]
pub enum RunConfigError {
    /// The leader-election timings or `Lease` name are unusable.
    #[error(transparent)]
    LeaderElection(#[from] LeaderElectionConfigError),

    /// The sharding flags are unusable, or contradict the election mode (`T13.3`).
    #[error(transparent)]
    Sharding(#[from] ShardingConfigError),
}

impl RunOptions {
    /// Validates and resolves leader election **and** sharding together.
    ///
    /// They are resolved in one place because they constrain each other (`T13.3`): sharding requires
    /// election and *derives* the `Lease` name, so a plan that owns one without the other must be
    /// impossible to construct.
    ///
    /// # Errors
    ///
    /// [`RunConfigError::Sharding`] for a half-specified or out-of-range shard, sharding without
    /// leader election, or sharding combined with a `Lease` name other than the per-shard one;
    /// [`RunConfigError::LeaderElection`] for timings that would make a healthy leader lose its
    /// lease (see [`LeaderElectionConfig::validate`]).
    pub fn ha_plan(&self, namespace: &str) -> Result<HaPlan, RunConfigError> {
        // Sharding first: it decides the lease name, and a half-configured shard fleet must fail
        // before anything is built from the lease configuration.
        let shard = self.shard_config()?;
        let Some(options) = self.leader_election.as_ref() else {
            return Ok(HaPlan {
                leader_election: None,
                shard,
            });
        };
        let identity = options
            .identity
            .clone()
            .or_else(|| std::env::var("HOSTNAME").ok())
            .filter(|identity| !identity.trim().is_empty())
            .unwrap_or_else(|| format!("ferriscd-controller-{}", std::process::id()));
        let mut config = LeaderElectionConfig::new(namespace, identity);
        if let Some(lease_name) = &options.lease_name {
            config = config.with_lease_name(lease_name.clone());
        }
        if let Some(lease_duration) = options.lease_duration {
            config = config.with_lease_duration(lease_duration);
        }
        if let Some(renew_interval) = options.renew_interval {
            config = config.with_renew_interval(renew_interval);
        }
        if let Some(shard) = shard {
            // The per-shard name always wins: `shard_config` already refused every other name, and
            // re-applying it here means the lease the elector writes is the one the shard named,
            // never the single-leader default (`ferriscd-controller-leader`).
            config = config.with_lease_name(shard.lease_name());
        }
        config.validate()?;
        Ok(HaPlan {
            leader_election: Some(config),
            shard,
        })
    }

    /// Resolves this replica's shard (`T13.3`), or `None` when sharding is off.
    ///
    /// Also refuses the two combinations that cannot be deployed safely:
    ///
    /// * sharding without leader election — two replicas given the same `--shard-id` would both
    ///   reconcile that shard (double applies, racing prunes), and
    /// * sharding with any `Lease` other than its own `ferriscd-leader-shard-<id>` — one shared
    ///   `Lease` makes exactly one replica a leader, so the other shards would never be reconciled
    ///   while their replicas stand by.
    ///
    /// # Errors
    ///
    /// [`ShardingConfigError`] for an incomplete/out-of-range configuration (see
    /// [`sharding::from_values`]) or either refused combination above.
    pub fn shard_config(&self) -> Result<Option<Sharding>, ShardingConfigError> {
        let Some(shard) = sharding::resolve(self.shard.shard_id, self.shard.total_shards)? else {
            return Ok(None);
        };
        let Some(options) = self.leader_election.as_ref() else {
            return Err(ShardingConfigError::RequiresLeaderElection {
                shard_id: shard.shard_id(),
                total_shards: shard.total_shards(),
                prefix: SHARD_LEASE_PREFIX,
            });
        };
        if let Some(configured) = options.lease_name.as_deref() {
            let configured = configured.trim();
            if configured != shard.lease_name() {
                return Err(ShardingConfigError::LeaseNameConflict {
                    expected: shard.lease_name(),
                    configured: configured.to_owned(),
                });
            }
        }
        Ok(Some(shard))
    }

    /// Builds the validated leader-election configuration, or `None` when it is disabled.
    ///
    /// A thin view over [`Self::ha_plan`]: the sharding validation runs either way, so a sharded
    /// replica can never be started with an election configuration that ignores its shard.
    ///
    /// # Errors
    ///
    /// See [`Self::ha_plan`].
    pub fn leader_election_config(
        &self,
        namespace: &str,
    ) -> Result<Option<LeaderElectionConfig>, RunConfigError> {
        Ok(self.ha_plan(namespace)?.leader_election)
    }
}

/// Runs the controller loop entrypoint with default [`RunOptions`].
///
/// # Errors
///
/// See [`run_with`].
pub async fn run() -> anyhow::Result<()> {
    run_with(RunOptions::default()).await
}

/// Runs the `v0.2` controller: watch `Application` objects, resolve Git, render manifests,
/// normalize scopes, read live state, apply with SSA and persist a crash-safe inventory.
///
/// # Errors
///
/// Fails when the log format is invalid, the namespace configuration is invalid, the
/// Kubernetes client cannot be configured, or in-flight reconciles outlive the drain timeout.
pub async fn run_with(options: RunOptions) -> anyhow::Result<()> {
    prepare(options).await?.run().await
}

/// Everything one `ferriscd` process builds **once**, shared by the controller loop and the
/// in-process API server (`T14.1`, ADR-002).
///
/// This is the answer to finding C9: `GET .../diff` renders, diffs and reads live state through
/// the *same* [`InventorySyncPipeline`](crate::sync::InventorySyncPipeline) — and therefore the
/// same `RepoCache`, renderer cache, `ClusterManager`, `DiscoveryCache` and `DryRunEvaluator` — that
/// the next reconcile will use. Nothing is duplicated and nothing is persisted: a preview is
/// computed on demand and thrown away, which is why `Application.status` never has to hold rendered
/// YAML or a diff (ADR-001).
///
/// Building is deliberately separate from running: `ferriscd server` needs the collaborators, while
/// `ferriscd controller` only needs [`ControlPlane::run`]. Both share the one cluster registry watch
/// this value owns.
pub struct ControlPlane {
    client: Client,
    config: ControllerConfig,
    ctx: Arc<ReconcileContext>,
    pipeline: Arc<dyn SyncPipeline>,
    clusters: Arc<ClusterManager>,
    leader_election: Option<LeaderElectionConfig>,
    cluster_stop: tokio_util::sync::CancellationToken,
    cluster_watch: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane")
            .field("namespace", &self.config.namespace)
            .field(
                "application_scope",
                &self.config.application_scope().describe(),
            )
            .field("clusters", &self.clusters.names())
            .field("leader_election", &self.leader_election.is_some())
            .finish_non_exhaustive()
    }
}

impl ControlPlane {
    /// The control plane's own `kube::Client` (the API server reads `Application`s with it).
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The controller configuration (namespace, application scope, shard, concurrency).
    #[must_use]
    pub fn config(&self) -> &ControllerConfig {
        &self.config
    }

    /// The control-plane namespace (`--namespace`, `ferriscd-system` by default).
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.config.namespace
    }

    /// Which namespaces may host `Application` objects (`T12.2`).
    #[must_use]
    pub fn application_scope(&self) -> ferriscd_engine::policy::ApplicationScope {
        self.config.application_scope()
    }

    /// The diff/sync pipeline: the controller's, not a copy of it (`T14.1`).
    #[must_use]
    pub fn sync_pipeline(&self) -> Arc<dyn SyncPipeline> {
        self.pipeline.clone()
    }

    /// The cluster registry (`T13.1`), including the control plane's own `in-cluster` handle.
    #[must_use]
    pub fn clusters(&self) -> Arc<ClusterManager> {
        self.clusters.clone()
    }

    /// Runs the controller loop until `SIGINT`/`SIGTERM`, then stops the cluster registry watch.
    ///
    /// # Errors
    ///
    /// See [`run_with`].
    pub async fn run(self) -> anyhow::Result<()> {
        let stop = tokio_util::sync::CancellationToken::new();
        let listener = stop.clone();
        // The listener only cancels the token: everything that reacts to a stop (lease release,
        // drain) is `run_until`'s job, so `SIGTERM` and an external stop are the same code path.
        let signal = tokio::spawn(async move {
            let reason = shutdown_signal().await;
            tracing::info!(
                signal = reason.as_str(),
                "graceful shutdown requested; draining in-flight reconciles"
            );
            listener.cancel();
        });
        let result = self.run_until(stop).await;
        signal.abort();
        result
    }

    /// Runs the controller loop until `stop` is cancelled (`T14.1`).
    ///
    /// This is what makes `ferriscd server` a **single** process with **one** shutdown: the CLI owns
    /// one signal listener, cancels this token, and both the reconcile loops and the API server drain
    /// from that one decision. A lost leader lease ends the term through the same token, exactly as
    /// before.
    ///
    /// # Errors
    ///
    /// See [`run_with`].
    pub async fn run_until(self, stop: tokio_util::sync::CancellationToken) -> anyhow::Result<()> {
        let result: anyhow::Result<()> = match self.leader_election.clone() {
            // The non-leader path reuses the public per-term driver: it treats the token as its only
            // shutdown input, which is precisely the contract this method promises.
            None => controller::run_as_leader(
                self.client.clone(),
                self.config.clone(),
                self.ctx.clone(),
                stop.clone(),
            )
            .await
            .map_err(anyhow::Error::from),
            Some(leader) => {
                run_as_leader(
                    self.client.clone(),
                    self.config.clone(),
                    self.ctx.clone(),
                    leader,
                    self.cluster_stop.clone(),
                    stop,
                )
                .await
            }
        };
        // The registry is a background watcher: stopping it is enough, nothing is buffered.
        self.cluster_stop.cancel();
        drop(self.cluster_watch);
        result
    }
}

/// Builds the [`ControlPlane`] a controller loop *or* an API server runs on.
///
/// # Errors
///
/// See [`run_with`].
pub async fn prepare(options: RunOptions) -> anyhow::Result<ControlPlane> {
    use anyhow::Context as _;

    // `T12.3` prerequisite: two `rustls` providers are linked into this binary (`ring` via `kube`,
    // `aws-lc-rs` via `gix`'s `reqwest`), and `rustls` refuses to pick one. Pin it before the first
    // HTTPS client — the controller's own included — is built.
    impersonation::ensure_crypto_provider();

    let log_format = init_logging()?;
    tracing::info!(
        controller = controller_name(),
        api_group = ferriscd_crd::api_group(),
        log_format = log_format.as_str(),
        allow_local_repos = options.allow_local_repos,
        leader_election = options.leader_election.is_some(),
        "ferriscd-controller starting"
    );
    if options.leader_election.is_none() {
        tracing::warn!(
            "leader election is disabled: run exactly ONE controller replica. Two replicas without \
             it both reconcile, which can double-apply and race on the same objects \
             (--leader-election turns on the coordination.k8s.io/v1 Lease)"
        );
    }

    let namespace_value = match options.namespace.as_deref() {
        Some(namespace) => Some(namespace.to_owned()),
        None => std::env::var(controller::NAMESPACE_ENV).ok(),
    };
    // `T12.2`: the flag wins, then `FERRISCD_APPLICATION_NAMESPACES`, then the safe default
    // (`--namespace` only).
    let application_namespaces = match options.application_namespaces.as_deref() {
        Some(value) => ApplicationNamespaces::parse(Some(value))?,
        None => ControllerConfig::application_namespaces_from_env()?,
    };
    let namespace = controller::namespace_from_env_value(namespace_value.as_deref())?;
    // `T13.2` finding M8 and `T13.3`: the lease/renewal combination **and** the shard assignment are
    // validated together, before any client, pool or registry is built. A renewal interval that
    // cannot keep a healthy leader alive, or a shard that contradicts the election mode, must be a
    // startup failure — not a controller that acquires a lease and then oscillates, or one that
    // quietly reconciles a slice nobody asked for.
    let plan = options.ha_plan(&namespace)?;
    let leader_election = plan.leader_election;
    let shard = plan.shard;
    let config = ControllerConfig {
        namespace,
        application_namespaces,
        shard,
        ..ControllerConfig::default()
    };
    if let Some(shard) = shard {
        tracing::info!(
            shard_id = shard.shard_id(),
            total_shards = shard.total_shards(),
            shard = %shard,
            lease = %shard.lease_name(),
            "deterministic sharding enabled: this replica reconciles only the Applications whose \
             sha256(namespace, name) falls in its shard, and holds the per-shard leader lease \
             `ferriscd-leader-shard-<id>`; every --total-shards value must match across replicas and \
             every --shard-id must be unique"
        );
    }
    // The `Config` is inferred once and shared: the controller's own client and the `T12.3`
    // impersonation pool are both built from it, so a tenant request authenticates with the same
    // credential material as the controller's.
    let kube_config = kube::Config::infer().await.context(
        "failed to infer the Kubernetes configuration from kubeconfig/in-cluster config",
    )?;
    let client = Client::try_from(kube_config.clone())
        .context("failed to initialize the Kubernetes client from kubeconfig/in-cluster config")?;

    if config
        .application_scope()
        .watches_more_than_the_control_plane()
    {
        tracing::warn!(
            control_plane_namespace = %config.namespace,
            application_namespaces = %config.application_scope().describe(),
            "Apps-in-any-namespace is enabled: an Application outside the control-plane namespace \
             is refused unless it sets spec.serviceAccountName (it is deployed as that \
             ServiceAccount, never as the controller's) and its AppProject lists its namespace, \
             destination, Kubernetes kinds, and that ServiceAccount (spec.sourceNamespaces, \
             spec.destinations, *ResourceWhitelist, spec.allowedServiceAccounts). The project \
             allow-lists stay the boundary: impersonation narrows what a tenant can do, it does \
             not authorize an Application the project does not permit."
        );
    }

    let apps_api = Api::<Application>::namespaced(client.clone(), &config.namespace);
    // Status patches and finalizer writes follow the object's own namespace, so a tenant
    // `Application` is patched where it lives (`T12.2`).
    let status = Arc::new(ApiStatusWriter::new(apps_api.clone()).with_client(client.clone()));

    // Git: one scratch root backs both the gix worktrees and the repo cache, so publishing a
    // checkout is a same-filesystem atomic rename.
    let work_root = options
        .work_root
        .clone()
        .unwrap_or_else(std::env::temp_dir)
        .join("ferriscd-repos");
    let url_policy = if options.allow_local_repos {
        tracing::warn!(
            "allowing local and file:// Git repositories (--allow-local-repos); never use this \
             in production"
        );
        ferriscd_engine::repo::RepoUrlPolicy::AllowLocal
    } else {
        ferriscd_engine::repo::RepoUrlPolicy::Production
    };
    let git = ferriscd_engine::repo::GixGitClient::new(
        ferriscd_engine::repo::GixGitClientConfig::new()
            .with_url_policy(url_policy)
            .with_work_root(&work_root),
    );
    let repos = Arc::new(ferriscd_engine::repo::RepoCache::new(
        Arc::new(git),
        ferriscd_engine::repo::RepoCacheConfig::new(&work_root),
    ));

    // `T12.3`: ONE shared HTTP/TLS connector for every impersonated identity, built once from the
    // controller's own `kube::Config` (see `impersonation::ImpersonationPool`). It is created
    // eagerly — not lazily on the first tenant `Application` — so a broken TLS configuration is a
    // startup failure instead of a reconcile that fails forever.
    let pool_config = kube_config.clone();
    let pool = Arc::new(
        tokio::task::spawn_blocking(move || impersonation::ImpersonationPool::new(&pool_config))
            .await
            .context("the impersonation connector task panicked")?
            .context(
                "failed to build the ServiceAccount impersonation connector; tenant Applications \
             need it, and deploying them with the controller's own identity is never an option",
            )?,
    );
    tracing::info!(
        connectors = pool.connectors(),
        "ServiceAccount impersonation pool ready (one shared HTTP/TLS connector)"
    );
    tracing::info!(
        namespace = %config.namespace,
        label = %credentials::SecretCredentialStore::label_selector(),
        "repository credentials: reading labeled Secrets from the control-plane namespace only \
         (namespaced list, never cluster-wide; no match clones anonymously)"
    );
    // `T13.1`: the cluster registry. The in-cluster handle reuses the controller's own client, its
    // own discovery cache and the pool built above — sharing the ONE connector — so answering
    // `in-cluster` allocates nothing new. Remote clusters come from
    // `ferriscd.io/secret-type=cluster` Secrets in the control-plane namespace, watched (never read
    // per reconcile) by a namespaced `Api<Secret>`.
    let cluster_options = if options.allow_insecure_clusters {
        tracing::warn!(
            "accepting insecure cluster registrations (--allow-insecure-cluster-tls): TLS \
             verification of remote API servers can be disabled by a Secret. Never use this in \
             production"
        );
        ClusterOptions::allowing_insecure()
    } else {
        ClusterOptions::strict()
    };
    let in_cluster = Arc::new(ClusterHandle::new(
        ClusterName::in_cluster(),
        client.clone(),
        DiscoveryCache::new(client.clone()),
        pool.clone(),
    ));
    let clusters = Arc::new(ClusterManager::new(
        in_cluster,
        config.namespace.clone(),
        cluster_options,
        Arc::new(KubeClusterBuilder::new(cluster_options)),
    ));
    // Seed from one initial list before the watch starts: an `Application` that already references
    // a remote cluster must not fail terminally in the window between the watch being spawned and
    // its first event arriving. The watch then owns every subsequent add/change/delete.
    seed_registry(&clusters, client.clone(), &config.namespace).await;
    let cluster_stop = tokio_util::sync::CancellationToken::new();
    let cluster_watch = tokio::spawn(clusters.clone().run(
        Arc::new(SecretClusterSource::new(
            client.clone(),
            config.namespace.clone(),
        )),
        cluster_stop.clone(),
    ));
    tracing::info!(
        namespace = %config.namespace,
        label = %SecretClusterSource::label_selector(),
        allow_insecure = cluster_options.allow_insecure,
        "remote clusters: watching labeled Secrets in the control-plane namespace only \
         (namespaced watch, never cluster-wide); `in-cluster` is always available"
    );
    let impersonation_source: Arc<dyn impersonation::ImpersonationSource> =
        Arc::new(impersonation::ImpersonatingAccess::new(pool.clone()));

    // `T14.1`: the pipeline is held as `Arc<dyn SyncPipeline>` so the API server can compute a live
    // diff through the *same* object the controller reconciles with (`SyncPipeline::diff`).
    let pipeline: Arc<dyn SyncPipeline> = Arc::new(
        sync::InventorySyncPipeline::new(
            repos,
            DiscoveryCache::new(client.clone()),
            Arc::new(DynamicApiSource::new(client.clone())),
            Arc::new(DynamicApiApplier::new(client.clone())),
            // The dry-run half of drift detection (T07.1): `dryRun=All` PATCHes per resource.
            Arc::new(DynamicDryRunApi::new(client.clone())),
        )
        .with_url_policy(url_policy)
        // `T12.1`: every `Application` is validated against its `AppProject`, which is read from
        // the control-plane namespace (never from the `Application`'s own namespace).
        .with_project_source(Arc::new(ApiProjectSource::new(
            client.clone(),
            &config.namespace,
        )))
        // `T12.2`: the same scope the watcher uses, so a tenant `Application` is refused here even
        // if it somehow reaches a reconcile.
        .with_application_scope(config.application_scope())
        // `T12.3`: one pooled connector for every impersonated ServiceAccount. Building it reads
        // the CA bundle, so it is moved off the async workers; it happens exactly once.
        .with_impersonation_source(impersonation_source)
        // `T12.4`: Git credentials come from `ferriscd.io/secret-type=repository` Secrets in the
        // control-plane namespace only. The store holds a *namespaced* `Api<Secret>`, so no code
        // path can ask for a cluster-wide `Secret` read (trap guard for `T12.4`); no match means
        // anonymous, which keeps public repositories working unchanged.
        .with_credential_source(Arc::new(credentials::SecretCredentialStore::new(
            client.clone(),
            &config.namespace,
        )))
        // `T13.1`: `spec.destination.cluster` is resolved through the registry. Without this every
        // non-`in-cluster` destination is a terminal error, which is the pre-Phase-13 behaviour.
        .with_cluster_source(clusters.clone()),
    );
    let ctx = Arc::new(
        ReconcileContext::new(apps_api, pipeline.clone(), status).with_client(client.clone()),
    );

    Ok(ControlPlane {
        client,
        config,
        ctx,
        pipeline,
        clusters,
        leader_election,
        cluster_stop,
        cluster_watch,
    })
}

/// Seeds the cluster registry from one label-filtered list of the control-plane namespace.
///
/// Failure is logged, never fatal: the watch performs the same reads and retries on its own.
async fn seed_registry(clusters: &ClusterManager, client: Client, namespace: &str) {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client, namespace);
    let params = kube::api::ListParams::default().labels(&SecretClusterSource::label_selector());
    let listed = match secrets.list(&params).await {
        Ok(listed) => listed,
        Err(err) => {
            tracing::warn!(
                error = %err,
                namespace = %namespace,
                "could not list the cluster registration Secrets at startup; the watch will retry"
            );
            return;
        }
    };
    let mut registered = 0_usize;
    for secret in &listed.items {
        match clusters.seed(secret).await {
            Ok(_) => registered = registered.saturating_add(1),
            Err(err) => tracing::warn!(
                cluster = %secret.name_any(),
                error = %err,
                "a cluster registration Secret cannot be used; skipping it"
            ),
        }
    }
    tracing::info!(
        namespace = %namespace,
        registered,
        clusters = ?clusters.names(),
        "cluster registry seeded"
    );
}

/// Which half of a leader term ended first.
#[derive(Debug)]
enum TermEnd<C> {
    /// The controller set ended on its own; the term token was cancelled by [`race_term`].
    Controllers(C),
    /// The lease holder ended: leadership was lost, or a graceful stop released the lease.
    Hold(Result<HoldOutcome, LeaderElectionError>),
}

/// Races the controller set against the lease holder for one leader term.
///
/// The two must **not** be joined (finding: `run_as_leader` join semantics). If the controller set
/// ends while the term token is still live, `join!` would keep renewing the lease forever: this
/// replica would hold leadership while reconciling nothing, and no standby could ever take over — a
/// black hole. Racing them means "the controller set finished" ends the term, and cancelling the
/// token here is what stops anything from scheduling more work under it.
///
/// The losing half is left untouched (only polled, never dropped by this helper), so the caller can
/// still await it — the controller set has to drain after the lease is lost, exactly like a
/// `SIGTERM`.
async fn race_term<C>(
    controllers: &mut C,
    hold: &mut (impl Future<Output = Result<HoldOutcome, LeaderElectionError>> + Unpin),
    token: &tokio_util::sync::CancellationToken,
) -> TermEnd<C::Output>
where
    C: Future + Unpin,
{
    tokio::select! {
        result = controllers => {
            token.cancel();
            TermEnd::Controllers(result)
        }
        result = hold => TermEnd::Hold(result),
    }
}

/// Runs the active/standby loop (`T13.2`).
///
/// The standby waits for the `Lease`; the leader runs the controller set until the lease is lost
/// (then it becomes a standby again) or the process is asked to stop (then it releases the lease
/// voluntarily, so the standby takes over at once).
async fn run_as_leader(
    client: Client,
    config: ControllerConfig,
    ctx: Arc<ReconcileContext>,
    leader: LeaderElectionConfig,
    cluster_stop: tokio_util::sync::CancellationToken,
    stop: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let election = LeaderElection::from_client(client.clone(), leader)?;
    // `stop` is owned by the caller (`ControlPlane::run` wires it to `SIGINT`/`SIGTERM`): releasing
    // the lease (and cancelling the leader token) is `Leadership::hold`'s job, so the release happens
    // in one place, and a CLI that stops the API server stops the lease too.
    tracing::info!(
        lease = %election.elector().config().lease_name(),
        namespace = %election.elector().config().namespace(),
        identity = %election.elector().config().identity(),
        lease_duration = ?election.elector().config().lease_duration(),
        renew_interval = ?election.elector().config().renew_interval(),
        "leader election enabled: this replica is an active/standby candidate"
    );

    loop {
        let Some(term) = election
            .campaign(&stop)
            .await
            .context("leader election failed")?
        else {
            break;
        };
        let token = term.token();
        // Boxed so one `select!` can poll both halves without moving either: the controller set has
        // to be awaited *after* the term ends, so in-flight passes drain like a `SIGTERM`.
        let mut controllers = Box::pin(controller::run_as_leader(
            client.clone(),
            config.clone(),
            ctx.clone(),
            token.clone(),
        ));
        let mut hold = Box::pin(term.hold(&stop));
        let outcome = match race_term(&mut controllers, &mut hold, &token).await {
            TermEnd::Controllers(result) => {
                // The controller set ended while the lease was still ours. Hand the lease back
                // instead of renewing an idle term: a replica that holds leadership but runs no
                // reconcilers is a black hole no standby can take over from.
                drop(hold);
                tracing::warn!(
                    lease = %term.elector().config().lease_name(),
                    identity = %term.elector().config().identity(),
                    "the controller set ended before the leader term; releasing the leader lease so \
                     a standby takes over instead of renewing an idle term"
                );
                if let Err(err) = term.elector().release().await {
                    tracing::warn!(
                        lease = %term.elector().config().lease_name(),
                        error = %err,
                        "failed to release the leader lease; the standby will wait for it to expire"
                    );
                }
                // The controller set's own failure is reported after the lease is safely released.
                result?;
                HoldOutcome::Released
            }
            TermEnd::Hold(result) => {
                let outcome = result.context("holding the leader lease failed")?;
                // The term token is already cancelled (lost or released): let the controller set
                // drain rather than abandoning in-flight applies and status patches.
                controllers.await?;
                outcome
            }
        };
        if outcome == HoldOutcome::Lost {
            tracing::warn!("standing by: another replica will take the leader lease");
            continue;
        }
        break;
    }
    cluster_stop.cancel();
    Ok(())
}

/// Creates the `reconcile` span carrying the application identity.
#[must_use]
pub fn reconcile_span(app: &Application) -> tracing::Span {
    tracing::info_span!(
        "reconcile",
        "app.namespace" = %app.namespace().unwrap_or_default(),
        "app.name" = %app.name_any(),
        "app.generation" = app.metadata.generation.unwrap_or_default(),
    )
}

/// Locks `mutex`, recovering from poisoning instead of panicking.
///
/// A panicking test or a poisoned status buffer must never take the controller down: the
/// guarded data here is bookkeeping (counters, indices) that stays usable.
pub(crate) fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads `lock`, recovering from poisoning instead of panicking.
pub(crate) fn read_recover<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

/// Writes `lock`, recovering from poisoning instead of panicking.
pub(crate) fn write_recover<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// How the controller was asked to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// `SIGINT` / Ctrl+C.
    Interrupt,
    /// `SIGTERM` (Kubernetes pod termination).
    Terminate,
}

impl ShutdownReason {
    /// Stable label for logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
        }
    }
}

/// Errors raised while shutting the controller down.
#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    /// In-flight reconciles did not finish inside the drain window.
    ///
    /// Reported as a failure on purpose: a status patch or an apply that was abandoned
    /// mid-flight must not look like a clean shutdown.
    #[error("controller drain timed out after {timeout:?}; in-flight reconciles were abandoned")]
    DrainTimeout {
        /// The configured drain window.
        timeout: Duration,
    },
}

/// Resolves when the process receives `SIGINT` (Ctrl+C) or `SIGTERM`.
///
/// Feed this into `Controller::graceful_shutdown_on`.
pub async fn shutdown_signal() -> ShutdownReason {
    first_of(interrupt_signal(), terminate_signal()).await
}

async fn interrupt_signal() -> ShutdownReason {
    if tokio::signal::ctrl_c().await.is_err() {
        tracing::warn!("failed to listen for SIGINT; only SIGTERM will trigger shutdown");
        std::future::pending::<()>().await;
    }
    ShutdownReason::Interrupt
}

#[cfg(unix)]
async fn terminate_signal() -> ShutdownReason {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut signal) => {
            signal.recv().await;
            ShutdownReason::Terminate
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to listen for SIGTERM");
            std::future::pending::<()>().await;
            ShutdownReason::Terminate
        }
    }
}

#[cfg(not(unix))]
async fn terminate_signal() -> ShutdownReason {
    std::future::pending::<()>().await;
    ShutdownReason::Terminate
}

/// Awaits whichever signal future completes first.
async fn first_of<A, B>(interrupt: A, terminate: B) -> ShutdownReason
where
    A: Future<Output = ShutdownReason>,
    B: Future<Output = ShutdownReason>,
{
    tokio::select! {
        reason = interrupt => reason,
        reason = terminate => reason,
    }
}

/// Runs `run` to completion, allowing at most `drain_timeout` once `shutdown` resolves.
///
/// # Errors
///
/// [`ShutdownError::DrainTimeout`] when `run` is still pending after the drain window —
/// the caller must exit non-zero so the abandoned work is visible.
pub async fn await_drained<F, S, R>(
    run: F,
    shutdown: S,
    drain_timeout: Duration,
) -> Result<R, ShutdownError>
where
    F: Future<Output = R>,
    S: Future<Output = ()>,
{
    let mut run = std::pin::pin!(run);
    let mut shutdown = std::pin::pin!(shutdown);
    tokio::select! {
        result = &mut run => Ok(result),
        () = &mut shutdown => {
            tracing::info!(
                drain_timeout_seconds = drain_timeout.as_secs(),
                "shutdown signal observed; draining in-flight reconciles"
            );
            match tokio::time::timeout(drain_timeout, run).await {
                Ok(result) => Ok(result),
                Err(_) => Err(ShutdownError::DrainTimeout {
                    timeout: drain_timeout,
                }),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Log format
// ---------------------------------------------------------------------------

/// Structured log format selected by [`LOG_FORMAT_ENV`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable, multi-line output (default).
    #[default]
    Pretty,
    /// One JSON object per line, for log aggregation.
    Json,
}

impl LogFormat {
    /// Parses an explicit `FERRISCD_LOG_FORMAT` value.
    ///
    /// `json` selects [`LogFormat::Json`]; `pretty`, `text`, and `plain` select
    /// [`LogFormat::Pretty`]. Matching is case-insensitive and surrounding whitespace is
    /// ignored.
    ///
    /// # Errors
    ///
    /// [`LogFormatError::Unknown`] for any other value: a typo must not silently fall back
    /// to the wrong format.
    pub fn parse(value: &str) -> Result<Self, LogFormatError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" | "text" | "plain" => Ok(Self::Pretty),
            other => Err(LogFormatError::Unknown {
                value: other.to_owned(),
            }),
        }
    }

    /// Stable label used in logs and configuration errors.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Json => "json",
        }
    }

    /// Returns whether JSON output was requested.
    #[must_use]
    pub fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
}

/// Log-format parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum LogFormatError {
    /// The value is not a known format.
    #[error("unknown {LOG_FORMAT_ENV} value {value:?}: expected one of json, pretty, text")]
    Unknown {
        /// The rejected value.
        value: String,
    },
}

/// Resolves [`LOG_FORMAT_ENV`] without touching the environment (testable).
///
/// An unset or blank variable means [`LogFormat::Pretty`].
///
/// # Errors
///
/// [`LogFormatError::Unknown`] for an unrecognized value.
pub fn log_format_from_env_value(value: Option<&str>) -> Result<LogFormat, LogFormatError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(LogFormat::Pretty),
        Some(value) => LogFormat::parse(value),
    }
}

/// Reads [`LOG_FORMAT_ENV`] from the process environment.
///
/// # Errors
///
/// [`LogFormatError::Unknown`] for an unrecognized value.
pub fn log_format_from_env() -> Result<LogFormat, LogFormatError> {
    let value = std::env::var(LOG_FORMAT_ENV).ok();
    log_format_from_env_value(value.as_deref())
}

/// Installs the global tracing subscriber using [`LOG_FORMAT_ENV`] and `RUST_LOG`.
///
/// Called once from the binary; returning the selected format lets the caller log it.
///
/// # Errors
///
/// Fails for an unknown format or when a global subscriber is already installed.
pub fn init_logging() -> anyhow::Result<LogFormat> {
    let format = log_format_from_env()?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let installed = match format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
    installed.map_err(|err| anyhow::anyhow!("failed to install tracing subscriber: {err}"))?;
    Ok(format)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn controller_name_matches_field_manager() {
        assert_eq!(controller_name(), "ferriscd");
    }

    #[test]
    fn log_format_parsing_accepts_known_values_and_rejects_typos() {
        assert_eq!(LogFormat::parse(" JSON ").expect("json"), LogFormat::Json);
        assert_eq!(LogFormat::parse("text").expect("text"), LogFormat::Pretty);
        assert_eq!(LogFormat::parse("plain").expect("plain"), LogFormat::Pretty);
        assert!(LogFormat::parse("jsonl").is_err());
        assert_eq!(
            log_format_from_env_value(Some("   ")).expect("blank defaults"),
            LogFormat::Pretty
        );
        assert_eq!(
            log_format_from_env_value(None).expect("unset defaults"),
            LogFormat::Pretty
        );
    }

    // ---------------------------------------------------------------------
    // `T13.3`: sharding is per-shard leader election
    // ---------------------------------------------------------------------

    /// The pre-Phase-13 default: no election, no shard, no `leases` RBAC required.
    #[test]
    fn the_default_ha_plan_is_unchanged() {
        let plan = RunOptions::default()
            .ha_plan(ferriscd_crd::CONTROL_PLANE_NAMESPACE)
            .expect("the defaults must be valid");
        assert!(plan.leader_election.is_none(), "election stays opt-in");
        assert!(plan.shard.is_none(), "sharding stays opt-in");
        assert!(
            RunOptions::default()
                .shard_config()
                .expect("no shard flags is valid")
                .is_none()
        );
    }

    /// **`T13.3` wiring:** a sharded replica's `Lease` is `ferriscd-leader-shard-<id>` — never the
    /// single-leader default, which would leave every other shard unreconciled.
    #[test]
    fn sharding_derives_the_per_shard_lease() {
        let options = RunOptions {
            leader_election: Some(LeaderElectionOptions {
                identity: Some("pod-1".to_owned()),
                ..Default::default()
            }),
            shard: ShardOptions::new(Some(1), Some(3)),
            ..Default::default()
        };
        let plan = options
            .ha_plan(ferriscd_crd::CONTROL_PLANE_NAMESPACE)
            .expect("a sharded replica with election is valid");
        let shard = plan.shard.expect("sharding is on");
        assert_eq!(shard.shard_id(), 1);
        assert_eq!(shard.total_shards(), 3);
        let lease = plan.leader_election.expect("election is on");
        assert_eq!(lease.lease_name(), "ferriscd-leader-shard-1");
        assert_ne!(lease.lease_name(), DEFAULT_LEASE_NAME);
        assert_eq!(lease.identity(), "pod-1");
        assert_eq!(lease.lease_duration(), DEFAULT_LEASE_DURATION);

        // `--total-shards 1` is legal: one shard holds everything, and still has its own lease.
        let single = RunOptions {
            leader_election: Some(LeaderElectionOptions::default()),
            shard: ShardOptions::new(Some(0), Some(1)),
            ..Default::default()
        }
        .ha_plan(ferriscd_crd::CONTROL_PLANE_NAMESPACE)
        .expect("one shard is valid");
        assert_eq!(
            single.leader_election.expect("election is on").lease_name(),
            "ferriscd-leader-shard-0"
        );
        assert!(
            single
                .shard
                .expect("sharding is on")
                .owns("ferriscd-system", "any-application"),
            "with one shard, this replica owns every Application"
        );

        // The "explicitly paired" mode: the shard's own name may be stated by hand.
        let paired = RunOptions {
            leader_election: Some(LeaderElectionOptions {
                lease_name: Some(" ferriscd-leader-shard-1 ".to_owned()),
                ..Default::default()
            }),
            shard: ShardOptions::new(Some(1), Some(3)),
            ..Default::default()
        };
        assert_eq!(
            paired
                .ha_plan(ferriscd_crd::CONTROL_PLANE_NAMESPACE)
                .expect("the per-shard name is correct, padding aside")
                .leader_election
                .expect("election is on")
                .lease_name(),
            "ferriscd-leader-shard-1"
        );
    }

    /// **`T13.3` trap guard:** the two unsafe combinations are refused, and a half-specified pair is
    /// never defaulted.
    #[test]
    fn sharding_cannot_be_combined_with_single_leader_election() {
        // No election at all: two replicas with the same shard id would double-apply.
        let err = RunOptions {
            shard: ShardOptions::new(Some(0), Some(2)),
            ..Default::default()
        }
        .ha_plan(ferriscd_crd::CONTROL_PLANE_NAMESPACE)
        .expect_err("sharding without election must be refused");
        assert!(
            matches!(
                err,
                RunConfigError::Sharding(ShardingConfigError::RequiresLeaderElection { .. })
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("--leader-election"), "{err}");

        // One shared lease: only one replica would ever lead, leaving the other shards unreconciled.
        for lease_name in [DEFAULT_LEASE_NAME, "ferriscd-controller-leader", "custom"] {
            let err = RunOptions {
                leader_election: Some(LeaderElectionOptions {
                    lease_name: Some(lease_name.to_owned()),
                    ..Default::default()
                }),
                shard: ShardOptions::new(Some(1), Some(3)),
                ..Default::default()
            }
            .ha_plan(ferriscd_crd::CONTROL_PLANE_NAMESPACE)
            .expect_err("only the per-shard lease name is allowed");
            assert!(
                matches!(
                    err,
                    RunConfigError::Sharding(ShardingConfigError::LeaseNameConflict { .. })
                ),
                "{lease_name}: {err:?}"
            );
            assert!(
                err.to_string().contains("ferriscd-leader-shard-1"),
                "the refusal names the lease the shard needs: {err}"
            );
        }

        // A half-specified pair, and an index that cannot exist.
        for (shard_id, total_shards) in [
            (Some(0), None),
            (None, Some(4)),
            (Some(4), Some(4)),
            (Some(0), Some(0)),
        ] {
            let err = RunOptions {
                leader_election: Some(LeaderElectionOptions::default()),
                shard: ShardOptions::new(shard_id, total_shards),
                ..Default::default()
            }
            .ha_plan(ferriscd_crd::CONTROL_PLANE_NAMESPACE)
            .expect_err("an unusable shard must be refused");
            assert!(
                matches!(err, RunConfigError::Sharding(_)),
                "{shard_id:?}/{total_shards:?}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn await_drained_returns_work_completed_before_shutdown() {
        let result = await_drained(
            async { 7_u8 },
            std::future::pending::<()>(),
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(result, Ok(7)));
    }

    #[tokio::test]
    async fn await_drained_times_out_on_stuck_work() {
        let result = await_drained(
            std::future::pending::<()>(),
            async {},
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(result, Err(ShutdownError::DrainTimeout { .. })));
    }

    #[tokio::test]
    async fn await_drained_finishes_work_that_completes_during_the_window() {
        let result = await_drained(
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                9_u8
            },
            async {},
            Duration::from_millis(100),
        )
        .await;
        assert!(matches!(result, Ok(9)));
    }

    /// **`run_as_leader` join semantics:** a controller set that ends on its own must end the leader
    /// term (and the term token with it). Joining both halves instead would keep renewing a lease
    /// this replica no longer exercises — leadership with no reconcilers, and no takeover.
    #[tokio::test]
    async fn a_controller_set_that_ends_first_ends_the_leader_term() {
        let token = tokio_util::sync::CancellationToken::new();
        let mut controllers = Box::pin(async { Ok::<(), anyhow::Error>(()) });
        let mut hold = Box::pin(std::future::pending::<
            Result<HoldOutcome, LeaderElectionError>,
        >());

        match race_term(&mut controllers, &mut hold, &token).await {
            TermEnd::Controllers(result) => assert!(result.is_ok()),
            TermEnd::Hold(result) => {
                panic!("the controller set ended first, not the lease holder: {result:?}");
            }
        }
        assert!(
            token.is_cancelled(),
            "the term token must be cancelled when the controller set ends, so nothing keeps \
             scheduling work under a lease the replica is about to release"
        );
    }

    /// The other half of the race: a lost (or released) lease ends the term immediately, and the
    /// controller set is left for the caller to drain — the cancellation is `hold`'s own job.
    #[tokio::test]
    async fn a_lost_lease_ends_the_term_before_the_controller_set_drains() {
        let token = tokio_util::sync::CancellationToken::new();
        let mut controllers = Box::pin(std::future::pending::<anyhow::Result<()>>());
        let mut hold =
            Box::pin(async { Ok::<HoldOutcome, LeaderElectionError>(HoldOutcome::Lost) });

        match race_term(&mut controllers, &mut hold, &token).await {
            TermEnd::Hold(Ok(HoldOutcome::Lost)) => {}
            other => panic!("expected a lost lease, got {other:?}"),
        }
        assert!(
            !token.is_cancelled(),
            "a lost lease ends the term without this helper cancelling the token"
        );
    }
}

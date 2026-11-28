//! `ferriscd controller` — run the Kubernetes controller (Phase 06 `v0.2`).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Args;

/// Arguments for `ferriscd controller`.
///
/// `Debug` is implemented manually so `--audit-webhook-url` never prints query-string tokens or
/// embedded credentials into startup logs or panic messages (`T17.2`).
#[derive(Args)]
pub struct ControllerArgs {
    /// Namespace whose `Application` objects this controller owns.
    ///
    /// Defaults to `FERRISCD_NAMESPACE`, then `ferriscd-system`.
    #[arg(short = 'n', long = "namespace")]
    pub namespace: Option<String>,

    /// Namespaces allowed to host `Application` objects (comma-separated, or `*` for all).
    ///
    /// Defaults to `FERRISCD_APPLICATION_NAMESPACES`, then to `--namespace` only — the safe
    /// single-tenant default. The control-plane namespace is always watched. Every `Application`
    /// outside it must set `spec.serviceAccountName` and be authorized by its `AppProject`
    /// (`spec.sourceNamespaces`, `spec.destinations`, the resource whitelists, and
    /// `spec.allowedServiceAccounts`); without a `serviceAccountName` it is refused with
    /// `Ready=False, reason=PolicyViolation` rather than deployed with the controller's identity.
    ///
    /// Tenant Applications are deployed **as** their ServiceAccount (impersonation), so the
    /// controller's ClusterRole needs, beyond the usual Application/AppProject access:
    ///
    ///   - apiGroups: [""] resources: ["users", "groups"] verbs: ["impersonate"]
    ///   - apiGroups: [""] resources: ["serviceaccounts"] verbs: ["impersonate"]
    ///   - apiGroups: ["ferriscd.io"] resources: ["appprojects"] verbs: ["get"]
    ///   - apiGroups: ["ferriscd.io"] resources: ["applications"] verbs: ["get", "list", "watch", "patch"]  (tenant namespaces)
    ///   - apiGroups: ["ferriscd.io"] resources: ["applications/status"] verbs: ["patch", "update"]
    ///   - apiGroups: ["ferriscd.io"] resources: ["applications/finalizers"] verbs: ["update"]
    ///
    /// With `*` the `applications` verbs must be cluster-wide. `system:masters` is never
    /// impersonated. See `deploy/README.md` for the full matrix.
    ///
    /// Git credentials (`T12.4`) additionally need `secrets` access, but only inside the
    /// control-plane namespace — a namespaced Role, never a ClusterRole rule:
    ///
    ///   - apiGroups: [""] resources: ["secrets"] verbs: ["get", "list", "watch"]  (namespace: ferriscd-system via a Role/RoleBinding)
    ///
    /// The controller holds a namespaced `Api<Secret>` and reads `Secret`s labeled
    /// `ferriscd.io/secret-type=repository` from `--namespace` only: it never performs a
    /// cluster-wide `Secret` read, and a `Secret` a tenant writes in its own namespace is never
    /// used as a credential.
    #[arg(long = "application-namespaces", value_name = "NAMESPACES")]
    pub application_namespaces: Option<String>,

    /// Allow `file://` URLs and local filesystem paths as Git sources.
    ///
    /// Off by default: production only accepts `https://`, `ssh://` and SCP-style SSH remotes.
    /// Enable this only for local `kind` demos and integration tests.
    #[arg(long = "allow-local-repos")]
    pub allow_local_repos: bool,

    /// Directory for the Git mirror cache and materialized worktrees.
    ///
    /// Defaults to `<system temp dir>/ferriscd-repos`; in a cluster this should be an
    /// `emptyDir` volume.
    #[arg(long = "work-root")]
    pub work_root: Option<PathBuf>,

    /// Accept `insecureSkipTLSVerify` and plaintext `http://` in cluster registration Secrets.
    ///
    /// Off by default, and deliberately so: TLS verification is what stops anything on the
    /// control-plane-to-workload path from reading and rewriting every manifest FerrisCD applies.
    /// Only use this on a throwaway local cluster.
    #[arg(long = "allow-insecure-cluster-tls")]
    pub allow_insecure_cluster_tls: bool,

    /// Stamp `ferriscd.io/managed-by` and `ferriscd.io/app-hash` labels on managed resources.
    ///
    /// Off by default. This is the label half of the opt-in drift watcher (`T18.1`/`T18.2`): an
    /// annotation cannot be used in a Kubernetes watch label selector, so these two bounded labels
    /// are what let the controller filter `ferriscd.io/managed-by=ferriscd` **server-side** instead
    /// of receiving every object in the cluster. The values are always 16 lowercase hex characters
    /// (`SHA-256("<app-namespace>/<app-name>")` truncated), so they stay valid under the 63-character
    /// label limit for any `Application` name.
    ///
    /// Additive and idempotent: turning it off does not rewrite any manifest body, and the next sync
    /// converges the labels away, so toggling it is safe on a live fleet.
    ///
    /// The environment fallback `FERRISCD_ENABLE_DRIFT_WATCHER` must be exactly `true` or `false`
    /// (lowercase; the parse is a bool parse, not a truthiness test). Unset means off — identical to
    /// omitting the flag — and any other value, including the empty string, is a **usage error**
    /// rather than a silent "off", so a typo cannot quietly leave the labels unset.
    #[arg(
        long = "enable-drift-watcher",
        env = ferriscd_controller::DRIFT_WATCHER_ENV
    )]
    pub enable_drift_watcher: bool,

    /// Elect one active replica with a `coordination.k8s.io/v1` Lease (active/standby HA).
    ///
    /// Without it, run exactly ONE controller replica: two replicas both reconcile, which can
    /// double-apply and race on the same objects. With it, every replica stands by until it holds
    /// the Lease, and the leader renews it (releasing it voluntarily on `SIGTERM`, so the standby
    /// takes over at once).
    ///
    /// Remote clusters additionally need `secrets` read access, again only inside the control-plane
    /// namespace (a namespaced Role, never a ClusterRole rule):
    ///
    ///   - apiGroups: [""] resources: ["secrets"] verbs: ["get", "list", "watch"]  (label ferriscd.io/secret-type=cluster)
    ///
    /// Leader election needs the Lease in that same namespace:
    ///
    ///   - apiGroups: ["coordination.k8s.io"] resources: ["leases"] verbs: ["get", "create", "update"]
    #[arg(long = "leader-election")]
    pub leader_election: bool,

    /// Name of the leader-election `Lease`.
    #[arg(
        long = "leader-election-lease-name",
        value_name = "NAME",
        default_value = ferriscd_controller::DEFAULT_LEASE_NAME
    )]
    pub leader_election_lease_name: String,

    /// Leader-election lease duration in seconds (must be > 3x the renew interval).
    #[arg(
        long = "leader-election-lease-duration-seconds",
        value_name = "SECONDS",
        default_value_t = ferriscd_controller::DEFAULT_LEASE_DURATION.as_secs()
    )]
    pub leader_election_lease_duration_seconds: u64,

    /// Leader-election renew interval in seconds (strictly less than a third of the lease).
    #[arg(
        long = "leader-election-renew-interval-seconds",
        value_name = "SECONDS",
        default_value_t = ferriscd_controller::DEFAULT_RENEW_INTERVAL.as_secs()
    )]
    pub leader_election_renew_interval_seconds: u64,

    /// Deterministic sharding (`T13.3`): this replica's zero-based shard index.
    ///
    /// Sharding splits the `Application`s between replicas instead of keeping all but one idle:
    /// `shard = sha256(namespace, name) % --total-shards`, computed locally from the object's own
    /// identity, so every replica agrees without talking to anyone and a restart never reshuffles
    /// ownership.
    ///
    /// Sharding is **per-shard leader election**, never a replacement for it, so it needs
    /// `--leader-election` and gets its own `Lease` — `ferriscd-leader-shard-<id>` — which is refused
    /// together with `--leader-election-lease-name`: one shared `Lease` would make a single replica
    /// lead and leave every other shard unreconciled. Replicas of one shard still compete for that
    /// shard's lease, so two pods configured with the same `--shard-id` cannot both reconcile it.
    ///
    /// Every replica must use the same `--total-shards`; the shard indexes must be distinct. The
    /// shard count is a capacity decision, not a per-pod knob: changing it re-partitions every
    /// `Application` on the next watch event (safe — each one is still owned exactly once — but it is
    /// a fleet-wide restart). Turning sharding on/off or changing the count is a **stop-then-start**:
    /// a sharded replica's `Lease` and an unsharded replica's `ferriscd-controller-leader` do not
    /// exclude each other, so overlapping shapes double-apply.
    ///
    /// Falls back to `FERRISCD_SHARD_ID` (a `StatefulSet` ordinal, typically), and is refused without
    /// `--total-shards`. The `leases` RBAC above already covers every per-shard `Lease`: they are all
    /// namespaced in the control-plane namespace.
    #[arg(
        long = "shard-id",
        value_name = "ID",
        requires = "total_shards",
        conflicts_with = "leader_election_lease_name"
    )]
    pub shard_id: Option<u32>,

    /// Deterministic sharding (`T13.3`): how many shards `--shard-id` is one of (`>= 1`).
    ///
    /// `--total-shards 1` is legal and means "one shard holds everything" (the same work partition
    /// as no sharding at all, still with its own `Lease`).
    ///
    /// Falls back to `FERRISCD_TOTAL_SHARDS`, and is refused without `--shard-id`.
    #[arg(
        long = "total-shards",
        value_name = "N",
        requires = "shard_id",
        conflicts_with = "leader_election_lease_name"
    )]
    pub total_shards: Option<u32>,

    /// Address of the **dedicated internal Prometheus metrics listener** (`T15.1`).
    ///
    /// `GET /metrics` is served here and nowhere else: the REST API port (`--api-addr`) carries the
    /// bearer-protected `/api/v1/*` routes and the unauthenticated `/healthz`/`/readyz` probes, and
    /// the webhook endpoints, so a scraper never needs (and never gets) a credential and the API is
    /// never reachable through the metrics port. Defaults to `0.0.0.0:9090` — all interfaces on
    /// purpose, because Prometheus scrapes the pod IP; use `127.0.0.1:9090` or a `NetworkPolicy`
    /// to restrict it. `:0` binds an ephemeral port, which is logged.
    ///
    /// The exposition is strictly low-cardinality and carries no secret material: no `commit_sha`,
    /// no error message, no repository URL and no resource name is ever a label — only
    /// `result` (`success|retryable|terminal`), `outcome` (`hit|miss`), the
    /// `app_namespace`/`app_name` identity, and the fixed sync/health status sets. Families:
    /// `ferriscd_reconcile_duration_seconds`, `ferriscd_reconcile_total`,
    /// `ferriscd_app_sync_status`, `ferriscd_app_health_status`,
    /// `ferriscd_git_fetch_duration_seconds`, `ferriscd_render_cache_total`, and
    /// `ferriscd_active_reconciles`. Falls back to `FERRISCD_METRICS_ADDR`.
    #[arg(
        long = "metrics-addr",
        value_name = "ADDR",
        env = ferriscd_controller::METRICS_ADDR_ENV,
        default_value = ferriscd_controller::DEFAULT_METRICS_ADDR
    )]
    pub metrics_addr: String,

    /// Optional append-only JSONL compliance audit log file path (`T17.2`).
    ///
    /// Structured JSON audit events are always emitted to stdout (`ferriscd::audit` target); this
    /// adds a non-blocking local JSONL file sink. The sink keeps the file handle for the process
    /// lifetime, so rotate with `copytruncate` (or a sidecar that does), never plain `mv`:
    /// logrotate's default rename+create would leave the trail writing to the renamed file.
    #[arg(
        long = "audit-log-path",
        value_name = "PATH",
        env = "FERRISCD_AUDIT_LOG_PATH"
    )]
    pub audit_log_path: Option<PathBuf>,

    /// Optional async batched HTTPS compliance audit webhook URL (`T17.2`).
    ///
    /// Must use `https://` with no embedded credentials; loopback and link-local/IMDS targets are
    /// refused by the built-in SSRF guard.
    #[arg(
        long = "audit-webhook-url",
        value_name = "HTTPS_URL",
        env = "FERRISCD_AUDIT_WEBHOOK_URL",
        hide_env_values = true
    )]
    pub audit_webhook_url: Option<String>,

    /// Enable event-driven notifications (`T19.4`).
    ///
    /// Off by default. When enabled, the `/status` writer is decorated with a notification observer,
    /// and `Application`s opt in **exclusively** through annotations:
    ///
    ///   notifications.ferriscd.io/subscribe.<trigger>.<service>: <recipient>
    ///
    /// where `<trigger>` is one of `on-sync-succeeded`, `on-sync-failed`, `on-health-degraded`,
    /// `on-out-of-sync`, `<service>` is `slack`, `teams`, `pagerduty` or `webhook`, and `<recipient>`
    /// names a `Secret` labelled `ferriscd.io/secret-type=notifications` in `--namespace` with
    /// `url` (https:// only), `service`, and optionally `signingKey` (generic webhook HMAC-SHA256,
    /// sent as `X-FerrisCD-Signature-256`), `routingKey` (PagerDuty Events API v2), `token` (Slack
    /// Bot API bearer credential, sent in the `Authorization` header) or `channel` (the Slack
    /// channel `chat.postMessage` posts into). Slack therefore supports both an Incoming Webhook
    /// URL and the Bot API; Teams Workflow webhooks send an Adaptive Card.
    ///
    /// Message templates and the `on-out-of-sync` debounce come from
    /// `ConfigMap/ferriscd-notifications-cm` (key `notifications.yaml`); without it the built-in
    /// templates are used. No credential ever lives in an annotation or a `ConfigMap`.
    ///
    /// Delivery is non-blocking (bounded queue of 512, dropped and counted when full), SSRF-guarded
    /// (HTTPS only, loopback/link-local/cloud-metadata/private addresses refused, redirects never
    /// followed, validated IP pinned at connect) and retried at most 3 times with a 5 s timeout per
    /// attempt. Failures increment `ferriscd_notifications_total{service, outcome}`.
    ///
    /// The controller therefore needs `get`/`list` on `configmaps` and `secrets` in the control-plane
    /// namespace (the same namespaced grants `T12.4`/`T13.1` already require).
    #[arg(long = "enable-notifications", env = "FERRISCD_ENABLE_NOTIFICATIONS")]
    pub enable_notifications: bool,

    /// CIDRs whose **private** notification destinations are allowed through the SSRF guard.
    ///
    /// Comma-separated (`10.20.0.0/16,fd00:20::/48`). Only RFC 1918 / CGNAT / IPv6 ULA targets can
    /// be unlocked: loopback, link-local and cloud metadata addresses (`169.254.169.254`,
    /// `fd00:ec2::254`, `::ffff:169.254.169.254`) stay refused, and a `/0` entry is rejected rather
    /// than silently disabling the guard. Falls back to
    /// `FERRISCD_NOTIFICATIONS_ALLOW_PRIVATE_CIDRS`.
    #[arg(
        long = "notifications-allow-private-cidrs",
        value_name = "CIDRS",
        env = "FERRISCD_NOTIFICATIONS_ALLOW_PRIVATE_CIDRS"
    )]
    pub notifications_allow_private_cidrs: Option<String>,

    /// Namespaces whose `Application`s may subscribe to notifications at all.
    ///
    /// Comma-separated (`team-a,team-b`). Unset means **every** namespace may opt in through its
    /// annotations, which is the default. Because a channel `Secret` lives in the control-plane
    /// namespace, an `Application` in *any* namespace could otherwise name another team's channel
    /// and page them; this flag is the tenancy boundary: an `Application` outside the list is
    /// ignored before any edge, deduplication, rate-limit or delivery decision (finding R1-M6). At most
    /// 256 namespaces, and an empty entry is refused at startup rather than ignored.
    /// Falls back to `FERRISCD_NOTIFICATIONS_ALLOWED_NAMESPACES`.
    #[arg(
        long = "notifications-allowed-namespaces",
        value_name = "NAMESPACES",
        env = "FERRISCD_NOTIFICATIONS_ALLOWED_NAMESPACES"
    )]
    pub notifications_allowed_namespaces: Option<String>,

    /// PEM CA bundle whose certificates are **added** to the notification client's trust roots.
    ///
    /// Use this for an internal HTTPS receiver signed by a private or self-signed CA: the
    /// certificates are *added* to the platform roots, so verification and hostname/IP checks stay on
    /// and the SSRF guard is untouched. There is deliberately no flag to skip verification or to
    /// allow plaintext: a receiver that cannot present a certificate the controller trusts is not a
    /// valid notification destination. The file is read (and must parse) at startup, so a typo fails
    /// immediately instead of failing TLS on the first alert. It is read **even when
    /// `--enable-notifications` is off**, so a bad path can never sit dormant until the feature is
    /// switched on. Falls back to `FERRISCD_NOTIFICATIONS_CA_FILE`.
    #[arg(
        long = "notifications-ca-file",
        value_name = "PATH",
        env = "FERRISCD_NOTIFICATIONS_CA_FILE"
    )]
    pub notifications_ca_file: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for ControllerArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerArgs")
            .field("namespace", &self.namespace)
            .field("application_namespaces", &self.application_namespaces)
            .field("allow_local_repos", &self.allow_local_repos)
            .field("work_root", &self.work_root)
            .field(
                "allow_insecure_cluster_tls",
                &self.allow_insecure_cluster_tls,
            )
            .field("enable_drift_watcher", &self.enable_drift_watcher)
            .field("leader_election", &self.leader_election)
            .field(
                "leader_election_lease_name",
                &self.leader_election_lease_name,
            )
            .field(
                "leader_election_lease_duration_seconds",
                &self.leader_election_lease_duration_seconds,
            )
            .field(
                "leader_election_renew_interval_seconds",
                &self.leader_election_renew_interval_seconds,
            )
            .field("shard_id", &self.shard_id)
            .field("total_shards", &self.total_shards)
            .field("metrics_addr", &self.metrics_addr)
            .field("audit_log_path", &self.audit_log_path)
            .field(
                "audit_webhook_url",
                &self
                    .audit_webhook_url
                    .as_deref()
                    .map(ferriscd_controller::audit::redact_audit_url),
            )
            .field("enable_notifications", &self.enable_notifications)
            .field(
                "notifications_allow_private_cidrs",
                &self.notifications_allow_private_cidrs,
            )
            .field(
                "notifications_allowed_namespaces",
                &self.notifications_allowed_namespaces,
            )
            .field("notifications_ca_file", &self.notifications_ca_file)
            .finish()
    }
}

/// Executes `ferriscd controller`, blocking until `SIGINT`/`SIGTERM`.
pub async fn run(args: ControllerArgs) -> Result<()> {
    ferriscd_controller::run_with(run_options(args)).await
}

/// Maps the parsed flags onto the controller's [`RunOptions`].
///
/// Split out of [`run`] so the flag → controller mapping is testable without a cluster — including
/// the `T13.3` decision never to forward the single-leader `Lease` name to a sharded replica.
pub(crate) fn run_options(args: ControllerArgs) -> ferriscd_controller::RunOptions {
    let leader_election =
        args.leader_election
            .then(|| ferriscd_controller::LeaderElectionOptions {
                // The single-leader default is never forwarded: it is what the controller applies
                // when no name is given, and a sharded replica must never claim it (its per-shard
                // `ferriscd-leader-shard-<id>` name is derived by the controller, which also refuses
                // any other name — `T13.3`). Passing `--leader-election-lease-name` *explicitly* with
                // its default value is therefore the same as omitting it, which is exactly the
                // documented meaning of a default.
                lease_name: (args.leader_election_lease_name
                    != ferriscd_controller::DEFAULT_LEASE_NAME)
                    .then(|| args.leader_election_lease_name.clone()),
                lease_duration: Some(Duration::from_secs(
                    args.leader_election_lease_duration_seconds,
                )),
                renew_interval: Some(Duration::from_secs(
                    args.leader_election_renew_interval_seconds,
                )),
                identity: None,
            });
    ferriscd_controller::RunOptions {
        namespace: args.namespace,
        application_namespaces: args.application_namespaces,
        allow_local_repos: args.allow_local_repos,
        work_root: args.work_root,
        allow_insecure_clusters: args.allow_insecure_cluster_tls,
        // `T18.1`: `--enable-drift-watcher` / `FERRISCD_ENABLE_DRIFT_WATCHER`. Off means the apply
        // body keeps only the `ferriscd.io/tracking-id` annotation, exactly as before `v1.2`.
        enable_drift_watcher: args.enable_drift_watcher,
        leader_election,
        // `T13.3`: the raw flag pair; the controller validates it and refuses sharding without
        // `--leader-election` (or with a lease name other than the per-shard one). Both unset — the
        // default — leaves the single-replica behaviour untouched.
        shard: ferriscd_controller::ShardOptions::new(args.shard_id, args.total_shards),
        // `T15.1`: the CLI always serves `/metrics`; the library default (`None`) keeps tests and
        // other embedders off a socket. The controller parses and binds this before any client.
        metrics_addr: Some(args.metrics_addr),
        audit_log_path: args.audit_log_path,
        audit_webhook_url: args.audit_webhook_url,
        // `T19.4`: notifications stay off unless `--enable-notifications` is given; the CIDR
        // allowlist and the tenant allowlist are only meaningful with them on, and both are
        // validated by the controller at startup (a malformed entry must fail loudly, never
        // silently default).
        notifications: ferriscd_controller::NotificationOptions {
            enabled: args.enable_notifications,
            allow_private_cidrs: args.notifications_allow_private_cidrs,
            allowed_namespaces: args.notifications_allowed_namespaces,
            ca_file: args.notifications_ca_file,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    /// Minimal parser harness so the subcommand wiring is testable without the real binary.
    #[derive(Debug, Parser)]
    #[command(name = "ferriscd")]
    struct Harness {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Debug, clap::Subcommand)]
    enum Command {
        Controller(ControllerArgs),
    }

    fn parse(args: &[&str]) -> ControllerArgs {
        let harness = Harness::try_parse_from(args).expect("controller arguments must parse");
        match harness.command {
            Command::Controller(args) => args,
        }
    }

    #[test]
    fn controller_defaults_are_production_safe() {
        let args = parse(&["ferriscd", "controller"]);
        assert_eq!(args.namespace, None);
        assert!(
            !args.allow_local_repos,
            "local repositories must never be allowed by default"
        );
        assert_eq!(args.work_root, None);
        assert_eq!(
            args.application_namespaces, None,
            "Apps-in-any-namespace must stay opt-in"
        );
        assert!(
            !args.leader_election,
            "leader election must stay opt-in: without it the single-replica behaviour is what \
             ships"
        );
        assert!(
            !args.allow_insecure_cluster_tls,
            "remote-cluster TLS verification must never be disabled by default"
        );
        // The defaults are the documented, valid lease timings.
        assert_eq!(
            args.leader_election_lease_name,
            ferriscd_controller::DEFAULT_LEASE_NAME
        );
        assert_eq!(
            args.leader_election_lease_duration_seconds,
            ferriscd_controller::DEFAULT_LEASE_DURATION.as_secs()
        );
        assert_eq!(
            args.leader_election_renew_interval_seconds,
            ferriscd_controller::DEFAULT_RENEW_INTERVAL.as_secs()
        );
        // The defaults must satisfy the controller's own validation.
        let options = ferriscd_controller::RunOptions {
            leader_election: Some(ferriscd_controller::LeaderElectionOptions::default()),
            ..Default::default()
        };
        assert!(
            options
                .leader_election_config("ferriscd-system")
                .expect("the defaults must be valid")
                .is_some()
        );
        // `T15.1`: the CLI always serves `/metrics`, on the dedicated metrics port only.
        assert_eq!(args.metrics_addr, ferriscd_controller::DEFAULT_METRICS_ADDR);
        let options = run_options(parse(&["ferriscd", "controller"]));
        assert_eq!(
            options.metrics_addr.as_deref(),
            Some(ferriscd_controller::DEFAULT_METRICS_ADDR),
            "the shipped command must serve the metrics endpoint: the library default (`None`) is \
             only for tests and other embedders"
        );
        assert!(
            ferriscd_controller::DEFAULT_METRICS_ADDR.ends_with(":9090"),
            "the metrics listener has its own documented port"
        );
        // `T13.3`: no shard flags means no sharding, i.e. the pre-Phase-13 work partition.
        assert_eq!(args.shard_id, None);
        assert_eq!(args.total_shards, None);
        let plan = ferriscd_controller::RunOptions::default()
            .ha_plan("ferriscd-system")
            .expect("the defaults must be valid");
        assert_eq!(plan.shard, None, "sharding must stay opt-in");
        assert_eq!(plan.leader_election, None);
    }

    #[test]
    fn controller_parses_the_ha_flags() {
        let args = parse(&[
            "ferriscd",
            "controller",
            "--leader-election",
            "--leader-election-lease-name",
            "custom-lease",
            "--leader-election-lease-duration-seconds",
            "30",
            "--leader-election-renew-interval-seconds",
            "8",
            "--allow-insecure-cluster-tls",
        ]);
        assert!(args.leader_election);
        assert_eq!(args.leader_election_lease_name, "custom-lease");
        assert_eq!(args.leader_election_lease_duration_seconds, 30);
        assert_eq!(args.leader_election_renew_interval_seconds, 8);
        assert!(args.allow_insecure_cluster_tls);
    }

    /// **`T13.3`:** the sharding flags parse, and a sharded replica gets its **own** per-shard
    /// `Lease` — never the single-leader default, which is what `run_options` decides.
    #[test]
    fn controller_parses_the_sharding_flags_and_derives_the_per_shard_lease() {
        let args = parse(&[
            "ferriscd",
            "controller",
            "--leader-election",
            "--shard-id",
            "1",
            "--total-shards",
            "3",
        ]);
        assert_eq!(args.shard_id, Some(1));
        assert_eq!(args.total_shards, Some(3));
        assert!(args.leader_election);

        // The real flag → controller mapping, so this test cannot drift from `run`.
        let options = run_options(args);
        assert_eq!(
            options.shard,
            ferriscd_controller::ShardOptions::new(Some(1), Some(3))
        );
        let plan = options
            .ha_plan("ferriscd-system")
            .expect("a sharded replica with leader election is valid");
        let shard = plan.shard.expect("sharding is on");
        assert_eq!(shard.shard_id(), 1);
        assert_eq!(shard.total_shards(), 3);
        let lease = plan.leader_election.expect("election is on");
        assert_eq!(
            lease.lease_name(),
            "ferriscd-leader-shard-1",
            "the shard's own Lease, not ferriscd-controller-leader"
        );
        assert_ne!(
            lease.lease_name(),
            ferriscd_controller::DEFAULT_LEASE_NAME,
            "a sharded replica must never compete for the single-leader Lease"
        );
        assert_eq!(lease.namespace(), "ferriscd-system");

        // A `Lease` name that matches the shard's own is accepted (the "explicitly paired" mode).
        let paired = ferriscd_controller::RunOptions {
            leader_election: Some(ferriscd_controller::LeaderElectionOptions {
                lease_name: Some("ferriscd-leader-shard-1".to_owned()),
                ..Default::default()
            }),
            shard: ferriscd_controller::ShardOptions::new(Some(1), Some(3)),
            ..Default::default()
        };
        assert_eq!(
            paired
                .ha_plan("ferriscd-system")
                .expect("the per-shard name is explicit and correct")
                .leader_election
                .expect("election is on")
                .lease_name(),
            "ferriscd-leader-shard-1"
        );
    }

    /// **`T13.3` trap guard:** no flag combination can produce "sharding plus one shared leader" or
    /// "sharding with no election at all" — the two shapes that either starve every shard but one or
    /// double-apply a shard.
    #[test]
    fn sharding_conflicts_are_rejected() {
        // clap level: the pair is all-or-nothing.
        for partial in [
            vec![
                "ferriscd",
                "controller",
                "--leader-election",
                "--shard-id",
                "0",
            ],
            vec![
                "ferriscd",
                "controller",
                "--leader-election",
                "--total-shards",
                "3",
            ],
        ] {
            assert!(
                Harness::try_parse_from(&partial).is_err(),
                "{partial:?} must be rejected: --shard-id and --total-shards go together"
            );
        }

        // clap level: an explicit `Lease` name cannot be combined with sharding — a shard's name is
        // derived, and one shared `Lease` would leave every other shard unreconciled.
        for lease in [
            ferriscd_controller::DEFAULT_LEASE_NAME,
            "ferriscd-leader-shard-0",
            "custom",
        ] {
            assert!(
                Harness::try_parse_from([
                    "ferriscd",
                    "controller",
                    "--leader-election",
                    "--shard-id",
                    "0",
                    "--total-shards",
                    "2",
                    "--leader-election-lease-name",
                    lease,
                ])
                .is_err(),
                "--leader-election-lease-name {lease} must be rejected together with --shard-id"
            );
        }

        // The controller level, where the rule actually lives (the CLI is one caller of it):
        // sharding without leader election.
        let options = ferriscd_controller::RunOptions {
            shard: ferriscd_controller::ShardOptions::new(Some(0), Some(2)),
            ..Default::default()
        };
        let err = options
            .ha_plan("ferriscd-system")
            .expect_err("sharding without leader election must be refused");
        assert!(
            err.to_string().contains("--leader-election"),
            "the refusal must name the missing flag: {err}"
        );

        // Sharding combined with the single-leader `Lease`.
        let conflicted = ferriscd_controller::RunOptions {
            leader_election: Some(ferriscd_controller::LeaderElectionOptions {
                lease_name: Some(ferriscd_controller::DEFAULT_LEASE_NAME.to_owned()),
                ..Default::default()
            }),
            shard: ferriscd_controller::ShardOptions::new(Some(0), Some(2)),
            ..Default::default()
        };
        let err = conflicted
            .ha_plan("ferriscd-system")
            .expect_err("one shared Lease cannot serve per-shard election");
        assert!(
            err.to_string().contains("ferriscd-leader-shard-0"),
            "the refusal must name the Lease the shard needs: {err}"
        );

        // Out of range: a shard index that cannot exist would reconcile nothing.
        let out_of_range = ferriscd_controller::RunOptions {
            leader_election: Some(ferriscd_controller::LeaderElectionOptions::default()),
            shard: ferriscd_controller::ShardOptions::new(Some(2), Some(2)),
            ..Default::default()
        };
        assert!(
            out_of_range.ha_plan("ferriscd-system").is_err(),
            "--shard-id 2 of --total-shards 2 must be refused"
        );
    }

    #[test]
    fn controller_accepts_explicit_overrides() {
        let args = parse(&[
            "ferriscd",
            "controller",
            "--namespace",
            "apps",
            "--allow-local-repos",
            "--work-root",
            "/var/run/ferriscd",
        ]);
        assert_eq!(args.namespace.as_deref(), Some("apps"));
        assert!(args.allow_local_repos);
        assert_eq!(args.work_root, Some(PathBuf::from("/var/run/ferriscd")));
    }

    #[test]
    fn controller_parses_the_application_namespaces_flag() {
        let listed = parse(&[
            "ferriscd",
            "controller",
            "--application-namespaces",
            "ferriscd-system,team-a",
        ]);
        assert_eq!(
            listed.application_namespaces.as_deref(),
            Some("ferriscd-system,team-a")
        );

        let all = parse(&["ferriscd", "controller", "--application-namespaces", "*"]);
        assert_eq!(all.application_namespaces.as_deref(), Some("*"));

        // The value is validated by the controller config, not here, so a malformed value still
        // parses as a string (and is then rejected loudly instead of silently defaulting).
        let malformed = parse(&[
            "ferriscd",
            "controller",
            "--application-namespaces",
            "Team-A",
        ]);
        assert_eq!(malformed.application_namespaces.as_deref(), Some("Team-A"));
    }

    /// **`T15.1`:** the metrics flag parses, reaches the controller's `RunOptions`, and declares its
    /// environment fallback. The listener is on its own port, so `--metrics-addr` is independent of
    /// `--api-addr` (`ferriscd server` refuses a value that collides with it).
    #[test]
    fn controller_parses_the_metrics_flag_and_its_env_fallback() {
        let args = parse(&[
            "ferriscd",
            "controller",
            "--metrics-addr",
            "127.0.0.1:19090",
        ]);
        assert_eq!(args.metrics_addr, "127.0.0.1:19090");
        assert_eq!(
            run_options(args).metrics_addr.as_deref(),
            Some("127.0.0.1:19090")
        );

        // The env fallback is *declared* on the flag (clap reads `FERRISCD_METRICS_ADDR` when the
        // flag is absent); asserting the declaration avoids mutating the process environment.
        let mut command = Harness::command();
        let controller = command
            .find_subcommand_mut("controller")
            .expect("the controller subcommand exists");
        let arg = controller
            .get_arguments()
            .find(|arg| arg.get_id() == "metrics_addr")
            .expect("the --metrics-addr argument exists");
        assert_eq!(
            arg.get_env().and_then(|env| env.to_str()),
            Some("FERRISCD_METRICS_ADDR")
        );
        assert_eq!(
            arg.get_default_values()
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec![ferriscd_controller::DEFAULT_METRICS_ADDR.to_owned()],
            "the default is the documented dedicated metrics port"
        );

        // The value is passed through untouched; the controller parses it at startup and rejects an
        // unusable one with the expected format in the message (never a silent default).
        let unusable = run_options(parse(&["ferriscd", "controller", "--metrics-addr", "9090"]));
        assert_eq!(unusable.metrics_addr.as_deref(), Some("9090"));
    }

    /// **`T19.4`:** notifications are opt-in, the allowlist reaches the controller untouched, and the
    /// flag help documents the annotation contract, the `Secret` label, the metrics family and the
    /// RBAC an operator must grant.
    #[test]
    fn controller_parses_the_notification_flags_and_documents_the_contract() {
        let defaults = parse(&["ferriscd", "controller"]);
        assert!(
            !defaults.enable_notifications,
            "notifications must stay opt-in"
        );
        assert_eq!(defaults.notifications_allow_private_cidrs, None);
        let options = run_options(parse(&["ferriscd", "controller"]));
        assert!(!options.notifications.enabled);
        assert_eq!(options.notifications.allow_private_cidrs, None);
        assert!(
            options
                .notifications
                .egress_policy()
                .expect("the default policy is the strict one")
                .is_strict()
        );

        let args = parse(&[
            "ferriscd",
            "controller",
            "--enable-notifications",
            "--notifications-allow-private-cidrs",
            "10.20.0.0/16,fd00:20::/48",
        ]);
        assert!(args.enable_notifications);
        let options = run_options(args);
        assert!(options.notifications.enabled);
        assert_eq!(
            options.notifications.allow_private_cidrs.as_deref(),
            Some("10.20.0.0/16,fd00:20::/48")
        );
        assert_eq!(
            options
                .notifications
                .egress_policy()
                .expect("the allowlist is valid")
                .allowlisted_networks()
                .len(),
            2
        );

        // A malformed allowlist is refused by the controller (here: the same validation), not
        // silently ignored.
        let invalid = run_options(parse(&[
            "ferriscd",
            "controller",
            "--enable-notifications",
            "--notifications-allow-private-cidrs",
            "0.0.0.0/0",
        ]));
        assert!(invalid.notifications.egress_policy().is_err());

        let mut command = Harness::command();
        let help = command
            .find_subcommand_mut("controller")
            .expect("the controller subcommand exists")
            .render_long_help()
            .to_string();
        for expected in [
            "--enable-notifications",
            "--notifications-allow-private-cidrs",
            "notifications.ferriscd.io/subscribe.",
            "on-sync-failed",
            "on-health-degraded",
            "on-out-of-sync",
            "ferriscd.io/secret-type=notifications",
            "X-FerrisCD-Signature-256",
            "ferriscd-notifications-cm",
            "ferriscd_notifications_total",
            "169.254.169.254",
            "FERRISCD_ENABLE_NOTIFICATIONS",
            "FERRISCD_NOTIFICATIONS_ALLOW_PRIVATE_CIDRS",
        ] {
            assert!(
                help.contains(expected),
                "the flag help must document {expected:?}"
            );
        }
    }

    /// **`T19.4` findings R1-M6 + P19-H1:** the tenancy allowlist and the private-CA bundle reach the
    /// controller untouched, both have an environment fallback, and the help states why there is no
    /// "skip TLS verification" escape hatch.
    #[test]
    fn controller_parses_the_notification_scope_and_ca_flags() {
        // Finding R1-M6: the tenant allowlist is forwarded verbatim and normalised by the controller.
        let options = run_options(parse(&[
            "ferriscd",
            "controller",
            "--enable-notifications",
            "--notifications-allowed-namespaces",
            "team-a, team-b",
        ]));
        assert_eq!(
            options.notifications.allowed_namespaces.as_deref(),
            Some("team-a, team-b"),
            "the raw flag reaches the controller untouched"
        );
        assert_eq!(
            options
                .notifications
                .allowed_namespaces()
                .expect("a valid allowlist"),
            Some(vec!["team-a".to_owned(), "team-b".to_owned()]),
            "the controller normalises (and bounds) it at startup"
        );

        // Unset means "every namespace may opt in", the pre-existing behaviour.
        assert_eq!(
            run_options(parse(&["ferriscd", "controller"]))
                .notifications
                .allowed_namespaces()
                .expect("no allowlist is valid"),
            None
        );
        // A blank entry fails closed instead of silently widening the list.
        assert!(
            run_options(parse(&[
                "ferriscd",
                "controller",
                "--notifications-allowed-namespaces",
                "team-a,",
            ]))
            .notifications
            .allowed_namespaces()
            .is_err(),
            "an empty entry must be refused at startup"
        );

        // Finding P19-H1: the CA path is forwarded untouched; the controller reads and parses it at
        // startup (a typo must fail then, not on the first alert).
        let options = run_options(parse(&[
            "ferriscd",
            "controller",
            "--enable-notifications",
            "--notifications-ca-file",
            "/etc/ferriscd/notifications-ca.pem",
        ]));
        assert_eq!(
            options.notifications.ca_file.as_deref(),
            Some(std::path::Path::new("/etc/ferriscd/notifications-ca.pem"))
        );
        assert_eq!(
            run_options(parse(&["ferriscd", "controller"]))
                .notifications
                .ca_file,
            None,
            "no CA file means the platform trust store alone"
        );
        // A path is not a credential, so the options' `Debug` may print it.
        assert!(
            format!("{options:?}").contains("/etc/ferriscd/notifications-ca.pem"),
            "{options:?}"
        );

        // Both flags have an environment fallback (asserted through clap's own metadata, so the
        // process environment is never mutated by a test).
        let mut command = Harness::command();
        let controller = command
            .find_subcommand_mut("controller")
            .expect("the controller subcommand exists");
        for (id, expected_env) in [
            (
                "notifications_allowed_namespaces",
                "FERRISCD_NOTIFICATIONS_ALLOWED_NAMESPACES",
            ),
            ("notifications_ca_file", "FERRISCD_NOTIFICATIONS_CA_FILE"),
        ] {
            let arg = controller
                .get_arguments()
                .find(|arg| arg.get_id() == id)
                .expect("the argument exists");
            assert_eq!(
                arg.get_env().and_then(|env| env.to_str()),
                Some(expected_env),
                "{id} must fall back to {expected_env}"
            );
        }

        let mut command = Harness::command();
        let help = command
            .find_subcommand_mut("controller")
            .expect("the controller subcommand exists")
            .render_long_help()
            .to_string();
        for expected in [
            "--notifications-allowed-namespaces",
            "FERRISCD_NOTIFICATIONS_ALLOWED_NAMESPACES",
            "--notifications-ca-file",
            "FERRISCD_NOTIFICATIONS_CA_FILE",
            "private or self-signed CA",
            "SSRF guard",
            "tenancy boundary",
        ] {
            assert!(
                help.contains(expected),
                "the flag help must document {expected:?}"
            );
        }
    }

    /// **`T18.1`:** `--enable-drift-watcher` is off by default, reaches `RunOptions`, and declares
    /// its environment fallback. It is the only switch that adds the ownership label pair to every
    /// applied object, so a mistaken default would rewrite the whole fleet's metadata.
    #[test]
    fn controller_parses_the_drift_watcher_flag_and_its_env_fallback() {
        let args = parse(&["ferriscd", "controller"]);
        assert!(
            !args.enable_drift_watcher,
            "the ownership labels must stay opt-in"
        );
        assert!(!run_options(parse(&["ferriscd", "controller"])).enable_drift_watcher);
        assert!(
            !ferriscd_controller::RunOptions::default().enable_drift_watcher,
            "the library default is off too (hermetic tests and other embedders)"
        );

        let enabled = parse(&["ferriscd", "controller", "--enable-drift-watcher"]);
        assert!(enabled.enable_drift_watcher);
        assert!(
            run_options(enabled).enable_drift_watcher,
            "the flag must reach the controller's RunOptions, where the pipeline reads it"
        );

        // The env fallback is *declared* on the flag (clap reads it when the flag is absent);
        // asserting the declaration avoids mutating the process environment.
        let mut command = Harness::command();
        let controller = command
            .find_subcommand_mut("controller")
            .expect("the controller subcommand exists");
        let arg = controller
            .get_arguments()
            .find(|arg| arg.get_id() == "enable_drift_watcher")
            .expect("the --enable-drift-watcher argument exists");
        assert_eq!(
            arg.get_env().and_then(|env| env.to_str()),
            Some(ferriscd_controller::DRIFT_WATCHER_ENV),
            "a Deployment must be able to opt in without changing argv"
        );
        assert_eq!(
            arg.get_default_values().len(),
            0,
            "a bool flag with no default is `false`: the labels are additive and opt-in"
        );
        // **Finding M2:** the action is what pins the env semantics. `SetTrue` (not `Set`/`Count`)
        // is why a value is optional on the command line yet each env/default value is parsed as a
        // bool, so `FERRISCD_ENABLE_DRIFT_WATCHER=false` really means *off* and a non-`true`/`false`
        // value is a usage error instead of a truthiness guess. (`ArgAction` is `Clone + Debug` only,
        // so the pin is a `matches!`, not an `assert_eq!`.)
        assert!(
            matches!(arg.get_action(), clap::ArgAction::SetTrue),
            "a `Set`/`Count` action would let any non-empty env value enable the labels, got {:?}",
            arg.get_action()
        );
    }

    /// **Finding T12-M1:** the RBAC an operator has to grant for multi-tenancy is in the flag help, not    /// only in a doc file nobody reads before turning the flag on.
    #[test]
    fn the_application_namespaces_help_documents_the_required_rbac() {
        let mut command = Harness::command();
        let help = command
            .find_subcommand_mut("controller")
            .expect("the controller subcommand exists")
            .render_long_help()
            .to_string();

        for expected in [
            "--application-namespaces",
            // `T13.1`/`T13.2`: the cluster-registry and Lease grants must be in `--help` too.
            "--leader-election",
            "coordination.k8s.io",
            "leases",
            "--allow-insecure-cluster-tls",
            "ferriscd.io/secret-type=cluster",
            "serviceAccountName",
            "impersonate",
            "users",
            "groups",
            "serviceaccounts",
            "appprojects",
            "applications/status",
            "applications/finalizers",
            "system:masters",
            "deploy/README.md",
            // `T12.4`: the repository credential `Secret` grant must be visible in `--help` too,
            // and it must say "namespaced", so nobody adds a cluster-wide `secrets` rule.
            "secrets",
            "ferriscd.io/secret-type=repository",
            "Role/RoleBinding",
            // `T13.3`: the sharding flags, the per-shard lease naming and the environment
            // fallbacks an operator needs for a `StatefulSet`.
            "--shard-id",
            "--total-shards",
            "ferriscd-leader-shard-",
            "FERRISCD_SHARD_ID",
            "FERRISCD_TOTAL_SHARDS",
            // `T15.1`: the metrics listener is on its own port, with an env fallback, and the help
            // states the cardinality contract so nobody adds a `commit_sha` label.
            "--metrics-addr",
            "FERRISCD_METRICS_ADDR",
            "9090",
            "/metrics",
            "ferriscd_reconcile_total",
            "ferriscd_reconcile_duration_seconds",
            "ferriscd_app_sync_status",
            "ferriscd_app_health_status",
            "ferriscd_git_fetch_duration_seconds",
            "ferriscd_render_cache_total",
            "ferriscd_active_reconciles",
            "commit_sha",
            // `T18.1`: the ownership-label opt-in and its env fallback.
            "--enable-drift-watcher",
            "FERRISCD_ENABLE_DRIFT_WATCHER",
            "ferriscd.io/managed-by",
            "ferriscd.io/app-hash",
        ] {
            assert!(
                help.contains(expected),
                "the flag help must document {expected:?}: {help}"
            );
        }
    }
}

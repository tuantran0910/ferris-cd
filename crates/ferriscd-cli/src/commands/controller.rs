//! `ferriscd controller` — run the Kubernetes controller (Phase 06 `v0.2`).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Args;

/// Arguments for `ferriscd controller`.
#[derive(Debug, Args)]
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
        leader_election,
        // `T13.3`: the raw flag pair; the controller validates it and refuses sharding without
        // `--leader-election` (or with a lease name other than the per-shard one). Both unset — the
        // default — leaves the single-replica behaviour untouched.
        shard: ferriscd_controller::ShardOptions::new(args.shard_id, args.total_shards),
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

    /// **Finding M1:** the RBAC an operator has to grant for multi-tenancy is in the flag help, not
    /// only in a doc file nobody reads before turning the flag on.
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
        ] {
            assert!(
                help.contains(expected),
                "the flag help must document {expected:?}: {help}"
            );
        }
    }
}

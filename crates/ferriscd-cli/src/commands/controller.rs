//! `ferriscd controller` — run the Kubernetes controller (Phase 06 `v0.2`).

use std::path::PathBuf;

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
}

/// Executes `ferriscd controller`, blocking until `SIGINT`/`SIGTERM`.
pub async fn run(args: ControllerArgs) -> Result<()> {
    ferriscd_controller::run_with(ferriscd_controller::RunOptions {
        namespace: args.namespace,
        application_namespaces: args.application_namespaces,
        allow_local_repos: args.allow_local_repos,
        work_root: args.work_root,
    })
    .await
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
        ] {
            assert!(
                help.contains(expected),
                "the flag help must document {expected:?}: {help}"
            );
        }
    }
}

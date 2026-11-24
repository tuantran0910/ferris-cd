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
        allow_local_repos: args.allow_local_repos,
        work_root: args.work_root,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

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
}

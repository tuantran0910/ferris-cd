//! `ferriscd` CLI binary entrypoint.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "ferriscd", version, about = "FerrisCD GitOps CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Apply a Git repository's manifests via Server-Side Apply.
    Apply(commands::apply::ApplyArgs),
    /// Apply a single Kubernetes YAML manifest via Server-Side Apply.
    ApplyFile(commands::apply_file::ApplyFileArgs),
    /// Generate or verify the committed FerrisCD CustomResourceDefinition manifests.
    Crd(commands::crd::CrdArgs),
    /// Run the Kubernetes controller (watch `Application` CRs and sync them).
    Controller(commands::controller::ControllerArgs),
    /// Run the controller **and** the in-process REST API/webhook server in one process.
    Server(commands::server::ServerArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing::debug!(
        api_group = ferriscd_crd::api_group(),
        field_manager = ferriscd_engine::default_field_manager(),
        controller = ferriscd_controller::controller_name(),
        "executing ferriscd cli"
    );

    match cli.command {
        Commands::Apply(args) => commands::apply::run(args).await,
        Commands::ApplyFile(args) => commands::apply_file::run(args).await,
        Commands::Crd(args) => commands::crd::run(args).await,
        Commands::Controller(args) => commands::controller::run(args).await,
        Commands::Server(args) => commands::server::run(args).await,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn crate_boundaries_wire_cleanly() {
        assert_eq!(ferriscd_crd::api_group(), "ferriscd.io");
        assert_eq!(ferriscd_engine::default_field_manager(), "ferriscd");
        assert_eq!(ferriscd_controller::controller_name(), "ferriscd");
    }

    fn apply_file_args(cli: Cli) -> commands::apply_file::ApplyFileArgs {
        match cli.command {
            Commands::ApplyFile(args) => args,
            other => panic!("expected apply-file command, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_apply_command() {
        let cli = Cli::try_parse_from([
            "ferriscd",
            "apply",
            "--repo",
            "https://github.com/example/payment-service.git",
            "--rev",
            "main",
            "--path",
            "deploy/production",
            "--namespace",
            "payments",
        ])
        .expect("should parse `apply`");
        let args = match cli.command {
            Commands::Apply(args) => args,
            other => panic!("expected apply command, got {other:?}"),
        };
        assert_eq!(args.repo, "https://github.com/example/payment-service.git");
        assert_eq!(args.rev, "main");
        assert_eq!(args.path, "deploy/production");
        assert_eq!(args.namespace, "payments");
    }

    #[test]
    fn cli_parses_apply_file_with_and_without_namespace() {
        let cli_default =
            Cli::try_parse_from(["ferriscd", "apply-file", "examples/basic/configmap.yaml"])
                .expect("should parse without --namespace");
        let args = apply_file_args(cli_default);
        assert_eq!(args.path, Path::new("examples/basic/configmap.yaml"));
        assert_eq!(args.namespace, None);

        let cli_short_ns = Cli::try_parse_from([
            "ferriscd",
            "apply-file",
            "examples/basic/configmap.yaml",
            "-n",
            "ferriscd-demo",
        ])
        .expect("should parse with -n");
        let args = apply_file_args(cli_short_ns);
        assert_eq!(args.namespace.as_deref(), Some("ferriscd-demo"));

        let cli_long_ns = Cli::try_parse_from([
            "ferriscd",
            "apply-file",
            "examples/basic/configmap.yaml",
            "--namespace",
            "ferriscd-demo",
        ])
        .expect("should parse with --namespace");
        let args = apply_file_args(cli_long_ns);
        assert_eq!(args.namespace.as_deref(), Some("ferriscd-demo"));
    }

    #[test]
    fn cli_parses_crd_generate_with_defaults_and_overrides() {
        let default = Cli::try_parse_from(["ferriscd", "crd", "generate"])
            .expect("should parse `crd generate`");
        match default.command {
            Commands::Crd(args) => match args.command {
                commands::crd::CrdCommand::Generate(generate) => {
                    assert_eq!(
                        generate.output_dir,
                        Path::new(ferriscd_crd::generate::CRD_DIRECTORY)
                    );
                    assert!(!generate.check);
                }
            },
            other => panic!("expected crd command, got {other:?}"),
        }

        let override_args = Cli::try_parse_from([
            "ferriscd",
            "crd",
            "generate",
            "--output-dir",
            "deploy/crds",
            "--check",
        ])
        .expect("should parse `crd generate --check`");
        match override_args.command {
            Commands::Crd(args) => match args.command {
                commands::crd::CrdCommand::Generate(generate) => {
                    assert_eq!(generate.output_dir, Path::new("deploy/crds"));
                    assert!(generate.check);
                }
            },
            other => panic!("expected crd command, got {other:?}"),
        }
    }
}

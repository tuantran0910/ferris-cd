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
    /// Apply a single Kubernetes YAML manifest via Server-Side Apply.
    ApplyFile(commands::apply_file::ApplyFileArgs),
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
        Commands::ApplyFile(args) => commands::apply_file::run(args).await,
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

    #[test]
    fn cli_parses_apply_file_with_and_without_namespace() {
        let cli_default =
            Cli::try_parse_from(["ferriscd", "apply-file", "examples/basic/configmap.yaml"])
                .expect("should parse without --namespace");
        match cli_default.command {
            Commands::ApplyFile(args) => {
                assert_eq!(args.path, Path::new("examples/basic/configmap.yaml"));
                assert_eq!(args.namespace, None);
            }
        }

        let cli_short_ns = Cli::try_parse_from([
            "ferriscd",
            "apply-file",
            "examples/basic/configmap.yaml",
            "-n",
            "ferriscd-demo",
        ])
        .expect("should parse with -n");
        match cli_short_ns.command {
            Commands::ApplyFile(args) => {
                assert_eq!(args.namespace.as_deref(), Some("ferriscd-demo"));
            }
        }

        let cli_long_ns = Cli::try_parse_from([
            "ferriscd",
            "apply-file",
            "examples/basic/configmap.yaml",
            "--namespace",
            "ferriscd-demo",
        ])
        .expect("should parse with --namespace");
        match cli_long_ns.command {
            Commands::ApplyFile(args) => {
                assert_eq!(args.namespace.as_deref(), Some("ferriscd-demo"));
            }
        }
    }
}

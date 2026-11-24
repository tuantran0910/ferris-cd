//! `ferriscd crd` — generate (or verify) the committed CRD manifests.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

/// Arguments for `ferriscd crd`.
#[derive(Debug, Args)]
pub struct CrdArgs {
    /// CRD subcommand to run.
    #[command(subcommand)]
    pub command: CrdCommand,
}

/// Supported `ferriscd crd` subcommands.
#[derive(Debug, Subcommand)]
pub enum CrdCommand {
    /// Write `deploy/crds/*.yaml` from the Rust CRD definitions.
    Generate(GenerateArgs),
}

/// Arguments for `ferriscd crd generate`.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Directory the CRD manifests are written to.
    #[arg(long = "output-dir", default_value = ferriscd_crd::generate::CRD_DIRECTORY)]
    pub output_dir: PathBuf,

    /// Verify the manifests on disk instead of writing them (fails on drift).
    #[arg(long = "check")]
    pub check: bool,
}

/// Executes `ferriscd crd <subcommand>`.
pub async fn run(args: CrdArgs) -> Result<()> {
    match args.command {
        CrdCommand::Generate(args) => generate(&args).await,
    }
}

/// Renders the CRD manifests and writes them (or verifies them with `--check`).
///
/// All file access goes through `tokio::fs` so this never blocks an async worker.
pub async fn generate(args: &GenerateArgs) -> Result<()> {
    let documents = ferriscd_crd::generate::crd_documents().context("failed to render CRD YAML")?;

    if args.check {
        for document in &documents {
            let path = document.path_in(&args.output_dir);
            let existing = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("failed to read '{}'", path.display()))?;
            anyhow::ensure!(
                existing == document.manifest,
                "'{}' is out of date; run `ferriscd crd generate`",
                path.display()
            );
            println!("up to date: {}", path.display());
        }
        return Ok(());
    }

    tokio::fs::create_dir_all(&args.output_dir)
        .await
        .with_context(|| {
            format!(
                "failed to create output directory '{}'",
                args.output_dir.display()
            )
        })?;

    for document in &documents {
        let path = document.path_in(&args.output_dir);
        tokio::fs::write(&path, document.manifest.as_bytes())
            .await
            .with_context(|| format!("failed to write '{}'", path.display()))?;
        println!(
            "wrote {} ({} bytes)",
            path.display(),
            document.manifest.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferriscd_crd::generate::{
        APPLICATION_CRD_FILE_NAME, APPPROJECT_CRD_FILE_NAME, crd_documents,
    };

    fn args(output_dir: &std::path::Path, check: bool) -> GenerateArgs {
        GenerateArgs {
            output_dir: output_dir.to_path_buf(),
            check,
        }
    }

    #[tokio::test]
    async fn generate_writes_both_manifests_deterministically() {
        let temp = tempfile::tempdir().expect("tempdir must be created");
        let target = temp.path().join("crds");

        generate(&args(&target, false))
            .await
            .expect("generation must succeed");

        let application = tokio::fs::read_to_string(target.join(APPLICATION_CRD_FILE_NAME))
            .await
            .expect("applications CRD must be written");
        let appproject = tokio::fs::read_to_string(target.join(APPPROJECT_CRD_FILE_NAME))
            .await
            .expect("appprojects CRD must be written");
        assert!(application.contains("kind: CustomResourceDefinition"));
        assert!(application.contains("name: applications.ferriscd.io"));
        assert!(appproject.contains("name: appprojects.ferriscd.io"));

        // A second run over an existing directory must be byte-identical.
        generate(&args(&target, false))
            .await
            .expect("re-generation must succeed");
        let application_again = tokio::fs::read_to_string(target.join(APPLICATION_CRD_FILE_NAME))
            .await
            .expect("applications CRD must be readable");
        let appproject_again = tokio::fs::read_to_string(target.join(APPPROJECT_CRD_FILE_NAME))
            .await
            .expect("appprojects CRD must be readable");
        assert_eq!(application, application_again);
        assert_eq!(appproject, appproject_again);

        // ...and must match what the library renders in memory.
        let documents = crd_documents().expect("rendering must succeed");
        assert_eq!(documents[0].manifest, application);
        assert_eq!(documents[1].manifest, appproject);

        generate(&args(&target, true))
            .await
            .expect("freshly written manifests must pass --check");
    }

    #[tokio::test]
    async fn check_detects_drift_and_missing_files() {
        let temp = tempfile::tempdir().expect("tempdir must be created");
        let target = temp.path().join("crds");

        generate(&args(&target, true))
            .await
            .expect_err("--check must fail for a missing directory");

        generate(&args(&target, false))
            .await
            .expect("generation must succeed");

        tokio::fs::write(
            target.join(APPLICATION_CRD_FILE_NAME),
            b"apiVersion: v1\nkind: ConfigMap\n",
        )
        .await
        .expect("tamper write must succeed");

        let error = generate(&args(&target, true))
            .await
            .expect_err("--check must fail for a tampered manifest");
        assert!(
            error.to_string().contains("out of date"),
            "unexpected error: {error}"
        );
    }
}

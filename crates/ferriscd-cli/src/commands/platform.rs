//! `ferriscd project list` and `ferriscd cluster list` (`T14.5`).
//!
//! Both are read-only views of what the server already filters per caller (`T14.4`): a project the
//! token has no grant on is absent, and a cluster is just a name — so neither command needs any
//! authorization logic of its own.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::client::Client;
use crate::commands::app::{ConnectionArgs, EXIT_OK};
use crate::output::{OutputFormat, Table, emit, render_json, render_yaml};

/// `ferriscd project <subcommand>`.
#[derive(Debug, Args)]
pub struct ProjectArgs {
    /// Connection overrides (`--server-url`, `--token`).
    #[command(flatten)]
    pub connection: ConnectionArgs,

    /// The action.
    #[command(subcommand)]
    pub command: ProjectCommand,
}

/// The `ferriscd project` actions.
#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// List the `AppProject`s you may see.
    List(ListArgs),
}

/// `ferriscd project list`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Output format.
    #[arg(long = "output", short = 'o', value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

/// `ferriscd cluster <subcommand>`.
#[derive(Debug, Args)]
pub struct ClusterArgs {
    /// Connection overrides (`--server-url`, `--token`).
    #[command(flatten)]
    pub connection: ConnectionArgs,

    /// The action.
    #[command(subcommand)]
    pub command: ClusterCommand,
}

/// The `ferriscd cluster` actions.
#[derive(Debug, Subcommand)]
pub enum ClusterCommand {
    /// List the clusters the control plane can address.
    List(ListArgs),
}

/// Executes `ferriscd project …`.
///
/// # Errors
///
/// Any client or serialization failure.
pub async fn run_project(args: ProjectArgs) -> Result<u8> {
    let client = Client::connect(
        args.connection.server_url.as_deref(),
        args.connection.token.as_deref(),
    )?;
    match args.command {
        ProjectCommand::List(list) => list_projects(&client, list).await,
    }
}

/// Executes `ferriscd cluster …`.
///
/// # Errors
///
/// Any client or serialization failure.
pub async fn run_cluster(args: ClusterArgs) -> Result<u8> {
    let client = Client::connect(
        args.connection.server_url.as_deref(),
        args.connection.token.as_deref(),
    )?;
    match args.command {
        ClusterCommand::List(list) => list_clusters(&client, list).await,
    }
}

async fn list_projects(client: &Client, args: ListArgs) -> Result<u8> {
    let projects = client.list_projects().await?;
    match args.output {
        OutputFormat::Json => emit(&render_json(&projects)?),
        OutputFormat::Yaml => emit(&render_yaml(&projects)?),
        OutputFormat::Table => {
            let mut table = Table::new(["NAME", "DESCRIPTION", "DESTINATIONS", "SOURCE REPOS"]);
            for project in &projects.items {
                table.push([
                    project.name.clone(),
                    project
                        .description
                        .clone()
                        .unwrap_or_else(|| "<none>".to_owned()),
                    if project.destinations.is_empty() {
                        "<none>".to_owned()
                    } else {
                        project.destinations.join(", ")
                    },
                    if project.source_repos.is_empty() {
                        "<none>".to_owned()
                    } else {
                        project.source_repos.join(", ")
                    },
                ]);
            }
            if table.is_empty() {
                table.push(["<no projects>", "", "", ""]);
            }
            emit(&table.render());
        }
    }
    Ok(EXIT_OK)
}

async fn list_clusters(client: &Client, args: ListArgs) -> Result<u8> {
    let clusters = client.list_clusters().await?;
    match args.output {
        OutputFormat::Json => emit(&render_json(&clusters)?),
        OutputFormat::Yaml => emit(&render_yaml(&clusters)?),
        OutputFormat::Table => {
            let mut table = Table::new(["NAME", "IN CLUSTER"]);
            for cluster in &clusters.items {
                table.push([
                    cluster.name.clone(),
                    if cluster.in_cluster { "yes" } else { "no" }.to_owned(),
                ]);
            }
            if table.is_empty() {
                table.push(["<no clusters>", ""]);
            }
            emit(&table.render());
        }
    }
    Ok(EXIT_OK)
}

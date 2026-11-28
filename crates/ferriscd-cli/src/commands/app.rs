//! `ferriscd app …` — list, inspect, diff, sync, roll back (`T14.5`).
//!
//! Every command is a thin call into [`crate::client`] plus a renderer. Two properties matter and are
//! tested:
//!
//! * **Exit codes are scriptable.** `0` is success (a diff that found nothing, a sync that was
//!   accepted), `1` is an error (a refusal, a transport failure, a missing application), `2` is "the
//!   application is out of sync" — the `git diff --exit-code` convention a CI job branches on.
//! * **Nothing re-derives a secret.** `app diff` renders the `DiffView` the server sent, whose values
//!   the engine already replaced with `***REDACTED(...)***`. The CLI has no code path that reads a
//!   `Secret`, decodes base64, or fetches an object: the payload *is* the redaction.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};
use ferriscd_server::api::{
    ApplicationDetailView, ApplicationSummary, DiffResourceView, DiffSummaryView, DiffView,
    HistoryView, OperationView, SyncView,
};

use crate::client::{Client, DEFAULT_NAMESPACE};
use crate::output::{
    ColorChoice, OutputFormat, Table, emit, paint, render_json, render_yaml, style,
};

/// Exit code for success.
pub const EXIT_OK: u8 = 0;
/// Exit code for an error.
pub const EXIT_ERROR: u8 = 1;
/// Exit code for "there is drift" (`app diff`), so CI can gate on it.
pub const EXIT_OUT_OF_SYNC: u8 = 2;

/// Where the connection comes from for read/mutation commands.
#[derive(Debug, Args, Clone)]
pub struct ConnectionArgs {
    /// Override the stored server URL.
    #[arg(long = "server-url", value_name = "URL", global = true)]
    pub server_url: Option<String>,

    /// Override the stored bearer token (prefer `$FERRISCD_TOKEN`).
    #[arg(
        long = "token",
        value_name = "TOKEN",
        env = "FERRISCD_TOKEN",
        hide_env_values = true,
        global = true
    )]
    pub token: Option<String>,
}

impl ConnectionArgs {
    /// Builds the client from the flags, the environment, or the stored configuration.
    ///
    /// Async since `T19.2`: the stored credential is read on the blocking pool instead of on an
    /// executor thread (the `docs/REVIEW_LOG.md` §`v1.0` follow-up).
    async fn client(&self) -> Result<Client> {
        Client::connect_async(self.server_url.as_deref(), self.token.as_deref())
            .await
            .context("cannot connect to ferriscd-server")
    }
}

/// `ferriscd app <subcommand>`.
#[derive(Debug, Args)]
pub struct AppArgs {
    /// Connection overrides (`--server-url`, `--token`).
    #[command(flatten)]
    pub connection: ConnectionArgs,

    /// The action.
    #[command(subcommand)]
    pub command: AppCommand,
}

/// The `ferriscd app` actions.
#[derive(Debug, Subcommand)]
pub enum AppCommand {
    /// List the applications you may see.
    List(ListArgs),
    /// Show one application's status, conditions, and history.
    Get(GetArgs),
    /// Show the live, Secret-redacted diff (exit 2 when there is drift).
    Diff(DiffArgs),
    /// Request a sync (the controller performs it).
    Sync(SyncArgs),
    /// Request a rollback to a history entry.
    Rollback(RollbackArgs),
    /// Show one application's deployment history.
    History(HistoryArgs),
}

/// `ferriscd app list`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Output format.
    #[arg(long = "output", short = 'o', value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,

    /// Colour (only used by `--output table`).
    #[arg(long = "color", value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,
}

/// One application addressed by `[namespace/]name`.
#[derive(Debug, Args, Clone)]
pub struct TargetArgs {
    /// Application name, optionally prefixed with its namespace (`ferriscd-system/payments-api`).
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Namespace of the `Application` (defaults to `ferriscd-system`, or the `ns/` prefix).
    #[arg(long = "namespace", short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,
}

impl TargetArgs {
    /// Splits `[namespace/]name` into `(namespace, name)`.
    ///
    /// The `-n/--namespace` flag wins over the prefix, so a script can keep one `ns/` name and
    /// override the namespace when moving between clusters.
    #[must_use]
    pub fn resolve(&self) -> (String, String) {
        match self.name.split_once('/') {
            Some((namespace, name)) if !namespace.is_empty() && !name.is_empty() => (
                self.namespace
                    .clone()
                    .unwrap_or_else(|| namespace.to_owned()),
                name.to_owned(),
            ),
            _ => (
                self.namespace
                    .clone()
                    .unwrap_or_else(|| DEFAULT_NAMESPACE.to_owned()),
                self.name.clone(),
            ),
        }
    }
}

/// `ferriscd app get`.
#[derive(Debug, Args)]
pub struct GetArgs {
    /// The application.
    #[command(flatten)]
    pub target: TargetArgs,

    /// Output format.
    #[arg(long = "output", short = 'o', value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

/// `ferriscd app diff`.
#[derive(Debug, Args)]
pub struct DiffArgs {
    /// The application.
    #[command(flatten)]
    pub target: TargetArgs,

    /// Output format (`table` is the colourised human view).
    #[arg(long = "output", short = 'o', value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,

    /// Colour (only used by `--output table`).
    #[arg(long = "color", value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,
}

/// `ferriscd app sync`.
#[derive(Debug, Args)]
pub struct SyncArgs {
    /// The application.
    #[command(flatten)]
    pub target: TargetArgs,

    /// Ask the server to prune. `v1.0` servers refuse this (`422`): pruning is a spec field
    /// (`spec.syncPolicy.automated.prune`), and the CLI forwards the request rather than pretending.
    #[arg(long = "prune")]
    pub prune: bool,

    /// Wait for the controller to settle the sync, then report the outcome.
    #[arg(long = "watch")]
    pub watch: bool,

    /// How long `--watch` waits before giving up, in seconds.
    #[arg(long = "timeout", value_name = "SECONDS", default_value_t = 300)]
    pub timeout: u64,
}

/// `ferriscd app rollback`.
#[derive(Debug, Args)]
pub struct RollbackArgs {
    /// The application.
    #[command(flatten)]
    pub target: TargetArgs,

    /// `status.history[].id` to redeploy (`ferriscd app history` lists them).
    #[arg(value_name = "HISTORY_ID")]
    pub history_id: i64,
}

/// `ferriscd app history`.
#[derive(Debug, Args)]
pub struct HistoryArgs {
    /// The application.
    #[command(flatten)]
    pub target: TargetArgs,

    /// Output format.
    #[arg(long = "output", short = 'o', value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,
}

/// Executes `ferriscd app …`, returning the process exit code.
///
/// # Errors
///
/// Any client or serialization failure; the caller maps it onto exit code `1`.
pub async fn run(args: AppArgs) -> Result<u8> {
    let client = args.connection.client().await?;
    match args.command {
        AppCommand::List(list) => list_applications(&client, list).await,
        AppCommand::Get(get) => get_application(&client, get).await,
        AppCommand::Diff(diff) => diff_application(&client, diff).await,
        AppCommand::Sync(sync) => sync_application(&client, sync).await,
        AppCommand::Rollback(rollback) => rollback_application(&client, rollback).await,
        AppCommand::History(history) => history_application(&client, history).await,
    }
}

async fn list_applications(client: &Client, args: ListArgs) -> Result<u8> {
    let list = client.list_applications().await?;
    match args.output {
        OutputFormat::Json => emit(&render_json(&list)?),
        OutputFormat::Yaml => emit(&render_yaml(&list)?),
        OutputFormat::Table => emit(&applications_table(&list.items, args.color).render()),
    }
    Ok(EXIT_OK)
}

async fn get_application(client: &Client, args: GetArgs) -> Result<u8> {
    let (namespace, name) = args.target.resolve();
    let detail = client.get_application(&namespace, &name).await?;
    match args.output {
        OutputFormat::Json => emit(&render_json(&detail)?),
        OutputFormat::Yaml => emit(&render_yaml(&detail)?),
        OutputFormat::Table => emit(&detail_table(&detail)),
    }
    Ok(EXIT_OK)
}

async fn diff_application(client: &Client, args: DiffArgs) -> Result<u8> {
    let (namespace, name) = args.target.resolve();
    let diff = client.diff(&namespace, &name).await?;
    match args.output {
        OutputFormat::Json => emit(&render_json(&diff)?),
        OutputFormat::Yaml => emit(&render_yaml(&diff)?),
        OutputFormat::Table => emit(&render_diff(
            &namespace,
            &name,
            &diff,
            args.color.for_stdout(),
        )),
    }
    Ok(diff_exit_code(&diff))
}

async fn sync_application(client: &Client, args: SyncArgs) -> Result<u8> {
    let (namespace, name) = args.target.resolve();
    let operation = client.sync(&namespace, &name, args.prune).await?;
    println!(
        "{} sync requested for {namespace}/{name} ({}); the controller performs it",
        operation.status, operation.request
    );
    if !args.watch {
        return Ok(EXIT_OK);
    }
    watch(
        client,
        &namespace,
        &name,
        Duration::from_secs(args.timeout),
        Duration::from_secs(1),
    )
    .await
}

async fn rollback_application(client: &Client, args: RollbackArgs) -> Result<u8> {
    let (namespace, name) = args.target.resolve();
    let operation = client.rollback(&namespace, &name, args.history_id).await?;
    println!(
        "{} rollback requested for {namespace}/{name} to history id {} ({})",
        operation.status, args.history_id, operation.request
    );
    Ok(EXIT_OK)
}

async fn history_application(client: &Client, args: HistoryArgs) -> Result<u8> {
    let (namespace, name) = args.target.resolve();
    let detail = client.get_application(&namespace, &name).await?;
    match args.output {
        OutputFormat::Json => emit(&render_json(&detail.history)?),
        OutputFormat::Yaml => emit(&render_yaml(&detail.history)?),
        OutputFormat::Table => emit(&history_table(&detail.history).render()),
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// Watching (no fixed sleep on the first poll)
// ---------------------------------------------------------------------------

/// How a `--watch` pass sees the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settle {
    /// Still working (a running operation, or no settled sync yet).
    Running,
    /// The sync succeeded.
    Succeeded,
    /// The operation failed; the message is the server's (bounded, secret-free).
    Failed(String),
}

/// Classifies one poll of an `Application` (`T14.5` `--watch`).
///
/// Pure so the state machine is testable without a clock: an operation in a terminal phase decides
/// the outcome, and a completed operation with a `Synced` status is also success (the controller
/// consumes `ferriscd.io/operation` once a pass settles).
#[must_use]
pub fn settle(detail: &ApplicationDetailView) -> Settle {
    if let Some(operation) = detail.operation.as_ref() {
        return match operation.phase.as_str() {
            "Succeeded" => Settle::Succeeded,
            "Failed" | "Error" => Settle::Failed(operation_message(operation)),
            _ => Settle::Running,
        };
    }
    match detail
        .application
        .sync
        .as_ref()
        .map(|sync| sync.status.as_str())
    {
        Some("Synced") => Settle::Succeeded,
        _ => Settle::Running,
    }
}

/// The bounded message of an operation (`None` operation state never invents one).
fn operation_message(operation: &OperationView) -> String {
    operation
        .message
        .clone()
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| format!("the sync ended in phase {}", operation.phase))
}

/// Polls until the sync settles or the deadline passes.
///
/// The **first** poll happens before any sleep, so a fast controller is reported immediately and a
/// test (or a CI run) never pays a fixed delay. `interval` is the poll period otherwise.
async fn watch(
    client: &Client,
    namespace: &str,
    name: &str,
    timeout: Duration,
    interval: Duration,
) -> Result<u8> {
    let deadline = Instant::now() + timeout;
    loop {
        let detail = client.get_application(namespace, name).await?;
        match settle(&detail) {
            Settle::Succeeded => {
                let revision = detail
                    .application
                    .sync
                    .as_ref()
                    .and_then(|sync| sync.last_synced_revision.clone())
                    .unwrap_or_else(|| "<unknown>".to_owned());
                println!("{namespace}/{name} is synced at revision {revision}");
                return Ok(EXIT_OK);
            }
            Settle::Failed(message) => {
                eprintln!("{namespace}/{name} did not sync: {message}");
                return Ok(EXIT_ERROR);
            }
            Settle::Running => {}
        }
        if Instant::now() >= deadline {
            eprintln!(
                "{namespace}/{name} did not settle within {}s; it is still being reconciled",
                timeout.as_secs()
            );
            return Ok(EXIT_ERROR);
        }
        tokio::time::sleep(interval).await;
    }
}

/// The `--watch` loop, exposed so an in-crate test can drive it with an explicit interval.
#[cfg(test)]
pub(crate) async fn watch_for_tests(
    client: &Client,
    namespace: &str,
    name: &str,
    timeout: Duration,
    interval: Duration,
) -> Result<u8> {
    watch(client, namespace, name, timeout, interval).await
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

/// The `app list` table.
#[must_use]
pub fn applications_table(items: &[ApplicationSummary], color: ColorChoice) -> Table {
    let enabled = color.for_stdout();
    let mut table = Table::new(["NAME", "PROJECT", "SYNC", "HEALTH", "CLUSTER/NAMESPACE"]);
    for item in items {
        table.push([
            format!("{}/{}", item.namespace, item.name),
            item.project.clone(),
            sync_cell(item.sync.as_ref(), enabled),
            health_cell(
                item.health.as_ref().map(|health| health.status.as_str()),
                enabled,
            ),
            format!(
                "{}/{}",
                item.destination.cluster, item.destination.namespace
            ),
        ]);
    }
    if table.is_empty() {
        // An empty list is a fact, printed once instead of an empty table nobody can read.
        table.push(["<no applications>", "", "", "", ""]);
    }
    table
}

/// The `app get` view: a key/value block, then conditions and history.
#[must_use]
pub fn detail_table(detail: &ApplicationDetailView) -> String {
    let app = &detail.application;
    let mut rendered = String::new();
    rendered.push_str(&format!("Application   {}/{}\n", app.namespace, app.name));
    rendered.push_str(&format!("Project       {}\n", app.project));
    rendered.push_str(&format!(
        "Source        {} ({}, {})\n",
        app.source.repo_url, app.source.path, app.source.target_revision
    ));
    rendered.push_str(&format!(
        "Destination   {}/{}\n",
        app.destination.cluster, app.destination.namespace
    ));
    rendered.push_str(&format!(
        "Sync          {}\n",
        app.sync
            .as_ref()
            .map_or_else(|| "Unknown".to_owned(), |sync| sync.status.clone())
    ));
    rendered.push_str(&format!(
        "Health        {}\n",
        app.health
            .as_ref()
            .map_or_else(|| "Unknown".to_owned(), |health| health.status.clone())
    ));
    if let Some(revision) = app
        .sync
        .as_ref()
        .and_then(|sync| sync.last_synced_revision.clone())
    {
        rendered.push_str(&format!("Revision      {revision}\n"));
    }
    rendered.push_str(&format!("Resources     {}\n", app.resource_count));
    if let Some(operation) = detail.operation.as_ref() {
        rendered.push_str(&format!(
            "Operation     {} (wave {})\n",
            operation.phase, operation.current_wave
        ));
        if let Some(message) = operation.message.as_deref() {
            rendered.push_str(&format!("              {message}\n"));
        }
    }
    if !app.conditions.is_empty() {
        rendered.push('\n');
        let mut conditions = Table::new(["CONDITION", "STATUS", "REASON", "MESSAGE"]);
        for condition in &app.conditions {
            conditions.push([
                condition.type_.clone(),
                condition.status.clone(),
                condition.reason.clone(),
                condition.message.clone(),
            ]);
        }
        rendered.push_str(&conditions.render());
    }
    if !detail.history.is_empty() {
        rendered.push('\n');
        rendered.push_str(&history_table(&detail.history).render());
    }
    rendered
}

/// The `app history` table.
#[must_use]
pub fn history_table(history: &[HistoryView]) -> Table {
    let mut table = Table::new(["ID", "REVISION", "DEPLOYED AT"]);
    for entry in history {
        table.push([
            entry.id.to_string(),
            entry
                .revision
                .clone()
                .unwrap_or_else(|| "<none>".to_owned()),
            entry.deployed_at.clone(),
        ]);
    }
    if table.is_empty() {
        table.push(["<no history>", "", ""]);
    }
    table
}

/// The colourised, redacted `app diff` view.
///
/// Every value printed comes from the server's `DiffView`, i.e. straight out of the engine's redacting
/// diff: the renderer never has a raw value to print, even if it wanted one.
#[must_use]
pub fn render_diff(namespace: &str, name: &str, diff: &DiffView, color: bool) -> String {
    let mut rendered = String::new();
    rendered.push_str(&format!(
        "Application   {namespace}/{name}\nRev           {}\nWould sync    {}\n",
        diff.revision, diff.would_sync
    ));
    rendered.push_str(&format!(
        "Summary       {} resource(s): {} synced, {} out of sync, {} missing, {} orphaned, {} ownership conflict(s), {} field conflict(s)\n",
        diff.summary.total,
        diff.summary.synced,
        diff.summary.out_of_sync,
        diff.summary.missing,
        diff.summary.orphaned,
        diff.summary.ownership_conflicts,
        diff.summary.field_conflicts,
    ));
    if diff.resources.is_empty() {
        rendered.push_str("\nNothing is tracked yet: this application has never been applied.\n");
        rendered.push('\n');
        rendered.push_str(&verdict(&diff.summary, color));
        return rendered;
    }
    rendered.push('\n');
    let mut table = Table::new(["RESOURCE", "STATUS", "CHANGES"]);
    for resource in &diff.resources {
        table.push([
            resource.key.clone(),
            status_cell(resource, color),
            format!(
                "{}{}",
                resource.changes.len(),
                if resource.truncated { "+" } else { "" }
            ),
        ]);
    }
    rendered.push_str(&table.render());
    for resource in &diff.resources {
        if resource.changes.is_empty() && resource.conflicts.is_empty() {
            continue;
        }
        rendered.push('\n');
        rendered.push_str(&format!(
            "{} {}\n",
            paint(color, style::DIM, resource.key.as_str()),
            resource.status.as_str()
        ));
        if let Some(owner) = resource.owner.as_deref() {
            rendered.push_str(&format!(
                "  {} owned by {owner}\n",
                paint(color, style::YELLOW, "owner")
            ));
        }
        for change in &resource.changes {
            let marker = match change.kind.as_str() {
                "added" => paint(color, style::GREEN, "+"),
                "removed" => paint(color, style::RED, "-"),
                _ => paint(color, style::YELLOW, "~"),
            };
            rendered.push_str(&format!("  {marker} {}\n", change.path));
            if let Some(live) = change.live.as_ref() {
                rendered.push_str(&format!("      live:      {}\n", json_scalar(live)));
            }
            if let Some(predicted) = change.predicted.as_ref() {
                rendered.push_str(&format!("      predicted: {}\n", json_scalar(predicted)));
            }
        }
        for conflict in &resource.conflicts {
            rendered.push_str(&format!(
                "  {} {} managed by {}\n",
                paint(color, style::YELLOW, "conflict"),
                conflict.field.as_deref().unwrap_or("<unknown field>"),
                conflict.manager.as_deref().unwrap_or("<unknown manager>"),
            ));
        }
        if resource.truncated {
            rendered.push_str("  (the change list was truncated by the server)\n");
        }
    }
    let summary = &diff.summary;
    rendered.push('\n');
    rendered.push_str(&verdict(summary, color));
    rendered
}

/// The one-line verdict, coloured by drift.
fn verdict(summary: &DiffSummaryView, color: bool) -> String {
    let drift = summary.out_of_sync
        + summary.missing
        + summary.orphaned
        + summary.ownership_conflicts
        + summary.field_conflicts;
    if drift == 0 {
        format!("{}\n", paint(color, style::GREEN, "in sync"))
    } else {
        format!(
            "{}\n",
            paint(
                color,
                style::RED,
                &format!("{drift} resource(s) out of sync"),
            )
        )
    }
}

/// The `app diff` exit code: `2` when there is drift, `0` when there is none.
#[must_use]
pub fn diff_exit_code(diff: &DiffView) -> u8 {
    let summary = &diff.summary;
    let drift = summary.out_of_sync
        + summary.missing
        + summary.orphaned
        + summary.ownership_conflicts
        + summary.field_conflicts;
    if drift > 0 || diff.would_sync {
        EXIT_OUT_OF_SYNC
    } else {
        EXIT_OK
    }
}

fn sync_cell(sync: Option<&SyncView>, color: bool) -> String {
    match sync.map(|sync| sync.status.as_str()) {
        Some("Synced") => paint(color, style::GREEN, "Synced"),
        Some("OutOfSync") => paint(color, style::RED, "OutOfSync"),
        Some(other) => other.to_owned(),
        None => "Unknown".to_owned(),
    }
}

fn health_cell(health: Option<&str>, color: bool) -> String {
    match health {
        Some("Healthy") => paint(color, style::GREEN, "Healthy"),
        Some("Degraded") | Some("Missing") => paint(color, style::RED, health.unwrap_or_default()),
        Some("Progressing") => paint(color, style::YELLOW, "Progressing"),
        Some(other) => other.to_owned(),
        None => "Unknown".to_owned(),
    }
}

fn status_cell(resource: &DiffResourceView, color: bool) -> String {
    match resource.status.as_str() {
        "synced" => paint(color, style::GREEN, "synced"),
        "orphaned" => paint(color, style::YELLOW, "orphaned"),
        other => paint(color, style::RED, other),
    }
}

/// Renders a JSON value as one line (strings unquoted, everything else compact JSON).
fn json_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferriscd_server::api::{
        ApplicationDetailView, ApplicationSummary, DestinationView, DiffChangeView,
        DiffConflictView, DiffSummaryView, HealthView, SourceView, SyncView,
    };

    fn summary() -> ApplicationSummary {
        ApplicationSummary {
            namespace: "ferriscd-system".to_owned(),
            name: "payments-api".to_owned(),
            project: "payments".to_owned(),
            source: SourceView {
                repo_url: "https://github.com/example/payments.git".to_owned(),
                path: "deploy".to_owned(),
                target_revision: "main".to_owned(),
                renderer: "plainYaml".to_owned(),
            },
            destination: DestinationView {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync: Some(SyncView {
                status: "Synced".to_owned(),
                revision: Some("8f3a1c2".to_owned()),
                last_synced_revision: Some("8f3a1c2".to_owned()),
                last_synced_at: None,
            }),
            health: Some(HealthView {
                status: "Healthy".to_owned(),
                message: None,
            }),
            conditions: Vec::new(),
            resource_count: 2,
            observed_generation: Some(3),
        }
    }

    fn empty_summary() -> DiffSummaryView {
        DiffSummaryView {
            total: 0,
            synced: 0,
            out_of_sync: 0,
            missing: 0,
            orphaned: 0,
            ownership_conflicts: 0,
            field_conflicts: 0,
        }
    }

    #[test]
    fn a_diff_with_drift_exits_two_and_a_clean_one_zero() {
        let clean = DiffView {
            revision: "8f3a1c2".to_owned(),
            desired: 1,
            would_sync: false,
            summary: DiffSummaryView {
                total: 1,
                synced: 1,
                ..empty_summary()
            },
            resources: Vec::new(),
        };
        assert_eq!(diff_exit_code(&clean), EXIT_OK);

        for drifting in [
            DiffSummaryView {
                out_of_sync: 1,
                ..empty_summary()
            },
            DiffSummaryView {
                missing: 1,
                ..empty_summary()
            },
            DiffSummaryView {
                orphaned: 1,
                ..empty_summary()
            },
            DiffSummaryView {
                ownership_conflicts: 1,
                ..empty_summary()
            },
            DiffSummaryView {
                field_conflicts: 1,
                ..empty_summary()
            },
        ] {
            let diff = DiffView {
                revision: "8f3a1c2".to_owned(),
                desired: 1,
                would_sync: true,
                summary: drifting,
                resources: Vec::new(),
            };
            assert_eq!(
                diff_exit_code(&diff),
                EXIT_OUT_OF_SYNC,
                "CI must see drift as exit 2: {diff:?}"
            );
        }
    }

    /// The colourised diff prints the server's redacted values verbatim — and nothing that looks like
    /// a Secret's contents can appear, because the payload never contains one.
    #[test]
    fn a_diff_renders_the_servers_redacted_values_and_never_a_secret() {
        let diff = DiffView {
            revision: "8f3a1c2".to_owned(),
            desired: 1,
            would_sync: true,
            summary: DiffSummaryView {
                total: 1,
                out_of_sync: 1,
                ..empty_summary()
            },
            resources: vec![DiffResourceView {
                key: "/Secret/payments/db".to_owned(),
                status: "outOfSync".to_owned(),
                owner: None,
                changes: vec![DiffChangeView {
                    path: "/data/password".to_owned(),
                    kind: "modified".to_owned(),
                    live: Some(serde_json::Value::String(
                        "***REDACTED(sha256:0123456789ab)***".to_owned(),
                    )),
                    predicted: Some(serde_json::Value::String(
                        "***REDACTED(sha256:ba9876543210)***".to_owned(),
                    )),
                }],
                conflicts: vec![DiffConflictView {
                    field: Some("spec.replicas".to_owned()),
                    manager: Some("kubectl".to_owned()),
                }],
                truncated: false,
            }],
        };
        let plain = render_diff("ferriscd-system", "payments-api", &diff, false);
        assert!(plain.contains("/Secret/payments/db"), "{plain}");
        assert!(
            plain.contains("***REDACTED(sha256:0123456789ab)***"),
            "{plain}"
        );
        assert!(
            plain.contains("***REDACTED(sha256:ba9876543210)***"),
            "{plain}"
        );
        assert!(plain.contains("out of sync"), "{plain}");
        assert!(plain.contains("managed by kubectl"), "{plain}");
        assert!(
            !plain.contains('\u{1b}'),
            "no colour when disabled: {plain:?}"
        );

        // Colour is presentation-only: the same text, wrapped in escapes.
        let colored = render_diff("ferriscd-system", "payments-api", &diff, true);
        assert!(colored.contains('\u{1b}'), "{colored:?}");
        assert!(colored.contains("***REDACTED(sha256:0123456789ab)***"));
    }

    #[test]
    fn an_empty_diff_says_so_instead_of_printing_an_empty_table() {
        let diff = DiffView {
            revision: "8f3a1c2".to_owned(),
            desired: 0,
            would_sync: false,
            summary: empty_summary(),
            resources: Vec::new(),
        };
        let rendered = render_diff("ferriscd-system", "payments-api", &diff, false);
        assert!(rendered.contains("never been applied"), "{rendered}");
        assert!(rendered.contains("in sync"), "{rendered}");
    }

    #[test]
    fn the_list_table_names_the_application_and_colours_its_status() {
        let plain = applications_table(&[summary()], ColorChoice::Never).render();
        assert!(plain.contains("ferriscd-system/payments-api"), "{plain}");
        assert!(plain.contains("payments"), "{plain}");
        assert!(plain.contains("Synced"), "{plain}");
        assert!(plain.contains("in-cluster/payments"), "{plain}");
        assert!(!plain.contains('\u{1b}'), "{plain:?}");

        let colored = applications_table(&[summary()], ColorChoice::Always).render();
        assert!(colored.contains('\u{1b}'), "{colored:?}");

        let empty = applications_table(&[], ColorChoice::Never).render();
        assert!(empty.contains("<no applications>"), "{empty}");
    }

    #[test]
    fn the_detail_and_history_views_carry_the_server_values() {
        let detail = ApplicationDetailView {
            application: summary(),
            history: vec![HistoryView {
                id: 7,
                revision: Some("8f3a1c2".to_owned()),
                deployed_at: "2027-01-15T10:30:00Z".to_owned(),
            }],
            operation: None,
        };
        let rendered = detail_table(&detail);
        assert!(
            rendered.contains("Application   ferriscd-system/payments-api"),
            "{rendered}"
        );
        assert!(rendered.contains("Project       payments"), "{rendered}");
        assert!(rendered.contains("Revision      8f3a1c2"), "{rendered}");
        assert!(rendered.contains("2027-01-15T10:30:00Z"), "{rendered}");

        let history = history_table(&detail.history).render();
        assert!(history.contains("ID"), "{history}");
        assert!(history.contains('7'), "{history}");
        assert!(history_table(&[]).render().contains("<no history>"));
    }

    /// `--watch`'s state machine: a running operation keeps polling, a terminal one decides.
    #[test]
    fn watching_settles_on_the_operations_terminal_phase() {
        let mut detail = ApplicationDetailView {
            application: summary(),
            history: Vec::new(),
            operation: Some(OperationView {
                phase: "Running".to_owned(),
                current_wave: 1,
                revision: Some("8f3a1c2".to_owned()),
                started_at: "2027-01-15T10:30:00Z".to_owned(),
                finished_at: None,
                message: None,
            }),
        };
        assert_eq!(settle(&detail), Settle::Running);

        if let Some(operation) = detail.operation.as_mut() {
            operation.phase = "Succeeded".to_owned();
        }
        assert_eq!(settle(&detail), Settle::Succeeded);

        if let Some(operation) = detail.operation.as_mut() {
            operation.phase = "Failed".to_owned();
            operation.message = Some("apply failed on wave 0".to_owned());
        }
        assert_eq!(
            settle(&detail),
            Settle::Failed("apply failed on wave 0".to_owned())
        );

        // No recorded operation: the sync status decides (a consumed `ferriscd.io/operation`).
        detail.operation = None;
        assert_eq!(settle(&detail), Settle::Succeeded);
        detail.application.sync = Some(SyncView {
            status: "OutOfSync".to_owned(),
            revision: None,
            last_synced_revision: None,
            last_synced_at: None,
        });
        assert_eq!(settle(&detail), Settle::Running);
        detail.application.sync = None;
        assert_eq!(settle(&detail), Settle::Running);
    }

    #[test]
    fn a_target_accepts_a_namespace_prefix_and_the_flag_wins() {
        let bare = TargetArgs {
            name: "payments-api".to_owned(),
            namespace: None,
        };
        assert_eq!(
            bare.resolve(),
            ("ferriscd-system".to_owned(), "payments-api".to_owned())
        );

        let prefixed = TargetArgs {
            name: "ferriscd-system/payments-api".to_owned(),
            namespace: None,
        };
        assert_eq!(
            prefixed.resolve(),
            ("ferriscd-system".to_owned(), "payments-api".to_owned())
        );

        let overridden = TargetArgs {
            name: "other-ns/payments-api".to_owned(),
            namespace: Some("ferriscd-system".to_owned()),
        };
        assert_eq!(
            overridden.resolve(),
            ("ferriscd-system".to_owned(), "payments-api".to_owned())
        );

        // A trailing or leading slash is not a namespace separator.
        for odd in ["/payments-api", "payments-api/"] {
            let target = TargetArgs {
                name: odd.to_owned(),
                namespace: None,
            };
            assert_eq!(target.resolve().0, "ferriscd-system", "{odd}");
        }
    }
}

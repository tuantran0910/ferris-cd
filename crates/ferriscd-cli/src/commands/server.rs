//! `ferriscd server` — run the controller **and** the in-process REST API in one process (`T14.1`).
//!
//! This is the modular monolith of ADR-002 in one command: one `kube::Client`, one `RepoCache`, one
//! renderer cache, one `ClusterManager`, one `DiscoveryCache` and one `SyncPipeline`, shared by the
//! reconcile loops and by `GET .../diff` / `GET .../resources`. There is no second process and no
//! state to keep in sync (finding C9).
//!
//! Shutdown is **unified**: this command owns the single `SIGINT`/`SIGTERM` listener, cancels one
//! [`CancellationToken`](tokio_util::sync::CancellationToken), and the controller (including a held
//! leader `Lease`) and the API server both drain from that one decision.
//!
//! `ferriscd server openapi` exports the OpenAPI 3.1 contract instead of serving, which is what keeps
//! `docs/api/openapi.json` (and the TypeScript client generated from it, `T16.1`) honest.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};
use ferriscd_server::{AuthPolicy, WebhookSecret};

use crate::commands::controller::{ControllerArgs, run_options};

/// Arguments for `ferriscd server`.
///
/// `Debug` is written by hand: two of the fields are webhook credentials, and a derived `Debug`
/// would print them the first time anybody logged the parsed arguments (finding `P14-M2`).
#[derive(Args)]
pub struct ServerArgs {
    /// Controller flags (`--namespace`, `--allow-local-repos`, `--leader-election`, ...).
    ///
    /// `ferriscd server` runs the controller, so it accepts exactly the same flags.
    #[command(flatten)]
    pub controller: ControllerArgs,

    /// Address the REST API listens on (health/readiness probes included).
    ///
    /// Defaults to loopback: publishing an API is a deliberate act, not a default. The protected
    /// routes authenticate with `TokenReview` (`--auth-policy token-review`), so binding `0.0.0.0`
    /// is defensible in a cluster — do it explicitly, and put a TLS-terminating `Service`/Ingress in
    /// front of it.
    #[arg(
        long = "api-addr",
        value_name = "ADDR",
        default_value = ferriscd_server::DEFAULT_API_ADDR
    )]
    pub api_addr: String,

    /// How the bearer-protected `/api/v1/*` routes are authenticated.
    ///
    /// `token-review` (the default) validates `Authorization: Bearer <token>` with a Kubernetes
    /// `TokenReview`, caching a successful review for 30 s. `pass-through` is an explicit
    /// **development** escape hatch: every protected request is allowed and annotated anonymous, so
    /// it must stay on a loopback address. `deny-all` is a lockdown that refuses every protected
    /// request with `401` without calling the API server. Falls back to `FERRISCD_AUTH_POLICY`.
    ///
    /// A `token-review` server also needs the `ferriscd-rbac-cm` ConfigMap (project-scoped
    /// authorization, `T14.4`); without it every authenticated request is refused (default-deny).
    #[arg(
        long = "auth-policy",
        value_name = "POLICY",
        env = "FERRISCD_AUTH_POLICY",
        default_value = "token-review"
    )]
    pub auth_policy: AuthPolicy,

    /// GitHub webhook secret (HMAC-SHA256 key for `X-Hub-Signature-256`).
    ///
    /// Without it `POST /api/v1/webhooks/github` answers `422`: an unverified webhook is never
    /// accepted. Falls back to `FERRISCD_GITHUB_WEBHOOK_SECRET`, which is the recommended way (a
    /// flag is visible in `ps`).
    #[arg(
        long = "github-webhook-secret",
        value_name = "SECRET",
        env = "FERRISCD_GITHUB_WEBHOOK_SECRET",
        hide_env_values = true
    )]
    pub github_webhook_secret: Option<String>,

    /// GitLab webhook token (shared secret for `X-Gitlab-Token`).
    ///
    /// Falls back to `FERRISCD_GITLAB_WEBHOOK_TOKEN`. GitLab signs nothing, so this token is the
    /// whole authentication for `/api/v1/webhooks/gitlab`.
    #[arg(
        long = "gitlab-webhook-token",
        value_name = "TOKEN",
        env = "FERRISCD_GITLAB_WEBHOOK_TOKEN",
        hide_env_values = true
    )]
    pub gitlab_webhook_token: Option<String>,

    /// Per-repository webhook debounce window, in seconds.
    ///
    /// A monorepo push that matches 50 `Application`s is coalesced into one fan-out after this
    /// window instead of fifty simultaneous reconciles.
    #[arg(
        long = "webhook-debounce-seconds",
        value_name = "SECONDS",
        default_value_t = 2
    )]
    pub webhook_debounce_seconds: u64,

    /// Maximum per-`Application` delay inside one webhook fan-out, in milliseconds.
    #[arg(
        long = "webhook-max-jitter-millis",
        value_name = "MILLIS",
        default_value_t = 500
    )]
    pub webhook_max_jitter_millis: u64,

    /// Optional action instead of serving.
    #[command(subcommand)]
    pub command: Option<ServerCommand>,
}

impl std::fmt::Debug for ServerArgs {
    /// Never prints a webhook secret or token: the parsed arguments are logged at startup and may be
    /// shown by a panic message (finding `P14-M2`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerArgs")
            .field("controller", &self.controller)
            .field("api_addr", &self.api_addr)
            .field("metrics_addr", &self.controller.metrics_addr)
            .field("auth_policy", &self.auth_policy)
            .field(
                "github_webhook_secret",
                &redacted(self.github_webhook_secret.is_some()),
            )
            .field(
                "gitlab_webhook_token",
                &redacted(self.gitlab_webhook_token.is_some()),
            )
            .field("webhook_debounce_seconds", &self.webhook_debounce_seconds)
            .field("webhook_max_jitter_millis", &self.webhook_max_jitter_millis)
            .field("command", &self.command)
            .finish()
    }
}

/// `Some(<redacted>)`/`None`: says whether a credential is configured, never which one.
fn redacted(configured: bool) -> Option<&'static str> {
    configured.then_some("<redacted>")
}

/// Non-serving actions of `ferriscd server`.
#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Write the OpenAPI 3.1 document (the TypeScript client is generated from it).
    Openapi(OpenApiArgs),
}

/// Arguments for `ferriscd server openapi`.
#[derive(Debug, Args)]
pub struct OpenApiArgs {
    /// Where to write the document.
    #[arg(
        long = "output",
        short = 'o',
        value_name = "PATH",
        default_value = "docs/api/openapi.json"
    )]
    pub output: PathBuf,

    /// Fail (exit 1) if the file on disk differs from the generated document.
    #[arg(long = "check")]
    pub check: bool,
}

/// Executes `ferriscd server` (or `ferriscd server openapi`).
pub async fn run(args: ServerArgs) -> Result<()> {
    if let Some(ServerCommand::Openapi(openapi)) = args.command {
        return export_openapi(openapi);
    }
    serve(args).await
}

/// Writes (or checks) the OpenAPI document.
///
/// # Errors
///
/// Fails when the document cannot be serialized, the file cannot be read/written, or `--check` finds
/// a stale file.
pub fn export_openapi(args: OpenApiArgs) -> Result<()> {
    let document = ferriscd_server::openapi::document_json_pretty()
        .context("the OpenAPI document could not be serialized")?;
    let document = format!("{document}\n");
    if args.check {
        let existing = std::fs::read_to_string(&args.output).with_context(|| {
            format!(
                "the committed OpenAPI document {} cannot be read; run `ferriscd server openapi`",
                args.output.display()
            )
        })?;
        anyhow::ensure!(
            existing == document,
            "{} is stale: run `ferriscd server openapi` and commit the result",
            args.output.display()
        );
        println!("{} is up to date", args.output.display());
        return Ok(());
    }
    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    std::fs::write(&args.output, document)
        .with_context(|| format!("cannot write {}", args.output.display()))?;
    println!("wrote {}", args.output.display());
    Ok(())
}

/// Builds the webhook configuration from the flags.
///
/// # Errors
///
/// A flag that parses to an empty secret is an error rather than a silently disabled webhook: an
/// empty HMAC key or token would authenticate everyone.
fn webhook_config(args: &ServerArgs) -> Result<ferriscd_server::WebhookConfig> {
    let github_secret = match args.github_webhook_secret.as_deref() {
        None => None,
        Some(secret) => {
            Some(WebhookSecret::new(secret).context("--github-webhook-secret must not be empty")?)
        }
    };
    let gitlab_secret = match args.gitlab_webhook_token.as_deref() {
        None => None,
        Some(token) => {
            Some(WebhookSecret::new(token).context("--gitlab-webhook-token must not be empty")?)
        }
    };
    Ok(ferriscd_server::WebhookConfig {
        github_secret,
        gitlab_secret,
        debounce: Duration::from_secs(args.webhook_debounce_seconds),
        max_jitter: Duration::from_millis(args.webhook_max_jitter_millis),
        ..ferriscd_server::WebhookConfig::default()
    })
}

/// Refuses a `--metrics-addr` that resolves to the API port (`T15.1`).
///
/// The comparison is on the **port** only: two listeners can never share a port even when their
/// addresses differ (`127.0.0.1:8080` and `0.0.0.0:8080` overlap on loopback, and a `0.0.0.0` bind
/// takes the port on every interface), so an address comparison would let that collision through to
/// a confusing "address already in use".
///
/// An unparsable value is left to the controller's own startup validation (which reports it with the
/// expected format), so this check only covers the collision it can recognise.
fn ensure_metrics_addr_differs(api: SocketAddr, metrics_addr: &str) -> Result<()> {
    if let Ok(metrics) = metrics_addr.parse::<SocketAddr>() {
        anyhow::ensure!(
            metrics.port() != api.port(),
            "--metrics-addr ({metrics}) must not use the --api-addr port ({}): the metrics \
             listener is never served on the API/webhook port, whatever address it binds",
            api.port()
        );
    }
    Ok(())
}

/// Builds the shared control plane and runs the controller and the API server together.
async fn serve(args: ServerArgs) -> Result<()> {
    let address: SocketAddr = args
        .api_addr
        .parse()
        .with_context(|| format!("--api-addr {:?} is not a socket address", args.api_addr))?;
    // `T15.1`: `/metrics` gets its **own** listener. Sharing the API port would put the scrape
    // endpoint behind the same socket as the bearer-protected `/api/v1/*` surface (and the webhook
    // POSTs), which is exactly what `T14.3` split apart — so the collision is refused up front
    // instead of surfacing as a confusing "address already in use" from whichever bind ran second.
    ensure_metrics_addr_differs(address, &args.controller.metrics_addr)?;
    let webhooks = webhook_config(&args)?;

    // The ONE control plane: the same caches, registry, pipeline and discovery every handler and
    // every reconcile uses (finding C9).
    let plane = ferriscd_controller::prepare(run_options(args.controller)).await?;
    // `T14.4`: the project-scoped policy is a startup snapshot read from `ferriscd-rbac-cm` in the
    // control-plane namespace. A missing or malformed policy is deny-all with a loud log, never
    // allow-all (`fallback_to_deny_all`).
    let rbac = ferriscd_server::kube::load_rbac_policy(&plane).await;
    let state = ferriscd_server::kube::app_state(&plane, webhooks)
        .with_auth(args.auth_policy)
        .with_rbac(std::sync::Arc::new(rbac));
    if let Some(metrics_addr) = plane.metrics_addr() {
        // `T15.1`: said out loud where the API address is decided, so a scrape that fails is not
        // diagnosed as a missing endpoint.
        tracing::info!(
            metrics_addr = %metrics_addr,
            api_addr = %address,
            "internal Prometheus metrics listener bound (GET /metrics); it is a separate port, \
             never the API/webhook one"
        );
    }
    if ferriscd_server::auth::exposes_unauthenticated_api(address, args.auth_policy) {
        // Before the listener exists, so the operator sees it even if the bind then fails. The
        // listener logs it again with the address it really bound (`serve_listener`).
        tracing::warn!(
            addr = %address,
            auth = args.auth_policy.as_str(),
            "the protected API is UNAUTHENTICATED: --auth-policy=pass-through (a development \
             escape hatch, not the default) is binding {address}, which is not loopback, so any \
             client that can reach it can read diffs and request syncs/rollbacks. Drop \
             --auth-policy to use TokenReview, or bind --api-addr 127.0.0.1:<port>"
        );
    }
    if ferriscd_server::kube::denies_every_authenticated_caller(&state) {
        tracing::warn!(
            auth = state.auth.as_str(),
            "the RBAC policy is empty: every authenticated request will be refused (default-deny). \
             Publish the ferriscd-rbac-cm ConfigMap (key policy.yaml) in the control-plane \
             namespace and restart the server"
        );
    }
    if !state.webhooks.is_configured() {
        tracing::warn!(
            "no webhook secret is configured (--github-webhook-secret / \
             --gitlab-webhook-token): both webhook endpoints answer 422 and push-triggered syncs \
             are disabled; the periodic requeue still reconciles every Application"
        );
    }

    // One shutdown decision for the whole process.
    let stop = tokio_util::sync::CancellationToken::new();
    let signal = stop.clone();
    tokio::spawn(async move {
        let reason = ferriscd_controller::shutdown_signal().await;
        tracing::info!(
            signal = reason.as_str(),
            "graceful shutdown requested; draining the API server and in-flight reconciles"
        );
        signal.cancel();
    });

    let api_stop = stop.clone();
    let mut api = tokio::spawn(async move {
        ferriscd_server::serve(address, state, api_stop.cancelled_owned()).await
    });
    let controller_stop = stop.clone();
    let mut controller = tokio::spawn(async move { plane.run_until(controller_stop).await });

    tokio::select! {
        // The controller ended (a signal, or a leader lease that will not be renewed).
        result = &mut controller => {
            stop.cancel();
            let served = api
                .await
                .context("the API server task panicked")?;
            result.context("the controller task panicked")??;
            served?;
            Ok(())
        }
        // The API server ended first: stop the controller through the same token and wait for it to
        // drain, so a failed listener never leaves a reconciling process that nobody can reach.
        served = &mut api => {
            stop.cancel();
            let drained = controller
                .await
                .context("the controller task panicked")?;
            served.context("the API server task panicked")??;
            drained?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;

    #[derive(Debug, Parser)]
    #[command(name = "ferriscd")]
    struct Harness {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Debug, clap::Subcommand)]
    enum Command {
        Server(ServerArgs),
    }

    fn parse(args: &[&str]) -> ServerArgs {
        let harness = Harness::try_parse_from(args).expect("server arguments must parse");
        match harness.command {
            Command::Server(args) => args,
        }
    }

    #[test]
    fn the_server_defaults_are_production_safe() {
        let args = parse(&["ferriscd", "server"]);
        assert_eq!(args.api_addr, ferriscd_server::DEFAULT_API_ADDR);
        assert!(
            args.github_webhook_secret.is_none() && args.gitlab_webhook_token.is_none(),
            "no webhook secret may be defaulted: an empty secret authenticates everybody"
        );
        assert_eq!(args.webhook_debounce_seconds, 2);
        assert_eq!(args.webhook_max_jitter_millis, 500);
        assert!(args.command.is_none());
        // The controller flags are inherited, including their owner.
        assert!(args.controller.namespace.is_none());
        assert!(!args.controller.allow_local_repos);
        // **`T14.3`:** the default policy authenticates every protected request with a
        // `TokenReview`, and the default bind is loopback — the safe combination, from defaults.
        assert_eq!(args.auth_policy, AuthPolicy::TokenReview);
        let address: SocketAddr = args.api_addr.parse().expect("a socket address");
        assert!(
            !ferriscd_server::auth::exposes_unauthenticated_api(address, args.auth_policy),
            "the shipped default must not be the unauthenticated-bind combination: {address}"
        );
        // **`T15.1`:** the metrics listener is inherited from `ferriscd controller`, and its default
        // is a *different* port from the API — the scrape endpoint is never the API/webhook port.
        assert_eq!(
            args.controller.metrics_addr,
            ferriscd_controller::DEFAULT_METRICS_ADDR
        );
        let metrics: SocketAddr = args
            .controller
            .metrics_addr
            .parse()
            .expect("a socket address");
        assert_eq!(metrics.port(), 9090);
        assert_ne!(metrics, address);
        ensure_metrics_addr_differs(address, &args.controller.metrics_addr)
            .expect("the shipped default pair must not collide");
    }

    /// **`T15.1`:** a `--metrics-addr` that lands on the API port is refused before any listener is
    /// bound, instead of surfacing as a confusing "address already in use" from the second bind.
    ///
    /// The check is by port, so a *different* address on the same port is refused too: two
    /// listeners cannot share a port, and `0.0.0.0:8080` overlaps `127.0.0.1:8080` on loopback.
    #[test]
    fn a_metrics_address_that_is_the_api_address_is_refused() {
        let api: SocketAddr = "127.0.0.1:8080".parse().expect("a socket address");
        for metrics_addr in [
            "127.0.0.1:8080",
            "0.0.0.0:8080",
            "[::1]:8080",
            "10.0.0.1:8080",
        ] {
            let error = ensure_metrics_addr_differs(api, metrics_addr)
                .expect_err("sharing the API port must be refused");
            assert!(
                error
                    .to_string()
                    .contains("must not use the --api-addr port"),
                "{error}"
            );
        }
        // The reverse direction collides as well (the API bound to all interfaces).
        let wildcard: SocketAddr = "0.0.0.0:8080".parse().expect("a socket address");
        ensure_metrics_addr_differs(wildcard, "127.0.0.1:8080")
            .expect_err("the same port collides whatever the address is");
        ensure_metrics_addr_differs(api, "0.0.0.0:9090").expect("a distinct address is accepted");
        ensure_metrics_addr_differs(api, "127.0.0.1:9091").expect("a distinct port is accepted");
        // Only a parsed socket address can collide; an unparsable value is the controller's own
        // startup error (with the expected format), not a silent default.
        ensure_metrics_addr_differs(api, "9090").expect("the controller validates the format");
    }

    /// **Finding `P14-H1`:** the policy is selectable, the flag takes both documented values, a typo
    /// is refused (never silently the permissive default), and the env fallback is declared.
    #[test]
    fn the_auth_policy_flag_and_env_are_wired() {
        assert_eq!(
            parse(&["ferriscd", "server", "--auth-policy", "deny-all"]).auth_policy,
            AuthPolicy::DenyAll
        );
        assert_eq!(
            parse(&["ferriscd", "server", "--auth-policy", " pass-through "]).auth_policy,
            AuthPolicy::PassThrough
        );
        assert_eq!(
            parse(&["ferriscd", "server", "--auth-policy", "token-review"]).auth_policy,
            AuthPolicy::TokenReview
        );

        let rejected = Harness::try_parse_from(["ferriscd", "server", "--auth-policy", "open"]);
        let error = rejected.expect_err("an unknown policy must be refused");
        assert!(
            error.to_string().contains("unknown authentication policy"),
            "{error}"
        );

        // The env var is declared on the flag (clap reads `FERRISCD_AUTH_POLICY` when the flag is
        // absent); asserting the declaration avoids mutating the process environment in a test.
        let mut command = Harness::command();
        let server = command
            .find_subcommand_mut("server")
            .expect("the server subcommand exists");
        let arg = server
            .get_arguments()
            .find(|arg| arg.get_id() == "auth_policy")
            .expect("the --auth-policy argument exists");
        assert_eq!(
            arg.get_env().and_then(|env| env.to_str()),
            Some("FERRISCD_AUTH_POLICY")
        );
        assert_eq!(
            arg.get_default_values()
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["token-review".to_owned()],
            "the default must authenticate: pass-through is an explicit development escape hatch"
        );
    }

    #[test]
    fn the_server_parses_the_api_and_webhook_flags() {
        let args = parse(&[
            "ferriscd",
            "server",
            "--api-addr",
            "127.0.0.1:18080",
            "--github-webhook-secret",
            "s3cr3t",
            "--gitlab-webhook-token",
            "glpat-token",
            "--webhook-debounce-seconds",
            "5",
            "--webhook-max-jitter-millis",
            "50",
            "--namespace",
            "ferriscd-system",
            "--leader-election",
        ]);
        assert_eq!(args.api_addr, "127.0.0.1:18080");
        assert_eq!(args.github_webhook_secret.as_deref(), Some("s3cr3t"));
        assert_eq!(args.gitlab_webhook_token.as_deref(), Some("glpat-token"));
        assert_eq!(args.webhook_debounce_seconds, 5);
        assert_eq!(args.webhook_max_jitter_millis, 50);
        assert!(args.controller.leader_election);

        let config = webhook_config(&args).expect("a non-empty secret is valid");
        assert!(config.github_secret.is_some());
        assert!(config.gitlab_secret.is_some());
        assert_eq!(config.debounce, Duration::from_secs(5));
        // The secrets never reach Debug (a startup log line must stay safe).
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(!rendered.contains("glpat-token"), "{rendered}");
    }

    /// **Finding `P14-M2`:** `ServerArgs` holds both webhook credentials in plaintext, so its
    /// `Debug` — which a log line, a panic message or `dbg!` will render — must not print them.
    #[test]
    fn the_parsed_arguments_never_print_a_webhook_secret() {
        let args = parse(&[
            "ferriscd",
            "server",
            "--github-webhook-secret",
            "s3cr3t-value",
            "--gitlab-webhook-token",
            "glpat-secret-value",
        ]);
        let rendered = format!("{args:?}");
        assert!(!rendered.contains("s3cr3t-value"), "{rendered}");
        assert!(!rendered.contains("glpat-secret-value"), "{rendered}");
        assert!(
            rendered.contains("<redacted>"),
            "the credentials are reported as configured, never as content: {rendered}"
        );
        // The non-secret fields stay visible, or the log line would be useless for debugging.
        assert!(
            rendered.contains(ferriscd_server::DEFAULT_API_ADDR),
            "{rendered}"
        );
        assert!(rendered.contains("TokenReview"), "{rendered}");

        // Nothing at all when no credential is configured.
        let none = format!("{:?}", parse(&["ferriscd", "server"]));
        assert!(!none.contains("<redacted>"), "{none}");
    }

    #[test]
    fn an_empty_webhook_secret_is_refused() {
        let args = parse(&["ferriscd", "server", "--github-webhook-secret", "   "]);
        let error = webhook_config(&args).expect_err("an empty secret must be refused");
        assert!(error.to_string().contains("must not be empty"), "{error}");
    }

    #[test]
    fn the_openapi_subcommand_parses_with_defaults_and_overrides() {
        let default = parse(&["ferriscd", "server", "openapi"]);
        match default.command {
            Some(ServerCommand::Openapi(openapi)) => {
                assert_eq!(openapi.output, PathBuf::from("docs/api/openapi.json"));
                assert!(!openapi.check);
            }
            other => panic!("expected the openapi subcommand, got {other:?}"),
        }

        let overridden = parse(&["ferriscd", "server", "openapi", "-o", "api.json", "--check"]);
        match overridden.command {
            Some(ServerCommand::Openapi(openapi)) => {
                assert_eq!(openapi.output, PathBuf::from("api.json"));
                assert!(openapi.check);
            }
            other => panic!("expected the openapi subcommand, got {other:?}"),
        }
    }

    /// **`T14.1`:** the export command is what keeps `docs/api/openapi.json` and the served document
    /// identical; this pins the write/`--check` behaviour without touching the repository.
    #[test]
    fn the_export_writes_and_then_verifies_the_document() {
        let directory = tempfile::tempdir().expect("a scratch directory");
        let output = directory.path().join("api").join("openapi.json");

        export_openapi(OpenApiArgs {
            output: output.clone(),
            check: false,
        })
        .expect("the document is written");
        let written = std::fs::read_to_string(&output).expect("the file exists");
        assert!(written.starts_with('{'));
        assert!(written.ends_with("}\n"));
        let parsed: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
        assert_eq!(
            parsed["info"]["title"], "FerrisCD Control Plane API",
            "the exported document is the served contract"
        );

        export_openapi(OpenApiArgs {
            output: output.clone(),
            check: true,
        })
        .expect("an up-to-date file passes --check");

        std::fs::write(&output, "{}").expect("the file is overwritten");
        let error = export_openapi(OpenApiArgs {
            output: output.clone(),
            check: true,
        })
        .expect_err("a stale file must fail --check");
        assert!(error.to_string().contains("is stale"), "{error}");

        let missing = directory.path().join("nope.json");
        assert!(
            export_openapi(OpenApiArgs {
                output: missing,
                check: true,
            })
            .is_err(),
            "an unreadable document must fail --check"
        );
    }

    /// The flag help must document the operator-facing security knobs.
    #[test]
    fn the_help_documents_the_api_and_webhook_surface() {
        let mut command = Harness::command();
        let help = command
            .find_subcommand_mut("server")
            .expect("the server subcommand exists")
            .render_long_help()
            .to_string();
        for expected in [
            "--api-addr",
            "--auth-policy",
            "FERRISCD_AUTH_POLICY",
            "token-review",
            "deny-all",
            "ferriscd-rbac-cm",
            "--github-webhook-secret",
            "--gitlab-webhook-token",
            "FERRISCD_GITHUB_WEBHOOK_SECRET",
            "FERRISCD_GITLAB_WEBHOOK_TOKEN",
            "--webhook-debounce-seconds",
            "--webhook-max-jitter-millis",
            "openapi",
            // `T15.1`: `ferriscd server` inherits the controller's metrics flag, and the help must
            // say it is a separate port.
            "--metrics-addr",
            "FERRISCD_METRICS_ADDR",
            "ferriscd_reconcile_total",
        ] {
            assert!(
                help.contains(expected),
                "the flag help must document {expected:?}: {help}"
            );
        }
    }
}

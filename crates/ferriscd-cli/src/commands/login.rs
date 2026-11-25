//! `ferriscd login` — store a server URL and a Kubernetes bearer token (`T14.5`).
//!
//! The credential goes to `~/.config/ferriscd/config.json` with mode `0600` (or `$FERRISCD_CONFIG`),
//! never to a dotfile the shell sources, never to a URL parameter, and never to the terminal echo:
//! `--token` is documented but `--token-file` or `$FERRISCD_TOKEN` keep it out of `ps` and shell
//! history.
//!
//! `login` verifies the token against the server before storing it (`GET /api/v1/clusters`, the one
//! protected endpoint that is not project-scoped), so a typo fails here instead of at the first real
//! command. `--no-verify` stores it anyway, for an environment where the API is not up yet.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use clap::Args;

use crate::client::{Client, StoredConfig, TOKEN_ENV, config_path, normalize_server_url};

/// Arguments for `ferriscd login`.
///
/// `Debug` is written by hand: `token` is a credential and a derived `Debug` would print it the first
/// time anybody logged the parsed arguments.
#[derive(Args)]
pub struct LoginArgs {
    /// Base URL of `ferriscd-server` (for example https://ferriscd.example.com).
    #[arg(value_name = "SERVER_URL")]
    pub server_url: String,

    /// Kubernetes bearer token (a `ServiceAccount` token); prefer `--token-file` or
    /// `$FERRISCD_TOKEN` so it stays out of `ps` and your shell history.
    #[arg(
        long = "token",
        value_name = "TOKEN",
        env = "FERRISCD_TOKEN",
        hide_env_values = true,
        conflicts_with = "token_file"
    )]
    pub token: Option<String>,

    /// Read the token from a file (`kubectl create token ... > token`), where it is not visible in
    /// the process table.
    #[arg(long = "token-file", value_name = "PATH", conflicts_with = "token")]
    pub token_file: Option<PathBuf>,

    /// Do not check the token against the server before storing it.
    #[arg(long = "no-verify")]
    pub no_verify: bool,
}

impl std::fmt::Debug for LoginArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginArgs")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("token_file", &self.token_file)
            .field("no_verify", &self.no_verify)
            .finish()
    }
}

/// Executes `ferriscd login`.
///
/// # Errors
///
/// Fails when no token is supplied, the URL is not absolute http(s), the server refuses the token
/// (unless `--no-verify`), or the configuration cannot be written.
pub async fn run(args: LoginArgs) -> Result<()> {
    // Reading the token file and writing the credential are blocking disk operations; they run on
    // the blocking pool so the command never stalls an async worker (AGENTS.md async hygiene), even
    // though a CLI process would rarely notice.
    let token = tokio::task::spawn_blocking({
        let token = args.token.clone();
        let token_file = args.token_file.clone();
        move || read_token(token.as_deref(), token_file.as_deref())
    })
    .await
    .context("reading the token panicked")??;
    let server_url = normalize_server_url(&args.server_url).context(
        "the server URL is not usable: pass an absolute http(s) URL, e.g. https://ferriscd.example.com",
    )?;

    if !args.no_verify {
        let client =
            Client::new(&server_url, token.clone()).context("cannot build the API client")?;
        let clusters = client
            .list_clusters()
            .await
            .context("the server refused the token, so nothing was stored")?;
        println!(
            "authenticated against {} ({} cluster(s) visible)",
            client.base_url(),
            clusters.items.len()
        );
    }

    let path = config_path()?;
    let stored = StoredConfig {
        server_url: server_url.clone(),
        token,
    };
    tokio::task::spawn_blocking({
        let path = path.clone();
        move || stored.save_to(&path)
    })
    .await
    .context("storing the credential panicked")??;
    println!(
        "stored the credential for {server_url} in {}",
        path.display()
    );
    println!("next: `ferriscd app list`");
    Ok(())
}

/// The token, from the flag, `$FERRISCD_TOKEN`, or a file.
///
/// # Errors
///
/// [`crate::client::ClientError::MissingToken`] when none is supplied, and a read failure for an
/// unreadable `--token-file`.
fn read_token(token: Option<&str>, token_file: Option<&Path>) -> Result<String> {
    if let Some(token) = token {
        let token = token.trim();
        anyhow::ensure!(!token.is_empty(), "the supplied token is empty");
        return Ok(token.to_owned());
    }
    if let Some(path) = token_file {
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read the token file {}", path.display()))?;
        let token = token.trim();
        anyhow::ensure!(
            !token.is_empty(),
            "the token file {} is empty",
            path.display()
        );
        return Ok(token.to_owned());
    }
    Err(crate::client::ClientError::MissingToken).context(format!(
        "no token was supplied; `ferriscd login` reads --token, --token-file or ${TOKEN_ENV}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(token: Option<&str>, token_file: Option<&std::path::Path>) -> LoginArgs {
        LoginArgs {
            server_url: "https://ferriscd.example.com".to_owned(),
            token: token.map(ToOwned::to_owned),
            token_file: token_file.map(ToOwned::to_owned),
            no_verify: false,
        }
    }

    /// `read_token` over the parsed arguments.
    fn read(args: &LoginArgs) -> Result<String> {
        read_token(args.token.as_deref(), args.token_file.as_deref())
    }

    #[test]
    fn a_token_from_a_flag_or_a_file_is_trimmed_and_required() {
        assert_eq!(read(&args(Some(" abc\n"), None)).expect("a token"), "abc");
        assert!(read(&args(Some("   "), None)).is_err(), "empty is refused");
        assert!(read(&args(None, None)).is_err(), "missing is refused");

        let directory = tempfile::tempdir().expect("a scratch directory");
        let path = directory.path().join("token");
        std::fs::write(&path, "from-a-file\n").expect("write");
        assert_eq!(
            read(&args(None, Some(&path))).expect("a token"),
            "from-a-file"
        );

        std::fs::write(&path, "  \n").expect("write");
        assert!(
            read(&args(None, Some(&path))).is_err(),
            "an empty file is refused"
        );
        assert!(
            read(&args(None, Some(&directory.path().join("nope")))).is_err(),
            "an unreadable file is refused"
        );
    }

    /// `LoginArgs` holds a credential: its `Debug` must never print it.
    #[test]
    fn the_parsed_arguments_never_print_the_token() {
        let rendered = format!("{:?}", args(Some("super-secret-token"), None));
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("https://ferriscd.example.com"),
            "{rendered}"
        );
    }
}

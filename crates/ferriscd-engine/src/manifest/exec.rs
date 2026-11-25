//! Hardened subprocess runner for external manifest renderers (`kustomize`, `helm`).
//!
//! Rendering an untrusted Git repository by shelling out is one of the sharpest edges in a
//! GitOps control plane: the child process inherits whatever the controller's environment holds
//! (Kubernetes service-account tokens, cloud credentials, proxy settings pointing at a real
//! network) and its output is bounded only by the child's willingness to produce bytes. This
//! module is the single place where that edge is narrowed:
//!
//! * **Environment is cleared.** [`SandboxedCommand`] calls `env_clear()` and passes only a
//!   minimal `PATH`, plus a per-invocation scratch `HOME`, `TMPDIR`, `XDG_CACHE_HOME`, and
//!   `XDG_CONFIG_HOME`. Nothing else from the controller process reaches the child — no
//!   `KUBERNETES_*`, no `AWS_*`, no `KUBECONFIG`, no Helm/Kustomize plugin environment.
//! * **The program must be absolute.** Only an absolute path or a bare `PATH` name is executed; a
//!   relative path (`./kustomize`) is rejected, because it would resolve to a binary the untrusted
//!   repository supplied.
//! * **Egress is poisoned.** `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (and their lowercase
//!   spellings) point at `http://127.0.0.1:0` — a port nothing listens on — and `NO_PROXY` is
//!   emptied. A renderer that ignores its own "offline" flags still cannot reach a remote
//!   `http(s)://` base or the link-local metadata service through a proxy it invents.
//! * **Runtime is bounded.** A hard deadline (default [`DEFAULT_TIMEOUT`]) kills the child;
//!   `kill_on_drop(true)` guarantees it also dies if the render future is cancelled.
//! * **Output is bounded.** Both pipes are drained by reader tasks that abort as soon as a
//!   stream exceeds its cap (default [`DEFAULT_MAX_OUTPUT_BYTES`] each), so a chart that
//!   template-loops cannot exhaust controller memory.
//! * **No shell.** Arguments are `OsStr` values handed straight to `execve`; nothing is ever
//!   string-concatenated into a shell command line.
//!
//! Blocking work: only `resolve_program`'s `PATH` scan and a single `tempdir_in` happen on the
//! calling (Tokio) task, both bounded single-syscall operations. The child itself is spawned and
//! reaped asynchronously.
//!
//! # Residual risk (documented, not fixed here)
//!
//! The child still runs with the controller's uid/gid and filesystem view. Pod-level isolation
//! (a dedicated renderer pod, `automountServiceAccountToken: false`, a `NetworkPolicy` that
//! denies egress) is the Phase 16 deployment story; see
//! `docs/lessons/11-safe-manifest-rendering-helm-and-kustomize.md`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

/// Default hard execution deadline for one external renderer invocation.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default per-stream output cap (20 MiB), matching the YAML budget head-room of Phase 03.
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 20 * 1024 * 1024;

/// Maximum number of stderr bytes quoted in a failure message.
const MAX_STDERR_IN_ERROR: usize = 4096;

/// `PATH` handed to the child: absolute system directories only, never the controller's.
const MINIMAL_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Dead proxy endpoint: port 0 is never connectable, so proxied egress fails immediately.
const BLOCKED_PROXY: &str = "http://127.0.0.1:0";

/// Size of one pipe read.
const READ_CHUNK: usize = 8 * 1024;

/// Errors produced by [`SandboxedCommand`].
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The program could not be located on the parent `PATH`.
    #[error("renderer binary '{program}' was not found on PATH")]
    ProgramNotFound {
        /// Program name as requested.
        program: String,
    },

    /// The program was given as a relative path, which is never executed.
    #[error(
        "renderer binary '{program}' must be an absolute path or a bare name looked up on PATH; \
         relative paths are never executed"
    )]
    ProgramRelativePath {
        /// Program path as requested.
        program: String,
    },

    /// The program exists but could not be spawned.
    #[error("failed to spawn '{program}': {source}")]
    Spawn {
        /// Program name as requested.
        program: String,
        /// Underlying spawn error.
        #[source]
        source: io::Error,
    },

    /// The child exceeded its deadline and was killed.
    #[error("'{program}' was killed after exceeding the {millis}ms deadline")]
    Timeout {
        /// Program name as requested.
        program: String,
        /// Deadline in milliseconds (exact; a 250 ms deadline must not report `0s`).
        millis: u64,
    },

    /// A stream exceeded its byte cap; the child was killed.
    #[error("'{program}' {stream} exceeded the {limit}-byte cap")]
    OutputLimit {
        /// Program name as requested.
        program: String,
        /// Which stream breached the cap.
        stream: &'static str,
        /// Cap in bytes.
        limit: u64,
    },

    /// The child exited with a non-success status.
    #[error("'{program}' exited with {status}: {stderr}")]
    Failed {
        /// Program name as requested.
        program: String,
        /// Exit code or signal description.
        status: String,
        /// Bounded stderr excerpt (lossy UTF-8).
        stderr: String,
    },

    /// A pipe produced non-UTF-8 output that cannot be a rendered manifest.
    #[error("'{program}' {stream} was not valid UTF-8")]
    InvalidUtf8 {
        /// Program name as requested.
        program: String,
        /// Which stream was invalid.
        stream: &'static str,
    },

    /// Pipes, scratch directories, or task joins failed.
    #[error("I/O error while running '{program}' ({context}): {source}")]
    Io {
        /// Program name as requested.
        program: String,
        /// Operation being performed.
        context: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

impl ExecError {
    /// Returns `true` for failures that could plausibly be transient.
    ///
    /// Deliberately strict: a renderer that could not be spawned, timed out, or exited non-zero
    /// against one immutable commit will produce the same result on retry, so only genuine I/O
    /// error kinds are retryable (and even those are usually a broken scratch filesystem).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Io { source, .. } => !matches!(
                source.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::NotFound
            ),
            _ => false,
        }
    }
}

/// Result of one successful (exit code 0) sandboxed invocation.
#[derive(Clone, PartialEq, Eq)]
pub struct SandboxedOutput {
    /// Captured stdout (rendered manifests), validated as UTF-8.
    pub stdout: String,
    /// Captured stderr (diagnostics), lossy UTF-8 with a bounded size.
    ///
    /// Bounded is **not** redacted: `helm`/`kustomize` diagnostics quote chart and kustomization
    /// content, which a repository can populate with credentials. Callers must treat this as
    /// untrusted text and never log it unredacted (finding M2).
    pub stderr: String,
    /// Exit status (always success, since non-zero exits are errors).
    pub status: ExitStatus,
}

impl fmt::Debug for SandboxedOutput {
    /// Prints sizes, never the captured text: `stdout` is the rendered bundle (which can contain a
    /// `Secret`'s plaintext data once normalized) and `stderr` is repository-influenced.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxedOutput")
            .field("status", &self.status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .finish()
    }
}

/// A single external command executed under the render sandbox described in the module docs.
///
/// Construct with [`SandboxedCommand::new`], chain the builder methods, then
/// [`SandboxedCommand::run`]. The command is single-use: every `run` gets its own scratch
/// `HOME`/`TMPDIR`, so two concurrent invocations never share renderer state.
#[derive(Clone)]
pub struct SandboxedCommand {
    program: OsString,
    args: Vec<OsString>,
    current_dir: Option<PathBuf>,
    timeout: Duration,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
    scratch_parent: Option<PathBuf>,
}

impl fmt::Debug for SandboxedCommand {
    /// Redacts argument *values*: renderer argv can carry `--set password=...` style values, and
    /// this struct is logged by callers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags: Vec<&str> = self
            .args
            .iter()
            .filter_map(|arg| arg.to_str())
            .filter(|arg| arg.starts_with('-'))
            .collect();
        f.debug_struct("SandboxedCommand")
            .field("program", &self.program)
            .field("argument_count", &self.args.len())
            .field("flags", &flags)
            .field("current_dir", &self.current_dir)
            .field("timeout", &self.timeout)
            .field("max_stdout_bytes", &self.max_stdout_bytes)
            .field("max_stderr_bytes", &self.max_stderr_bytes)
            .finish_non_exhaustive()
    }
}

impl SandboxedCommand {
    /// Creates a sandboxed invocation of `program`.
    ///
    /// Accepted forms are an absolute path (used as-is) and a bare name (resolved against the
    /// **parent** `PATH`, a bounded metadata scan, then executed by absolute path, so the child's
    /// cleared environment can never influence which binary runs). A relative path such as
    /// `./kustomize` is a terminal [`ExecError::ProgramRelativePath`]: it would resolve against the
    /// checkout directory the renderer was pointed at, which is attacker-controlled.
    #[must_use]
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: None,
            timeout: DEFAULT_TIMEOUT,
            max_stdout_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            scratch_parent: None,
        }
    }

    /// Appends one argument verbatim (`OsStr`, never shell-interpreted).
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Appends several arguments verbatim.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets the child's working directory.
    #[must_use]
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(dir.into());
        self
    }

    /// Overrides the hard execution deadline.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides the per-stream output cap (applies to stdout and stderr).
    #[must_use]
    pub fn max_output_bytes(mut self, max_bytes: u64) -> Self {
        self.max_stdout_bytes = max_bytes;
        self.max_stderr_bytes = max_bytes;
        self
    }

    /// Places the per-invocation scratch directory under `parent` instead of the system temp
    /// directory (useful when the system temp directory is small or on another filesystem).
    #[must_use]
    pub fn scratch_parent(mut self, parent: impl Into<PathBuf>) -> Self {
        self.scratch_parent = Some(parent.into());
        self
    }

    /// Runs the command to completion under the sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ProgramNotFound`] when the binary is missing,
    /// [`ExecError::Timeout`] when the deadline kills the child,
    /// [`ExecError::OutputLimit`] when a stream exceeds its cap,
    /// [`ExecError::Failed`] when the child exits non-zero, and [`ExecError::Io`] /
    /// [`ExecError::InvalidUtf8`] for pipe and encoding failures.
    pub async fn run(&self) -> Result<SandboxedOutput, ExecError> {
        let program = self.program.to_string_lossy().into_owned();

        // Program lookup (`PATH` scan) and scratch-directory creation are bounded but blocking
        // filesystem work, so they run on the blocking pool rather than a Tokio worker.
        let prepared = {
            let requested = self.program.clone();
            let scratch_parent = self.scratch_parent.clone();
            let display = program.clone();
            tokio::task::spawn_blocking(move || {
                prepare_invocation(requested.as_os_str(), scratch_parent.as_deref(), &display)
            })
            .await
            .map_err(|join_err| ExecError::Io {
                program: program.clone(),
                context: "preparing the sandbox".to_owned(),
                source: io::Error::other(format!("sandbox preparation task failed: {join_err}")),
            })??
        };
        let resolved = prepared.program;
        let home = prepared.home;
        let tmp = prepared.tmp;
        // Kept alive (and deleted on drop) for the whole invocation.
        let _scratch = prepared.scratch;

        let mut command = Command::new(&resolved);
        command
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The child must die with us even if this future is dropped mid-flight (a cancelled
            // reconcile must never leave a renderer running).
            .kill_on_drop(true)
            .env_clear();
        for (key, value) in hardened_env(&home, &tmp) {
            command.env(key, value);
        }
        if let Some(dir) = &self.current_dir {
            command.current_dir(dir);
        }

        let mut child = command.spawn().map_err(|source| ExecError::Spawn {
            program: program.clone(),
            source,
        })?;

        let stdout = child.stdout.take().ok_or_else(|| ExecError::Io {
            program: program.clone(),
            context: "taking the child stdout pipe".to_owned(),
            source: io::Error::other("stdout pipe was not created"),
        })?;
        let stderr = child.stderr.take().ok_or_else(|| ExecError::Io {
            program: program.clone(),
            context: "taking the child stderr pipe".to_owned(),
            source: io::Error::other("stderr pipe was not created"),
        })?;

        // The waiter owns the child: aborting it drops the child, and `kill_on_drop` then kills
        // the process, which is exactly the behaviour the timeout and output-cap paths need.
        let mut waiter = tokio::spawn(async move { child.wait().await });
        let mut stdout_task = tokio::spawn(read_bounded(stdout, self.max_stdout_bytes));
        let mut stderr_task = tokio::spawn(read_bounded(stderr, self.max_stderr_bytes));

        let mut stdout_bytes: Option<Vec<u8>> = None;
        let mut stderr_bytes: Option<Vec<u8>> = None;
        let mut exit: Option<io::Result<ExitStatus>> = None;

        let deadline = tokio::time::sleep(self.timeout);
        tokio::pin!(deadline);

        let failure = loop {
            if exit.is_some() && stdout_bytes.is_some() && stderr_bytes.is_some() {
                break None;
            }

            tokio::select! {
                res = &mut waiter, if exit.is_none() => {
                    exit = Some(match res {
                        Ok(result) => result,
                        Err(join_err) => Err(io::Error::other(format!(
                            "child reaper task failed: {join_err}"
                        ))),
                    });
                }
                res = &mut stdout_task, if stdout_bytes.is_none() => {
                    match stream_result(res, &program, "stdout", self.max_stdout_bytes) {
                        Ok(bytes) => stdout_bytes = Some(bytes),
                        Err(err) => break Some(err),
                    }
                }
                res = &mut stderr_task, if stderr_bytes.is_none() => {
                    match stream_result(res, &program, "stderr", self.max_stderr_bytes) {
                        Ok(bytes) => stderr_bytes = Some(bytes),
                        Err(err) => break Some(err),
                    }
                }
                () = &mut deadline => {
                    break Some(ExecError::Timeout {
                        program: program.clone(),
                        millis: u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX),
                    });
                }
            }
        };

        if let Some(err) = failure {
            // Dropping (aborting) the waiter drops the `Child`, and `kill_on_drop` kills it.
            waiter.abort();
            stdout_task.abort();
            stderr_task.abort();
            return Err(err);
        }

        let status = match exit {
            Some(Ok(status)) => status,
            Some(Err(source)) => {
                return Err(ExecError::Io {
                    program,
                    context: "waiting for the child process".to_owned(),
                    source,
                });
            }
            None => {
                return Err(ExecError::Io {
                    program,
                    context: "waiting for the child process".to_owned(),
                    source: io::Error::other("child exit status was never observed"),
                });
            }
        };

        let stdout_bytes = stdout_bytes.unwrap_or_default();
        let stderr_bytes = stderr_bytes.unwrap_or_default();
        let stderr_text = describe_stderr(&stderr_bytes);

        if !status.success() {
            return Err(ExecError::Failed {
                program,
                status: describe_status(status),
                stderr: stderr_text,
            });
        }

        let stdout = String::from_utf8(stdout_bytes).map_err(|_| ExecError::InvalidUtf8 {
            program,
            stream: "stdout",
        })?;

        Ok(SandboxedOutput {
            stdout,
            stderr: stderr_text,
            status,
        })
    }
}

/// Result of the blocking half of an invocation.
struct PreparedInvocation {
    program: PathBuf,
    scratch: tempfile::TempDir,
    home: PathBuf,
    tmp: PathBuf,
}

/// Resolves the program and creates the per-invocation scratch directories (blocking).
fn prepare_invocation(
    requested: &OsStr,
    scratch_parent: Option<&Path>,
    program: &str,
) -> Result<PreparedInvocation, ExecError> {
    let resolved = resolve_program(requested)?;

    let mut builder = tempfile::Builder::new();
    builder.prefix("ferriscd-render-");
    let scratch = match scratch_parent {
        Some(parent) => builder.tempdir_in(parent),
        None => builder.tempdir(),
    }
    .map_err(|source| ExecError::Io {
        program: program.to_owned(),
        context: "creating the render scratch directory".to_owned(),
        source,
    })?;

    let home = scratch.path().join("home");
    let tmp = scratch.path().join("tmp");
    for dir in [&home, &tmp] {
        std::fs::create_dir_all(dir).map_err(|source| ExecError::Io {
            program: program.to_owned(),
            context: format!("creating sandbox scratch directory '{}'", dir.display()),
            source,
        })?;
    }

    Ok(PreparedInvocation {
        program: resolved,
        scratch,
        home,
        tmp,
    })
}

/// Returns the exact environment handed to a sandboxed child.
///
/// Only these keys exist in the child: a minimal `PATH`, a scratch `HOME`/`TMPDIR`/XDG pair, and
/// dead proxy endpoints. Everything else the controller process holds stays out.
fn hardened_env(home: &Path, tmp: &Path) -> Vec<(&'static str, OsString)> {
    vec![
        ("PATH", OsString::from(MINIMAL_PATH)),
        ("HOME", home.as_os_str().to_owned()),
        ("TMPDIR", tmp.as_os_str().to_owned()),
        ("TMP", tmp.as_os_str().to_owned()),
        ("XDG_CACHE_HOME", home.join(".cache").into_os_string()),
        ("XDG_CONFIG_HOME", home.join(".config").into_os_string()),
        ("XDG_DATA_HOME", home.join(".local/share").into_os_string()),
        ("HTTP_PROXY", OsString::from(BLOCKED_PROXY)),
        ("HTTPS_PROXY", OsString::from(BLOCKED_PROXY)),
        ("ALL_PROXY", OsString::from(BLOCKED_PROXY)),
        ("NO_PROXY", OsString::new()),
        ("http_proxy", OsString::from(BLOCKED_PROXY)),
        ("https_proxy", OsString::from(BLOCKED_PROXY)),
        ("all_proxy", OsString::from(BLOCKED_PROXY)),
        ("no_proxy", OsString::new()),
    ]
}

/// Resolves `program` to an absolute path.
///
/// **Only two forms are executable** (finding M1):
///
/// * an absolute path (`/usr/local/bin/kustomize`), used as-is, and
/// * a bare name (`kustomize`), searched on the **parent** `PATH` so the lookup is independent of
///   the (cleared) child environment; a name that cannot be resolved is a terminal
///   [`ExecError::ProgramNotFound`].
///
/// A *relative* path with a separator (`./kustomize`, `bin/helm`, `../kustomize`) is rejected
/// outright: it resolves against the child's working directory, which is the untrusted checkout,
/// so a repository could ship its own `./kustomize` and have the controller run it. Nothing in
/// FerrisCD has a legitimate reason to execute a relative program.
fn resolve_program(program: &OsStr) -> Result<PathBuf, ExecError> {
    let requested = Path::new(program);
    let display = program.to_string_lossy().into_owned();

    if program.is_empty() {
        return Err(ExecError::ProgramNotFound { program: display });
    }

    if requested.is_absolute() {
        return Ok(requested.to_path_buf());
    }

    // A bare name has exactly one `Normal` component; `./x`, `a/b` and `..` do not.
    let mut components = requested.components();
    let bare =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !bare {
        return Err(ExecError::ProgramRelativePath { program: display });
    }

    let search = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&search) {
        // An empty or relative `PATH` entry would resolve against the process' working directory.
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join(requested);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }

    Err(ExecError::ProgramNotFound { program: display })
}

/// Returns `true` when `path` is a regular file executable by the current process.
fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Why a bounded pipe reader stopped early.
#[derive(Debug)]
enum StreamFailure {
    /// The stream produced more bytes than its cap allows.
    Limit,
    /// The pipe itself failed.
    Io(io::Error),
}

/// Reads `reader` until EOF, refusing to buffer more than `cap` bytes.
async fn read_bounded<R>(mut reader: R, cap: u64) -> Result<Vec<u8>, StreamFailure>
where
    R: AsyncRead + Unpin,
{
    let mut collected: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        let read = reader.read(&mut chunk).await.map_err(StreamFailure::Io)?;
        if read == 0 {
            return Ok(collected);
        }
        if collected.len() as u64 + read as u64 > cap {
            return Err(StreamFailure::Limit);
        }
        collected.extend_from_slice(&chunk[..read]);
    }
}

/// Flattens one reader-task result into captured bytes or an [`ExecError`].
fn stream_result(
    result: Result<Result<Vec<u8>, StreamFailure>, tokio::task::JoinError>,
    program: &str,
    stream: &'static str,
    limit: u64,
) -> Result<Vec<u8>, ExecError> {
    match result {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(StreamFailure::Limit)) => Err(ExecError::OutputLimit {
            program: program.to_owned(),
            stream,
            limit,
        }),
        Ok(Err(StreamFailure::Io(source))) => Err(ExecError::Io {
            program: program.to_owned(),
            context: format!("reading child {stream}"),
            source,
        }),
        Err(join_err) => Err(ExecError::Io {
            program: program.to_owned(),
            context: format!("reading child {stream}"),
            source: io::Error::other(format!("{stream} reader task failed: {join_err}")),
        }),
    }
}

/// Renders bounded, lossy UTF-8 stderr for an error message.
fn describe_stderr(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    if trimmed.len() <= MAX_STDERR_IN_ERROR {
        return trimmed.to_owned();
    }
    let mut end = MAX_STDERR_IN_ERROR;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… (truncated)", &trimmed[..end])
}

/// Describes an exit status as an exit code or signal name.
fn describe_status(status: ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exit code {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return format!("signal {signal}");
        }
    }
    "an unknown status".to_owned()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::time::Instant;

    use super::*;

    /// Environment variables that must never cross the trust boundary, cleared by `env_clear()`.
    ///
    /// Test-only on purpose: production code must not have a list to *allow*, only a list of
    /// things to assert it never passes.
    const NEVER_INHERITED: [&str; 8] = [
        "KUBERNETES_SERVICE_HOST",
        "KUBERNETES_SERVICE_PORT",
        "KUBECONFIG",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "HELM_REPOSITORY_CONFIG",
        "HELM_PLUGINS",
        "KUSTOMIZE_PLUGIN_HOME",
    ];

    /// Runs `/bin/sh -c <script>` under the sandbox (POSIX-only, like the fixtures below).
    #[cfg(unix)]
    fn shell(script: &str) -> SandboxedCommand {
        SandboxedCommand::new("/bin/sh").args(["-c", script])
    }

    /// Runs `env` directly (no shell), so the printed environment is exactly the child's.
    #[cfg(unix)]
    fn env_command() -> SandboxedCommand {
        SandboxedCommand::new("env")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sleeping_child_is_killed_when_the_deadline_expires() {
        // `exec` replaces the shell, so exactly one process is involved and nothing is orphaned.
        let started = Instant::now();
        let err = shell("exec sleep 30")
            .timeout(Duration::from_millis(250))
            .run()
            .await
            .expect_err("a sleeping child must hit the deadline");
        let elapsed = started.elapsed();

        assert!(
            matches!(err, ExecError::Timeout { millis: 250, .. }),
            "expected a 250ms timeout (reported in milliseconds, not truncated to seconds), \
             got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the deadline must kill the child instead of waiting for it ({elapsed:?})"
        );
        assert!(!err.is_retryable(), "a render timeout is terminal");

        // The runner keeps working after a killed child: no leaked state, no stuck pipe.
        let output = shell("printf ok").run().await.expect("second invocation");
        assert_eq!(output.stdout, "ok");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn oversized_stdout_aborts_before_buffering_unbounded_output() {
        // `cat /dev/zero` never ends; the cap (not the deadline) must end the invocation.
        let err = shell("exec cat /dev/zero")
            .max_output_bytes(16 * 1024)
            .timeout(Duration::from_secs(30))
            .run()
            .await
            .expect_err("unbounded output must abort");

        match err {
            ExecError::OutputLimit { stream, .. } => assert_eq!(stream, "stdout"),
            other => panic!("expected an output-limit failure, got {other:?}"),
        }
        assert!(!err.is_retryable(), "an output cap breach is terminal");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn oversized_stderr_aborts_too() {
        let err = shell("exec cat /dev/zero >&2")
            .max_output_bytes(8 * 1024)
            .timeout(Duration::from_secs(30))
            .run()
            .await
            .expect_err("unbounded stderr must abort");

        match err {
            ExecError::OutputLimit { stream, .. } => assert_eq!(stream, "stderr"),
            other => panic!("expected an output-limit failure, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn child_environment_is_a_clean_allow_list() {
        // `env` prints the child's real environment, one KEY=VALUE per line. It is executed
        // directly (not through a shell) so the shell cannot add `PWD`/`SHLVL` of its own.
        let output = env_command().run().await.expect("env must run");
        let mut keys: Vec<String> = output
            .stdout
            .lines()
            .filter_map(|line| line.split_once('=').map(|(key, _)| key.to_owned()))
            .collect();
        keys.sort();

        let mut expected: Vec<String> = hardened_env(Path::new("/home"), Path::new("/tmp"))
            .into_iter()
            .map(|(key, _)| key.to_owned())
            .collect();
        expected.sort();
        assert_eq!(
            keys, expected,
            "the child must see exactly the hardened environment"
        );

        // The credential-shaped variables FerrisCD exists to keep out are absent by name...
        for forbidden in NEVER_INHERITED {
            assert!(
                !keys.contains(&forbidden.to_owned()),
                "'{forbidden}' must never reach a renderer child"
            );
        }
        // ...and nothing else the controller process holds leaks in either: the allow-list above
        // is exact, so this covers every parent variable including ones not named here.
        let parent_env = std::env::vars_os();
        for (parent_key, _) in parent_env {
            let key = parent_key.to_string_lossy().into_owned();
            if expected.contains(&key) {
                continue;
            }
            assert!(
                !keys.contains(&key),
                "parent variable '{key}' leaked into the renderer child"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn parent_path_and_home_are_not_inherited() {
        let parent_path = std::env::var_os("PATH").expect("the test process has a PATH");
        let output = env_command().run().await.expect("env must run");

        let child_path = output
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("PATH="))
            .expect("child PATH must be set");
        assert_eq!(child_path, MINIMAL_PATH);
        assert_ne!(
            Some(OsString::from(child_path)),
            Some(parent_path),
            "the controller PATH must never be handed to the child"
        );

        let child_home = output
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("HOME="))
            .expect("child HOME must be set");
        assert!(
            child_home.contains("ferriscd-render-"),
            "HOME must be the per-invocation scratch directory, got '{child_home}'"
        );
        assert_ne!(
            Some(OsString::from(child_home)),
            std::env::var_os("HOME"),
            "the controller HOME must never be handed to the child"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn proxy_egress_is_poisoned() {
        let output = env_command().run().await.expect("env must run");
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            let value = output
                .stdout
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("{key} must be set"));
            assert_eq!(value, BLOCKED_PROXY, "{key} must point at the dead proxy");
        }
        for key in ["NO_PROXY", "no_proxy"] {
            let value = output
                .stdout
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("{key} must be set"));
            assert_eq!(value, "", "{key} must be empty");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn arguments_are_never_shell_interpreted() {
        // `$0` is the shell's own argv[0]; the remaining positional parameters are ours.
        let output = SandboxedCommand::new("/bin/sh")
            .args([
                "-c",
                r#"printf '%s\n' "$@""#,
                "sh",
                "a b",
                "$(id)",
                "`id`",
                "--namespace",
            ])
            .run()
            .await
            .expect("argv pass-through");

        assert_eq!(output.stdout, "a b\n$(id)\n`id`\n--namespace\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_zero_exit_reports_bounded_stderr() {
        let err = shell("printf 'boom: chart not found\\n' >&2; exit 3")
            .run()
            .await
            .expect_err("non-zero exit must fail");
        match &err {
            ExecError::Failed { status, stderr, .. } => {
                assert_eq!(status, "exit code 3");
                assert!(stderr.contains("boom: chart not found"), "{stderr}");
            }
            other => panic!("expected a failed exit, got {other:?}"),
        }
        assert!(!err.is_retryable(), "a non-zero renderer exit is terminal");
    }

    #[tokio::test]
    async fn missing_program_is_reported_without_spawning() {
        let err = SandboxedCommand::new("ferriscd-definitely-not-installed-7f3a")
            .arg("build")
            .run()
            .await
            .expect_err("a missing binary must fail");
        assert!(matches!(err, ExecError::ProgramNotFound { .. }), "{err:?}");
        assert!(!err.is_retryable());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn current_dir_is_honoured() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = shell("exec pwd")
            .current_dir(temp.path())
            .run()
            .await
            .expect("pwd must run");
        // macOS reports `/private/var/...` for `/var/...`; compare canonical forms.
        let reported = std::fs::canonicalize(output.stdout.trim()).expect("canonicalize pwd");
        let expected = std::fs::canonicalize(temp.path()).expect("canonicalize tempdir");
        assert_eq!(reported, expected);
    }

    #[tokio::test]
    async fn debug_output_redacts_argument_values() {
        let command = SandboxedCommand::new("helm").args([
            "--set-string",
            "password=hunter2",
            "--namespace",
            "prod",
        ]);
        let rendered = format!("{command:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("password="), "{rendered}");
        assert!(rendered.contains("--namespace"), "{rendered}");
    }

    /// Finding M2: the captured stdout of a renderer can be a `Secret`; `Debug` prints sizes only.
    #[cfg(unix)]
    #[tokio::test]
    async fn sandboxed_output_debug_prints_sizes_not_the_rendered_text() {
        let output = shell("printf 'data:\\n  token: hunter2\\n'; printf 'warn: hunter2\\n' >&2")
            .run()
            .await
            .expect("render must succeed");
        assert!(output.stdout.contains("hunter2"));

        let rendered = format!("{output:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("stdout_bytes"), "{rendered}");
        assert!(rendered.contains("stderr_bytes"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn program_resolution_prefers_explicit_paths_and_rejects_empty_names() {
        let explicit = resolve_program(OsStr::new("/bin/sh")).expect("absolute path");
        assert_eq!(explicit, PathBuf::from("/bin/sh"));

        // A bare name resolves against the parent PATH to an absolute path.
        let resolved = resolve_program(OsStr::new("sh")).expect("sh is on PATH");
        assert!(resolved.is_absolute(), "{}", resolved.display());

        assert!(matches!(
            resolve_program(OsStr::new("")),
            Err(ExecError::ProgramNotFound { .. })
        ));
    }

    /// Finding M1: a relative program path is refused — including the repo-provided
    /// `./kustomize` that used to be executed verbatim against the checkout as its working
    /// directory.
    #[test]
    fn relative_program_paths_are_rejected() {
        for program in [
            "./kustomize",
            "../kustomize",
            "bin/helm",
            "tools/kustomize",
            ".",
            "..",
        ] {
            let err = resolve_program(OsStr::new(program))
                .expect_err("a relative program path must never resolve");
            assert!(
                matches!(err, ExecError::ProgramRelativePath { .. }),
                "'{program}' must be rejected, got {err:?}"
            );
            assert!(!err.is_retryable(), "a rejected program is terminal");
        }
    }

    /// The trap itself: a repository that ships its own `./kustomize` must never have it run, while
    /// the same script executed by absolute path (what a legitimate operator override looks like)
    /// still works — so the assertion below is about the *path form*, not about a broken fixture.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_repository_provided_relative_binary_is_never_executed() {
        let checkout = tempfile::tempdir().expect("checkout");
        let script = checkout.path().join("kustomize");
        let marker = checkout.path().join("executed");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nprintf 'ran\\n' >> '{}'\n", marker.display()),
        )
        .expect("write script");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod script");

        let err = SandboxedCommand::new("./kustomize")
            .arg("build")
            .arg(".")
            .current_dir(checkout.path())
            .run()
            .await
            .expect_err("a relative program must be rejected");
        assert!(
            matches!(err, ExecError::ProgramRelativePath { .. }),
            "{err:?}"
        );
        assert!(
            !marker.exists(),
            "the repository-provided binary must never run"
        );

        // The identical script executes when it is named by absolute path.
        SandboxedCommand::new(script.as_os_str().to_owned())
            .current_dir(checkout.path())
            .run()
            .await
            .expect("an absolute program runs");
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap_or_default().trim(),
            "ran",
            "the fixture script must be executable, otherwise the rejection above is vacuous"
        );
    }
}

//! Optional OpenTelemetry OTLP trace export (`T15.2`) and tracing subscriber bootstrap.
//!
//! # Zero-overhead default
//!
//! OTLP tracing is strictly opt-in via [`OTEL_EXPORTER_OTLP_ENDPOINT_ENV`]: when the variable is
//! unset or blank, **no** `SpanExporter`, `SdkTracerProvider`, HTTP client, or background
//! `BatchSpanProcessor` thread is constructed, and the process behaves identically to plain
//! `tracing_subscriber` logging.
//!
//! # Blocking HTTP transport on `BatchSpanProcessor`
//!
//! `opentelemetry_sdk`'s `BatchSpanProcessor` drains spans on its own background OS thread, which
//! has no Tokio reactor. Using `opentelemetry-otlp` with `reqwest-blocking-client` +
//! `reqwest-rustls` avoids any async-runtime coupling inside the processor thread while sharing the
//! process-level `ring` `rustls::crypto::CryptoProvider` pinned at startup
//! ([`crate::impersonation::ensure_crypto_provider`]).
//!
//! # Credential hygiene
//!
//! An OTLP collector endpoint can carry userinfo (`https://user:token@collector:4318`) or query
//! parameters (`?api_key=…`). [`redact_endpoint_url`] strips both before any value is stored in
//! [`TelemetryError`], formatted via `Debug`, or written to logs.

use std::sync::Mutex;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

use crate::{LogFormat, LogFormatError, lock_recover, log_format_from_env};

/// Environment variable enabling OpenTelemetry OTLP trace export.
///
/// Unset or blank disables OTLP completely (zero exporter constructed, zero network traffic).
pub const OTEL_EXPORTER_OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Environment variable overriding the OpenTelemetry `service.name` resource attribute.
///
/// Defaults to [`DEFAULT_SERVICE_NAME`] when unset or blank.
pub const OTEL_SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";

/// Default OpenTelemetry `service.name` resource attribute.
pub const DEFAULT_SERVICE_NAME: &str = "ferriscd-controller";

/// Instrumentation scope name attached to exported spans.
const TRACER_SCOPE: &str = "ferriscd-controller";

/// Standard OTLP/HTTP trace ingest path appended when an endpoint omits it.
const OTLP_TRACES_PATH: &str = "/v1/traces";

/// Errors raised while configuring, installing, or shutting down telemetry.
///
/// Every endpoint string carried by these variants is **already redacted**
/// ([`redact_endpoint_url`]), so printing or formatting an error can never leak credentials.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// `FERRISCD_LOG_FORMAT` was set to an unknown value.
    #[error(transparent)]
    InvalidLogFormat(#[from] LogFormatError),

    /// `OTEL_EXPORTER_OTLP_ENDPOINT` is not a valid `http://` or `https://` URL.
    #[error("invalid {OTEL_EXPORTER_OTLP_ENDPOINT_ENV} value {endpoint:?}: {reason}")]
    InvalidEndpoint {
        /// Redacted representation of the rejected endpoint URL.
        endpoint: String,
        /// Why the URL was rejected.
        reason: String,
    },

    /// The OTLP span exporter could not be constructed.
    #[error("failed to build OTLP span exporter for {endpoint}: {message}")]
    ExporterBuild {
        /// Redacted representation of the configured endpoint URL.
        endpoint: String,
        /// Redacted error detail from `opentelemetry-otlp`.
        message: String,
    },

    /// Installing the global `tracing` subscriber failed (usually already initialized).
    #[error("failed to install tracing subscriber: {message}")]
    SubscriberInstall {
        /// Underlying subscriber error message.
        message: String,
    },

    /// Flushing or shutting down the `SdkTracerProvider` failed.
    #[error("failed to shut down OpenTelemetry tracer provider: {message}")]
    Shutdown {
        /// Redacted underlying SDK error message.
        message: String,
    },
}

impl TelemetryError {
    fn exporter_build(config: &OtlpConfig, raw_message: &str) -> Self {
        Self::ExporterBuild {
            endpoint: config.redacted_endpoint().to_owned(),
            message: redact_message(
                raw_message,
                Some(config.endpoint()),
                Some(config.redacted_endpoint()),
            ),
        }
    }

    fn shutdown(
        raw_message: &str,
        raw_endpoint: Option<&str>,
        redacted_endpoint: Option<&str>,
    ) -> Self {
        Self::Shutdown {
            message: redact_message(raw_message, raw_endpoint, redacted_endpoint),
        }
    }
}

/// Validated OpenTelemetry OTLP exporter configuration.
///
/// `Debug` is written by hand so the raw endpoint URL (which may carry userinfo or query tokens)
/// is never printed — only [`Self::redacted_endpoint`] is shown.
#[derive(Clone, PartialEq, Eq)]
pub struct OtlpConfig {
    endpoint: String,
    redacted_endpoint: String,
    service_name: String,
}

impl std::fmt::Debug for OtlpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpConfig")
            .field("endpoint", &self.redacted_endpoint)
            .field("service_name", &self.service_name)
            .finish()
    }
}

impl OtlpConfig {
    /// Resolves OTLP settings from [`OTEL_EXPORTER_OTLP_ENDPOINT_ENV`] and
    /// [`OTEL_SERVICE_NAME_ENV`].
    ///
    /// Returns `Ok(None)` when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset or blank.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::InvalidEndpoint`] when the endpoint is set to an invalid URL or
    /// uses a scheme other than `http` / `https`.
    pub fn from_env() -> Result<Option<Self>, TelemetryError> {
        let endpoint = std::env::var(OTEL_EXPORTER_OTLP_ENDPOINT_ENV).ok();
        let service_name = std::env::var(OTEL_SERVICE_NAME_ENV).ok();
        Self::from_env_values(endpoint.as_deref(), service_name.as_deref())
    }

    /// Pure, testable constructor accepting raw environment variable values.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::InvalidEndpoint`] for an unusable endpoint URL.
    pub fn from_env_values(
        endpoint: Option<&str>,
        service_name: Option<&str>,
    ) -> Result<Option<Self>, TelemetryError> {
        let Some(raw) = endpoint.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let validated = validate_endpoint_url(raw)?;
        let normalized = resolve_traces_endpoint(&validated);
        let redacted_endpoint = redact_endpoint_url(&normalized);
        let service_name = service_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_SERVICE_NAME)
            .to_owned();
        Ok(Some(Self {
            endpoint: normalized,
            redacted_endpoint,
            service_name,
        }))
    }

    /// The validated and normalized traces endpoint URL passed to `opentelemetry-otlp`.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Credential-redacted endpoint URL safe for logs, diagnostics, and error messages.
    #[must_use]
    pub fn redacted_endpoint(&self) -> &str {
        &self.redacted_endpoint
    }

    /// The OpenTelemetry `service.name` resource attribute.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }
}

/// Validates an OTLP HTTP endpoint URL.
///
/// Accepts `http://` and `https://` URLs with a non-empty host. Rejects relative paths, unsupported
/// schemes, missing hosts, and whitespace/control characters, returning a redacted error so
/// credentials embedded in a malformed URL are never echoed back.
fn validate_endpoint_url(raw: &str) -> Result<String, TelemetryError> {
    let redacted = redact_endpoint_url(raw);
    if raw.chars().any(char::is_control) {
        return Err(TelemetryError::InvalidEndpoint {
            endpoint: redacted,
            reason: "endpoint must not contain control characters".to_owned(),
        });
    }
    let uri: http::Uri = raw.parse().map_err(|err| TelemetryError::InvalidEndpoint {
        endpoint: redacted.clone(),
        reason: format!("malformed URI: {err}"),
    })?;
    let Some(scheme) = uri.scheme_str() else {
        return Err(TelemetryError::InvalidEndpoint {
            endpoint: redacted,
            reason: "missing URL scheme (expected http:// or https://)".to_owned(),
        });
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(TelemetryError::InvalidEndpoint {
            endpoint: redacted,
            reason: format!("unsupported scheme {scheme:?} (expected http or https)"),
        });
    }
    let Some(host) = uri.host() else {
        return Err(TelemetryError::InvalidEndpoint {
            endpoint: redacted,
            reason: "missing host in endpoint URL".to_owned(),
        });
    };
    if host.is_empty() {
        return Err(TelemetryError::InvalidEndpoint {
            endpoint: redacted,
            reason: "host in endpoint URL must not be empty".to_owned(),
        });
    }
    Ok(raw.to_owned())
}

/// Normalizes an OTLP HTTP endpoint URL so its path ends with `/v1/traces`.
///
/// `opentelemetry-otlp`'s `.with_endpoint(...)` sends requests to the configured URL verbatim
/// without appending `/v1/traces`, whereas operators typically configure a base collector URL
/// (e.g. `http://otel-collector:4318`) via [`OTEL_EXPORTER_OTLP_ENDPOINT_ENV`]. This appends
/// `/v1/traces` to the path component before any `?query` or `#fragment`, avoids double slashes on
/// trailing `/`, and leaves endpoints already ending with `/v1/traces` unchanged.
#[must_use]
pub fn resolve_traces_endpoint(url: &str) -> String {
    let split_idx = url.find(['?', '#']).unwrap_or(url.len());
    let (head, tail) = url.split_at(split_idx);
    let Some((scheme, after_scheme)) = head.split_once("://") else {
        return url.to_owned();
    };
    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, ""),
    };
    let trimmed_path = path.trim_end_matches('/');
    if trimmed_path.ends_with(OTLP_TRACES_PATH) {
        format!("{scheme}://{authority}{trimmed_path}{tail}")
    } else {
        format!("{scheme}://{authority}{trimmed_path}{OTLP_TRACES_PATH}{tail}")
    }
}

/// Redacts userinfo, query parameters, and fragments from a URL string.
///
/// Unlike a strict URI parser, this works on **malformed** URL strings too (for example,
/// `http://user:s3cr3t@bad host:9999?token=xyz`), so [`TelemetryError::InvalidEndpoint`] can never
/// echo embedded credentials into a log line or startup failure.
#[must_use]
pub fn redact_endpoint_url(raw: &str) -> String {
    // Strip fragment and query first so tokens in `?api_key=...` or `#...` cannot leak.
    let (without_fragment, has_fragment) = match raw.split_once('#') {
        Some((before, _)) => (before, true),
        None => (raw, false),
    };
    let (base, has_query) = match without_fragment.split_once('?') {
        Some((before, _)) => (before, true),
        None => (without_fragment, false),
    };

    let redacted_base = if let Some((scheme, rest)) = base.split_once("://") {
        // Authority ends at the first `/` (if any). Only an `@` inside the authority is userinfo.
        let (authority, tail) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        if let Some((_userinfo, host_port)) = authority.rsplit_once('@') {
            format!("{scheme}://***@{host_port}{tail}")
        } else {
            base.to_owned()
        }
    } else {
        base.to_owned()
    };

    let mut out = redacted_base;
    if has_query {
        out.push_str("?<redacted>");
    }
    if has_fragment {
        out.push_str("#<redacted>");
    }
    out
}

/// Redacts any whitespace-delimited token containing `://` so embedded credentials in repository
/// or endpoint URLs cannot leak into error messages, logs, or Kubernetes Event notes.
#[must_use]
pub(crate) fn redact_urls_in_text(input: &str) -> String {
    if !input.contains("://") {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    let bytes = input.as_bytes();
    while cursor < bytes.len() {
        let Some(ch) = input[cursor..].chars().next() else {
            break;
        };
        if ch.is_whitespace() {
            out.push(ch);
            cursor += ch.len_utf8();
            continue;
        }
        let start = cursor;
        while cursor < bytes.len() {
            let Some(next) = input[cursor..].chars().next() else {
                break;
            };
            if next.is_whitespace() {
                break;
            }
            cursor += next.len_utf8();
        }
        let token = &input[start..cursor];
        if token.contains("://") {
            out.push_str(&redact_url_token(token));
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Redacts a token containing `://`, preserving surrounding punctuation (quotes, parens, commas).
fn redact_url_token(token: &str) -> String {
    let prefix_len = token.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(0);
    let prefix = &token[..prefix_len];
    let rest = &token[prefix_len..];
    let trimmed_end = rest.trim_end_matches(['.', ',', ';', ':', ')', ']', '}', '"', '\'']);
    let suffix = &rest[trimmed_end.len()..];
    if trimmed_end.contains("://") {
        format!("{prefix}{}{suffix}", redact_endpoint_url(trimmed_end))
    } else {
        token.to_owned()
    }
}

/// Builds an [`SdkTracerProvider`] wired to an HTTP/protobuf OTLP [`SpanExporter`].
///
/// Split out from [`init_telemetry`] so unit tests can verify exporter + provider construction and
/// clean shutdown hermetically without installing a global `tracing` subscriber.
///
/// # Errors
///
/// Returns [`TelemetryError::ExporterBuild`] if `opentelemetry-otlp` rejects the configuration or
/// fails to initialize its blocking HTTP client.
pub fn build_tracer_provider(config: &OtlpConfig) -> Result<SdkTracerProvider, TelemetryError> {
    // Ensure the process-level `ring` TLS crypto provider is installed even if a caller invokes
    // telemetry before `prepare()`.
    crate::impersonation::ensure_crypto_provider();

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(config.endpoint())
        .build()
        .map_err(|err| TelemetryError::exporter_build(config, &err.to_string()))?;

    let resource = Resource::builder()
        .with_service_name(config.service_name().to_owned())
        .build();

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}

/// Replaces any occurrence of the configured raw endpoint URL and redacts any embedded URL
/// credentials inside a third-party error string.
fn redact_message(
    message: &str,
    raw_endpoint: Option<&str>,
    redacted_endpoint: Option<&str>,
) -> String {
    let replaced = match (raw_endpoint, redacted_endpoint) {
        (Some(raw), Some(redacted)) if raw != redacted => message.replace(raw, redacted),
        _ => message.to_owned(),
    };
    redact_urls_in_text(&replaced)
}

/// Lifetime guard owning the active [`SdkTracerProvider`] (when OTLP is enabled).
///
/// Holding this guard for the lifetime of the process keeps the `BatchSpanProcessor` alive; calling
/// [`Self::shutdown_async`] (during graceful shutdown) or [`Self::shutdown`] (or dropping the guard)
/// flushes buffered spans cleanly.
pub struct TelemetryGuard {
    log_format: LogFormat,
    raw_endpoint: Option<String>,
    redacted_endpoint: Option<String>,
    service_name: Option<String>,
    provider: Mutex<Option<SdkTracerProvider>>,
}

impl std::fmt::Debug for TelemetryGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryGuard")
            .field("log_format", &self.log_format)
            .field("otlp_enabled", &self.otlp_enabled())
            .field("endpoint", &self.redacted_endpoint)
            .field("service_name", &self.service_name)
            .finish()
    }
}

impl TelemetryGuard {
    /// Creates a guard representing logging-only mode (no OTLP provider constructed).
    #[must_use]
    pub fn disabled(log_format: LogFormat) -> Self {
        Self {
            log_format,
            raw_endpoint: None,
            redacted_endpoint: None,
            service_name: None,
            provider: Mutex::new(None),
        }
    }

    /// Creates a guard owning `provider` for an active OTLP pipeline.
    #[must_use]
    pub fn with_provider(
        log_format: LogFormat,
        config: &OtlpConfig,
        provider: SdkTracerProvider,
    ) -> Self {
        Self {
            log_format,
            raw_endpoint: Some(config.endpoint().to_owned()),
            redacted_endpoint: Some(config.redacted_endpoint().to_owned()),
            service_name: Some(config.service_name().to_owned()),
            provider: Mutex::new(Some(provider)),
        }
    }

    /// Selected structured log format (`Pretty` or `Json`).
    #[must_use]
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }

    /// Whether OTLP trace export was configured at startup.
    #[must_use]
    pub fn otlp_enabled(&self) -> bool {
        self.redacted_endpoint.is_some()
    }

    /// Redacted OTLP endpoint URL, or `None` when OTLP is disabled.
    #[must_use]
    pub fn redacted_endpoint(&self) -> Option<&str> {
        self.redacted_endpoint.as_deref()
    }

    /// OpenTelemetry `service.name`, or `None` when OTLP is disabled.
    #[must_use]
    pub fn service_name(&self) -> Option<&str> {
        self.service_name.as_deref()
    }

    /// Synchronously flushes and shuts down the tracer provider (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Shutdown`] if the SDK reports a flush/shutdown failure.
    pub fn shutdown(&self) -> Result<(), TelemetryError> {
        let provider = lock_recover(&self.provider).take();
        let Some(provider) = provider else {
            return Ok(());
        };
        provider.shutdown().map_err(|err| {
            TelemetryError::shutdown(
                &err.to_string(),
                self.raw_endpoint.as_deref(),
                self.redacted_endpoint.as_deref(),
            )
        })
    }

    /// Flushes and shuts down the tracer provider off the async worker pool (idempotent).
    ///
    /// `SdkTracerProvider::shutdown` blocks waiting for the `BatchSpanProcessor` background thread
    /// to drain, so running it inside `tokio::task::spawn_blocking` keeps async workers unblocked
    /// during graceful shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Shutdown`] if the blocking shutdown task fails or panics.
    pub async fn shutdown_async(&self) -> Result<(), TelemetryError> {
        let provider = lock_recover(&self.provider).take();
        let Some(provider) = provider else {
            return Ok(());
        };
        let raw_endpoint = self.raw_endpoint.clone();
        let redacted_endpoint = self.redacted_endpoint.clone();
        let raw_endpoint_for_join = raw_endpoint.clone();
        let redacted_endpoint_for_join = redacted_endpoint.clone();
        tokio::task::spawn_blocking(move || {
            provider.shutdown().map_err(|err| {
                TelemetryError::shutdown(
                    &err.to_string(),
                    raw_endpoint.as_deref(),
                    redacted_endpoint.as_deref(),
                )
            })
        })
        .await
        .map_err(|err| {
            TelemetryError::shutdown(
                &format!("telemetry shutdown task failed: {err}"),
                raw_endpoint_for_join.as_deref(),
                redacted_endpoint_for_join.as_deref(),
            )
        })?
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = lock_recover(&self.provider).take() {
            let _ = provider.shutdown();
        }
    }
}

/// Initializes global structured logging and optional OpenTelemetry OTLP tracing from environment
/// variables (`FERRISCD_LOG_FORMAT`, `RUST_LOG`, `OTEL_EXPORTER_OTLP_ENDPOINT`,
/// `OTEL_SERVICE_NAME`).
///
/// The returned [`TelemetryGuard`] **must** be kept alive until process shutdown so buffered OTLP
/// spans are flushed cleanly.
///
/// # Errors
///
/// Returns [`TelemetryError`] when the log format or OTLP endpoint is invalid, when the OTLP
/// exporter cannot be built, or when a global `tracing` subscriber is already installed.
pub fn init_telemetry() -> Result<TelemetryGuard, TelemetryError> {
    let format = log_format_from_env()?;
    let otlp = OtlpConfig::from_env()?;
    init_telemetry_with(format, otlp)
}

/// Installs the global `tracing` subscriber for an explicit `(format, otlp)` pair.
///
/// When `otlp` is `None`, **zero** OpenTelemetry exporter or provider is constructed.
///
/// # Errors
///
/// Returns [`TelemetryError`] if building the exporter or installing the global subscriber fails.
pub fn init_telemetry_with(
    format: LogFormat,
    otlp: Option<OtlpConfig>,
) -> Result<TelemetryGuard, TelemetryError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let (otel_layer, global_provider, guard) = match otlp {
        None => (None, None, TelemetryGuard::disabled(format)),
        Some(config) => {
            let provider = build_tracer_provider(&config)?;
            let tracer = provider.tracer(TRACER_SCOPE);
            let layer = tracing_opentelemetry::layer().with_tracer(tracer);
            let global_provider = provider.clone();
            let guard = TelemetryGuard::with_provider(format, &config, provider);
            (Some(layer), Some(global_provider), guard)
        }
    };

    let fmt_layer = match format {
        LogFormat::Json => tracing_subscriber::fmt::layer().json().boxed(),
        LogFormat::Pretty => tracing_subscriber::fmt::layer().boxed(),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(otel_layer)
        .with(fmt_layer)
        .try_init()
        .map_err(|err| TelemetryError::SubscriberInstall {
            message: err.to_string(),
        })?;

    if let Some(provider) = global_provider {
        opentelemetry::global::set_tracer_provider(provider);
    }

    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otlp_is_disabled_when_endpoint_is_unset_or_blank() {
        assert_eq!(
            OtlpConfig::from_env_values(None, None).expect("unset endpoint is valid"),
            None
        );
        assert_eq!(
            OtlpConfig::from_env_values(Some(""), None).expect("empty endpoint is disabled"),
            None
        );
        assert_eq!(
            OtlpConfig::from_env_values(Some("   \t\n  "), Some("custom-svc"))
                .expect("whitespace endpoint is disabled"),
            None
        );
    }

    #[test]
    fn otlp_config_parses_valid_endpoint_and_service_name_default() {
        let default_svc = OtlpConfig::from_env_values(Some("  http://127.0.0.1:4318  "), None)
            .expect("valid loopback endpoint")
            .expect("config is enabled");
        assert_eq!(default_svc.endpoint(), "http://127.0.0.1:4318/v1/traces");
        assert_eq!(
            default_svc.redacted_endpoint(),
            "http://127.0.0.1:4318/v1/traces"
        );
        assert_eq!(default_svc.service_name(), DEFAULT_SERVICE_NAME);

        let custom_svc = OtlpConfig::from_env_values(
            Some("https://otel.example.com:4318/v1/traces"),
            Some("  ferriscd-prod  "),
        )
        .expect("valid https endpoint")
        .expect("config is enabled");
        assert_eq!(
            custom_svc.endpoint(),
            "https://otel.example.com:4318/v1/traces"
        );
        assert_eq!(custom_svc.service_name(), "ferriscd-prod");
    }

    #[test]
    fn resolve_traces_endpoint_normalizes_paths_without_corrupting_query_or_userinfo() {
        let cases = [
            ("http://otel:4318", "http://otel:4318/v1/traces"),
            ("http://otel:4318/", "http://otel:4318/v1/traces"),
            (
                "http://otel:4318/prefix",
                "http://otel:4318/prefix/v1/traces",
            ),
            (
                "http://otel:4318/prefix/",
                "http://otel:4318/prefix/v1/traces",
            ),
            ("http://otel:4318/v1/traces", "http://otel:4318/v1/traces"),
            ("http://otel:4318/v1/traces/", "http://otel:4318/v1/traces"),
            (
                "http://otel:4318/prefix/v1/traces",
                "http://otel:4318/prefix/v1/traces",
            ),
            (
                "http://user:pw@otel:4318?token=abc",
                "http://user:pw@otel:4318/v1/traces?token=abc",
            ),
            (
                "http://user:pw@otel:4318/#frag",
                "http://user:pw@otel:4318/v1/traces#frag",
            ),
            (
                "http://user:pw@otel:4318/v1/traces?token=abc#frag",
                "http://user:pw@otel:4318/v1/traces?token=abc#frag",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(
                resolve_traces_endpoint(input),
                expected,
                "normalization mismatch for {input:?}"
            );
        }

        let config = OtlpConfig::from_env_values(Some("http://user:pw@otel:4318?token=abc"), None)
            .expect("valid URL with userinfo and query")
            .expect("enabled");
        assert_eq!(
            config.endpoint(),
            "http://user:pw@otel:4318/v1/traces?token=abc"
        );
        assert_eq!(
            config.redacted_endpoint(),
            "http://***@otel:4318/v1/traces?<redacted>"
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("user"), "{debug}");
        assert!(!debug.contains("pw"), "{debug}");
        assert!(!debug.contains("token=abc"), "{debug}");
        assert!(
            debug.contains("http://***@otel:4318/v1/traces?<redacted>"),
            "{debug}"
        );
    }

    #[test]
    fn invalid_endpoint_urls_return_typed_errors() {
        for bad in [
            "not-a-url",
            "ftp://otel.example.com:4318",
            "grpc://otel.example.com:4317",
            "http://",
            "://missing-scheme",
            "http://bad host:4318",
            "http://127.0.0.1:4318/v1\ntraces",
        ] {
            let err = OtlpConfig::from_env_values(Some(bad), None)
                .expect_err(&format!("{bad:?} must be rejected"));
            assert!(
                matches!(err, TelemetryError::InvalidEndpoint { .. }),
                "expected InvalidEndpoint for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn credentials_in_endpoint_urls_are_redacted_in_debug_and_errors() {
        // Valid URL with embedded userinfo and query token: Debug must never echo them.
        let config = OtlpConfig::from_env_values(
            Some("https://ingest:super-secret-pass@otel.example.com:4318/v1/traces?api_key=tok123#frag456"),
            None,
        )
        .expect("valid URL with credentials")
        .expect("enabled");
        assert_eq!(
            config.redacted_endpoint(),
            "https://***@otel.example.com:4318/v1/traces?<redacted>#<redacted>"
        );
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super-secret-pass"),
            "{debug_output}"
        );
        assert!(!debug_output.contains("ingest"), "{debug_output}");
        assert!(!debug_output.contains("tok123"), "{debug_output}");
        assert!(!debug_output.contains("frag456"), "{debug_output}");
        assert!(
            debug_output.contains("https://***@otel.example.com:4318/v1/traces"),
            "{debug_output}"
        );

        // Invalid URL with embedded credentials: Display and Debug of TelemetryError must redact.
        let err = OtlpConfig::from_env_values(
            Some("ftp://alice:my-secret-token@otel.example.com:4318/v1/traces?key=leakme"),
            None,
        )
        .expect_err("ftp scheme must be rejected");
        let display = err.to_string();
        let debug = format!("{err:?}");
        for rendered in [&display, &debug] {
            assert!(!rendered.contains("my-secret-token"), "{rendered}");
            assert!(!rendered.contains("alice"), "{rendered}");
            assert!(!rendered.contains("leakme"), "{rendered}");
            assert!(rendered.contains("***@otel.example.com:4318"), "{rendered}");
        }

        // Malformed URI with spaces AND credentials must still redact before failing.
        let malformed = OtlpConfig::from_env_values(
            Some("http://bob:topsecret@bad host:4318?token=nope"),
            None,
        )
        .expect_err("malformed URI must be rejected");
        let display = malformed.to_string();
        assert!(!display.contains("topsecret"), "{display}");
        assert!(!display.contains("bob"), "{display}");
        assert!(!display.contains("nope"), "{display}");
    }

    #[test]
    fn exporter_build_and_shutdown_errors_redact_embedded_urls_and_credentials() {
        let config = OtlpConfig::from_env_values(
            Some("https://ingest:primary-secret@otel.example.com:4318?api_key=primary_tok"),
            None,
        )
        .expect("valid URL")
        .expect("enabled");

        let raw_transport_err = concat!(
            "error sending request for url (https://ingest:primary-secret@otel.example.com:4318/v1/traces?api_key=primary_tok): ",
            "upstream proxy http://proxy-user:proxy-pass@proxy.internal:8080/relay?token=proxy_tok#sec rejected"
        );

        let build_err = TelemetryError::exporter_build(&config, raw_transport_err);
        let shutdown_err = TelemetryError::shutdown(
            raw_transport_err,
            Some(config.endpoint()),
            Some(config.redacted_endpoint()),
        );
        // Even without configured endpoint hints, arbitrary embedded URLs must still be redacted.
        let shutdown_err_no_hint = TelemetryError::shutdown(raw_transport_err, None, None);

        for err in [&build_err, &shutdown_err, &shutdown_err_no_hint] {
            for rendered in [err.to_string(), format!("{err:?}")] {
                assert!(!rendered.contains("primary-secret"), "{rendered}");
                assert!(!rendered.contains("ingest"), "{rendered}");
                assert!(!rendered.contains("primary_tok"), "{rendered}");
                assert!(!rendered.contains("proxy-user"), "{rendered}");
                assert!(!rendered.contains("proxy-pass"), "{rendered}");
                assert!(!rendered.contains("proxy_tok"), "{rendered}");
                assert!(!rendered.contains("#sec"), "{rendered}");
                assert!(
                    rendered.contains("https://***@otel.example.com:4318/v1/traces?<redacted>"),
                    "{rendered}"
                );
                assert!(
                    rendered.contains("http://***@proxy.internal:8080/relay?<redacted>#<redacted>"),
                    "{rendered}"
                );
            }
        }
    }

    #[test]
    fn otlp_exporter_and_tracer_provider_initialize_and_shut_down_cleanly() {
        let config = OtlpConfig::from_env_values(Some("http://127.0.0.1:4318"), None)
            .expect("valid loopback endpoint")
            .expect("enabled");
        let provider = build_tracer_provider(&config)
            .expect("OTLP HTTP exporter and SdkTracerProvider must initialize cleanly");
        let guard = TelemetryGuard::with_provider(LogFormat::Pretty, &config, provider);
        assert!(guard.otlp_enabled());
        assert_eq!(
            guard.redacted_endpoint(),
            Some("http://127.0.0.1:4318/v1/traces")
        );
        assert_eq!(guard.service_name(), Some(DEFAULT_SERVICE_NAME));
        // Shutdown must be clean and idempotent.
        guard.shutdown().expect("first shutdown succeeds");
        guard
            .shutdown()
            .expect("second shutdown is a clean idempotent no-op");
    }

    #[tokio::test]
    async fn otlp_guard_shuts_down_cleanly_inside_tokio_runtime() {
        let config = OtlpConfig::from_env_values(
            Some("http://user:secret@127.0.0.1:4318"),
            Some("ferriscd-test"),
        )
        .expect("valid endpoint")
        .expect("enabled");
        let provider = build_tracer_provider(&config).expect("provider builds inside tokio");
        let guard = TelemetryGuard::with_provider(LogFormat::Json, &config, provider);
        let debug = format!("{guard:?}");
        assert!(!debug.contains("secret"), "{debug}");
        assert!(
            debug.contains("http://***@127.0.0.1:4318/v1/traces"),
            "{debug}"
        );
        assert!(debug.contains("ferriscd-test"), "{debug}");
        guard
            .shutdown_async()
            .await
            .expect("async shutdown completes without blocking tokio worker");
    }

    #[tokio::test]
    async fn otlp_exporter_posts_to_v1_traces_for_base_endpoint() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        use opentelemetry::trace::{Span as _, Tracer as _};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback OTLP listener");
        let addr = listener.local_addr().expect("listener local addr");
        let (tx, rx) = mpsc::channel::<String>();

        let server = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut raw = Vec::new();
            let mut chunk = [0u8; 2048];
            let mut header_end = None;
            let mut content_length = 0usize;

            while raw.len() < 65_536 {
                let Ok(n) = stream.read(&mut chunk) else {
                    break;
                };
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
                if header_end.is_none()
                    && let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let end = pos + 4;
                    header_end = Some(end);
                    let headers = String::from_utf8_lossy(&raw[..end]);
                    for line in headers.lines() {
                        if let Some((name, val)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            content_length = val.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if let Some(end) = header_end
                    && raw.len() >= end + content_length
                {
                    break;
                }
            }

            let request = String::from_utf8_lossy(&raw).into_owned();
            let _ = tx.send(request);
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        // Base URL intentionally omits `/v1/traces`; `OtlpConfig` must normalize it.
        let base_url = format!("http://{addr}");
        let config = OtlpConfig::from_env_values(Some(&base_url), Some("ferriscd-wire-test"))
            .expect("valid loopback endpoint")
            .expect("enabled");
        assert_eq!(config.endpoint(), format!("{base_url}/v1/traces"));

        let provider = build_tracer_provider(&config).expect("provider builds");
        let tracer = provider.tracer(TRACER_SCOPE);
        let mut span = tracer.start("reconcile-wire-test");
        span.end();

        let guard = TelemetryGuard::with_provider(LogFormat::Json, &config, provider);
        guard
            .shutdown_async()
            .await
            .expect("shutdown flushes exported span to mock collector");

        let request = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("mock collector must receive OTLP HTTP request");
        let request_line = request.lines().next().unwrap_or("");
        assert!(
            request_line.starts_with("POST /v1/traces "),
            "expected `POST /v1/traces ...`, got request line: {request_line:?}"
        );

        server.join().expect("mock collector thread exited cleanly");
    }
}

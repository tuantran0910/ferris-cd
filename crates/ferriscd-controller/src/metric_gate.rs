//! Metric-gated wave promotion (`T20.3`).
//!
//! A canary that is *healthy* is not a canary that is *good*. This module is the second half of
//! progressive delivery: after a sync wave has converged, an opt-in
//! [`MetricGate`](ferriscd_crd::MetricGate) in `spec.syncPolicy.metricGates` can hold promotion to
//! the next wave until a Prometheus query has satisfied its `successCondition` `count` times in a
//! row — or abort the rollout when it does not.
//!
//! # Re-entrancy: no worker ever sleeps on a bake
//!
//! The whole gate is a **pure fold** over state that already lives in `/status`:
//!
//! ```text
//! plan(spec, persisted, now)   -> Sample | Hold | Passed | Failed   (no I/O at all)
//!        |
//!        +-- Sample: the caller issues ONE bounded query and calls
//!            record(spec, state, observation, now) -> Hold | Passed | Failed
//! ```
//!
//! [`plan`] and [`record`] read no clock, perform no I/O, and never sleep; the caller passes `now`.
//! The progress they produce ([`MetricGateState`](ferriscd_crd::status::MetricGateState)) is
//! persisted into `status.operationState.metricGate` **before** the pass requeues, which is what
//! makes a controller restart mid-bake resume from `consecutiveSuccesses` instead of starting over —
//! and what keeps the reconcile worker free while the bake runs.
//!
//! `intervalSeconds` is a *requeue hint*, never a `sleep`: [`GateStep::Hold`] carries the remaining
//! time as data, exactly like the wave state machine's own requeue hints (`T10.1`).
//!
//! # SSRF: tenant manifests never name an endpoint
//!
//! The `provider` field of a gate is a **key** of `ConfigMap/ferriscd-metrics-providers-cm` in the
//! control-plane namespace, resolved here through [`MetricProviderSource`]. `ApplicationSpec`
//! cannot express a URL at all — [`ApplicationSpec::validate`](ferriscd_crd::ApplicationSpec) even
//! rejects a value shaped like one — so a tenant cannot make the controller dial anything. A gate
//! naming a provider that is not configured is a **terminal** refusal
//! ([`resolve_provider`]), never a silent skip: a gate that cannot be sampled must not let a rollout
//! proceed.
//!
//! # Failure classification
//!
//! | Observation | Verdict | Why |
//! |---|---|---|
//! | condition satisfied, fewer than `count` samples | `Hold` | keep sampling |
//! | condition satisfied `count` times | `Passed` | promotion may continue |
//! | condition **not** satisfied | `Failed` → `failureAction` | a single breach aborts: this is a regression, not noise |
//! | query timed out / transport error / `5xx` (retryable) | `Hold`, then `Failed` **as `Pause`** after [`MAX_GATE_QUERY_ERRORS`] | a flaky provider must not block forever, and must not pass either |
//! | `4xx`, unparseable body, unsupported `resultType`, unparsable condition (terminal) | `Failed` **as `Pause`** | retrying cannot fix it, and it is not evidence of a regression |
//!
//! Only a **measurement breach** honours `failureAction` (`T20.3` finding M4). A gate that could not
//! be *evaluated* — a `successCondition` this build cannot parse, a `4xx` from the provider, a body
//! that is not the Prometheus envelope, an unsupported `resultType` — says nothing about whether the
//! canary regressed, so `failureAction: Rollback` must not revert a perfectly good deployment because
//! somebody mistyped a condition. Those verdicts always pause, and the decided action is persisted in
//! [`MetricGateState::failure_action`] so a resumed `Failed` state stays honest.
//!
//! # Remediation passes are never gated
//!
//! `failureAction: Rollback` writes the `ferriscd.io/operation` request and leaves the *existing*
//! `T10.5` implementation to perform it. The next pass therefore renders the **pinned historical
//! revision**, which is a remediation, not a promotion forward: sampling a gate on it would re-run
//! the same query against the same bad dashboard, fail again, and overwrite the request the rollback
//! path is trying to honour — an unbounded oscillation in which the remediation never lands
//! (`T20.3` finding C1). The pass carries `gate_suppressed` for exactly the passes that render a
//! pinned revision, mirroring the rule that a *failing* wave is never gated.
//!
//! Every query is bounded: one request per pass, [`METRIC_GATE_QUERY_TIMEOUT`] per request, the
//! PromQL string is length-capped by the CRD validation, and the response body is accumulated under
//! [`MAX_METRIC_GATE_RESPONSE_BYTES`] — so a hostile or overloaded metrics backend cannot make a
//! reconcile worker allocate or wait without bound.
//!
//! # What is never echoed
//!
//! Transport failures are classified, never formatted: `reqwest::Error`'s `Display` contains the
//! request URL, and that URL may carry credentials, so [`MetricQueryError`] carries only a class.
//! Everything that reaches `/status` (`MetricGateState::message`) is built from the provider *name*,
//! the operator's own condition text, a bounded sample summary, and a bounded error class.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use ferriscd_crd::status::{MAX_STATUS_MESSAGE_CHARS, MetricGatePhase, MetricGateState};
use ferriscd_crd::{CONTROL_PLANE_NAMESPACE, MetricGate, MetricGateFailureAction};
use futures::StreamExt as _;
use futures::future::BoxFuture;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::Api;
use serde::Deserialize;
use tracing::debug;

use crate::reconcile::ReconcileError;

/// `ConfigMap` a cluster administrator configures Prometheus providers in (`T20.3`).
///
/// Read from the control-plane namespace only, one scoped `GET` per reconcile that needs it — never
/// a cluster-wide informer, and never from an `Application`'s own namespace.
pub const METRICS_PROVIDERS_CONFIGMAP_NAME: &str = "ferriscd-metrics-providers-cm";

/// Hard timeout of one Prometheus query.
///
/// The roadmap's `5 s`: an unresponsive metrics backend must cost at most this much of one
/// reconcile, and the gate must never turn Prometheus latency into controller latency.
pub const METRIC_GATE_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard cap on the Prometheus response body the controller will read.
pub const MAX_METRIC_GATE_RESPONSE_BYTES: usize = 1024 * 1024;

/// How many consecutive **retryable** query failures fail the gate closed.
///
/// A provider that cannot be reached must not hold a rollout open forever, and it must not promote
/// either: after this many consecutive failures the gate abstains as a **breach**, which is the safe
/// direction.
pub const MAX_GATE_QUERY_ERRORS: u32 = 3;

/// How many samples one Prometheus response may carry.
///
/// A gate query is meant to return one (or a handful of) series. A response with hundreds is either
/// a mistake or an attempt to make the controller parse an unbounded document, so it is refused as
/// a terminal error instead of being truncated (truncating would change `len(result)`).
pub const MAX_PROMETHEUS_SAMPLES: usize = 32;

/// Prometheus instant-query endpoint appended to a provider's base URL.
pub const PROMETHEUS_QUERY_PATH: &str = "/api/v1/query";

/// How many hexadecimal characters of the gate fingerprint are kept in `/status`.
///
/// 32 hex characters = 128 bits = the first half of a SHA-256 digest: a 2^64 birthday bound, which is
/// unreachable for the handful of gate revisions one `Application` can ever carry, in 32 bytes of the
/// budgeted `/status` (trap T9).
pub const FINGERPRINT_HEX_CHARS: usize = 32;

/// Why one metric query produced no usable measurement.
///
/// Carries a **class**, never a rendered `reqwest` error: that `Display` contains the request URL,
/// which is exactly the value the SSRF guard exists to keep out of `/status` and logs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetricQueryError {
    /// The request exceeded [`METRIC_GATE_QUERY_TIMEOUT`] (retryable).
    #[error("the query timed out")]
    Timeout,
    /// The connection could not be established (retryable: the provider may be restarting).
    #[error("the provider could not be reached")]
    Connect,
    /// Any other transport-level failure (retryable; deliberately carries no message).
    #[error("the query failed in transport")]
    Transport,
    /// The provider answered with a non-2xx status (`5xx` retryable, `4xx` terminal).
    #[error("the provider answered HTTP {code}")]
    Status {
        /// HTTP status code.
        code: u16,
    },
    /// The provider answered 2xx with a body this controller cannot use (terminal).
    #[error("the provider answered with an unusable body: {reason}")]
    Body {
        /// What is wrong, bounded — never a URL and never the whole body.
        reason: String,
    },
}

impl MetricQueryError {
    /// Whether retrying the same query could produce a different answer.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout | Self::Connect | Self::Transport => true,
            // A 5xx is the provider's problem and may pass; a 4xx is our query being wrong.
            Self::Status { code } => *code >= 500,
            Self::Body { .. } => false,
        }
    }
}

/// The measurements one Prometheus query returned, in response order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PrometheusQueryResponse {
    samples: Vec<f64>,
}

impl PrometheusQueryResponse {
    /// Builds a response from the parsed sample values.
    #[must_use]
    pub fn new(samples: Vec<f64>) -> Self {
        Self { samples }
    }

    /// The sample values, in response order.
    #[must_use]
    pub fn samples(&self) -> &[f64] {
        &self.samples
    }

    /// The one bounded sentence a `/status` message may quote about this response.
    #[must_use]
    pub fn describe(&self) -> String {
        match self.samples.first() {
            Some(value) => format!("{} sample(s), first = {value}", self.samples.len()),
            None => "no samples".to_owned(),
        }
    }
}

/// One Prometheus query issued by the gate.
#[derive(Debug, Clone, Copy)]
pub struct MetricQueryRequest<'a> {
    /// Provider base URL, resolved from the admin-configured `ConfigMap`.
    pub url: &'a str,
    /// The operator's PromQL query (already length-capped by CRD validation).
    pub query: &'a str,
    /// Per-request timeout ([`METRIC_GATE_QUERY_TIMEOUT`] in production).
    pub timeout: Duration,
}

/// Sends one metrics query. Abstracted so the gate is testable without a metrics backend.
pub trait MetricQueryTransport: Send + Sync + 'static {
    /// Runs one instant query against the provider.
    fn query<'a>(
        &'a self,
        request: MetricQueryRequest<'a>,
    ) -> BoxFuture<'a, Result<PrometheusQueryResponse, MetricQueryError>>;
}

/// Production [`MetricQueryTransport`] over `reqwest`.
///
/// Deliberately **not** HTTPS-only and **not** SSRF-filtered: the URL comes from a `ConfigMap` a
/// cluster administrator authors in the control-plane namespace, and an in-cluster Prometheus is
/// routinely plaintext (`http://prometheus.monitoring.svc:9090`). Redirects are refused anyway, so a
/// hijacked provider cannot bounce the controller somewhere else.
pub struct ReqwestMetricTransport {
    client: reqwest::Client,
    timeout: Duration,
}

impl fmt::Debug for ReqwestMetricTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestMetricTransport")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl ReqwestMetricTransport {
    /// Builds the production client: bounded timeout, no redirects, no retries (a gate samples on
    /// its own schedule, so a retried request would double the query load).
    ///
    /// # Errors
    ///
    /// [`MetricQueryError::Transport`] when the TLS/HTTP stack cannot be initialized.
    pub fn build() -> Result<Self, MetricQueryError> {
        let client = reqwest::Client::builder()
            .timeout(METRIC_GATE_QUERY_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| MetricQueryError::Transport)?;
        Ok(Self {
            client,
            timeout: METRIC_GATE_QUERY_TIMEOUT,
        })
    }

    /// The per-request timeout this transport enforces.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl MetricQueryTransport for ReqwestMetricTransport {
    fn query<'a>(
        &'a self,
        request: MetricQueryRequest<'a>,
    ) -> BoxFuture<'a, Result<PrometheusQueryResponse, MetricQueryError>> {
        Box::pin(async move {
            // A `GET` with the query as one percent-encoded parameter: the CRD caps the query at
            // 2048 characters, so the request URI stays bounded, and no extra `reqwest` feature
            // (which would add a dependency) is needed to encode a form body.
            let url = format!(
                "{}{PROMETHEUS_QUERY_PATH}?query={}",
                request.url.trim_end_matches('/'),
                percent_encode(request.query)
            );
            let response = self
                .client
                .get(&url)
                .timeout(request.timeout)
                .send()
                .await
                .map_err(classify_transport_error)?;
            let status = response.status();
            if !status.is_success() {
                return Err(MetricQueryError::Status {
                    code: status.as_u16(),
                });
            }
            if let Some(length) = response.content_length()
                && length > MAX_METRIC_GATE_RESPONSE_BYTES as u64
            {
                return Err(MetricQueryError::Body {
                    reason: format!(
                        "response announces {length} bytes, over the {MAX_METRIC_GATE_RESPONSE_BYTES}-byte cap"
                    ),
                });
            }
            // Streamed rather than `bytes()`: a provider that answers without `Content-Length`
            // (chunked) would otherwise let the controller buffer an unbounded document.
            let mut stream = response.bytes_stream();
            let mut body: Vec<u8> = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(classify_transport_error)?;
                if body.len() + chunk.len() > MAX_METRIC_GATE_RESPONSE_BYTES {
                    return Err(MetricQueryError::Body {
                        reason: format!(
                            "response exceeds the {MAX_METRIC_GATE_RESPONSE_BYTES}-byte cap"
                        ),
                    });
                }
                body.extend_from_slice(&chunk);
            }
            let body = std::str::from_utf8(&body).map_err(|_| MetricQueryError::Body {
                reason: "response is not valid UTF-8".to_owned(),
            })?;
            parse_prometheus_response(body)
        })
    }
}

/// Classifies a `reqwest` failure **without** formatting it (`T20.3` secret hygiene).
fn classify_transport_error(error: reqwest::Error) -> MetricQueryError {
    if error.is_timeout() {
        MetricQueryError::Timeout
    } else if error.is_connect() {
        MetricQueryError::Connect
    } else {
        MetricQueryError::Transport
    }
}

/// Percent-encodes a PromQL query for a request URI.
///
/// Only the RFC 3986 unreserved set is passed through; everything else (spaces, `"`, `{`, `}`,
/// `+`, `&`, `=`) is escaped, so a query can never inject a second request parameter.
fn percent_encode(query: &str) -> String {
    let mut encoded = String::with_capacity(query.len());
    for byte in query.bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

/// Parses a Prometheus `/api/v1/query` response into its sample values.
///
/// Supports the two result types an instant query can return (`vector`, `scalar`). Anything else —
/// including a `success:false` envelope — is a terminal [`MetricQueryError::Body`]: a gate must never
/// guess a measurement, and `success:false` is a query the operator has to fix.
///
/// The provider's own `error`/`warnings` text is never echoed (it can quote the query verbatim);
/// the message names only the shape of the problem.
///
/// # Errors
///
/// [`MetricQueryError::Body`] for malformed JSON, a non-`success` status, an unsupported result type,
/// a sample count over [`MAX_PROMETHEUS_SAMPLES`], or a non-numeric sample value.
pub fn parse_prometheus_response(body: &str) -> Result<PrometheusQueryResponse, MetricQueryError> {
    #[derive(Deserialize)]
    struct Envelope {
        status: String,
        #[serde(default)]
        data: Option<Data>,
    }

    #[derive(Deserialize)]
    struct Data {
        #[serde(rename = "resultType")]
        result_type: String,
        #[serde(default)]
        result: serde_json::Value,
    }

    let envelope: Envelope = serde_json::from_str(body).map_err(|_| MetricQueryError::Body {
        reason: "response is not the Prometheus query JSON envelope".to_owned(),
    })?;
    if !envelope.status.eq_ignore_ascii_case("success") {
        return Err(MetricQueryError::Body {
            reason: format!("query status is {:?}", clip(&envelope.status, 32)),
        });
    }
    let data = envelope.data.ok_or_else(|| MetricQueryError::Body {
        reason: "response carries no data block".to_owned(),
    })?;

    match data.result_type.as_str() {
        "vector" => {
            let series = data
                .result
                .as_array()
                .ok_or_else(|| MetricQueryError::Body {
                    reason: "a vector result is not an array".to_owned(),
                })?;
            if series.len() > MAX_PROMETHEUS_SAMPLES {
                return Err(MetricQueryError::Body {
                    reason: format!(
                        "the query returned {} series, over the {MAX_PROMETHEUS_SAMPLES}-series cap",
                        series.len()
                    ),
                });
            }
            let mut samples = Vec::with_capacity(series.len());
            for entry in series {
                // A vector entry is `{"metric": {...}, "value": [<ts>, "<value>"]}`.
                let value = entry.get("value").ok_or_else(|| MetricQueryError::Body {
                    reason: "a vector entry carries no value".to_owned(),
                })?;
                samples.push(parse_sample_value(value)?);
            }
            Ok(PrometheusQueryResponse::new(samples))
        }
        "scalar" => Ok(PrometheusQueryResponse::new(vec![parse_sample_value(
            &data.result,
        )?])),
        other => Err(MetricQueryError::Body {
            reason: format!(
                "resultType {:?} is not supported (expected vector or scalar)",
                clip(other, 32)
            ),
        }),
    }
}

/// Parses a `[<timestamp>, "<value>"]` pair into the sample's `f64`.
fn parse_sample_value(value: &serde_json::Value) -> Result<f64, MetricQueryError> {
    let text = value
        .as_array()
        .and_then(|pair| pair.get(1))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MetricQueryError::Body {
            reason: "a sample is not a [timestamp, value] pair".to_owned(),
        })?;
    parse_sample_text(text)
}

/// Parses Prometheus' float spellings (`"NaN"`, `"+Inf"`, `"-Inf"`, decimal, exponent).
fn parse_sample_text(text: &str) -> Result<f64, MetricQueryError> {
    let text = text.trim();
    let parsed = match text {
        "NaN" => f64::NAN,
        "+Inf" | "Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        other => other.parse::<f64>().map_err(|_| MetricQueryError::Body {
            reason: "a sample value is not a number".to_owned(),
        })?,
    };
    Ok(parsed)
}

/// Comparison operators a `successCondition` may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `==`
    Eq,
    /// `!=`
    Ne,
}

impl Comparison {
    /// Applies the operator.
    ///
    /// A non-finite measurement (`NaN`, `+Inf`) or threshold never satisfies anything: `NaN` is what
    /// Prometheus returns for an empty-but-valid expression, and "no data" must never promote a
    /// rollout. (`!=` would otherwise be satisfied by `NaN`.)
    #[must_use]
    pub fn matches(self, left: f64, right: f64) -> bool {
        if !left.is_finite() || !right.is_finite() {
            return false;
        }
        match self {
            Self::Lt => left < right,
            Self::Le => left <= right,
            Self::Gt => left > right,
            Self::Ge => left >= right,
            Self::Eq => approx_eq(left, right),
            Self::Ne => !approx_eq(left, right),
        }
    }

    /// The operator's source spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Eq => "==",
            Self::Ne => "!=",
        }
    }

    /// Parses the operator that starts `text`, returning it and the remaining (trimmed) text.
    fn parse_prefix(text: &str) -> Option<(Self, &str)> {
        // Two-character operators first, or `<=` would parse as `<` and leave `= 0.05`.
        for (token, comparison) in [
            ("<=", Self::Le),
            (">=", Self::Ge),
            ("==", Self::Eq),
            ("!=", Self::Ne),
            ("<", Self::Lt),
            (">", Self::Gt),
        ] {
            if let Some(rest) = text.strip_prefix(token) {
                return Some((comparison, rest.trim_start()));
            }
        }
        None
    }
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether two finite measurements are the same number, up to IEEE-754 rounding.
///
/// `==`/`!=` compare decimal literals from a manifest (`0.001`) against floating-point samples that
/// Prometheus computed, so an absolute `f64::EPSILON` comparison is the wrong scale at both ends of
/// the range (`T20.3` nit): `EPSILON` is ~2.2e-16, which is far *tighter* than a double can hold for
/// a value like `1e12` (where the spacing is ~1e-4) and far *looser* than necessary for one like
/// `1e-9` (where distinct doubles differ by ~1e-25). A relative tolerance scaled by the magnitude —
/// floored at 1.0 so it stays an absolute `EPSILON` near zero — is exact at both ends.
fn approx_eq(left: f64, right: f64) -> bool {
    let tolerance = f64::EPSILON * left.abs().max(right.abs()).max(1.0);
    (left - right).abs() <= tolerance
}

/// A parsed `successCondition`.
///
/// The grammar is deliberately tiny — there is no expression language and no dependency:
///
/// ```text
/// result[<index>] <op> <number>      e.g. result[0] <= 0.01
/// len(result)      <op> <number>     e.g. len(result) > 0
/// ```
///
/// Anything else is a terminal configuration error ([`ConditionError`]), which the gate fails closed
/// on: a condition that cannot be understood must never be treated as satisfied.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MetricCondition {
    /// `result[index] <op> value`.
    Sample {
        /// Zero-based index into the instant vector.
        index: usize,
        /// Operator.
        comparison: Comparison,
        /// Threshold.
        value: f64,
    },
    /// `len(result) <op> value`.
    Len {
        /// Operator.
        comparison: Comparison,
        /// Threshold.
        value: f64,
    },
}

/// Why a `successCondition` could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "successCondition {condition:?} is not a supported comparison: expected \
     `result[<index>] <op> <number>` or `len(result) <op> <number>` with `<op>` one of \
     `< <= > >= == !=`"
)]
pub struct ConditionError {
    /// The offending condition text (bounded).
    pub condition: String,
}

impl MetricCondition {
    /// Parses a `successCondition`.
    ///
    /// # Errors
    ///
    /// [`ConditionError`] for anything outside the documented grammar.
    pub fn parse(condition: &str) -> Result<Self, ConditionError> {
        let reject = || ConditionError {
            condition: clip(condition, 128).to_owned(),
        };
        let text = condition.trim();

        if let Some(rest) = text.strip_prefix("result[") {
            let (index, rest) = rest.split_once(']').ok_or_else(reject)?;
            let index: usize = index.trim().parse().map_err(|_| reject())?;
            if index >= MAX_PROMETHEUS_SAMPLES {
                return Err(reject());
            }
            let (comparison, rest) =
                Comparison::parse_prefix(rest.trim_start()).ok_or_else(reject)?;
            let value: f64 = rest.parse().map_err(|_| reject())?;
            return Ok(Self::Sample {
                index,
                comparison,
                value,
            });
        }

        if let Some(rest) = text.strip_prefix("len(result)") {
            let (comparison, rest) =
                Comparison::parse_prefix(rest.trim_start()).ok_or_else(reject)?;
            let value: f64 = rest.parse().map_err(|_| reject())?;
            return Ok(Self::Len { comparison, value });
        }

        Err(reject())
    }

    /// The comparison this condition performs.
    #[must_use]
    pub const fn comparison(&self) -> Comparison {
        match self {
            Self::Sample { comparison, .. } | Self::Len { comparison, .. } => *comparison,
        }
    }

    /// Whether `response` satisfies the condition.
    ///
    /// A missing sample never satisfies a `result[i]` condition (an empty vector is "no data", which
    /// must fail closed), and a non-finite value never satisfies anything.
    #[must_use]
    pub fn is_satisfied(&self, response: &PrometheusQueryResponse) -> bool {
        match self {
            Self::Sample {
                index,
                comparison,
                value,
            } => response
                .samples
                .get(*index)
                .is_some_and(|sample| comparison.matches(*sample, *value)),
            Self::Len { comparison, value } => {
                comparison.matches(response.samples.len() as f64, *value)
            }
        }
    }
}

/// One Prometheus provider, as configured by a cluster administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricProvider {
    url: String,
}

impl MetricProvider {
    /// Builds a provider from its validated base URL.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// The base URL (`/api/v1/query` is appended by the transport).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// The admin-configured provider allowlist (`ConfigMap/ferriscd-metrics-providers-cm`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricProviderSet {
    providers: BTreeMap<String, MetricProvider>,
}

impl MetricProviderSet {
    /// No providers: every gate is refused.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parses the `data` of `ConfigMap/ferriscd-metrics-providers-cm`.
    ///
    /// One entry per provider, keyed by the name a gate references:
    ///
    /// ```yaml
    /// prod:
    ///   url: http://prometheus.monitoring.svc:9090
    /// ```
    ///
    /// Pure: the caller does the API read. Entries are parsed in key order (deterministic).
    ///
    /// # Errors
    ///
    /// [`MetricProviderError`] when an entry is not a provider document, has no usable URL, embeds
    /// credentials, or uses a scheme other than `http`/`https`. The caller must fail closed: a
    /// `ConfigMap` that cannot be parsed is never "no providers".
    pub fn from_configmap_data(
        configmap: &str,
        data: &BTreeMap<String, String>,
    ) -> Result<Self, MetricProviderError> {
        #[derive(Deserialize)]
        struct Document {
            url: String,
        }

        let mut providers = BTreeMap::new();
        for (name, value) in data {
            let name_trimmed = name.trim();
            if name_trimmed.is_empty() {
                return Err(MetricProviderError::Invalid {
                    configmap: configmap.to_owned(),
                    provider: "<empty key>".to_owned(),
                    reason: "a provider name must not be empty".to_owned(),
                });
            }
            let document: Document =
                ferriscd_engine::manifest::parse_document(value).map_err(|_| {
                    MetricProviderError::Invalid {
                        configmap: configmap.to_owned(),
                        provider: name_trimmed.to_owned(),
                        reason: "the entry is not a `url: <endpoint>` document".to_owned(),
                    }
                })?;
            validate_provider_url(configmap, name_trimmed, &document.url)?;
            providers.insert(
                name_trimmed.to_owned(),
                MetricProvider::new(document.url.trim()),
            );
        }
        Ok(Self { providers })
    }

    /// The provider configured under `name`, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&MetricProvider> {
        self.providers.get(name)
    }

    /// Number of configured providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether no provider is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// The configured provider names, in key order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.providers.keys().map(String::as_str)
    }
}

/// Validates one provider URL.
///
/// The URL is admin-authored, so this is a *hygiene* check rather than a security boundary; the
/// boundary is that a tenant cannot supply it at all. Credentials are refused because they would be
/// echoed by any transport error and there is no supported way to rotate them out of a `ConfigMap`.
///
/// It also refuses the addresses nothing legitimate is ever behind (`T20.3` nit, mirroring the
/// `ferriscd-server` webhook guard): loopback, the unspecified address, and the IPv4 link-local range
/// that hosts the cloud metadata endpoint. A "Prometheus" on `127.0.0.1:9090` is either a typo that
/// silently queries the controller's own sidecar, or an admin (or a compromised `ConfigMap` write)
/// turning the metrics client into a request forwarder onto `169.254.169.254`. A provider is a
/// cluster service DNS name in every supported deployment.
fn validate_provider_url(
    configmap: &str,
    provider: &str,
    url: &str,
) -> Result<(), MetricProviderError> {
    let reject = |reason: &str| MetricProviderError::Invalid {
        configmap: configmap.to_owned(),
        provider: provider.to_owned(),
        reason: reason.to_owned(),
    };
    let url = url.trim();
    if url.is_empty() {
        return Err(reject("url must not be empty"));
    }
    let authority = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        return Err(reject("url must start with http:// or https://"));
    };
    let authority = authority.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err(reject("url has no host"));
    }
    if authority.contains('@') {
        return Err(reject(
            "url must not embed credentials: a ConfigMap is not a Secret, and the value would be \
             echoed by transport errors",
        ));
    }
    if let Some(reason) = denied_host(authority) {
        return Err(reject(&format!(
            "url must name the provider's in-cluster service; a {reason} address is refused \
             (either a typo pointing the query at the controller's own pod, or a request forwarder \
             onto the cloud metadata endpoint)"
        )));
    }
    if url.contains('?') || url.contains('#') {
        // The controller appends `/api/v1/query?query=<promql>` to this value, so a query string or
        // fragment in the base URL would silently drop or mangle the gate's own query.
        return Err(reject(
            "url must be a base endpoint without a query string or fragment (the controller \
             appends /api/v1/query?query=...)",
        ));
    }
    Ok(())
}

/// Why `authority` is an address a metrics provider must never point at, if it is one.
///
/// Returns `None` for everything a real in-cluster provider looks like: a DNS name
/// (`prometheus.monitoring.svc`), an IPv6 service VIP, or a routable IPv4 address.
fn denied_host(authority: &str) -> Option<&'static str> {
    // Strip an IPv6 literal's brackets and any `:port`, without ever failing on a malformed value
    // (a `ConfigMap` entry is untrusted input for the purposes of this function).
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    let lower = host.trim().to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Some("loopback");
    }
    let address: std::net::IpAddr = lower.parse().ok()?;
    if address.is_loopback() {
        return Some("loopback");
    }
    if address.is_unspecified() {
        return Some("unspecified");
    }
    match address {
        std::net::IpAddr::V4(v4) if v4.is_link_local() => Some("link-local"),
        std::net::IpAddr::V6(v6) if v6.is_unicast_link_local() => Some("link-local"),
        _ => None,
    }
}

/// Why `ConfigMap/ferriscd-metrics-providers-cm` is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetricProviderError {
    /// One entry is not a usable provider.
    #[error("metric provider {provider:?} in ConfigMap {configmap} is unusable: {reason}")]
    Invalid {
        /// The `ConfigMap` name.
        configmap: String,
        /// The entry key.
        provider: String,
        /// Why it was rejected.
        reason: String,
    },
}

/// Reads the admin-configured metric providers.
pub trait MetricProviderSource: Send + Sync + 'static {
    /// Returns the providers in force.
    fn providers(&self) -> BoxFuture<'_, Result<MetricProviderSet, ReconcileError>>;
}

/// [`MetricProviderSource`] backed by `Api<ConfigMap>` in the control-plane namespace.
#[derive(Clone)]
pub struct ApiMetricProviderSource {
    api: Api<ConfigMap>,
    namespace: String,
    name: String,
}

impl ApiMetricProviderSource {
    /// Builds a source reading `ConfigMap/ferriscd-metrics-providers-cm` from `namespace`.
    #[must_use]
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            namespace: namespace.to_owned(),
            name: METRICS_PROVIDERS_CONFIGMAP_NAME.to_owned(),
        }
    }

    /// Builds a source reading from [`CONTROL_PLANE_NAMESPACE`].
    #[must_use]
    pub fn in_control_plane(client: kube::Client) -> Self {
        Self::new(client, CONTROL_PLANE_NAMESPACE)
    }

    /// The namespace the `ConfigMap` is read from.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The `ConfigMap` name.
    #[must_use]
    pub fn configmap_name(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for ApiMetricProviderSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiMetricProviderSource")
            .field("namespace", &self.namespace)
            .field("configmap", &self.name)
            .finish_non_exhaustive()
    }
}

impl MetricProviderSource for ApiMetricProviderSource {
    fn providers(&self) -> BoxFuture<'_, Result<MetricProviderSet, ReconcileError>> {
        Box::pin(async move {
            // `get_opt`: no providers configured is the documented normal state, while an
            // unreadable `ConfigMap` stays an error (retryable).
            let configmap = self
                .api
                .get_opt(&self.name)
                .await
                .map_err(ReconcileError::Api)?;
            let Some(configmap) = configmap else {
                return Ok(MetricProviderSet::empty());
            };
            let data = configmap.data.unwrap_or_default();
            MetricProviderSet::from_configmap_data(&self.name, &data).map_err(|err| {
                ReconcileError::Invalid {
                    message: format!(
                        "{err}; fix or delete the ConfigMap in namespace {:?} — providers that \
                         cannot be parsed are never treated as absent",
                        self.namespace
                    ),
                }
            })
        })
    }
}

/// Resolves the provider a gate names, or the terminal refusal the pass must raise.
///
/// This is the `T20.3` SSRF trap guard in one place: the only URLs the controller will ever dial are
/// the ones an administrator wrote in the control-plane `ConfigMap`, and a gate naming anything else
/// stops the sync instead of being skipped.
///
/// # Errors
///
/// [`ReconcileError::Invalid`] (terminal) when `gate.provider` is not configured.
pub fn resolve_provider<'a>(
    providers: &'a MetricProviderSet,
    gate: &MetricGate,
) -> Result<&'a MetricProvider, ReconcileError> {
    providers.get(gate.provider.trim()).ok_or_else(|| {
        let configured: Vec<&str> = providers.names().collect();
        ReconcileError::Invalid {
            message: format!(
                "spec.syncPolicy.metricGates: provider {:?} is not configured in \
                 ConfigMap/{METRICS_PROVIDERS_CONFIGMAP_NAME}, so the gate cannot be sampled; \
                 configured providers: {}. A Prometheus endpoint is never read from an \
                 Application — a cluster administrator must add it to the ConfigMap in \
                 namespace {CONTROL_PLANE_NAMESPACE:?}",
                gate.provider,
                if configured.is_empty() {
                    "<none>".to_owned()
                } else {
                    configured.join(", ")
                }
            ),
        }
    })
}

/// What the gate says about promotion at one wave boundary.
///
/// Every variant is reachable (`plan` returns `Sample`, `Hold`, `Passed` or `Failed`; `record`
/// returns `Hold`, `Passed` or `Failed`), so a caller must handle all of them and no arm is
/// defensive-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStep {
    /// A sample is due; the caller issues exactly one query and calls [`record`].
    Sample {
        /// The state to fold the observation into.
        state: MetricGateState,
    },
    /// Promotion is held: requeue after `requeue_after` and re-plan. Never a sleep.
    Hold {
        /// The state to persist.
        state: MetricGateState,
        /// How long to wait before the next pass may sample again.
        requeue_after: Duration,
    },
    /// The gate passed: promotion may continue.
    Passed {
        /// The state to persist (terminal, `Passed`).
        state: MetricGateState,
    },
    /// The gate refused promotion: the operation must stop promoting.
    Failed {
        /// The state to persist (terminal, `Failed`).
        state: MetricGateState,
        /// What the operator asked for when the gate fails.
        action: MetricGateFailureAction,
        /// Bounded, secret-free explanation for `/status`.
        message: String,
    },
}

impl GateStep {
    /// The gate state this step carries (every variant carries exactly one).
    #[must_use]
    pub fn state(&self) -> Option<&MetricGateState> {
        match self {
            Self::Sample { state }
            | Self::Hold { state, .. }
            | Self::Passed { state }
            | Self::Failed { state, .. } => Some(state),
        }
    }
}

/// The gate guarding promotion **off** `wave`, if any.
///
/// `spec.syncPolicy.metricGates` is validated to hold at most one gate per wave, so the first match
/// is the only match.
#[must_use]
pub fn gate_after_wave(gates: &[MetricGate], wave: i32) -> Option<&MetricGate> {
    gates.iter().find(|gate| gate.after_wave == wave)
}

/// The declared gates whose `afterWave` names no wave of the rendered bundle (`T20.3` finding M6).
///
/// A gate is evaluated at the boundary **after** its wave, so a gate naming a wave the bundle never
/// renders has no boundary to fire on: it is inert. That is never a bypass — the promotion it was
/// meant to guard is not gated — so the controller says so out loud on every pass that renders such
/// a bundle instead of leaving the operator with a `metricGates` block that quietly does nothing
/// (a typo in `afterWave`, or a gate left behind after the source lost its `sync-wave` annotations).
#[must_use]
pub fn unmatched_gates<'a>(gates: &'a [MetricGate], wave_numbers: &[i32]) -> Vec<&'a MetricGate> {
    gates
        .iter()
        .filter(|gate| !wave_numbers.contains(&gate.after_wave))
        .collect()
}

/// Stable identity of a gate's decision inputs.
///
/// `sha256("ferriscd/metric-gate/v1" ‖ len(part) ‖ part …)`, truncated to
/// [`FINGERPRINT_HEX_CHARS`] lowercase hex characters, over the fields that decide the verdict
/// (wave, provider, query, condition, count); the interval is excluded because changing the cadence
/// must not restart a bake. Persisted in [`MetricGateState::fingerprint`] so an operator's edit
/// restarts the gate instead of crediting samples taken under different rules.
///
/// A truncated SHA-256 rather than a 64-bit non-cryptographic hash (`T20.3` finding M2): the
/// fingerprint is the *only* thing that separates "these samples were taken under these rules" from
/// "these samples were taken under different rules", so a collision silently credits a bake to a
/// gate nobody measured — a fail-open. 128 bits puts the birthday bound at 2^64 fingerprints, far
/// beyond the handful of spec revisions one `Application` ever sees, while staying 32 characters in
/// the budgeted `/status` (trap T9). Every part is length-prefixed, so `("ab", "c")` and `("a", "bc")`
/// cannot hash alike, and no delimiter can be smuggled in through a `provider`/`query`/condition.
#[must_use]
pub fn fingerprint(gate: &MetricGate) -> String {
    const DOMAIN: &[u8] = b"ferriscd/metric-gate/v1";

    let mut key: Vec<u8> = Vec::with_capacity(256);
    key.extend_from_slice(DOMAIN);
    for part in [
        gate.after_wave.to_string(),
        gate.provider.trim().to_owned(),
        gate.query.trim().to_owned(),
        gate.success_condition.trim().to_owned(),
        gate.count.to_string(),
    ] {
        key.extend_from_slice(&(part.len() as u64).to_be_bytes());
        key.extend_from_slice(part.as_bytes());
    }
    ferriscd_engine::manifest::cache::sha256_hex(&key)
        .chars()
        .take(FINGERPRINT_HEX_CHARS)
        .collect()
}

/// The state a gate starts from, ignoring any persisted progress.
fn fresh_state(gate: &MetricGate) -> MetricGateState {
    MetricGateState {
        fingerprint: fingerprint(gate),
        after_wave: gate.after_wave,
        gate_phase: MetricGatePhase::Pending,
        // No verdict has been decided yet, so the safe action is recorded: `fail` overwrites it with
        // the action the failure actually earned (a breach may roll back, an unusable gate may not).
        failure_action: MetricGateFailureAction::Pause,
        consecutive_successes: 0,
        required_successes: gate.count.max(1),
        consecutive_errors: 0,
        last_checked_at: None,
        message: None,
    }
}

/// The persisted state, when it belongs to this gate.
fn resume(gate: &MetricGate, persisted: Option<&MetricGateState>) -> MetricGateState {
    match persisted {
        Some(state) if state.fingerprint == fingerprint(gate) => state.clone(),
        // A different gate (spec edit, or a new operation): start over. Crediting samples taken
        // under other rules is the one way a re-entrant bake could promote without a real sample.
        _ => fresh_state(gate),
    }
}

/// Plans one pass at a wave boundary: sample, hold, or report a terminal verdict.
///
/// Pure: no clock (`now` is an argument), no I/O, no sleep. The caller issues a query only when this
/// returns [`GateStep::Sample`], which is what bounds a gate to **one** query per pass and makes the
/// `intervalSeconds` a requeue hint rather than a busy loop.
#[must_use]
pub fn plan(gate: &MetricGate, persisted: Option<&MetricGateState>, now: &Time) -> GateStep {
    let state = resume(gate, persisted);

    match state.gate_phase {
        // Terminal: a passed gate stays passed, and a failed one stays failed. Re-sampling a failed
        // gate would let a flapping provider promote the rollout it just aborted.
        MetricGatePhase::Passed => return GateStep::Passed { state },
        MetricGatePhase::Failed => {
            // The *decided* action is persisted, not re-read from `spec` (`T20.3` finding M4): a gate
            // that failed because it could not be evaluated must stay a pause even though the spec
            // says `Rollback`.
            let action = state.failure_action;
            let message = state.message.clone().unwrap_or_else(|| {
                bounded(&format!(
                    "metric gate after wave {} previously failed",
                    gate.after_wave
                ))
            });
            return GateStep::Failed {
                state,
                action,
                message,
            };
        }
        MetricGatePhase::Pending | MetricGatePhase::Sampling => {}
    }

    // Fail closed on a condition this build cannot evaluate, *before* spending a query: a hand-patched
    // `/status` or a controller rollback must not degrade a gate into "always satisfied".
    let condition = match MetricCondition::parse(&gate.success_condition) {
        Ok(condition) => condition,
        Err(err) => {
            let message = bounded(&format!("metric gate is misconfigured: {err}"));
            let mut failed = state;
            failed.gate_phase = MetricGatePhase::Failed;
            failed.last_checked_at = Some(now.clone());
            failed.message = Some(message.clone());
            // A condition this build cannot parse is a configuration error, never a regression:
            // `failureAction: Rollback` must not revert a healthy deployment over a typo (M4).
            failed.failure_action = MetricGateFailureAction::Pause;
            return GateStep::Failed {
                state: failed,
                action: MetricGateFailureAction::Pause,
                message,
            };
        }
    };
    debug!(
        after_wave = gate.after_wave,
        comparison = %condition.comparison(),
        "planning a metric gate sample"
    );

    if let Some(last) = state.last_checked_at.as_ref() {
        let interval = u64::from(gate.interval_seconds.max(1));
        let elapsed = elapsed_seconds(now, last);
        if elapsed < interval {
            return GateStep::Hold {
                state,
                requeue_after: Duration::from_secs(interval - elapsed),
            };
        }
    }

    let mut sampling = state;
    sampling.gate_phase = MetricGatePhase::Sampling;
    sampling.required_successes = gate.count.max(1);
    GateStep::Sample { state: sampling }
}

/// Folds one sample observation into the gate state.
///
/// Pure: `now` is an argument and `observation` is what the caller's transport returned, so every
/// branch — a pass, a breach, a timeout, a `4xx` — is a unit test rather than a network fixture.
#[must_use]
pub fn record(
    gate: &MetricGate,
    state: &MetricGateState,
    observation: &Result<PrometheusQueryResponse, MetricQueryError>,
    now: &Time,
) -> GateStep {
    let mut state = state.clone();
    state.last_checked_at = Some(now.clone());
    state.required_successes = gate.count.max(1);

    let condition = match MetricCondition::parse(&gate.success_condition) {
        Ok(condition) => condition,
        Err(err) => {
            return fail(
                state,
                MetricGateFailureAction::Pause,
                format!("metric gate is misconfigured: {err}"),
            );
        }
    };

    match observation {
        Ok(response) => {
            state.consecutive_errors = 0;
            if condition.is_satisfied(response) {
                state.consecutive_successes = state.consecutive_successes.saturating_add(1);
                if state.consecutive_successes >= state.required_successes {
                    state.gate_phase = MetricGatePhase::Passed;
                    let message = bounded(&format!(
                        "metric gate after wave {} passed ({} sample(s) satisfied `{}`)",
                        gate.after_wave, state.consecutive_successes, gate.success_condition
                    ));
                    state.message = Some(message);
                    return GateStep::Passed { state };
                }
                state.gate_phase = MetricGatePhase::Sampling;
                state.message = Some(bounded(&format!(
                    "metric gate after wave {}: {}/{} sample(s) satisfied `{}` ({})",
                    gate.after_wave,
                    state.consecutive_successes,
                    state.required_successes,
                    gate.success_condition,
                    response.describe()
                )));
                return GateStep::Hold {
                    state,
                    requeue_after: gate.interval(),
                };
            }
            // A real measurement that misses the threshold is the one failure that may roll back.
            fail(
                state,
                gate.failure_action,
                format!(
                    "metric gate after wave {} breached: `{}` was not satisfied ({})",
                    gate.after_wave,
                    gate.success_condition,
                    response.describe()
                ),
            )
        }
        Err(error) => {
            state.consecutive_errors = state.consecutive_errors.saturating_add(1);
            // `count` is a count of **consecutive usable samples** (`T20.3` finding H1): a failed
            // query breaks the run. Leaving the successes in place would let `count: 3` pass on
            // samples separated by error passes that measured nothing at all — a fail-open.
            state.consecutive_successes = 0;
            if error.is_retryable() && state.consecutive_errors < MAX_GATE_QUERY_ERRORS {
                // A flaky provider is not a regression: hold and try again, but only a bounded
                // number of times (a gate that can never sample must not hold a rollout forever).
                state.gate_phase = MetricGatePhase::Sampling;
                state.message = Some(bounded(&format!(
                    "metric gate after wave {}: provider {:?} could not be sampled \
                     ({}/{MAX_GATE_QUERY_ERRORS} attempts): {error}",
                    gate.after_wave, gate.provider, state.consecutive_errors
                )));
                return GateStep::Hold {
                    state,
                    requeue_after: gate.interval(),
                };
            }
            let attempts = state.consecutive_errors;
            // A provider that cannot be queried (or answers with something unusable) is not a
            // measurement breach: always pause, never roll back (`T20.3` finding M4).
            fail(
                state,
                MetricGateFailureAction::Pause,
                format!(
                    "metric gate after wave {} could not be evaluated: provider {:?} {error} \
                     ({attempts}/{MAX_GATE_QUERY_ERRORS} consecutive attempts)",
                    gate.after_wave, gate.provider
                ),
            )
        }
    }
}

/// Marks `state` failed and builds the terminal step.
///
/// `action` is the action the failure **earned**, not the one `spec` declares: only a measurement
/// breach is allowed to honour `failureAction: Rollback` (finding M4). It is recorded in
/// [`MetricGateState::failure_action`] so a resumed `Failed` verdict cannot be upgraded to a rollback
/// later.
fn fail(mut state: MetricGateState, action: MetricGateFailureAction, message: String) -> GateStep {
    let message = bounded(&message);
    state.gate_phase = MetricGatePhase::Failed;
    state.failure_action = action;
    state.message = Some(message.clone());
    GateStep::Failed {
        state,
        action,
        message,
    }
}

/// Whole seconds elapsed between `then` and `now`, saturating at `0` for a backwards clock.
fn elapsed_seconds(now: &Time, then: &Time) -> u64 {
    u64::try_from(now.0.duration_since(then.0).as_secs()).unwrap_or(0)
}

/// Truncates a `/status` message to the CRD's own budget, on a UTF-8 boundary.
///
/// `status.operationState.metricGate.message` lives in the same budgeted `/status` as every other
/// message (trap T9), and part of it is operator-supplied (`successCondition`), so it is bounded
/// before it is ever written. The ellipsis is *inside* the budget, not on top of it (`T20.3` nit):
/// truncating to `MAX_STATUS_MESSAGE_CHARS` and then appending `…` produced a message one character
/// over the limit the rest of `/status` is held to.
fn bounded(message: &str) -> String {
    if message.chars().count() <= MAX_STATUS_MESSAGE_CHARS {
        return message.to_owned();
    }
    let mut truncated: String = message.chars().take(MAX_STATUS_MESSAGE_CHARS - 1).collect();
    truncated.push('…');
    truncated
}

/// Borrows at most `max_chars` characters of `value` (used for the short diagnostics that quote
/// provider-supplied text such as `status`/`resultType`).
fn clip(value: &str, max_chars: usize) -> &str {
    match value.char_indices().nth(max_chars) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ferriscd_crd::status::MetricGatePhase;
    use serde_json::json;

    use super::*;

    fn at(rfc3339: &str) -> Time {
        Time(rfc3339.parse().expect("valid RFC 3339 timestamp"))
    }

    fn gate() -> MetricGate {
        MetricGate {
            after_wave: 0,
            provider: "prod".to_owned(),
            query: "sum(rate(http_requests_total{code=~\"5..\"}[5m]))".to_owned(),
            success_condition: "result[0] < 0.01".to_owned(),
            interval_seconds: 10,
            count: 3,
            failure_action: MetricGateFailureAction::Pause,
        }
    }

    fn ok(value: f64) -> Result<PrometheusQueryResponse, MetricQueryError> {
        Ok(PrometheusQueryResponse::new(vec![value]))
    }

    /// One simulated reconcile: `plan`, and only when a sample is due, `record`.
    ///
    /// The second return value is how many queries the pass would have issued — the assertion that
    /// makes "one bounded query per pass, none while holding" observable without a network.
    fn reconcile(
        gate: &MetricGate,
        persisted: Option<&MetricGateState>,
        now: &Time,
        sample: impl FnOnce() -> Result<PrometheusQueryResponse, MetricQueryError>,
    ) -> (GateStep, usize) {
        match plan(gate, persisted, now) {
            GateStep::Sample { state } => {
                let observation = sample();
                (record(gate, &state, &observation, now), 1)
            }
            other => (other, 0),
        }
    }

    /// A controller restart: the gate state survives only through `/status`.
    fn restart(state: &MetricGateState) -> MetricGateState {
        let json = serde_json::to_value(state).expect("gate state must serialize");
        serde_json::from_value(json).expect("gate state must deserialize")
    }

    fn hold(state: &GateStep) -> (MetricGateState, Duration) {
        match state {
            GateStep::Hold {
                state,
                requeue_after,
            } => (state.clone(), *requeue_after),
            other => panic!("expected Hold, got {other:?}"),
        }
    }

    // --- acceptance (1): a multi-sample gate needs one pass per sample ---------------------

    /// `count: 3` promotes only after three **separate** passes, each of which requeues instead of
    /// sleeping, and each of which issues exactly one query.
    #[test]
    fn a_multi_sample_gate_requires_three_passes_across_requeues() {
        let gate = gate();
        let t0 = at("2026-11-24T12:00:00Z");
        let t1 = at("2026-11-24T12:00:10Z");
        let t2 = at("2026-11-24T12:00:20Z");

        // Pass 1: sample 1/3 -> hold for the interval, never Passed.
        let (step, queries) = reconcile(&gate, None, &t0, || ok(0.001));
        assert_eq!(queries, 1, "exactly one query per pass");
        let (state, requeue) = hold(&step);
        assert_eq!(state.gate_phase, MetricGatePhase::Sampling);
        assert_eq!(state.consecutive_successes, 1);
        assert_eq!(state.required_successes, 3);
        assert_eq!(
            requeue,
            Duration::from_secs(10),
            "the interval is a requeue hint"
        );
        assert_eq!(state.last_checked_at, Some(t0.clone()));

        // A pass that arrives early must not sample: no busy loop against Prometheus.
        let (early, queries) = reconcile(
            &gate,
            Some(&restart(&state)),
            &at("2026-11-24T12:00:01Z"),
            || panic!("an early pass must not query the provider"),
        );
        assert_eq!(queries, 0);
        let (early_state, remaining) = hold(&early);
        assert_eq!(
            early_state.consecutive_successes, 1,
            "no sample was credited"
        );
        assert_eq!(
            remaining,
            Duration::from_secs(9),
            "the remaining interval is data"
        );

        // Pass 2 (after the interval): 2/3 -> still holding.
        let (step, queries) = reconcile(&gate, Some(&restart(&state)), &t1, || ok(0.002));
        assert_eq!(queries, 1);
        let (state, _) = hold(&step);
        assert_eq!(state.consecutive_successes, 2);

        // Pass 3: 3/3 -> Passed, and promotion may continue.
        let (step, queries) = reconcile(&gate, Some(&restart(&state)), &t2, || ok(0.0005));
        assert_eq!(queries, 1);
        match step {
            GateStep::Passed { state } => {
                assert_eq!(state.consecutive_successes, 3);
                assert_eq!(state.gate_phase, MetricGatePhase::Passed);
                assert!(state.is_terminal());
            }
            other => panic!("expected Passed on the third sample, got {other:?}"),
        }

        // A passed gate never samples again (no query, no churn).
        let passed = MetricGateState {
            gate_phase: MetricGatePhase::Passed,
            consecutive_successes: 3,
            required_successes: 3,
            ..state_of(&gate)
        };
        let (again, queries) = reconcile(&gate, Some(&passed), &at("2026-11-24T13:00:00Z"), || {
            panic!("a passed gate must not query the provider again")
        });
        assert_eq!(queries, 0);
        assert!(matches!(again, GateStep::Passed { .. }));
    }

    fn state_of(gate: &MetricGate) -> MetricGateState {
        fresh_state(gate)
    }

    // --- acceptance (2): a restart mid-gate resumes from persisted state -------------------

    #[test]
    fn a_controller_restart_mid_gate_resumes_from_the_persisted_state() {
        let gate = gate();
        let t0 = at("2026-11-24T12:00:00Z");
        let t1 = at("2026-11-24T12:00:10Z");

        // Two samples taken by the worker that is about to die.
        let (step, _) = reconcile(&gate, None, &t0, || ok(0.001));
        let (state, _) = hold(&step);
        let (step, _) = reconcile(&gate, Some(&state), &t1, || ok(0.001));
        let (state, _) = hold(&step);
        assert_eq!(state.consecutive_successes, 2);

        // The worker restarts: the state now lives only in `/status`.
        let resumed = restart(&state);
        assert_eq!(resumed, state, "the progress survives a /status round-trip");

        // The restarted worker does not re-sample before the interval...
        let early_at = at("2026-11-24T12:00:11Z");
        let (early, queries) = reconcile(&gate, Some(&resumed), &early_at, || {
            panic!("the interval is still running across the restart")
        });
        assert_eq!(queries, 0);
        let (_, remaining) = hold(&early);
        assert_eq!(remaining, Duration::from_secs(9));

        // ...and the third sample completes the gate for the same revision.
        let t3 = at("2026-11-24T12:00:21Z");
        let (step, queries) = reconcile(&gate, Some(&resumed), &t3, || ok(0.001));
        assert_eq!(queries, 1);
        assert!(matches!(step, GateStep::Passed { .. }), "{step:?}");

        // A brand-new operation (no persisted state) starts at zero: two samples of a previous
        // revision are never credited to a new one.
        let (step, _) = reconcile(&gate, None, &t3, || ok(0.001));
        let (fresh, _) = hold(&step);
        assert_eq!(fresh.consecutive_successes, 1);
    }

    /// A spec edit changes the gate's identity, so the bake restarts instead of crediting samples
    /// taken under different rules; changing only the cadence keeps the progress.
    #[test]
    fn a_spec_edit_restarts_the_gate_and_an_interval_change_does_not() {
        let gate = gate();
        let t0 = at("2026-11-24T12:00:00Z");
        let (step, _) = reconcile(&gate, None, &t0, || ok(0.001));
        let (state, _) = hold(&step);
        assert_eq!(state.consecutive_successes, 1);

        // Same decision inputs, new cadence: the progress is kept, and the shorter interval makes
        // the next sample due one second later.
        let mut faster = gate.clone();
        faster.interval_seconds = 1;
        assert_eq!(fingerprint(&faster), fingerprint(&gate));
        assert_eq!(resume(&faster, Some(&state)).consecutive_successes, 1);
        let (step, queries) = reconcile(&faster, Some(&state), &at("2026-11-24T12:00:01Z"), || {
            ok(0.001)
        });
        assert_eq!(queries, 1);
        assert_eq!(hold(&step).0.consecutive_successes, 2);

        // A different threshold, count, query or provider is a different gate: start over.
        for edited in [
            MetricGate {
                success_condition: "result[0] < 0.05".to_owned(),
                ..gate.clone()
            },
            MetricGate {
                count: 5,
                ..gate.clone()
            },
            MetricGate {
                query: "sum(rate(http_requests_total[5m]))".to_owned(),
                ..gate.clone()
            },
            MetricGate {
                provider: "staging".to_owned(),
                ..gate.clone()
            },
            MetricGate {
                after_wave: 7,
                ..gate.clone()
            },
        ] {
            let resumed = resume(&edited, Some(&state));
            assert_eq!(
                resumed.consecutive_successes, 0,
                "a changed gate must not inherit samples: {edited:?}"
            );
            assert_eq!(resumed.gate_phase, MetricGatePhase::Pending);
            assert_eq!(resumed.fingerprint, fingerprint(&edited));
        }
    }

    // --- acceptance (3): a breach is deterministic and honours Pause / Rollback -----------

    #[test]
    fn a_metric_breach_triggers_pause_or_rollback_deterministically() {
        let t = at("2026-11-24T12:00:00Z");
        for action in [
            MetricGateFailureAction::Pause,
            MetricGateFailureAction::Rollback,
        ] {
            let mut gate = gate();
            gate.failure_action = action;
            let (step, queries) = reconcile(&gate, None, &t, || ok(0.42));
            assert_eq!(queries, 1);
            match step {
                GateStep::Failed {
                    state,
                    action: chosen,
                    message,
                } => {
                    assert_eq!(chosen, action, "the spec's failureAction is honoured");
                    assert_eq!(state.gate_phase, MetricGatePhase::Failed);
                    assert_eq!(state.failure_action, action, "the decision is persisted");
                    assert_eq!(state.consecutive_successes, 0);
                    assert!(state.is_terminal());
                    assert!(
                        message.contains("breached") && message.contains("0.42"),
                        "the operator must see the measurement: {message}"
                    );
                    assert_eq!(state.message.as_deref(), Some(message.as_str()));
                }
                other => panic!("expected Failed, got {other:?}"),
            }

            // Deterministic: the same inputs produce the same verdict, and a failed gate is never
            // re-sampled (a flapping provider must not promote the rollout it just aborted).
            let failed = MetricGateState {
                gate_phase: MetricGatePhase::Failed,
                failure_action: action,
                message: Some("breached".to_owned()),
                ..fresh_state(&gate)
            };
            let (again, queries) =
                reconcile(&gate, Some(&failed), &at("2026-11-24T13:00:00Z"), || {
                    panic!("a failed gate must not query the provider again")
                });
            assert_eq!(queries, 0);
            match again {
                GateStep::Failed {
                    action: chosen,
                    message,
                    ..
                } => {
                    assert_eq!(chosen, action);
                    assert_eq!(message, "breached", "the recorded reason survives");
                }
                other => panic!("expected Failed, got {other:?}"),
            }
        }
    }

    /// A sample of exactly `count - 1` successes followed by a breach aborts: partial progress never
    /// promotes.
    #[test]
    fn a_breach_after_progress_aborts_instead_of_promoting() {
        let gate = gate();
        let t0 = at("2026-11-24T12:00:00Z");
        let t1 = at("2026-11-24T12:00:10Z");
        let (step, _) = reconcile(&gate, None, &t0, || ok(0.001));
        let (state, _) = hold(&step);
        let (step, _) = reconcile(&gate, Some(&state), &t1, || ok(0.5));
        match step {
            GateStep::Failed { state, .. } => {
                assert_eq!(
                    state.consecutive_successes, 1,
                    "progress is kept for the operator"
                );
                assert_eq!(state.gate_phase, MetricGatePhase::Failed);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // --- failure classification ------------------------------------------------------------

    /// `T20.3` finding H1: `count` counts **consecutive usable** samples. A pass whose query fails
    /// measures nothing, so it must break the run — otherwise `success, error, success` would satisfy
    /// a `count: 2` gate on two samples that were never consecutive, which is a fail-open.
    #[test]
    fn a_query_error_breaks_the_run_of_consecutive_successes() {
        let mut gate = gate();
        gate.count = 2;
        let t0 = at("2026-11-24T12:00:00Z");
        let t1 = at("2026-11-24T12:00:10Z");
        let t2 = at("2026-11-24T12:00:20Z");

        // S: 1/2 satisfied.
        let (step, _) = reconcile(&gate, None, &t0, || ok(0.001));
        let (sampling, _) = hold(&step);
        assert_eq!(sampling.consecutive_successes, 1);

        // E: the provider times out. The run is broken; the rollout keeps holding.
        let (step, queries) = reconcile(&gate, Some(&sampling), &t1, || {
            Err(MetricQueryError::Timeout)
        });
        assert_eq!(queries, 1);
        let (errored, _) = hold(&step);
        assert_eq!(
            errored.consecutive_successes, 0,
            "a failed query must reset the run, not bank the earlier sample"
        );
        assert_eq!(errored.consecutive_errors, 1);

        // S: one usable sample again — 1/2, **not** Passed.
        let (step, _) = reconcile(&gate, Some(&errored), &t2, || ok(0.001));
        match step {
            GateStep::Hold { state, .. } => {
                assert_eq!(
                    state.consecutive_successes, 1,
                    "S,E,S must not satisfy a `count: 2` gate"
                );
                assert_eq!(state.required_successes, 2);
                assert_eq!(state.gate_phase, MetricGatePhase::Sampling);
                assert_eq!(
                    state.consecutive_errors, 0,
                    "a usable sample clears the run"
                );
            }
            other => panic!("expected Hold (1/2) after S,E,S, got {other:?}"),
        }

        // A fourth pass with a usable sample is what actually promotes.
        let (step, _) = reconcile(&gate, Some(&errored), &t2, || ok(0.001));
        let (again, _) = hold(&step);
        let (step, _) = reconcile(&gate, Some(&again), &at("2026-11-24T12:00:30Z"), || {
            ok(0.001)
        });
        assert!(matches!(step, GateStep::Passed { .. }), "{step:?}");
    }

    #[test]
    fn an_unreachable_provider_fails_closed_after_a_bounded_number_of_attempts() {
        let gate = gate();
        let mut state = fresh_state(&gate);
        let mut now = 0_u32;

        // Two retryable failures hold the rollout (the provider may be restarting)...
        for attempt in 1..MAX_GATE_QUERY_ERRORS {
            let at_now = at(&format!("2026-11-24T12:00:{now:02}Z"));
            let (step, queries) = reconcile(&gate, Some(&state), &at_now, || {
                Err(MetricQueryError::Timeout)
            });
            assert_eq!(queries, 1);
            let (next, requeue) = hold(&step);
            assert_eq!(next.consecutive_errors, attempt);
            assert_eq!(next.gate_phase, MetricGatePhase::Sampling);
            assert_eq!(requeue, Duration::from_secs(10));
            state = next;
            now += 10;
        }

        // ...and the third fails the gate closed instead of holding a rollout open forever.
        let (step, _) = reconcile(&gate, Some(&state), &at("2026-11-24T12:00:20Z"), || {
            Err(MetricQueryError::Timeout)
        });
        match step {
            GateStep::Failed { state, message, .. } => {
                assert_eq!(state.consecutive_errors, MAX_GATE_QUERY_ERRORS);
                assert!(
                    message.contains("could not be evaluated"),
                    "a provider outage must not read as a metric breach: {message}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        // A successful sample clears the error counter.
        let mut holding = fresh_state(&gate);
        holding.consecutive_errors = 1;
        let (step, _) = reconcile(&gate, Some(&holding), &at("2026-11-24T12:00:00Z"), || {
            ok(0.001)
        });
        let (recovered, _) = hold(&step);
        assert_eq!(recovered.consecutive_errors, 0);
    }

    #[test]
    fn a_terminal_query_failure_fails_immediately() {
        let gate = gate();
        for error in [
            MetricQueryError::Status { code: 400 },
            MetricQueryError::Body {
                reason: "not the envelope".to_owned(),
            },
        ] {
            assert!(!error.is_retryable(), "{error:?}");
            let (step, _) = reconcile(&gate, None, &at("2026-11-24T12:00:00Z"), || {
                Err(error.clone())
            });
            assert!(
                matches!(step, GateStep::Failed { .. }),
                "{error:?} must fail immediately: {step:?}"
            );
        }
        // A 5xx is the provider's problem: retryable.
        assert!(MetricQueryError::Status { code: 503 }.is_retryable());
        assert!(MetricQueryError::Connect.is_retryable());
        assert!(MetricQueryError::Transport.is_retryable());
    }

    /// A `successCondition` this build cannot evaluate fails closed *before* any query: a gate must
    /// never degrade into "always satisfied".
    #[test]
    fn an_unparsable_condition_fails_the_gate_without_querying() {
        let mut gate = gate();
        gate.success_condition = "errorRate < 1%".to_owned();
        let (step, queries) = reconcile(&gate, None, &at("2026-11-24T12:00:00Z"), || {
            panic!("a misconfigured gate must not query the provider")
        });
        assert_eq!(queries, 0);
        match step {
            GateStep::Failed { state, message, .. } => {
                assert_eq!(state.gate_phase, MetricGatePhase::Failed);
                assert!(message.contains("misconfigured"), "{message}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        // `record` is total even when called with a bad condition (a hand-built state).
        let state = fresh_state(&gate);
        assert!(matches!(
            record(&gate, &state, &ok(0.0), &at("2026-11-24T12:00:00Z")),
            GateStep::Failed { .. }
        ));
    }

    /// `T20.3` finding M4: only a **measurement breach** may act on `failureAction`. A gate that
    /// could not be evaluated — a bad condition, a `4xx`, a non-JSON body, an unsupported
    /// `resultType` — says nothing about whether the canary regressed, so it must always pause.
    #[test]
    fn a_gate_that_cannot_be_evaluated_pauses_instead_of_rolling_back() {
        let now = at("2026-11-24T12:00:00Z");
        let mut gate = gate();
        gate.failure_action = MetricGateFailureAction::Rollback;

        // The configuration/transport failures, each of which must land as `Pause`.
        let mut misconfigured = gate.clone();
        misconfigured.success_condition = "errorRate < 1%".to_owned();
        for (label, refused, observation) in [
            ("unparsable condition", &misconfigured, ok(0.0)),
            ("4xx", &gate, Err(MetricQueryError::Status { code: 400 })),
            (
                "5xx exhaustion",
                &gate,
                Err(MetricQueryError::Status { code: 503 }),
            ),
            (
                "non-JSON body",
                &gate,
                Err(MetricQueryError::Body {
                    reason: "response is not the Prometheus query JSON envelope".to_owned(),
                }),
            ),
            (
                "unsupported resultType (matrix)",
                &gate,
                Err(MetricQueryError::Body {
                    reason: "resultType \"matrix\" is not supported".to_owned(),
                }),
            ),
        ] {
            // Exhaust the retryable budget so the 5xx case reaches its terminal verdict.
            let mut state = fresh_state(refused);
            state.consecutive_errors = MAX_GATE_QUERY_ERRORS - 1;
            let (step, _) = reconcile(refused, Some(&state), &now, || observation.clone());
            match step {
                GateStep::Failed {
                    state,
                    action,
                    message,
                } => {
                    assert_eq!(
                        action,
                        MetricGateFailureAction::Pause,
                        "{label}: only a measurement breach may roll back: {message}"
                    );
                    assert_eq!(
                        state.failure_action,
                        MetricGateFailureAction::Pause,
                        "{label}: the persisted decision must match"
                    );
                }
                other => panic!("{label}: expected Failed, got {other:?}"),
            }
        }

        // The resumed verdict keeps the recorded action, so a restart cannot upgrade a pause into a
        // rollback just because `spec` says `Rollback`.
        let resumed = MetricGateState {
            gate_phase: MetricGatePhase::Failed,
            failure_action: MetricGateFailureAction::Pause,
            message: Some("metric gate is misconfigured".to_owned()),
            ..fresh_state(&gate)
        };
        let (step, queries) = reconcile(&gate, Some(&resumed), &now, || {
            panic!("a failed gate is never re-sampled")
        });
        assert_eq!(queries, 0);
        match step {
            GateStep::Failed { action, .. } => assert_eq!(
                action,
                MetricGateFailureAction::Pause,
                "a configuration failure must not become a rollback after a restart"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }

        // The contrast: the same `Rollback` spec *does* roll back on a real breach.
        let (step, _) = reconcile(&gate, None, &now, || ok(0.42));
        match step {
            GateStep::Failed { action, .. } => {
                assert_eq!(action, MetricGateFailureAction::Rollback)
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        // `record` is entered with an already-sampled state, so its own unparsable-condition arm is
        // checked directly rather than through `plan` (which would have refused before querying).
        match record(&misconfigured, &fresh_state(&misconfigured), &ok(0.0), &now) {
            GateStep::Failed { state, action, .. } => {
                assert_eq!(action, MetricGateFailureAction::Pause);
                assert_eq!(state.failure_action, MetricGateFailureAction::Pause);
                assert_eq!(state.gate_phase, MetricGatePhase::Failed);
            }
            other => panic!("expected a terminal pause, got {other:?}"),
        }
    }

    // --- the condition grammar -------------------------------------------------------------

    #[test]
    fn success_conditions_are_parsed_and_evaluated() {
        let response = PrometheusQueryResponse::new(vec![0.004, 0.9]);
        for (text, satisfied) in [
            ("result[0] < 0.01", true),
            ("result[1] < 0.01", false),
            ("result[0] <= 0.004", true),
            ("result[0] > 0.01", false),
            ("result[0] >= 0.004", true),
            ("result[0] == 0.004", true),
            ("result[1] != 0.5", true),
            ("len(result) > 0", true),
            ("len(result) > 2", false),
            // An index the response does not carry never satisfies anything.
            ("result[5] < 0.01", false),
        ] {
            let condition = MetricCondition::parse(text).expect(text);
            assert_eq!(condition.is_satisfied(&response), satisfied, "{text}");
        }

        // `NaN`/`+Inf` (an empty-but-valid expression) never satisfy: `!=` must not be a loophole.
        let nan = PrometheusQueryResponse::new(vec![f64::NAN, f64::INFINITY]);
        for text in [
            "result[0] < 1",
            "result[0] > 1",
            "result[0] != 1",
            "result[1] >= 0",
        ] {
            assert!(
                !MetricCondition::parse(text).expect(text).is_satisfied(&nan),
                "{text} must not be satisfied by a non-finite sample"
            );
        }

        for text in [
            "",
            "errorRate < 0.01",
            "result[0]",
            "result[0] ~ 1",
            "result[-1] < 1",
            "result[0] < abc",
            "len(result)",
            "result[0] <",
        ] {
            assert!(
                MetricCondition::parse(text).is_err(),
                "{text:?} must be rejected"
            );
        }

        // The error names the grammar instead of echoing a secret or a URL.
        let err = MetricCondition::parse("errorRate < 1%").expect_err("rejected");
        assert!(err.to_string().contains("result[<index>]"), "{err}");
    }

    /// `T20.3` nit: `==`/`!=` use a **relative** tolerance. An absolute `f64::EPSILON` is the wrong
    /// scale for a measurement that can be `1e-9` (error rate) or `1e12` (a request counter), and it
    /// made `result[0] == 1e12` false for a value a double physically cannot tell apart.
    #[test]
    fn equality_uses_a_relative_tolerance() {
        // The magnitude where an absolute EPSILON is meaningless: the spacing of doubles near 1e12
        // is ~1e-4, so a sample Prometheus sends as `1000000000000` must equal the literal `1e12`.
        assert!(Comparison::Eq.matches(1e12, 1e12));
        assert!(
            Comparison::Eq.matches(1e12, 1e12_f64.next_up()),
            "one ULP apart at 1e12 is the same measurement"
        );
        // Near zero it stays an absolute tolerance: two genuinely different small values differ.
        assert!(!Comparison::Eq.matches(0.001, 0.002));
        assert!(Comparison::Ne.matches(0.001, 0.002));
        // The classic decimal literal: `0.1 + 0.2` is not bit-equal to `0.3`, but it is the same
        // number, and an operator's `result[0] == 0.3` must agree with what Prometheus measured.
        assert!(Comparison::Eq.matches(0.1 + 0.2, 0.3));
        // Every operator keeps its exact ordering semantics at the boundary.
        assert!(Comparison::Lt.matches(0.004, 0.01));
        assert!(!Comparison::Lt.matches(0.01, 0.01));
        assert!(Comparison::Le.matches(0.01, 0.01));
        assert!(Comparison::Gt.matches(0.01, 0.004));
        assert!(Comparison::Ge.matches(0.01, 0.01));
        // `==`/`!=` are exact complements for finite values (only the non-finite guard is shared).
        for (left, right) in [(0.0, 0.0), (1.0, 1.000_000_1), (-3.5, -3.5), (1e-9, 2e-9)] {
            assert_ne!(
                Comparison::Eq.matches(left, right),
                Comparison::Ne.matches(left, right),
                "{left} vs {right}"
            );
        }
    }

    // --- the Prometheus wire format --------------------------------------------------------

    #[test]
    fn prometheus_responses_are_parsed_total() {
        let vector = parse_prometheus_response(
            &json!({
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        { "metric": { "code": "500" }, "value": [1_700_000_000.0, "0.004"] },
                        { "metric": { "code": "502" }, "value": [1_700_000_000.0, "NaN"] },
                    ],
                },
            })
            .to_string(),
        )
        .expect("a vector parses");
        assert_eq!(vector.samples().len(), 2);
        assert_eq!(vector.samples()[0], 0.004);
        assert!(vector.samples()[1].is_nan());
        assert!(vector.describe().starts_with("2 sample(s), first = 0.004"));

        let scalar = parse_prometheus_response(
            &json!({
                "status": "success",
                "data": { "resultType": "scalar", "result": [1_700_000_000.0, "+Inf"] },
            })
            .to_string(),
        )
        .expect("a scalar parses");
        assert_eq!(scalar.samples(), &[f64::INFINITY]);

        let empty = parse_prometheus_response(
            &json!({
                "status": "success",
                "data": { "resultType": "vector", "result": [] },
            })
            .to_string(),
        )
        .expect("an empty vector parses");
        assert!(empty.samples().is_empty());
        assert_eq!(empty.describe(), "no samples");

        // Terminal: a failed query, an unsupported result type, a malformed body, too many series.
        for body in [
            json!({ "status": "error", "error": "parse error: unexpected end of input" })
                .to_string(),
            json!({ "status": "success", "data": { "resultType": "matrix", "result": [] } })
                .to_string(),
            json!({ "status": "success" }).to_string(),
            "not json".to_owned(),
            json!({
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": (0..(MAX_PROMETHEUS_SAMPLES + 1))
                        .map(|_| json!({ "value": [0.0, "1"] }))
                        .collect::<Vec<_>>(),
                },
            })
            .to_string(),
            json!({
                "status": "success",
                "data": { "resultType": "vector", "result": [{ "value": "not-a-pair" }] },
            })
            .to_string(),
            json!({
                "status": "success",
                "data": { "resultType": "vector", "result": [{ "value": [0.0, "abc"] }] },
            })
            .to_string(),
        ] {
            let error = parse_prometheus_response(&body).expect_err("must be refused");
            assert!(!error.is_retryable(), "{error:?}");
            // The provider's own error text (which quotes the query) is never echoed.
            assert!(
                !error.to_string().contains("unexpected end of input"),
                "{error}"
            );
        }
    }

    /// Transport failures carry a class, never a rendered `reqwest` error: that `Display` contains
    /// the request URL (which may carry credentials), and the message reaches `/status`.
    #[test]
    fn transport_failures_never_echo_the_provider_url() {
        for error in [
            MetricQueryError::Timeout,
            MetricQueryError::Connect,
            MetricQueryError::Transport,
            MetricQueryError::Status { code: 403 },
            MetricQueryError::Body {
                reason: "response is not valid UTF-8".to_owned(),
            },
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("http"), "{rendered}");
            assert!(!rendered.contains('@'), "{rendered}");
        }

        // The production transport is bounded and redirect-free.
        let transport = ReqwestMetricTransport::build().expect("the HTTP client must build");
        assert_eq!(transport.timeout(), METRIC_GATE_QUERY_TIMEOUT);
        assert_eq!(METRIC_GATE_QUERY_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn queries_are_percent_encoded_so_a_query_cannot_inject_a_parameter() {
        let encoded = percent_encode("sum(rate(x{job=\"api\"}[5m])) & limit=1");
        assert!(!encoded.contains(' '), "{encoded}");
        assert!(!encoded.contains('&'), "{encoded}");
        assert!(!encoded.contains('"'), "{encoded}");
        assert!(!encoded.contains('{'), "{encoded}");
        assert!(encoded.contains("%20"), "{encoded}");
        assert!(
            encoded.contains("%26"),
            "the `&` must be escaped: {encoded}"
        );
        assert_eq!(percent_encode("up"), "up");
    }

    // --- acceptance (4): the tenant cannot pick the endpoint ------------------------------

    #[test]
    fn a_tenant_application_cannot_specify_an_unallowlisted_endpoint() {
        let providers = MetricProviderSet::from_configmap_data(
            METRICS_PROVIDERS_CONFIGMAP_NAME,
            &BTreeMap::from([(
                "prod".to_owned(),
                "url: http://prometheus.monitoring.svc:9090".to_owned(),
            )]),
        )
        .expect("the admin ConfigMap parses");
        assert_eq!(providers.len(), 1);

        // The allowlisted provider resolves.
        let allowed = gate();
        assert_eq!(
            resolve_provider(&providers, &allowed)
                .expect("allowlisted")
                .url(),
            "http://prometheus.monitoring.svc:9090"
        );

        // Anything else is a *terminal* refusal, whatever it looks like.
        for provider in [
            "staging",
            // A URL pasted into the provider field: never dialled, even though `validate()` also
            // rejects it — defence in depth for a legacy object or a hand-patched status.
            "http://169.254.169.254:9090",
            "https://prometheus.example.com",
        ] {
            let mut refused = gate();
            refused.provider = provider.to_owned();
            let error = resolve_provider(&providers, &refused)
                .expect_err("an unallowlisted provider must refuse the pass");
            assert_eq!(
                error.failure_class(),
                crate::FailureClass::Terminal,
                "retrying cannot configure a provider: {provider}"
            );
            let message = error.to_string();
            assert!(
                message.contains(METRICS_PROVIDERS_CONFIGMAP_NAME),
                "the refusal must name the ConfigMap: {message}"
            );
            assert!(
                message.contains("prod"),
                "the refusal must list what *is* configured: {message}"
            );
            assert!(message.contains(CONTROL_PLANE_NAMESPACE), "{message}");
        }

        // No providers at all is also a refusal, never a skip.
        let error = resolve_provider(&MetricProviderSet::empty(), &gate())
            .expect_err("no providers must refuse");
        assert!(error.to_string().contains("<none>"), "{error}");
    }

    // --- the admin ConfigMap --------------------------------------------------------------

    #[test]
    fn providers_are_parsed_from_one_admin_configmap() {
        let providers = MetricProviderSet::from_configmap_data(
            METRICS_PROVIDERS_CONFIGMAP_NAME,
            &BTreeMap::from([
                (
                    "prod".to_owned(),
                    "url: https://prometheus.example.com\n".to_owned(),
                ),
                (
                    "staging".to_owned(),
                    "url: http://prometheus.staging.svc:9090/".to_owned(),
                ),
            ]),
        )
        .expect("both providers parse");
        assert_eq!(providers.len(), 2);
        assert!(!providers.is_empty());
        assert_eq!(
            providers.names().collect::<Vec<_>>(),
            vec!["prod", "staging"],
            "the set is ordered by provider name"
        );
        assert_eq!(
            providers.get("staging").expect("staging").url(),
            "http://prometheus.staging.svc:9090/"
        );
        assert_eq!(
            MetricProvider::new("http://x").url(),
            "http://x",
            "MetricProvider is a plain URL holder"
        );

        // Determinism: parsing twice yields the same set (a diff-clean ConfigMap).
        assert_eq!(
            providers,
            MetricProviderSet::from_configmap_data(
                METRICS_PROVIDERS_CONFIGMAP_NAME,
                &BTreeMap::from([
                    (
                        "staging".to_owned(),
                        "url: http://prometheus.staging.svc:9090/".to_owned()
                    ),
                    (
                        "prod".to_owned(),
                        "url: https://prometheus.example.com\n".to_owned()
                    ),
                ]),
            )
            .expect("both providers parse")
        );
    }

    #[test]
    fn a_provider_entry_that_cannot_be_used_is_terminal() {
        for (name, value) in [
            ("prod", "endpoint: http://prometheus:9090"),
            ("prod", "url: \"\""),
            ("prod", "url: file:///etc/passwd"),
            ("prod", "url: prometheus:9090"),
            ("prod", "url: http://user:secret@prometheus:9090"),
            ("prod", "url: http://prometheus:9090/api?tenant=prod"),
            ("prod", "url: http://prometheus:9090#frag"),
            ("   ", "url: http://prometheus:9090"),
        ] {
            let error = MetricProviderSet::from_configmap_data(
                METRICS_PROVIDERS_CONFIGMAP_NAME,
                &BTreeMap::from([(name.to_owned(), value.to_owned())]),
            )
            .expect_err("an unusable provider must be refused");
            // A `ConfigMap` that cannot be parsed is never "no providers" (fail closed).
            assert!(
                error.to_string().contains(METRICS_PROVIDERS_CONFIGMAP_NAME),
                "{error}"
            );
            // Credentials embedded in a URL are never echoed.
            assert!(!error.to_string().contains("secret"), "{error}");
        }
    }

    /// `T20.3` nit: the loopback/unspecified/link-local deny-list. An admin `ConfigMap` is not a
    /// secret store, so a sloppy (or tampered) entry must not turn the metrics client into a request
    /// forwarder onto the controller's own pod or onto the cloud metadata endpoint.
    #[test]
    fn a_provider_may_not_point_at_loopback_or_link_local() {
        for url in [
            "http://127.0.0.1:9090",
            "http://127.8.8.8:9090",
            "http://localhost:9090",
            "http://prometheus.localhost:9090",
            "http://[::1]:9090",
            "http://0.0.0.0:9090",
            "http://[::]:9090",
            // The cloud metadata endpoint: link-local, exactly what an SSRF payload reaches for.
            "http://169.254.169.254",
            "http://[fe80::1]:9090",
        ] {
            let error = MetricProviderSet::from_configmap_data(
                METRICS_PROVIDERS_CONFIGMAP_NAME,
                &BTreeMap::from([("prod".to_owned(), format!("url: {url}"))]),
            )
            .expect_err("a loopback/link-local provider must be refused");
            assert!(
                error.to_string().contains("in-cluster service"),
                "{url} must be refused with the actionable reason: {error}"
            );
        }

        // And the addresses a real provider uses still parse: DNS service names, a cluster VIP.
        let providers = MetricProviderSet::from_configmap_data(
            METRICS_PROVIDERS_CONFIGMAP_NAME,
            &BTreeMap::from([
                (
                    "prod".to_owned(),
                    "url: http://prometheus.monitoring.svc:9090".to_owned(),
                ),
                ("vip".to_owned(), "url: https://10.96.0.10:9090/".to_owned()),
                (
                    "routable".to_owned(),
                    "url: https://prometheus.example.com".to_owned(),
                ),
                (
                    "ipv6-vip".to_owned(),
                    "url: http://[fd00::1]:9090".to_owned(),
                ),
            ]),
        )
        .expect("every in-cluster shape must be accepted");
        assert_eq!(providers.len(), 4);
    }

    // --- the ConfigMap read --------------------------------------------------------------

    /// A `kube::Client` that records request URIs and answers every call with `body`/`status`.
    fn recording_client(
        status: u16,
        body: serde_json::Value,
    ) -> (kube::Client, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let body = serde_json::to_vec(&body).expect("a serializable body");
        let client = kube::Client::new(
            tower::service_fn(move |request: http::Request<kube::client::Body>| {
                let recorder = recorder.clone();
                let body = body.clone();
                async move {
                    recorder
                        .lock()
                        .expect("the recorder lock is never poisoned in a test")
                        .push(request.uri().to_string());
                    let response = http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body))
                        .expect("a valid response");
                    Ok::<_, std::convert::Infallible>(response)
                }
            }),
            CONTROL_PLANE_NAMESPACE,
        );
        (client, seen)
    }

    fn configmap(data: serde_json::Value) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": METRICS_PROVIDERS_CONFIGMAP_NAME,
                "namespace": CONTROL_PLANE_NAMESPACE,
            },
            "data": data,
        })
    }

    #[tokio::test]
    async fn the_allowlist_is_read_from_one_scoped_get() {
        let (client, seen) = recording_client(
            200,
            configmap(json!({ "prod": "url: http://prometheus.monitoring.svc:9090" })),
        );
        let source = ApiMetricProviderSource::in_control_plane(client);
        assert_eq!(source.namespace(), CONTROL_PLANE_NAMESPACE);
        assert_eq!(source.configmap_name(), METRICS_PROVIDERS_CONFIGMAP_NAME);

        let providers = source.providers().await.expect("the ConfigMap parses");
        assert_eq!(providers.len(), 1);

        let requests = seen
            .lock()
            .expect("the recorder lock is never poisoned in a test")
            .clone();
        assert_eq!(requests.len(), 1, "one scoped GET: {requests:?}");
        assert!(
            requests[0].starts_with("/api/v1/namespaces/ferriscd-system/configmaps/"),
            "{requests:?}"
        );
        assert!(
            requests[0].contains(METRICS_PROVIDERS_CONFIGMAP_NAME),
            "{requests:?}"
        );

        // Debug names the scope without a client handle.
        let (client, _seen) = recording_client(404, json!({}));
        let debug = format!("{:?}", ApiMetricProviderSource::new(client, "apps"));
        assert!(debug.contains("apps"), "{debug}");
        assert!(debug.contains(METRICS_PROVIDERS_CONFIGMAP_NAME), "{debug}");
    }

    #[tokio::test]
    async fn a_missing_configmap_means_no_providers_and_an_unparsable_one_refuses() {
        let (client, _seen) = recording_client(
            404,
            json!({
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "message": format!("configmaps \"{METRICS_PROVIDERS_CONFIGMAP_NAME}\" not found"),
                "reason": "NotFound",
                "code": 404,
            }),
        );
        assert!(
            ApiMetricProviderSource::in_control_plane(client)
                .providers()
                .await
                .expect("a missing ConfigMap is not an error")
                .is_empty()
        );

        let (client, _seen) = recording_client(200, configmap(json!({ "prod": "endpoint: nope" })));
        let error = ApiMetricProviderSource::in_control_plane(client)
            .providers()
            .await
            .expect_err("an unparsable ConfigMap must refuse");
        assert_eq!(error.failure_class(), crate::FailureClass::Terminal);
        assert!(
            error.to_string().contains("never treated as absent"),
            "{error}"
        );
    }

    /// The trait objects must stay object-safe: the pipeline holds `Arc<dyn …>`.
    #[test]
    fn the_gate_seams_are_object_safe() {
        fn assert_provider_source(_: &dyn MetricProviderSource) {}
        fn assert_transport(_: &dyn MetricQueryTransport) {}

        struct Empty;
        impl MetricProviderSource for Empty {
            fn providers(&self) -> BoxFuture<'_, Result<MetricProviderSet, ReconcileError>> {
                Box::pin(async { Ok(MetricProviderSet::empty()) })
            }
        }
        struct NoQuery;
        impl MetricQueryTransport for NoQuery {
            fn query<'a>(
                &'a self,
                _request: MetricQueryRequest<'a>,
            ) -> BoxFuture<'a, Result<PrometheusQueryResponse, MetricQueryError>> {
                Box::pin(async { Err(MetricQueryError::Transport) })
            }
        }

        assert_provider_source(&Empty);
        assert_transport(&NoQuery);
    }

    #[test]
    fn the_gate_is_selected_by_the_wave_it_guards() {
        let mut second = gate();
        second.after_wave = 5;
        let gates = vec![gate(), second];

        assert!(gate_after_wave(&gates, 0).is_some());
        assert!(gate_after_wave(&gates, 5).is_some());
        assert_eq!(
            gate_after_wave(&gates, 5).map(|gate| gate.after_wave),
            Some(5)
        );
        assert!(
            gate_after_wave(&gates, 1).is_none(),
            "a boundary without a gate is open"
        );
        assert!(gate_after_wave(&[], 0).is_none());

        // Every `GateStep` variant is reachable and carries the state the caller must persist.
        let state = fresh_state(&gate());
        let steps = [
            GateStep::Sample {
                state: state.clone(),
            },
            GateStep::Hold {
                state: state.clone(),
                requeue_after: Duration::from_secs(1),
            },
            GateStep::Passed {
                state: state.clone(),
            },
            GateStep::Failed {
                state: state.clone(),
                action: MetricGateFailureAction::Pause,
                message: "breached".to_owned(),
            },
        ];
        for step in steps {
            assert!(step.state().is_some(), "{step:?} must carry a state");
        }
    }

    /// `T20.3` finding M6: a gate whose `afterWave` names no wave of the bundle can never fire, and
    /// the controller must be able to say so (`prepare_pass` logs a `Warning` from this list).
    #[test]
    fn a_gate_that_matches_no_wave_is_reported() {
        let mut deep = gate();
        deep.after_wave = 42;
        let mut last = gate();
        last.after_wave = -1;
        let gates = vec![gate(), deep, last];

        // The bundle this fixture renders: waves -1 and 0. Both real boundaries match; 42 does not.
        let waves = [-1, 0];
        let unmatched = unmatched_gates(&gates, &waves);
        assert_eq!(unmatched.len(), 1, "{unmatched:?}");
        assert_eq!(unmatched[0].after_wave, 42);

        // A gate on the **last** wave is *not* unmatched: a single-wave bundle is gated on the only
        // boundary it has (`T20.3` finding M5), so nothing may be reported as inert there.
        assert!(unmatched_gates(&[gate()], &[0]).is_empty());
        assert!(unmatched_gates(&[], &[0]).is_empty());
        // Nothing matches an empty plan, so every gate is reported (a bundle that rendered nothing).
        assert_eq!(unmatched_gates(&gates, &[]).len(), 3);
    }

    // --- the gate fingerprint ---------------------------------------------------------------

    /// `T20.3` finding M2: the fingerprint is a truncated SHA-256 — stable across runs and across
    /// processes (it is compared against persisted `/status`), and wide enough that no two distinct
    /// gates of one `Application` can share one.
    #[test]
    fn the_fingerprint_is_a_stable_truncated_sha256() {
        let gate = gate();
        let printed = fingerprint(&gate);

        // Stable: the same inputs always produce the same 128-bit hex digest, byte-for-byte. A
        // pinned literal is what proves it is not just stable within this process (a fingerprint
        // written by an older build must still be recognised after an upgrade).
        assert_eq!(printed, fingerprint(&gate.clone()));
        assert_eq!(printed.len(), FINGERPRINT_HEX_CHARS);
        assert!(
            printed.chars().all(|char| char.is_ascii_hexdigit()),
            "{printed}"
        );
        // Independent of the SHA-256 implementation's exact output? No — it *is* the digest prefix,
        // so the known-answer value below is asserted: it makes an accidental algorithm change a
        // failing test rather than a silently restarted bake on every upgrade.
        assert_eq!(printed, expected_fingerprint());

        // Trimming is not part of the identity: an operator adding a trailing space to the query
        // (YAML `>-` folding) must not restart a bake that is already running.
        let padded = MetricGate {
            query: format!("{}  ", gate.query),
            provider: format!(" {} ", gate.provider),
            ..gate.clone()
        };
        assert_eq!(fingerprint(&padded), printed);
        // The interval is a cadence, not a decision input.
        assert_eq!(
            fingerprint(&MetricGate {
                interval_seconds: 999,
                ..gate.clone()
            }),
            printed
        );

        // Collision resistance: distinct gates (including the classic concatenation ambiguity) do
        // not collide, over a set far larger than one `Application` can ever declare.
        let mut seen = std::collections::BTreeSet::new();
        let mut probes = vec![
            // ("ab","c") vs ("a","bc") — a naive concatenation would collide here.
            MetricGate {
                provider: "ab".to_owned(),
                query: "c".to_owned(),
                ..gate.clone()
            },
            MetricGate {
                provider: "a".to_owned(),
                query: "bc".to_owned(),
                ..gate.clone()
            },
        ];
        for index in 0..512_i32 {
            probes.push(MetricGate {
                after_wave: index,
                query: format!("up{{shard=\"{index}\"}}"),
                success_condition: format!("result[0] < 0.0{index}"),
                count: u32::try_from(index % 10 + 1).expect("1..=10"),
                ..gate.clone()
            });
        }
        for probe in &probes {
            assert!(
                seen.insert(fingerprint(probe)),
                "two distinct gates collided: {probe:?}"
            );
        }
        assert_eq!(seen.len(), probes.len());
    }

    /// The pinned known answer for [`gate`]: `sha256("ferriscd/metric-gate/v1" ‖ …)` truncated.
    ///
    /// Written out in full so a change to the encoding (a dropped field, a different separator, a
    /// different hash) fails here instead of silently invalidating every in-flight bake.
    fn expected_fingerprint() -> &'static str {
        "30e968c1fff5090bf5b5029db28d2edc"
    }

    // --- the `/status` message budget (nit) ---------------------------------------------------

    /// The ellipsis is *inside* the budget (`T20.3` nit): a message that had to be truncated is one
    /// character over `MAX_STATUS_MESSAGE_CHARS` otherwise, which is the exact limit the rest of
    /// `/status` is held to.
    #[test]
    fn a_truncated_message_fits_the_status_budget() {
        let exact = "m".repeat(MAX_STATUS_MESSAGE_CHARS);
        assert_eq!(bounded(&exact), exact, "an exact-fit message is untouched");

        let over = "m".repeat(MAX_STATUS_MESSAGE_CHARS + 50);
        let cut = bounded(&over);
        assert_eq!(cut.chars().count(), MAX_STATUS_MESSAGE_CHARS);
        assert!(cut.ends_with('…'), "{cut}");
        assert!(cut.starts_with("mmm"), "{cut}");

        // Multi-byte input is cut on a character boundary, never mid-codepoint.
        let emoji = "é".repeat(MAX_STATUS_MESSAGE_CHARS + 10);
        let cut = bounded(&emoji);
        assert_eq!(cut.chars().count(), MAX_STATUS_MESSAGE_CHARS);
        assert_eq!(
            cut.chars().filter(|char| *char == 'é').count(),
            MAX_STATUS_MESSAGE_CHARS - 1
        );

        // Clip is a *borrow* of at most `max_chars`, so callers can quote provider text safely.
        assert_eq!(clip("abcdef", 3), "abc");
        assert_eq!(clip("abc", 6), "abc");
        assert_eq!(clip("ééé", 2), "éé");
        assert_eq!(clip("", 4), "");
    }
}

//! Delivery adapters: one payload per service, plus the generic-webhook HMAC (`T19.4`).
//!
//! | Service | Body | Credential |
//! |---|---|---|
//! | Slack | `{"text": "..."}` (Incoming Webhook and Bot API both accept it) | the URL's own token |
//! | Microsoft Teams | `{"type":"message","attachments":[AdaptiveCard]}` (Workflow webhook) | the URL's own token |
//! | PagerDuty | Events API v2 `trigger` event with a stable `dedup_key` | `routingKey` **in the body** (the protocol requires it) |
//! | Generic webhook | FerrisCD's own JSON envelope | `X-FerrisCD-Signature-256: sha256=<hex HMAC>` |
//!
//! # Why the envelope is `serde_json`-built, not string-formatted
//!
//! A notification message is built from an `Application`'s identity, revision and condition message
//! — attacker-influenced strings. Formatting them into a JSON string is how a `"` in a namespace
//! label becomes a forged field, so every body here is serialized from a `serde_json::Value`;
//! escaping is the serializer's job, not ours.
//!
//! # Why the body is bounded
//!
//! The rendered message is already capped at
//! [`MAX_RENDERED_MESSAGE_BYTES`](crate::notifications::template::MAX_RENDERED_MESSAGE_BYTES); the
//! whole request body is capped at [`MAX_REQUEST_BODY_BYTES`]. A receiver is not a log sink, and a
//! multi-megabyte alert is one a receiver (or the network in front of it) rejects for every
//! subsequent alert too.

use ferriscd_crd::annotations;
use ferriscd_engine::diff::sha256;
use serde_json::{Map, Value, json};

use crate::notifications::{
    MessageTemplate, NotificationChannel, NotificationContext, NotificationService,
};

/// Header carrying the generic-webhook HMAC.
pub const SIGNATURE_HEADER: &str = "X-FerrisCD-Signature-256";

/// Header naming the trigger (`on-sync-failed`, ...) on generic webhooks.
pub const TRIGGER_HEADER: &str = "X-FerrisCD-Trigger";

/// Header carrying the deduplication key, so a receiver can collapse repeats exactly like
/// PagerDuty's `dedup_key`.
pub const DELIVERY_HEADER: &str = "X-FerrisCD-Delivery";

/// Header carrying the channel's bearer token (Slack **Bot API** `chat.postMessage`).
///
/// The token is sent as a header, never in the body: a body is what receivers log.
pub const AUTHORIZATION_HEADER: &str = "Authorization";

/// Upper bound on one request body (16 KiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;

/// One HTTP request the worker may send: a validated URL, headers, and a bounded JSON body.
///
/// `Debug` is hand-written (finding **R1-M4**): a `#[derive(Debug)]` here would print the raw
/// destination URL — whose path or query string *is* the Slack/Teams webhook token — and every
/// header **value**, one of which is the Slack bearer token and another the HMAC. Only the redacted
/// URL, the header names and the body's size are printable.
#[derive(Clone, PartialEq, Eq)]
pub struct Delivery {
    /// Destination URL (may carry a query-string token; never logged).
    pub url: String,
    /// Request headers (never include a credential in a header *name*, and values are only the
    /// signature/envelope metadata).
    pub headers: Vec<(String, String)>,
    /// JSON body, already bounded and escaped.
    pub body: String,
    /// The trigger this delivery reports (used for metrics and logs only).
    pub trigger: &'static str,
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery")
            .field(
                "url",
                &crate::notifications::redact_notification_url(&self.url),
            )
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("body_bytes", &self.body.len())
            .field("trigger", &self.trigger)
            .finish()
    }
}

/// Errors raised while building a delivery payload.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdapterError {
    /// The serialized body exceeds [`MAX_REQUEST_BODY_BYTES`].
    #[error("the {service} notification body is {bytes} bytes, over the {max}-byte limit")]
    BodyTooLarge {
        /// The service whose payload was too large.
        service: &'static str,
        /// Actual size.
        bytes: usize,
        /// Documented limit.
        max: usize,
    },
    /// The body could not be serialized (a serializer bug; never a user input problem).
    #[error("the {service} notification body could not be serialized: {message}")]
    Serialize {
        /// The service whose payload failed.
        service: &'static str,
        /// The serializer's message (contains no payload content).
        message: String,
    },
    /// A PagerDuty channel reached the adapter without its routing key.
    #[error("the PagerDuty channel {channel} has no routingKey")]
    MissingRoutingKey {
        /// The channel name.
        channel: String,
    },
}

/// Builds the request for `channel` from the rendered template.
///
/// # Errors
///
/// [`AdapterError`] for a body over [`MAX_REQUEST_BODY_BYTES`], a serialization failure, or a
/// PagerDuty channel without a routing key.
pub fn build_delivery(
    channel: &NotificationChannel,
    template: &MessageTemplate,
    context: &NotificationContext,
    dedup_key: &str,
) -> Result<Delivery, AdapterError> {
    let (title, body) = template.render(context);
    let (value, headers) = match channel.service {
        NotificationService::Slack => (
            slack_payload(&title, &body, channel.sink_channel()),
            Vec::new(),
        ),
        NotificationService::Teams => (teams_payload(&title, &body), Vec::new()),
        NotificationService::PagerDuty => (
            pagerduty_payload(channel, context, &title, &body, dedup_key)?,
            Vec::new(),
        ),
        NotificationService::Webhook => {
            let envelope = webhook_envelope(context, &title, &body, dedup_key);
            let serialized = serialize(channel.service, &envelope)?;
            let mut headers = vec![
                (
                    TRIGGER_HEADER.to_owned(),
                    context.resolve("trigger").unwrap_or_default().to_owned(),
                ),
                (DELIVERY_HEADER.to_owned(), dedup_key.to_owned()),
            ];
            if let Some(key) = channel.signing_key() {
                headers.push((
                    SIGNATURE_HEADER.to_owned(),
                    signature_header(key.expose(), serialized.as_bytes()),
                ));
            }
            return finish(channel, context, serialized, headers);
        }
    };
    let serialized = serialize(channel.service, &value)?;
    finish(channel, context, serialized, headers)
}

/// Adds the channel's bearer credential (when it has one) to `headers`.
fn with_bearer(channel: &NotificationChannel, headers: &mut Vec<(String, String)>) {
    if let Some(token) = channel.token()
        && let Ok(token) = std::str::from_utf8(token.expose())
    {
        headers.push((AUTHORIZATION_HEADER.to_owned(), format!("Bearer {token}")));
    }
}

fn finish(
    channel: &NotificationChannel,
    context: &NotificationContext,
    body: String,
    mut headers: Vec<(String, String)>,
) -> Result<Delivery, AdapterError> {
    if body.len() > MAX_REQUEST_BODY_BYTES {
        return Err(AdapterError::BodyTooLarge {
            service: channel.service.as_str(),
            bytes: body.len(),
            max: MAX_REQUEST_BODY_BYTES,
        });
    }
    with_bearer(channel, &mut headers);
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    {
        headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
    }
    Ok(Delivery {
        url: channel.url().to_owned(),
        headers,
        body,
        trigger: context.trigger(),
    })
}

fn serialize(service: NotificationService, value: &Value) -> Result<String, AdapterError> {
    serde_json::to_string(value).map_err(|err| AdapterError::Serialize {
        service: service.as_str(),
        message: err.to_string(),
    })
}

/// Slack: `{"text": "..."}`, which both Incoming Webhooks and `chat.postMessage` accept.
///
/// `chat.postMessage` additionally requires `channel` and a bearer token; both come from the channel
/// `Secret`, so one adapter serves the webhook and the Bot API path.
fn slack_payload(title: &str, body: &str, sink_channel: Option<&str>) -> Value {
    let mut payload = json!({
        "text": format!("*{title}*\n{body}"),
        "unfurl_links": false,
        "unfurl_media": false,
    });
    if let (Some(channel), Some(object)) = (sink_channel, payload.as_object_mut()) {
        object.insert("channel".to_owned(), Value::from(channel));
    }
    payload
}

/// Microsoft Teams *Workflow* webhooks: an Adaptive Card wrapped in a `message` attachment.
fn teams_payload(title: &str, body: &str) -> Value {
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": Value::Null,
            "content": {
                "$type": "AdaptiveCard",
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": title,
                        "weight": "Bolder",
                        "wrap": true
                    },
                    {
                        "type": "TextBlock",
                        "text": body,
                        "wrap": true
                    }
                ]
            }
        }]
    })
}

/// PagerDuty Events API v2 `trigger` event.
///
/// `dedup_key` is FerrisCD's own deduplication key, so PagerDuty collapses a repeat even across a
/// controller restart (where the in-memory LRU is empty).
fn pagerduty_payload(
    channel: &NotificationChannel,
    context: &NotificationContext,
    title: &str,
    body: &str,
    dedup_key: &str,
) -> Result<Value, AdapterError> {
    let Some(routing_key) = channel.routing_key() else {
        return Err(AdapterError::MissingRoutingKey {
            channel: channel.name.clone(),
        });
    };
    let routing_key =
        std::str::from_utf8(routing_key.expose()).map_err(|_| AdapterError::MissingRoutingKey {
            channel: channel.name.clone(),
        })?;
    // The routing key must be UTF-8 to travel in the JSON body; a non-UTF-8 key is refused rather
    // than sent as a mangled string.
    let trigger = context.trigger();
    let severity = if trigger == annotations::TRIGGER_SYNC_FAILED
        || trigger == annotations::TRIGGER_HEALTH_DEGRADED
    {
        "error"
    } else {
        "info"
    };
    Ok(json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": format!("{title}: {body}"),
            "source": format!(
                "ferriscd/{namespace}/{name}",
                namespace = context.resolve("app.namespace").unwrap_or_default(),
                name = context.resolve("app.name").unwrap_or_default(),
            ),
            "severity": severity,
            "component": context.resolve("app.name").unwrap_or_default(),
            "group": context.resolve("app.project").unwrap_or_default(),
            "class": context.resolve("trigger").unwrap_or_default(),
            "custom_details": redacted_details(context),
        },
    }))
}

/// Generic-webhook envelope: the redacted status facts, nothing else.
fn webhook_envelope(
    context: &NotificationContext,
    title: &str,
    body: &str,
    dedup_key: &str,
) -> Value {
    let mut app = Map::new();
    app.insert(
        "name".to_owned(),
        Value::from(context.resolve("app.name").unwrap_or_default()),
    );
    app.insert(
        "namespace".to_owned(),
        Value::from(context.resolve("app.namespace").unwrap_or_default()),
    );
    app.insert(
        "project".to_owned(),
        Value::from(context.resolve("app.project").unwrap_or_default()),
    );
    app.insert(
        "repoUrl".to_owned(),
        Value::from(context.resolve("app.repoUrl").unwrap_or_default()),
    );
    app.insert(
        "revision".to_owned(),
        Value::from(context.resolve("app.revision").unwrap_or_default()),
    );
    json!({
        "schemaVersion": "1",
        "trigger": context.resolve("trigger").unwrap_or_default(),
        "service": context.resolve("service").unwrap_or_default(),
        "recipient": context.resolve("recipient").unwrap_or_default(),
        "dedupKey": dedup_key,
        "title": title,
        "message": body,
        "app": Value::Object(app),
        "status": {
            "sync": context.resolve("app.syncStatus").unwrap_or_default(),
            "health": context.resolve("app.healthStatus").unwrap_or_default(),
            "message": context.resolve("app.message").unwrap_or_default(),
            "observedGeneration": context.resolve("app.observedGeneration").unwrap_or_default(),
        },
    })
}

fn redacted_details(context: &NotificationContext) -> Value {
    json!({
        "app": context.resolve("app.name").unwrap_or_default(),
        "namespace": context.resolve("app.namespace").unwrap_or_default(),
        "project": context.resolve("app.project").unwrap_or_default(),
        "revision": context.resolve("app.revision").unwrap_or_default(),
        "syncStatus": context.resolve("app.syncStatus").unwrap_or_default(),
        "healthStatus": context.resolve("app.healthStatus").unwrap_or_default(),
        "observedGeneration": context.resolve("app.observedGeneration").unwrap_or_default(),
    })
}

/// HMAC-SHA256 (RFC 2104) over the workspace's SHA-256.
///
/// The workspace deliberately has one SHA-256 (`ferriscd_engine::diff::sha256`, pinned to the
/// FIPS 180-4 known-answer vectors): `ferriscd-server`'s GitHub webhook verifier builds its HMAC on
/// the same primitive, and this module does the same instead of pulling a second hash into the
/// build. A vetted implementation (`ring::hmac`) should replace it the moment one is a direct
/// dependency.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend(key_block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(key_block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&sha256::digest(&inner));
    sha256::digest(&outer)
}

/// The `X-FerrisCD-Signature-256` header value (`sha256=<lowercase hex>`).
#[must_use]
pub fn signature_header(key: &[u8], body: &[u8]) -> String {
    let digest = hmac_sha256(key, body);
    let mut header = String::with_capacity(7 + 64);
    header.push_str("sha256=");
    for byte in digest {
        use std::fmt::Write as _;
        // Writing into a `String` cannot fail; the `let _` keeps the crate's no-`unwrap` rule.
        let _ = write!(header, "{byte:02x}");
    }
    header
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::annotations::TRIGGER_SYNC_FAILED;
    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::status::{
        ApplicationStatus, Condition, ConditionStatus, HealthState, HealthStatus, SyncState,
        SyncStatus,
    };
    use ferriscd_crd::{
        Application, ApplicationSpec, DestinationSpec, GitSourceSpec, RendererSpec, SourceSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    use crate::notifications::SecretValue;
    use crate::notifications::template::NotificationContext;

    use super::*;

    const SIGNING_KEY: &str = "hmac-signing-key-material";

    fn context(trigger: &'static str) -> NotificationContext {
        let spec = ApplicationSpec {
            project: "payments".to_owned(),
            service_account_name: None,
            source: Some(SourceSpec {
                git: Some(GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: RendererSpec::default(),
            }),
            sources: Vec::new(),
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut app = Application::new("demo-app", spec);
        app.metadata.namespace = Some("ferriscd-system".to_owned());
        let status = ApplicationStatus {
            observed_generation: Some(3),
            sync: Some(SyncState::new(
                SyncStatus::OutOfSync,
                Some("c0ffee1234".to_owned()),
            )),
            health: Some(HealthState::new(HealthStatus::Degraded)),
            conditions: vec![Condition::ready(
                ConditionStatus::False,
                "SyncFailed",
                "apply failed: 422 Immutable on Deployment/payments/api",
                Time("2026-11-24T12:00:00Z".parse().expect("timestamp")),
            )],
            ..ApplicationStatus::default()
        };
        NotificationContext::from_status(&app, &status, trigger, "webhook", "internal-automation")
    }

    fn channel(service: NotificationService) -> NotificationChannel {
        let (url, routing) = match service {
            NotificationService::PagerDuty => (
                "https://events.pagerduty.com/v2/enqueue",
                Some(SecretValue::new(b"pd-routing-key".to_vec())),
            ),
            NotificationService::Slack => {
                ("https://hooks.slack.com/services/T000/B000/token", None)
            }
            NotificationService::Teams => (
                "https://prod-00.westeurope.logic.azure.com/workflows/xyz",
                None,
            ),
            NotificationService::Webhook => ("https://automation.example.com/hooks/ferriscd", None),
        };
        NotificationChannel::new(
            "internal-automation",
            service,
            url,
            Some(SecretValue::new(SIGNING_KEY.as_bytes())),
            routing,
        )
        .expect("a valid test channel")
    }

    /// **Verification bullet (5), HMAC half:** the signature matches the published RFC 4231
    /// vectors, so a receiver implementing them verifies FerrisCD's header.
    #[test]
    fn hmac_sha256_matches_the_rfc_4231_vectors() {
        // Case 1: 20-byte key of 0x0b, message "Hi There".
        assert_eq!(
            signature_header(&[0x0b; 20], b"Hi There"),
            "sha256=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Case 2: the classic "Jefe" vector.
        assert_eq!(
            signature_header(b"Jefe", b"what do ya want for nothing?"),
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Case 6: a key longer than the 64-byte block is hashed first.
        assert_eq!(
            signature_header(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "sha256=60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // A receiver recomputes the same value from the raw body.
        let body = br#"{"a":1}"#;
        let header = signature_header(SIGNING_KEY.as_bytes(), body);
        assert_eq!(
            header,
            signature_header(SIGNING_KEY.as_bytes(), body),
            "signing is deterministic"
        );
        assert_ne!(
            header,
            signature_header(b"another-key", body),
            "a different key signs differently"
        );
    }

    /// Each service gets the payload its API documents.
    #[test]
    fn every_service_builds_its_documented_payload() {
        let template = MessageTemplate::default_for(TRIGGER_SYNC_FAILED);
        let ctx = context(TRIGGER_SYNC_FAILED);

        // Slack: a single `text` field, no attachments.
        let slack = build_delivery(
            &channel(NotificationService::Slack),
            &template,
            &ctx,
            "key-1",
        )
        .expect("slack delivery");
        let body: Value = serde_json::from_str(&slack.body).expect("valid JSON");
        assert!(
            body["text"]
                .as_str()
                .expect("text")
                .contains("ferriscd-system/demo-app")
        );
        assert!(body.get("attachments").is_none());
        assert_eq!(
            header(&slack, "Content-Type"),
            Some("application/json"),
            "every body is JSON"
        );

        // Teams: an Adaptive Card inside a `message` attachment.
        let teams = build_delivery(
            &channel(NotificationService::Teams),
            &template,
            &ctx,
            "key-1",
        )
        .expect("teams delivery");
        let body: Value = serde_json::from_str(&teams.body).expect("valid JSON");
        assert_eq!(body["type"], "message");
        assert_eq!(
            body["attachments"][0]["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        assert_eq!(body["attachments"][0]["content"]["$type"], "AdaptiveCard");
        assert_eq!(
            body["attachments"][0]["content"]["body"][0]["type"],
            "TextBlock"
        );
        assert!(
            body["attachments"][0]["content"]["body"][1]["text"]
                .as_str()
                .expect("body text")
                .contains("demo-app")
        );

        // PagerDuty: an Events API v2 trigger with a stable dedup key.
        let pagerduty = build_delivery(
            &channel(NotificationService::PagerDuty),
            &template,
            &ctx,
            "ferriscd:default/demo-app:on-sync-failed:3",
        )
        .expect("pagerduty delivery");
        let body: Value = serde_json::from_str(&pagerduty.body).expect("valid JSON");
        assert_eq!(body["event_action"], "trigger");
        assert_eq!(
            body["dedup_key"],
            "ferriscd:default/demo-app:on-sync-failed:3"
        );
        assert_eq!(body["payload"]["severity"], "error");
        assert_eq!(
            body["payload"]["source"],
            "ferriscd/ferriscd-system/demo-app"
        );
        assert_eq!(body["routing_key"], "pd-routing-key");
        assert_eq!(body["payload"]["class"], TRIGGER_SYNC_FAILED);

        // Generic webhook: the FerrisCD envelope plus its signature header.
        let webhook = build_delivery(
            &channel(NotificationService::Webhook),
            &template,
            &ctx,
            "key-1",
        )
        .expect("webhook delivery");
        let body: Value = serde_json::from_str(&webhook.body).expect("valid JSON");
        assert_eq!(body["trigger"], TRIGGER_SYNC_FAILED);
        assert_eq!(body["app"]["name"], "demo-app");
        assert_eq!(body["app"]["revision"], "c0ffee1234");
        assert_eq!(body["status"]["sync"], "OutOfSync");
        assert_eq!(body["status"]["health"], "Degraded");
        assert_eq!(body["dedupKey"], "key-1");
        assert_eq!(header(&webhook, TRIGGER_HEADER), Some(TRIGGER_SYNC_FAILED));
        assert_eq!(header(&webhook, DELIVERY_HEADER), Some("key-1"));
        let signature = header(&webhook, SIGNATURE_HEADER).expect("the generic webhook is signed");
        assert_eq!(
            signature,
            signature_header(SIGNING_KEY.as_bytes(), webhook.body.as_bytes()),
            "the signature covers exactly the bytes that are posted"
        );
    }

    /// **Slack Bot API** (`chat.postMessage`): the bearer token travels in a header, the sink channel
    /// in the body, and neither the token nor the URL is printable.
    #[test]
    fn the_slack_bot_api_channel_sends_a_bearer_token_and_channel() {
        let template = MessageTemplate::default_for(TRIGGER_SYNC_FAILED);
        let ctx = context(TRIGGER_SYNC_FAILED);
        let bot = NotificationChannel::with_bearer(
            "slack-bot",
            NotificationService::Slack,
            "https://slack.com/api/chat.postMessage",
            None,
            None,
            Some(SecretValue::new(b"xoxb-bot-token".to_vec())),
            Some("#payments-alerts".to_owned()),
        )
        .expect("a valid Bot API channel");

        let delivery = build_delivery(&bot, &template, &ctx, "key-1").expect("delivery");
        assert_eq!(
            header(&delivery, AUTHORIZATION_HEADER),
            Some("Bearer xoxb-bot-token")
        );
        let body: Value = serde_json::from_str(&delivery.body).expect("valid JSON");
        assert_eq!(body["channel"], "#payments-alerts");
        assert!(
            !delivery.body.contains("xoxb-bot-token"),
            "{}",
            delivery.body
        );
        let printed = format!("{bot:?}");
        assert!(!printed.contains("xoxb-bot-token"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    /// A receiver can verify the signature and detect tampering; an unsigned channel sends none.
    #[test]
    fn the_generic_webhook_signature_verifies_and_detects_tampering() {
        let template = MessageTemplate::default_for(TRIGGER_SYNC_FAILED);
        let ctx = context(TRIGGER_SYNC_FAILED);
        let signed = build_delivery(
            &channel(NotificationService::Webhook),
            &template,
            &ctx,
            "key-1",
        )
        .expect("webhook delivery");
        let expected = signature_header(SIGNING_KEY.as_bytes(), signed.body.as_bytes());
        assert_eq!(header(&signed, SIGNATURE_HEADER), Some(expected.as_str()));

        // Tampering with one byte of the body invalidates it.
        let tampered = format!("{}}}", signed.body);
        assert_ne!(
            signature_header(SIGNING_KEY.as_bytes(), tampered.as_bytes()),
            expected
        );

        // A channel without a signing key sends the envelope unsigned (and still delivers).
        let unsigned = NotificationChannel::new(
            "plain",
            NotificationService::Webhook,
            "https://automation.example.com/hooks/ferriscd",
            None,
            None,
        )
        .expect("unsigned channel");
        let delivery =
            build_delivery(&unsigned, &template, &ctx, "key-1").expect("unsigned delivery");
        assert!(header(&delivery, SIGNATURE_HEADER).is_none());
        assert!(header(&delivery, TRIGGER_HEADER).is_some());
    }

    /// **Verification bullet (5), leakage half:** no credential reaches a body or a header —
    /// neither the HMAC key, nor the PagerDuty routing key outside the one field its protocol
    /// requires, nor a webhook token.
    #[test]
    fn no_channel_credential_reaches_a_payload_or_a_header() {
        let template = MessageTemplate::default_for(TRIGGER_SYNC_FAILED);
        let ctx = context(TRIGGER_SYNC_FAILED);

        for service in [
            NotificationService::Slack,
            NotificationService::Teams,
            NotificationService::Webhook,
        ] {
            let channel = channel(service);
            let delivery = build_delivery(&channel, &template, &ctx, "key-1").expect("delivery");
            assert!(
                !delivery.body.contains(SIGNING_KEY),
                "{service}: the signing key leaked into the body"
            );
            for (name, value) in &delivery.headers {
                assert!(
                    !value.contains(SIGNING_KEY),
                    "{service}: the signing key leaked into {name}"
                );
                assert!(
                    !value.contains("pd-routing-key"),
                    "{service}: the routing key leaked into {name}"
                );
            }
            // The URL token is never echoed back into the payload either.
            assert!(!delivery.body.contains("/services/T000/B000/token"));
        }

        // A bearer token only ever travels in the `Authorization` header, never in a body.
        let bot = NotificationChannel::with_bearer(
            "bot",
            NotificationService::Webhook,
            "https://automation.example.com/hook",
            None,
            None,
            Some(SecretValue::new(b"bot-token-material".to_vec())),
            None,
        )
        .expect("a channel with a bearer token");
        let delivery = build_delivery(&bot, &template, &ctx, "key-1").expect("delivery");
        assert!(
            !delivery.body.contains("bot-token-material"),
            "{}",
            delivery.body
        );
        for (name, value) in &delivery.headers {
            if name.eq_ignore_ascii_case(AUTHORIZATION_HEADER) {
                assert_eq!(value, "Bearer bot-token-material");
            } else {
                assert!(
                    !value.contains("bot-token-material"),
                    "the token leaked into {name}"
                );
            }
        }

        // PagerDuty must carry its routing key in the body (that *is* the protocol), and nothing
        // else from the channel does.
        let pagerduty = build_delivery(
            &channel(NotificationService::PagerDuty),
            &template,
            &ctx,
            "key-1",
        )
        .expect("pagerduty delivery");
        assert!(pagerduty.body.contains("pd-routing-key"));
        assert!(!pagerduty.body.contains(SIGNING_KEY));
        assert!(
            !format!("{:?}", channel(NotificationService::PagerDuty)).contains("pd-routing-key"),
            "the channel Debug redacts the routing key"
        );
    }

    /// The request body is bounded: a body over the limit is refused, never posted, and a rendered
    /// message (itself capped) fits comfortably inside it.
    #[test]
    fn oversized_bodies_are_refused() {
        let ctx = context(TRIGGER_SYNC_FAILED);
        let channel = channel(NotificationService::Slack);

        // A rendered message is capped well below the request limit, so no template can exceed it.
        let huge_template = MessageTemplate::parse(
            "title",
            &format!(
                "{{{{app.message}}}}{}",
                "x".repeat(MAX_REQUEST_BODY_BYTES * 2)
            ),
        )
        .expect("valid template");
        let delivery = build_delivery(&channel, &huge_template, &ctx, "key-1")
            .expect("the rendered message is capped, so the body fits");
        assert!(delivery.body.len() <= MAX_REQUEST_BODY_BYTES);

        // The last line of defence, exercised directly: a body over the limit is refused.
        let err = finish(
            &channel,
            &ctx,
            "x".repeat(MAX_REQUEST_BODY_BYTES + 1),
            Vec::new(),
        )
        .expect_err("the body must be refused");
        assert!(
            matches!(err, AdapterError::BodyTooLarge { max, .. } if max == MAX_REQUEST_BODY_BYTES),
            "{err:?}"
        );
    }

    /// A PagerDuty channel that somehow lost its routing key is refused at build time.
    #[test]
    fn a_pagerduty_channel_without_a_routing_key_is_refused_by_the_adapter() {
        let template = MessageTemplate::default_for(TRIGGER_SYNC_FAILED);
        let ctx = context(TRIGGER_SYNC_FAILED);
        let broken = NotificationChannel {
            name: "pd".to_owned(),
            service: NotificationService::PagerDuty,
            url: "https://events.pagerduty.com/v2/enqueue".to_owned(),
            signing_key: None,
            routing_key: None,
            token: None,
            sink: None,
        };
        let err = build_delivery(&broken, &template, &ctx, "key-1")
            .expect_err("a routing key is required");
        assert!(
            matches!(err, AdapterError::MissingRoutingKey { .. }),
            "{err:?}"
        );
    }

    /// **Finding R1-M4:** `Delivery`'s hand-written `Debug` prints the **redacted** destination, the
    /// header *names* and the body's size — never the URL path/query (a Slack/Teams webhook token
    /// lives there), never a header value (the HMAC and the Slack bearer token are header values),
    /// and never the body (it repeats the `Application`'s condition message).
    #[test]
    fn delivery_debug_redacts_the_url_path_the_header_values_and_the_body() {
        let template = MessageTemplate::default_for(TRIGGER_SYNC_FAILED);
        let ctx = context(TRIGGER_SYNC_FAILED);

        // A `derive(Debug)` would print this whole URL: the path segment is the replayable token.
        let mut webhook = NotificationChannel::with_bearer(
            "internal-automation",
            NotificationService::Webhook,
            "https://automation.example.com/services/T000/B000/superSecretPathToken?token=abc123",
            Some(SecretValue::new(SIGNING_KEY.as_bytes())),
            None,
            Some(SecretValue::new(b"xoxb-bearer-token".to_vec())),
            None,
        )
        .expect("a valid channel");
        let delivery = build_delivery(&webhook, &template, &ctx, "key-1").expect("a delivery");
        let printed = format!("{delivery:?}");
        for secret in [
            "superSecretPathToken",
            "abc123",
            SIGNING_KEY,
            "xoxb-bearer-token",
            // The condition message the payload carries (the rendered body itself).
            "422 Immutable",
        ] {
            assert!(
                !printed.contains(secret),
                "{secret:?} must never be printed by `Delivery`'s Debug: {printed}"
            );
        }
        // What *is* printable: the destination host (diagnostics) and the header names.
        assert!(printed.contains("automation.example.com"), "{printed}");
        for name in [
            SIGNATURE_HEADER,
            TRIGGER_HEADER,
            DELIVERY_HEADER,
            AUTHORIZATION_HEADER,
        ] {
            assert!(
                printed.contains(name),
                "header name {name} is useful: {printed}"
            );
        }
        assert_eq!(
            delivery
                .headers
                .iter()
                .filter(|(name, _)| name == SIGNATURE_HEADER)
                .count(),
            1,
            "the signature header really is present, so the redaction above is not vacuous"
        );
        assert!(
            printed.contains("body_bytes"),
            "only the body size is printable: {printed}"
        );
        assert!(
            printed.contains(&format!("body_bytes: {}", delivery.body.len())),
            "the printed size is the real one (so `body_bytes` is not a vacuous field): {printed}"
        );

        // The same contract for the unsigned/credential-free shapes (Slack, Teams, PagerDuty).
        for service in [
            NotificationService::Slack,
            NotificationService::Teams,
            NotificationService::PagerDuty,
        ] {
            let delivery =
                build_delivery(&channel(service), &template, &ctx, "key-1").expect("a delivery");
            let printed = format!("{delivery:?}");
            assert!(!printed.contains(SIGNING_KEY), "{service}: {printed}");
            assert!(!printed.contains("pd-routing-key"), "{service}: {printed}");
            assert!(
                !printed.contains("422 Immutable"),
                "{service}: the body is never printed: {printed}"
            );
            assert!(
                printed.contains(&format!("body_bytes: {}", delivery.body.len())),
                "{service}: the size is printed: {printed}"
            );
        }

        // A `Secret`-free channel is no different: the URL path is still redacted.
        webhook = NotificationChannel::new(
            "internal-automation",
            NotificationService::Webhook,
            "https://automation.example.com/services/T000/B000/superSecretPathToken",
            None,
            None,
        )
        .expect("a valid channel");
        let delivery = build_delivery(&webhook, &template, &ctx, "key-1").expect("a delivery");
        assert!(!format!("{delivery:?}").contains("superSecretPathToken"));
    }

    fn header<'a>(delivery: &'a Delivery, name: &str) -> Option<&'a str> {
        delivery
            .headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

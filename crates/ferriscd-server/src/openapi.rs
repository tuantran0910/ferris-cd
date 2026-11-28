//! The OpenAPI 3.1 contract (`T14.1`).
//!
//! One document serves three consumers, and they must never drift:
//!
//! * `GET /api/v1/openapi.json` — the running server's contract,
//! * `docs/api/openapi.json` — the committed artifact `ferriscd server openapi` writes (a test in
//!   this crate fails when the two differ, exactly like the CRD drift check), and
//! * `apps/ferriscd-web/src/api/schema.d.ts` — the TypeScript types generated from it (`T16.1`).
//!
//! The security scheme is declared even though authentication lands in `T14.3`: the operation
//! contract (which routes require a bearer token) is part of the API shape, and the router already
//! reads it from [`crate::auth::AuthPolicy`] with the protected/webhook/probe split in place.

use utoipa::OpenApi;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};

/// The API description, generated from the handler annotations and the DTO schemas.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "FerrisCD Control Plane API",
        version = "0.1.0",
        description = "In-process REST API of the FerrisCD GitOps control plane (ADR-002). \
                       `GET .../diff` and `GET .../resources` are computed live from the same \
                       `RepoCache`, renderer cache, `ClusterManager` and SSA dry-run diff the \
                       controller reconciles with, so an API answer can never disagree with the \
                       next reconcile. All diff payloads are `Secret`-redacted before they leave \
                       the engine.",
        license(name = "Apache-2.0"),
    ),
    paths(
        crate::api::healthz,
        crate::api::readyz,
        crate::api::list_applications,
        crate::api::stream_applications,
        crate::api::get_application,
        crate::api::get_resources,
        crate::api::get_diff,
        crate::api::get_application_events,
        crate::api::sync_application,
        crate::api::rollback_application,
        crate::api::list_projects,
        crate::api::list_clusters,
        crate::api::openapi_document,
        crate::webhooks::github,
        crate::webhooks::gitlab,
    ),
    components(schemas(
        crate::api::HealthResponse,
        crate::api::ReadyResponse,
        crate::api::ApplicationListView,
        crate::api::ApplicationSummary,
        crate::api::ApplicationDetailView,
        crate::api::SourceView,
        crate::api::DestinationView,
        crate::api::SyncView,
        crate::api::HealthView,
        crate::api::ConditionView,
        crate::api::HistoryView,
        crate::api::OperationView,
        crate::api::ResourceGraphView,
        crate::api::ResourceNodeView,
        crate::api::DiffView,
        crate::api::DiffSummaryView,
        crate::api::DiffResourceView,
        crate::api::DiffChangeView,
        crate::api::DiffConflictView,
        crate::api::SyncRequestBody,
        crate::api::RollbackRequestBody,
        crate::api::OperationResponse,
        crate::api::ProjectListView,
        crate::api::ProjectView,
        crate::api::ProjectSyncWindowView,
        crate::api::SyncWindowGateView,
        crate::api::ClusterListView,
        crate::api::ClusterView,
        crate::api::ApplicationEventListView,
        crate::api::ApplicationEventView,
        crate::webhooks::WebhookResponse,
        crate::error::ApiErrorBody,
        crate::error::ApiErrorDetail,
    )),
    tags(
        (name = "health", description = "Liveness and readiness probes"),
        (name = "applications", description = "Applications, live resources, diffs, and manual operations"),
        (name = "platform", description = "Projects, clusters, and the OpenAPI contract"),
        (name = "webhooks", description = "GitHub/GitLab push webhooks (secret-authenticated)"),
    ),
    modifiers(&BearerAuth),
)]
pub struct ApiDoc;

/// Declares the bearer scheme every protected route documents (`T14.3`).
struct BearerAuth;

impl utoipa::Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );
    }
}

/// The generated document.
#[must_use]
pub fn document() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

/// The document as JSON, for `GET /api/v1/openapi.json`.
///
/// # Errors
///
/// Only a serialization failure. It is returned rather than swallowed: a handler that answered
/// `200 null` because the document could not be serialized would hand the UI (and the TypeScript
/// codegen) an empty contract that looks valid, which is worse than a loud `502`
/// (finding `P14-M3`).
pub fn document_value() -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(document())
}

/// The document as pretty-printed JSON: the exact bytes `docs/api/openapi.json` holds.
///
/// # Errors
///
/// Only a serialization failure, which is a programming error (every type in the document is
/// `serde`-serializable by construction).
pub fn document_json_pretty() -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&document())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document must be a valid OpenAPI 3.1 object with the paths and components the roadmap
    /// promises (verification bullet: "OpenAPI JSON schema validity check").
    #[test]
    fn the_document_declares_every_endpoint_and_schema() {
        let value = document_value().expect("the document is serializable");
        let openapi = value.as_object().expect("the document is an object");
        let version = openapi
            .get("openapi")
            .and_then(|value| value.as_str())
            .expect("a version string");
        assert!(
            version.starts_with("3.1"),
            "utoipa must emit OpenAPI 3.1, got {version}"
        );
        assert!(openapi.contains_key("info"));

        let paths = openapi
            .get("paths")
            .and_then(|value| value.as_object())
            .expect("paths");
        for path in [
            "/healthz",
            "/readyz",
            "/api/v1/applications",
            "/api/v1/applications/stream",
            "/api/v1/applications/{namespace}/{name}",
            "/api/v1/applications/{namespace}/{name}/resources",
            "/api/v1/applications/{namespace}/{name}/diff",
            "/api/v1/applications/{namespace}/{name}/events",
            "/api/v1/applications/{namespace}/{name}/sync",
            "/api/v1/applications/{namespace}/{name}/rollback",
            "/api/v1/projects",
            "/api/v1/clusters",
            "/api/v1/openapi.json",
            "/api/v1/webhooks/github",
            "/api/v1/webhooks/gitlab",
        ] {
            assert!(paths.contains_key(path), "the document must declare {path}");
        }

        let schemas = openapi["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        for schema in [
            "ApplicationSummary",
            "ApplicationDetailView",
            "ResourceGraphView",
            "DiffView",
            "OperationResponse",
            "ProjectView",
            "ClusterView",
            "ApplicationEventListView",
            "ApplicationEventView",
            "WebhookResponse",
            "ApiErrorBody",
        ] {
            assert!(
                schemas.contains_key(schema),
                "the document must declare the {schema} schema"
            );
        }

        let security = &openapi["components"]["securitySchemes"];
        assert_eq!(security["bearer_auth"]["scheme"], "bearer");
        assert_eq!(security["bearer_auth"]["type"], "http");
    }

    /// Every protected operation documents the bearer requirement, and the probes do not: the
    /// generated client must not send a token to `/healthz`.
    #[test]
    fn the_security_requirements_match_the_route_groups() {
        let value = document_value().expect("the document is serializable");
        let paths = &value["paths"];
        for protected in [
            "/api/v1/applications",
            "/api/v1/applications/stream",
            "/api/v1/applications/{namespace}/{name}",
            "/api/v1/applications/{namespace}/{name}/resources",
            "/api/v1/applications/{namespace}/{name}/diff",
            "/api/v1/applications/{namespace}/{name}/events",
            "/api/v1/applications/{namespace}/{name}/sync",
            "/api/v1/applications/{namespace}/{name}/rollback",
            "/api/v1/projects",
            "/api/v1/clusters",
            "/api/v1/openapi.json",
        ] {
            let operation = paths[protected]
                .as_object()
                .and_then(|methods| methods.values().next())
                .expect("an operation");
            assert_eq!(
                operation["security"][0]["bearer_auth"],
                serde_json::json!([]),
                "{protected} must document the bearer requirement"
            );
        }
        for public in ["/healthz", "/readyz"] {
            let operation = paths[public]
                .as_object()
                .and_then(|methods| methods.values().next())
                .expect("an operation");
            assert!(
                operation.get("security").is_none(),
                "{public} must be documented as unauthenticated"
            );
        }
        for webhook in ["/api/v1/webhooks/github", "/api/v1/webhooks/gitlab"] {
            let operation = paths[webhook]
                .as_object()
                .and_then(|methods| methods.values().next())
                .expect("an operation");
            assert!(
                operation.get("security").is_none(),
                "{webhook} is authenticated by its own secret, not by a bearer token"
            );
            assert_eq!(
                operation["responses"]["413"]["description"],
                "Payload too large"
            );
        }
    }

    /// The pretty export is what `docs/api/openapi.json` must contain, byte for byte.
    #[test]
    fn the_pretty_export_round_trips() {
        let pretty = document_json_pretty().expect("serializable");
        let parsed: serde_json::Value = serde_json::from_str(&pretty).expect("valid JSON");
        assert_eq!(parsed, document_value().expect("serializable"));
        assert!(pretty.ends_with('}'));
    }
}

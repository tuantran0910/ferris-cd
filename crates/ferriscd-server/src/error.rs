//! The one error shape the REST API returns.
//!
//! Two rules live here:
//!
//! * **One JSON shape.** Every failure is `{"error":{"code":"...","message":"..."}}` with a stable,
//!   machine-readable `code` and an HTTP status the UI can branch on, so the TypeScript client
//!   generated from the OpenAPI document (`T16.1`) never has to parse prose.
//! * **No secret material.** Messages come from the controller/engine, which already quote
//!   repository URLs through `redact_repo_url` and never echo `Secret` values, credential
//!   material, or request headers. On top of that every message is bounded
//!   ([`MAX_ERROR_MESSAGE_CHARS`]) and the payload of a rejected request is never reflected back.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Longest error message the API will render.
///
/// The controller bounds its own messages (`reconcile::bounded`); this is the API's independent
/// guard so a future caller cannot grow a response without bound.
pub const MAX_ERROR_MESSAGE_CHARS: usize = 512;

/// Every failure mode of the API.
///
/// The variants map 1:1 onto the status codes an operator/UI has to distinguish: "it does not
/// exist" (404), "the cluster says no, and retrying will not help" (409/422), "you are not
/// authenticated/authorized" (401/403, the `T14.3`/`T14.4` seam), and "the backend could not
/// answer right now" (502) which a client may retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// No such `Application`/`AppProject`.
    NotFound {
        /// Kind that was looked up (`Application`).
        kind: String,
        /// Namespace that was searched.
        namespace: String,
        /// Object name that was requested.
        name: String,
    },
    /// The request body is missing, malformed, or unacceptable for another reason that is the
    /// caller's to fix.
    BadRequest {
        /// Explanation, secret-free.
        message: String,
    },
    /// The request conflicts with the object's current state (an operation is already pending, or
    /// the object changed under us — the compare-and-swap precondition failed).
    Conflict {
        /// Explanation, secret-free.
        message: String,
    },
    /// The request is understood but cannot be honoured as written (an unknown history id, a body
    /// asking for something `v1.0` cannot do).
    Unprocessable {
        /// Explanation, secret-free.
        message: String,
    },
    /// No (valid) identity was presented. Produced only by the `T14.3` seam.
    Unauthorized {
        /// Explanation, secret-free.
        message: String,
    },
    /// An identity was presented but is not allowed to perform the request. `T14.4` seam.
    Forbidden {
        /// Explanation, secret-free.
        message: String,
    },
    /// The cluster, the Git remote, or the renderer could not answer. Retryable by nature.
    Backend {
        /// Explanation, secret-free and bounded.
        message: String,
    },
    /// The request body exceeded the endpoint's limit (`T14.2`: 1 MiB for webhooks).
    PayloadTooLarge {
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },
}

impl ApiError {
    /// Builds a [`Self::NotFound`] for `kind` `namespace/name`.
    #[must_use]
    pub fn not_found(kind: impl Into<String>, namespace: &str, name: &str) -> Self {
        Self::NotFound {
            kind: kind.into(),
            namespace: namespace.to_owned(),
            name: name.to_owned(),
        }
    }

    /// Builds a [`Self::BadRequest`].
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: bounded(&message.into()),
        }
    }

    /// Builds a [`Self::Conflict`].
    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: bounded(&message.into()),
        }
    }

    /// Builds an [`Self::Unprocessable`].
    #[must_use]
    pub fn unprocessable(message: impl Into<String>) -> Self {
        Self::Unprocessable {
            message: bounded(&message.into()),
        }
    }

    /// Builds an [`Self::Unauthorized`].
    #[must_use]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized {
            message: bounded(&message.into()),
        }
    }

    /// Builds an [`Self::Backend`] from any engine/controller failure.
    ///
    /// The failure is rendered through `Display` and bounded: nothing else is copied, and the
    /// engine's own messages are already secret-free (they quote repository URLs through
    /// `redact_repo_url` and never print `Secret` data).
    #[must_use]
    pub fn backend(err: &(impl std::fmt::Display + ?Sized)) -> Self {
        Self::Backend {
            message: bounded(&err.to_string()),
        }
    }

    /// The stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "NotFound",
            Self::BadRequest { .. } => "BadRequest",
            Self::Conflict { .. } => "Conflict",
            Self::Unprocessable { .. } => "Unprocessable",
            Self::Unauthorized { .. } => "Unauthorized",
            Self::Forbidden { .. } => "Forbidden",
            Self::Backend { .. } => "BackendUnavailable",
            Self::PayloadTooLarge { .. } => "PayloadTooLarge",
        }
    }

    /// The HTTP status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::Unprocessable { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::Backend { .. } => StatusCode::BAD_GATEWAY,
            Self::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    /// The rendered message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::NotFound {
                kind,
                namespace,
                name,
            } => format!("{kind} {namespace}/{name} not found"),
            Self::BadRequest { message }
            | Self::Conflict { message }
            | Self::Unprocessable { message }
            | Self::Unauthorized { message }
            | Self::Forbidden { message }
            | Self::Backend { message } => message.clone(),
            Self::PayloadTooLarge { limit } => {
                format!("the request body exceeds the {limit} byte limit")
            }
        }
    }
}

/// The body of a failed request.
///
/// `Deserialize` as well as `Serialize` because it is the contract in **both** directions: the
/// `ferriscd` CLI (`T14.5`) maps a refused request back onto this shape instead of re-inventing one.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorBody {
    /// The failure.
    pub error: ApiErrorDetail,
}

/// One failure, in the shape the OpenAPI document declares.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorDetail {
    /// Stable code (`NotFound`, `BadRequest`, `Conflict`, `Unprocessable`, `Unauthorized`,
    /// `Forbidden`, `BackendUnavailable`, `PayloadTooLarge`).
    pub code: String,
    /// Human-readable explanation, secret-free.
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Rendered through the same bounded, secret-free message the HTTP body carries.
        f.write_str(&self.message())
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiErrorBody {
            error: ApiErrorDetail {
                code: self.code().to_owned(),
                message: self.message(),
            },
        };
        (self.status(), Json(body)).into_response()
    }
}

impl From<ApiError> for ApiErrorBody {
    fn from(error: ApiError) -> Self {
        Self {
            error: ApiErrorDetail {
                code: error.code().to_owned(),
                message: error.message(),
            },
        }
    }
}

/// Truncates `message` to [`MAX_ERROR_MESSAGE_CHARS`] characters on a boundary.
fn bounded(message: &str) -> String {
    let message = message.trim();
    if message.chars().count() <= MAX_ERROR_MESSAGE_CHARS {
        return message.to_owned();
    }
    let mut bounded: String = message.chars().take(MAX_ERROR_MESSAGE_CHARS).collect();
    bounded.push('…');
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_a_distinct_code_and_status() {
        let variants = [
            ApiError::not_found("Application", "ferriscd-system", "payments"),
            ApiError::bad_request("malformed payload"),
            ApiError::conflict("nothing to do"),
            ApiError::unprocessable("nope"),
            ApiError::unauthorized("missing bearer token"),
            ApiError::Forbidden {
                message: "denied".to_owned(),
            },
            ApiError::backend(&"cluster unreachable"),
            ApiError::PayloadTooLarge { limit: 1024 },
        ];
        let mut codes = std::collections::HashSet::new();
        for variant in &variants {
            assert!(codes.insert(variant.code()), "{variant:?}");
            assert!(!variant.message().is_empty(), "{variant:?}");
        }
        assert_eq!(codes.len(), variants.len());

        assert_eq!(variants[0].status(), StatusCode::NOT_FOUND);
        assert_eq!(variants[1].status(), StatusCode::BAD_REQUEST);
        assert_eq!(variants[2].status(), StatusCode::CONFLICT);
        assert_eq!(variants[3].status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(variants[4].status(), StatusCode::UNAUTHORIZED);
        assert_eq!(variants[5].status(), StatusCode::FORBIDDEN);
        assert_eq!(variants[6].status(), StatusCode::BAD_GATEWAY);
        assert_eq!(variants[7].status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn a_not_found_names_the_object_but_never_a_payload() {
        let error = ApiError::not_found("Application", "team-a", "payments");
        assert_eq!(error.message(), "Application team-a/payments not found");
    }

    /// A backend message is bounded, so an engine error can never grow a response without limit.
    #[test]
    fn backend_messages_are_bounded() {
        let long = "x".repeat(MAX_ERROR_MESSAGE_CHARS * 3);
        let error = ApiError::backend(&long);
        let message = error.message();
        assert_eq!(message.chars().count(), MAX_ERROR_MESSAGE_CHARS + 1);
        assert!(message.ends_with('…'));

        let short = ApiError::backend(&"git fetch failed");
        assert_eq!(short.message(), "git fetch failed");
    }
}

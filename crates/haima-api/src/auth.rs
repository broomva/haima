//! JWT authentication middleware for Haima.
//!
//! Reuses [`lago_auth::jwt`] for token validation. Haima does not need
//! Lago session mapping — it only validates that the caller holds a valid
//! JWT signed with the shared secret.
//!
//! **Behaviour**:
//! - If no JWT secret is configured, auth is **disabled** (local dev mode)
//!   and a warning is logged on startup.
//! - If a secret IS configured, all protected routes require a valid
//!   `Authorization: Bearer <token>` header.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use lago_auth::jwt::{extract_bearer_token, validate_jwt};

/// Auth configuration injected as axum state.
#[derive(Clone)]
pub struct AuthConfig {
    /// `None` means auth is disabled (local dev).
    pub jwt_secret: Option<String>,
}

impl AuthConfig {
    /// Create auth config from environment variables.
    ///
    /// Checks `HAIMA_JWT_SECRET` first, then falls back to `AUTH_SECRET`.
    /// Returns `None` secret (auth disabled) if neither is set.
    pub fn from_env() -> Self {
        let secret = std::env::var("HAIMA_JWT_SECRET")
            .ok()
            .or_else(|| std::env::var("AUTH_SECRET").ok())
            .filter(|s| !s.is_empty());

        if secret.is_none() {
            tracing::warn!(
                "no HAIMA_JWT_SECRET or AUTH_SECRET configured — auth DISABLED (local dev mode)"
            );
        } else {
            tracing::info!("JWT auth enabled for protected routes");
        }

        Self { jwt_secret: secret }
    }
}

/// Auth error response body.
#[derive(Serialize)]
struct AuthErrorBody {
    error: String,
    message: String,
}

fn auth_error(status: StatusCode, message: impl Into<String>) -> Response {
    let body = AuthErrorBody {
        error: "unauthorized".to_string(),
        message: message.into(),
    };
    (status, axum::Json(body)).into_response()
}

/// Axum middleware that validates JWT bearer tokens on protected routes.
///
/// If auth is disabled (no secret configured), requests pass through.
/// If auth is enabled, a valid `Authorization: Bearer <token>` is required.
pub async fn require_auth(
    axum::extract::State(config): axum::extract::State<Arc<AuthConfig>>,
    request: Request,
    next: Next,
) -> Response {
    // If no secret configured, auth is disabled — pass through
    let Some(secret) = &config.jwt_secret else {
        return next.run(request).await;
    };

    // Extract Authorization header
    let auth_header = match request.headers().get("authorization") {
        Some(h) => match h.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return auth_error(StatusCode::UNAUTHORIZED, "invalid authorization header"),
        },
        None => return auth_error(StatusCode::UNAUTHORIZED, "missing authorization header"),
    };

    // Extract bearer token
    let token = match extract_bearer_token(&auth_header) {
        Ok(t) => t,
        Err(e) => return auth_error(StatusCode::UNAUTHORIZED, e.to_string()),
    };

    // Validate JWT
    match validate_jwt(token, secret) {
        Ok(claims) => {
            tracing::debug!(
                user_id = %claims.sub,
                email = %claims.email,
                "authenticated request"
            );
        }
        Err(e) => return auth_error(StatusCode::UNAUTHORIZED, e.to_string()),
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use lago_auth::BroomvaClaims;
    use tower::ServiceExt;

    const TEST_SECRET: &str = "test-haima-secret-key";

    fn make_token(sub: &str, email: &str, secret: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = BroomvaClaims {
            sub: sub.to_string(),
            email: email.to_string(),
            exp: now + 3600,
            iat: now,
            tenant_id: None,
            tenant_tier: None,
        };
        let key = EncodingKey::from_secret(secret.as_bytes());
        encode(&Header::default(), &claims, &key).unwrap()
    }

    fn test_app(auth_config: AuthConfig) -> Router {
        let config = Arc::new(auth_config);
        Router::new()
            .route(
                "/protected",
                get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
            )
            .layer(axum::middleware::from_fn_with_state(
                config.clone(),
                require_auth,
            ))
            .route(
                "/public",
                get(|| async { axum::Json(serde_json::json!({"public": true})) }),
            )
    }

    #[tokio::test]
    async fn public_route_no_auth_needed() {
        let app = test_app(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let req = HttpRequest::builder()
            .uri("/public")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_route_without_token_returns_401() {
        let app = test_app(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let req = HttpRequest::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn protected_route_with_valid_token_returns_200() {
        let app = test_app(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let token = make_token("user1", "user1@broomva.tech", TEST_SECRET);
        let req = HttpRequest::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_route_with_wrong_secret_returns_401() {
        let app = test_app(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let token = make_token("user1", "user1@broomva.tech", "wrong-secret");
        let req = HttpRequest::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_disabled_passes_through() {
        let app = test_app(AuthConfig { jwt_secret: None });
        let req = HttpRequest::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_auth_header_returns_401() {
        let app = test_app(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let req = HttpRequest::builder()
            .uri("/protected")
            .header("Authorization", "Basic abc123")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

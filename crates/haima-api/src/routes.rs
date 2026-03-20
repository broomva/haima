//! API route handlers.
//!
//! - `GET /health` — public (no auth, used by Railway health checks)
//! - `GET /state` — protected (requires JWT when auth is enabled)

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::require_auth;

pub fn routes(state: AppState) -> Router {
    // Protected routes — JWT required when auth is enabled
    let protected = Router::new()
        .route("/state", get(financial_state))
        .layer(axum::middleware::from_fn_with_state(
            state.auth_config.clone(),
            require_auth,
        ))
        .with_state(state.clone());

    // Public routes — no auth
    let public = Router::new()
        .route("/health", get(health))
        .with_state(state);

    // Merge: public routes are NOT behind the auth layer
    public.merge(protected)
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "haimad",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn financial_state(State(state): State<AppState>) -> Json<Value> {
    let fs = state.financial_state.read().await;
    Json(json!({
        "total_expenses": fs.total_expenses,
        "total_revenue": fs.total_revenue,
        "net_balance": fs.net_balance,
        "payment_count": fs.payment_count,
        "revenue_count": fs.revenue_count,
        "failed_count": fs.failed_count,
        "session_spend": fs.session_spend,
        "wallet_address": fs.wallet_address,
        "on_chain_balance": fs.on_chain_balance,
        "pending_bills": fs.pending_bills.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
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
        };
        let key = EncodingKey::from_secret(secret.as_bytes());
        encode(&Header::default(), &claims, &key).unwrap()
    }

    // --- Health endpoint (always public) ---

    #[tokio::test]
    async fn health_without_token_returns_200() {
        let state = AppState::new(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let app = routes(state);
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- State endpoint (protected) ---

    #[tokio::test]
    async fn state_without_token_auth_enabled_returns_401() {
        let state = AppState::new(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let app = routes(state);
        let req = Request::builder()
            .uri("/state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn state_with_valid_token_returns_200() {
        let state = AppState::new(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let app = routes(state);
        let token = make_token("user1", "user1@broomva.tech", TEST_SECRET);
        let req = Request::builder()
            .uri("/state")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn state_with_wrong_secret_returns_401() {
        let state = AppState::new(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let app = routes(state);
        let token = make_token("user1", "user1@broomva.tech", "wrong-secret");
        let req = Request::builder()
            .uri("/state")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Auth disabled (local dev mode) ---

    #[tokio::test]
    async fn state_without_token_auth_disabled_returns_200() {
        let state = AppState::new(AuthConfig { jwt_secret: None });
        let app = routes(state);
        let req = Request::builder()
            .uri("/state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

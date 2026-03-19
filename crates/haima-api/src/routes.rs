//! API route handlers.

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use serde_json::{Value, json};

use crate::AppState;

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/state", get(financial_state))
        .with_state(state)
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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_endpoint() {
        let app = routes(AppState::default());
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn state_endpoint() {
        let app = routes(AppState::default());
        let req = Request::builder()
            .uri("/state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

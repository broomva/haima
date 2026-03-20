//! HTTP API for Haima — wallet, balance, transactions, payment endpoints.
//!
//! Endpoints:
//! - `GET /health` — health check (public, no auth)
//! - `GET /state` — get full financial state projection (protected)
//!
//! Auth is controlled via `HAIMA_JWT_SECRET` or `AUTH_SECRET` env var.
//! If neither is set, auth is disabled (local dev mode).

pub mod auth;
pub mod routes;

use std::sync::Arc;

use axum::Router;
use haima_lago::FinancialState;
use tokio::sync::RwLock;

use crate::auth::AuthConfig;

/// Shared application state for the Haima API.
#[derive(Clone)]
pub struct AppState {
    pub financial_state: Arc<RwLock<FinancialState>>,
    pub auth_config: Arc<AuthConfig>,
}

impl AppState {
    /// Create a new `AppState` with the given auth config and default financial state.
    pub fn new(auth_config: AuthConfig) -> Self {
        Self {
            financial_state: Arc::new(RwLock::new(FinancialState::default())),
            auth_config: Arc::new(auth_config),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            financial_state: Arc::new(RwLock::new(FinancialState::default())),
            auth_config: Arc::new(AuthConfig { jwt_secret: None }),
        }
    }
}

/// Build the Haima API router.
pub fn router(state: AppState) -> Router {
    routes::routes(state)
}

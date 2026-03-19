//! HTTP API for Haima — wallet, balance, transactions, payment endpoints.
//!
//! Endpoints:
//! - `GET /health` — health check
//! - `GET /wallet` — get agent wallet info
//! - `GET /balance` — get on-chain + internal balance
//! - `GET /transactions` — list transaction history
//! - `GET /state` — get full financial state projection
//! - `POST /bill` — create a task billing record

pub mod routes;

use axum::Router;
use haima_lago::FinancialState;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state for the Haima API.
#[derive(Clone)]
pub struct AppState {
    pub financial_state: Arc<RwLock<FinancialState>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            financial_state: Arc::new(RwLock::new(FinancialState::default())),
        }
    }
}

/// Build the Haima API router.
pub fn router(state: AppState) -> Router {
    routes::routes(state)
}

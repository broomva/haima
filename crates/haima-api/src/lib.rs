//! HTTP API for Haima — wallet, balance, transactions, payment endpoints.
//!
//! Endpoints:
//! - `GET /health` — health check (public, no auth)
//! - `GET /state` — get full financial state projection (protected)
//! - `POST /v1/facilitate` — x402 payment facilitation (public)
//! - `GET /v1/facilitator/stats` — facilitator dashboard stats (public)
//! - `GET /v1/bureau/:agent_id` — agent credit bureau report (public)
//!
//! Auth is controlled via `HAIMA_JWT_SECRET` or `AUTH_SECRET` env var.
//! If neither is set, auth is disabled (local dev mode).

pub mod auth;
pub mod insurance;
pub mod outcome;
pub mod routes;

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use haima_core::bureau::{PaymentHistory, TrustContext};
use haima_core::credit::CreditScore;
use haima_core::lending::CreditLine;
use haima_lago::{FinancialState, InsuranceState, OutcomePricingState};
use haima_outcome::OutcomeEngine;
use haima_x402::FacilitatorStatsCounter;
use tokio::sync::RwLock;

use crate::auth::AuthConfig;

/// Shared application state for the Haima API.
#[derive(Clone)]
pub struct AppState {
    pub financial_state: Arc<RwLock<FinancialState>>,
    pub auth_config: Arc<AuthConfig>,
    /// In-memory facilitator statistics counter.
    pub facilitator_stats: Arc<FacilitatorStatsCounter>,
    /// Facilitator fee in basis points.
    pub facilitator_fee_bps: u32,
    /// In-memory credit score cache, keyed by `agent_id`.
    pub credit_scores: Arc<RwLock<HashMap<String, CreditScore>>>,
    /// In-memory credit lines, keyed by `agent_id`.
    pub credit_lines: Arc<RwLock<HashMap<String, CreditLine>>>,
    /// In-memory trust context cache, keyed by `agent_id` (from Autonomic).
    pub trust_contexts: Arc<RwLock<HashMap<String, TrustContext>>>,
    /// In-memory payment history cache, keyed by `agent_id`.
    pub payment_histories: Arc<RwLock<HashMap<String, PaymentHistory>>>,
    /// Outcome-based pricing state (contracts, task stats, pending tasks).
    pub outcome_state: Arc<RwLock<OutcomePricingState>>,
    /// Outcome pricing engine (contract → verify → bill → refund orchestrator).
    pub outcome_engine: Arc<RwLock<OutcomeEngine>>,
    /// Insurance marketplace state (products, policies, claims, pool).
    pub insurance_state: Arc<RwLock<InsuranceState>>,
}

impl AppState {
    /// Create a new `AppState` with the given auth config and default financial state.
    pub fn new(auth_config: AuthConfig) -> Self {
        let outcome_state = Arc::new(RwLock::new(OutcomePricingState::default()));
        let financial_state = Arc::new(RwLock::new(FinancialState::default()));
        let engine = OutcomeEngine::new(Arc::clone(&outcome_state), Arc::clone(&financial_state));

        Self {
            financial_state,
            auth_config: Arc::new(auth_config),
            facilitator_stats: Arc::new(FacilitatorStatsCounter::new()),
            facilitator_fee_bps: haima_x402::DEFAULT_FEE_BPS,
            credit_scores: Arc::new(RwLock::new(HashMap::new())),
            credit_lines: Arc::new(RwLock::new(HashMap::new())),
            trust_contexts: Arc::new(RwLock::new(HashMap::new())),
            payment_histories: Arc::new(RwLock::new(HashMap::new())),
            outcome_state,
            outcome_engine: Arc::new(RwLock::new(engine)),
            insurance_state: Arc::new(RwLock::new(InsuranceState::default())),
        }
    }

    /// Create a new `AppState` with the insurance marketplace bootstrapped
    /// (default pool with seed reserves, products, self-insurance provider,
    /// and a licensed MGA provider stub).
    pub fn with_insurance(auth_config: AuthConfig) -> Self {
        let pool_id = "life-network-pool";
        let mut pool = haima_core::marketplace::create_pool(
            pool_id,
            "Life Network Self-Insurance Pool",
            250, // 2.5% management fee
        );
        // Seed the pool with initial reserves ($100 = 100M micro-USD).
        // In production this would come from network funding events.
        haima_core::marketplace::contribute_to_pool(&mut pool, 100_000_000);

        let products = haima_core::marketplace::default_products(pool_id);
        let pool_provider = haima_core::marketplace::default_pool_provider(pool_id);

        // Register a licensed MGA (Managing General Agent) provider stub.
        // This represents a partnership with a licensed insurer for higher-tier
        // coverage that exceeds the self-insurance pool's capacity.
        let mga_provider = haima_core::insurance::InsuranceProvider {
            provider_id: "mga-aegis-underwriters".to_string(),
            name: "Aegis AI Underwriters MGA".to_string(),
            provider_type: haima_core::insurance::ProviderType::LicensedInsurer,
            offered_products: vec![
                haima_core::insurance::InsuranceProductType::FinancialError,
                haima_core::insurance::InsuranceProductType::DataBreach,
            ],
            commission_rate_bps: 2000, // 20% facilitation commission
            active: true,
            api_endpoint: Some("https://api.aegis-underwriters.example/v1".to_string()),
            registered_at: chrono::Utc::now(),
        };

        let mut insurance = InsuranceState::default();
        insurance.pool = Some(pool);
        for p in products {
            insurance.products.insert(p.product_id.clone(), p);
        }
        insurance
            .providers
            .insert(pool_provider.provider_id.clone(), pool_provider);
        insurance
            .providers
            .insert(mga_provider.provider_id.clone(), mga_provider);

        let outcome_state = Arc::new(RwLock::new(OutcomePricingState::default()));
        let financial_state = Arc::new(RwLock::new(FinancialState::default()));
        let engine = OutcomeEngine::new(Arc::clone(&outcome_state), Arc::clone(&financial_state));

        Self {
            financial_state,
            auth_config: Arc::new(auth_config),
            facilitator_stats: Arc::new(FacilitatorStatsCounter::new()),
            facilitator_fee_bps: haima_x402::DEFAULT_FEE_BPS,
            credit_scores: Arc::new(RwLock::new(HashMap::new())),
            credit_lines: Arc::new(RwLock::new(HashMap::new())),
            trust_contexts: Arc::new(RwLock::new(HashMap::new())),
            payment_histories: Arc::new(RwLock::new(HashMap::new())),
            outcome_state,
            outcome_engine: Arc::new(RwLock::new(engine)),
            insurance_state: Arc::new(RwLock::new(insurance)),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        let outcome_state = Arc::new(RwLock::new(OutcomePricingState::default()));
        let financial_state = Arc::new(RwLock::new(FinancialState::default()));
        let engine = OutcomeEngine::new(Arc::clone(&outcome_state), Arc::clone(&financial_state));

        Self {
            financial_state,
            auth_config: Arc::new(AuthConfig { jwt_secret: None }),
            facilitator_stats: Arc::new(FacilitatorStatsCounter::new()),
            facilitator_fee_bps: haima_x402::DEFAULT_FEE_BPS,
            credit_scores: Arc::new(RwLock::new(HashMap::new())),
            credit_lines: Arc::new(RwLock::new(HashMap::new())),
            trust_contexts: Arc::new(RwLock::new(HashMap::new())),
            payment_histories: Arc::new(RwLock::new(HashMap::new())),
            outcome_state,
            outcome_engine: Arc::new(RwLock::new(engine)),
            insurance_state: Arc::new(RwLock::new(InsuranceState::default())),
        }
    }
}

/// Build the Haima API router.
pub fn router(state: AppState) -> Router {
    let outcome = outcome::outcome_routes(state.clone());
    let insurance = insurance::insurance_routes(state.clone());
    routes::routes(state).merge(outcome).merge(insurance)
}

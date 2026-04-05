//! Agent insurance facilitation marketplace.
//!
//! Re-exports the core marketplace logic from `haima-core::marketplace` and
//! adds the higher-level orchestration layer with Autonomic integration.
//!
//! # Architecture
//!
//! ```text
//! Autonomic (trust scores) ──┐
//!                            ├──▶ Risk Engine ──▶ Pricing ──▶ Policy Issuance
//! Lago (event history) ──────┘                                    │
//!                                                                 ▼
//! Claims ◀── Verification (Lago events) ◀── Claim Submission ◀── Agent
//!   │
//!   ▼
//! Pool Management ──▶ Payout ──▶ Agent
//! ```

// Re-export core marketplace API.
pub use haima_core::marketplace::{
    ClaimsHistory, InsuranceDashboard, assess_risk, bind_policy, calculate_premium,
    contribute_to_pool, create_claim, create_pool, default_pool_provider, default_products,
    generate_quote, pool_payout, pool_register_policy, verify_claim,
};

// Submodules with additional business logic.
pub mod claims;
pub mod marketplace;
pub mod pool;
pub mod pricing;
pub mod risk;

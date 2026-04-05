//! Outcome-based pricing engine for Haima.
//!
//! This crate provides the **engine layer** that sits between `haima-core` (types)
//! and `haima-api` (HTTP). It orchestrates the full outcome-based pricing lifecycle:
//!
//! 1. **Contract registration** — define what "done" means for each task type
//! 2. **Task acceptance** — resolve price based on complexity + trust score
//! 3. **Automated verification** — dispatch pluggable verifiers per criterion
//! 4. **Billing** — emit billing events on successful outcomes
//! 5. **Refund processing** — auto-refund on failure or SLA breach
//! 6. **SLA monitoring** — background task watches for deadline expirations
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌─────────────────┐     ┌──────────────┐
//! │  haima-api   │────▶│  haima-outcome   │────▶│  haima-core  │
//! │  (HTTP)      │     │  (engine)        │     │  (types)     │
//! └─────────────┘     └────────┬────────┘     └──────────────┘
//!                              │
//!                     ┌────────▼────────┐
//!                     │   haima-lago    │
//!                     │  (projection)  │
//!                     └─────────────────┘
//! ```
//!
//! # Pricing Model
//!
//! | Task Type           | Price Range   | SLA       |
//! |---------------------|---------------|-----------|
//! | Code Review         | $2 – $5       | 2 hours   |
//! | Data Pipeline       | $5 – $20      | 1 hour    |
//! | Support Ticket      | $0.50 – $2.00 | 30 min    |
//! | Document Generation | $1 – $10      | 1 hour    |

pub mod engine;
pub mod sla;
pub mod verifier;

pub use engine::{AcceptResult, EngineError, OutcomeEngine, VerifyResult};
pub use sla::{ExpiredTask, SlaMonitorConfig, check_expired_tasks, spawn_sla_monitor};
pub use verifier::{
    DataValidatedVerifier, ManualApprovalVerifier, SuccessVerifier, TestsPassedVerifier,
    WebhookConfirmedVerifier,
};

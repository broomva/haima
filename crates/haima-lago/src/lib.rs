//! Lago bridge for Haima — transaction journaling and balance projections.
//!
//! All financial events flow through Lago's append-only event journal using
//! `EventKind::Custom` with the `"finance."` namespace. This crate provides:
//!
//! - **Publisher**: Writes finance events to the Lago journal
//! - **Subscriber**: Subscribes to finance events for real-time projections
//! - **Projection**: Deterministic fold over finance events → `FinancialState`

pub mod projection;
pub mod publisher;

pub use projection::FinancialState;
pub use publisher::FinancePublisher;

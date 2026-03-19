//! Core types, traits, and errors for the Haima agentic finance engine.
//!
//! Haima (αἷμα, Greek for "blood") is the circulatory system of the Agent OS —
//! distributing economic resources (payments, revenue, credits) throughout the
//! organism. It implements the x402 protocol for machine-to-machine payments
//! at the HTTP layer, enabling agents to pay for resources and charge for services
//! without human intervention.

pub mod error;
pub mod event;
pub mod payment;
pub mod policy;
pub mod receipt;
pub mod scheme;
pub mod wallet;

pub use error::{HaimaError, HaimaResult};
pub use event::FinanceEventKind;
pub use payment::{PaymentDecision, PaymentRequest};
pub use policy::PaymentPolicy;
pub use receipt::PaymentReceipt;
pub use scheme::PaymentScheme;
pub use wallet::{ChainId, OnChainBalance, WalletAddress};

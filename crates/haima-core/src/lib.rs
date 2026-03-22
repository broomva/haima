//! Core types, traits, and errors for the Haima agentic finance engine.
//!
//! Haima (αἷμα, Greek for "blood") is the circulatory system of the Agent OS —
//! distributing economic resources (payments, revenue, credits) throughout the
//! organism. It implements the x402 protocol for machine-to-machine payments
//! at the HTTP layer, enabling agents to pay for resources and charge for services
//! without human intervention.

pub mod bureau;
pub mod credit;
pub mod error;
pub mod event;
pub mod lending;
pub mod payment;
pub mod policy;
pub mod receipt;
pub mod scheme;
pub mod wallet;

pub use bureau::{
    AgentCreditReport, CreditLineSummary, PaymentHistory, PaymentSummary, RiskFlag, RiskFlagType,
    RiskRating, TrustContext, TrustTrajectory, assess_risk_rating, detect_risk_flags,
    generate_credit_report,
};
pub use credit::{
    CreditCheckResult, CreditFactors, CreditScore, CreditTier, check_credit, compute_credit_score,
};
pub use error::{HaimaError, HaimaResult};
pub use event::FinanceEventKind;
pub use lending::{
    CreditLine, CreditLineStatus, DrawRequest, DrawResult, RepaymentRecord, accrue_interest,
    close_credit_line, default_credit_line, draw, freeze_credit_line, open_credit_line, repay,
    unfreeze_credit_line,
};
pub use payment::{PaymentDecision, PaymentRequest};
pub use policy::PaymentPolicy;
pub use receipt::PaymentReceipt;
pub use scheme::PaymentScheme;
pub use wallet::{ChainId, OnChainBalance, WalletAddress};

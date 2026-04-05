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
pub mod insurance;
pub mod lending;
pub mod marketplace;
pub mod outcome;
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
pub use insurance::{
    BindRequest, ClaimRequest, ClaimStatus, ClaimVerification, InsuranceClaim, InsurancePolicy,
    InsurancePool, InsuranceProduct, InsuranceProductType, InsuranceProvider, InsuranceQuote,
    InsuranceTrustTier, PolicyStatus, PoolContributionRequest, PoolStatus, ProviderType,
    QuoteRequest, RiskAssessment, RiskComponents,
};
pub use lending::{
    CreditLine, CreditLineStatus, DrawRequest, DrawResult, RepaymentRecord, accrue_interest,
    close_credit_line, default_credit_line, draw, freeze_credit_line, open_credit_line, repay,
    unfreeze_credit_line,
};
pub use marketplace::{
    ClaimsHistory, InsuranceDashboard, assess_risk, bind_policy, calculate_premium,
    contribute_to_pool, create_claim, create_pool, default_pool_provider, default_products,
    generate_quote, pool_payout, pool_register_policy, verify_claim,
};
pub use outcome::{
    CriterionResult, OutcomeRecord, OutcomeVerification, RefundPolicy, SuccessCriterion,
    TaskComplexity, TaskContract, TaskOutcome, TaskType, default_code_review_contract,
    default_data_pipeline_contract, default_document_generation_contract,
    default_support_ticket_contract,
};
pub use payment::{PaymentDecision, PaymentRequest};
pub use policy::PaymentPolicy;
pub use receipt::PaymentReceipt;
pub use scheme::PaymentScheme;
pub use wallet::{ChainId, OnChainBalance, WalletAddress};

//! Error types for Haima.

use thiserror::Error;

pub type HaimaResult<T> = Result<T, HaimaError>;

#[derive(Debug, Error)]
pub enum HaimaError {
    #[error("wallet error: {0}")]
    Wallet(String),

    #[error("payment denied: {0}")]
    PaymentDenied(String),

    #[error("settlement failed: {0}")]
    SettlementFailed(String),

    #[error("facilitator error: {0}")]
    Facilitator(String),

    #[error("insufficient balance: need {needed} micro-credits, have {available}")]
    InsufficientBalance { needed: i64, available: i64 },

    #[error("amount exceeds policy cap: {amount} > {cap} micro-credits")]
    ExceedsPolicyCap { amount: i64, cap: i64 },

    #[error("unsupported chain: {0}")]
    UnsupportedChain(String),

    #[error("unsupported payment scheme: {0}")]
    UnsupportedScheme(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("http error: {0}")]
    Http(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("insufficient credit: {reason}")]
    InsufficientCredit { reason: String },

    // -- Insurance errors --
    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    #[error("policy not active: {policy_id} is {status}")]
    PolicyNotActive { policy_id: String, status: String },

    #[error("claim exceeds coverage: claimed {claimed} > remaining {remaining} micro-USD")]
    ClaimExceedsCoverage { claimed: i64, remaining: i64 },

    #[error("agent not insurable: {reason}")]
    NotInsurable { reason: String },

    #[error("quote expired: {quote_id}")]
    QuoteExpired { quote_id: String },

    #[error("quote not found: {0}")]
    QuoteNotFound(String),

    #[error("product not found: {0}")]
    ProductNotFound(String),

    #[error("pool reserves insufficient: need {needed}, have {available} micro-USD")]
    PoolReservesInsufficient { needed: i64, available: i64 },

    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    #[error("claim not found: {0}")]
    ClaimNotFound(String),
}

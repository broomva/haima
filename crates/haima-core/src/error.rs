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
}

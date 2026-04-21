//! x402 protocol integration for Haima.
//!
//! Implements the x402 payment protocol at the HTTP layer:
//! - **Client middleware**: Intercepts HTTP 402 responses, parses payment terms,
//!   signs payments with the agent's wallet, and retries requests.
//! - **Server middleware**: Protects API routes with payment requirements,
//!   verifies incoming payments, and settles on-chain via a facilitator.
//! - **Facilitator client**: Communicates with Coinbase CDP (default) or
//!   self-hosted facilitators for payment verification and settlement.
//!
//! # Protocol Flow (Client)
//!
//! ```text
//! HTTP Request -> 402 + PAYMENT-REQUIRED header
//!   -> Parse PaymentRequired terms
//!   -> Evaluate against PaymentPolicy (auto-approve / require approval / deny)
//!   -> Sign with WalletBackend (message signing)
//!   -> Retry with PAYMENT-SIGNATURE header
//!   -> Receive 200 + PAYMENT-RESPONSE header (settlement confirmation)
//! ```

pub mod bazaar;
pub mod client;
pub mod facilitator;
pub mod header;
pub mod server;

pub use bazaar::{BazaarClient, BazaarClientBuilder, DEFAULT_BAZAAR_URL, ServiceEntry};
pub use client::{HandleResult, SettlementResult, X402Client};
pub use facilitator::{
    DEFAULT_FEE_BPS, FacilitateRequest, FacilitateResponse, FacilitationStatus, Facilitator,
    FacilitatorConfig, FacilitatorStats, FacilitatorStatsCounter, SettlementReceipt, calculate_fee,
    verify_payment_header,
};
pub use header::{
    Eip3009Authorization, PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER, PaymentRequiredHeader, PaymentResponseHeader, PaymentSignatureHeader,
    SchemeRequirement, encode_payment_required, encode_payment_response, encode_payment_signature,
    parse_payment_required, parse_payment_response, parse_payment_signature,
};
pub use server::X402ServerMiddleware;

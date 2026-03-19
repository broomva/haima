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
//! HTTP Request → 402 + PAYMENT-REQUIRED header
//!   → Parse PaymentRequired terms
//!   → Evaluate against PaymentPolicy (auto-approve / require approval / deny)
//!   → Sign with WalletBackend (EIP-3009 transferWithAuthorization)
//!   → Retry with PAYMENT-SIGNATURE header
//!   → Receive 200 + PAYMENT-RESPONSE header (settlement confirmation)
//! ```

pub mod client;
pub mod facilitator;
pub mod header;
pub mod server;

pub use client::X402Client;
pub use facilitator::{Facilitator, FacilitatorConfig};
pub use server::X402ServerMiddleware;

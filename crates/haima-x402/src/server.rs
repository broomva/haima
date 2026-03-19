//! x402 server middleware — protects API routes with payment requirements.
//!
//! When an external client requests a paid resource, the middleware:
//! 1. Returns HTTP 402 with `PAYMENT-REQUIRED` header if no payment is attached
//! 2. Verifies the `PAYMENT-SIGNATURE` header via the facilitator
//! 3. Records revenue to Lago on successful settlement
//! 4. Passes the request through to the handler

use haima_core::scheme::TokenInfo;
use haima_core::wallet::WalletAddress;
use serde::{Deserialize, Serialize};

/// Configuration for a paid API route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceTag {
    /// Amount in the token's smallest unit.
    pub amount: u64,
    /// Token to accept.
    pub token: TokenInfo,
    /// Recipient wallet (the agent's address).
    pub recipient: WalletAddress,
    /// Facilitator URL for payment verification.
    pub facilitator_url: String,
}

/// x402 server middleware (Phase F3 — scaffolded).
///
/// Will be implemented as axum middleware that:
/// - Checks for `PAYMENT-SIGNATURE` header
/// - If absent: returns 402 with `PAYMENT-REQUIRED`
/// - If present: verifies via facilitator, records revenue, passes through
pub struct X402ServerMiddleware {
    /// Price tag for this route.
    pub price_tag: PriceTag,
}

impl X402ServerMiddleware {
    pub fn new(price_tag: PriceTag) -> Self {
        Self { price_tag }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use haima_core::wallet::ChainId;

    #[test]
    fn price_tag_serde_roundtrip() {
        let tag = PriceTag {
            amount: 10_000,
            token: TokenInfo::usdc_base(),
            recipient: WalletAddress {
                address: "0xagent".into(),
                chain: ChainId::base(),
            },
            facilitator_url: "https://x402.org/facilitator".into(),
        };
        let json = serde_json::to_string(&tag).unwrap();
        let back: PriceTag = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount, 10_000);
    }
}

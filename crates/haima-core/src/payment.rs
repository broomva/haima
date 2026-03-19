//! Payment request and decision types.
//!
//! These types flow through the system when an agent encounters an HTTP 402
//! response or when an external client pays for agent services.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::scheme::PaymentScheme;
use crate::wallet::WalletAddress;

/// A payment request parsed from an HTTP 402 response's `PAYMENT-REQUIRED` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequest {
    /// URL of the resource that requires payment.
    pub resource_url: String,
    /// The payment scheme and terms.
    pub scheme: PaymentScheme,
    /// Human-readable description of what's being purchased.
    pub description: Option<String>,
    /// When this payment request was received.
    pub received_at: DateTime<Utc>,
}

/// The decision on whether to authorize a payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PaymentDecision {
    /// Payment approved — agent will sign and submit.
    Approved {
        /// The wallet that will pay.
        payer: WalletAddress,
        /// Amount in micro-credits this will cost.
        micro_credit_cost: i64,
        /// Reason for approval.
        reason: String,
    },
    /// Payment requires human approval via the ApprovalPort.
    RequiresApproval {
        /// Amount in micro-credits.
        micro_credit_cost: i64,
        /// Why human approval is needed.
        reason: String,
    },
    /// Payment denied by policy.
    Denied {
        /// Why the payment was denied.
        reason: String,
    },
}

impl PaymentDecision {
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{PaymentScheme, TokenInfo};
    use crate::wallet::ChainId;

    #[test]
    fn payment_request_serde_roundtrip() {
        let req = PaymentRequest {
            resource_url: "https://api.example.com/data".into(),
            scheme: PaymentScheme::Exact {
                amount: 10_000,
                token: TokenInfo::usdc_base(),
                recipient: WalletAddress {
                    address: "0xrecipient".into(),
                    chain: ChainId::base(),
                },
                facilitator_url: "https://x402.org/facilitator".into(),
            },
            description: Some("Real-time market data".into()),
            received_at: Utc::now(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PaymentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resource_url, "https://api.example.com/data");
    }

    #[test]
    fn payment_decision_variants() {
        let approved = PaymentDecision::Approved {
            payer: WalletAddress {
                address: "0xpayer".into(),
                chain: ChainId::base(),
            },
            micro_credit_cost: 10_000,
            reason: "within auto-approve threshold".into(),
        };
        assert!(approved.is_approved());
        assert!(!approved.is_denied());

        let denied = PaymentDecision::Denied {
            reason: "hibernate mode".into(),
        };
        assert!(denied.is_denied());
        assert!(!denied.is_approved());
    }
}

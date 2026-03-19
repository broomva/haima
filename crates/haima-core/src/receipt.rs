//! Payment receipt types — settlement confirmation from on-chain transactions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::wallet::{ChainId, WalletAddress};

/// A payment receipt confirming on-chain settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Transaction hash on the target chain.
    pub tx_hash: String,
    /// Chain where settlement occurred.
    pub chain: ChainId,
    /// Payer address.
    pub payer: WalletAddress,
    /// Recipient address.
    pub recipient: WalletAddress,
    /// Amount in the token's smallest unit.
    pub amount: u64,
    /// Token symbol.
    pub token: String,
    /// Equivalent in micro-credits.
    pub micro_credits: i64,
    /// When settlement was confirmed.
    pub settled_at: DateTime<Utc>,
    /// Settlement latency in milliseconds.
    pub latency_ms: u64,
    /// The facilitator that processed this payment.
    pub facilitator: String,
}

/// Direction of a financial transaction from the agent's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionDirection {
    /// Agent paid for a resource (expense).
    Outgoing,
    /// Agent received payment for a service (revenue).
    Incoming,
}

/// A complete transaction record combining request + receipt + direction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Unique transaction ID (ULID).
    pub id: String,
    /// Direction from the agent's perspective.
    pub direction: TransactionDirection,
    /// The resource URL involved.
    pub resource_url: String,
    /// Settlement receipt.
    pub receipt: PaymentReceipt,
    /// Session that initiated the transaction.
    pub session_id: String,
    /// Task that this payment is associated with (for per-task billing).
    pub task_id: Option<String>,
    /// When the transaction was recorded.
    pub recorded_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::ChainId;

    #[test]
    fn transaction_direction_serde() {
        let out = TransactionDirection::Outgoing;
        let json = serde_json::to_string(&out).unwrap();
        assert_eq!(json, "\"outgoing\"");

        let inc: TransactionDirection = serde_json::from_str("\"incoming\"").unwrap();
        assert_eq!(inc, TransactionDirection::Incoming);
    }

    #[test]
    fn payment_receipt_serde_roundtrip() {
        let receipt = PaymentReceipt {
            tx_hash: "0xabc123".into(),
            chain: ChainId::base(),
            payer: WalletAddress {
                address: "0xpayer".into(),
                chain: ChainId::base(),
            },
            recipient: WalletAddress {
                address: "0xrecipient".into(),
                chain: ChainId::base(),
            },
            amount: 10_000,
            token: "USDC".into(),
            micro_credits: 10_000,
            settled_at: Utc::now(),
            latency_ms: 1200,
            facilitator: "coinbase-cdp".into(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: PaymentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tx_hash, "0xabc123");
    }
}

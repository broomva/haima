//! Finance event kinds for the Lago event journal.
//!
//! All Haima events use `EventKind::Custom` with the `"finance."` namespace
//! for forward-compatible persistence through Lago.

use serde::{Deserialize, Serialize};

/// Finance-specific event kinds persisted via Lago.
///
/// These are serialized into `EventKind::Custom { event_type, data }` where
/// `event_type` is `"finance.{variant_name}"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FinanceEventKind {
    /// Agent encountered an HTTP 402 response.
    PaymentRequested {
        resource_url: String,
        amount_micro_credits: i64,
        token: String,
        chain: String,
    },

    /// Agent authorized and signed a payment.
    PaymentAuthorized {
        resource_url: String,
        amount_micro_credits: i64,
        payer_address: String,
        recipient_address: String,
    },

    /// On-chain settlement confirmed.
    PaymentSettled {
        tx_hash: String,
        amount_micro_credits: i64,
        chain: String,
        latency_ms: u64,
        facilitator: String,
    },

    /// Payment failed (insufficient funds, facilitator error, etc.).
    PaymentFailed {
        resource_url: String,
        amount_micro_credits: i64,
        reason: String,
    },

    /// Agent received payment for services rendered.
    RevenueReceived {
        tx_hash: String,
        amount_micro_credits: i64,
        payer_address: String,
        task_id: Option<String>,
    },

    /// Wallet keypair generated and registered.
    WalletCreated {
        address: String,
        chain: String,
        key_blob_id: Option<String>,
    },

    /// On-chain balance synchronized with internal ledger.
    BalanceSynced {
        address: String,
        chain: String,
        on_chain_micro_credits: i64,
        internal_micro_credits: i64,
        drift: i64,
    },

    /// Task billing record — agent completed a task and set a price.
    TaskBilled {
        task_id: String,
        description: String,
        price_micro_credits: i64,
        token: String,
        chain: String,
    },
}

impl FinanceEventKind {
    /// The `EventKind::Custom` `event_type` prefix for all Haima events.
    pub const NAMESPACE: &'static str = "finance";

    /// Get the full event type string for Lago `Custom` events.
    pub fn event_type(&self) -> String {
        let variant = match self {
            Self::PaymentRequested { .. } => "payment_requested",
            Self::PaymentAuthorized { .. } => "payment_authorized",
            Self::PaymentSettled { .. } => "payment_settled",
            Self::PaymentFailed { .. } => "payment_failed",
            Self::RevenueReceived { .. } => "revenue_received",
            Self::WalletCreated { .. } => "wallet_created",
            Self::BalanceSynced { .. } => "balance_synced",
            Self::TaskBilled { .. } => "task_billed",
        };
        format!("{}.{variant}", Self::NAMESPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_format() {
        let event = FinanceEventKind::PaymentSettled {
            tx_hash: "0xabc".into(),
            amount_micro_credits: 10_000,
            chain: "eip155:8453".into(),
            latency_ms: 1200,
            facilitator: "coinbase-cdp".into(),
        };
        assert_eq!(event.event_type(), "finance.payment_settled");
    }

    #[test]
    fn all_event_types_have_namespace() {
        let events: Vec<FinanceEventKind> = vec![
            FinanceEventKind::PaymentRequested {
                resource_url: "https://example.com".into(),
                amount_micro_credits: 100,
                token: "USDC".into(),
                chain: "eip155:8453".into(),
            },
            FinanceEventKind::PaymentAuthorized {
                resource_url: "https://example.com".into(),
                amount_micro_credits: 100,
                payer_address: "0xpayer".into(),
                recipient_address: "0xrecipient".into(),
            },
            FinanceEventKind::PaymentFailed {
                resource_url: "https://example.com".into(),
                amount_micro_credits: 100,
                reason: "test".into(),
            },
            FinanceEventKind::RevenueReceived {
                tx_hash: "0xabc".into(),
                amount_micro_credits: 100,
                payer_address: "0xpayer".into(),
                task_id: None,
            },
            FinanceEventKind::WalletCreated {
                address: "0xaddr".into(),
                chain: "eip155:8453".into(),
                key_blob_id: None,
            },
            FinanceEventKind::BalanceSynced {
                address: "0xaddr".into(),
                chain: "eip155:8453".into(),
                on_chain_micro_credits: 1000,
                internal_micro_credits: 1000,
                drift: 0,
            },
            FinanceEventKind::TaskBilled {
                task_id: "task-1".into(),
                description: "code review".into(),
                price_micro_credits: 500_000,
                token: "USDC".into(),
                chain: "eip155:8453".into(),
            },
        ];
        for event in events {
            assert!(event.event_type().starts_with("finance."));
        }
    }

    #[test]
    fn finance_event_serde_roundtrip() {
        let event = FinanceEventKind::TaskBilled {
            task_id: "task-42".into(),
            description: "debug production issue".into(),
            price_micro_credits: 250_000,
            token: "USDC".into(),
            chain: "eip155:8453".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: FinanceEventKind = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, FinanceEventKind::TaskBilled { .. }));
    }
}

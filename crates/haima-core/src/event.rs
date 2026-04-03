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

    /// Agent is attempting a payment through the facilitator.
    PaymentAttempted {
        resource_url: String,
        amount_micro_credits: i64,
        facilitator_url: String,
    },

    /// Agent's credit was insufficient for a payment.
    CreditInsufficient {
        agent_id: String,
        resource_url: String,
        amount_micro_credits: i64,
        reason: String,
    },

    // -- Outcome-based pricing events --
    /// A task contract was accepted — agent committed to deliver an outcome.
    TaskContracted {
        task_id: String,
        contract_id: String,
        agent_id: String,
        complexity: String,
        price_micro_credits: i64,
        sla_deadline_ms: i64,
    },

    /// Task outcome was verified — success criteria checked.
    TaskVerified {
        task_id: String,
        contract_id: String,
        outcome: String,
        price_micro_credits: i64,
        criteria_passed: u32,
        criteria_total: u32,
    },

    /// Refund issued for a failed or timed-out task.
    TaskRefunded {
        task_id: String,
        contract_id: String,
        refund_micro_credits: i64,
        reason: String,
    },

    // -- Insurance events --
    /// Insurance policy issued to an agent.
    PolicyIssued {
        policy_id: String,
        agent_id: String,
        product_type: String,
        coverage_micro_usd: i64,
        premium_micro_usd: i64,
        provider_id: String,
    },

    /// Insurance premium payment collected.
    PremiumCollected {
        policy_id: String,
        agent_id: String,
        amount_micro_usd: i64,
        commission_micro_usd: i64,
    },

    /// Insurance claim submitted.
    ClaimSubmitted {
        claim_id: String,
        policy_id: String,
        agent_id: String,
        incident_type: String,
        claimed_amount_micro_usd: i64,
    },

    /// Insurance claim verified against Lago event evidence.
    ClaimVerified {
        claim_id: String,
        policy_id: String,
        incident_confirmed: bool,
        confidence: f64,
        evidence_events_validated: u32,
    },

    /// Insurance claim payout processed.
    ClaimPaid {
        claim_id: String,
        policy_id: String,
        agent_id: String,
        payout_micro_usd: i64,
        source: String, // "pool" or provider_id
    },

    /// Insurance claim denied.
    ClaimDenied {
        claim_id: String,
        policy_id: String,
        reason: String,
    },

    /// Contribution to the self-insurance pool.
    PoolContribution {
        pool_id: String,
        agent_id: String,
        amount_micro_usd: i64,
    },

    /// Pool payout for a claim.
    PoolPayout {
        pool_id: String,
        claim_id: String,
        amount_micro_usd: i64,
        reserves_after_micro_usd: i64,
    },

    /// Risk assessment computed for an agent.
    RiskAssessed {
        agent_id: String,
        risk_score: f64,
        risk_rating: String,
        premium_multiplier: f64,
        insurable: bool,
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
            Self::PaymentAttempted { .. } => "payment_attempted",
            Self::CreditInsufficient { .. } => "credit_insufficient",
            Self::TaskContracted { .. } => "task_contracted",
            Self::TaskVerified { .. } => "task_verified",
            Self::TaskRefunded { .. } => "task_refunded",
            Self::PolicyIssued { .. } => "policy_issued",
            Self::PremiumCollected { .. } => "premium_collected",
            Self::ClaimSubmitted { .. } => "claim_submitted",
            Self::ClaimVerified { .. } => "claim_verified",
            Self::ClaimPaid { .. } => "claim_paid",
            Self::ClaimDenied { .. } => "claim_denied",
            Self::PoolContribution { .. } => "pool_contribution",
            Self::PoolPayout { .. } => "pool_payout",
            Self::RiskAssessed { .. } => "risk_assessed",
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
            FinanceEventKind::PaymentAttempted {
                resource_url: "https://example.com".into(),
                amount_micro_credits: 100,
                facilitator_url: "https://haimad-production.up.railway.app".into(),
            },
            FinanceEventKind::CreditInsufficient {
                agent_id: "agent-1".into(),
                resource_url: "https://example.com".into(),
                amount_micro_credits: 100,
                reason: "insufficient credit".into(),
            },
            FinanceEventKind::TaskContracted {
                task_id: "task-1".into(),
                contract_id: "contract-1".into(),
                agent_id: "agent-1".into(),
                complexity: "standard".into(),
                price_micro_credits: 3_000_000,
                sla_deadline_ms: 1_700_000_000_000,
            },
            FinanceEventKind::TaskVerified {
                task_id: "task-1".into(),
                contract_id: "contract-1".into(),
                outcome: "success".into(),
                price_micro_credits: 3_000_000,
                criteria_passed: 2,
                criteria_total: 2,
            },
            FinanceEventKind::TaskRefunded {
                task_id: "task-1".into(),
                contract_id: "contract-1".into(),
                refund_micro_credits: 3_000_000,
                reason: "sla_exceeded".into(),
            },
            FinanceEventKind::PolicyIssued {
                policy_id: "pol-1".into(),
                agent_id: "agent-1".into(),
                product_type: "task_failure".into(),
                coverage_micro_usd: 10_000_000,
                premium_micro_usd: 100_000,
                provider_id: "pool-1".into(),
            },
            FinanceEventKind::PremiumCollected {
                policy_id: "pol-1".into(),
                agent_id: "agent-1".into(),
                amount_micro_usd: 100_000,
                commission_micro_usd: 15_000,
            },
            FinanceEventKind::ClaimSubmitted {
                claim_id: "claim-1".into(),
                policy_id: "pol-1".into(),
                agent_id: "agent-1".into(),
                incident_type: "task_failure".into(),
                claimed_amount_micro_usd: 5_000_000,
            },
            FinanceEventKind::ClaimVerified {
                claim_id: "claim-1".into(),
                policy_id: "pol-1".into(),
                incident_confirmed: true,
                confidence: 0.95,
                evidence_events_validated: 3,
            },
            FinanceEventKind::ClaimPaid {
                claim_id: "claim-1".into(),
                policy_id: "pol-1".into(),
                agent_id: "agent-1".into(),
                payout_micro_usd: 4_500_000,
                source: "pool-1".into(),
            },
            FinanceEventKind::ClaimDenied {
                claim_id: "claim-2".into(),
                policy_id: "pol-1".into(),
                reason: "insufficient_evidence".into(),
            },
            FinanceEventKind::PoolContribution {
                pool_id: "pool-1".into(),
                agent_id: "agent-1".into(),
                amount_micro_usd: 1_000_000,
            },
            FinanceEventKind::PoolPayout {
                pool_id: "pool-1".into(),
                claim_id: "claim-1".into(),
                amount_micro_usd: 4_500_000,
                reserves_after_micro_usd: 95_500_000,
            },
            FinanceEventKind::RiskAssessed {
                agent_id: "agent-1".into(),
                risk_score: 0.25,
                risk_rating: "low".into(),
                premium_multiplier: 0.9,
                insurable: true,
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

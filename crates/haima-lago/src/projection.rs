//! Financial state projection — deterministic fold over finance events.
//!
//! The `FinancialState` is derived entirely from the Lago event journal.
//! It is never mutated directly — only recomputed by folding over events.

use chrono::{DateTime, Utc};
use haima_core::event::FinanceEventKind;
use serde::{Deserialize, Serialize};

/// The agent's financial state, accumulated from finance events in the Lago journal.
///
/// This is a projection — it is recomputed by folding over events on startup
/// and kept in sync via the event subscriber.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinancialState {
    /// Total payments made (outgoing) in micro-credits.
    pub total_expenses: i64,
    /// Total revenue received (incoming) in micro-credits.
    pub total_revenue: i64,
    /// Net balance from financial transactions (revenue - expenses).
    pub net_balance: i64,
    /// Number of successful outgoing payments.
    pub payment_count: u64,
    /// Number of successful incoming payments.
    pub revenue_count: u64,
    /// Number of failed payment attempts.
    pub failed_count: u64,
    /// Total spend in the current session.
    pub session_spend: i64,
    /// Timestamp of the last financial event.
    pub last_event_at: Option<DateTime<Utc>>,
    /// The wallet address (set on `WalletCreated`).
    pub wallet_address: Option<String>,
    /// Last known on-chain balance (micro-credits).
    pub on_chain_balance: Option<i64>,
    /// Tasks billed but not yet paid.
    pub pending_bills: Vec<PendingBill>,
}

/// A task that has been billed but not yet paid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBill {
    pub task_id: String,
    pub description: String,
    pub price_micro_credits: i64,
    pub billed_at: DateTime<Utc>,
}

impl FinancialState {
    /// Apply a finance event to update the projection.
    ///
    /// This is the core fold function — must be deterministic and pure.
    pub fn apply(&mut self, event: &FinanceEventKind, timestamp: DateTime<Utc>) {
        self.last_event_at = Some(timestamp);

        match event {
            FinanceEventKind::PaymentSettled {
                amount_micro_credits,
                ..
            } => {
                self.total_expenses += amount_micro_credits;
                self.net_balance -= amount_micro_credits;
                self.session_spend += amount_micro_credits;
                self.payment_count += 1;
            }
            FinanceEventKind::PaymentFailed { .. } => {
                self.failed_count += 1;
            }
            FinanceEventKind::RevenueReceived {
                amount_micro_credits,
                task_id,
                ..
            } => {
                self.total_revenue += amount_micro_credits;
                self.net_balance += amount_micro_credits;
                self.revenue_count += 1;
                // Remove from pending bills if task was billed
                if let Some(tid) = task_id {
                    self.pending_bills.retain(|b| &b.task_id != tid);
                }
            }
            FinanceEventKind::WalletCreated { address, .. } => {
                self.wallet_address = Some(address.clone());
            }
            FinanceEventKind::BalanceSynced {
                on_chain_micro_credits,
                ..
            } => {
                self.on_chain_balance = Some(*on_chain_micro_credits);
            }
            FinanceEventKind::TaskBilled {
                task_id,
                description,
                price_micro_credits,
                ..
            } => {
                self.pending_bills.push(PendingBill {
                    task_id: task_id.clone(),
                    description: description.clone(),
                    price_micro_credits: *price_micro_credits,
                    billed_at: timestamp,
                });
            }
            // Informational and outcome events — no FinancialState change.
            // Outcome events are handled by OutcomePricingState.
            _ => {}
        }
    }

    /// Reset session-scoped counters (called on new session).
    pub fn reset_session(&mut self) {
        self.session_spend = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state() {
        let state = FinancialState::default();
        assert_eq!(state.total_expenses, 0);
        assert_eq!(state.total_revenue, 0);
        assert_eq!(state.net_balance, 0);
        assert_eq!(state.payment_count, 0);
    }

    #[test]
    fn apply_payment_settled() {
        let mut state = FinancialState::default();
        state.apply(
            &FinanceEventKind::PaymentSettled {
                tx_hash: "0xabc".into(),
                amount_micro_credits: 10_000,
                chain: "eip155:8453".into(),
                latency_ms: 1200,
                facilitator: "coinbase-cdp".into(),
            },
            Utc::now(),
        );
        assert_eq!(state.total_expenses, 10_000);
        assert_eq!(state.net_balance, -10_000);
        assert_eq!(state.payment_count, 1);
        assert_eq!(state.session_spend, 10_000);
    }

    #[test]
    fn apply_revenue_received() {
        let mut state = FinancialState::default();
        state.apply(
            &FinanceEventKind::RevenueReceived {
                tx_hash: "0xdef".into(),
                amount_micro_credits: 500_000,
                payer_address: "0xclient".into(),
                task_id: None,
            },
            Utc::now(),
        );
        assert_eq!(state.total_revenue, 500_000);
        assert_eq!(state.net_balance, 500_000);
        assert_eq!(state.revenue_count, 1);
    }

    #[test]
    fn apply_payment_failed() {
        let mut state = FinancialState::default();
        state.apply(
            &FinanceEventKind::PaymentFailed {
                resource_url: "https://example.com".into(),
                amount_micro_credits: 100,
                reason: "insufficient funds".into(),
            },
            Utc::now(),
        );
        assert_eq!(state.failed_count, 1);
        assert_eq!(state.net_balance, 0); // No balance change on failure
    }

    #[test]
    fn task_billed_then_paid() {
        let mut state = FinancialState::default();
        let now = Utc::now();

        // Bill for a task
        state.apply(
            &FinanceEventKind::TaskBilled {
                task_id: "task-42".into(),
                description: "code review".into(),
                price_micro_credits: 250_000,
                token: "USDC".into(),
                chain: "eip155:8453".into(),
            },
            now,
        );
        assert_eq!(state.pending_bills.len(), 1);

        // Revenue received for that task
        state.apply(
            &FinanceEventKind::RevenueReceived {
                tx_hash: "0xpay".into(),
                amount_micro_credits: 250_000,
                payer_address: "0xclient".into(),
                task_id: Some("task-42".into()),
            },
            now,
        );
        assert_eq!(state.pending_bills.len(), 0);
        assert_eq!(state.total_revenue, 250_000);
    }

    #[test]
    fn reset_session() {
        let mut state = FinancialState {
            session_spend: 50_000,
            ..Default::default()
        };
        state.reset_session();
        assert_eq!(state.session_spend, 0);
        // Lifetime totals are not reset
    }
}

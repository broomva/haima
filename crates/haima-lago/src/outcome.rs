//! Outcome-based pricing projection — per-task-type analytics and dashboard data.
//!
//! Deterministic fold over outcome-related finance events to produce:
//! - Per-task-type statistics (count, revenue, completion rate, avg cost)
//! - Active task contracts
//! - Pending verifications
//! - Refund tracking
//! - Revenue dashboard data

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use haima_core::event::FinanceEventKind;
use haima_core::outcome::{TaskContract, TaskOutcome};
use serde::{Deserialize, Serialize};

/// Per-task-type statistics for the revenue dashboard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskTypeStats {
    /// Total tasks completed (any outcome).
    pub total_tasks: u64,
    /// Tasks that succeeded.
    pub successful_tasks: u64,
    /// Tasks that failed.
    pub failed_tasks: u64,
    /// Tasks that partially succeeded.
    pub partial_tasks: u64,
    /// Tasks that timed out.
    pub timed_out_tasks: u64,
    /// Total revenue earned (micro-credits) from successful tasks.
    pub total_revenue_micro_credits: i64,
    /// Total refunds issued (micro-credits).
    pub total_refunds_micro_credits: i64,
    /// Net revenue (revenue - refunds).
    pub net_revenue_micro_credits: i64,
    /// Completion rate (successful / total, 0.0 - 1.0).
    pub completion_rate: f64,
    /// Average price per successful task (micro-credits).
    pub avg_price_micro_credits: i64,
}

impl TaskTypeStats {
    /// Recompute derived fields.
    fn recompute(&mut self) {
        self.completion_rate = if self.total_tasks > 0 {
            self.successful_tasks as f64 / self.total_tasks as f64
        } else {
            0.0
        };
        self.net_revenue_micro_credits =
            self.total_revenue_micro_credits - self.total_refunds_micro_credits;
        self.avg_price_micro_credits = if self.successful_tasks > 0 {
            self.total_revenue_micro_credits / self.successful_tasks as i64
        } else {
            0
        };
    }
}

/// A task that has been contracted but not yet verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTask {
    pub task_id: String,
    pub contract_id: String,
    pub agent_id: String,
    pub complexity: String,
    pub agent_trust_score: f64,
    pub price_micro_credits: i64,
    pub sla_deadline_ms: i64,
    pub contracted_at: DateTime<Utc>,
}

/// The outcome pricing projection — accumulated from outcome-related finance events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutcomePricingState {
    /// Registered task contracts, keyed by `contract_id`.
    pub contracts: HashMap<String, TaskContract>,
    /// Per-task-type aggregate statistics.
    pub stats_by_type: HashMap<String, TaskTypeStats>,
    /// Tasks contracted but not yet verified/completed.
    pub pending_tasks: Vec<PendingTask>,
    /// Total outcome revenue across all task types (micro-credits).
    pub total_outcome_revenue: i64,
    /// Total refunds across all task types (micro-credits).
    pub total_outcome_refunds: i64,
    /// Total tasks contracted (lifetime).
    pub total_tasks_contracted: u64,
    /// Total tasks verified (lifetime).
    pub total_tasks_verified: u64,
    /// Total tasks refunded (lifetime).
    pub total_tasks_refunded: u64,
    /// Timestamp of last outcome event.
    pub last_event_at: Option<DateTime<Utc>>,
}

impl OutcomePricingState {
    /// Register a task contract. Does not come from events — set directly.
    pub fn register_contract(&mut self, contract: TaskContract) {
        self.contracts
            .insert(contract.contract_id.clone(), contract);
    }

    /// Apply a finance event to update the outcome projection.
    pub fn apply(&mut self, event: &FinanceEventKind, timestamp: DateTime<Utc>) {
        match event {
            FinanceEventKind::TaskContracted {
                task_id,
                contract_id,
                agent_id,
                complexity,
                price_micro_credits,
                sla_deadline_ms,
            } => {
                self.last_event_at = Some(timestamp);
                self.total_tasks_contracted += 1;
                self.pending_tasks.push(PendingTask {
                    task_id: task_id.clone(),
                    contract_id: contract_id.clone(),
                    agent_id: agent_id.clone(),
                    complexity: complexity.clone(),
                    agent_trust_score: 0.0, // Trust score stored at accept time via engine
                    price_micro_credits: *price_micro_credits,
                    sla_deadline_ms: *sla_deadline_ms,
                    contracted_at: timestamp,
                });
            }

            FinanceEventKind::TaskVerified {
                task_id,
                contract_id,
                outcome,
                price_micro_credits,
                ..
            } => {
                self.last_event_at = Some(timestamp);
                self.total_tasks_verified += 1;

                // Remove from pending.
                self.pending_tasks.retain(|t| &t.task_id != task_id);

                // Determine task type from contract.
                let task_type_key = self
                    .contracts
                    .get(contract_id)
                    .map(|c| c.task_type.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let stats = self.stats_by_type.entry(task_type_key).or_default();
                stats.total_tasks += 1;

                let parsed_outcome = match outcome.as_str() {
                    "success" => TaskOutcome::Success,
                    "failure" => TaskOutcome::Failure,
                    "partial_success" => TaskOutcome::PartialSuccess,
                    "timeout" => TaskOutcome::Timeout,
                    _ => TaskOutcome::Failure,
                };

                match parsed_outcome {
                    TaskOutcome::Success => {
                        stats.successful_tasks += 1;
                        stats.total_revenue_micro_credits += price_micro_credits;
                        self.total_outcome_revenue += price_micro_credits;
                    }
                    TaskOutcome::Failure => {
                        stats.failed_tasks += 1;
                    }
                    TaskOutcome::PartialSuccess => {
                        stats.partial_tasks += 1;
                        // Partial success still earns revenue.
                        stats.total_revenue_micro_credits += price_micro_credits;
                        self.total_outcome_revenue += price_micro_credits;
                    }
                    TaskOutcome::Timeout => {
                        stats.timed_out_tasks += 1;
                    }
                    TaskOutcome::Refunded => {
                        // Handled by TaskRefunded event.
                    }
                }

                stats.recompute();
            }

            FinanceEventKind::TaskRefunded {
                task_id,
                contract_id,
                refund_micro_credits,
                ..
            } => {
                self.last_event_at = Some(timestamp);
                self.total_tasks_refunded += 1;
                self.total_outcome_refunds += refund_micro_credits;

                // Remove from pending if still there.
                self.pending_tasks.retain(|t| &t.task_id != task_id);

                let task_type_key = self
                    .contracts
                    .get(contract_id)
                    .map(|c| c.task_type.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let stats = self.stats_by_type.entry(task_type_key).or_default();
                stats.total_refunds_micro_credits += refund_micro_credits;
                stats.recompute();
            }

            // Non-outcome events — ignore.
            _ => {}
        }
    }

    /// Generate a dashboard summary.
    pub fn dashboard(&self) -> DashboardSummary {
        DashboardSummary {
            total_tasks_contracted: self.total_tasks_contracted,
            total_tasks_verified: self.total_tasks_verified,
            total_tasks_refunded: self.total_tasks_refunded,
            pending_tasks: self.pending_tasks.len() as u64,
            total_outcome_revenue: self.total_outcome_revenue,
            total_outcome_refunds: self.total_outcome_refunds,
            net_outcome_revenue: self.total_outcome_revenue - self.total_outcome_refunds,
            stats_by_type: self.stats_by_type.clone(),
            contracts_registered: self.contracts.len() as u64,
        }
    }
}

/// Revenue dashboard summary for the outcome pricing engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub total_tasks_contracted: u64,
    pub total_tasks_verified: u64,
    pub total_tasks_refunded: u64,
    pub pending_tasks: u64,
    pub total_outcome_revenue: i64,
    pub total_outcome_refunds: i64,
    pub net_outcome_revenue: i64,
    pub stats_by_type: HashMap<String, TaskTypeStats>,
    pub contracts_registered: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use haima_core::outcome::default_code_review_contract;

    fn make_state_with_contract() -> OutcomePricingState {
        let mut state = OutcomePricingState::default();
        state.register_contract(default_code_review_contract());
        state
    }

    #[test]
    fn register_contract() {
        let state = make_state_with_contract();
        assert_eq!(state.contracts.len(), 1);
        assert!(state.contracts.contains_key("contract-code-review-v1"));
    }

    #[test]
    fn task_contracted_adds_pending() {
        let mut state = make_state_with_contract();
        state.apply(
            &FinanceEventKind::TaskContracted {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                agent_id: "agent-1".into(),
                complexity: "standard".into(),
                price_micro_credits: 3_000_000,
                sla_deadline_ms: 1_700_000_000_000,
            },
            Utc::now(),
        );
        assert_eq!(state.pending_tasks.len(), 1);
        assert_eq!(state.total_tasks_contracted, 1);
    }

    #[test]
    fn task_verified_success_updates_stats() {
        let mut state = make_state_with_contract();
        let now = Utc::now();

        state.apply(
            &FinanceEventKind::TaskContracted {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                agent_id: "agent-1".into(),
                complexity: "standard".into(),
                price_micro_credits: 3_000_000,
                sla_deadline_ms: 1_700_000_000_000,
            },
            now,
        );

        state.apply(
            &FinanceEventKind::TaskVerified {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                outcome: "success".into(),
                price_micro_credits: 3_000_000,
                criteria_passed: 2,
                criteria_total: 2,
            },
            now,
        );

        assert_eq!(state.pending_tasks.len(), 0);
        assert_eq!(state.total_tasks_verified, 1);
        assert_eq!(state.total_outcome_revenue, 3_000_000);

        let stats = state.stats_by_type.get("code_review").unwrap();
        assert_eq!(stats.total_tasks, 1);
        assert_eq!(stats.successful_tasks, 1);
        assert_eq!(stats.total_revenue_micro_credits, 3_000_000);
        assert!((stats.completion_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn task_verified_failure_no_revenue() {
        let mut state = make_state_with_contract();
        let now = Utc::now();

        state.apply(
            &FinanceEventKind::TaskContracted {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                agent_id: "agent-1".into(),
                complexity: "simple".into(),
                price_micro_credits: 2_000_000,
                sla_deadline_ms: 1_700_000_000_000,
            },
            now,
        );

        state.apply(
            &FinanceEventKind::TaskVerified {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                outcome: "failure".into(),
                price_micro_credits: 2_000_000,
                criteria_passed: 0,
                criteria_total: 2,
            },
            now,
        );

        assert_eq!(state.total_outcome_revenue, 0);
        let stats = state.stats_by_type.get("code_review").unwrap();
        assert_eq!(stats.failed_tasks, 1);
        assert_eq!(stats.total_revenue_micro_credits, 0);
    }

    #[test]
    fn task_refunded_updates_stats() {
        let mut state = make_state_with_contract();
        let now = Utc::now();

        // Contract → Verify as success → Refund
        state.apply(
            &FinanceEventKind::TaskContracted {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                agent_id: "agent-1".into(),
                complexity: "standard".into(),
                price_micro_credits: 3_000_000,
                sla_deadline_ms: 1_700_000_000_000,
            },
            now,
        );
        state.apply(
            &FinanceEventKind::TaskVerified {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                outcome: "success".into(),
                price_micro_credits: 3_000_000,
                criteria_passed: 2,
                criteria_total: 2,
            },
            now,
        );
        state.apply(
            &FinanceEventKind::TaskRefunded {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                refund_micro_credits: 3_000_000,
                reason: "customer_dispute".into(),
            },
            now,
        );

        assert_eq!(state.total_tasks_refunded, 1);
        assert_eq!(state.total_outcome_refunds, 3_000_000);

        let stats = state.stats_by_type.get("code_review").unwrap();
        assert_eq!(stats.total_refunds_micro_credits, 3_000_000);
        assert_eq!(stats.net_revenue_micro_credits, 0);
    }

    #[test]
    fn dashboard_summary() {
        let mut state = make_state_with_contract();
        let now = Utc::now();

        state.apply(
            &FinanceEventKind::TaskContracted {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                agent_id: "agent-1".into(),
                complexity: "standard".into(),
                price_micro_credits: 3_000_000,
                sla_deadline_ms: 1_700_000_000_000,
            },
            now,
        );
        state.apply(
            &FinanceEventKind::TaskVerified {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                outcome: "success".into(),
                price_micro_credits: 3_000_000,
                criteria_passed: 2,
                criteria_total: 2,
            },
            now,
        );

        let dashboard = state.dashboard();
        assert_eq!(dashboard.total_tasks_contracted, 1);
        assert_eq!(dashboard.total_tasks_verified, 1);
        assert_eq!(dashboard.pending_tasks, 0);
        assert_eq!(dashboard.total_outcome_revenue, 3_000_000);
        assert_eq!(dashboard.net_outcome_revenue, 3_000_000);
        assert_eq!(dashboard.contracts_registered, 1);
    }

    #[test]
    fn completion_rate_across_outcomes() {
        let mut state = make_state_with_contract();
        let now = Utc::now();

        // 3 tasks: 2 success, 1 failure → 66.7% completion rate
        for i in 0..3 {
            state.apply(
                &FinanceEventKind::TaskContracted {
                    task_id: format!("task-{i}"),
                    contract_id: "contract-code-review-v1".into(),
                    agent_id: "agent-1".into(),
                    complexity: "standard".into(),
                    price_micro_credits: 3_000_000,
                    sla_deadline_ms: 1_700_000_000_000,
                },
                now,
            );
        }

        state.apply(
            &FinanceEventKind::TaskVerified {
                task_id: "task-0".into(),
                contract_id: "contract-code-review-v1".into(),
                outcome: "success".into(),
                price_micro_credits: 3_000_000,
                criteria_passed: 2,
                criteria_total: 2,
            },
            now,
        );
        state.apply(
            &FinanceEventKind::TaskVerified {
                task_id: "task-1".into(),
                contract_id: "contract-code-review-v1".into(),
                outcome: "success".into(),
                price_micro_credits: 3_000_000,
                criteria_passed: 2,
                criteria_total: 2,
            },
            now,
        );
        state.apply(
            &FinanceEventKind::TaskVerified {
                task_id: "task-2".into(),
                contract_id: "contract-code-review-v1".into(),
                outcome: "failure".into(),
                price_micro_credits: 3_000_000,
                criteria_passed: 0,
                criteria_total: 2,
            },
            now,
        );

        let stats = state.stats_by_type.get("code_review").unwrap();
        assert_eq!(stats.total_tasks, 3);
        assert_eq!(stats.successful_tasks, 2);
        assert_eq!(stats.failed_tasks, 1);
        assert!((stats.completion_rate - 2.0 / 3.0).abs() < 0.01);
        assert_eq!(stats.avg_price_micro_credits, 3_000_000);
    }

    #[test]
    fn non_outcome_events_ignored() {
        let mut state = OutcomePricingState::default();
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
        assert_eq!(state.total_tasks_contracted, 0);
        assert!(state.last_event_at.is_none());
    }
}

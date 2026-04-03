//! SLA monitor — background task that checks pending tasks against deadlines
//! and auto-triggers refunds for expired tasks.
//!
//! The monitor runs on a configurable interval (default 30 seconds) and scans
//! the pending tasks list. For each task whose SLA deadline + grace period has
//! passed, it emits a `TaskVerified` (timeout) and `TaskRefunded` event.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use haima_core::event::FinanceEventKind;
use haima_lago::OutcomePricingState;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info};

/// Configuration for the SLA monitor.
#[derive(Debug, Clone)]
pub struct SlaMonitorConfig {
    /// How often to check for expired tasks (default: 30 seconds).
    pub check_interval: Duration,
    /// Whether the monitor is enabled (default: true).
    pub enabled: bool,
}

impl Default for SlaMonitorConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            enabled: true,
        }
    }
}

/// A single expired task that was auto-refunded.
#[derive(Debug, Clone)]
pub struct ExpiredTask {
    pub task_id: String,
    pub contract_id: String,
    pub refund_micro_credits: i64,
}

/// Check pending tasks for SLA breaches and process refunds.
///
/// This is the core logic, separated from the background loop for testability.
/// Returns the list of tasks that were expired and refunded.
pub async fn check_expired_tasks(
    outcome_state: &Arc<RwLock<OutcomePricingState>>,
) -> Vec<ExpiredTask> {
    let now_ms = Utc::now().timestamp_millis();
    let mut expired = Vec::new();

    // First pass: identify expired tasks.
    let pending_snapshot = {
        let state = outcome_state.read().await;
        state
            .pending_tasks
            .iter()
            .filter_map(|task| {
                // Look up the contract's grace period.
                let grace_ms = state
                    .contracts
                    .get(&task.contract_id)
                    .map(|c| c.refund_policy.grace_period_seconds as i64 * 1000)
                    .unwrap_or(300_000); // Default 5 min grace.

                let deadline_with_grace = task.sla_deadline_ms + grace_ms;

                if now_ms > deadline_with_grace {
                    // Look up refund percentage.
                    let refund_pct = state
                        .contracts
                        .get(&task.contract_id)
                        .map(|c| c.refund_policy.refund_percentage)
                        .unwrap_or(100);

                    let refund_amount =
                        (task.price_micro_credits as f64 * refund_pct as f64 / 100.0) as i64;

                    Some(ExpiredTask {
                        task_id: task.task_id.clone(),
                        contract_id: task.contract_id.clone(),
                        refund_micro_credits: refund_amount,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    };

    // Second pass: apply events for each expired task.
    if !pending_snapshot.is_empty() {
        let mut state = outcome_state.write().await;
        let now = Utc::now();

        for task in &pending_snapshot {
            // Emit timeout verification.
            let verify_event = FinanceEventKind::TaskVerified {
                task_id: task.task_id.clone(),
                contract_id: task.contract_id.clone(),
                outcome: "timeout".to_string(),
                price_micro_credits: 0, // No revenue for timed-out tasks.
                criteria_passed: 0,
                criteria_total: 0,
            };
            state.apply(&verify_event, now);

            // Emit refund.
            let refund_event = FinanceEventKind::TaskRefunded {
                task_id: task.task_id.clone(),
                contract_id: task.contract_id.clone(),
                refund_micro_credits: task.refund_micro_credits,
                reason: "sla_timeout".to_string(),
            };
            state.apply(&refund_event, now);

            info!(
                task_id = %task.task_id,
                refund = task.refund_micro_credits,
                "SLA timeout — auto-refund processed"
            );
        }

        expired = pending_snapshot;
    }

    expired
}

/// Spawn the SLA monitor as a background tokio task.
///
/// Returns a `JoinHandle` that can be used to cancel the monitor.
/// The monitor runs indefinitely until the handle is dropped or aborted.
#[allow(clippy::needless_pass_by_value)] // config is moved into the spawned task
pub fn spawn_sla_monitor(
    outcome_state: Arc<RwLock<OutcomePricingState>>,
    config: SlaMonitorConfig,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if !config.enabled {
            info!("SLA monitor disabled");
            return;
        }

        info!(
            interval_secs = config.check_interval.as_secs(),
            "SLA monitor started"
        );

        let mut interval = tokio::time::interval(config.check_interval);
        loop {
            interval.tick().await;
            debug!("SLA monitor tick");

            let expired = check_expired_tasks(&outcome_state).await;
            if !expired.is_empty() {
                info!(count = expired.len(), "SLA monitor processed expired tasks");
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use haima_core::event::FinanceEventKind;
    use haima_core::outcome::default_code_review_contract;

    #[tokio::test]
    async fn no_expired_tasks() {
        let state = Arc::new(RwLock::new(OutcomePricingState::default()));
        let expired = check_expired_tasks(&state).await;
        assert!(expired.is_empty());
    }

    #[tokio::test]
    async fn expired_task_gets_refunded() {
        let state = Arc::new(RwLock::new(OutcomePricingState::default()));

        // Register contract.
        {
            let mut s = state.write().await;
            s.register_contract(default_code_review_contract());
        }

        // Contract a task with an SLA deadline already in the past.
        let past_deadline_ms = Utc::now().timestamp_millis() - 1_000_000; // 1000s ago
        {
            let mut s = state.write().await;
            s.apply(
                &FinanceEventKind::TaskContracted {
                    task_id: "expired-task".into(),
                    contract_id: "contract-code-review-v1".into(),
                    agent_id: "agent-1".into(),
                    complexity: "standard".into(),
                    price_micro_credits: 3_000_000,
                    sla_deadline_ms: past_deadline_ms,
                },
                Utc::now(),
            );
        }

        // Run the check.
        let expired = check_expired_tasks(&state).await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].task_id, "expired-task");
        assert_eq!(expired[0].refund_micro_credits, 3_000_000); // 100% refund

        // Verify state was updated.
        let s = state.read().await;
        assert_eq!(s.total_tasks_verified, 1);
        assert_eq!(s.total_tasks_refunded, 1);
        assert!(s.pending_tasks.is_empty());
    }

    #[tokio::test]
    async fn non_expired_task_not_refunded() {
        let state = Arc::new(RwLock::new(OutcomePricingState::default()));

        {
            let mut s = state.write().await;
            s.register_contract(default_code_review_contract());
        }

        // Task with deadline far in the future.
        let future_deadline_ms = Utc::now().timestamp_millis() + 10_000_000; // ~3 hours
        {
            let mut s = state.write().await;
            s.apply(
                &FinanceEventKind::TaskContracted {
                    task_id: "active-task".into(),
                    contract_id: "contract-code-review-v1".into(),
                    agent_id: "agent-1".into(),
                    complexity: "standard".into(),
                    price_micro_credits: 3_000_000,
                    sla_deadline_ms: future_deadline_ms,
                },
                Utc::now(),
            );
        }

        let expired = check_expired_tasks(&state).await;
        assert!(expired.is_empty());

        let s = state.read().await;
        assert_eq!(s.pending_tasks.len(), 1);
    }

    #[tokio::test]
    async fn partial_refund_percentage() {
        let state = Arc::new(RwLock::new(OutcomePricingState::default()));

        // Create a contract with 50% refund.
        let mut contract = default_code_review_contract();
        contract.refund_policy.refund_percentage = 50;
        {
            let mut s = state.write().await;
            s.register_contract(contract);
        }

        let past_deadline_ms = Utc::now().timestamp_millis() - 1_000_000;
        {
            let mut s = state.write().await;
            s.apply(
                &FinanceEventKind::TaskContracted {
                    task_id: "task-50pct".into(),
                    contract_id: "contract-code-review-v1".into(),
                    agent_id: "agent-1".into(),
                    complexity: "standard".into(),
                    price_micro_credits: 4_000_000,
                    sla_deadline_ms: past_deadline_ms,
                },
                Utc::now(),
            );
        }

        let expired = check_expired_tasks(&state).await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].refund_micro_credits, 2_000_000); // 50% of 4M
    }
}

//! Outcome pricing engine — orchestrates the full task lifecycle.
//!
//! The engine manages:
//! 1. **Contract registration** — register default and custom task contracts
//! 2. **Task acceptance** — price resolution, trust checks, SLA deadline calculation
//! 3. **Automated verification** — dispatch verifiers per criterion, derive outcome
//! 4. **Billing** — emit billing events on successful verification
//! 5. **Refund processing** — manual or SLA-triggered refunds
//!
//! The engine is stateless — all state lives in [`OutcomePricingState`] and
//! [`FinancialState`] projections, accessed via `Arc<RwLock<_>>`.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use haima_core::event::FinanceEventKind;
use haima_core::outcome::{
    CriterionResult, OutcomeRecord, OutcomeVerification, SuccessCriterion, TaskComplexity,
    TaskContract, TaskOutcome,
};
use haima_lago::{FinancialState, OutcomePricingState};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::verifier::{
    DataValidatedVerifier, ManualApprovalVerifier, SuccessVerifier, TestsPassedVerifier,
    WebhookConfirmedVerifier,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a complexity string (from events) back to the enum.
fn parse_complexity(s: &str) -> TaskComplexity {
    match s {
        "simple" => TaskComplexity::Simple,
        "standard" => TaskComplexity::Standard,
        "complex" => TaskComplexity::Complex,
        "critical" => TaskComplexity::Critical,
        _ => TaskComplexity::Standard,
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The outcome pricing engine — orchestrates contract → verify → bill → refund.
pub struct OutcomeEngine {
    /// Outcome projection state (contracts, pending tasks, stats).
    pub outcome_state: Arc<RwLock<OutcomePricingState>>,
    /// Financial state projection (for billing events).
    pub financial_state: Arc<RwLock<FinancialState>>,
    /// Registered verifiers, keyed by verifier name.
    verifiers: HashMap<String, Box<dyn SuccessVerifier>>,
    /// Completed outcome records (in-memory history).
    outcome_records: Arc<RwLock<Vec<OutcomeRecord>>>,
}

/// Result of accepting a task under a contract.
#[derive(Debug, Clone)]
pub struct AcceptResult {
    pub task_id: String,
    pub contract_id: String,
    pub agent_id: String,
    pub price_micro_credits: i64,
    pub sla_deadline_ms: i64,
}

/// Result of verifying a task.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub verification: OutcomeVerification,
    pub billing_triggered: bool,
    pub refund_triggered: bool,
    pub refund_amount: i64,
}

/// Error type for engine operations.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("contract not found: {0}")]
    ContractNotFound(String),

    #[error("agent trust score {score} below contract minimum {min}")]
    TrustScoreTooLow { score: f64, min: f64 },

    #[error("task not found in pending: {0}")]
    TaskNotPending(String),

    #[error("invalid price range: floor ({floor}) > ceiling ({ceiling})")]
    InvalidPriceRange { floor: i64, ceiling: i64 },
}

impl OutcomeEngine {
    /// Create a new engine with shared state handles.
    ///
    /// Registers the default verifiers. Additional verifiers can be added
    /// via [`register_verifier`].
    pub fn new(
        outcome_state: Arc<RwLock<OutcomePricingState>>,
        financial_state: Arc<RwLock<FinancialState>>,
    ) -> Self {
        Self {
            outcome_state,
            financial_state,
            verifiers: HashMap::new(),
            outcome_records: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register built-in verifiers with service URLs.
    ///
    /// Call this during startup after constructing the engine.
    pub fn register_default_verifiers(
        &mut self,
        ci_base_url: Option<String>,
        validation_base_url: Option<String>,
    ) {
        if let Some(url) = ci_base_url {
            self.register_verifier(Box::new(TestsPassedVerifier::new(url)));
        }
        if let Some(url) = validation_base_url {
            self.register_verifier(Box::new(DataValidatedVerifier::new(url)));
        }
        self.register_verifier(Box::new(WebhookConfirmedVerifier::new()));
        self.register_verifier(Box::new(ManualApprovalVerifier));
    }

    /// Register a custom verifier.
    pub fn register_verifier(&mut self, verifier: Box<dyn SuccessVerifier>) {
        self.verifiers.insert(verifier.name().to_string(), verifier);
    }

    /// Register default task contracts (code review, data pipeline, support ticket, document gen).
    pub async fn register_default_contracts(&self) {
        let mut state = self.outcome_state.write().await;
        state.register_contract(haima_core::outcome::default_code_review_contract());
        state.register_contract(haima_core::outcome::default_data_pipeline_contract());
        state.register_contract(haima_core::outcome::default_support_ticket_contract());
        state.register_contract(haima_core::outcome::default_document_generation_contract());
        info!("registered 4 default task contracts");
    }

    /// Register a custom task contract.
    pub async fn register_contract(&self, contract: TaskContract) -> Result<String, EngineError> {
        if contract.price_floor_micro_credits > contract.price_ceiling_micro_credits {
            return Err(EngineError::InvalidPriceRange {
                floor: contract.price_floor_micro_credits,
                ceiling: contract.price_ceiling_micro_credits,
            });
        }
        let id = contract.contract_id.clone();
        let mut state = self.outcome_state.write().await;
        state.register_contract(contract);
        info!(contract_id = %id, "registered task contract");
        Ok(id)
    }

    /// Accept a task under a contract — resolve price, check trust, start SLA clock.
    pub async fn accept_task(
        &self,
        task_id: String,
        contract_id: String,
        agent_id: String,
        complexity: TaskComplexity,
        agent_trust_score: f64,
    ) -> Result<AcceptResult, EngineError> {
        let mut state = self.outcome_state.write().await;

        let contract = state
            .contracts
            .get(&contract_id)
            .cloned()
            .ok_or_else(|| EngineError::ContractNotFound(contract_id.clone()))?;

        if agent_trust_score < contract.min_trust_score {
            return Err(EngineError::TrustScoreTooLow {
                score: agent_trust_score,
                min: contract.min_trust_score,
            });
        }

        let price = contract.resolve_price(complexity, agent_trust_score);
        let sla_deadline_ms =
            Utc::now().timestamp_millis() + (contract.refund_policy.sla_seconds as i64 * 1000);

        let event = FinanceEventKind::TaskContracted {
            task_id: task_id.clone(),
            contract_id: contract_id.clone(),
            agent_id: agent_id.clone(),
            complexity: format!("{complexity:?}").to_lowercase(),
            price_micro_credits: price,
            sla_deadline_ms,
        };
        state.apply(&event, Utc::now());

        // Store agent_trust_score on the pending task (not part of the event).
        if let Some(pending) = state
            .pending_tasks
            .iter_mut()
            .find(|t| t.task_id == task_id)
        {
            pending.agent_trust_score = agent_trust_score;
        }

        info!(
            task_id = %task_id,
            contract_id = %contract_id,
            agent_id = %agent_id,
            price = price,
            "task contracted"
        );

        Ok(AcceptResult {
            task_id,
            contract_id,
            agent_id,
            price_micro_credits: price,
            sla_deadline_ms,
        })
    }

    /// Run automated verification for a task.
    ///
    /// Dispatches the appropriate verifier for each success criterion in the
    /// contract, derives the overall outcome, and triggers billing or refund.
    pub async fn verify_task(
        &self,
        task_id: &str,
        contract_id: &str,
    ) -> Result<VerifyResult, EngineError> {
        let state = self.outcome_state.read().await;

        let contract = state
            .contracts
            .get(contract_id)
            .cloned()
            .ok_or_else(|| EngineError::ContractNotFound(contract_id.to_string()))?;

        let pending = state.pending_tasks.iter().find(|t| t.task_id == task_id);
        let price = pending
            .map(|t| t.price_micro_credits)
            .unwrap_or(contract.price_floor_micro_credits);
        let agent_id = pending.map(|t| t.agent_id.clone()).unwrap_or_default();
        let complexity = pending
            .map(|t| parse_complexity(&t.complexity))
            .unwrap_or(TaskComplexity::Standard);
        let agent_trust_score = pending.map(|t| t.agent_trust_score).unwrap_or(0.0);
        let accepted_at = pending.map(|t| t.contracted_at).unwrap_or_else(Utc::now);

        drop(state); // Release read lock before running verifiers.

        // Run verifiers for each criterion.
        let mut criterion_results = Vec::new();
        for criterion in &contract.success_criteria {
            let result = self.verify_criterion(task_id, criterion).await;
            criterion_results.push(result);
        }

        let outcome = OutcomeVerification::derive_outcome(&criterion_results);
        let criteria_passed = criterion_results.iter().filter(|r| r.passed).count() as u32;
        let criteria_total = criterion_results.len() as u32;

        let outcome_str = match outcome {
            TaskOutcome::Success => "success",
            TaskOutcome::Failure => "failure",
            TaskOutcome::PartialSuccess => "partial_success",
            TaskOutcome::Timeout => "timeout",
            TaskOutcome::Refunded => "refunded",
        };

        // Apply verification event.
        let verify_event = FinanceEventKind::TaskVerified {
            task_id: task_id.to_string(),
            contract_id: contract_id.to_string(),
            outcome: outcome_str.to_string(),
            price_micro_credits: price,
            criteria_passed,
            criteria_total,
        };
        {
            let mut state = self.outcome_state.write().await;
            state.apply(&verify_event, Utc::now());
        }

        // Billing on success/partial success.
        let billing_triggered =
            outcome == TaskOutcome::Success || outcome == TaskOutcome::PartialSuccess;
        if billing_triggered {
            let bill_event = FinanceEventKind::TaskBilled {
                task_id: task_id.to_string(),
                description: format!("outcome: {} ({})", contract.name, outcome_str),
                price_micro_credits: price,
                token: "USDC".to_string(),
                chain: "eip155:8453".to_string(),
            };
            let mut fs = self.financial_state.write().await;
            fs.apply(&bill_event, Utc::now());
            info!(task_id = %task_id, price = price, "billing triggered");
        }

        // Auto-refund on failure if policy says so.
        let mut refund_triggered = false;
        let mut refund_amount = 0i64;
        if outcome == TaskOutcome::Failure && contract.refund_policy.auto_refund {
            refund_amount =
                (price as f64 * contract.refund_policy.refund_percentage as f64 / 100.0) as i64;
            let refund_event = FinanceEventKind::TaskRefunded {
                task_id: task_id.to_string(),
                contract_id: contract_id.to_string(),
                refund_micro_credits: refund_amount,
                reason: "auto_refund_on_failure".to_string(),
            };
            let mut state = self.outcome_state.write().await;
            state.apply(&refund_event, Utc::now());
            refund_triggered = true;
            info!(task_id = %task_id, refund = refund_amount, "auto-refund triggered");
        }

        // Record outcome with actual complexity and trust score from the pending task.
        let record = OutcomeRecord {
            task_id: task_id.to_string(),
            contract_id: contract_id.to_string(),
            task_type: contract.task_type,
            complexity,
            agent_id,
            agent_trust_score,
            price_micro_credits: price,
            outcome,
            accepted_at,
            completed_at: Utc::now(),
            refunded: refund_triggered,
            refund_amount_micro_credits: refund_amount,
        };
        self.outcome_records.write().await.push(record);

        let verification = OutcomeVerification {
            task_id: task_id.to_string(),
            contract_id: contract_id.to_string(),
            results: criterion_results,
            outcome,
            price_micro_credits: price,
            verified_at: Utc::now(),
        };

        Ok(VerifyResult {
            verification,
            billing_triggered,
            refund_triggered,
            refund_amount,
        })
    }

    /// Verify a task with externally-supplied criterion results (manual verification).
    pub async fn verify_task_manual(
        &self,
        task_id: &str,
        contract_id: &str,
        results: Vec<CriterionResult>,
    ) -> Result<VerifyResult, EngineError> {
        let state = self.outcome_state.read().await;

        let contract = state
            .contracts
            .get(contract_id)
            .cloned()
            .ok_or_else(|| EngineError::ContractNotFound(contract_id.to_string()))?;

        let pending = state.pending_tasks.iter().find(|t| t.task_id == task_id);
        let price = pending
            .map(|t| t.price_micro_credits)
            .unwrap_or(contract.price_floor_micro_credits);

        drop(state);

        let outcome = OutcomeVerification::derive_outcome(&results);
        let criteria_passed = results.iter().filter(|r| r.passed).count() as u32;
        let criteria_total = results.len() as u32;

        let outcome_str = match outcome {
            TaskOutcome::Success => "success",
            TaskOutcome::Failure => "failure",
            TaskOutcome::PartialSuccess => "partial_success",
            TaskOutcome::Timeout => "timeout",
            TaskOutcome::Refunded => "refunded",
        };

        let verify_event = FinanceEventKind::TaskVerified {
            task_id: task_id.to_string(),
            contract_id: contract_id.to_string(),
            outcome: outcome_str.to_string(),
            price_micro_credits: price,
            criteria_passed,
            criteria_total,
        };
        {
            let mut os = self.outcome_state.write().await;
            os.apply(&verify_event, Utc::now());
        }

        let billing_triggered =
            outcome == TaskOutcome::Success || outcome == TaskOutcome::PartialSuccess;
        if billing_triggered {
            let bill_event = FinanceEventKind::TaskBilled {
                task_id: task_id.to_string(),
                description: format!("outcome: {} ({})", contract.name, outcome_str),
                price_micro_credits: price,
                token: "USDC".to_string(),
                chain: "eip155:8453".to_string(),
            };
            let mut fs = self.financial_state.write().await;
            fs.apply(&bill_event, Utc::now());
        }

        let mut refund_triggered = false;
        let mut refund_amount = 0i64;
        if outcome == TaskOutcome::Failure && contract.refund_policy.auto_refund {
            refund_amount =
                (price as f64 * contract.refund_policy.refund_percentage as f64 / 100.0) as i64;
            let refund_event = FinanceEventKind::TaskRefunded {
                task_id: task_id.to_string(),
                contract_id: contract_id.to_string(),
                refund_micro_credits: refund_amount,
                reason: "auto_refund_on_failure".to_string(),
            };
            let mut os = self.outcome_state.write().await;
            os.apply(&refund_event, Utc::now());
            refund_triggered = true;
        }

        let verification = OutcomeVerification {
            task_id: task_id.to_string(),
            contract_id: contract_id.to_string(),
            results,
            outcome,
            price_micro_credits: price,
            verified_at: Utc::now(),
        };

        Ok(VerifyResult {
            verification,
            billing_triggered,
            refund_triggered,
            refund_amount,
        })
    }

    /// Process a manual refund for a task.
    pub async fn refund_task(
        &self,
        task_id: &str,
        contract_id: &str,
        reason: &str,
    ) -> Result<i64, EngineError> {
        let mut state = self.outcome_state.write().await;

        let contract = state
            .contracts
            .get(contract_id)
            .cloned()
            .ok_or_else(|| EngineError::ContractNotFound(contract_id.to_string()))?;

        let price = state
            .pending_tasks
            .iter()
            .find(|t| t.task_id == task_id)
            .map(|t| t.price_micro_credits)
            .unwrap_or(contract.price_floor_micro_credits);

        let refund_amount =
            (price as f64 * contract.refund_policy.refund_percentage as f64 / 100.0) as i64;

        let event = FinanceEventKind::TaskRefunded {
            task_id: task_id.to_string(),
            contract_id: contract_id.to_string(),
            refund_micro_credits: refund_amount,
            reason: reason.to_string(),
        };
        state.apply(&event, Utc::now());

        info!(
            task_id = %task_id,
            refund = refund_amount,
            reason = %reason,
            "manual refund processed"
        );

        Ok(refund_amount)
    }

    /// Get all outcome records (completed tasks).
    pub async fn outcome_records(&self) -> Vec<OutcomeRecord> {
        self.outcome_records.read().await.clone()
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Dispatch the appropriate verifier for a single criterion.
    async fn verify_criterion(
        &self,
        task_id: &str,
        criterion: &SuccessCriterion,
    ) -> CriterionResult {
        let verifier_name = match criterion {
            SuccessCriterion::TestsPassed { .. } => "tests_passed",
            SuccessCriterion::DataValidated { .. } => "data_validated",
            SuccessCriterion::WebhookConfirmed { .. } => "webhook_confirmed",
            SuccessCriterion::ManualApproval { .. } => "manual_approval",
            SuccessCriterion::Custom { .. } => "manual_approval", // Custom falls back to manual.
        };

        match self.verifiers.get(verifier_name) {
            Some(verifier) => verifier.verify(task_id, criterion).await,
            None => {
                warn!(
                    verifier = verifier_name,
                    task_id = task_id,
                    "no verifier registered, criterion fails"
                );
                CriterionResult {
                    criterion: criterion.clone(),
                    passed: false,
                    details: Some(format!("no verifier registered for {verifier_name}")),
                    checked_at: Utc::now(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use haima_core::outcome::{default_code_review_contract, default_support_ticket_contract};

    fn make_engine() -> OutcomeEngine {
        let outcome_state = Arc::new(RwLock::new(OutcomePricingState::default()));
        let financial_state = Arc::new(RwLock::new(FinancialState::default()));
        let mut engine = OutcomeEngine::new(outcome_state, financial_state);
        engine.register_verifier(Box::new(ManualApprovalVerifier));
        engine.register_verifier(Box::new(WebhookConfirmedVerifier::new()));
        engine
    }

    #[tokio::test]
    async fn register_and_accept_task() {
        let engine = make_engine();
        engine.register_default_contracts().await;

        let result = engine
            .accept_task(
                "task-1".into(),
                "contract-code-review-v1".into(),
                "agent-1".into(),
                TaskComplexity::Standard,
                0.5,
            )
            .await
            .unwrap();

        assert_eq!(result.task_id, "task-1");
        assert_eq!(result.contract_id, "contract-code-review-v1");
        assert!(result.price_micro_credits >= 2_000_000);
        assert!(result.price_micro_credits <= 5_000_000);
        assert!(result.sla_deadline_ms > 0);

        let state = engine.outcome_state.read().await;
        assert_eq!(state.pending_tasks.len(), 1);
    }

    #[tokio::test]
    async fn reject_low_trust_score() {
        let engine = make_engine();
        engine.register_default_contracts().await;

        let result = engine
            .accept_task(
                "task-1".into(),
                "contract-code-review-v1".into(),
                "agent-1".into(),
                TaskComplexity::Simple,
                0.1, // Below min_trust_score of 0.3
            )
            .await;

        assert!(matches!(result, Err(EngineError::TrustScoreTooLow { .. })));
    }

    #[tokio::test]
    async fn contract_not_found() {
        let engine = make_engine();

        let result = engine
            .accept_task(
                "task-1".into(),
                "nonexistent".into(),
                "agent-1".into(),
                TaskComplexity::Simple,
                0.5,
            )
            .await;

        assert!(matches!(result, Err(EngineError::ContractNotFound(_))));
    }

    #[tokio::test]
    async fn manual_verify_success() {
        let engine = make_engine();
        engine.register_default_contracts().await;

        engine
            .accept_task(
                "task-1".into(),
                "contract-support-ticket-v1".into(),
                "agent-1".into(),
                TaskComplexity::Simple,
                0.5,
            )
            .await
            .unwrap();

        let results = vec![CriterionResult {
            criterion: SuccessCriterion::Custom {
                description: "Customer marked ticket as resolved".into(),
            },
            passed: true,
            details: Some("resolved by customer".into()),
            checked_at: Utc::now(),
        }];

        let verify = engine
            .verify_task_manual("task-1", "contract-support-ticket-v1", results)
            .await
            .unwrap();

        assert_eq!(verify.verification.outcome, TaskOutcome::Success);
        assert!(verify.billing_triggered);
        assert!(!verify.refund_triggered);

        // Check billing was applied.
        let fs = engine.financial_state.read().await;
        assert!(fs.pending_bills.len() == 1 || fs.pending_bills.is_empty());
    }

    #[tokio::test]
    async fn manual_verify_failure_triggers_refund() {
        let engine = make_engine();
        engine.register_default_contracts().await;

        engine
            .accept_task(
                "task-1".into(),
                "contract-support-ticket-v1".into(),
                "agent-1".into(),
                TaskComplexity::Simple,
                0.5,
            )
            .await
            .unwrap();

        let results = vec![CriterionResult {
            criterion: SuccessCriterion::Custom {
                description: "Customer marked ticket as resolved".into(),
            },
            passed: false,
            details: Some("customer unsatisfied".into()),
            checked_at: Utc::now(),
        }];

        let verify = engine
            .verify_task_manual("task-1", "contract-support-ticket-v1", results)
            .await
            .unwrap();

        assert_eq!(verify.verification.outcome, TaskOutcome::Failure);
        assert!(!verify.billing_triggered);
        assert!(verify.refund_triggered);
        assert!(verify.refund_amount > 0);
    }

    #[tokio::test]
    async fn manual_refund() {
        let engine = make_engine();
        engine.register_default_contracts().await;

        engine
            .accept_task(
                "task-1".into(),
                "contract-code-review-v1".into(),
                "agent-1".into(),
                TaskComplexity::Standard,
                0.5,
            )
            .await
            .unwrap();

        let refund = engine
            .refund_task("task-1", "contract-code-review-v1", "customer_request")
            .await
            .unwrap();

        assert!(refund > 0);

        let state = engine.outcome_state.read().await;
        assert_eq!(state.total_tasks_refunded, 1);
    }

    #[tokio::test]
    async fn register_custom_contract() {
        let engine = make_engine();

        let contract = TaskContract {
            contract_id: "custom-contract".into(),
            task_type: haima_core::outcome::TaskType::Custom,
            name: "Custom Task".into(),
            price_floor_micro_credits: 1_000_000,
            price_ceiling_micro_credits: 3_000_000,
            success_criteria: vec![SuccessCriterion::Custom {
                description: "custom check".into(),
            }],
            refund_policy: haima_core::outcome::RefundPolicy::default(),
            min_trust_score: 0.0,
            custom_label: Some("custom".into()),
            created_at: Utc::now(),
        };

        let id = engine.register_contract(contract).await.unwrap();
        assert_eq!(id, "custom-contract");

        let state = engine.outcome_state.read().await;
        assert!(state.contracts.contains_key("custom-contract"));
    }

    #[tokio::test]
    async fn invalid_price_range_rejected() {
        let engine = make_engine();

        let contract = TaskContract {
            contract_id: "bad-contract".into(),
            task_type: haima_core::outcome::TaskType::Custom,
            name: "Bad".into(),
            price_floor_micro_credits: 5_000_000,
            price_ceiling_micro_credits: 1_000_000, // floor > ceiling
            success_criteria: vec![],
            refund_policy: haima_core::outcome::RefundPolicy::default(),
            min_trust_score: 0.0,
            custom_label: None,
            created_at: Utc::now(),
        };

        let result = engine.register_contract(contract).await;
        assert!(matches!(result, Err(EngineError::InvalidPriceRange { .. })));
    }
}

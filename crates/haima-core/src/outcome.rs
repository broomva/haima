//! Outcome-based pricing engine — task contracts, success verification, and pricing tiers.
//!
//! Implements the "charge per outcome, not per seat or per token" model:
//! - **Task contracts** define what "done" means for each task type
//! - **Success verification** provides automated checks (tests pass, data validated, etc.)
//! - **Pricing tiers** adjust price by task complexity and agent trust score
//! - **Refund policy** handles automatic refunds when SLA is not met
//!
//! # Pricing Examples
//!
//! | Task Type           | Price Range (USDC)  |
//! |---------------------|---------------------|
//! | Code review         | $2 - $5 per PR      |
//! | Data pipeline       | $5 - $20 per run    |
//! | Support ticket      | $0.50 - $2.00       |
//! | Document generation | $1 - $10            |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Task types
// ---------------------------------------------------------------------------

/// The category of task being priced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    /// Code review of a pull request.
    CodeReview,
    /// Data pipeline execution (ETL, transformations).
    DataPipeline,
    /// Customer support ticket resolution.
    SupportTicket,
    /// Document generation (reports, specs, etc.).
    DocumentGeneration,
    /// User-defined task type.
    Custom,
}

impl std::fmt::Display for TaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeReview => write!(f, "code_review"),
            Self::DataPipeline => write!(f, "data_pipeline"),
            Self::SupportTicket => write!(f, "support_ticket"),
            Self::DocumentGeneration => write!(f, "document_generation"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

// ---------------------------------------------------------------------------
// Task complexity
// ---------------------------------------------------------------------------

/// Complexity level of a task — drives pricing within a contract's range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskComplexity {
    /// Trivial task — minimum price.
    Simple,
    /// Normal task — midpoint price.
    Standard,
    /// Involved task — upper-range price.
    Complex,
    /// Mission-critical or urgent — maximum price.
    Critical,
}

impl TaskComplexity {
    /// Multiplier applied to the base price (0.0 - 1.0 within the range).
    fn range_position(&self) -> f64 {
        match self {
            Self::Simple => 0.0,
            Self::Standard => 0.33,
            Self::Complex => 0.66,
            Self::Critical => 1.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Success criteria
// ---------------------------------------------------------------------------

/// A criterion that must be satisfied for a task to be considered successful.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SuccessCriterion {
    /// All tests in the specified scope must pass.
    TestsPassed {
        /// Scope of tests (e.g., "unit", "integration", "e2e").
        scope: String,
    },
    /// Output data must pass validation against a schema or set of rules.
    DataValidated {
        /// Validation rule identifier.
        rule_id: String,
    },
    /// Explicit approval from the customer or reviewer.
    ManualApproval {
        /// Who must approve (role or agent ID).
        approver: String,
    },
    /// A webhook returned a success status code.
    WebhookConfirmed {
        /// The webhook URL that was called.
        url: String,
    },
    /// Custom criterion with a freeform description.
    Custom {
        /// Human-readable description of what must be true.
        description: String,
    },
}

// ---------------------------------------------------------------------------
// Refund policy
// ---------------------------------------------------------------------------

/// Policy governing when refunds are issued for failed tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundPolicy {
    /// Whether automatic refunds are enabled.
    pub auto_refund: bool,
    /// SLA deadline in seconds from task acceptance. If the task is not
    /// verified as successful within this window, a refund is triggered.
    pub sla_seconds: u64,
    /// Percentage of the billed amount to refund (0 - 100).
    /// 100 = full refund, 50 = half refund, etc.
    pub refund_percentage: u8,
    /// Grace period in seconds after SLA expiry before auto-refund fires.
    pub grace_period_seconds: u64,
}

impl Default for RefundPolicy {
    fn default() -> Self {
        Self {
            auto_refund: true,
            sla_seconds: 3600,         // 1 hour
            refund_percentage: 100,    // full refund
            grace_period_seconds: 300, // 5 minute grace
        }
    }
}

// ---------------------------------------------------------------------------
// Task contract
// ---------------------------------------------------------------------------

/// A task contract defines the pricing, success criteria, and SLA for a task type.
///
/// Contracts are registered once and applied to every task of that type.
/// The actual price is resolved at billing time based on complexity and trust score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskContract {
    /// Unique contract identifier.
    pub contract_id: String,
    /// The task type this contract covers.
    pub task_type: TaskType,
    /// Human-readable name for this contract.
    pub name: String,
    /// Minimum price in micro-credits (e.g., 500_000 = $0.50).
    pub price_floor_micro_credits: i64,
    /// Maximum price in micro-credits (e.g., 5_000_000 = $5.00).
    pub price_ceiling_micro_credits: i64,
    /// Success criteria that must all be satisfied.
    pub success_criteria: Vec<SuccessCriterion>,
    /// Refund policy for failed tasks.
    pub refund_policy: RefundPolicy,
    /// Minimum trust score (0.0 - 1.0) required for an agent to accept this task.
    /// Higher trust score → lower price within the range.
    pub min_trust_score: f64,
    /// Optional custom label for the task type (used when `task_type` is `Custom`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
    /// When this contract was created.
    pub created_at: DateTime<Utc>,
}

impl TaskContract {
    /// Resolve the price in micro-credits for a given complexity and trust score.
    ///
    /// Higher trust score → discount (lower end of range).
    /// Higher complexity → premium (upper end of range).
    ///
    /// Formula:
    /// ```text
    /// range = ceiling - floor
    /// complexity_offset = range * complexity_position
    /// trust_discount = range * trust_score * 0.2  (up to 20% discount)
    /// price = floor + complexity_offset - trust_discount
    /// ```
    pub fn resolve_price(&self, complexity: TaskComplexity, trust_score: f64) -> i64 {
        let range = self.price_ceiling_micro_credits - self.price_floor_micro_credits;
        if range <= 0 {
            return self.price_floor_micro_credits;
        }

        let complexity_offset = (range as f64 * complexity.range_position()) as i64;
        // Trust discount: up to 20% of the range for a perfect trust score.
        let trust_discount = (range as f64 * trust_score.clamp(0.0, 1.0) * 0.2) as i64;

        let price = self.price_floor_micro_credits + complexity_offset - trust_discount;
        // Clamp to [floor, ceiling].
        price.clamp(
            self.price_floor_micro_credits,
            self.price_ceiling_micro_credits,
        )
    }
}

// ---------------------------------------------------------------------------
// Task outcome
// ---------------------------------------------------------------------------

/// The result of executing and verifying a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskOutcome {
    /// All success criteria were met — bill the customer.
    Success,
    /// One or more success criteria failed — trigger refund policy.
    Failure,
    /// Some criteria met — partial billing may apply.
    PartialSuccess,
    /// Task exceeded the SLA deadline — auto-refund triggered.
    Timeout,
    /// Refund was already processed for this task.
    Refunded,
}

/// A verification result for a single success criterion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionResult {
    /// Which criterion was checked.
    pub criterion: SuccessCriterion,
    /// Whether this criterion passed.
    pub passed: bool,
    /// Optional details about the check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// When the check was performed.
    pub checked_at: DateTime<Utc>,
}

/// Complete verification record for a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeVerification {
    /// The task being verified.
    pub task_id: String,
    /// The contract that governs this task.
    pub contract_id: String,
    /// Individual criterion results.
    pub results: Vec<CriterionResult>,
    /// Overall outcome.
    pub outcome: TaskOutcome,
    /// The price that was (or would be) charged.
    pub price_micro_credits: i64,
    /// When verification was completed.
    pub verified_at: DateTime<Utc>,
}

impl OutcomeVerification {
    /// Derive the overall outcome from individual criterion results.
    pub fn derive_outcome(results: &[CriterionResult]) -> TaskOutcome {
        if results.is_empty() {
            return TaskOutcome::Failure;
        }
        let passed = results.iter().filter(|r| r.passed).count();
        let total = results.len();
        if passed == total {
            TaskOutcome::Success
        } else if passed > 0 {
            TaskOutcome::PartialSuccess
        } else {
            TaskOutcome::Failure
        }
    }
}

/// A record of a completed task with its outcome and billing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeRecord {
    /// Unique task identifier.
    pub task_id: String,
    /// Contract that governed this task.
    pub contract_id: String,
    /// Task type.
    pub task_type: TaskType,
    /// Complexity level assigned to this task.
    pub complexity: TaskComplexity,
    /// Agent that executed the task.
    pub agent_id: String,
    /// Trust score of the agent at the time of billing.
    pub agent_trust_score: f64,
    /// Price charged in micro-credits.
    pub price_micro_credits: i64,
    /// Task outcome.
    pub outcome: TaskOutcome,
    /// When the task was accepted.
    pub accepted_at: DateTime<Utc>,
    /// When the task was completed (or timed out).
    pub completed_at: DateTime<Utc>,
    /// Whether a refund was issued.
    pub refunded: bool,
    /// Refund amount in micro-credits (0 if no refund).
    pub refund_amount_micro_credits: i64,
}

// ---------------------------------------------------------------------------
// Default contracts
// ---------------------------------------------------------------------------

/// Create the default contract for code review tasks.
///
/// Price range: $2 - $5 per PR (2,000,000 - 5,000,000 micro-credits).
pub fn default_code_review_contract() -> TaskContract {
    TaskContract {
        contract_id: "contract-code-review-v1".into(),
        task_type: TaskType::CodeReview,
        name: "Code Review".into(),
        price_floor_micro_credits: 2_000_000,
        price_ceiling_micro_credits: 5_000_000,
        success_criteria: vec![
            SuccessCriterion::TestsPassed {
                scope: "unit".into(),
            },
            SuccessCriterion::ManualApproval {
                approver: "reviewer".into(),
            },
        ],
        refund_policy: RefundPolicy {
            sla_seconds: 7200, // 2 hours
            ..Default::default()
        },
        min_trust_score: 0.3,
        custom_label: None,
        created_at: Utc::now(),
    }
}

/// Create the default contract for data pipeline tasks.
///
/// Price range: $5 - $20 per pipeline run.
pub fn default_data_pipeline_contract() -> TaskContract {
    TaskContract {
        contract_id: "contract-data-pipeline-v1".into(),
        task_type: TaskType::DataPipeline,
        name: "Data Pipeline Run".into(),
        price_floor_micro_credits: 5_000_000,
        price_ceiling_micro_credits: 20_000_000,
        success_criteria: vec![SuccessCriterion::DataValidated {
            rule_id: "pipeline-output-schema".into(),
        }],
        refund_policy: RefundPolicy {
            sla_seconds: 3600, // 1 hour
            ..Default::default()
        },
        min_trust_score: 0.5,
        custom_label: None,
        created_at: Utc::now(),
    }
}

/// Create the default contract for support ticket resolution.
///
/// Price range: $0.50 - $2.00 per ticket.
pub fn default_support_ticket_contract() -> TaskContract {
    TaskContract {
        contract_id: "contract-support-ticket-v1".into(),
        task_type: TaskType::SupportTicket,
        name: "Support Ticket Resolution".into(),
        price_floor_micro_credits: 500_000,
        price_ceiling_micro_credits: 2_000_000,
        success_criteria: vec![SuccessCriterion::Custom {
            description: "Customer marked ticket as resolved".into(),
        }],
        refund_policy: RefundPolicy {
            sla_seconds: 1800, // 30 minutes
            ..Default::default()
        },
        min_trust_score: 0.3,
        custom_label: None,
        created_at: Utc::now(),
    }
}

/// Create the default contract for document generation.
///
/// Price range: $1 - $10 per document.
pub fn default_document_generation_contract() -> TaskContract {
    TaskContract {
        contract_id: "contract-doc-gen-v1".into(),
        task_type: TaskType::DocumentGeneration,
        name: "Document Generation".into(),
        price_floor_micro_credits: 1_000_000,
        price_ceiling_micro_credits: 10_000_000,
        success_criteria: vec![SuccessCriterion::DataValidated {
            rule_id: "document-schema".into(),
        }],
        refund_policy: RefundPolicy {
            sla_seconds: 3600,
            ..Default::default()
        },
        min_trust_score: 0.3,
        custom_label: None,
        created_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_type_display() {
        assert_eq!(TaskType::CodeReview.to_string(), "code_review");
        assert_eq!(TaskType::DataPipeline.to_string(), "data_pipeline");
        assert_eq!(TaskType::SupportTicket.to_string(), "support_ticket");
        assert_eq!(
            TaskType::DocumentGeneration.to_string(),
            "document_generation"
        );
        assert_eq!(TaskType::Custom.to_string(), "custom");
    }

    #[test]
    fn task_type_serde_roundtrip() {
        let tt = TaskType::CodeReview;
        let json = serde_json::to_string(&tt).unwrap();
        assert_eq!(json, "\"code_review\"");
        let back: TaskType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tt);
    }

    #[test]
    fn resolve_price_simple_no_trust() {
        let contract = default_code_review_contract();
        // Simple + 0.0 trust → floor price
        let price = contract.resolve_price(TaskComplexity::Simple, 0.0);
        assert_eq!(price, 2_000_000);
    }

    #[test]
    fn resolve_price_critical_no_trust() {
        let contract = default_code_review_contract();
        // Critical + 0.0 trust → ceiling price
        let price = contract.resolve_price(TaskComplexity::Critical, 0.0);
        assert_eq!(price, 5_000_000);
    }

    #[test]
    fn resolve_price_simple_max_trust() {
        let contract = default_code_review_contract();
        // Simple + 1.0 trust → floor - 20% discount, clamped to floor
        let price = contract.resolve_price(TaskComplexity::Simple, 1.0);
        // floor + 0 - 600_000 → 1_400_000 clamped to 2_000_000
        assert_eq!(price, 2_000_000);
    }

    #[test]
    fn resolve_price_critical_max_trust() {
        let contract = default_code_review_contract();
        // Critical + 1.0 trust → ceiling - 20% discount
        let price = contract.resolve_price(TaskComplexity::Critical, 1.0);
        // floor(2M) + range(3M) - discount(600k) = 4_400_000
        assert_eq!(price, 4_400_000);
    }

    #[test]
    fn resolve_price_standard_mid_trust() {
        let contract = default_code_review_contract();
        // Standard + 0.5 trust
        let price = contract.resolve_price(TaskComplexity::Standard, 0.5);
        // range = 3M, complexity_offset = 3M * 0.33 = 990_000
        // trust_discount = 3M * 0.5 * 0.2 = 300_000
        // price = 2M + 990k - 300k = 2_690_000
        assert_eq!(price, 2_690_000);
    }

    #[test]
    fn resolve_price_flat_range() {
        // When floor == ceiling, price is always the floor.
        let contract = TaskContract {
            contract_id: "flat".into(),
            task_type: TaskType::Custom,
            name: "Flat Price".into(),
            price_floor_micro_credits: 1_000_000,
            price_ceiling_micro_credits: 1_000_000,
            success_criteria: vec![],
            refund_policy: RefundPolicy::default(),
            min_trust_score: 0.0,
            custom_label: Some("flat".into()),
            created_at: Utc::now(),
        };
        assert_eq!(
            contract.resolve_price(TaskComplexity::Critical, 1.0),
            1_000_000
        );
    }

    #[test]
    fn derive_outcome_all_pass() {
        let results = vec![
            CriterionResult {
                criterion: SuccessCriterion::TestsPassed {
                    scope: "unit".into(),
                },
                passed: true,
                details: None,
                checked_at: Utc::now(),
            },
            CriterionResult {
                criterion: SuccessCriterion::DataValidated {
                    rule_id: "schema-1".into(),
                },
                passed: true,
                details: None,
                checked_at: Utc::now(),
            },
        ];
        assert_eq!(
            OutcomeVerification::derive_outcome(&results),
            TaskOutcome::Success
        );
    }

    #[test]
    fn derive_outcome_partial() {
        let results = vec![
            CriterionResult {
                criterion: SuccessCriterion::TestsPassed {
                    scope: "unit".into(),
                },
                passed: true,
                details: None,
                checked_at: Utc::now(),
            },
            CriterionResult {
                criterion: SuccessCriterion::ManualApproval {
                    approver: "reviewer".into(),
                },
                passed: false,
                details: Some("reviewer rejected".into()),
                checked_at: Utc::now(),
            },
        ];
        assert_eq!(
            OutcomeVerification::derive_outcome(&results),
            TaskOutcome::PartialSuccess
        );
    }

    #[test]
    fn derive_outcome_all_fail() {
        let results = vec![CriterionResult {
            criterion: SuccessCriterion::TestsPassed {
                scope: "e2e".into(),
            },
            passed: false,
            details: Some("3 tests failed".into()),
            checked_at: Utc::now(),
        }];
        assert_eq!(
            OutcomeVerification::derive_outcome(&results),
            TaskOutcome::Failure
        );
    }

    #[test]
    fn derive_outcome_empty() {
        assert_eq!(
            OutcomeVerification::derive_outcome(&[]),
            TaskOutcome::Failure
        );
    }

    #[test]
    fn default_contracts_have_valid_ranges() {
        let contracts = vec![
            default_code_review_contract(),
            default_data_pipeline_contract(),
            default_support_ticket_contract(),
            default_document_generation_contract(),
        ];
        for c in &contracts {
            assert!(
                c.price_floor_micro_credits <= c.price_ceiling_micro_credits,
                "contract {} has floor > ceiling",
                c.contract_id
            );
            assert!(
                !c.success_criteria.is_empty(),
                "contract {} has no success criteria",
                c.contract_id
            );
            assert!(c.min_trust_score >= 0.0 && c.min_trust_score <= 1.0);
        }
    }

    #[test]
    fn refund_policy_default() {
        let policy = RefundPolicy::default();
        assert!(policy.auto_refund);
        assert_eq!(policy.sla_seconds, 3600);
        assert_eq!(policy.refund_percentage, 100);
        assert_eq!(policy.grace_period_seconds, 300);
    }

    #[test]
    fn task_contract_serde_roundtrip() {
        let contract = default_code_review_contract();
        let json = serde_json::to_string(&contract).unwrap();
        let back: TaskContract = serde_json::from_str(&json).unwrap();
        assert_eq!(back.contract_id, contract.contract_id);
        assert_eq!(back.task_type, contract.task_type);
        assert_eq!(
            back.price_floor_micro_credits,
            contract.price_floor_micro_credits
        );
    }

    #[test]
    fn outcome_record_serde_roundtrip() {
        let record = OutcomeRecord {
            task_id: "task-1".into(),
            contract_id: "contract-code-review-v1".into(),
            task_type: TaskType::CodeReview,
            complexity: TaskComplexity::Standard,
            agent_id: "agent-1".into(),
            agent_trust_score: 0.8,
            price_micro_credits: 3_000_000,
            outcome: TaskOutcome::Success,
            accepted_at: Utc::now(),
            completed_at: Utc::now(),
            refunded: false,
            refund_amount_micro_credits: 0,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: OutcomeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.task_id, "task-1");
        assert_eq!(back.outcome, TaskOutcome::Success);
    }

    #[test]
    fn support_ticket_pricing_range() {
        let contract = default_support_ticket_contract();
        let min = contract.resolve_price(TaskComplexity::Simple, 1.0);
        let max = contract.resolve_price(TaskComplexity::Critical, 0.0);
        // Min should be >= floor
        assert!(min >= 500_000, "min = {min}");
        // Max should be <= ceiling
        assert!(max <= 2_000_000, "max = {max}");
    }

    #[test]
    fn data_pipeline_pricing_range() {
        let contract = default_data_pipeline_contract();
        let min = contract.resolve_price(TaskComplexity::Simple, 1.0);
        let max = contract.resolve_price(TaskComplexity::Critical, 0.0);
        assert!(min >= 5_000_000, "min = {min}");
        assert!(max <= 20_000_000, "max = {max}");
    }
}

//! Agent Credit Bureau — behavioral risk registry for the Agent OS.
//!
//! Aggregates credit scores (from Haima) and trust scores (from Autonomic)
//! into a unified credit report with risk ratings, payment summaries,
//! credit line utilization, and risk flags.
//!
//! The bureau acts as the cross-network view of an agent's financial
//! reputation, enabling other agents and facilitators to assess
//! counterparty risk before engaging in transactions.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::credit::CreditTier;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A comprehensive credit report for an agent, combining credit and trust data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCreditReport {
    /// The agent this report describes.
    pub agent_id: String,
    /// DID:key if available (decentralized identity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Composite credit score (0.0 - 1.0).
    pub credit_score: f64,
    /// Credit tier derived from the composite score.
    pub credit_tier: CreditTier,
    /// Trust score from Autonomic (0.0 - 1.0).
    pub trust_score: f64,
    /// Trust tier string (unverified/provisional/trusted/certified).
    pub trust_tier: String,
    /// Overall risk rating based on scores and flags.
    pub risk_rating: RiskRating,
    /// Summary of the agent's payment history.
    pub payment_summary: PaymentSummary,
    /// Active credit lines and their utilization.
    pub credit_lines: Vec<CreditLineSummary>,
    /// Active risk flags detected for this agent.
    pub flags: Vec<RiskFlag>,
    /// When this report was generated.
    pub report_generated_at: DateTime<Utc>,
}

/// Overall risk rating for an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskRating {
    /// Score >= 0.75, no flags.
    Low,
    /// Score 0.5 - 0.75, minor flags only.
    Medium,
    /// Score 0.3 - 0.5, major flags.
    High,
    /// Score < 0.3, default history.
    Critical,
}

impl std::fmt::Display for RiskRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Summary of an agent's payment history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSummary {
    /// Total number of transactions.
    pub total_transactions: u64,
    /// Total volume in micro-USD.
    pub total_volume_micro_usd: u64,
    /// Ratio of on-time payments (0.0 - 1.0).
    pub on_time_rate: f64,
    /// Average settlement time in milliseconds.
    pub average_settlement_time_ms: u64,
    /// Number of defaults (failed payments).
    pub defaults: u32,
    /// Timestamp of the oldest transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_transaction_at: Option<DateTime<Utc>>,
}

impl Default for PaymentSummary {
    fn default() -> Self {
        Self {
            total_transactions: 0,
            total_volume_micro_usd: 0,
            on_time_rate: 0.0,
            average_settlement_time_ms: 0,
            defaults: 0,
            oldest_transaction_at: None,
        }
    }
}

/// Summary of a single credit line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditLineSummary {
    /// Credit limit in micro-USD.
    pub limit_micro_usd: u64,
    /// Amount currently drawn in micro-USD.
    pub drawn_micro_usd: u64,
    /// Utilization ratio (drawn / limit, 0.0 - 1.0).
    pub utilization_ratio: f64,
    /// Status of this credit line (e.g., "active", "frozen", "closed").
    pub status: String,
}

/// A risk flag detected for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFlag {
    /// The type of risk detected.
    pub flag_type: RiskFlagType,
    /// Severity level: "info", "warning", or "critical".
    pub severity: String,
    /// Human-readable description.
    pub description: String,
    /// When this flag was detected.
    pub detected_at: DateTime<Utc>,
}

/// Types of risk flags that can be detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlagType {
    /// Credit utilization exceeds 80%.
    HighUtilization,
    /// Default (failed payment) in the last 30 days.
    RecentDefault,
    /// Trust trajectory is "degrading".
    TrustDegrading,
    /// Account is less than 7 days old.
    NewAgent,
    /// Spending velocity exceeds threshold.
    RapidSpending,
    /// Agent is in Hibernate economic mode.
    EconomicHibernate,
}

impl std::fmt::Display for RiskFlagType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighUtilization => write!(f, "high_utilization"),
            Self::RecentDefault => write!(f, "recent_default"),
            Self::TrustDegrading => write!(f, "trust_degrading"),
            Self::NewAgent => write!(f, "new_agent"),
            Self::RapidSpending => write!(f, "rapid_spending"),
            Self::EconomicHibernate => write!(f, "economic_hibernate"),
        }
    }
}

// ---------------------------------------------------------------------------
// Input parameters for bureau functions
// ---------------------------------------------------------------------------

/// Payment history data used for report generation and flag detection.
#[derive(Debug, Clone)]
pub struct PaymentHistory {
    /// Total transactions processed.
    pub total_transactions: u64,
    /// Total volume in micro-USD.
    pub total_volume_micro_usd: u64,
    /// On-time payment rate (0.0 - 1.0).
    pub on_time_rate: f64,
    /// Average settlement time in milliseconds.
    pub average_settlement_time_ms: u64,
    /// Number of payment defaults.
    pub defaults: u32,
    /// When the oldest transaction occurred.
    pub oldest_transaction_at: Option<DateTime<Utc>>,
    /// Whether a default occurred in the last 30 days.
    pub has_recent_default: bool,
    /// Whether spending velocity is above normal thresholds.
    pub rapid_spending: bool,
    /// Whether the agent is in Hibernate economic mode.
    pub economic_hibernate: bool,
}

impl Default for PaymentHistory {
    fn default() -> Self {
        Self {
            total_transactions: 0,
            total_volume_micro_usd: 0,
            on_time_rate: 0.0,
            average_settlement_time_ms: 0,
            defaults: 0,
            oldest_transaction_at: None,
            has_recent_default: false,
            rapid_spending: false,
            economic_hibernate: false,
        }
    }
}

/// Trust trajectory from Autonomic, used for flag detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTrajectory {
    /// Trust score is improving.
    Improving,
    /// Trust score is stable.
    Stable,
    /// Trust score is degrading.
    Degrading,
}

/// Additional context for trust data used in report generation.
#[derive(Debug, Clone)]
pub struct TrustContext {
    /// Trust score (0.0 - 1.0).
    pub score: f64,
    /// Trust tier string.
    pub tier: String,
    /// Trust trajectory direction.
    pub trajectory: TrustTrajectory,
}

impl Default for TrustContext {
    fn default() -> Self {
        Self {
            score: 0.0,
            tier: "unverified".to_string(),
            trajectory: TrustTrajectory::Stable,
        }
    }
}

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/// Credit utilization ratio above which the `HighUtilization` flag fires.
const HIGH_UTILIZATION_THRESHOLD: f64 = 0.80;

/// Account age in days below which the `NewAgent` flag fires.
const NEW_AGENT_THRESHOLD_DAYS: i64 = 7;

/// Risk rating threshold: scores at or above this are `Low`.
const RISK_LOW_THRESHOLD: f64 = 0.75;

/// Risk rating threshold: scores at or above this are `Medium`.
const RISK_MEDIUM_THRESHOLD: f64 = 0.50;

/// Risk rating threshold: scores at or above this are `High`.
const RISK_HIGH_THRESHOLD: f64 = 0.30;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect risk flags from credit, trust, credit line, and payment data.
///
/// Examines all available data sources and returns a list of active risk flags
/// ordered by severity.
pub fn detect_risk_flags(
    credit_score: f64,
    trust_context: &TrustContext,
    credit_lines: &[CreditLineSummary],
    payment_history: &PaymentHistory,
) -> Vec<RiskFlag> {
    let now = Utc::now();
    let mut flags = Vec::new();

    // 1. High utilization on any credit line
    for line in credit_lines {
        if line.utilization_ratio > HIGH_UTILIZATION_THRESHOLD && line.status == "active" {
            flags.push(RiskFlag {
                flag_type: RiskFlagType::HighUtilization,
                severity: "warning".to_string(),
                description: format!(
                    "Credit line utilization at {:.0}% (limit: {} micro-USD)",
                    line.utilization_ratio * 100.0,
                    line.limit_micro_usd
                ),
                detected_at: now,
            });
            break; // One flag per type is enough
        }
    }

    // 2. Recent default
    if payment_history.has_recent_default {
        flags.push(RiskFlag {
            flag_type: RiskFlagType::RecentDefault,
            severity: "critical".to_string(),
            description: format!(
                "Payment default detected in the last 30 days ({} total defaults)",
                payment_history.defaults
            ),
            detected_at: now,
        });
    }

    // 3. Trust degrading
    if trust_context.trajectory == TrustTrajectory::Degrading {
        flags.push(RiskFlag {
            flag_type: RiskFlagType::TrustDegrading,
            severity: "warning".to_string(),
            description: format!(
                "Trust score is degrading (current: {:.2}, tier: {})",
                trust_context.score, trust_context.tier
            ),
            detected_at: now,
        });
    }

    // 4. New agent (account age < 7 days)
    if let Some(oldest) = payment_history.oldest_transaction_at {
        let age = now.signed_duration_since(oldest);
        if age < Duration::days(NEW_AGENT_THRESHOLD_DAYS) {
            flags.push(RiskFlag {
                flag_type: RiskFlagType::NewAgent,
                severity: "info".to_string(),
                description: format!(
                    "Agent account is less than {NEW_AGENT_THRESHOLD_DAYS} days old"
                ),
                detected_at: now,
            });
        }
    } else if payment_history.total_transactions == 0 {
        // No transactions at all — definitely new
        flags.push(RiskFlag {
            flag_type: RiskFlagType::NewAgent,
            severity: "info".to_string(),
            description: "Agent has no transaction history".to_string(),
            detected_at: now,
        });
    }

    // 5. Rapid spending
    if payment_history.rapid_spending {
        flags.push(RiskFlag {
            flag_type: RiskFlagType::RapidSpending,
            severity: "warning".to_string(),
            description: "Spending velocity exceeds normal thresholds".to_string(),
            detected_at: now,
        });
    }

    // 6. Economic hibernate
    if payment_history.economic_hibernate {
        flags.push(RiskFlag {
            flag_type: RiskFlagType::EconomicHibernate,
            severity: "critical".to_string(),
            description: "Agent is in Hibernate economic mode — payments blocked".to_string(),
            detected_at: now,
        });
    }

    // Suppress credit_score to avoid unused variable warning
    let _ = credit_score;

    flags
}

/// Assess the overall risk rating from scores and flags.
///
/// The composite score is the weighted average of credit and trust scores
/// (60% credit, 40% trust). Critical flags can override the score-based rating.
pub fn assess_risk_rating(credit_score: f64, trust_score: f64, flags: &[RiskFlag]) -> RiskRating {
    // Weighted composite: 60% credit, 40% trust
    let composite = 0.6 * credit_score.clamp(0.0, 1.0) + 0.4 * trust_score.clamp(0.0, 1.0);

    // Count critical flags
    let critical_count = flags.iter().filter(|f| f.severity == "critical").count();

    // Critical flags can downgrade the rating
    if critical_count >= 2 || composite < RISK_HIGH_THRESHOLD {
        return RiskRating::Critical;
    }

    if critical_count >= 1 || composite < RISK_MEDIUM_THRESHOLD {
        return RiskRating::High;
    }

    if composite < RISK_LOW_THRESHOLD {
        return RiskRating::Medium;
    }

    // Only Low if no warning/critical flags
    let has_warning_or_critical = flags
        .iter()
        .any(|f| f.severity == "warning" || f.severity == "critical");

    if has_warning_or_critical {
        RiskRating::Medium
    } else {
        RiskRating::Low
    }
}

/// Generate a full credit report for an agent.
///
/// Aggregates credit score, trust data, payment history, and credit lines
/// into a comprehensive `AgentCreditReport` with detected risk flags and
/// an overall risk rating.
pub fn generate_credit_report(
    agent_id: &str,
    did: Option<String>,
    credit_score: f64,
    credit_tier: CreditTier,
    trust_context: &TrustContext,
    payment_history: &PaymentHistory,
    credit_lines: Vec<CreditLineSummary>,
) -> AgentCreditReport {
    // Detect risk flags
    let flags = detect_risk_flags(credit_score, trust_context, &credit_lines, payment_history);

    // Assess risk rating
    let risk_rating = assess_risk_rating(credit_score, trust_context.score, &flags);

    // Build payment summary
    let payment_summary = PaymentSummary {
        total_transactions: payment_history.total_transactions,
        total_volume_micro_usd: payment_history.total_volume_micro_usd,
        on_time_rate: payment_history.on_time_rate,
        average_settlement_time_ms: payment_history.average_settlement_time_ms,
        defaults: payment_history.defaults,
        oldest_transaction_at: payment_history.oldest_transaction_at,
    };

    AgentCreditReport {
        agent_id: agent_id.to_string(),
        did,
        credit_score,
        credit_tier,
        trust_score: trust_context.score,
        trust_tier: trust_context.tier.clone(),
        risk_rating,
        payment_summary,
        credit_lines,
        flags,
        report_generated_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Risk rating assessment tests
    // -----------------------------------------------------------------------

    #[test]
    fn risk_rating_low_with_high_scores_no_flags() {
        let rating = assess_risk_rating(0.9, 0.85, &[]);
        assert_eq!(rating, RiskRating::Low);
    }

    #[test]
    fn risk_rating_medium_with_moderate_scores() {
        let rating = assess_risk_rating(0.6, 0.6, &[]);
        // composite = 0.6*0.6 + 0.4*0.6 = 0.60
        assert_eq!(rating, RiskRating::Medium);
    }

    #[test]
    fn risk_rating_medium_with_high_scores_but_warning_flag() {
        let flags = vec![RiskFlag {
            flag_type: RiskFlagType::HighUtilization,
            severity: "warning".to_string(),
            description: "test".to_string(),
            detected_at: Utc::now(),
        }];
        let rating = assess_risk_rating(0.9, 0.9, &flags);
        assert_eq!(rating, RiskRating::Medium);
    }

    #[test]
    fn risk_rating_high_with_one_critical_flag() {
        let flags = vec![RiskFlag {
            flag_type: RiskFlagType::RecentDefault,
            severity: "critical".to_string(),
            description: "test".to_string(),
            detected_at: Utc::now(),
        }];
        let rating = assess_risk_rating(0.8, 0.8, &flags);
        assert_eq!(rating, RiskRating::High);
    }

    #[test]
    fn risk_rating_critical_with_two_critical_flags() {
        let flags = vec![
            RiskFlag {
                flag_type: RiskFlagType::RecentDefault,
                severity: "critical".to_string(),
                description: "default".to_string(),
                detected_at: Utc::now(),
            },
            RiskFlag {
                flag_type: RiskFlagType::EconomicHibernate,
                severity: "critical".to_string(),
                description: "hibernate".to_string(),
                detected_at: Utc::now(),
            },
        ];
        let rating = assess_risk_rating(0.8, 0.8, &flags);
        assert_eq!(rating, RiskRating::Critical);
    }

    #[test]
    fn risk_rating_critical_with_very_low_score() {
        let rating = assess_risk_rating(0.1, 0.2, &[]);
        // composite = 0.6*0.1 + 0.4*0.2 = 0.14 < 0.3
        assert_eq!(rating, RiskRating::Critical);
    }

    #[test]
    fn risk_rating_high_with_score_between_03_and_05() {
        let rating = assess_risk_rating(0.5, 0.3, &[]);
        // composite = 0.6*0.5 + 0.4*0.3 = 0.42
        assert_eq!(rating, RiskRating::High);
    }

    #[test]
    fn risk_rating_at_exact_boundary_075() {
        let rating = assess_risk_rating(0.75, 0.75, &[]);
        // composite = 0.75
        assert_eq!(rating, RiskRating::Low);
    }

    #[test]
    fn risk_rating_info_flags_do_not_downgrade() {
        let flags = vec![RiskFlag {
            flag_type: RiskFlagType::NewAgent,
            severity: "info".to_string(),
            description: "new agent".to_string(),
            detected_at: Utc::now(),
        }];
        let rating = assess_risk_rating(0.9, 0.9, &flags);
        assert_eq!(rating, RiskRating::Low);
    }

    // -----------------------------------------------------------------------
    // Risk flag detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn flag_high_utilization_detected() {
        let credit_lines = vec![CreditLineSummary {
            limit_micro_usd: 100_000,
            drawn_micro_usd: 85_000,
            utilization_ratio: 0.85,
            status: "active".to_string(),
        }];
        let flags = detect_risk_flags(
            0.7,
            &TrustContext::default(),
            &credit_lines,
            &PaymentHistory::default(),
        );
        assert!(
            flags
                .iter()
                .any(|f| f.flag_type == RiskFlagType::HighUtilization),
            "Expected HighUtilization flag"
        );
        let flag = flags
            .iter()
            .find(|f| f.flag_type == RiskFlagType::HighUtilization)
            .unwrap();
        assert_eq!(flag.severity, "warning");
    }

    #[test]
    fn flag_high_utilization_not_triggered_at_80_percent() {
        let credit_lines = vec![CreditLineSummary {
            limit_micro_usd: 100_000,
            drawn_micro_usd: 80_000,
            utilization_ratio: 0.80,
            status: "active".to_string(),
        }];
        let flags = detect_risk_flags(
            0.7,
            &TrustContext::default(),
            &credit_lines,
            &PaymentHistory::default(),
        );
        assert!(
            !flags
                .iter()
                .any(|f| f.flag_type == RiskFlagType::HighUtilization),
            "Should NOT trigger at exactly 80%"
        );
    }

    #[test]
    fn flag_high_utilization_ignored_for_frozen_line() {
        let credit_lines = vec![CreditLineSummary {
            limit_micro_usd: 100_000,
            drawn_micro_usd: 95_000,
            utilization_ratio: 0.95,
            status: "frozen".to_string(),
        }];
        let flags = detect_risk_flags(
            0.7,
            &TrustContext::default(),
            &credit_lines,
            &PaymentHistory::default(),
        );
        assert!(
            !flags
                .iter()
                .any(|f| f.flag_type == RiskFlagType::HighUtilization),
            "Should not flag frozen credit lines"
        );
    }

    #[test]
    fn flag_recent_default_detected() {
        let history = PaymentHistory {
            has_recent_default: true,
            defaults: 3,
            ..PaymentHistory::default()
        };
        let flags = detect_risk_flags(0.5, &TrustContext::default(), &[], &history);
        assert!(
            flags
                .iter()
                .any(|f| f.flag_type == RiskFlagType::RecentDefault),
            "Expected RecentDefault flag"
        );
        let flag = flags
            .iter()
            .find(|f| f.flag_type == RiskFlagType::RecentDefault)
            .unwrap();
        assert_eq!(flag.severity, "critical");
    }

    #[test]
    fn flag_trust_degrading_detected() {
        let trust = TrustContext {
            score: 0.4,
            tier: "provisional".to_string(),
            trajectory: TrustTrajectory::Degrading,
        };
        let flags = detect_risk_flags(0.5, &trust, &[], &PaymentHistory::default());
        assert!(
            flags
                .iter()
                .any(|f| f.flag_type == RiskFlagType::TrustDegrading),
            "Expected TrustDegrading flag"
        );
        let flag = flags
            .iter()
            .find(|f| f.flag_type == RiskFlagType::TrustDegrading)
            .unwrap();
        assert_eq!(flag.severity, "warning");
    }

    #[test]
    fn flag_new_agent_detected_for_young_account() {
        let history = PaymentHistory {
            total_transactions: 5,
            oldest_transaction_at: Some(Utc::now() - Duration::days(3)),
            ..PaymentHistory::default()
        };
        let flags = detect_risk_flags(0.5, &TrustContext::default(), &[], &history);
        assert!(
            flags.iter().any(|f| f.flag_type == RiskFlagType::NewAgent),
            "Expected NewAgent flag"
        );
        let flag = flags
            .iter()
            .find(|f| f.flag_type == RiskFlagType::NewAgent)
            .unwrap();
        assert_eq!(flag.severity, "info");
    }

    #[test]
    fn flag_new_agent_detected_for_no_history() {
        let flags = detect_risk_flags(
            0.5,
            &TrustContext::default(),
            &[],
            &PaymentHistory::default(),
        );
        assert!(
            flags.iter().any(|f| f.flag_type == RiskFlagType::NewAgent),
            "Expected NewAgent flag for empty history"
        );
    }

    #[test]
    fn flag_new_agent_not_triggered_for_old_account() {
        let history = PaymentHistory {
            total_transactions: 100,
            oldest_transaction_at: Some(Utc::now() - Duration::days(90)),
            ..PaymentHistory::default()
        };
        let flags = detect_risk_flags(0.8, &TrustContext::default(), &[], &history);
        assert!(
            !flags.iter().any(|f| f.flag_type == RiskFlagType::NewAgent),
            "Should NOT flag 90-day-old account as new"
        );
    }

    #[test]
    fn flag_rapid_spending_detected() {
        let history = PaymentHistory {
            rapid_spending: true,
            total_transactions: 50,
            oldest_transaction_at: Some(Utc::now() - Duration::days(30)),
            ..PaymentHistory::default()
        };
        let flags = detect_risk_flags(0.5, &TrustContext::default(), &[], &history);
        assert!(
            flags
                .iter()
                .any(|f| f.flag_type == RiskFlagType::RapidSpending),
            "Expected RapidSpending flag"
        );
        let flag = flags
            .iter()
            .find(|f| f.flag_type == RiskFlagType::RapidSpending)
            .unwrap();
        assert_eq!(flag.severity, "warning");
    }

    #[test]
    fn flag_economic_hibernate_detected() {
        let history = PaymentHistory {
            economic_hibernate: true,
            total_transactions: 10,
            oldest_transaction_at: Some(Utc::now() - Duration::days(30)),
            ..PaymentHistory::default()
        };
        let flags = detect_risk_flags(0.5, &TrustContext::default(), &[], &history);
        assert!(
            flags
                .iter()
                .any(|f| f.flag_type == RiskFlagType::EconomicHibernate),
            "Expected EconomicHibernate flag"
        );
        let flag = flags
            .iter()
            .find(|f| f.flag_type == RiskFlagType::EconomicHibernate)
            .unwrap();
        assert_eq!(flag.severity, "critical");
    }

    #[test]
    fn no_flags_for_healthy_agent() {
        let trust = TrustContext {
            score: 0.9,
            tier: "certified".to_string(),
            trajectory: TrustTrajectory::Stable,
        };
        let history = PaymentHistory {
            total_transactions: 200,
            total_volume_micro_usd: 5_000_000,
            on_time_rate: 0.99,
            average_settlement_time_ms: 500,
            defaults: 0,
            oldest_transaction_at: Some(Utc::now() - Duration::days(180)),
            has_recent_default: false,
            rapid_spending: false,
            economic_hibernate: false,
        };
        let credit_lines = vec![CreditLineSummary {
            limit_micro_usd: 10_000_000,
            drawn_micro_usd: 2_000_000,
            utilization_ratio: 0.20,
            status: "active".to_string(),
        }];
        let flags = detect_risk_flags(0.9, &trust, &credit_lines, &history);
        assert!(
            flags.is_empty(),
            "Expected no flags for healthy agent, got: {flags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Report generation tests
    // -----------------------------------------------------------------------

    #[test]
    fn generate_report_for_new_agent() {
        let trust = TrustContext::default();
        let history = PaymentHistory::default();
        let report = generate_credit_report(
            "agent-new",
            None,
            0.0,
            CreditTier::None,
            &trust,
            &history,
            vec![],
        );
        assert_eq!(report.agent_id, "agent-new");
        assert_eq!(report.credit_tier, CreditTier::None);
        assert_eq!(report.credit_score, 0.0);
        assert_eq!(report.trust_score, 0.0);
        assert_eq!(report.trust_tier, "unverified");
        assert_eq!(report.risk_rating, RiskRating::Critical);
        assert!(
            report
                .flags
                .iter()
                .any(|f| f.flag_type == RiskFlagType::NewAgent)
        );
    }

    #[test]
    fn generate_report_for_premium_agent() {
        let trust = TrustContext {
            score: 0.95,
            tier: "certified".to_string(),
            trajectory: TrustTrajectory::Stable,
        };
        let history = PaymentHistory {
            total_transactions: 500,
            total_volume_micro_usd: 50_000_000,
            on_time_rate: 0.99,
            average_settlement_time_ms: 450,
            defaults: 0,
            oldest_transaction_at: Some(Utc::now() - Duration::days(365)),
            has_recent_default: false,
            rapid_spending: false,
            economic_hibernate: false,
        };
        let credit_lines = vec![CreditLineSummary {
            limit_micro_usd: 10_000_000,
            drawn_micro_usd: 1_000_000,
            utilization_ratio: 0.10,
            status: "active".to_string(),
        }];
        let report = generate_credit_report(
            "agent-premium",
            Some("did:key:z6MkpTHR8VNs5zPG7IL56D".to_string()),
            0.95,
            CreditTier::Premium,
            &trust,
            &history,
            credit_lines,
        );
        assert_eq!(report.agent_id, "agent-premium");
        assert_eq!(report.credit_tier, CreditTier::Premium);
        assert_eq!(report.risk_rating, RiskRating::Low);
        assert!(report.flags.is_empty());
        assert_eq!(report.payment_summary.total_transactions, 500);
        assert_eq!(report.payment_summary.on_time_rate, 0.99);
        assert!(report.did.is_some());
    }

    #[test]
    fn generate_report_with_multiple_flags() {
        let trust = TrustContext {
            score: 0.3,
            tier: "provisional".to_string(),
            trajectory: TrustTrajectory::Degrading,
        };
        let history = PaymentHistory {
            total_transactions: 10,
            total_volume_micro_usd: 50_000,
            on_time_rate: 0.6,
            average_settlement_time_ms: 2000,
            defaults: 2,
            oldest_transaction_at: Some(Utc::now() - Duration::days(5)),
            has_recent_default: true,
            rapid_spending: true,
            economic_hibernate: false,
        };
        let credit_lines = vec![CreditLineSummary {
            limit_micro_usd: 1_000,
            drawn_micro_usd: 900,
            utilization_ratio: 0.90,
            status: "active".to_string(),
        }];
        let report = generate_credit_report(
            "agent-risky",
            None,
            0.35,
            CreditTier::Micro,
            &trust,
            &history,
            credit_lines,
        );
        assert_eq!(report.agent_id, "agent-risky");
        assert_eq!(report.credit_tier, CreditTier::Micro);
        // Should have multiple flags: HighUtilization, RecentDefault, TrustDegrading, NewAgent, RapidSpending
        assert!(
            report.flags.len() >= 4,
            "Expected at least 4 flags, got {}",
            report.flags.len()
        );
        // With critical flags (RecentDefault) + low composite, risk should be High or Critical
        assert!(
            report.risk_rating == RiskRating::High || report.risk_rating == RiskRating::Critical,
            "Expected High or Critical risk, got {:?}",
            report.risk_rating
        );
    }

    #[test]
    fn report_payment_summary_matches_history() {
        let history = PaymentHistory {
            total_transactions: 42,
            total_volume_micro_usd: 1_234_567,
            on_time_rate: 0.95,
            average_settlement_time_ms: 750,
            defaults: 1,
            oldest_transaction_at: Some(Utc::now() - Duration::days(60)),
            has_recent_default: false,
            rapid_spending: false,
            economic_hibernate: false,
        };
        let report = generate_credit_report(
            "agent-test",
            None,
            0.7,
            CreditTier::Standard,
            &TrustContext::default(),
            &history,
            vec![],
        );
        assert_eq!(report.payment_summary.total_transactions, 42);
        assert_eq!(report.payment_summary.total_volume_micro_usd, 1_234_567);
        assert_eq!(report.payment_summary.on_time_rate, 0.95);
        assert_eq!(report.payment_summary.average_settlement_time_ms, 750);
        assert_eq!(report.payment_summary.defaults, 1);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn risk_rating_serde_roundtrip() {
        for rating in [
            RiskRating::Low,
            RiskRating::Medium,
            RiskRating::High,
            RiskRating::Critical,
        ] {
            let json = serde_json::to_string(&rating).unwrap();
            let back: RiskRating = serde_json::from_str(&json).unwrap();
            assert_eq!(back, rating);
        }
    }

    #[test]
    fn risk_flag_type_serde_roundtrip() {
        for flag_type in [
            RiskFlagType::HighUtilization,
            RiskFlagType::RecentDefault,
            RiskFlagType::TrustDegrading,
            RiskFlagType::NewAgent,
            RiskFlagType::RapidSpending,
            RiskFlagType::EconomicHibernate,
        ] {
            let json = serde_json::to_string(&flag_type).unwrap();
            let back: RiskFlagType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, flag_type);
        }
    }

    #[test]
    fn credit_report_serde_roundtrip() {
        let report = generate_credit_report(
            "agent-serde",
            Some("did:key:z6MkpTHR8VNs".to_string()),
            0.7,
            CreditTier::Standard,
            &TrustContext {
                score: 0.8,
                tier: "trusted".to_string(),
                trajectory: TrustTrajectory::Stable,
            },
            &PaymentHistory {
                total_transactions: 50,
                total_volume_micro_usd: 500_000,
                on_time_rate: 0.96,
                average_settlement_time_ms: 600,
                defaults: 0,
                oldest_transaction_at: Some(Utc::now() - Duration::days(60)),
                has_recent_default: false,
                rapid_spending: false,
                economic_hibernate: false,
            },
            vec![CreditLineSummary {
                limit_micro_usd: 100_000,
                drawn_micro_usd: 30_000,
                utilization_ratio: 0.30,
                status: "active".to_string(),
            }],
        );
        let json = serde_json::to_string(&report).unwrap();
        let back: AgentCreditReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_id, "agent-serde");
        assert_eq!(back.credit_tier, CreditTier::Standard);
        assert_eq!(back.risk_rating, report.risk_rating);
        assert!((back.credit_score - 0.7).abs() < 1e-10);
        assert_eq!(back.trust_tier, "trusted");
    }

    #[test]
    fn risk_rating_display() {
        assert_eq!(RiskRating::Low.to_string(), "low");
        assert_eq!(RiskRating::Medium.to_string(), "medium");
        assert_eq!(RiskRating::High.to_string(), "high");
        assert_eq!(RiskRating::Critical.to_string(), "critical");
    }

    #[test]
    fn risk_flag_type_display() {
        assert_eq!(
            RiskFlagType::HighUtilization.to_string(),
            "high_utilization"
        );
        assert_eq!(RiskFlagType::RecentDefault.to_string(), "recent_default");
        assert_eq!(RiskFlagType::TrustDegrading.to_string(), "trust_degrading");
        assert_eq!(RiskFlagType::NewAgent.to_string(), "new_agent");
        assert_eq!(RiskFlagType::RapidSpending.to_string(), "rapid_spending");
        assert_eq!(
            RiskFlagType::EconomicHibernate.to_string(),
            "economic_hibernate"
        );
    }
}

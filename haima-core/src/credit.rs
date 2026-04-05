//! Agent behavioral credit scoring model.
//!
//! Builds on top of trust scores (from Autonomic) to determine spending limits
//! and overdraft eligibility for agents. Credit scores are derived from a weighted
//! composite of behavioral factors including trust, payment history, transaction
//! volume, account age, and economic stability.
//!
//! # Credit Tiers
//!
//! | Tier     | Score Range  | Spending Limit        |
//! |----------|-------------|-----------------------|
//! | None     | < 0.3       | 0 (prepay only)       |
//! | Micro    | 0.3 - 0.5   | 1,000 micro-USD       |
//! | Standard | 0.5 - 0.75  | 100,000 micro-USD     |
//! | Premium  | >= 0.75     | 10,000,000 micro-USD  |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Credit tier determines spending limits and overdraft eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditTier {
    /// No credit -- prepay only.
    None,
    /// Up to 1,000 micro-USD (~$0.001).
    Micro,
    /// Up to 100,000 micro-USD (~$0.10).
    Standard,
    /// Up to 10,000,000 micro-USD (~$10).
    Premium,
}

impl CreditTier {
    /// Spending limit in micro-USD for this tier.
    pub fn spending_limit(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Micro => 1_000,
            Self::Standard => 100_000,
            Self::Premium => 10_000_000,
        }
    }
}

impl std::fmt::Display for CreditTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Micro => write!(f, "micro"),
            Self::Standard => write!(f, "standard"),
            Self::Premium => write!(f, "premium"),
        }
    }
}

/// An agent's credit score with tier, spending limit, and contributing factors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditScore {
    /// The agent this score belongs to.
    pub agent_id: String,
    /// The computed credit tier.
    pub tier: CreditTier,
    /// Composite credit score (0.0 - 1.0).
    pub score: f64,
    /// Maximum spending limit in micro-USD for this tier.
    pub spending_limit_micro_usd: u64,
    /// Current balance in micro-USD (negative = debt).
    pub current_balance_micro_usd: i64,
    /// The factors that contributed to this score.
    pub factors: CreditFactors,
    /// When this score was computed.
    pub assessed_at: DateTime<Utc>,
}

/// The behavioral factors used to compute a credit score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditFactors {
    /// Trust score from Autonomic (0.0 - 1.0).
    pub trust_score: f64,
    /// On-time payment ratio (0.0 - 1.0).
    pub payment_history: f64,
    /// Lifetime transaction volume in micro-USD.
    pub transaction_volume: u64,
    /// How long the agent has been active, in days.
    pub account_age_days: u32,
    /// How stable the economic mode has been (0.0 - 1.0).
    pub economic_stability: f64,
}

impl Default for CreditFactors {
    fn default() -> Self {
        Self {
            trust_score: 0.0,
            payment_history: 0.0,
            transaction_volume: 0,
            account_age_days: 0,
            economic_stability: 0.0,
        }
    }
}

/// The result of a credit check for a proposed spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditCheckResult {
    /// Whether the spend is approved.
    pub approved: bool,
    /// The agent's credit tier.
    pub tier: CreditTier,
    /// Remaining spending limit after this transaction (if approved).
    pub remaining_limit: u64,
    /// Reason for rejection (if not approved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Scoring weights
// ---------------------------------------------------------------------------

/// Weight for trust score in the composite (30%).
const WEIGHT_TRUST: f64 = 0.30;
/// Weight for payment history in the composite (30%).
const WEIGHT_PAYMENT_HISTORY: f64 = 0.30;
/// Weight for transaction volume in the composite (15%).
const WEIGHT_TRANSACTION_VOLUME: f64 = 0.15;
/// Weight for account age in the composite (10%).
const WEIGHT_ACCOUNT_AGE: f64 = 0.10;
/// Weight for economic stability in the composite (15%).
const WEIGHT_ECONOMIC_STABILITY: f64 = 0.15;

// ---------------------------------------------------------------------------
// Tier thresholds
// ---------------------------------------------------------------------------

/// Minimum score for Micro tier.
const TIER_MICRO_THRESHOLD: f64 = 0.3;
/// Minimum score for Standard tier.
const TIER_STANDARD_THRESHOLD: f64 = 0.5;
/// Minimum score for Premium tier.
const TIER_PREMIUM_THRESHOLD: f64 = 0.75;

// ---------------------------------------------------------------------------
// Normalization constants
// ---------------------------------------------------------------------------

/// Volume at which the log-scaled factor saturates to 1.0 (10 USDC lifetime).
const VOLUME_SATURATION: f64 = 10_000_000.0;
/// Account age at which the factor saturates to 1.0 (90 days).
const AGE_SATURATION_DAYS: f64 = 90.0;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute a credit score from behavioral factors.
///
/// The composite score is a weighted average:
/// - `trust_score`: 30% (from Autonomic)
/// - `payment_history`: 30% (on-time settlement ratio)
/// - `transaction_volume`: 15% (log-scaled activity)
/// - `account_age`: 10% (time-based trust, linear up to 90 days)
/// - `economic_stability`: 15% (mode stability from Autonomic)
pub fn compute_credit_score(agent_id: &str, factors: &CreditFactors) -> CreditScore {
    // Normalize transaction volume using log scale.
    // ln(1 + volume) / ln(1 + saturation) clamped to [0, 1].
    let volume_factor = if factors.transaction_volume == 0 {
        0.0
    } else {
        let raw = (1.0 + factors.transaction_volume as f64).ln() / (1.0 + VOLUME_SATURATION).ln();
        raw.min(1.0)
    };

    // Normalize account age linearly up to saturation.
    let age_factor = (factors.account_age_days as f64 / AGE_SATURATION_DAYS).min(1.0);

    // Weighted composite.
    let score = WEIGHT_TRUST * factors.trust_score.clamp(0.0, 1.0)
        + WEIGHT_PAYMENT_HISTORY * factors.payment_history.clamp(0.0, 1.0)
        + WEIGHT_TRANSACTION_VOLUME * volume_factor
        + WEIGHT_ACCOUNT_AGE * age_factor
        + WEIGHT_ECONOMIC_STABILITY * factors.economic_stability.clamp(0.0, 1.0);

    // Clamp final score to [0, 1].
    let score = score.clamp(0.0, 1.0);

    let tier = score_to_tier(score);

    CreditScore {
        agent_id: agent_id.to_string(),
        tier,
        score,
        spending_limit_micro_usd: tier.spending_limit(),
        current_balance_micro_usd: 0, // Set by caller from financial state
        factors: factors.clone(),
        assessed_at: Utc::now(),
    }
}

/// Derive the credit tier from a composite score.
fn score_to_tier(score: f64) -> CreditTier {
    if score >= TIER_PREMIUM_THRESHOLD {
        CreditTier::Premium
    } else if score >= TIER_STANDARD_THRESHOLD {
        CreditTier::Standard
    } else if score >= TIER_MICRO_THRESHOLD {
        CreditTier::Micro
    } else {
        CreditTier::None
    }
}

/// Check whether an agent can spend a given amount against their credit.
///
/// Returns an approval/rejection result based on the agent's credit tier
/// and current balance.
pub fn check_credit(credit: &CreditScore, amount_micro_usd: u64) -> CreditCheckResult {
    let limit = credit.spending_limit_micro_usd;

    // Calculate effective available credit.
    // If the agent has debt (negative balance), that reduces available credit.
    let used = if credit.current_balance_micro_usd < 0 {
        credit.current_balance_micro_usd.unsigned_abs()
    } else {
        0
    };

    if used >= limit {
        return CreditCheckResult {
            approved: false,
            tier: credit.tier,
            remaining_limit: 0,
            reason: Some("insufficient_credit".into()),
        };
    }

    let available = limit - used;

    if amount_micro_usd > available {
        return CreditCheckResult {
            approved: false,
            tier: credit.tier,
            remaining_limit: available,
            reason: Some("insufficient_credit".into()),
        };
    }

    CreditCheckResult {
        approved: true,
        tier: credit.tier,
        remaining_limit: available - amount_micro_usd,
        reason: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Tier tests --

    #[test]
    fn tier_spending_limits() {
        assert_eq!(CreditTier::None.spending_limit(), 0);
        assert_eq!(CreditTier::Micro.spending_limit(), 1_000);
        assert_eq!(CreditTier::Standard.spending_limit(), 100_000);
        assert_eq!(CreditTier::Premium.spending_limit(), 10_000_000);
    }

    #[test]
    fn tier_display() {
        assert_eq!(CreditTier::None.to_string(), "none");
        assert_eq!(CreditTier::Micro.to_string(), "micro");
        assert_eq!(CreditTier::Standard.to_string(), "standard");
        assert_eq!(CreditTier::Premium.to_string(), "premium");
    }

    #[test]
    fn tier_serde_roundtrip() {
        let tier = CreditTier::Standard;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"standard\"");
        let back: CreditTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tier);
    }

    // -- Score computation tests --

    #[test]
    fn new_agent_with_no_history_gets_none_tier() {
        let factors = CreditFactors::default();
        let score = compute_credit_score("agent-new", &factors);
        assert_eq!(score.tier, CreditTier::None);
        assert_eq!(score.score, 0.0);
        assert_eq!(score.spending_limit_micro_usd, 0);
    }

    #[test]
    fn agent_with_perfect_history_gets_premium() {
        let factors = CreditFactors {
            trust_score: 1.0,
            payment_history: 1.0,
            transaction_volume: 10_000_000, // saturated
            account_age_days: 90,           // saturated
            economic_stability: 1.0,
        };
        let score = compute_credit_score("agent-perfect", &factors);
        assert_eq!(score.tier, CreditTier::Premium);
        assert!(score.score >= 0.95, "expected >= 0.95, got {}", score.score);
        assert_eq!(score.spending_limit_micro_usd, 10_000_000);
    }

    #[test]
    fn agent_with_moderate_history_gets_standard() {
        let factors = CreditFactors {
            trust_score: 0.7,
            payment_history: 0.8,
            transaction_volume: 500_000,
            account_age_days: 30,
            economic_stability: 0.6,
        };
        let score = compute_credit_score("agent-moderate", &factors);
        assert_eq!(score.tier, CreditTier::Standard);
        assert!(score.score >= 0.5 && score.score < 0.75);
    }

    #[test]
    fn agent_with_low_history_gets_micro() {
        let factors = CreditFactors {
            trust_score: 0.4,
            payment_history: 0.5,
            transaction_volume: 10_000,
            account_age_days: 7,
            economic_stability: 0.3,
        };
        let score = compute_credit_score("agent-low", &factors);
        assert_eq!(score.tier, CreditTier::Micro);
        assert!(score.score >= 0.3 && score.score < 0.5);
    }

    #[test]
    fn score_clamps_inputs_above_one() {
        let factors = CreditFactors {
            trust_score: 1.5,     // out of range
            payment_history: 2.0, // out of range
            transaction_volume: u64::MAX,
            account_age_days: 365,
            economic_stability: 1.5, // out of range
        };
        let score = compute_credit_score("agent-clamped", &factors);
        // All factors clamped to 1.0 -> score should be 1.0
        assert!((score.score - 1.0).abs() < 1e-10);
        assert_eq!(score.tier, CreditTier::Premium);
    }

    #[test]
    fn score_weights_sum_to_one() {
        let total = WEIGHT_TRUST
            + WEIGHT_PAYMENT_HISTORY
            + WEIGHT_TRANSACTION_VOLUME
            + WEIGHT_ACCOUNT_AGE
            + WEIGHT_ECONOMIC_STABILITY;
        assert!((total - 1.0).abs() < 1e-10, "weights sum to {total}");
    }

    #[test]
    fn volume_factor_is_zero_for_no_volume() {
        let factors = CreditFactors {
            trust_score: 1.0,
            payment_history: 1.0,
            transaction_volume: 0,
            account_age_days: 90,
            economic_stability: 1.0,
        };
        let score = compute_credit_score("agent-no-vol", &factors);
        // With zero volume, the volume component is 0.
        // Expected: 0.30 + 0.30 + 0.0 + 0.10 + 0.15 = 0.85
        assert!(
            (score.score - 0.85).abs() < 1e-10,
            "score = {}",
            score.score
        );
        assert_eq!(score.tier, CreditTier::Premium);
    }

    #[test]
    fn credit_score_serde_roundtrip() {
        let factors = CreditFactors {
            trust_score: 0.8,
            payment_history: 0.9,
            transaction_volume: 100_000,
            account_age_days: 30,
            economic_stability: 0.7,
        };
        let score = compute_credit_score("agent-serde", &factors);
        let json = serde_json::to_string(&score).unwrap();
        let back: CreditScore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_id, "agent-serde");
        assert_eq!(back.tier, score.tier);
        assert!((back.score - score.score).abs() < 1e-10);
    }

    // -- Credit check tests --

    #[test]
    fn check_credit_approved() {
        let score = CreditScore {
            agent_id: "agent-1".into(),
            tier: CreditTier::Standard,
            score: 0.6,
            spending_limit_micro_usd: 100_000,
            current_balance_micro_usd: 0,
            factors: CreditFactors::default(),
            assessed_at: Utc::now(),
        };
        let result = check_credit(&score, 5_000);
        assert!(result.approved);
        assert_eq!(result.remaining_limit, 95_000);
        assert!(result.reason.is_none());
    }

    #[test]
    fn check_credit_rejected_exceeds_limit() {
        let score = CreditScore {
            agent_id: "agent-2".into(),
            tier: CreditTier::Micro,
            score: 0.35,
            spending_limit_micro_usd: 1_000,
            current_balance_micro_usd: 0,
            factors: CreditFactors::default(),
            assessed_at: Utc::now(),
        };
        let result = check_credit(&score, 2_000);
        assert!(!result.approved);
        assert_eq!(result.remaining_limit, 1_000);
        assert_eq!(result.reason.as_deref(), Some("insufficient_credit"));
    }

    #[test]
    fn check_credit_with_debt_reduces_available() {
        let score = CreditScore {
            agent_id: "agent-3".into(),
            tier: CreditTier::Standard,
            score: 0.6,
            spending_limit_micro_usd: 100_000,
            current_balance_micro_usd: -30_000, // owes 30k
            factors: CreditFactors::default(),
            assessed_at: Utc::now(),
        };
        let result = check_credit(&score, 50_000);
        assert!(result.approved);
        // 100k limit - 30k debt = 70k available - 50k spend = 20k remaining
        assert_eq!(result.remaining_limit, 20_000);
    }

    #[test]
    fn check_credit_with_debt_exceeding_limit() {
        let score = CreditScore {
            agent_id: "agent-4".into(),
            tier: CreditTier::Micro,
            score: 0.35,
            spending_limit_micro_usd: 1_000,
            current_balance_micro_usd: -1_500, // owes more than limit
            factors: CreditFactors::default(),
            assessed_at: Utc::now(),
        };
        let result = check_credit(&score, 100);
        assert!(!result.approved);
        assert_eq!(result.remaining_limit, 0);
        assert_eq!(result.reason.as_deref(), Some("insufficient_credit"));
    }

    #[test]
    fn check_credit_none_tier_always_rejected() {
        let score = CreditScore {
            agent_id: "agent-5".into(),
            tier: CreditTier::None,
            score: 0.1,
            spending_limit_micro_usd: 0,
            current_balance_micro_usd: 0,
            factors: CreditFactors::default(),
            assessed_at: Utc::now(),
        };
        let result = check_credit(&score, 1);
        assert!(!result.approved);
    }

    #[test]
    fn check_credit_positive_balance_no_reduction() {
        let score = CreditScore {
            agent_id: "agent-6".into(),
            tier: CreditTier::Standard,
            score: 0.6,
            spending_limit_micro_usd: 100_000,
            current_balance_micro_usd: 50_000, // positive balance
            factors: CreditFactors::default(),
            assessed_at: Utc::now(),
        };
        let result = check_credit(&score, 90_000);
        assert!(result.approved);
        // Positive balance doesn't reduce limit
        assert_eq!(result.remaining_limit, 10_000);
    }

    #[test]
    fn check_credit_exact_limit_approved() {
        let score = CreditScore {
            agent_id: "agent-7".into(),
            tier: CreditTier::Micro,
            score: 0.35,
            spending_limit_micro_usd: 1_000,
            current_balance_micro_usd: 0,
            factors: CreditFactors::default(),
            assessed_at: Utc::now(),
        };
        let result = check_credit(&score, 1_000);
        assert!(result.approved);
        assert_eq!(result.remaining_limit, 0);
    }

    #[test]
    fn credit_check_result_serde_roundtrip() {
        let result = CreditCheckResult {
            approved: true,
            tier: CreditTier::Standard,
            remaining_limit: 95_000,
            reason: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CreditCheckResult = serde_json::from_str(&json).unwrap();
        assert!(back.approved);
        assert_eq!(back.tier, CreditTier::Standard);
        assert_eq!(back.remaining_limit, 95_000);
        assert!(back.reason.is_none());
    }

    #[test]
    fn credit_check_rejected_includes_reason_in_json() {
        let result = CreditCheckResult {
            approved: false,
            tier: CreditTier::Micro,
            remaining_limit: 0,
            reason: Some("insufficient_credit".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("insufficient_credit"));
        let back: CreditCheckResult = serde_json::from_str(&json).unwrap();
        assert!(!back.approved);
        assert_eq!(back.reason.as_deref(), Some("insufficient_credit"));
    }

    // -- Edge case: tier boundary values --

    #[test]
    fn tier_at_exact_boundary_micro() {
        let tier = score_to_tier(0.3);
        assert_eq!(tier, CreditTier::Micro);
    }

    #[test]
    fn tier_just_below_micro() {
        let tier = score_to_tier(0.299);
        assert_eq!(tier, CreditTier::None);
    }

    #[test]
    fn tier_at_exact_boundary_standard() {
        let tier = score_to_tier(0.5);
        assert_eq!(tier, CreditTier::Standard);
    }

    #[test]
    fn tier_at_exact_boundary_premium() {
        let tier = score_to_tier(0.75);
        assert_eq!(tier, CreditTier::Premium);
    }
}

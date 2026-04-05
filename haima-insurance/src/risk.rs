//! Risk assessment engine powered by Autonomic trust scores and Lago event history.
//!
//! Computes a risk score for agents seeking insurance coverage. The risk score
//! drives premium pricing and determines insurability.
//!
//! # Risk Components (weights)
//!
//! | Component              | Weight | Source                          |
//! |------------------------|--------|---------------------------------|
//! | Operational reliability| 25%    | Autonomic operational pillar    |
//! | Payment reliability    | 20%    | Haima credit/payment history    |
//! | Economic stability     | 20%    | Autonomic economic pillar       |
//! | Task completion rate   | 15%    | Autonomic cognitive pillar      |
//! | Account maturity       | 10%    | Account age (linear, 90d cap)   |
//! | Claims history         | 10%    | Prior claims on this network    |

use chrono::Utc;
use haima_core::bureau::RiskRating;
use haima_core::credit::{CreditScore, CreditTier};
use haima_core::insurance::{InsuranceTrustTier, RiskAssessment, RiskComponents};

// ---------------------------------------------------------------------------
// Weights
// ---------------------------------------------------------------------------

const W_OPERATIONAL: f64 = 0.25;
const W_PAYMENT: f64 = 0.20;
const W_ECONOMIC: f64 = 0.20;
const W_TASK_COMPLETION: f64 = 0.15;
const W_MATURITY: f64 = 0.10;
const W_CLAIMS: f64 = 0.10;

/// Account age at which the maturity factor saturates to 1.0 (90 days).
const AGE_SATURATION_DAYS: f64 = 90.0;

// ---------------------------------------------------------------------------
// Premium multiplier thresholds
// ---------------------------------------------------------------------------

/// Low risk agents get a discount.
const LOW_RISK_MULTIPLIER: f64 = 0.8;
/// Medium risk agents pay base rate.
const MEDIUM_RISK_MULTIPLIER: f64 = 1.0;
/// High risk agents pay a surcharge.
const HIGH_RISK_MULTIPLIER: f64 = 1.5;
/// Critical risk agents pay the maximum surcharge.
const CRITICAL_RISK_MULTIPLIER: f64 = 2.5;

/// Minimum composite score to be insurable at all.
const MIN_INSURABLE_SCORE: f64 = 0.20;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Assess an agent's insurance risk from their behavioral data.
///
/// Takes the agent's credit score (which embeds trust and payment factors)
/// plus optional additional signals to compute a comprehensive risk assessment.
#[allow(clippy::too_many_arguments)]
pub fn assess_risk(
    agent_id: &str,
    credit_score: &CreditScore,
    trust_score: f64,
    operational_reliability: f64,
    task_completion_rate: f64,
    account_age_days: u32,
    prior_claims: u32,
    prior_claims_paid_micro_usd: i64,
    total_coverage_micro_usd: i64,
) -> RiskAssessment {
    let components = compute_components(
        operational_reliability,
        credit_score.factors.payment_history,
        credit_score.factors.economic_stability,
        task_completion_rate,
        account_age_days,
        prior_claims,
        prior_claims_paid_micro_usd,
        total_coverage_micro_usd,
    );

    // Composite risk score: higher = riskier (inverted from reliability scores).
    let reliability_score = W_OPERATIONAL * components.operational_reliability
        + W_PAYMENT * components.payment_reliability
        + W_ECONOMIC * components.economic_stability
        + W_TASK_COMPLETION * components.task_completion_rate
        + W_MATURITY * components.account_maturity
        + W_CLAIMS * components.claims_history;

    // Risk is the inverse of reliability.
    let risk_score = (1.0 - reliability_score).clamp(0.0, 1.0);

    let risk_rating = score_to_rating(risk_score);
    let premium_multiplier = rating_to_multiplier(risk_rating);
    let (insurable, denial_reason) = check_insurability(risk_score, trust_score, credit_score.tier);

    RiskAssessment {
        agent_id: agent_id.to_string(),
        risk_score,
        risk_rating,
        credit_tier: credit_score.tier,
        trust_score,
        components,
        premium_multiplier,
        insurable,
        denial_reason,
        assessed_at: Utc::now(),
    }
}

/// Quick check: is an agent eligible for insurance coverage?
pub fn is_eligible_for_insurance(
    trust_score: f64,
    credit_tier: CreditTier,
    min_trust_tier: InsuranceTrustTier,
) -> bool {
    let meets_trust = match min_trust_tier {
        InsuranceTrustTier::Any => true,
        InsuranceTrustTier::Provisional => trust_score >= 0.50,
        InsuranceTrustTier::Trusted => trust_score >= 0.75,
        InsuranceTrustTier::Certified => trust_score >= 0.90,
    };

    let meets_credit = credit_tier != CreditTier::None;

    meets_trust && meets_credit
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn compute_components(
    operational_reliability: f64,
    payment_history: f64,
    economic_stability: f64,
    task_completion_rate: f64,
    account_age_days: u32,
    prior_claims: u32,
    prior_claims_paid_micro_usd: i64,
    total_coverage_micro_usd: i64,
) -> RiskComponents {
    let maturity = (account_age_days as f64 / AGE_SATURATION_DAYS).min(1.0);

    // Claims history: penalize based on loss ratio (claims paid / coverage).
    let claims_history = if prior_claims == 0 {
        1.0
    } else if total_coverage_micro_usd <= 0 {
        // No coverage baseline, use claim count penalty.
        (1.0 - 0.15 * prior_claims as f64).max(0.0)
    } else {
        // Loss ratio: lower is better for the insurer.
        let loss_ratio = prior_claims_paid_micro_usd as f64 / total_coverage_micro_usd as f64;
        (1.0 - loss_ratio).clamp(0.0, 1.0)
    };

    RiskComponents {
        operational_reliability: operational_reliability.clamp(0.0, 1.0),
        payment_reliability: payment_history.clamp(0.0, 1.0),
        economic_stability: economic_stability.clamp(0.0, 1.0),
        task_completion_rate: task_completion_rate.clamp(0.0, 1.0),
        account_maturity: maturity,
        claims_history,
    }
}

fn score_to_rating(risk_score: f64) -> RiskRating {
    if risk_score <= 0.25 {
        RiskRating::Low
    } else if risk_score <= 0.50 {
        RiskRating::Medium
    } else if risk_score <= 0.75 {
        RiskRating::High
    } else {
        RiskRating::Critical
    }
}

fn rating_to_multiplier(rating: RiskRating) -> f64 {
    match rating {
        RiskRating::Low => LOW_RISK_MULTIPLIER,
        RiskRating::Medium => MEDIUM_RISK_MULTIPLIER,
        RiskRating::High => HIGH_RISK_MULTIPLIER,
        RiskRating::Critical => CRITICAL_RISK_MULTIPLIER,
    }
}

fn check_insurability(
    risk_score: f64,
    trust_score: f64,
    credit_tier: CreditTier,
) -> (bool, Option<String>) {
    if risk_score > (1.0 - MIN_INSURABLE_SCORE) {
        return (
            false,
            Some(format!(
                "risk score {risk_score:.2} exceeds maximum insurable threshold"
            )),
        );
    }
    if trust_score < 0.20 {
        return (
            false,
            Some("trust score below minimum insurable threshold (0.20)".into()),
        );
    }
    if credit_tier == CreditTier::None {
        return (
            false,
            Some("no credit tier — agents must have at least Micro credit".into()),
        );
    }
    (true, None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use haima_core::credit::{CreditFactors, compute_credit_score};

    fn make_credit_score(trust: f64, payment: f64, stability: f64) -> CreditScore {
        let factors = CreditFactors {
            trust_score: trust,
            payment_history: payment,
            transaction_volume: 1_000_000,
            account_age_days: 60,
            economic_stability: stability,
        };
        compute_credit_score("test-agent", &factors)
    }

    #[test]
    fn weights_sum_to_one() {
        let total =
            W_OPERATIONAL + W_PAYMENT + W_ECONOMIC + W_TASK_COMPLETION + W_MATURITY + W_CLAIMS;
        assert!((total - 1.0).abs() < 1e-10, "weights sum to {total}");
    }

    #[test]
    fn perfect_agent_gets_low_risk() {
        let cs = make_credit_score(1.0, 1.0, 1.0);
        let assessment = assess_risk("agent-perfect", &cs, 1.0, 1.0, 1.0, 90, 0, 0, 0);
        assert_eq!(assessment.risk_rating, RiskRating::Low);
        assert!(assessment.risk_score < 0.10);
        assert!(assessment.insurable);
        assert!(assessment.premium_multiplier < 1.0);
    }

    #[test]
    fn new_agent_moderate_risk() {
        let cs = make_credit_score(0.5, 0.5, 0.5);
        let assessment = assess_risk("agent-new", &cs, 0.5, 0.5, 0.5, 7, 0, 0, 0);
        assert!(assessment.risk_score > 0.25);
        assert!(assessment.insurable);
    }

    #[test]
    fn terrible_agent_not_insurable() {
        let cs = make_credit_score(0.1, 0.1, 0.1);
        let assessment = assess_risk("agent-bad", &cs, 0.1, 0.1, 0.1, 1, 5, 5_000_000, 1_000_000);
        assert!(!assessment.insurable);
        assert!(assessment.denial_reason.is_some());
    }

    #[test]
    fn prior_claims_increase_risk() {
        let cs = make_credit_score(0.8, 0.8, 0.8);
        let no_claims = assess_risk("a1", &cs, 0.8, 0.8, 0.8, 60, 0, 0, 10_000_000);
        let with_claims = assess_risk("a1", &cs, 0.8, 0.8, 0.8, 60, 3, 3_000_000, 10_000_000);
        assert!(with_claims.risk_score > no_claims.risk_score);
    }

    #[test]
    fn eligibility_check() {
        assert!(is_eligible_for_insurance(
            0.8,
            CreditTier::Standard,
            InsuranceTrustTier::Any
        ));
        assert!(is_eligible_for_insurance(
            0.8,
            CreditTier::Standard,
            InsuranceTrustTier::Trusted
        ));
        assert!(!is_eligible_for_insurance(
            0.4,
            CreditTier::Standard,
            InsuranceTrustTier::Trusted
        ));
        assert!(!is_eligible_for_insurance(
            0.9,
            CreditTier::None,
            InsuranceTrustTier::Any
        ));
    }

    #[test]
    fn risk_score_clamped() {
        let cs = make_credit_score(0.0, 0.0, 0.0);
        let assessment = assess_risk("edge", &cs, 0.0, 0.0, 0.0, 0, 0, 0, 0);
        assert!(assessment.risk_score >= 0.0 && assessment.risk_score <= 1.0);
    }
}

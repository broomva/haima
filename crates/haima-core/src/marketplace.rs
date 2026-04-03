//! Insurance marketplace engine — business logic for underwriting, quoting,
//! binding, claims verification, and pool management.
//!
//! This module implements the core marketplace operations that connect agents
//! with insurance products. Risk assessment is powered by Autonomic trust
//! scores and Haima credit data. Claims verification uses Lago event evidence.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::bureau::{RiskRating, TrustContext, TrustTrajectory};
use crate::credit::{CreditScore, CreditTier};
use crate::insurance::{
    ClaimRequest, ClaimStatus, ClaimVerification, InsuranceClaim, InsurancePolicy, InsurancePool,
    InsuranceProduct, InsuranceProductType, InsuranceProvider, InsuranceQuote, InsuranceTrustTier,
    PolicyStatus, PoolStatus, ProviderType, QuoteRequest, RiskAssessment, RiskComponents,
};

// ---------------------------------------------------------------------------
// Risk Assessment Engine
// ---------------------------------------------------------------------------

/// Weights for computing the composite risk score.
const OPERATIONAL_WEIGHT: f64 = 0.25;
const PAYMENT_WEIGHT: f64 = 0.20;
const ECONOMIC_WEIGHT: f64 = 0.15;
const TASK_COMPLETION_WEIGHT: f64 = 0.20;
const MATURITY_WEIGHT: f64 = 0.10;
const CLAIMS_WEIGHT: f64 = 0.10;

/// Compute a risk assessment for an agent.
///
/// Uses trust data from Autonomic and credit data from Haima to produce
/// a composite risk score, premium multiplier, and insurability decision.
pub fn assess_risk(
    agent_id: &str,
    trust: Option<&TrustContext>,
    credit: Option<&CreditScore>,
    claims_history: &ClaimsHistory,
) -> RiskAssessment {
    let trust_score = trust.map(|t| t.score).unwrap_or(0.0);

    // Derive component scores from trust (behavioral) and credit (financial) data.
    // Trust provides a single composite score; we split it into pillars via heuristics.
    let trust_based = trust_score;
    let payment_based = credit.map(|c| c.factors.payment_history).unwrap_or(0.5);
    let econ_based = credit.map(|c| c.factors.economic_stability).unwrap_or(0.5);

    let components = RiskComponents {
        operational_reliability: trust_based.max(0.0).min(1.0),
        payment_reliability: payment_based.max(0.0).min(1.0),
        economic_stability: econ_based.max(0.0).min(1.0),
        task_completion_rate: trust_based.max(0.0).min(1.0),
        account_maturity: compute_maturity_factor(
            credit.map(|c| c.factors.account_age_days).unwrap_or(0),
        ),
        claims_history: claims_history.claims_factor(),
    };

    // Composite: higher = lower risk (reliability-oriented)
    let reliability_score = components.operational_reliability * OPERATIONAL_WEIGHT
        + components.payment_reliability * PAYMENT_WEIGHT
        + components.economic_stability * ECONOMIC_WEIGHT
        + components.task_completion_rate * TASK_COMPLETION_WEIGHT
        + components.account_maturity * MATURITY_WEIGHT
        + components.claims_history * CLAIMS_WEIGHT;

    // risk_score: 0.0 = lowest risk, 1.0 = highest risk (invert reliability)
    let risk_score = (1.0 - reliability_score).clamp(0.0, 1.0);

    let risk_rating = match risk_score {
        s if s < 0.25 => RiskRating::Low,
        s if s < 0.50 => RiskRating::Medium,
        s if s < 0.75 => RiskRating::High,
        _ => RiskRating::Critical,
    };

    // Premium multiplier: low risk pays less, high risk pays more.
    // Range: 0.7 (best) to 3.0 (worst).
    let premium_multiplier = match risk_rating {
        RiskRating::Low => 0.7 + risk_score,
        RiskRating::Medium => 1.0 + risk_score,
        RiskRating::High => 1.5 + risk_score,
        RiskRating::Critical => 2.5 + risk_score * 0.5,
    };

    // Agents with degrading trust or Critical risk are uninsurable.
    let degrading = trust
        .map(|t| t.trajectory == TrustTrajectory::Degrading)
        .unwrap_or(false);
    let insurable = risk_rating != RiskRating::Critical && !degrading;

    let denial_reason = if !insurable {
        if degrading {
            Some("trust trajectory is degrading — reassess after stabilization".into())
        } else {
            Some(
                "risk rating is critical — agent does not meet minimum insurability threshold"
                    .into(),
            )
        }
    } else {
        None
    };

    RiskAssessment {
        agent_id: agent_id.to_string(),
        risk_score,
        risk_rating,
        credit_tier: credit.map(|c| c.tier).unwrap_or(CreditTier::None),
        trust_score,
        components,
        premium_multiplier,
        insurable,
        denial_reason,
        assessed_at: Utc::now(),
    }
}

/// Claims history summary used for risk assessment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaimsHistory {
    pub total_claims: u32,
    pub approved_claims: u32,
    pub denied_claims: u32,
    pub total_payout_micro_usd: i64,
}

impl ClaimsHistory {
    /// Factor for risk scoring: 1.0 = no claims (best), 0.0 = many claims (worst).
    pub fn claims_factor(&self) -> f64 {
        if self.total_claims == 0 {
            return 1.0;
        }
        // Penalize for number of approved claims and payout volume.
        let claim_penalty = (self.approved_claims as f64 * 0.15).min(0.6);
        let volume_penalty = (self.total_payout_micro_usd as f64 / 10_000_000.0).min(0.3);
        (1.0 - claim_penalty - volume_penalty).max(0.0)
    }
}

fn compute_maturity_factor(account_age_days: u32) -> f64 {
    // 0 days = 0.0, 30 days = 0.5, 90+ days = 1.0
    (account_age_days as f64 / 90.0).min(1.0)
}

// ---------------------------------------------------------------------------
// Premium Calculation
// ---------------------------------------------------------------------------

/// Calculate the premium for a coverage request.
///
/// premium = base_rate * coverage * period_factor * risk_multiplier
pub fn calculate_premium(
    product: &InsuranceProduct,
    coverage_micro_usd: i64,
    risk_assessment: &RiskAssessment,
) -> i64 {
    let base_rate = product.base_rate_bps as f64 / 10_000.0;
    let period_factor = product.period_secs as f64 / (365.25 * 24.0 * 3600.0); // annualized
    let raw_premium =
        coverage_micro_usd as f64 * base_rate * period_factor * risk_assessment.premium_multiplier;
    raw_premium.round() as i64
}

// ---------------------------------------------------------------------------
// Quote Generation
// ---------------------------------------------------------------------------

/// Generate an insurance quote for an agent.
///
/// Returns `None` if the agent is not insurable or coverage is out of bounds.
pub fn generate_quote(
    request: &QuoteRequest,
    product: &InsuranceProduct,
    risk_assessment: &RiskAssessment,
) -> Option<InsuranceQuote> {
    // Check insurability.
    if !risk_assessment.insurable {
        return None;
    }

    // Check coverage bounds.
    if request.coverage_micro_usd < product.min_coverage_micro_usd
        || request.coverage_micro_usd > product.max_coverage_micro_usd
    {
        return None;
    }

    // Check trust tier eligibility.
    let agent_tier = trust_score_to_insurance_tier(risk_assessment.trust_score);
    if agent_tier < product.min_trust_tier {
        return None;
    }

    let premium = calculate_premium(product, request.coverage_micro_usd, risk_assessment);

    Some(InsuranceQuote {
        quote_id: format!("quote-{}", Utc::now().timestamp_millis()),
        agent_id: request.agent_id.clone(),
        product_id: product.product_id.clone(),
        product_type: product.product_type,
        coverage_micro_usd: request.coverage_micro_usd,
        deductible_micro_usd: product.default_deductible_micro_usd,
        premium_micro_usd: premium,
        period_secs: product.period_secs,
        risk_assessment: risk_assessment.clone(),
        provider_id: product.provider_id.clone(),
        valid_until: Utc::now() + Duration::hours(24),
        quoted_at: Utc::now(),
    })
}

fn trust_score_to_insurance_tier(trust_score: f64) -> InsuranceTrustTier {
    match trust_score {
        s if s >= 0.90 => InsuranceTrustTier::Certified,
        s if s >= 0.75 => InsuranceTrustTier::Trusted,
        s if s >= 0.50 => InsuranceTrustTier::Provisional,
        _ => InsuranceTrustTier::Any,
    }
}

// ---------------------------------------------------------------------------
// Policy Binding
// ---------------------------------------------------------------------------

/// Bind a quote into an active policy.
///
/// Returns `None` if the quote has expired.
pub fn bind_policy(quote: &InsuranceQuote) -> Option<InsurancePolicy> {
    if Utc::now() > quote.valid_until {
        return None;
    }

    let effective_from = Utc::now();
    let effective_until = effective_from + Duration::seconds(quote.period_secs as i64);

    Some(InsurancePolicy {
        policy_id: format!("pol-{}", Utc::now().timestamp_millis()),
        agent_id: quote.agent_id.clone(),
        product_id: quote.product_id.clone(),
        product_type: quote.product_type,
        coverage_limit_micro_usd: quote.coverage_micro_usd,
        deductible_micro_usd: quote.deductible_micro_usd,
        premium_micro_usd: quote.premium_micro_usd,
        status: PolicyStatus::Active,
        effective_from,
        effective_until,
        claims_paid_micro_usd: 0,
        claims_count: 0,
        provider_id: quote.provider_id.clone(),
        issued_at: Utc::now(),
    })
}

// ---------------------------------------------------------------------------
// Claims Processing
// ---------------------------------------------------------------------------

/// Create a claim from a request and look up the associated policy.
///
/// Returns `None` if the policy is not active or the incident type doesn't
/// match the policy coverage.
pub fn create_claim(request: &ClaimRequest, policy: &InsurancePolicy) -> Option<InsuranceClaim> {
    // Policy must be active.
    if policy.status != PolicyStatus::Active {
        return None;
    }

    // Incident type must match policy coverage.
    if request.incident_type != policy.product_type {
        return None;
    }

    // Incident must be within policy period.
    if request.incident_at < policy.effective_from || request.incident_at > policy.effective_until {
        return None;
    }

    // Claimed amount cannot exceed remaining coverage.
    let remaining_coverage = policy.coverage_limit_micro_usd - policy.claims_paid_micro_usd;
    if request.claimed_amount_micro_usd > remaining_coverage {
        return None;
    }

    Some(InsuranceClaim {
        claim_id: format!("claim-{}", Utc::now().timestamp_millis()),
        policy_id: request.policy_id.clone(),
        agent_id: request.agent_id.clone(),
        incident_type: request.incident_type,
        claimed_amount_micro_usd: request.claimed_amount_micro_usd,
        approved_amount_micro_usd: None,
        status: ClaimStatus::Submitted,
        description: request.description.clone(),
        evidence_event_ids: request.evidence_event_ids.clone(),
        session_id: request.session_id.clone(),
        incident_at: request.incident_at,
        filed_at: Utc::now(),
        resolved_at: None,
        resolution_notes: None,
        verification: None,
    })
}

/// Verify a claim against Lago event evidence.
///
/// `evidence_valid_count` is how many of the submitted event IDs were found
/// and validated in the Lago journal. `amount_consistent` indicates whether
/// the claimed amount aligns with the evidence.
pub fn verify_claim(
    claim: &mut InsuranceClaim,
    policy: &InsurancePolicy,
    evidence_valid_count: u32,
    amount_consistent: bool,
) -> ClaimVerification {
    let evidence_total = claim.evidence_event_ids.len() as u32;
    let evidence_ratio = if evidence_total > 0 {
        evidence_valid_count as f64 / evidence_total as f64
    } else {
        0.0
    };

    let policy_active_at_incident = policy.status == PolicyStatus::Active
        && claim.incident_at >= policy.effective_from
        && claim.incident_at <= policy.effective_until;

    let incident_confirmed = evidence_ratio >= 0.5 && evidence_valid_count > 0;

    // Confidence: weighted combination of evidence quality and consistency.
    let confidence = (evidence_ratio * 0.5
        + if amount_consistent { 0.3 } else { 0.0 }
        + if policy_active_at_incident { 0.2 } else { 0.0 })
    .clamp(0.0, 1.0);

    let verification = ClaimVerification {
        incident_confirmed,
        evidence_events_validated: evidence_valid_count,
        evidence_events_total: evidence_total,
        amount_consistent,
        policy_active_at_incident,
        confidence,
        notes: build_verification_notes(
            incident_confirmed,
            evidence_ratio,
            amount_consistent,
            policy_active_at_incident,
        ),
        verified_at: Utc::now(),
    };

    // Update claim status based on verification.
    if incident_confirmed && amount_consistent && policy_active_at_incident && confidence >= 0.7 {
        let payout = compute_payout(claim, policy);
        claim.approved_amount_micro_usd = Some(payout);
        claim.status = ClaimStatus::Approved;
    } else if confidence < 0.3 {
        claim.status = ClaimStatus::Denied;
        claim.resolution_notes =
            Some("automated verification failed — insufficient evidence".into());
    } else {
        claim.status = ClaimStatus::UnderReview;
        claim.resolution_notes =
            Some("confidence below auto-approval threshold — manual review required".into());
    }

    claim.verification = Some(verification.clone());
    verification
}

fn compute_payout(claim: &InsuranceClaim, policy: &InsurancePolicy) -> i64 {
    // Payout = claimed amount minus deductible, capped at remaining coverage.
    let after_deductible = (claim.claimed_amount_micro_usd - policy.deductible_micro_usd).max(0);
    let remaining_coverage = policy.coverage_limit_micro_usd - policy.claims_paid_micro_usd;
    after_deductible.min(remaining_coverage)
}

fn build_verification_notes(
    incident_confirmed: bool,
    evidence_ratio: f64,
    amount_consistent: bool,
    policy_active: bool,
) -> Vec<String> {
    let mut notes = Vec::new();
    if incident_confirmed {
        notes.push(format!(
            "incident confirmed — {:.0}% of evidence validated",
            evidence_ratio * 100.0
        ));
    } else {
        notes.push("incident not confirmed — insufficient evidence".into());
    }
    if amount_consistent {
        notes.push("claimed amount consistent with evidence".into());
    } else {
        notes.push("claimed amount inconsistent with evidence".into());
    }
    if policy_active {
        notes.push("policy was active at time of incident".into());
    } else {
        notes.push("policy was NOT active at time of incident".into());
    }
    notes
}

// ---------------------------------------------------------------------------
// Pool Operations
// ---------------------------------------------------------------------------

/// Create a new self-insurance pool.
pub fn create_pool(pool_id: &str, name: &str, management_fee_bps: u32) -> InsurancePool {
    InsurancePool {
        pool_id: pool_id.to_string(),
        name: name.to_string(),
        reserves_micro_usd: 0,
        total_contributions_micro_usd: 0,
        total_payouts_micro_usd: 0,
        active_policies: 0,
        total_coverage_outstanding_micro_usd: 0,
        reserve_ratio: 0.0,
        management_fee_bps,
        min_reserve_ratio: 0.10,
        status: PoolStatus::Active,
        created_at: Utc::now(),
    }
}

/// Process a contribution to the pool.
pub fn contribute_to_pool(pool: &mut InsurancePool, amount_micro_usd: i64) {
    pool.reserves_micro_usd += amount_micro_usd;
    pool.total_contributions_micro_usd += amount_micro_usd;
    update_pool_status(pool);
}

/// Process a payout from the pool for an approved claim.
///
/// Returns `None` if the pool has insufficient reserves.
pub fn pool_payout(pool: &mut InsurancePool, amount_micro_usd: i64) -> Option<i64> {
    if pool.reserves_micro_usd < amount_micro_usd {
        return None;
    }
    pool.reserves_micro_usd -= amount_micro_usd;
    pool.total_payouts_micro_usd += amount_micro_usd;
    update_pool_status(pool);
    Some(pool.reserves_micro_usd)
}

/// Register a new policy against the pool.
pub fn pool_register_policy(pool: &mut InsurancePool, coverage_micro_usd: i64) {
    pool.active_policies += 1;
    pool.total_coverage_outstanding_micro_usd += coverage_micro_usd;
    update_pool_status(pool);
}

fn update_pool_status(pool: &mut InsurancePool) {
    pool.reserve_ratio = if pool.total_coverage_outstanding_micro_usd > 0 {
        pool.reserves_micro_usd as f64 / pool.total_coverage_outstanding_micro_usd as f64
    } else {
        1.0
    };

    // Pause new policies if reserve ratio drops below minimum.
    if pool.reserve_ratio < pool.min_reserve_ratio && pool.status == PoolStatus::Active {
        pool.status = PoolStatus::Paused;
    } else if pool.reserve_ratio >= pool.min_reserve_ratio && pool.status == PoolStatus::Paused {
        pool.status = PoolStatus::Active;
    }
}

// ---------------------------------------------------------------------------
// Default Products Catalog
// ---------------------------------------------------------------------------

/// Create the default insurance product catalog.
pub fn default_products(pool_id: &str) -> Vec<InsuranceProduct> {
    vec![
        InsuranceProduct {
            product_id: "prod-task-failure".into(),
            product_type: InsuranceProductType::TaskFailure,
            name: "Task Failure Coverage".into(),
            description:
                "Covers customer losses when an agent task fails to produce the contracted outcome."
                    .into(),
            base_rate_bps: 250,                   // 2.5% annual
            min_coverage_micro_usd: 100_000,      // $0.10
            max_coverage_micro_usd: 100_000_000,  // $100
            default_deductible_micro_usd: 50_000, // $0.05
            period_secs: 30 * 24 * 3600,          // 30 days
            min_trust_tier: InsuranceTrustTier::Provisional,
            provider_id: pool_id.into(),
            active: true,
        },
        InsuranceProduct {
            product_id: "prod-financial-error".into(),
            product_type: InsuranceProductType::FinancialError,
            name: "Financial Error Coverage".into(),
            description: "Covers erroneous payments or transaction errors caused by the agent."
                .into(),
            base_rate_bps: 400, // 4.0% annual
            min_coverage_micro_usd: 100_000,
            max_coverage_micro_usd: 50_000_000,    // $50
            default_deductible_micro_usd: 100_000, // $0.10
            period_secs: 30 * 24 * 3600,
            min_trust_tier: InsuranceTrustTier::Trusted,
            provider_id: pool_id.into(),
            active: true,
        },
        InsuranceProduct {
            product_id: "prod-data-breach".into(),
            product_type: InsuranceProductType::DataBreach,
            name: "Data Breach Coverage".into(),
            description: "Covers liability from agent-caused data exposure incidents.".into(),
            base_rate_bps: 500,                    // 5.0% annual
            min_coverage_micro_usd: 1_000_000,     // $1
            max_coverage_micro_usd: 500_000_000,   // $500
            default_deductible_micro_usd: 500_000, // $0.50
            period_secs: 90 * 24 * 3600,           // 90 days
            min_trust_tier: InsuranceTrustTier::Trusted,
            provider_id: pool_id.into(),
            active: true,
        },
        InsuranceProduct {
            product_id: "prod-sla-penalty".into(),
            product_type: InsuranceProductType::SlaPenalty,
            name: "SLA Penalty Coverage".into(),
            description: "Covers SLA breach penalties when an agent misses contracted deadlines."
                .into(),
            base_rate_bps: 300, // 3.0% annual
            min_coverage_micro_usd: 100_000,
            max_coverage_micro_usd: 200_000_000, // $200
            default_deductible_micro_usd: 50_000,
            period_secs: 30 * 24 * 3600,
            min_trust_tier: InsuranceTrustTier::Provisional,
            provider_id: pool_id.into(),
            active: true,
        },
    ]
}

/// Create the default self-insurance pool provider.
pub fn default_pool_provider(pool_id: &str) -> InsuranceProvider {
    InsuranceProvider {
        provider_id: pool_id.to_string(),
        name: "Life Network Self-Insurance Pool".into(),
        provider_type: ProviderType::SelfInsurancePool,
        offered_products: vec![
            InsuranceProductType::TaskFailure,
            InsuranceProductType::FinancialError,
            InsuranceProductType::DataBreach,
            InsuranceProductType::SlaPenalty,
        ],
        commission_rate_bps: 1500, // 15% facilitation commission
        active: true,
        api_endpoint: None,
        registered_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Dashboard Summary
// ---------------------------------------------------------------------------

/// Insurance marketplace dashboard summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsuranceDashboard {
    pub total_products: usize,
    pub active_policies: u32,
    pub total_premiums_collected_micro_usd: i64,
    pub total_commission_earned_micro_usd: i64,
    pub total_claims_filed: u32,
    pub total_claims_paid_micro_usd: i64,
    pub pool_reserves_micro_usd: i64,
    pub pool_reserve_ratio: f64,
    pub pool_status: PoolStatus,
    pub loss_ratio: f64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_trust_context(score: f64, trajectory: TrustTrajectory) -> TrustContext {
        TrustContext {
            score,
            tier: if score >= 0.75 {
                "trusted".into()
            } else {
                "provisional".into()
            },
            trajectory,
        }
    }

    fn test_credit_score(score: f64, tier: CreditTier) -> CreditScore {
        use crate::credit::CreditFactors;
        CreditScore {
            agent_id: "agent-1".into(),
            tier,
            score,
            spending_limit_micro_usd: 1_000_000,
            current_balance_micro_usd: 0,
            factors: CreditFactors {
                trust_score: score,
                payment_history: score,
                transaction_volume: 100_000,
                account_age_days: 60,
                economic_stability: score,
            },
            assessed_at: Utc::now(),
        }
    }

    #[test]
    fn risk_assessment_low_risk_agent() {
        let trust = test_trust_context(0.85, TrustTrajectory::Stable);
        let credit = test_credit_score(0.80, CreditTier::Standard);
        let claims = ClaimsHistory::default();

        let assessment = assess_risk("agent-1", Some(&trust), Some(&credit), &claims);

        assert!(assessment.insurable);
        assert!(assessment.risk_score < 0.25);
        assert_eq!(assessment.risk_rating, RiskRating::Low);
        assert!(assessment.premium_multiplier < 1.5);
    }

    #[test]
    fn risk_assessment_degrading_trust_uninsurable() {
        let trust = test_trust_context(0.60, TrustTrajectory::Degrading);
        let credit = test_credit_score(0.50, CreditTier::Micro);
        let claims = ClaimsHistory::default();

        let assessment = assess_risk("agent-2", Some(&trust), Some(&credit), &claims);

        assert!(!assessment.insurable);
        assert!(assessment.denial_reason.is_some());
    }

    #[test]
    fn risk_assessment_no_data() {
        let claims = ClaimsHistory::default();
        let assessment = assess_risk("agent-new", None, None, &claims);

        // Unknown agent: medium risk, still insurable (with high premium).
        assert!(assessment.insurable);
        assert!(assessment.risk_score >= 0.25);
        assert!(assessment.risk_score < 0.75);
    }

    #[test]
    fn premium_calculation() {
        let product = &default_products("pool-1")[0]; // task failure, 250 bps
        let trust = test_trust_context(0.85, TrustTrajectory::Stable);
        let credit = test_credit_score(0.80, CreditTier::Standard);
        let assessment = assess_risk(
            "agent-1",
            Some(&trust),
            Some(&credit),
            &ClaimsHistory::default(),
        );

        let premium = calculate_premium(product, 10_000_000, &assessment); // $10 coverage
        assert!(premium > 0);
        // 30-day period = ~0.082 years, 250bps * $10 * 0.082 * ~0.85 multiplier ≈ reasonable
        assert!(premium < 500_000); // sanity: less than $0.50 for $10 coverage
    }

    #[test]
    fn quote_generation_and_binding() {
        let products = default_products("pool-1");
        let product = &products[0]; // task failure
        let trust = test_trust_context(0.85, TrustTrajectory::Stable);
        let credit = test_credit_score(0.80, CreditTier::Standard);
        let assessment = assess_risk(
            "agent-1",
            Some(&trust),
            Some(&credit),
            &ClaimsHistory::default(),
        );

        let request = QuoteRequest {
            agent_id: "agent-1".into(),
            product_type: InsuranceProductType::TaskFailure,
            coverage_micro_usd: 5_000_000,
            preferred_provider_id: None,
        };

        let quote = generate_quote(&request, product, &assessment);
        assert!(quote.is_some());

        let quote = quote.unwrap();
        assert_eq!(quote.agent_id, "agent-1");
        assert!(quote.premium_micro_usd > 0);

        let policy = bind_policy(&quote);
        assert!(policy.is_some());

        let policy = policy.unwrap();
        assert_eq!(policy.status, PolicyStatus::Active);
        assert_eq!(policy.coverage_limit_micro_usd, 5_000_000);
    }

    #[test]
    fn claim_creation_and_verification() {
        let products = default_products("pool-1");
        let product = &products[0];
        let trust = test_trust_context(0.85, TrustTrajectory::Stable);
        let credit = test_credit_score(0.80, CreditTier::Standard);
        let assessment = assess_risk(
            "agent-1",
            Some(&trust),
            Some(&credit),
            &ClaimsHistory::default(),
        );

        let request = QuoteRequest {
            agent_id: "agent-1".into(),
            product_type: InsuranceProductType::TaskFailure,
            coverage_micro_usd: 5_000_000,
            preferred_provider_id: None,
        };
        let quote = generate_quote(&request, product, &assessment).unwrap();
        let policy = bind_policy(&quote).unwrap();

        let claim_request = ClaimRequest {
            policy_id: policy.policy_id.clone(),
            agent_id: "agent-1".into(),
            incident_type: InsuranceProductType::TaskFailure,
            claimed_amount_micro_usd: 1_000_000,
            description: "task failed to produce output".into(),
            evidence_event_ids: vec!["evt-1".into(), "evt-2".into(), "evt-3".into()],
            session_id: Some("sess-1".into()),
            incident_at: Utc::now(),
        };

        let mut claim = create_claim(&claim_request, &policy).unwrap();
        assert_eq!(claim.status, ClaimStatus::Submitted);

        // Verify with good evidence.
        let verification = verify_claim(&mut claim, &policy, 3, true);
        assert!(verification.incident_confirmed);
        assert!(verification.confidence >= 0.7);
        assert_eq!(claim.status, ClaimStatus::Approved);
        assert!(claim.approved_amount_micro_usd.unwrap() > 0);
    }

    #[test]
    fn claim_denied_insufficient_evidence() {
        let products = default_products("pool-1");
        let product = &products[0];
        let trust = test_trust_context(0.85, TrustTrajectory::Stable);
        let credit = test_credit_score(0.80, CreditTier::Standard);
        let assessment = assess_risk(
            "agent-1",
            Some(&trust),
            Some(&credit),
            &ClaimsHistory::default(),
        );

        let request = QuoteRequest {
            agent_id: "agent-1".into(),
            product_type: InsuranceProductType::TaskFailure,
            coverage_micro_usd: 5_000_000,
            preferred_provider_id: None,
        };
        let quote = generate_quote(&request, product, &assessment).unwrap();
        let policy = bind_policy(&quote).unwrap();

        let claim_request = ClaimRequest {
            policy_id: policy.policy_id.clone(),
            agent_id: "agent-1".into(),
            incident_type: InsuranceProductType::TaskFailure,
            claimed_amount_micro_usd: 1_000_000,
            description: "task failed".into(),
            evidence_event_ids: vec!["evt-1".into(), "evt-2".into(), "evt-3".into()],
            session_id: None,
            incident_at: Utc::now(),
        };

        let mut claim = create_claim(&claim_request, &policy).unwrap();
        // Verify with no valid evidence.
        let verification = verify_claim(&mut claim, &policy, 0, false);
        assert!(!verification.incident_confirmed);
        assert_eq!(claim.status, ClaimStatus::Denied);
    }

    #[test]
    fn pool_operations() {
        let mut pool = create_pool("pool-1", "Test Pool", 250);
        assert_eq!(pool.reserves_micro_usd, 0);

        contribute_to_pool(&mut pool, 10_000_000);
        assert_eq!(pool.reserves_micro_usd, 10_000_000);

        pool_register_policy(&mut pool, 5_000_000);
        assert_eq!(pool.active_policies, 1);
        assert!(pool.reserve_ratio > 1.0); // 10M reserves / 5M coverage

        let remaining = pool_payout(&mut pool, 2_000_000);
        assert!(remaining.is_some());
        assert_eq!(pool.reserves_micro_usd, 8_000_000);
    }

    #[test]
    fn pool_pauses_on_low_reserves() {
        let mut pool = create_pool("pool-1", "Test Pool", 250);
        contribute_to_pool(&mut pool, 1_000_000);
        pool_register_policy(&mut pool, 100_000_000); // $100 coverage, only $1 reserves

        assert_eq!(pool.status, PoolStatus::Paused);
        assert!(pool.reserve_ratio < pool.min_reserve_ratio);
    }

    #[test]
    fn claims_history_factor() {
        let empty = ClaimsHistory::default();
        assert_eq!(empty.claims_factor(), 1.0);

        let some_claims = ClaimsHistory {
            total_claims: 3,
            approved_claims: 2,
            denied_claims: 1,
            total_payout_micro_usd: 5_000_000,
        };
        let factor = some_claims.claims_factor();
        assert!(factor > 0.0 && factor < 1.0);
    }
}

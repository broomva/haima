//! Claims submission, verification, and processing.
//!
//! Claims are verified against the immutable Lago event journal:
//! 1. Agent submits a claim with evidence event IDs
//! 2. System verifies the events exist and match the claim
//! 3. System checks policy was active at the time of incident
//! 4. System calculates payout (claimed amount minus deductible)
//! 5. Payout is processed from the pool or forwarded to the insurer

use chrono::Utc;
use haima_core::error::{HaimaError, HaimaResult};
use haima_core::insurance::{
    ClaimRequest, ClaimStatus, ClaimVerification, InsuranceClaim, InsurancePolicy, PolicyStatus,
};

/// File a new insurance claim from a request.
///
/// Validates the claim against the policy before creating it.
pub fn process_claim(
    request: &ClaimRequest,
    policy: &InsurancePolicy,
    claim_id: &str,
) -> HaimaResult<InsuranceClaim> {
    // Check policy is active.
    if policy.status != PolicyStatus::Active {
        return Err(HaimaError::PolicyNotActive {
            policy_id: policy.policy_id.clone(),
            status: policy.status.to_string(),
        });
    }

    // Check policy covers this incident type.
    if policy.product_type != request.incident_type {
        return Err(HaimaError::PolicyNotActive {
            policy_id: policy.policy_id.clone(),
            status: format!(
                "product type mismatch: policy covers {}, claim is for {}",
                policy.product_type, request.incident_type
            ),
        });
    }

    // Check the incident occurred within the policy period.
    if request.incident_at < policy.effective_from || request.incident_at > policy.effective_until {
        return Err(HaimaError::PolicyNotActive {
            policy_id: policy.policy_id.clone(),
            status: "incident occurred outside policy period".into(),
        });
    }

    // Check remaining coverage.
    let remaining_coverage = policy.coverage_limit_micro_usd - policy.claims_paid_micro_usd;
    if request.claimed_amount_micro_usd > remaining_coverage {
        return Err(HaimaError::ClaimExceedsCoverage {
            claimed: request.claimed_amount_micro_usd,
            remaining: remaining_coverage,
        });
    }

    // Check agent is the policyholder.
    if policy.agent_id != request.agent_id {
        return Err(HaimaError::PolicyNotFound(format!(
            "policy {} does not belong to agent {}",
            policy.policy_id, request.agent_id
        )));
    }

    let now = Utc::now();

    Ok(InsuranceClaim {
        claim_id: claim_id.to_string(),
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
        filed_at: now,
        resolved_at: None,
        resolution_notes: None,
        verification: None,
    })
}

/// Verify a claim against event evidence.
///
/// In a full implementation, this would query the Lago journal to validate
/// each evidence event ID. For now, it performs structural validation and
/// returns a verification result based on the evidence provided.
///
/// The `evidence_valid_count` parameter represents how many of the submitted
/// evidence events were found and validated in the Lago journal (caller
/// performs the actual journal lookup).
pub fn verify_claim(
    claim: &InsuranceClaim,
    policy: &InsurancePolicy,
    evidence_valid_count: u32,
) -> ClaimVerification {
    let now = Utc::now();
    let total = claim.evidence_event_ids.len() as u32;
    let mut notes = Vec::new();

    // Check evidence coverage.
    let evidence_ratio = if total > 0 {
        evidence_valid_count as f64 / total as f64
    } else {
        0.0
    };
    let incident_confirmed = evidence_ratio >= 0.5 && evidence_valid_count > 0;

    if total == 0 {
        notes.push("no evidence events submitted".into());
    } else if evidence_valid_count == 0 {
        notes.push("none of the evidence events could be validated".into());
    } else if evidence_valid_count < total {
        notes.push(format!(
            "{evidence_valid_count}/{total} evidence events validated"
        ));
    } else {
        notes.push(format!("all {total} evidence events validated"));
    }

    // Check policy was active at incident time.
    let policy_active = claim.incident_at >= policy.effective_from
        && claim.incident_at <= policy.effective_until
        && policy.status == PolicyStatus::Active;

    if !policy_active {
        notes.push("policy was not active at time of incident".into());
    }

    // Amount consistency: claimed amount should not exceed coverage.
    let remaining = policy.coverage_limit_micro_usd - policy.claims_paid_micro_usd;
    let amount_consistent =
        claim.claimed_amount_micro_usd <= remaining && claim.claimed_amount_micro_usd > 0;

    if !amount_consistent {
        notes.push(format!(
            "claimed amount {} exceeds remaining coverage {}",
            claim.claimed_amount_micro_usd, remaining
        ));
    }

    // Composite confidence.
    let confidence = if incident_confirmed && policy_active && amount_consistent {
        // Base confidence from evidence ratio, boosted by full validation.
        (evidence_ratio * 0.7 + 0.3).min(1.0)
    } else if incident_confirmed {
        evidence_ratio * 0.5
    } else {
        0.0
    };

    ClaimVerification {
        incident_confirmed,
        evidence_events_validated: evidence_valid_count,
        evidence_events_total: total,
        amount_consistent,
        policy_active_at_incident: policy_active,
        confidence,
        notes,
        verified_at: now,
    }
}

/// Calculate the payout amount for an approved claim.
///
/// Payout = claimed_amount - deductible, clamped to remaining coverage.
pub fn calculate_payout(
    claimed_micro_usd: i64,
    deductible_micro_usd: i64,
    remaining_coverage_micro_usd: i64,
) -> i64 {
    let after_deductible = (claimed_micro_usd - deductible_micro_usd).max(0);
    after_deductible.min(remaining_coverage_micro_usd)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use haima_core::insurance::InsuranceProductType;

    fn make_policy() -> InsurancePolicy {
        let now = Utc::now();
        InsurancePolicy {
            policy_id: "pol-1".into(),
            agent_id: "agent-1".into(),
            product_id: "prod-1".into(),
            product_type: InsuranceProductType::TaskFailure,
            coverage_limit_micro_usd: 10_000_000,
            deductible_micro_usd: 100_000,
            premium_micro_usd: 50_000,
            status: PolicyStatus::Active,
            effective_from: now - Duration::days(15),
            effective_until: now + Duration::days(15),
            claims_paid_micro_usd: 0,
            claims_count: 0,
            provider_id: "pool-1".into(),
            issued_at: now - Duration::days(15),
        }
    }

    fn make_claim_request() -> ClaimRequest {
        ClaimRequest {
            policy_id: "pol-1".into(),
            agent_id: "agent-1".into(),
            incident_type: InsuranceProductType::TaskFailure,
            claimed_amount_micro_usd: 1_000_000,
            description: "Task failed due to API timeout".into(),
            evidence_event_ids: vec!["evt-1".into(), "evt-2".into(), "evt-3".into()],
            session_id: Some("session-1".into()),
            incident_at: Utc::now() - Duration::hours(2),
        }
    }

    #[test]
    fn valid_claim_created() {
        let policy = make_policy();
        let request = make_claim_request();
        let claim = process_claim(&request, &policy, "claim-1").unwrap();
        assert_eq!(claim.status, ClaimStatus::Submitted);
        assert_eq!(claim.claimed_amount_micro_usd, 1_000_000);
        assert_eq!(claim.evidence_event_ids.len(), 3);
    }

    #[test]
    fn claim_rejected_inactive_policy() {
        let mut policy = make_policy();
        policy.status = PolicyStatus::Expired;
        let request = make_claim_request();
        let result = process_claim(&request, &policy, "claim-1");
        assert!(result.is_err());
    }

    #[test]
    fn claim_rejected_exceeds_coverage() {
        let mut policy = make_policy();
        policy.claims_paid_micro_usd = 9_500_000; // only 500k remaining
        let request = make_claim_request(); // claiming 1M
        let result = process_claim(&request, &policy, "claim-1");
        assert!(result.is_err());
    }

    #[test]
    fn claim_rejected_wrong_agent() {
        let policy = make_policy();
        let mut request = make_claim_request();
        request.agent_id = "agent-other".into();
        let result = process_claim(&request, &policy, "claim-1");
        assert!(result.is_err());
    }

    #[test]
    fn verification_all_evidence_valid() {
        let policy = make_policy();
        let request = make_claim_request();
        let claim = process_claim(&request, &policy, "claim-1").unwrap();
        let verification = verify_claim(&claim, &policy, 3); // all 3 valid
        assert!(verification.incident_confirmed);
        assert!(verification.confidence > 0.9);
        assert!(verification.policy_active_at_incident);
        assert!(verification.amount_consistent);
    }

    #[test]
    fn verification_no_evidence() {
        let policy = make_policy();
        let mut request = make_claim_request();
        request.evidence_event_ids.clear();
        let claim = process_claim(&request, &policy, "claim-1").unwrap();
        let verification = verify_claim(&claim, &policy, 0);
        assert!(!verification.incident_confirmed);
        assert_eq!(verification.confidence, 0.0);
    }

    #[test]
    fn payout_calculation() {
        assert_eq!(calculate_payout(1_000_000, 100_000, 10_000_000), 900_000);
        assert_eq!(calculate_payout(1_000_000, 100_000, 500_000), 500_000);
        assert_eq!(calculate_payout(50_000, 100_000, 10_000_000), 0);
    }
}

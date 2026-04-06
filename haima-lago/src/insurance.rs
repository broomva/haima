//! Insurance state projection — deterministic fold over insurance finance events.
//!
//! Accumulates insurance-related state from the Lago event journal:
//! - Active policies and their claims history
//! - Claims in various lifecycle stages
//! - Self-insurance pool reserves and metrics
//! - Premium and commission tracking
//! - Dashboard summary for the insurance marketplace

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use haima_core::event::FinanceEventKind;
use haima_core::insurance::{
    ClaimStatus, InsuranceClaim, InsurancePolicy, InsurancePool, InsuranceProduct,
    InsuranceProvider, InsuranceQuote, PolicyStatus, PoolStatus,
};
use haima_core::marketplace::{ClaimsHistory, InsuranceDashboard};
use serde::{Deserialize, Serialize};

/// Insurance marketplace state — accumulated from insurance finance events.
///
/// This is a projection: recomputed by folding over events on startup,
/// then kept in sync via the event subscriber.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InsuranceState {
    // -- Product catalog --
    /// Available insurance products, keyed by `product_id`.
    pub products: HashMap<String, InsuranceProduct>,

    /// Registered insurance providers, keyed by `provider_id`.
    pub providers: HashMap<String, InsuranceProvider>,

    // -- Active quotes (pending bind) --
    /// Outstanding quotes, keyed by `quote_id`.
    pub quotes: HashMap<String, InsuranceQuote>,

    // -- Policy tracking --
    /// Full policies, keyed by `policy_id`.
    pub policies: HashMap<String, InsurancePolicy>,

    /// Active policy count per agent.
    pub policies_by_agent: HashMap<String, Vec<String>>,

    /// Total active policies.
    pub active_policies: u32,

    // -- Claims tracking --
    /// Full claims, keyed by `claim_id`.
    pub claims: HashMap<String, InsuranceClaim>,

    /// Claims by status for dashboard metrics.
    pub claims_submitted: u32,
    pub claims_approved: u32,
    pub claims_denied: u32,
    pub claims_paid: u32,
    pub claims_under_review: u32,

    /// Per-agent claims history for risk assessment.
    pub agent_claims: HashMap<String, ClaimsHistory>,

    // -- Financial metrics --
    /// Total premiums collected (micro-USD).
    pub total_premiums_collected: i64,
    /// Total commission earned by the marketplace (micro-USD).
    pub total_commission_earned: i64,
    /// Total claims paid out (micro-USD).
    pub total_claims_paid: i64,

    // -- Pool state --
    /// Self-insurance pool, if initialized.
    pub pool: Option<InsurancePool>,

    /// Timestamp of last insurance event.
    pub last_event_at: Option<DateTime<Utc>>,
}

impl InsuranceState {
    /// Store a fully constructed policy in the state.
    pub fn store_policy(&mut self, policy: InsurancePolicy) {
        self.policies.insert(policy.policy_id.clone(), policy);
    }

    /// Store a claim in the state.
    pub fn store_claim(&mut self, claim: InsuranceClaim) {
        self.claims.insert(claim.claim_id.clone(), claim);
    }

    /// Look up a policy by ID.
    pub fn get_policy(&self, policy_id: &str) -> Option<&InsurancePolicy> {
        self.policies.get(policy_id)
    }

    /// Look up a claim by ID.
    pub fn get_claim(&self, claim_id: &str) -> Option<&InsuranceClaim> {
        self.claims.get(claim_id)
    }

    /// Get a mutable reference to a claim.
    pub fn get_claim_mut(&mut self, claim_id: &str) -> Option<&mut InsuranceClaim> {
        self.claims.get_mut(claim_id)
    }

    /// Apply an insurance-related finance event to update the projection.
    ///
    /// This is the core fold function — must be deterministic and pure.
    pub fn apply(&mut self, event: &FinanceEventKind, timestamp: DateTime<Utc>) {
        match event {
            FinanceEventKind::PolicyIssued {
                policy_id,
                agent_id,
                coverage_micro_usd,
                premium_micro_usd,
                provider_id,
                ..
            } => {
                self.last_event_at = Some(timestamp);
                self.active_policies += 1;

                self.policies_by_agent
                    .entry(agent_id.clone())
                    .or_default()
                    .push(policy_id.clone());

                // Update pool if pool-backed.
                if let Some(ref mut pool) = self.pool
                    && &pool.pool_id == provider_id
                {
                    pool.active_policies += 1;
                    pool.total_coverage_outstanding_micro_usd += coverage_micro_usd;
                    self.update_pool_ratios();
                }

                // Premium is collected at issuance.
                self.total_premiums_collected += premium_micro_usd;
            }

            FinanceEventKind::PremiumCollected {
                amount_micro_usd,
                commission_micro_usd,
                ..
            } => {
                self.last_event_at = Some(timestamp);
                // Commission earned by marketplace.
                self.total_commission_earned += commission_micro_usd;
                // Remaining premium goes to pool/provider reserves.
                let net_to_pool = amount_micro_usd - commission_micro_usd;
                if let Some(ref mut pool) = self.pool {
                    pool.reserves_micro_usd += net_to_pool;
                    pool.total_contributions_micro_usd += net_to_pool;
                    self.update_pool_ratios();
                }
            }

            FinanceEventKind::ClaimSubmitted { agent_id, .. } => {
                self.last_event_at = Some(timestamp);
                self.claims_submitted += 1;

                let history = self.agent_claims.entry(agent_id.clone()).or_default();
                history.total_claims += 1;
            }

            FinanceEventKind::ClaimVerified {
                claim_id,
                incident_confirmed,
                ..
            } => {
                self.last_event_at = Some(timestamp);
                if *incident_confirmed {
                    self.claims_approved += 1;
                    // Update stored claim status.
                    if let Some(claim) = self.claims.get_mut(claim_id) {
                        claim.status = ClaimStatus::Approved;
                    }
                } else {
                    self.claims_under_review += 1;
                    if let Some(claim) = self.claims.get_mut(claim_id) {
                        claim.status = ClaimStatus::UnderReview;
                    }
                }
            }

            FinanceEventKind::ClaimPaid {
                claim_id,
                agent_id,
                payout_micro_usd,
                ..
            } => {
                self.last_event_at = Some(timestamp);
                self.claims_paid += 1;
                self.total_claims_paid += payout_micro_usd;

                let history = self.agent_claims.entry(agent_id.clone()).or_default();
                history.approved_claims += 1;
                history.total_payout_micro_usd += payout_micro_usd;

                // Update stored claim and policy.
                if let Some(claim) = self.claims.get_mut(claim_id) {
                    claim.status = ClaimStatus::Paid;
                    claim.approved_amount_micro_usd = Some(*payout_micro_usd);
                    claim.resolved_at = Some(timestamp);

                    // Update the policy's claims tracking.
                    if let Some(policy) = self.policies.get_mut(&claim.policy_id) {
                        policy.claims_paid_micro_usd += payout_micro_usd;
                        policy.claims_count += 1;
                        // Exhaust policy if coverage limit reached.
                        if policy.claims_paid_micro_usd >= policy.coverage_limit_micro_usd {
                            policy.status = PolicyStatus::Exhausted;
                        }
                    }
                }
            }

            FinanceEventKind::ClaimDenied {
                claim_id, reason, ..
            } => {
                self.last_event_at = Some(timestamp);
                self.claims_denied += 1;
                if let Some(claim) = self.claims.get_mut(claim_id) {
                    claim.status = ClaimStatus::Denied;
                    claim.resolution_notes = Some(reason.clone());
                    claim.resolved_at = Some(timestamp);
                }
            }

            FinanceEventKind::PoolContribution {
                amount_micro_usd, ..
            } => {
                self.last_event_at = Some(timestamp);
                if let Some(ref mut pool) = self.pool {
                    pool.reserves_micro_usd += amount_micro_usd;
                    pool.total_contributions_micro_usd += amount_micro_usd;
                    self.update_pool_ratios();
                }
            }

            FinanceEventKind::PoolPayout {
                amount_micro_usd,
                reserves_after_micro_usd,
                ..
            } => {
                self.last_event_at = Some(timestamp);
                if let Some(ref mut pool) = self.pool {
                    pool.reserves_micro_usd = *reserves_after_micro_usd;
                    pool.total_payouts_micro_usd += amount_micro_usd;
                    self.update_pool_ratios();
                }
            }

            FinanceEventKind::RiskAssessed { .. } => {
                self.last_event_at = Some(timestamp);
                // Risk assessments are informational — no state change needed.
            }

            // Non-insurance events — ignore.
            _ => {}
        }
    }

    /// Update pool reserve ratio and status.
    fn update_pool_ratios(&mut self) {
        if let Some(ref mut pool) = self.pool {
            pool.reserve_ratio = if pool.total_coverage_outstanding_micro_usd > 0 {
                pool.reserves_micro_usd as f64 / pool.total_coverage_outstanding_micro_usd as f64
            } else {
                1.0
            };

            if pool.reserve_ratio < pool.min_reserve_ratio && pool.status == PoolStatus::Active {
                pool.status = PoolStatus::Paused;
            } else if pool.reserve_ratio >= pool.min_reserve_ratio
                && pool.status == PoolStatus::Paused
            {
                pool.status = PoolStatus::Active;
            }
        }
    }

    /// Generate the insurance marketplace dashboard.
    pub fn dashboard(&self) -> InsuranceDashboard {
        let (pool_reserves, pool_ratio, pool_status) = match &self.pool {
            Some(pool) => (pool.reserves_micro_usd, pool.reserve_ratio, pool.status),
            None => (0, 0.0, PoolStatus::Active),
        };

        let loss_ratio = if self.total_premiums_collected > 0 {
            self.total_claims_paid as f64 / self.total_premiums_collected as f64
        } else {
            0.0
        };

        InsuranceDashboard {
            total_products: self.products.len(),
            active_policies: self.active_policies,
            total_premiums_collected_micro_usd: self.total_premiums_collected,
            total_commission_earned_micro_usd: self.total_commission_earned,
            total_claims_filed: self.claims_submitted,
            total_claims_paid_micro_usd: self.total_claims_paid,
            pool_reserves_micro_usd: pool_reserves,
            pool_reserve_ratio: pool_ratio,
            pool_status,
            loss_ratio,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state_with_pool() -> InsuranceState {
        let pool = haima_core::marketplace::create_pool("pool-1", "Test Pool", 250);
        let products = haima_core::marketplace::default_products("pool-1");
        let provider = haima_core::marketplace::default_pool_provider("pool-1");

        let mut state = InsuranceState {
            pool: Some(pool),
            ..Default::default()
        };
        for p in products {
            state.products.insert(p.product_id.clone(), p);
        }
        state
            .providers
            .insert(provider.provider_id.clone(), provider);
        state
    }

    #[test]
    fn policy_issued_updates_state() {
        let mut state = make_state_with_pool();
        let now = Utc::now();

        state.apply(
            &FinanceEventKind::PolicyIssued {
                policy_id: "pol-1".into(),
                agent_id: "agent-1".into(),
                product_type: "task_failure".into(),
                coverage_micro_usd: 5_000_000,
                premium_micro_usd: 50_000,
                provider_id: "pool-1".into(),
            },
            now,
        );

        assert_eq!(state.active_policies, 1);
        assert_eq!(state.total_premiums_collected, 50_000);
        assert_eq!(state.policies_by_agent.get("agent-1").unwrap().len(), 1);
        assert_eq!(
            state
                .pool
                .as_ref()
                .unwrap()
                .total_coverage_outstanding_micro_usd,
            5_000_000
        );
    }

    #[test]
    fn premium_collected_splits_commission() {
        let mut state = make_state_with_pool();
        let now = Utc::now();

        state.apply(
            &FinanceEventKind::PremiumCollected {
                policy_id: "pol-1".into(),
                agent_id: "agent-1".into(),
                amount_micro_usd: 100_000,
                commission_micro_usd: 15_000, // 15% commission
            },
            now,
        );

        assert_eq!(state.total_commission_earned, 15_000);
        // Net to pool: 100k - 15k = 85k
        assert_eq!(state.pool.as_ref().unwrap().reserves_micro_usd, 85_000);
    }

    #[test]
    fn claim_lifecycle() {
        let mut state = make_state_with_pool();
        let now = Utc::now();

        // Submit
        state.apply(
            &FinanceEventKind::ClaimSubmitted {
                claim_id: "claim-1".into(),
                policy_id: "pol-1".into(),
                agent_id: "agent-1".into(),
                incident_type: "task_failure".into(),
                claimed_amount_micro_usd: 1_000_000,
            },
            now,
        );
        assert_eq!(state.claims_submitted, 1);
        assert_eq!(state.agent_claims.get("agent-1").unwrap().total_claims, 1);

        // Verify (confirmed)
        state.apply(
            &FinanceEventKind::ClaimVerified {
                claim_id: "claim-1".into(),
                policy_id: "pol-1".into(),
                incident_confirmed: true,
                confidence: 0.95,
                evidence_events_validated: 3,
            },
            now,
        );
        assert_eq!(state.claims_approved, 1);

        // Pay
        state.apply(
            &FinanceEventKind::ClaimPaid {
                claim_id: "claim-1".into(),
                policy_id: "pol-1".into(),
                agent_id: "agent-1".into(),
                payout_micro_usd: 900_000,
                source: "pool-1".into(),
            },
            now,
        );
        assert_eq!(state.claims_paid, 1);
        assert_eq!(state.total_claims_paid, 900_000);
        assert_eq!(
            state.agent_claims.get("agent-1").unwrap().approved_claims,
            1
        );
    }

    #[test]
    fn pool_contribution() {
        let mut state = make_state_with_pool();
        state.apply(
            &FinanceEventKind::PoolContribution {
                pool_id: "pool-1".into(),
                agent_id: "agent-1".into(),
                amount_micro_usd: 10_000_000,
            },
            Utc::now(),
        );
        assert_eq!(state.pool.as_ref().unwrap().reserves_micro_usd, 10_000_000);
    }

    #[test]
    fn pool_payout_updates_reserves() {
        let mut state = make_state_with_pool();
        // First contribute
        state.apply(
            &FinanceEventKind::PoolContribution {
                pool_id: "pool-1".into(),
                agent_id: "agent-1".into(),
                amount_micro_usd: 10_000_000,
            },
            Utc::now(),
        );
        // Then payout
        state.apply(
            &FinanceEventKind::PoolPayout {
                pool_id: "pool-1".into(),
                claim_id: "claim-1".into(),
                amount_micro_usd: 2_000_000,
                reserves_after_micro_usd: 8_000_000,
            },
            Utc::now(),
        );
        assert_eq!(state.pool.as_ref().unwrap().reserves_micro_usd, 8_000_000);
        assert_eq!(
            state.pool.as_ref().unwrap().total_payouts_micro_usd,
            2_000_000
        );
    }

    #[test]
    fn dashboard_computes_loss_ratio() {
        let mut state = make_state_with_pool();
        let _now = Utc::now();

        // Collect premiums
        state.total_premiums_collected = 1_000_000;
        // Pay claims
        state.total_claims_paid = 300_000;

        let dashboard = state.dashboard();
        assert!((dashboard.loss_ratio - 0.3).abs() < 0.01);
    }

    #[test]
    fn non_insurance_events_ignored() {
        let mut state = InsuranceState::default();
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
        assert!(state.last_event_at.is_none());
        assert_eq!(state.active_policies, 0);
    }
}

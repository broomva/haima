//! Insurance types for the agent insurance facilitation marketplace.
//!
//! Defines insurance products, policies, claims, and risk assessment types
//! that enable agents to purchase coverage against task failures, financial
//! errors, data breaches, and SLA penalties.
//!
//! # Insurance Products
//!
//! | Product            | Covers                                   |
//! |--------------------|------------------------------------------|
//! | Task Failure       | Customer losses from failed agent tasks   |
//! | Financial Error    | Erroneous payments/transactions           |
//! | Data Breach        | Agent-caused data exposure                |
//! | SLA Penalty        | SLA breach penalties                      |
//!
//! # Revenue Model
//!
//! - Facilitation commission: 10-20% of premiums
//! - Risk data licensing: anonymized risk data to insurers
//! - Self-insurance pool management fee: 2-3% of pool AUM

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::bureau::RiskRating;
use crate::credit::CreditTier;

// ---------------------------------------------------------------------------
// Insurance Products
// ---------------------------------------------------------------------------

/// The category of insurance coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceProductType {
    /// Covers customer losses from failed agent tasks.
    TaskFailure,
    /// Covers erroneous payments or transactions.
    FinancialError,
    /// Covers agent-caused data exposure incidents.
    DataBreach,
    /// Covers SLA breach penalties.
    SlaPenalty,
}

impl std::fmt::Display for InsuranceProductType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TaskFailure => write!(f, "task_failure"),
            Self::FinancialError => write!(f, "financial_error"),
            Self::DataBreach => write!(f, "data_breach"),
            Self::SlaPenalty => write!(f, "sla_penalty"),
        }
    }
}

/// An insurance product definition offered on the marketplace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsuranceProduct {
    /// Unique product identifier.
    pub product_id: String,
    /// Type of coverage.
    pub product_type: InsuranceProductType,
    /// Human-readable product name.
    pub name: String,
    /// Detailed description of coverage.
    pub description: String,
    /// Base premium rate in basis points per coverage unit per period.
    pub base_rate_bps: u32,
    /// Minimum coverage in micro-USD.
    pub min_coverage_micro_usd: i64,
    /// Maximum coverage in micro-USD.
    pub max_coverage_micro_usd: i64,
    /// Default deductible in micro-USD.
    pub default_deductible_micro_usd: i64,
    /// Coverage period in seconds.
    pub period_secs: u64,
    /// Minimum trust tier required to purchase.
    pub min_trust_tier: InsuranceTrustTier,
    /// Provider offering this product (network pool or external insurer).
    pub provider_id: String,
    /// Whether the product is currently available.
    pub active: bool,
}

/// Trust tier mapping for insurance eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceTrustTier {
    /// Any agent can purchase.
    Any,
    /// Must be at least Provisional trust.
    Provisional,
    /// Must be at least Trusted.
    Trusted,
    /// Must be Certified.
    Certified,
}

impl std::fmt::Display for InsuranceTrustTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Provisional => write!(f, "provisional"),
            Self::Trusted => write!(f, "trusted"),
            Self::Certified => write!(f, "certified"),
        }
    }
}

// ---------------------------------------------------------------------------
// Insurance Policies
// ---------------------------------------------------------------------------

/// An active insurance policy bound to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsurancePolicy {
    /// Unique policy identifier.
    pub policy_id: String,
    /// The insured agent.
    pub agent_id: String,
    /// Product this policy is based on.
    pub product_id: String,
    /// Type of coverage.
    pub product_type: InsuranceProductType,
    /// Coverage limit in micro-USD.
    pub coverage_limit_micro_usd: i64,
    /// Deductible in micro-USD.
    pub deductible_micro_usd: i64,
    /// Premium paid per period in micro-USD.
    pub premium_micro_usd: i64,
    /// Policy status.
    pub status: PolicyStatus,
    /// Coverage start.
    pub effective_from: DateTime<Utc>,
    /// Coverage end.
    pub effective_until: DateTime<Utc>,
    /// Total claims paid out under this policy.
    pub claims_paid_micro_usd: i64,
    /// Number of claims filed.
    pub claims_count: u32,
    /// Provider (pool or external insurer).
    pub provider_id: String,
    /// When the policy was issued.
    pub issued_at: DateTime<Utc>,
}

/// Policy lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    /// Policy is active and claims can be filed.
    Active,
    /// Policy has expired.
    Expired,
    /// Policy was cancelled.
    Cancelled,
    /// Policy is suspended (pending investigation).
    Suspended,
    /// Coverage limit exhausted.
    Exhausted,
}

impl std::fmt::Display for PolicyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Expired => write!(f, "expired"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Suspended => write!(f, "suspended"),
            Self::Exhausted => write!(f, "exhausted"),
        }
    }
}

// ---------------------------------------------------------------------------
// Risk Assessment
// ---------------------------------------------------------------------------

/// A risk assessment for an agent, used for underwriting and pricing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// The agent being assessed.
    pub agent_id: String,
    /// Overall risk score (0.0 = lowest risk, 1.0 = highest risk).
    pub risk_score: f64,
    /// Risk rating derived from score.
    pub risk_rating: RiskRating,
    /// Credit tier from Haima.
    pub credit_tier: CreditTier,
    /// Trust score from Autonomic (0.0 - 1.0).
    pub trust_score: f64,
    /// Component scores contributing to the risk assessment.
    pub components: RiskComponents,
    /// Premium multiplier based on risk (1.0 = base rate).
    pub premium_multiplier: f64,
    /// Whether the agent is insurable at all.
    pub insurable: bool,
    /// Reason if not insurable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    /// When this assessment was computed.
    pub assessed_at: DateTime<Utc>,
}

/// Component scores for risk assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskComponents {
    /// Operational reliability (uptime, error rate). 0.0 = risky, 1.0 = reliable.
    pub operational_reliability: f64,
    /// Payment history reliability. 0.0 = bad history, 1.0 = perfect.
    pub payment_reliability: f64,
    /// Economic stability (balance, burn rate). 0.0 = unstable, 1.0 = stable.
    pub economic_stability: f64,
    /// Task completion rate. 0.0 = never completes, 1.0 = always completes.
    pub task_completion_rate: f64,
    /// Account maturity factor. 0.0 = brand new, 1.0 = mature.
    pub account_maturity: f64,
    /// Prior claims history factor. 0.0 = many claims, 1.0 = no claims.
    pub claims_history: f64,
}

impl Default for RiskComponents {
    fn default() -> Self {
        Self {
            operational_reliability: 0.5,
            payment_reliability: 0.5,
            economic_stability: 0.5,
            task_completion_rate: 0.5,
            account_maturity: 0.0,
            claims_history: 1.0, // no claims = best
        }
    }
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// A claim filed against an insurance policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsuranceClaim {
    /// Unique claim identifier.
    pub claim_id: String,
    /// Policy this claim is filed against.
    pub policy_id: String,
    /// The insured agent.
    pub agent_id: String,
    /// Type of incident.
    pub incident_type: InsuranceProductType,
    /// Claimed amount in micro-USD.
    pub claimed_amount_micro_usd: i64,
    /// Approved payout amount in micro-USD (after deductible and verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount_micro_usd: Option<i64>,
    /// Claim status.
    pub status: ClaimStatus,
    /// Description of the incident.
    pub description: String,
    /// Lago event IDs that serve as evidence for this claim.
    pub evidence_event_ids: Vec<String>,
    /// Lago session ID where the incident occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// When the incident occurred.
    pub incident_at: DateTime<Utc>,
    /// When the claim was filed.
    pub filed_at: DateTime<Utc>,
    /// When the claim was resolved (if resolved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
    /// Resolution notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_notes: Option<String>,
    /// Verification result from automated checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<ClaimVerification>,
}

/// Claim lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    /// Claim submitted, awaiting verification.
    Submitted,
    /// Automated verification in progress.
    Verifying,
    /// Claim verified and approved for payout.
    Approved,
    /// Claim denied (evidence insufficient or policy doesn't cover).
    Denied,
    /// Payout processed.
    Paid,
    /// Claim is under manual investigation.
    UnderReview,
    /// Claim was withdrawn by the claimant.
    Withdrawn,
}

impl std::fmt::Display for ClaimStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Submitted => write!(f, "submitted"),
            Self::Verifying => write!(f, "verifying"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Paid => write!(f, "paid"),
            Self::UnderReview => write!(f, "under_review"),
            Self::Withdrawn => write!(f, "withdrawn"),
        }
    }
}

/// Result of automated claim verification against Lago event history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimVerification {
    /// Whether the incident is confirmed by event evidence.
    pub incident_confirmed: bool,
    /// Number of evidence events found and validated.
    pub evidence_events_validated: u32,
    /// Total evidence events submitted.
    pub evidence_events_total: u32,
    /// Whether the claimed amount is consistent with the evidence.
    pub amount_consistent: bool,
    /// Whether the policy was active at the time of incident.
    pub policy_active_at_incident: bool,
    /// Confidence score (0.0 - 1.0) in the verification.
    pub confidence: f64,
    /// Verification notes.
    pub notes: Vec<String>,
    /// When verification was performed.
    pub verified_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Self-Insurance Pool
// ---------------------------------------------------------------------------

/// The network's self-insurance pool state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsurancePool {
    /// Unique pool identifier.
    pub pool_id: String,
    /// Pool name.
    pub name: String,
    /// Total reserves in micro-USD.
    pub reserves_micro_usd: i64,
    /// Total contributions received.
    pub total_contributions_micro_usd: i64,
    /// Total payouts made.
    pub total_payouts_micro_usd: i64,
    /// Number of active policies backed by this pool.
    pub active_policies: u32,
    /// Total coverage outstanding across all active policies.
    pub total_coverage_outstanding_micro_usd: i64,
    /// Reserve ratio: reserves / `total_coverage_outstanding`.
    pub reserve_ratio: f64,
    /// Management fee in basis points (2-3% = 200-300 bps).
    pub management_fee_bps: u32,
    /// Minimum reserve ratio before new policies are paused.
    pub min_reserve_ratio: f64,
    /// Pool status.
    pub status: PoolStatus,
    /// When the pool was created.
    pub created_at: DateTime<Utc>,
}

/// Pool operational status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    /// Accepting new policies and processing claims.
    Active,
    /// Not accepting new policies (low reserves), but honoring existing ones.
    Paused,
    /// Pool is being wound down.
    WindingDown,
}

impl std::fmt::Display for PoolStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::WindingDown => write!(f, "winding_down"),
        }
    }
}

// ---------------------------------------------------------------------------
// Marketplace
// ---------------------------------------------------------------------------

/// An insurance provider registered on the marketplace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsuranceProvider {
    /// Unique provider identifier.
    pub provider_id: String,
    /// Provider name.
    pub name: String,
    /// Provider type.
    pub provider_type: ProviderType,
    /// Product types this provider offers.
    pub offered_products: Vec<InsuranceProductType>,
    /// Commission rate the marketplace charges this provider (basis points).
    pub commission_rate_bps: u32,
    /// Whether the provider is currently active.
    pub active: bool,
    /// Provider's external API endpoint (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_endpoint: Option<String>,
    /// When the provider joined.
    pub registered_at: DateTime<Utc>,
}

/// Type of insurance provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    /// Network-owned self-insurance pool.
    SelfInsurancePool,
    /// Licensed insurer or Managing General Agent.
    LicensedInsurer,
    /// Parametric insurance provider (automated payouts).
    Parametric,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SelfInsurancePool => write!(f, "self_insurance_pool"),
            Self::LicensedInsurer => write!(f, "licensed_insurer"),
            Self::Parametric => write!(f, "parametric"),
        }
    }
}

/// A quote for insurance coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsuranceQuote {
    /// Unique quote identifier.
    pub quote_id: String,
    /// The agent requesting coverage.
    pub agent_id: String,
    /// Product being quoted.
    pub product_id: String,
    /// Product type.
    pub product_type: InsuranceProductType,
    /// Coverage amount in micro-USD.
    pub coverage_micro_usd: i64,
    /// Deductible in micro-USD.
    pub deductible_micro_usd: i64,
    /// Premium per period in micro-USD.
    pub premium_micro_usd: i64,
    /// Coverage period in seconds.
    pub period_secs: u64,
    /// Risk assessment used for pricing.
    pub risk_assessment: RiskAssessment,
    /// Provider offering this quote.
    pub provider_id: String,
    /// Quote expiry.
    pub valid_until: DateTime<Utc>,
    /// When the quote was generated.
    pub quoted_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// API Request/Response types
// ---------------------------------------------------------------------------

/// Request to get an insurance quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteRequest {
    /// The agent seeking coverage.
    pub agent_id: String,
    /// Type of coverage desired.
    pub product_type: InsuranceProductType,
    /// Desired coverage amount in micro-USD.
    pub coverage_micro_usd: i64,
    /// Optional preferred provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_provider_id: Option<String>,
}

/// Request to bind (purchase) a policy from a quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindRequest {
    /// Quote to bind.
    pub quote_id: String,
    /// The agent purchasing coverage.
    pub agent_id: String,
}

/// Request to file an insurance claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// Policy to claim against.
    pub policy_id: String,
    /// The insured agent filing the claim.
    pub agent_id: String,
    /// Type of incident.
    pub incident_type: InsuranceProductType,
    /// Claimed amount in micro-USD.
    pub claimed_amount_micro_usd: i64,
    /// Description of what happened.
    pub description: String,
    /// Lago event IDs as evidence.
    pub evidence_event_ids: Vec<String>,
    /// Session where incident occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// When the incident happened.
    pub incident_at: DateTime<Utc>,
}

/// Request to contribute to the self-insurance pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolContributionRequest {
    /// Contributor agent ID.
    pub agent_id: String,
    /// Amount to contribute in micro-USD.
    pub amount_micro_usd: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_type_serde_roundtrip() {
        let pt = InsuranceProductType::TaskFailure;
        let json = serde_json::to_string(&pt).unwrap();
        assert_eq!(json, "\"task_failure\"");
        let back: InsuranceProductType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn policy_status_display() {
        assert_eq!(PolicyStatus::Active.to_string(), "active");
        assert_eq!(PolicyStatus::Suspended.to_string(), "suspended");
    }

    #[test]
    fn claim_status_display() {
        assert_eq!(ClaimStatus::Submitted.to_string(), "submitted");
        assert_eq!(ClaimStatus::Paid.to_string(), "paid");
        assert_eq!(ClaimStatus::UnderReview.to_string(), "under_review");
    }

    #[test]
    fn provider_type_serde_roundtrip() {
        let pt = ProviderType::SelfInsurancePool;
        let json = serde_json::to_string(&pt).unwrap();
        assert_eq!(json, "\"self_insurance_pool\"");
        let back: ProviderType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn risk_components_default() {
        let rc = RiskComponents::default();
        assert_eq!(rc.claims_history, 1.0);
        assert_eq!(rc.account_maturity, 0.0);
    }

    #[test]
    fn insurance_trust_tier_ordering() {
        assert!(InsuranceTrustTier::Any < InsuranceTrustTier::Provisional);
        assert!(InsuranceTrustTier::Provisional < InsuranceTrustTier::Trusted);
        assert!(InsuranceTrustTier::Trusted < InsuranceTrustTier::Certified);
    }

    #[test]
    fn pool_status_display() {
        assert_eq!(PoolStatus::Active.to_string(), "active");
        assert_eq!(PoolStatus::WindingDown.to_string(), "winding_down");
    }
}

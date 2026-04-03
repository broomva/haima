//! Insurance marketplace — connects agents with insurance providers.
//!
//! The marketplace maintains a registry of insurance products and providers,
//! generates quotes, and binds policies. It acts as the facilitation layer
//! between agents seeking coverage and providers offering it.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use haima_core::credit::CreditScore;
use haima_core::error::{HaimaError, HaimaResult};
use haima_core::insurance::{
    BindRequest, InsurancePolicy, InsuranceProduct, InsuranceProductType, InsuranceProvider,
    InsuranceQuote, InsuranceTrustTier, PolicyStatus, ProviderType, QuoteRequest,
};

use crate::pricing::calculate_premium;
use crate::risk::{assess_risk, is_eligible_for_insurance};

/// Default facilitation commission: 15% (1500 bps).
pub const DEFAULT_COMMISSION_BPS: u32 = 1500;

/// Standard coverage period: 30 days.
const STANDARD_PERIOD_SECS: u64 = 30 * 24 * 60 * 60;

/// Quote validity: 1 hour.
const QUOTE_VALIDITY_SECS: i64 = 3600;

// ---------------------------------------------------------------------------
// Marketplace State
// ---------------------------------------------------------------------------

/// In-memory marketplace state.
#[derive(Debug, Clone, Default)]
pub struct MarketplaceState {
    /// Available insurance products.
    pub products: HashMap<String, InsuranceProduct>,
    /// Registered providers.
    pub providers: HashMap<String, InsuranceProvider>,
    /// Active quotes (keyed by `quote_id`).
    pub quotes: HashMap<String, InsuranceQuote>,
    /// Active policies (keyed by `policy_id`).
    pub policies: HashMap<String, InsurancePolicy>,
}

// ---------------------------------------------------------------------------
// Product Catalog
// ---------------------------------------------------------------------------

/// Create the default set of insurance products offered by the network pool.
pub fn create_default_products(pool_provider_id: &str) -> Vec<InsuranceProduct> {
    vec![
        InsuranceProduct {
            product_id: "ins-task-failure-v1".into(),
            product_type: InsuranceProductType::TaskFailure,
            name: "Task Failure Coverage".into(),
            description: "Covers customer losses from failed agent tasks, including \
                partial completions, incorrect outputs, and timeouts."
                .into(),
            base_rate_bps: 150,                   // 1.5%
            min_coverage_micro_usd: 100_000,      // $0.10
            max_coverage_micro_usd: 100_000_000,  // $100
            default_deductible_micro_usd: 50_000, // $0.05
            period_secs: STANDARD_PERIOD_SECS,
            min_trust_tier: InsuranceTrustTier::Any,
            provider_id: pool_provider_id.to_string(),
            active: true,
        },
        InsuranceProduct {
            product_id: "ins-financial-error-v1".into(),
            product_type: InsuranceProductType::FinancialError,
            name: "Financial Error Coverage".into(),
            description: "Covers losses from erroneous payments, incorrect transaction \
                amounts, and misrouted funds caused by agent actions."
                .into(),
            base_rate_bps: 200,                    // 2%
            min_coverage_micro_usd: 1_000_000,     // $1
            max_coverage_micro_usd: 500_000_000,   // $500
            default_deductible_micro_usd: 100_000, // $0.10
            period_secs: STANDARD_PERIOD_SECS,
            min_trust_tier: InsuranceTrustTier::Provisional,
            provider_id: pool_provider_id.to_string(),
            active: true,
        },
        InsuranceProduct {
            product_id: "ins-data-breach-v1".into(),
            product_type: InsuranceProductType::DataBreach,
            name: "Data Breach Coverage".into(),
            description: "Covers liability from agent-caused data exposure, including \
                unauthorized access, data leakage, and PII exposure."
                .into(),
            base_rate_bps: 300,                    // 3%
            min_coverage_micro_usd: 5_000_000,     // $5
            max_coverage_micro_usd: 1_000_000_000, // $1,000
            default_deductible_micro_usd: 500_000, // $0.50
            period_secs: STANDARD_PERIOD_SECS,
            min_trust_tier: InsuranceTrustTier::Trusted,
            provider_id: pool_provider_id.to_string(),
            active: true,
        },
        InsuranceProduct {
            product_id: "ins-sla-penalty-v1".into(),
            product_type: InsuranceProductType::SlaPenalty,
            name: "SLA Penalty Coverage".into(),
            description: "Covers SLA breach penalties including response time violations, \
                uptime failures, and throughput shortfalls."
                .into(),
            base_rate_bps: 100,                   // 1%
            min_coverage_micro_usd: 100_000,      // $0.10
            max_coverage_micro_usd: 50_000_000,   // $50
            default_deductible_micro_usd: 25_000, // $0.025
            period_secs: STANDARD_PERIOD_SECS,
            min_trust_tier: InsuranceTrustTier::Any,
            provider_id: pool_provider_id.to_string(),
            active: true,
        },
    ]
}

// ---------------------------------------------------------------------------
// Provider Registration
// ---------------------------------------------------------------------------

/// Register a new insurance provider on the marketplace.
pub fn register_provider(state: &mut MarketplaceState, provider: InsuranceProvider) {
    state
        .providers
        .insert(provider.provider_id.clone(), provider);
}

/// Create a default self-insurance pool provider.
pub fn create_pool_provider(provider_id: &str) -> InsuranceProvider {
    InsuranceProvider {
        provider_id: provider_id.to_string(),
        name: "Network Self-Insurance Pool".into(),
        provider_type: ProviderType::SelfInsurancePool,
        offered_products: vec![
            InsuranceProductType::TaskFailure,
            InsuranceProductType::FinancialError,
            InsuranceProductType::DataBreach,
            InsuranceProductType::SlaPenalty,
        ],
        commission_rate_bps: DEFAULT_COMMISSION_BPS,
        active: true,
        api_endpoint: None,
        registered_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Quoting
// ---------------------------------------------------------------------------

/// Generate an insurance quote for an agent.
#[allow(clippy::too_many_arguments)]
pub fn get_quote(
    state: &MarketplaceState,
    request: &QuoteRequest,
    credit_score: &CreditScore,
    trust_score: f64,
    operational_reliability: f64,
    task_completion_rate: f64,
    account_age_days: u32,
    prior_claims: u32,
    prior_claims_paid: i64,
    quote_id: &str,
) -> HaimaResult<InsuranceQuote> {
    // Find matching product.
    let product = find_product(state, &request.product_type, &request.preferred_provider_id)?;

    // Check eligibility.
    if !is_eligible_for_insurance(trust_score, credit_score.tier, product.min_trust_tier) {
        return Err(HaimaError::NotInsurable {
            reason: format!(
                "agent does not meet trust/credit requirements for {} (need {} trust tier)",
                product.name, product.min_trust_tier
            ),
        });
    }

    // Validate coverage bounds.
    if request.coverage_micro_usd < product.min_coverage_micro_usd {
        return Err(HaimaError::Protocol(format!(
            "coverage {} below minimum {}",
            request.coverage_micro_usd, product.min_coverage_micro_usd
        )));
    }
    if request.coverage_micro_usd > product.max_coverage_micro_usd {
        return Err(HaimaError::Protocol(format!(
            "coverage {} above maximum {}",
            request.coverage_micro_usd, product.max_coverage_micro_usd
        )));
    }

    // Assess risk.
    let total_coverage = state
        .policies
        .values()
        .filter(|p| p.agent_id == request.agent_id && p.status == PolicyStatus::Active)
        .map(|p| p.coverage_limit_micro_usd)
        .sum::<i64>();

    let risk_assessment = assess_risk(
        &request.agent_id,
        credit_score,
        trust_score,
        operational_reliability,
        task_completion_rate,
        account_age_days,
        prior_claims,
        prior_claims_paid,
        total_coverage,
    );

    if !risk_assessment.insurable {
        return Err(HaimaError::NotInsurable {
            reason: risk_assessment
                .denial_reason
                .unwrap_or_else(|| "agent not insurable".into()),
        });
    }

    // Calculate premium.
    let premium = calculate_premium(product, request.coverage_micro_usd, &risk_assessment);
    let now = Utc::now();

    Ok(InsuranceQuote {
        quote_id: quote_id.to_string(),
        agent_id: request.agent_id.clone(),
        product_id: product.product_id.clone(),
        product_type: product.product_type,
        coverage_micro_usd: request.coverage_micro_usd,
        deductible_micro_usd: product.default_deductible_micro_usd,
        premium_micro_usd: premium,
        period_secs: product.period_secs,
        risk_assessment,
        provider_id: product.provider_id.clone(),
        valid_until: now + Duration::seconds(QUOTE_VALIDITY_SECS),
        quoted_at: now,
    })
}

// ---------------------------------------------------------------------------
// Policy Binding
// ---------------------------------------------------------------------------

/// Bind a quote into an active policy.
pub fn bind_policy(
    state: &mut MarketplaceState,
    request: &BindRequest,
    policy_id: &str,
) -> HaimaResult<InsurancePolicy> {
    // Find and validate the quote.
    let quote = state
        .quotes
        .get(&request.quote_id)
        .ok_or_else(|| HaimaError::QuoteNotFound(request.quote_id.clone()))?;

    // Verify the quote hasn't expired.
    let now = Utc::now();
    if now > quote.valid_until {
        return Err(HaimaError::QuoteExpired {
            quote_id: request.quote_id.clone(),
        });
    }

    // Verify the agent matches.
    if quote.agent_id != request.agent_id {
        return Err(HaimaError::Protocol(format!(
            "quote {} belongs to agent {}, not {}",
            request.quote_id, quote.agent_id, request.agent_id
        )));
    }

    let policy = InsurancePolicy {
        policy_id: policy_id.to_string(),
        agent_id: quote.agent_id.clone(),
        product_id: quote.product_id.clone(),
        product_type: quote.product_type,
        coverage_limit_micro_usd: quote.coverage_micro_usd,
        deductible_micro_usd: quote.deductible_micro_usd,
        premium_micro_usd: quote.premium_micro_usd,
        status: PolicyStatus::Active,
        effective_from: now,
        effective_until: now + Duration::seconds(quote.period_secs as i64),
        claims_paid_micro_usd: 0,
        claims_count: 0,
        provider_id: quote.provider_id.clone(),
        issued_at: now,
    };

    // Remove the used quote.
    state.quotes.remove(&request.quote_id);

    // Store the policy.
    state.policies.insert(policy_id.to_string(), policy.clone());

    Ok(policy)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[allow(clippy::trivially_copy_pass_by_ref)]
fn find_product<'a>(
    state: &'a MarketplaceState,
    product_type: &InsuranceProductType,
    preferred_provider: &Option<String>,
) -> HaimaResult<&'a InsuranceProduct> {
    // If a preferred provider is specified, look for their product.
    if let Some(provider_id) = preferred_provider {
        if let Some(product) = state
            .products
            .values()
            .find(|p| p.product_type == *product_type && p.provider_id == *provider_id && p.active)
        {
            return Ok(product);
        }
    }

    // Otherwise, find any active product of this type.
    state
        .products
        .values()
        .find(|p| p.product_type == *product_type && p.active)
        .ok_or_else(|| {
            HaimaError::ProductNotFound(format!("no active product for type {product_type}"))
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pricing::calculate_commission;
    use haima_core::credit::{CreditFactors, compute_credit_score};

    fn setup_marketplace() -> MarketplaceState {
        let pool_id = "pool-main";
        let provider = create_pool_provider(pool_id);
        let products = create_default_products(pool_id);

        let mut state = MarketplaceState::default();
        register_provider(&mut state, provider);
        for product in products {
            state.products.insert(product.product_id.clone(), product);
        }
        state
    }

    fn make_credit_score() -> CreditScore {
        let factors = CreditFactors {
            trust_score: 0.8,
            payment_history: 0.9,
            transaction_volume: 5_000_000,
            account_age_days: 60,
            economic_stability: 0.8,
        };
        compute_credit_score("agent-test", &factors)
    }

    #[test]
    fn default_products_created() {
        let products = create_default_products("pool-1");
        assert_eq!(products.len(), 4);

        let types: Vec<_> = products.iter().map(|p| p.product_type).collect();
        assert!(types.contains(&InsuranceProductType::TaskFailure));
        assert!(types.contains(&InsuranceProductType::FinancialError));
        assert!(types.contains(&InsuranceProductType::DataBreach));
        assert!(types.contains(&InsuranceProductType::SlaPenalty));
    }

    #[test]
    fn get_quote_succeeds() {
        let state = setup_marketplace();
        let cs = make_credit_score();

        let request = QuoteRequest {
            agent_id: "agent-test".into(),
            product_type: InsuranceProductType::TaskFailure,
            coverage_micro_usd: 10_000_000,
            preferred_provider_id: None,
        };

        let quote = get_quote(&state, &request, &cs, 0.8, 0.9, 0.85, 60, 0, 0, "q-1").unwrap();
        assert_eq!(quote.agent_id, "agent-test");
        assert!(quote.premium_micro_usd > 0);
        assert!(quote.risk_assessment.insurable);
    }

    #[test]
    fn get_quote_rejected_low_trust() {
        let state = setup_marketplace();
        let factors = CreditFactors {
            trust_score: 0.1,
            payment_history: 0.1,
            transaction_volume: 0,
            account_age_days: 1,
            economic_stability: 0.1,
        };
        let cs = compute_credit_score("agent-bad", &factors);

        let request = QuoteRequest {
            agent_id: "agent-bad".into(),
            product_type: InsuranceProductType::DataBreach,
            coverage_micro_usd: 10_000_000,
            preferred_provider_id: None,
        };

        let result = get_quote(&state, &request, &cs, 0.1, 0.1, 0.1, 1, 0, 0, "q-2");
        assert!(result.is_err());
    }

    #[test]
    fn bind_policy_from_quote() {
        let mut state = setup_marketplace();
        let cs = make_credit_score();

        let request = QuoteRequest {
            agent_id: "agent-test".into(),
            product_type: InsuranceProductType::TaskFailure,
            coverage_micro_usd: 5_000_000,
            preferred_provider_id: None,
        };

        let quote = get_quote(&state, &request, &cs, 0.8, 0.9, 0.85, 60, 0, 0, "q-bind").unwrap();
        state.quotes.insert(quote.quote_id.clone(), quote);

        let bind = BindRequest {
            quote_id: "q-bind".into(),
            agent_id: "agent-test".into(),
        };

        let policy = bind_policy(&mut state, &bind, "pol-1").unwrap();
        assert_eq!(policy.status, PolicyStatus::Active);
        assert_eq!(policy.coverage_limit_micro_usd, 5_000_000);
        assert_eq!(policy.agent_id, "agent-test");
        assert!(state.policies.contains_key("pol-1"));
        assert!(!state.quotes.contains_key("q-bind")); // quote consumed
    }

    #[test]
    fn bind_expired_quote_fails() {
        let mut state = setup_marketplace();
        let cs = make_credit_score();

        let request = QuoteRequest {
            agent_id: "agent-test".into(),
            product_type: InsuranceProductType::TaskFailure,
            coverage_micro_usd: 5_000_000,
            preferred_provider_id: None,
        };

        let mut quote =
            get_quote(&state, &request, &cs, 0.8, 0.9, 0.85, 60, 0, 0, "q-expired").unwrap();
        // Backdate the quote to make it expired.
        quote.valid_until = Utc::now() - Duration::hours(1);
        state.quotes.insert(quote.quote_id.clone(), quote);

        let bind = BindRequest {
            quote_id: "q-expired".into(),
            agent_id: "agent-test".into(),
        };

        let result = bind_policy(&mut state, &bind, "pol-2");
        assert!(result.is_err());
    }

    #[test]
    fn commission_from_premium() {
        let commission = calculate_commission(100_000, DEFAULT_COMMISSION_BPS);
        // 15% of 100,000 = 15,000
        assert_eq!(commission, 15_000);
    }
}

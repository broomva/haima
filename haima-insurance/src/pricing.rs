//! Premium calculation engine for agent insurance.
//!
//! Premiums are computed as:
//!
//! ```text
//! premium = base_rate_bps * coverage * risk_multiplier * period_factor
//! ```
//!
//! Where:
//! - `base_rate_bps`: product-specific base rate in basis points
//! - `coverage`: requested coverage amount in micro-USD
//! - `risk_multiplier`: from risk assessment (0.8x for low risk, up to 2.5x for critical)
//! - `period_factor`: coverage period / standard period (30 days)

use haima_core::insurance::{InsuranceProduct, RiskAssessment};

/// Standard period for rate calculation: 30 days in seconds.
const STANDARD_PERIOD_SECS: u64 = 30 * 24 * 60 * 60;

/// Minimum premium in micro-USD (floor to ensure economic viability).
const MIN_PREMIUM_MICRO_USD: i64 = 1_000; // $0.001

/// Calculate the premium for a given product, coverage amount, and risk profile.
///
/// Returns the premium in micro-USD per coverage period.
pub fn calculate_premium(
    product: &InsuranceProduct,
    coverage_micro_usd: i64,
    risk_assessment: &RiskAssessment,
) -> i64 {
    // Base rate: basis points applied to coverage amount.
    // 1 bps = 0.01% = 0.0001
    let base_premium = (coverage_micro_usd as f64) * (product.base_rate_bps as f64 / 10_000.0);

    // Apply risk multiplier.
    let risk_adjusted = base_premium * risk_assessment.premium_multiplier;

    // Period adjustment: scale premium for non-standard periods.
    let period_factor = product.period_secs as f64 / STANDARD_PERIOD_SECS as f64;
    let period_adjusted = risk_adjusted * period_factor;

    // Floor to minimum premium.
    let premium = period_adjusted.ceil() as i64;
    premium.max(MIN_PREMIUM_MICRO_USD)
}

/// Calculate the facilitation commission from a premium.
///
/// Commission is taken from the premium and retained by the marketplace.
/// Default rate: 15% (1500 bps).
pub fn calculate_commission(premium_micro_usd: i64, commission_rate_bps: u32) -> i64 {
    ((premium_micro_usd as f64) * (commission_rate_bps as f64 / 10_000.0)).ceil() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use haima_core::bureau::RiskRating;
    use haima_core::credit::CreditTier;
    use haima_core::insurance::{InsuranceProductType, InsuranceTrustTier, RiskComponents};

    fn make_product(base_rate_bps: u32) -> InsuranceProduct {
        InsuranceProduct {
            product_id: "prod-1".into(),
            product_type: InsuranceProductType::TaskFailure,
            name: "Task Failure Insurance".into(),
            description: "Covers task failures".into(),
            base_rate_bps,
            min_coverage_micro_usd: 100_000,
            max_coverage_micro_usd: 100_000_000,
            default_deductible_micro_usd: 10_000,
            period_secs: STANDARD_PERIOD_SECS,
            min_trust_tier: InsuranceTrustTier::Any,
            provider_id: "pool-1".into(),
            active: true,
        }
    }

    fn make_assessment(multiplier: f64, rating: RiskRating) -> RiskAssessment {
        RiskAssessment {
            agent_id: "agent-1".into(),
            risk_score: 0.3,
            risk_rating: rating,
            credit_tier: CreditTier::Standard,
            trust_score: 0.7,
            components: RiskComponents::default(),
            premium_multiplier: multiplier,
            insurable: true,
            denial_reason: None,
            assessed_at: Utc::now(),
        }
    }

    #[test]
    fn basic_premium_calculation() {
        let product = make_product(100); // 1% base rate
        let assessment = make_assessment(1.0, RiskRating::Medium);
        let premium = calculate_premium(&product, 10_000_000, &assessment); // $10 coverage
        // 1% of $10 = $0.10 = 100_000 micro-USD
        assert_eq!(premium, 100_000);
    }

    #[test]
    fn low_risk_discount() {
        let product = make_product(100);
        let assessment = make_assessment(0.8, RiskRating::Low);
        let premium = calculate_premium(&product, 10_000_000, &assessment);
        // 1% of $10 * 0.8 = $0.08 = 80_000 micro-USD
        assert_eq!(premium, 80_000);
    }

    #[test]
    fn high_risk_surcharge() {
        let product = make_product(100);
        let assessment = make_assessment(1.5, RiskRating::High);
        let premium = calculate_premium(&product, 10_000_000, &assessment);
        // 1% of $10 * 1.5 = $0.15 = 150_000 micro-USD
        assert_eq!(premium, 150_000);
    }

    #[test]
    fn minimum_premium_floor() {
        let product = make_product(1); // 0.01% base rate
        let assessment = make_assessment(0.8, RiskRating::Low);
        let premium = calculate_premium(&product, 1_000, &assessment); // $0.001 coverage
        // Very small → should hit minimum floor
        assert_eq!(premium, MIN_PREMIUM_MICRO_USD);
    }

    #[test]
    fn commission_calculation() {
        let commission = calculate_commission(100_000, 1500); // 15%
        assert_eq!(commission, 15_000);
    }

    #[test]
    fn double_period_doubles_premium() {
        let mut product = make_product(100);
        let assessment = make_assessment(1.0, RiskRating::Medium);

        let base_premium = calculate_premium(&product, 10_000_000, &assessment);
        product.period_secs = STANDARD_PERIOD_SECS * 2;
        let double_premium = calculate_premium(&product, 10_000_000, &assessment);

        assert_eq!(double_premium, base_premium * 2);
    }
}

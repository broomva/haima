//! Self-insurance pool management.
//!
//! The network maintains a self-funded reserve pool for small claims.
//! This provides immediate coverage without depending on external insurers,
//! and can handle rapid payouts for verified claims.
//!
//! # Economics
//!
//! - Management fee: 2-3% of pool AUM (basis points)
//! - Minimum reserve ratio: 15% (reserves / outstanding coverage)
//! - Pool pauses new policy issuance when reserves drop below minimum

use chrono::Utc;
use haima_core::error::{HaimaError, HaimaResult};
use haima_core::insurance::{InsurancePool, PoolStatus};

/// Default management fee: 250 bps = 2.5%.
pub const DEFAULT_MANAGEMENT_FEE_BPS: u32 = 250;

/// Default minimum reserve ratio before pausing new policies.
pub const DEFAULT_MIN_RESERVE_RATIO: f64 = 0.15;

/// Create a default self-insurance pool.
pub fn create_default_pool(pool_id: &str, initial_reserves: i64) -> InsurancePool {
    let now = Utc::now();
    InsurancePool {
        pool_id: pool_id.to_string(),
        name: "Network Self-Insurance Pool".into(),
        reserves_micro_usd: initial_reserves,
        total_contributions_micro_usd: initial_reserves,
        total_payouts_micro_usd: 0,
        active_policies: 0,
        total_coverage_outstanding_micro_usd: 0,
        reserve_ratio: if initial_reserves > 0 { 1.0 } else { 0.0 },
        management_fee_bps: DEFAULT_MANAGEMENT_FEE_BPS,
        min_reserve_ratio: DEFAULT_MIN_RESERVE_RATIO,
        status: PoolStatus::Active,
        created_at: now,
    }
}

/// Process a contribution to the pool.
///
/// Returns the updated pool state.
pub fn contribute_to_pool(pool: &mut InsurancePool, amount_micro_usd: i64) -> HaimaResult<()> {
    if amount_micro_usd <= 0 {
        return Err(HaimaError::Protocol("contribution must be positive".into()));
    }

    pool.reserves_micro_usd += amount_micro_usd;
    pool.total_contributions_micro_usd += amount_micro_usd;
    update_reserve_ratio(pool);

    // Re-activate if we were paused and now meet the ratio.
    if pool.status == PoolStatus::Paused && pool.reserve_ratio >= pool.min_reserve_ratio {
        pool.status = PoolStatus::Active;
    }

    Ok(())
}

/// Process a payout from the pool for a verified claim.
///
/// Returns the actual payout amount (may be less than requested if pool is low).
pub fn process_pool_payout(pool: &mut InsurancePool, payout_micro_usd: i64) -> HaimaResult<i64> {
    if payout_micro_usd <= 0 {
        return Err(HaimaError::Protocol("payout must be positive".into()));
    }

    if pool.reserves_micro_usd < payout_micro_usd {
        return Err(HaimaError::PoolReservesInsufficient {
            needed: payout_micro_usd,
            available: pool.reserves_micro_usd,
        });
    }

    pool.reserves_micro_usd -= payout_micro_usd;
    pool.total_payouts_micro_usd += payout_micro_usd;
    update_reserve_ratio(pool);

    // Pause if reserves drop below minimum ratio.
    if pool.reserve_ratio < pool.min_reserve_ratio && pool.status == PoolStatus::Active {
        pool.status = PoolStatus::Paused;
    }

    Ok(payout_micro_usd)
}

/// Track a new policy added to the pool.
pub fn add_policy_to_pool(pool: &mut InsurancePool, coverage_micro_usd: i64) {
    pool.active_policies += 1;
    pool.total_coverage_outstanding_micro_usd += coverage_micro_usd;
    update_reserve_ratio(pool);
}

/// Track a policy removed from the pool (expired or cancelled).
pub fn remove_policy_from_pool(pool: &mut InsurancePool, coverage_micro_usd: i64) {
    pool.active_policies = pool.active_policies.saturating_sub(1);
    pool.total_coverage_outstanding_micro_usd =
        (pool.total_coverage_outstanding_micro_usd - coverage_micro_usd).max(0);
    update_reserve_ratio(pool);
}

/// Calculate the management fee for a period.
pub fn calculate_management_fee(pool: &InsurancePool) -> i64 {
    ((pool.reserves_micro_usd as f64) * (pool.management_fee_bps as f64 / 10_000.0)).ceil() as i64
}

fn update_reserve_ratio(pool: &mut InsurancePool) {
    pool.reserve_ratio = if pool.total_coverage_outstanding_micro_usd > 0 {
        pool.reserves_micro_usd as f64 / pool.total_coverage_outstanding_micro_usd as f64
    } else if pool.reserves_micro_usd > 0 {
        1.0
    } else {
        0.0
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_pool_with_initial_reserves() {
        let pool = create_default_pool("pool-1", 100_000_000);
        assert_eq!(pool.reserves_micro_usd, 100_000_000);
        assert_eq!(pool.reserve_ratio, 1.0);
        assert_eq!(pool.status, PoolStatus::Active);
    }

    #[test]
    fn contribute_increases_reserves() {
        let mut pool = create_default_pool("pool-1", 50_000_000);
        contribute_to_pool(&mut pool, 10_000_000).unwrap();
        assert_eq!(pool.reserves_micro_usd, 60_000_000);
        assert_eq!(pool.total_contributions_micro_usd, 60_000_000);
    }

    #[test]
    fn payout_decreases_reserves() {
        let mut pool = create_default_pool("pool-1", 100_000_000);
        let paid = process_pool_payout(&mut pool, 5_000_000).unwrap();
        assert_eq!(paid, 5_000_000);
        assert_eq!(pool.reserves_micro_usd, 95_000_000);
        assert_eq!(pool.total_payouts_micro_usd, 5_000_000);
    }

    #[test]
    fn payout_fails_if_insufficient() {
        let mut pool = create_default_pool("pool-1", 1_000_000);
        let result = process_pool_payout(&mut pool, 5_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn pool_pauses_when_ratio_drops() {
        let mut pool = create_default_pool("pool-1", 20_000_000);
        add_policy_to_pool(&mut pool, 100_000_000); // 20% ratio
        assert_eq!(pool.status, PoolStatus::Active);

        // Payout drops reserves below 15% threshold.
        process_pool_payout(&mut pool, 6_000_000).unwrap();
        // Now reserves = 14M, coverage = 100M → 14% < 15% minimum
        assert_eq!(pool.status, PoolStatus::Paused);
    }

    #[test]
    fn pool_reactivates_on_contribution() {
        let mut pool = create_default_pool("pool-1", 14_000_000);
        add_policy_to_pool(&mut pool, 100_000_000);
        pool.status = PoolStatus::Paused; // simulate being paused

        contribute_to_pool(&mut pool, 5_000_000).unwrap();
        // Now reserves = 19M / 100M = 19% > 15%
        assert_eq!(pool.status, PoolStatus::Active);
    }

    #[test]
    fn management_fee_calculation() {
        let pool = create_default_pool("pool-1", 100_000_000);
        let fee = calculate_management_fee(&pool);
        // 2.5% of 100M = 2.5M
        assert_eq!(fee, 2_500_000);
    }

    #[test]
    fn add_and_remove_policy() {
        let mut pool = create_default_pool("pool-1", 50_000_000);
        add_policy_to_pool(&mut pool, 10_000_000);
        assert_eq!(pool.active_policies, 1);
        assert_eq!(pool.total_coverage_outstanding_micro_usd, 10_000_000);

        remove_policy_from_pool(&mut pool, 10_000_000);
        assert_eq!(pool.active_policies, 0);
        assert_eq!(pool.total_coverage_outstanding_micro_usd, 0);
    }
}

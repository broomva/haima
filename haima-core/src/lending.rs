//! Agent micro-credit and lending service.
//!
//! Builds on top of the credit scoring model (BRO-44) to provide revolving
//! credit lines that agents can draw against and repay. Interest accrues
//! continuously based on the agent's credit tier.
//!
//! # Interest Rates by Tier
//!
//! | Tier     | APR   | BPS   |
//! |----------|-------|-------|
//! | Micro    | 15%   | 1500  |
//! | Standard | 10%   | 1000  |
//! | Premium  | 5%    | 500   |
//!
//! # Credit Line Lifecycle
//!
//! ```text
//! open_credit_line(agent_id, credit_score)
//!   → CreditLine { status: Active }
//!     → draw(amount) → DrawResult
//!     → repay(amount) → RepaymentRecord
//!     → accrue_interest() → accrued micro-USD
//!     → freeze() → CreditLine { status: Frozen }
//!     → close/default
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::credit::{CreditScore, CreditTier};

// ---------------------------------------------------------------------------
// Interest rates by tier (basis points — annual)
// ---------------------------------------------------------------------------

/// Annual interest rate for Micro tier (15% APR).
const MICRO_INTEREST_BPS: u32 = 1500;
/// Annual interest rate for Standard tier (10% APR).
const STANDARD_INTEREST_BPS: u32 = 1000;
/// Annual interest rate for Premium tier (5% APR).
const PREMIUM_INTEREST_BPS: u32 = 500;
/// Seconds in a year (365.25 days).
const SECONDS_PER_YEAR: f64 = 365.25 * 24.0 * 3600.0;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Status of a credit line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditLineStatus {
    /// Credit line is open and available for draws.
    Active,
    /// Temporarily frozen (missed payment, trust score dropped).
    Frozen,
    /// Voluntarily closed or fully repaid.
    Closed,
    /// Exceeded overdraft window — written off.
    Defaulted,
}

impl std::fmt::Display for CreditLineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Frozen => write!(f, "frozen"),
            Self::Closed => write!(f, "closed"),
            Self::Defaulted => write!(f, "defaulted"),
        }
    }
}

/// A revolving credit line for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditLine {
    /// The agent this credit line belongs to.
    pub agent_id: String,
    /// The credit tier that determined this line's parameters.
    pub tier: CreditTier,
    /// Maximum credit limit in micro-USD.
    pub limit_micro_usd: u64,
    /// How much has been drawn (outstanding principal).
    pub drawn_micro_usd: u64,
    /// Available credit (limit - drawn).
    pub available_micro_usd: u64,
    /// Annual interest rate in basis points (500 = 5%).
    pub interest_rate_bps: u32,
    /// Accrued but unpaid interest in micro-USD.
    pub accrued_interest_micro_usd: u64,
    /// When this credit line was opened.
    pub opened_at: DateTime<Utc>,
    /// When the last draw was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_draw_at: Option<DateTime<Utc>>,
    /// When interest was last accrued.
    pub last_accrual_at: DateTime<Utc>,
    /// Current status of the credit line.
    pub status: CreditLineStatus,
}

/// Request to draw against a credit line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrawRequest {
    /// The agent requesting the draw.
    pub agent_id: String,
    /// Amount to draw in micro-USD.
    pub amount_micro_usd: u64,
    /// Purpose of the draw: `task_payment`, `prepay`, `overdraft`.
    pub purpose: String,
}

/// Result of a draw attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrawResult {
    /// Whether the draw was approved.
    pub approved: bool,
    /// Amount actually drawn (may be 0 if rejected).
    pub drawn_amount: u64,
    /// New outstanding balance after draw.
    pub new_balance: u64,
    /// Remaining available credit.
    pub available: u64,
    /// Interest accrued at the time of draw.
    pub interest_accrued: u64,
    /// Reason for rejection (if not approved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Record of a repayment against a credit line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepaymentRecord {
    /// The agent making the repayment.
    pub agent_id: String,
    /// Total amount repaid in micro-USD.
    pub amount_micro_usd: u64,
    /// Portion applied to accrued interest.
    pub interest_portion: u64,
    /// Portion applied to principal.
    pub principal_portion: u64,
    /// Remaining outstanding balance after repayment.
    pub remaining_balance: u64,
    /// When the repayment was recorded.
    pub repaid_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Get the annual interest rate in basis points for a credit tier.
pub fn interest_rate_for_tier(tier: CreditTier) -> u32 {
    match tier {
        CreditTier::None => 0, // No credit line possible
        CreditTier::Micro => MICRO_INTEREST_BPS,
        CreditTier::Standard => STANDARD_INTEREST_BPS,
        CreditTier::Premium => PREMIUM_INTEREST_BPS,
    }
}

/// Open a new credit line for an agent based on their credit score.
///
/// Returns `None` if the agent's tier is `None` (no credit eligible).
pub fn open_credit_line(agent_id: &str, credit_score: &CreditScore) -> Option<CreditLine> {
    if credit_score.tier == CreditTier::None {
        return None;
    }

    let limit = credit_score.tier.spending_limit();
    let rate = interest_rate_for_tier(credit_score.tier);
    let now = Utc::now();

    Some(CreditLine {
        agent_id: agent_id.to_string(),
        tier: credit_score.tier,
        limit_micro_usd: limit,
        drawn_micro_usd: 0,
        available_micro_usd: limit,
        interest_rate_bps: rate,
        accrued_interest_micro_usd: 0,
        opened_at: now,
        last_draw_at: None,
        last_accrual_at: now,
        status: CreditLineStatus::Active,
    })
}

/// Draw against a credit line.
///
/// Accrues interest before processing the draw. Rejects if:
/// - Credit line is not `Active`
/// - Requested amount exceeds available credit
pub fn draw(credit_line: &mut CreditLine, amount: u64, purpose: &str) -> DrawResult {
    // Must be active to draw
    if credit_line.status != CreditLineStatus::Active {
        return DrawResult {
            approved: false,
            drawn_amount: 0,
            new_balance: credit_line.drawn_micro_usd,
            available: credit_line.available_micro_usd,
            interest_accrued: credit_line.accrued_interest_micro_usd,
            reason: Some(format!(
                "credit_line_not_active: status is {}",
                credit_line.status
            )),
        };
    }

    // Zero draw is a no-op
    if amount == 0 {
        return DrawResult {
            approved: true,
            drawn_amount: 0,
            new_balance: credit_line.drawn_micro_usd,
            available: credit_line.available_micro_usd,
            interest_accrued: credit_line.accrued_interest_micro_usd,
            reason: None,
        };
    }

    // Accrue interest before the draw
    let accrued = accrue_interest(credit_line);

    // Check available credit
    if amount > credit_line.available_micro_usd {
        return DrawResult {
            approved: false,
            drawn_amount: 0,
            new_balance: credit_line.drawn_micro_usd,
            available: credit_line.available_micro_usd,
            interest_accrued: credit_line.accrued_interest_micro_usd,
            reason: Some(format!(
                "insufficient_credit: requested {} but only {} available (purpose: {})",
                amount, credit_line.available_micro_usd, purpose
            )),
        };
    }

    // Execute the draw
    let now = Utc::now();
    credit_line.drawn_micro_usd += amount;
    credit_line.available_micro_usd = credit_line.limit_micro_usd - credit_line.drawn_micro_usd;
    credit_line.last_draw_at = Some(now);

    DrawResult {
        approved: true,
        drawn_amount: amount,
        new_balance: credit_line.drawn_micro_usd,
        available: credit_line.available_micro_usd,
        interest_accrued: accrued,
        reason: None,
    }
}

/// Record a repayment against a credit line.
///
/// Interest is paid first, then principal. Returns a `RepaymentRecord`.
/// If the repayment fully pays off the balance, the remaining amount is ignored
/// (no negative balance).
pub fn repay(credit_line: &mut CreditLine, amount: u64) -> RepaymentRecord {
    let now = Utc::now();

    // Accrue interest first
    accrue_interest(credit_line);

    // Apply payment: interest first, then principal
    let interest_portion = amount.min(credit_line.accrued_interest_micro_usd);
    credit_line.accrued_interest_micro_usd -= interest_portion;

    let remaining_payment = amount - interest_portion;
    let principal_portion = remaining_payment.min(credit_line.drawn_micro_usd);
    credit_line.drawn_micro_usd -= principal_portion;
    credit_line.available_micro_usd = credit_line.limit_micro_usd - credit_line.drawn_micro_usd;

    RepaymentRecord {
        agent_id: credit_line.agent_id.clone(),
        amount_micro_usd: interest_portion + principal_portion,
        interest_portion,
        principal_portion,
        remaining_balance: credit_line.drawn_micro_usd,
        repaid_at: now,
    }
}

/// Calculate and accrue interest on a credit line based on elapsed time.
///
/// Uses simple interest: `interest = principal * rate * time_fraction`.
/// Returns the amount of interest accrued in this call.
pub fn accrue_interest(credit_line: &mut CreditLine) -> u64 {
    if credit_line.drawn_micro_usd == 0 || credit_line.interest_rate_bps == 0 {
        credit_line.last_accrual_at = Utc::now();
        return 0;
    }

    let now = Utc::now();
    let elapsed_secs = (now - credit_line.last_accrual_at).num_seconds().max(0) as f64;

    if elapsed_secs <= 0.0 {
        return 0;
    }

    let time_fraction = elapsed_secs / SECONDS_PER_YEAR;
    let rate = credit_line.interest_rate_bps as f64 / 10_000.0;
    let interest = (credit_line.drawn_micro_usd as f64 * rate * time_fraction).round() as u64;

    credit_line.accrued_interest_micro_usd += interest;
    credit_line.last_accrual_at = now;

    interest
}

/// Calculate interest for a given principal, rate, and duration without mutating state.
///
/// Useful for projections and previews.
pub fn calculate_interest(principal_micro_usd: u64, interest_rate_bps: u32, seconds: u64) -> u64 {
    if principal_micro_usd == 0 || interest_rate_bps == 0 || seconds == 0 {
        return 0;
    }

    let time_fraction = seconds as f64 / SECONDS_PER_YEAR;
    let rate = interest_rate_bps as f64 / 10_000.0;
    (principal_micro_usd as f64 * rate * time_fraction).round() as u64
}

/// Freeze a credit line for risk management.
///
/// A frozen credit line cannot accept new draws but still accrues interest.
/// Returns `false` if the credit line is already `Closed` or `Defaulted`.
pub fn freeze_credit_line(credit_line: &mut CreditLine) -> bool {
    match credit_line.status {
        CreditLineStatus::Active => {
            credit_line.status = CreditLineStatus::Frozen;
            true
        }
        CreditLineStatus::Frozen => true, // already frozen, idempotent
        CreditLineStatus::Closed | CreditLineStatus::Defaulted => false,
    }
}

/// Unfreeze a previously frozen credit line, returning it to `Active`.
///
/// Returns `false` if the credit line is not in `Frozen` state.
pub fn unfreeze_credit_line(credit_line: &mut CreditLine) -> bool {
    if credit_line.status == CreditLineStatus::Frozen {
        credit_line.status = CreditLineStatus::Active;
        true
    } else {
        false
    }
}

/// Mark a credit line as defaulted.
///
/// Returns `false` if the credit line is already `Closed`.
pub fn default_credit_line(credit_line: &mut CreditLine) -> bool {
    match credit_line.status {
        CreditLineStatus::Active | CreditLineStatus::Frozen => {
            credit_line.status = CreditLineStatus::Defaulted;
            true
        }
        CreditLineStatus::Defaulted => true, // already defaulted
        CreditLineStatus::Closed => false,
    }
}

/// Close a credit line (voluntary closure).
///
/// Only succeeds if the outstanding balance (drawn + interest) is zero.
pub fn close_credit_line(credit_line: &mut CreditLine) -> bool {
    accrue_interest(credit_line);

    if credit_line.drawn_micro_usd > 0 || credit_line.accrued_interest_micro_usd > 0 {
        return false;
    }

    credit_line.status = CreditLineStatus::Closed;
    credit_line.available_micro_usd = 0;
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credit::{CreditFactors, compute_credit_score};
    use chrono::Duration;

    // -- Helper --

    fn make_credit_score(tier: CreditTier) -> CreditScore {
        let factors = match tier {
            CreditTier::None => CreditFactors::default(),
            CreditTier::Micro => CreditFactors {
                trust_score: 0.4,
                payment_history: 0.5,
                transaction_volume: 10_000,
                account_age_days: 7,
                economic_stability: 0.3,
            },
            CreditTier::Standard => CreditFactors {
                trust_score: 0.7,
                payment_history: 0.8,
                transaction_volume: 500_000,
                account_age_days: 30,
                economic_stability: 0.6,
            },
            CreditTier::Premium => CreditFactors {
                trust_score: 1.0,
                payment_history: 1.0,
                transaction_volume: 10_000_000,
                account_age_days: 90,
                economic_stability: 1.0,
            },
        };
        compute_credit_score("test-agent", &factors)
    }

    // -- Open credit line tests --

    #[test]
    fn open_credit_line_none_tier_returns_none() {
        let score = make_credit_score(CreditTier::None);
        assert!(open_credit_line("agent-none", &score).is_none());
    }

    #[test]
    fn open_credit_line_micro_tier() {
        let score = make_credit_score(CreditTier::Micro);
        let line = open_credit_line("agent-micro", &score).unwrap();
        assert_eq!(line.agent_id, "agent-micro");
        assert_eq!(line.tier, CreditTier::Micro);
        assert_eq!(line.limit_micro_usd, 1_000);
        assert_eq!(line.drawn_micro_usd, 0);
        assert_eq!(line.available_micro_usd, 1_000);
        assert_eq!(line.interest_rate_bps, MICRO_INTEREST_BPS);
        assert_eq!(line.status, CreditLineStatus::Active);
        assert!(line.last_draw_at.is_none());
    }

    #[test]
    fn open_credit_line_standard_tier() {
        let score = make_credit_score(CreditTier::Standard);
        let line = open_credit_line("agent-std", &score).unwrap();
        assert_eq!(line.tier, CreditTier::Standard);
        assert_eq!(line.limit_micro_usd, 100_000);
        assert_eq!(line.interest_rate_bps, STANDARD_INTEREST_BPS);
    }

    #[test]
    fn open_credit_line_premium_tier() {
        let score = make_credit_score(CreditTier::Premium);
        let line = open_credit_line("agent-prem", &score).unwrap();
        assert_eq!(line.tier, CreditTier::Premium);
        assert_eq!(line.limit_micro_usd, 10_000_000);
        assert_eq!(line.interest_rate_bps, PREMIUM_INTEREST_BPS);
    }

    // -- Draw tests --

    #[test]
    fn draw_within_limit_approved() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-draw", &score).unwrap();
        let result = draw(&mut line, 50_000, "task_payment");
        assert!(result.approved);
        assert_eq!(result.drawn_amount, 50_000);
        assert_eq!(result.new_balance, 50_000);
        assert_eq!(result.available, 50_000);
        assert!(result.reason.is_none());
        assert!(line.last_draw_at.is_some());
    }

    #[test]
    fn draw_exact_limit_approved() {
        let score = make_credit_score(CreditTier::Micro);
        let mut line = open_credit_line("agent-exact", &score).unwrap();
        let result = draw(&mut line, 1_000, "prepay");
        assert!(result.approved);
        assert_eq!(result.drawn_amount, 1_000);
        assert_eq!(result.new_balance, 1_000);
        assert_eq!(result.available, 0);
    }

    #[test]
    fn draw_exceeds_limit_rejected() {
        let score = make_credit_score(CreditTier::Micro);
        let mut line = open_credit_line("agent-over", &score).unwrap();
        let result = draw(&mut line, 2_000, "overdraft");
        assert!(!result.approved);
        assert_eq!(result.drawn_amount, 0);
        assert_eq!(result.new_balance, 0);
        assert_eq!(result.available, 1_000);
        assert!(result.reason.is_some());
    }

    #[test]
    fn draw_on_frozen_line_rejected() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-frozen", &score).unwrap();
        freeze_credit_line(&mut line);
        let result = draw(&mut line, 1_000, "task_payment");
        assert!(!result.approved);
        assert!(
            result
                .reason
                .as_ref()
                .unwrap()
                .contains("credit_line_not_active")
        );
    }

    #[test]
    fn draw_zero_amount_is_noop() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-zero", &score).unwrap();
        let result = draw(&mut line, 0, "task_payment");
        assert!(result.approved);
        assert_eq!(result.drawn_amount, 0);
        assert_eq!(result.new_balance, 0);
    }

    #[test]
    fn multiple_draws_reduce_available() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-multi", &score).unwrap();

        let r1 = draw(&mut line, 30_000, "task_payment");
        assert!(r1.approved);
        assert_eq!(line.available_micro_usd, 70_000);

        let r2 = draw(&mut line, 40_000, "task_payment");
        assert!(r2.approved);
        assert_eq!(line.available_micro_usd, 30_000);

        // Third draw exceeds remaining
        let r3 = draw(&mut line, 50_000, "task_payment");
        assert!(!r3.approved);
        assert_eq!(line.drawn_micro_usd, 70_000);
    }

    // -- Repay tests --

    #[test]
    fn repay_reduces_balance() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-repay", &score).unwrap();
        draw(&mut line, 50_000, "task_payment");

        let record = repay(&mut line, 20_000);
        assert_eq!(record.agent_id, "agent-repay");
        assert_eq!(record.principal_portion, 20_000);
        assert_eq!(record.remaining_balance, 30_000);
        assert_eq!(line.available_micro_usd, 70_000);
    }

    #[test]
    fn repay_full_balance_restores_available() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-full-repay", &score).unwrap();
        draw(&mut line, 50_000, "task_payment");

        let record = repay(&mut line, 50_000);
        assert_eq!(record.remaining_balance, 0);
        assert_eq!(line.drawn_micro_usd, 0);
        assert_eq!(line.available_micro_usd, 100_000);
    }

    #[test]
    fn repay_overpayment_does_not_go_negative() {
        let score = make_credit_score(CreditTier::Micro);
        let mut line = open_credit_line("agent-overpay", &score).unwrap();
        draw(&mut line, 500, "task_payment");

        // Repay more than owed
        let record = repay(&mut line, 1_000);
        // Only 500 of principal should be consumed (no interest accrued in near-zero time)
        assert_eq!(record.principal_portion, 500);
        assert_eq!(record.remaining_balance, 0);
        assert_eq!(line.drawn_micro_usd, 0);
    }

    #[test]
    fn repay_interest_first_then_principal() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-interest-first", &score).unwrap();
        draw(&mut line, 50_000, "task_payment");

        // Manually set accrued interest for testing
        line.accrued_interest_micro_usd = 100;

        let record = repay(&mut line, 150);
        // First 100 goes to interest, remaining 50 to principal
        assert_eq!(record.interest_portion, 100);
        assert_eq!(record.principal_portion, 50);
        assert_eq!(line.accrued_interest_micro_usd, 0);
        assert_eq!(line.drawn_micro_usd, 49_950);
    }

    // -- Interest accrual tests --

    #[test]
    fn accrue_interest_zero_balance_returns_zero() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-no-interest", &score).unwrap();
        let accrued = accrue_interest(&mut line);
        assert_eq!(accrued, 0);
    }

    #[test]
    fn calculate_interest_one_year() {
        // 100,000 micro-USD at 10% APR for one year = 10,000 micro-USD
        let interest = calculate_interest(100_000, 1000, (SECONDS_PER_YEAR) as u64);
        assert_eq!(interest, 10_000);
    }

    #[test]
    fn calculate_interest_half_year() {
        // 100,000 micro-USD at 10% APR for half year = 5,000 micro-USD
        let half_year_secs = (SECONDS_PER_YEAR / 2.0) as u64;
        let interest = calculate_interest(100_000, 1000, half_year_secs);
        assert_eq!(interest, 5_000);
    }

    #[test]
    fn calculate_interest_zero_principal() {
        assert_eq!(calculate_interest(0, 1000, 86400), 0);
    }

    #[test]
    fn calculate_interest_zero_rate() {
        assert_eq!(calculate_interest(100_000, 0, 86400), 0);
    }

    #[test]
    fn calculate_interest_zero_duration() {
        assert_eq!(calculate_interest(100_000, 1000, 0), 0);
    }

    #[test]
    fn accrue_interest_with_drawn_balance() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-accrue", &score).unwrap();
        draw(&mut line, 50_000, "task_payment");

        // Manually backdate the last accrual to simulate time passing
        line.last_accrual_at = Utc::now() - Duration::days(365);

        let accrued = accrue_interest(&mut line);
        // 50,000 * 10% = 5,000 (approximately, due to slight time differences)
        assert!(
            (4_900..=5_100).contains(&accrued),
            "expected ~5000, got {}",
            accrued
        );
        assert_eq!(line.accrued_interest_micro_usd, accrued);
    }

    #[test]
    fn interest_rates_by_tier() {
        assert_eq!(interest_rate_for_tier(CreditTier::None), 0);
        assert_eq!(interest_rate_for_tier(CreditTier::Micro), 1500);
        assert_eq!(interest_rate_for_tier(CreditTier::Standard), 1000);
        assert_eq!(interest_rate_for_tier(CreditTier::Premium), 500);
    }

    // -- Freeze/unfreeze tests --

    #[test]
    fn freeze_active_line_succeeds() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-freeze", &score).unwrap();
        assert!(freeze_credit_line(&mut line));
        assert_eq!(line.status, CreditLineStatus::Frozen);
    }

    #[test]
    fn freeze_frozen_line_is_idempotent() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-idem", &score).unwrap();
        freeze_credit_line(&mut line);
        assert!(freeze_credit_line(&mut line)); // idempotent
        assert_eq!(line.status, CreditLineStatus::Frozen);
    }

    #[test]
    fn freeze_closed_line_fails() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-closed", &score).unwrap();
        close_credit_line(&mut line);
        assert!(!freeze_credit_line(&mut line));
    }

    #[test]
    fn unfreeze_frozen_line_succeeds() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-unfreeze", &score).unwrap();
        freeze_credit_line(&mut line);
        assert!(unfreeze_credit_line(&mut line));
        assert_eq!(line.status, CreditLineStatus::Active);
    }

    #[test]
    fn unfreeze_active_line_fails() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-active", &score).unwrap();
        assert!(!unfreeze_credit_line(&mut line));
    }

    // -- Default tests --

    #[test]
    fn default_active_line_succeeds() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-default", &score).unwrap();
        draw(&mut line, 50_000, "overdraft");
        assert!(default_credit_line(&mut line));
        assert_eq!(line.status, CreditLineStatus::Defaulted);
    }

    #[test]
    fn default_frozen_line_succeeds() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-default-frozen", &score).unwrap();
        freeze_credit_line(&mut line);
        assert!(default_credit_line(&mut line));
        assert_eq!(line.status, CreditLineStatus::Defaulted);
    }

    #[test]
    fn default_closed_line_fails() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-default-closed", &score).unwrap();
        close_credit_line(&mut line);
        assert!(!default_credit_line(&mut line));
    }

    #[test]
    fn draw_on_defaulted_line_rejected() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-draw-default", &score).unwrap();
        default_credit_line(&mut line);
        let result = draw(&mut line, 1_000, "task_payment");
        assert!(!result.approved);
    }

    // -- Close tests --

    #[test]
    fn close_zero_balance_succeeds() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-close", &score).unwrap();
        assert!(close_credit_line(&mut line));
        assert_eq!(line.status, CreditLineStatus::Closed);
        assert_eq!(line.available_micro_usd, 0);
    }

    #[test]
    fn close_with_balance_fails() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-close-bal", &score).unwrap();
        draw(&mut line, 10_000, "task_payment");
        assert!(!close_credit_line(&mut line));
        // Status should remain active
        assert_eq!(line.status, CreditLineStatus::Active);
    }

    // -- Full lifecycle test --

    #[test]
    fn full_draw_repay_close_lifecycle() {
        let score = make_credit_score(CreditTier::Standard);
        let mut line = open_credit_line("agent-lifecycle", &score).unwrap();
        assert_eq!(line.status, CreditLineStatus::Active);

        // Draw
        let r1 = draw(&mut line, 30_000, "task_payment");
        assert!(r1.approved);
        assert_eq!(line.drawn_micro_usd, 30_000);

        // Partial repay
        let r2 = repay(&mut line, 10_000);
        assert_eq!(r2.remaining_balance, 20_000);

        // Full repay
        let r3 = repay(&mut line, 20_000);
        assert_eq!(r3.remaining_balance, 0);

        // Close
        assert!(close_credit_line(&mut line));
        assert_eq!(line.status, CreditLineStatus::Closed);
    }

    // -- Serde roundtrip tests --

    #[test]
    fn credit_line_serde_roundtrip() {
        let score = make_credit_score(CreditTier::Standard);
        let line = open_credit_line("agent-serde", &score).unwrap();
        let json = serde_json::to_string(&line).unwrap();
        let back: CreditLine = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_id, "agent-serde");
        assert_eq!(back.tier, CreditTier::Standard);
        assert_eq!(back.status, CreditLineStatus::Active);
    }

    #[test]
    fn draw_result_serde_roundtrip() {
        let result = DrawResult {
            approved: true,
            drawn_amount: 5_000,
            new_balance: 5_000,
            available: 95_000,
            interest_accrued: 0,
            reason: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: DrawResult = serde_json::from_str(&json).unwrap();
        assert!(back.approved);
        assert_eq!(back.drawn_amount, 5_000);
        assert!(back.reason.is_none());
    }

    #[test]
    fn repayment_record_serde_roundtrip() {
        let record = RepaymentRecord {
            agent_id: "agent-serde".into(),
            amount_micro_usd: 10_000,
            interest_portion: 500,
            principal_portion: 9_500,
            remaining_balance: 40_000,
            repaid_at: Utc::now(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: RepaymentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.interest_portion, 500);
        assert_eq!(back.principal_portion, 9_500);
    }

    #[test]
    fn credit_line_status_serde_roundtrip() {
        for status in [
            CreditLineStatus::Active,
            CreditLineStatus::Frozen,
            CreditLineStatus::Closed,
            CreditLineStatus::Defaulted,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: CreditLineStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn credit_line_status_display() {
        assert_eq!(CreditLineStatus::Active.to_string(), "active");
        assert_eq!(CreditLineStatus::Frozen.to_string(), "frozen");
        assert_eq!(CreditLineStatus::Closed.to_string(), "closed");
        assert_eq!(CreditLineStatus::Defaulted.to_string(), "defaulted");
    }
}

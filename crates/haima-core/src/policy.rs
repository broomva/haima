//! Payment policy — rules governing when payments are auto-approved,
//! require human approval, or are denied outright.

use serde::{Deserialize, Serialize};

/// Payment authorization policy.
///
/// The agent consults this policy before signing any payment.
/// Amounts are in micro-credits (1 USDC = 1,000,000 micro-credits).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPolicy {
    /// Maximum auto-approve amount per transaction (micro-credits).
    /// Payments at or below this threshold are approved automatically.
    /// Default: 100 micro-credits ($0.0001).
    pub auto_approve_cap: i64,

    /// Maximum amount that can be approved with human confirmation (micro-credits).
    /// Payments above this are always denied.
    /// Default: 1,000,000 micro-credits ($1.00).
    pub hard_cap_per_tx: i64,

    /// Maximum total spend per session (micro-credits).
    /// Default: 10,000,000 micro-credits ($10.00).
    pub session_spend_cap: i64,

    /// Maximum transactions per minute (rate limiting).
    /// Default: 10.
    pub max_tx_per_minute: u32,

    /// Whether payments are enabled at all.
    /// Default: true.
    pub enabled: bool,

    /// Whether to allow payments in Hibernate economic mode.
    /// Default: false.
    pub allow_in_hibernate: bool,

    /// Whether to allow payments in Hustle economic mode.
    /// Default: true (but only auto-approve, not large amounts).
    pub allow_in_hustle: bool,
}

impl Default for PaymentPolicy {
    fn default() -> Self {
        Self {
            auto_approve_cap: 100,             // $0.0001
            hard_cap_per_tx: 1_000_000,        // $1.00
            session_spend_cap: 10_000_000,     // $10.00
            max_tx_per_minute: 10,
            enabled: true,
            allow_in_hibernate: false,
            allow_in_hustle: true,
        }
    }
}

impl PaymentPolicy {
    /// Evaluate whether a payment amount should be auto-approved, require
    /// human approval, or be denied.
    pub fn evaluate(&self, micro_credits: i64) -> PolicyVerdict {
        if !self.enabled {
            return PolicyVerdict::Denied("payments disabled by policy".into());
        }
        if micro_credits > self.hard_cap_per_tx {
            return PolicyVerdict::Denied(format!(
                "amount {micro_credits} exceeds hard cap {}",
                self.hard_cap_per_tx
            ));
        }
        if micro_credits <= self.auto_approve_cap {
            return PolicyVerdict::AutoApproved;
        }
        PolicyVerdict::RequiresApproval
    }
}

/// Result of policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// Payment is small enough to auto-approve.
    AutoApproved,
    /// Payment needs human confirmation via ApprovalPort.
    RequiresApproval,
    /// Payment is denied by policy.
    Denied(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy() {
        let policy = PaymentPolicy::default();
        assert_eq!(policy.auto_approve_cap, 100);
        assert_eq!(policy.hard_cap_per_tx, 1_000_000);
        assert!(policy.enabled);
    }

    #[test]
    fn auto_approve_small_amount() {
        let policy = PaymentPolicy::default();
        assert_eq!(policy.evaluate(50), PolicyVerdict::AutoApproved);
        assert_eq!(policy.evaluate(100), PolicyVerdict::AutoApproved);
    }

    #[test]
    fn require_approval_medium_amount() {
        let policy = PaymentPolicy::default();
        assert_eq!(policy.evaluate(101), PolicyVerdict::RequiresApproval);
        assert_eq!(policy.evaluate(500_000), PolicyVerdict::RequiresApproval);
    }

    #[test]
    fn deny_large_amount() {
        let policy = PaymentPolicy::default();
        let verdict = policy.evaluate(2_000_000);
        assert!(matches!(verdict, PolicyVerdict::Denied(_)));
    }

    #[test]
    fn deny_when_disabled() {
        let policy = PaymentPolicy {
            enabled: false,
            ..Default::default()
        };
        let verdict = policy.evaluate(1);
        assert!(matches!(verdict, PolicyVerdict::Denied(_)));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = PaymentPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: PaymentPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.auto_approve_cap, policy.auto_approve_cap);
    }
}

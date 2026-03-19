//! x402 client — intercepts 402 responses and handles payment flow.

use haima_core::HaimaResult;
use haima_core::payment::PaymentDecision;
use haima_core::policy::{PaymentPolicy, PolicyVerdict};
use haima_core::wallet::WalletAddress;
use haima_wallet::backend::WalletBackend;
use std::sync::Arc;
use tracing::warn;

use crate::facilitator::Facilitator;

/// x402 payment client that wraps HTTP requests with automatic 402 handling.
pub struct X402Client {
    wallet: Arc<dyn WalletBackend>,
    _facilitator: Facilitator,
    policy: PaymentPolicy,
}

impl X402Client {
    pub fn new(
        wallet: Arc<dyn WalletBackend>,
        facilitator: Facilitator,
        policy: PaymentPolicy,
    ) -> Self {
        Self {
            wallet,
            _facilitator: facilitator,
            policy,
        }
    }

    /// Evaluate a payment request against the configured policy.
    pub fn evaluate(&self, micro_credit_cost: i64) -> PaymentDecision {
        match self.policy.evaluate(micro_credit_cost) {
            PolicyVerdict::AutoApproved => PaymentDecision::Approved {
                payer: self.wallet.address().clone(),
                micro_credit_cost,
                reason: "within auto-approve threshold".into(),
            },
            PolicyVerdict::RequiresApproval => PaymentDecision::RequiresApproval {
                micro_credit_cost,
                reason: format!(
                    "amount {micro_credit_cost} exceeds auto-approve cap {}",
                    self.policy.auto_approve_cap
                ),
            },
            PolicyVerdict::Denied(reason) => PaymentDecision::Denied { reason },
        }
    }

    /// Process an HTTP 402 response: parse terms, evaluate policy, attempt payment.
    ///
    /// Returns `Ok(receipt)` if payment succeeds, `Err` if denied or failed.
    /// For `RequiresApproval` decisions, the caller (Arcan) should route through
    /// the `ApprovalPort` before calling `execute_payment`.
    pub async fn handle_402(
        &self,
        _resource_url: &str,
        _payment_required_header: &str,
    ) -> HaimaResult<PaymentDecision> {
        // Phase F1: Full implementation with x402-rs header parsing,
        // payment signing, and facilitator settlement.
        //
        // For now, parse the header and evaluate policy.
        // The actual signing + settlement will be wired when integrating x402-rs.
        warn!("x402 client handle_402: full flow pending x402-rs integration");
        Ok(PaymentDecision::Denied {
            reason: "x402 client not yet fully implemented — pending Phase F1".into(),
        })
    }

    pub fn wallet_address(&self) -> &WalletAddress {
        self.wallet.address()
    }

    pub fn policy(&self) -> &PaymentPolicy {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facilitator::FacilitatorConfig;
    use haima_core::wallet::ChainId;
    use haima_wallet::LocalSigner;

    fn test_client() -> X402Client {
        let signer = LocalSigner::generate(ChainId::base()).unwrap();
        let facilitator = Facilitator::new(FacilitatorConfig::default());
        X402Client::new(Arc::new(signer), facilitator, PaymentPolicy::default())
    }

    #[test]
    fn evaluate_auto_approve() {
        let client = test_client();
        let decision = client.evaluate(50);
        assert!(decision.is_approved());
    }

    #[test]
    fn evaluate_requires_approval() {
        let client = test_client();
        let decision = client.evaluate(500_000);
        assert!(matches!(decision, PaymentDecision::RequiresApproval { .. }));
    }

    #[test]
    fn evaluate_denied() {
        let client = test_client();
        let decision = client.evaluate(2_000_000);
        assert!(decision.is_denied());
    }
}

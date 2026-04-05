//! x402 client — intercepts 402 responses and handles the payment flow.
//!
//! The `X402Client` wraps an HTTP client with automatic 402 handling:
//! 1. Parse the `payment-required` header from the 402 response
//! 2. Evaluate the payment against `PaymentPolicy`
//! 3. If auto-approved, sign the payment with the `WalletBackend`
//! 4. Encode the `payment-signature` header for the retry request
//! 5. Parse the `payment-response` header from the 200 response
//!
//! For `RequiresApproval` decisions, the caller (Arcan) routes through the
//! `ApprovalPort` before calling `sign_payment` directly.

use haima_core::payment::PaymentDecision;
use haima_core::policy::{PaymentPolicy, PolicyVerdict};
use haima_core::wallet::{WalletAddress, usdc_raw_to_micro_credits};
use haima_core::{HaimaError, HaimaResult};
use haima_wallet::backend::WalletBackend;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::facilitator::{Facilitator, VerifyRequest, VerifyResponse};
use crate::header::{
    PaymentRequiredHeader, PaymentResponseHeader, PaymentSignatureHeader, SchemeRequirement,
    encode_payment_signature, parse_payment_required, parse_payment_response,
};

/// The result of processing an HTTP 402 response.
///
/// Contains the parsed payment requirement, the policy decision, and (if
/// approved) the encoded signature header ready to attach to the retry request.
#[derive(Debug, Clone)]
pub struct HandleResult {
    /// The parsed payment requirement from the 402 response.
    pub requirement: SchemeRequirement,
    /// The policy decision for this payment.
    pub decision: PaymentDecision,
    /// The encoded `payment-signature` header value (base64 JSON), if payment
    /// was signed. `None` when the decision is `RequiresApproval` or `Denied`.
    pub signature_header: Option<String>,
}

/// Settlement result after the facilitator verifies and settles a payment.
#[derive(Debug, Clone)]
pub struct SettlementResult {
    /// The transaction hash from on-chain settlement.
    pub tx_hash: String,
    /// The network where settlement occurred.
    pub network: String,
    /// Whether settlement is confirmed.
    pub settled: bool,
}

/// x402 payment client that wraps HTTP requests with automatic 402 handling.
pub struct X402Client {
    wallet: Arc<dyn WalletBackend>,
    facilitator: Facilitator,
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
            facilitator,
            policy,
        }
    }

    /// Evaluate a payment amount against the configured policy.
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

    /// Process an HTTP 402 response: parse terms, evaluate policy, sign if approved.
    ///
    /// # Flow
    /// 1. Parse the `payment-required` header (base64 JSON)
    /// 2. Select the first compatible scheme (currently: "exact" on an EVM network)
    /// 3. Convert the token amount to micro-credits for policy evaluation
    /// 4. If `AutoApproved`, sign the payment and return the encoded signature header
    /// 5. If `RequiresApproval`, return the decision without signing (caller handles approval)
    /// 6. If `Denied`, return the denial reason
    ///
    /// # Returns
    /// `HandleResult` containing the requirement, decision, and optional signature header.
    pub async fn handle_402(
        &self,
        resource_url: &str,
        payment_required_header: &str,
    ) -> HaimaResult<HandleResult> {
        // Step 1: Parse the payment-required header
        let header = parse_payment_required(payment_required_header)?;
        debug!(
            resource_url,
            version = header.version,
            schemes = header.schemes.len(),
            "parsed payment-required header"
        );

        // Step 2: Select a compatible scheme
        let requirement = select_scheme(&header)?;
        info!(
            scheme = requirement.scheme,
            network = requirement.network,
            amount = requirement.amount,
            recipient = requirement.recipient,
            "selected payment scheme"
        );

        // Step 3: Convert amount to micro-credits for policy evaluation
        let raw_amount: u64 = requirement.amount.parse().map_err(|e| {
            HaimaError::Protocol(format!("invalid amount '{}': {e}", requirement.amount))
        })?;
        let micro_credits = usdc_raw_to_micro_credits(raw_amount);

        // Step 4: Evaluate policy
        let decision = self.evaluate(micro_credits);
        debug!(?decision, micro_credits, "policy decision");

        // Step 5: Sign if auto-approved
        let signature_header = match &decision {
            PaymentDecision::Approved { .. } => {
                let sig = self.sign_payment(&requirement).await?;
                let encoded = encode_payment_signature(&sig)?;
                info!(
                    scheme = sig.scheme,
                    network = sig.network,
                    "payment signed and encoded"
                );
                Some(encoded)
            }
            PaymentDecision::RequiresApproval { .. } => {
                warn!(
                    micro_credits,
                    resource_url, "payment requires human approval"
                );
                None
            }
            PaymentDecision::Denied { reason } => {
                warn!(reason, resource_url, "payment denied by policy");
                None
            }
        };

        Ok(HandleResult {
            requirement,
            decision,
            signature_header,
        })
    }

    /// Sign a payment for a given scheme requirement.
    ///
    /// Produces a `PaymentSignatureHeader` ready for encoding and attachment
    /// to the retry request. This can be called directly when the caller
    /// has obtained human approval for a `RequiresApproval` decision.
    pub async fn sign_payment(
        &self,
        requirement: &SchemeRequirement,
    ) -> HaimaResult<PaymentSignatureHeader> {
        let raw_amount: u64 = requirement.amount.parse().map_err(|e| {
            HaimaError::Protocol(format!("invalid amount '{}': {e}", requirement.amount))
        })?;

        // Sign using EIP-191 personal sign over the payment payload.
        // The payload is: scheme | network | token | amount | recipient | facilitator
        // This is a simplified signing scheme. Full EIP-3009 transferWithAuthorization
        // would use EIP-712 typed data, but that requires the USDC contract's domain
        // separator which varies by chain. For now we sign a canonical message that
        // the facilitator can verify.
        let message = format!(
            "x402:{}:{}:{}:{}:{}:{}",
            requirement.scheme,
            requirement.network,
            requirement.token,
            raw_amount,
            requirement.recipient,
            requirement.facilitator,
        );

        let signature = self.wallet.sign_message(message.as_bytes()).await?;
        let payload = hex::encode(&signature);

        Ok(PaymentSignatureHeader {
            scheme: requirement.scheme.clone(),
            network: requirement.network.clone(),
            payload,
        })
    }

    /// Verify a signed payment through the facilitator and parse the settlement response.
    ///
    /// Called after the retry request returns HTTP 200 with a `payment-response` header,
    /// or to proactively verify through the facilitator before retrying.
    pub async fn verify_and_settle(
        &self,
        signature_header: &str,
        requirement_header: &str,
    ) -> HaimaResult<SettlementResult> {
        let verify_req = VerifyRequest {
            payment_payload: signature_header.into(),
            payment_requirements: requirement_header.into(),
        };

        let verify_resp: VerifyResponse = self.facilitator.verify(&verify_req).await?;

        if !verify_resp.valid {
            let reason = verify_resp
                .error
                .unwrap_or_else(|| "facilitator rejected payment".into());
            return Err(HaimaError::SettlementFailed(reason));
        }

        let tx_hash = verify_resp
            .tx_hash
            .ok_or_else(|| HaimaError::SettlementFailed("no tx_hash in verify response".into()))?;

        Ok(SettlementResult {
            tx_hash,
            network: String::new(), // Filled by caller from requirement
            settled: true,
        })
    }

    /// Parse a `payment-response` header from a 200 response.
    pub fn parse_settlement_response(
        &self,
        payment_response_header: &str,
    ) -> HaimaResult<PaymentResponseHeader> {
        parse_payment_response(payment_response_header)
    }

    pub fn wallet_address(&self) -> &WalletAddress {
        self.wallet.address()
    }

    pub fn policy(&self) -> &PaymentPolicy {
        &self.policy
    }

    pub fn facilitator(&self) -> &Facilitator {
        &self.facilitator
    }
}

/// Select the first compatible scheme from the payment-required header.
///
/// Currently supports only the "exact" scheme on EVM-compatible networks.
fn select_scheme(header: &PaymentRequiredHeader) -> HaimaResult<SchemeRequirement> {
    for scheme in &header.schemes {
        if scheme.scheme == "exact" && scheme.network.starts_with("eip155:") {
            return Ok(scheme.clone());
        }
    }
    Err(HaimaError::UnsupportedScheme(format!(
        "no compatible scheme found in {} options (need exact + EVM)",
        header.schemes.len()
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facilitator::FacilitatorConfig;
    use crate::header::encode_payment_required;
    use haima_core::wallet::ChainId;
    use haima_wallet::LocalSigner;

    fn test_client() -> X402Client {
        let signer = LocalSigner::generate(ChainId::base()).unwrap();
        let facilitator = Facilitator::new(FacilitatorConfig::default());
        X402Client::new(Arc::new(signer), facilitator, PaymentPolicy::default())
    }

    fn sample_requirement() -> SchemeRequirement {
        SchemeRequirement {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            amount: "50".into(), // 50 micro-credits, below auto-approve cap of 100
            recipient: "0xrecipient".into(),
            facilitator: "https://x402.org/facilitator".into(),
        }
    }

    fn sample_payment_required_header(amount: &str) -> PaymentRequiredHeader {
        PaymentRequiredHeader {
            schemes: vec![SchemeRequirement {
                scheme: "exact".into(),
                network: "eip155:8453".into(),
                token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
                amount: amount.into(),
                recipient: "0xrecipient".into(),
                facilitator: "https://x402.org/facilitator".into(),
            }],
            version: "v2".into(),
        }
    }

    // -- Policy evaluation tests --

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

    // -- handle_402 integration tests --

    #[tokio::test]
    async fn handle_402_auto_approve_signs_payment() {
        let client = test_client();
        let header = sample_payment_required_header("50");
        let encoded = encode_payment_required(&header).unwrap();

        let result = client
            .handle_402("https://api.example.com/data", &encoded)
            .await
            .unwrap();

        assert!(result.decision.is_approved());
        assert!(result.signature_header.is_some());
        assert_eq!(result.requirement.amount, "50");
        assert_eq!(result.requirement.network, "eip155:8453");
    }

    #[tokio::test]
    async fn handle_402_requires_approval_no_signature() {
        let client = test_client();
        // 500_000 micro-credits is above auto-approve cap (100) but below hard cap (1M)
        let header = sample_payment_required_header("500000");
        let encoded = encode_payment_required(&header).unwrap();

        let result = client
            .handle_402("https://api.example.com/data", &encoded)
            .await
            .unwrap();

        assert!(matches!(
            result.decision,
            PaymentDecision::RequiresApproval { .. }
        ));
        assert!(result.signature_header.is_none());
    }

    #[tokio::test]
    async fn handle_402_denied_above_hard_cap() {
        let client = test_client();
        // 2_000_000 exceeds hard cap of 1_000_000
        let header = sample_payment_required_header("2000000");
        let encoded = encode_payment_required(&header).unwrap();

        let result = client
            .handle_402("https://api.example.com/data", &encoded)
            .await
            .unwrap();

        assert!(result.decision.is_denied());
        assert!(result.signature_header.is_none());
    }

    #[tokio::test]
    async fn handle_402_invalid_header_returns_error() {
        let client = test_client();
        let result = client
            .handle_402("https://api.example.com/data", "not-valid-base64!!!")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_402_no_compatible_scheme() {
        let client = test_client();
        let header = PaymentRequiredHeader {
            schemes: vec![SchemeRequirement {
                scheme: "streaming".into(),       // Not "exact"
                network: "solana:mainnet".into(), // Not EVM
                token: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
                amount: "50".into(),
                recipient: "SoLaNaAddr".into(),
                facilitator: "https://x402.org/facilitator".into(),
            }],
            version: "v2".into(),
        };
        let encoded = encode_payment_required(&header).unwrap();

        let result = client
            .handle_402("https://api.example.com/data", &encoded)
            .await;
        assert!(result.is_err());
    }

    // -- sign_payment tests --

    #[tokio::test]
    async fn sign_payment_produces_valid_signature() {
        let client = test_client();
        let requirement = sample_requirement();

        let sig = client.sign_payment(&requirement).await.unwrap();

        assert_eq!(sig.scheme, "exact");
        assert_eq!(sig.network, "eip155:8453");
        assert!(!sig.payload.is_empty());
        // Payload should be hex-encoded
        assert!(hex::decode(&sig.payload).is_ok());
    }

    #[tokio::test]
    async fn sign_payment_roundtrip_through_header() {
        let client = test_client();
        let requirement = sample_requirement();

        let sig = client.sign_payment(&requirement).await.unwrap();
        let encoded = encode_payment_signature(&sig).unwrap();
        let decoded = crate::header::parse_payment_signature(&encoded).unwrap();

        assert_eq!(decoded, sig);
    }

    // -- select_scheme tests --

    #[test]
    fn select_scheme_prefers_exact_evm() {
        let header = PaymentRequiredHeader {
            schemes: vec![
                SchemeRequirement {
                    scheme: "streaming".into(),
                    network: "eip155:8453".into(),
                    token: "0xtoken".into(),
                    amount: "100".into(),
                    recipient: "0xrecip".into(),
                    facilitator: "https://example.com".into(),
                },
                SchemeRequirement {
                    scheme: "exact".into(),
                    network: "eip155:8453".into(),
                    token: "0xtoken".into(),
                    amount: "100".into(),
                    recipient: "0xrecip".into(),
                    facilitator: "https://example.com".into(),
                },
            ],
            version: "v2".into(),
        };

        let selected = select_scheme(&header).unwrap();
        assert_eq!(selected.scheme, "exact");
    }

    #[test]
    fn select_scheme_rejects_non_evm() {
        let header = PaymentRequiredHeader {
            schemes: vec![SchemeRequirement {
                scheme: "exact".into(),
                network: "solana:mainnet".into(),
                token: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
                amount: "100".into(),
                recipient: "SoLaNa".into(),
                facilitator: "https://example.com".into(),
            }],
            version: "v2".into(),
        };

        let result = select_scheme(&header);
        assert!(result.is_err());
    }

    // -- parse_settlement_response tests --

    #[test]
    fn parse_settlement_response_roundtrip() {
        let client = test_client();
        let response = PaymentResponseHeader {
            tx_hash: "0xabc123".into(),
            network: "eip155:8453".into(),
            settled: true,
        };
        let encoded = crate::header::encode_payment_response(&response).unwrap();
        let decoded = client.parse_settlement_response(&encoded).unwrap();
        assert_eq!(decoded, response);
    }
}

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
    Eip3009Authorization, PaymentRequiredHeader, PaymentResponseHeader, PaymentSignatureHeader,
    SchemeRequirement, encode_payment_signature, parse_payment_required, parse_payment_response,
};

/// Default validity window for signed EIP-3009 authorizations when the
/// [`SchemeRequirement`] does not set `max_timeout_seconds`.
const DEFAULT_AUTHORIZATION_WINDOW_SECS: u64 = 600;

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
    /// Produces a `PaymentSignatureHeader` carrying a real EIP-3009
    /// `transferWithAuthorization` signature plus the authorization payload.
    /// Callers with an approved `RequiresApproval` decision can invoke this
    /// directly after getting human sign-off.
    ///
    /// # Protocol
    /// 1. Parse `requirement.amount` as `u64` (USDC's smallest unit).
    /// 2. Generate a random 32-byte nonce — unique per authorization, so the
    ///    same agent can submit multiple concurrent payments without collision.
    /// 3. Set `validAfter = now` and `validBefore = now + max_timeout_seconds`
    ///    (defaults to 10 minutes).
    /// 4. Compute the EIP-712 digest and sign it recoverably with the wallet
    ///    (`WalletBackend::sign_transfer_authorization`).
    /// 5. Package the 65-byte `(r || s || v)` signature as hex in `payload`
    ///    and attach the authorization fields so facilitators can reconstruct
    ///    and verify the digest.
    pub async fn sign_payment(
        &self,
        requirement: &SchemeRequirement,
    ) -> HaimaResult<PaymentSignatureHeader> {
        use rand::RngCore;

        let raw_amount: u64 = requirement.amount.parse().map_err(|e| {
            HaimaError::Protocol(format!("invalid amount '{}': {e}", requirement.amount))
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let timeout = requirement
            .max_timeout_seconds
            .unwrap_or(DEFAULT_AUTHORIZATION_WINDOW_SECS);
        let valid_after = now;
        let valid_before = now.saturating_add(timeout);

        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let from = self.wallet.address().address.clone();
        let signature = self
            .wallet
            .sign_transfer_authorization(
                &from,
                &requirement.recipient,
                raw_amount,
                valid_after,
                valid_before,
                &nonce,
            )
            .await?;

        Ok(PaymentSignatureHeader {
            scheme: requirement.scheme.clone(),
            network: requirement.network.clone(),
            payload: hex::encode(&signature),
            authorization: Some(Eip3009Authorization {
                from,
                to: requirement.recipient.clone(),
                value: raw_amount.to_string(),
                valid_after: valid_after.to_string(),
                valid_before: valid_before.to_string(),
                nonce: format!("0x{}", hex::encode(nonce)),
            }),
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

    /// Arbitrary valid checksummed 20-byte address used by tests that need a
    /// parseable recipient (EIP-3009 signing rejects non-hex recipients).
    const TEST_RECIPIENT: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

    fn sample_requirement() -> SchemeRequirement {
        SchemeRequirement {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            amount: "50".into(), // 50 micro-credits, below auto-approve cap of 100
            recipient: TEST_RECIPIENT.into(),
            facilitator: "https://x402.org/facilitator".into(),
            max_timeout_seconds: None,
        }
    }

    fn sample_payment_required_header(amount: &str) -> PaymentRequiredHeader {
        PaymentRequiredHeader {
            schemes: vec![SchemeRequirement {
                scheme: "exact".into(),
                network: "eip155:8453".into(),
                token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
                amount: amount.into(),
                recipient: TEST_RECIPIENT.into(),
                facilitator: "https://x402.org/facilitator".into(),
                max_timeout_seconds: None,
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
                max_timeout_seconds: None,
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

    #[tokio::test]
    async fn sign_payment_populates_eip3009_authorization() {
        let client = test_client();
        let requirement = sample_requirement();

        let sig = client.sign_payment(&requirement).await.unwrap();

        let auth = sig
            .authorization
            .expect("EIP-3009 authorization must be present");
        assert_eq!(auth.to.to_lowercase(), TEST_RECIPIENT.to_lowercase());
        assert_eq!(auth.value, "50");
        assert!(auth.from.starts_with("0x"));
        assert!(auth.nonce.starts_with("0x") && auth.nonce.len() == 66);
        // valid_before > valid_after by the default window
        let after: u64 = auth.valid_after.parse().unwrap();
        let before: u64 = auth.valid_before.parse().unwrap();
        assert!(before > after);
        assert_eq!(before - after, 600);
    }

    #[tokio::test]
    async fn sign_payment_generates_unique_nonce_per_call() {
        let client = test_client();
        let requirement = sample_requirement();

        let sig1 = client.sign_payment(&requirement).await.unwrap();
        let sig2 = client.sign_payment(&requirement).await.unwrap();

        let nonce1 = sig1.authorization.unwrap().nonce;
        let nonce2 = sig2.authorization.unwrap().nonce;
        assert_ne!(nonce1, nonce2, "each signature must use a fresh nonce");
    }

    #[tokio::test]
    async fn sign_payment_produces_65_byte_recoverable_signature() {
        let client = test_client();
        let requirement = sample_requirement();

        let sig = client.sign_payment(&requirement).await.unwrap();
        let raw = hex::decode(&sig.payload).unwrap();
        assert_eq!(raw.len(), 65);
        let v = raw[64];
        assert!(v == 27 || v == 28);
    }

    #[tokio::test]
    async fn sign_payment_honors_custom_timeout() {
        let client = test_client();
        let mut requirement = sample_requirement();
        requirement.max_timeout_seconds = Some(60);

        let sig = client.sign_payment(&requirement).await.unwrap();
        let auth = sig.authorization.unwrap();
        let after: u64 = auth.valid_after.parse().unwrap();
        let before: u64 = auth.valid_before.parse().unwrap();
        assert_eq!(before - after, 60);
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
                    max_timeout_seconds: None,
                },
                SchemeRequirement {
                    scheme: "exact".into(),
                    network: "eip155:8453".into(),
                    token: "0xtoken".into(),
                    amount: "100".into(),
                    recipient: "0xrecip".into(),
                    facilitator: "https://example.com".into(),
                    max_timeout_seconds: None,
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
                max_timeout_seconds: None,
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

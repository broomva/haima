//! Full x402 client round-trip orchestration.
//!
//! [`X402Client`] handles a *single* 402 challenge (parse → policy → sign).
//! [`pay_x402`] drives the complete HTTP loop around it: initial request →
//! 402 → optional pre-sign `max_amount` cap → policy/sign → retry with the
//! `payment-signature` header → settlement + paid resource.
//!
//! The signing wallet is whatever [`WalletBackend`](haima_wallet::WalletBackend)
//! the caller built the [`X402Client`] with. Pass a
//! [`CustodyWalletAdapter`](crate::CustodyWalletAdapter) (feature
//! `custody-adapter`) to pay from a user's Anima-custodied wallet — that
//! composition is feature-independent here, so `pay.rs` itself pulls in no
//! anima dependency.
//!
//! Header-before-body discipline: `reqwest::Response::bytes` consumes the
//! response, so settlement headers are extracted before the body is read.

use haima_core::payment::PaymentDecision;
use haima_core::wallet::usdc_raw_to_micro_credits;
use haima_core::{HaimaError, HaimaResult};

use crate::client::X402Client;
use crate::header::{
    PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER,
    parse_payment_required,
};

/// HTTP 402 Payment Required.
const STATUS_PAYMENT_REQUIRED: u16 = 402;

/// A completed x402 payment plus the resource fetched after settlement.
#[derive(Debug, Clone)]
pub struct X402PaidOutcome {
    /// Settlement transaction hash, if the post-payment 200 carried a
    /// `payment-response` header.
    pub tx_hash: Option<String>,
    /// Whether the settlement response reported `settled`.
    pub settled: bool,
    /// CAIP-2 network the payment was authorized on (e.g. `eip155:8453`).
    pub network: String,
    /// Recipient address that was paid.
    pub recipient: String,
    /// Cost in micro-credits.
    pub micro_credits: i64,
    /// Body of the post-payment 200 response (the paid resource).
    pub resource_body: Vec<u8>,
}

/// Outcome of [`pay_x402`].
#[derive(Debug, Clone)]
pub enum X402PayResult {
    /// The resource was not paywalled — the initial request returned non-402.
    NotRequired { status: u16, resource_body: Vec<u8> },
    /// Payment authorized and the paid resource fetched.
    Paid(X402PaidOutcome),
    /// No payment made: policy required approval, denied it, or the amount
    /// exceeded `max_amount_micro_credits`. No funds moved, no signature
    /// submitted.
    Declined { reason: String, micro_credits: i64 },
}

/// Drive a full x402 client payment round-trip against `resource_url`.
///
/// `max_amount_micro_credits`, when set, is a per-call ceiling enforced
/// **before signing**, on top of the [`X402Client`]'s `PaymentPolicy`. An
/// amount over the cap returns [`X402PayResult::Declined`] without signing or
/// contacting the payee a second time.
///
/// Returns [`X402PayResult::NotRequired`] when the resource is not paywalled,
/// [`X402PayResult::Paid`] on a settled payment, or
/// [`X402PayResult::Declined`] when policy/cap/approval blocks the payment.
pub async fn pay_x402(
    client: &X402Client,
    http: &reqwest::Client,
    resource_url: &str,
    max_amount_micro_credits: Option<i64>,
) -> HaimaResult<X402PayResult> {
    // 1. Initial request.
    let first = http
        .get(resource_url)
        .send()
        .await
        .map_err(|e| HaimaError::Http(format!("initial request to {resource_url}: {e}")))?;

    if first.status().as_u16() != STATUS_PAYMENT_REQUIRED {
        let status = first.status().as_u16();
        let resource_body = first
            .bytes()
            .await
            .map_err(|e| HaimaError::Http(format!("reading non-402 body: {e}")))?
            .to_vec();
        return Ok(X402PayResult::NotRequired {
            status,
            resource_body,
        });
    }

    // 2. Extract the payment-required header from the 402.
    let required = first
        .headers()
        .get(PAYMENT_REQUIRED_HEADER)
        .ok_or_else(|| HaimaError::Protocol("402 response missing payment-required header".into()))?
        .to_str()
        .map_err(|e| HaimaError::Protocol(format!("payment-required header not UTF-8: {e}")))?
        .to_string();

    // 3. Enforce the per-call max_amount cap BEFORE signing.
    if let Some(cap) = max_amount_micro_credits {
        let header = parse_payment_required(&required)?;
        if let Some(scheme) = header
            .schemes
            .iter()
            .find(|s| s.scheme == "exact" && s.network.starts_with("eip155:"))
        {
            let raw: u64 = scheme.amount.parse().map_err(|e| {
                HaimaError::Protocol(format!("invalid amount '{}': {e}", scheme.amount))
            })?;
            let micro_credits = usdc_raw_to_micro_credits(raw);
            if micro_credits > cap {
                return Ok(X402PayResult::Declined {
                    reason: format!(
                        "amount {micro_credits} micro-credits exceeds max_amount {cap}"
                    ),
                    micro_credits,
                });
            }
        }
    }

    // 4. Single-challenge handling: parse → policy → sign-if-approved.
    let handled = client.handle_402(resource_url, &required).await?;

    match handled.decision {
        PaymentDecision::RequiresApproval {
            micro_credit_cost,
            reason,
        } => Ok(X402PayResult::Declined {
            reason,
            micro_credits: micro_credit_cost,
        }),
        PaymentDecision::Denied { reason } => Ok(X402PayResult::Declined {
            reason,
            micro_credits: 0,
        }),
        PaymentDecision::Approved {
            micro_credit_cost, ..
        } => {
            let signature_header = handled.signature_header.ok_or_else(|| {
                HaimaError::Protocol("approved payment produced no signature header".into())
            })?;

            // 5. Retry with the payment-signature header.
            let retry = http
                .get(resource_url)
                .header(PAYMENT_SIGNATURE_HEADER, &signature_header)
                .send()
                .await
                .map_err(|e| HaimaError::Http(format!("retry request to {resource_url}: {e}")))?;

            // 6. Extract the settlement header BEFORE consuming the body.
            let settlement = match retry.headers().get(PAYMENT_RESPONSE_HEADER) {
                Some(value) => {
                    let raw = value.to_str().map_err(|e| {
                        HaimaError::Protocol(format!("payment-response header not UTF-8: {e}"))
                    })?;
                    Some(client.parse_settlement_response(raw)?)
                }
                None => None,
            };

            let resource_body = retry
                .bytes()
                .await
                .map_err(|e| HaimaError::Http(format!("reading paid resource body: {e}")))?
                .to_vec();

            Ok(X402PayResult::Paid(X402PaidOutcome {
                tx_hash: settlement.as_ref().map(|s| s.tx_hash.clone()),
                settled: settlement.as_ref().is_some_and(|s| s.settled),
                network: handled.requirement.network,
                recipient: handled.requirement.recipient,
                micro_credits: micro_credit_cost,
                resource_body,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use haima_core::policy::PaymentPolicy;
    use haima_core::wallet::ChainId;
    use haima_wallet::LocalSigner;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::facilitator::{Facilitator, FacilitatorConfig};
    use crate::header::{
        PaymentRequiredHeader, PaymentResponseHeader, SchemeRequirement, encode_payment_required,
        encode_payment_response,
    };

    const TEST_RECIPIENT: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
    const USDC_BASE_MAINNET: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

    fn make_client() -> X402Client {
        let signer = LocalSigner::generate(ChainId::base()).expect("signer");
        let facilitator = Facilitator::new(FacilitatorConfig::default());
        X402Client::new(Arc::new(signer), facilitator, PaymentPolicy::default())
    }

    fn payment_required_header(amount: &str) -> String {
        let header = PaymentRequiredHeader {
            schemes: vec![SchemeRequirement {
                scheme: "exact".into(),
                network: "eip155:8453".into(),
                token: USDC_BASE_MAINNET.into(),
                amount: amount.into(),
                recipient: TEST_RECIPIENT.into(),
                facilitator: "https://x402.org/facilitator".into(),
                max_timeout_seconds: Some(300),
            }],
            version: "v2".into(),
        };
        encode_payment_required(&header).expect("encode header")
    }

    /// Mount the 402 (first GET) leg on a wiremock server.
    async fn mount_402(server: &MockServer, amount: &str) {
        Mock::given(method("GET"))
            .and(path("/api/data"))
            .respond_with(
                ResponseTemplate::new(402)
                    .insert_header(PAYMENT_REQUIRED_HEADER, payment_required_header(amount)),
            )
            .up_to_n_times(1)
            .mount(server)
            .await;
    }

    /// Mount the 200 + payment-response (retry-with-signature) leg.
    async fn mount_paid(server: &MockServer) {
        let resp = PaymentResponseHeader {
            tx_hash: "0xdeadbeef".into(),
            network: "eip155:8453".into(),
            settled: true,
        };
        let encoded = encode_payment_response(&resp).expect("encode response");
        Mock::given(method("GET"))
            .and(path("/api/data"))
            .and(header_exists(PAYMENT_SIGNATURE_HEADER))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(PAYMENT_RESPONSE_HEADER, encoded)
                    .set_body_string("{\"data\":\"ok\"}"),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn pays_and_returns_resource() {
        let server = MockServer::start().await;
        mount_402(&server, "50").await; // 50 μc — under the 100 auto-approve cap
        mount_paid(&server).await;

        let client = make_client();
        let http = reqwest::Client::new();
        let url = format!("{}/api/data", server.uri());

        let result = pay_x402(&client, &http, &url, None).await.expect("pay");
        match result {
            X402PayResult::Paid(o) => {
                assert!(o.settled);
                assert_eq!(o.tx_hash.as_deref(), Some("0xdeadbeef"));
                assert_eq!(o.network, "eip155:8453");
                assert_eq!(o.recipient.to_lowercase(), TEST_RECIPIENT.to_lowercase());
                assert_eq!(o.micro_credits, 50);
                assert_eq!(o.resource_body, b"{\"data\":\"ok\"}");
            }
            other => panic!("expected Paid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn max_amount_declines_before_signing() {
        let server = MockServer::start().await;
        // Only the 402 leg is mounted — if pay_x402 retried, the request would
        // 404 (no matching mock). The assertion that we get Declined proves the
        // retry never happened.
        mount_402(&server, "50").await;

        let client = make_client();
        let http = reqwest::Client::new();
        let url = format!("{}/api/data", server.uri());

        let result = pay_x402(&client, &http, &url, Some(10)).await.expect("pay");
        match result {
            X402PayResult::Declined {
                micro_credits,
                reason,
            } => {
                assert_eq!(micro_credits, 50);
                assert!(reason.contains("max_amount"));
            }
            other => panic!("expected Declined, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_denial_declines() {
        let server = MockServer::start().await;
        // 2_000_000 μc is above the default 1_000_000 hard cap → policy denies.
        mount_402(&server, "2000000").await;

        let client = make_client();
        let http = reqwest::Client::new();
        let url = format!("{}/api/data", server.uri());

        let result = pay_x402(&client, &http, &url, None).await.expect("pay");
        assert!(
            matches!(result, X402PayResult::Declined { .. }),
            "over-hard-cap amount must decline, got {result:?}"
        );
    }

    #[tokio::test]
    async fn not_required_when_unpaywalled() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data"))
            .respond_with(ResponseTemplate::new(200).set_body_string("free"))
            .mount(&server)
            .await;

        let client = make_client();
        let http = reqwest::Client::new();
        let url = format!("{}/api/data", server.uri());

        let result = pay_x402(&client, &http, &url, None).await.expect("pay");
        match result {
            X402PayResult::NotRequired {
                status,
                resource_body,
            } => {
                assert_eq!(status, 200);
                assert_eq!(resource_body, b"free");
            }
            other => panic!("expected NotRequired, got {other:?}"),
        }
    }
}

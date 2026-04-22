//! End-to-end smoke test for the full x402 payment flow.
//!
//! Boots a [`wiremock`] server that plays the role of a paid API, runs the
//! Haima [`X402Client`] against it through the complete protocol loop, and
//! asserts that the in-process facilitator produces a settlement receipt.
//!
//! No real mainnet, no real chain — the facilitator's on-chain submission is
//! already stubbed in F0 (`verify_payment_header` returns a deterministic tx
//! hash derived from the signature bytes). When F4 ships real RPC-backed
//! settlement, this same test can be extended with a chain mock.
//!
//! These tests exercise real header encoding, real signing, real policy, and
//! real facilitator verification logic — only the upstream API and the chain
//! are mocked.

use std::sync::Arc;
use std::time::Duration;

use haima_core::payment::PaymentDecision;
use haima_core::policy::PaymentPolicy;
use haima_core::wallet::ChainId;
use haima_wallet::LocalSigner;
use haima_x402::facilitator::{
    DEFAULT_FEE_BPS, FacilitateRequest, FacilitationStatus, Facilitator, FacilitatorConfig,
    FacilitatorStatsCounter, verify_payment_header,
};
use haima_x402::header::{
    PaymentRequiredHeader, PaymentResponseHeader, SchemeRequirement, encode_payment_required,
    encode_payment_response,
};
use haima_x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402Client};
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_RECIPIENT: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_BASE_MAINNET: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/// Build a test `X402Client` with a freshly-generated wallet on Base mainnet
/// and the default `https://x402.org/facilitator` config (not contacted in
/// these tests — settlement uses the in-process `verify_payment_header`).
fn make_client() -> X402Client {
    let signer = LocalSigner::generate(ChainId::base()).expect("signer");
    let facilitator = Facilitator::new(FacilitatorConfig::default());
    X402Client::new(Arc::new(signer), facilitator, PaymentPolicy::default())
}

fn requirement(amount: &str) -> SchemeRequirement {
    SchemeRequirement {
        scheme: "exact".into(),
        network: "eip155:8453".into(),
        token: USDC_BASE_MAINNET.into(),
        amount: amount.into(),
        recipient: TEST_RECIPIENT.into(),
        facilitator: "https://x402.org/facilitator".into(),
        max_timeout_seconds: Some(300),
    }
}

fn payment_required_header(amount: &str) -> String {
    let header = PaymentRequiredHeader {
        schemes: vec![requirement(amount)],
        version: "v2".into(),
    };
    encode_payment_required(&header).expect("encode header")
}

/// Full golden-path: 402 → parse → policy-approve → sign → retry → 200 + receipt.
#[tokio::test]
async fn e2e_auto_approved_payment_flow_succeeds() {
    let server = MockServer::start().await;
    let client = make_client();

    // Stage 1: unauthenticated GET returns 402 with PAYMENT-REQUIRED.
    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(402)
                .insert_header(PAYMENT_REQUIRED_HEADER, payment_required_header("50")),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Stage 2: authenticated GET (with PAYMENT-SIGNATURE) returns 200 +
    // PAYMENT-RESPONSE. We don't need to verify the signature server-side in
    // wiremock — the facilitator does that below.
    let fake_response = PaymentResponseHeader {
        tx_hash: "0xdeadbeef".into(),
        network: "eip155:8453".into(),
        settled: true,
    };
    let encoded_response = encode_payment_response(&fake_response).expect("encode response");
    Mock::given(method("GET"))
        .and(path("/api/data"))
        .and(header_exists("payment-signature"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(PAYMENT_RESPONSE_HEADER, encoded_response)
                .set_body_string("{\"data\":\"ok\"}"),
        )
        .mount(&server)
        .await;

    // --- Drive the protocol ---
    let http = reqwest::Client::new();
    let url = format!("{}/api/data", server.uri());

    let r1 = http.get(&url).send().await.expect("first request");
    assert_eq!(r1.status(), 402);
    let required = r1
        .headers()
        .get(PAYMENT_REQUIRED_HEADER)
        .expect("402 must carry payment-required")
        .to_str()
        .unwrap()
        .to_string();

    let handled = client
        .handle_402(&url, &required)
        .await
        .expect("handle_402");
    assert!(matches!(handled.decision, PaymentDecision::Approved { .. }));
    let signature_header = handled
        .signature_header
        .expect("auto-approved decision must produce a signed header");

    let r2 = http
        .get(&url)
        .header("payment-signature", &signature_header)
        .send()
        .await
        .expect("retry request");
    assert_eq!(r2.status(), 200);
    let returned = r2
        .headers()
        .get(PAYMENT_RESPONSE_HEADER)
        .expect("200 must carry payment-response");
    let parsed = client
        .parse_settlement_response(returned.to_str().unwrap())
        .expect("parse settlement");
    assert!(parsed.settled);
    assert_eq!(parsed.tx_hash, "0xdeadbeef");

    // --- Verify the signed authorization through the in-process facilitator ---
    let stats = FacilitatorStatsCounter::new();
    let facilitate_req = FacilitateRequest {
        payment_header: signature_header,
        resource_url: url.clone(),
        amount_micro_usd: 50,
        agent_id: None,
    };
    let resp = verify_payment_header(&facilitate_req, DEFAULT_FEE_BPS, &stats);
    assert_eq!(resp.status, FacilitationStatus::Settled);
    let receipt = resp.receipt.expect("settled → receipt");
    assert_eq!(receipt.amount_micro_usd, 50);
    assert_eq!(receipt.chain, "base");
    assert!(receipt.tx_hash.starts_with("0x"));
    assert_eq!(stats.snapshot().total_transactions, 1);
}

/// Amount above the hard cap → decision is Denied, no signing, no retry.
#[tokio::test]
async fn e2e_policy_denial_blocks_payment() {
    let client = make_client();

    // 2_000_000 micro-credits exceeds the default 1_000_000 hard cap.
    let required = payment_required_header("2000000");
    let handled = client
        .handle_402("https://api.example.com/data", &required)
        .await
        .expect("handle_402");
    assert!(matches!(handled.decision, PaymentDecision::Denied { .. }));
    assert!(handled.signature_header.is_none());
}

/// Malformed `payment-required` header surfaces an error instead of silently
/// signing. Important: silent failure here would let an attacker redirect
/// payment elsewhere.
#[tokio::test]
async fn e2e_malformed_402_header_surfaces_error() {
    let client = make_client();
    let result = client
        .handle_402("https://api.example.com/data", "not-valid-base64!!!")
        .await;
    assert!(result.is_err(), "malformed 402 header must not be ignored");
}

/// If the in-process facilitator rejects the signature (e.g., tampered
/// payload), the rejection propagates with a structured reason.
#[tokio::test]
async fn e2e_facilitator_rejection_propagates() {
    use haima_x402::header::{PaymentSignatureHeader, encode_payment_signature};

    // Craft a header that looks syntactically valid but carries a too-short
    // signature (facilitator validates sig length >= 64 bytes).
    let tampered = PaymentSignatureHeader {
        scheme: "exact".into(),
        network: "eip155:8453".into(),
        payload: hex::encode([0xabu8; 10]),
        authorization: None,
    };
    let encoded = encode_payment_signature(&tampered).expect("encode");
    let stats = FacilitatorStatsCounter::new();
    let resp = verify_payment_header(
        &FacilitateRequest {
            payment_header: encoded,
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 50,
            agent_id: None,
        },
        DEFAULT_FEE_BPS,
        &stats,
    );
    assert_eq!(resp.status, FacilitationStatus::Rejected);
    assert_eq!(
        resp.reason.as_deref(),
        Some("invalid_signature"),
        "reason should identify the failure class"
    );
    assert_eq!(stats.snapshot().total_rejected, 1);
}

/// Sanity check: the happy-path flow completes well under the 3s budget
/// called out in BRO-758. Duplicates the body of the golden-path test rather
/// than calling it, because `#[tokio::test]`-decorated fns are not
/// `async fn`s from the caller's perspective.
#[tokio::test]
async fn e2e_smoke_runs_quickly() {
    let start = std::time::Instant::now();

    let server = MockServer::start().await;
    let client = make_client();

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(402)
                .insert_header(PAYMENT_REQUIRED_HEADER, payment_required_header("50")),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let fake_response = PaymentResponseHeader {
        tx_hash: "0xdeadbeef".into(),
        network: "eip155:8453".into(),
        settled: true,
    };
    let encoded_response = encode_payment_response(&fake_response).expect("encode response");
    Mock::given(method("GET"))
        .and(path("/api/data"))
        .and(header_exists("payment-signature"))
        .respond_with(
            ResponseTemplate::new(200).insert_header(PAYMENT_RESPONSE_HEADER, encoded_response),
        )
        .mount(&server)
        .await;

    let http = reqwest::Client::new();
    let url = format!("{}/api/data", server.uri());
    let r1 = http.get(&url).send().await.expect("first");
    let required = r1
        .headers()
        .get(PAYMENT_REQUIRED_HEADER)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let handled = client.handle_402(&url, &required).await.expect("handle");
    let sig = handled.signature_header.expect("signed");
    let _r2 = http
        .get(&url)
        .header("payment-signature", &sig)
        .send()
        .await
        .expect("retry");

    assert!(
        start.elapsed() < Duration::from_secs(3),
        "e2e smoke should be fast (no real network/chain); took {:?}",
        start.elapsed()
    );
}

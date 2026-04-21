//! Facilitator client and server — communicates with payment facilitators for
//! verification and on-chain settlement, and hosts the facilitator endpoint.
//!
//! Supported facilitators:
//! - **Coinbase CDP** (default): Free tier 1K tx/month, then $0.001/tx
//! - **Self-hosted**: Reference facilitator for testing and sovereignty
//!
//! The facilitator endpoint (`POST /v1/facilitate`) receives payment headers
//! from clients, verifies them, and returns a settlement receipt.

use chrono::{DateTime, Utc};
use haima_core::{HaimaError, HaimaResult};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

/// Facilitator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitatorConfig {
    /// Facilitator base URL.
    pub url: String,
    /// Facilitator type.
    pub kind: FacilitatorKind,
    /// API key (required for Coinbase CDP).
    pub api_key: Option<String>,
}

/// Supported facilitator types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacilitatorKind {
    /// Coinbase CDP facilitator.
    CoinbaseCdp,
    /// Self-hosted reference facilitator.
    SelfHosted,
    /// Stripe facilitator.
    Stripe,
}

impl Default for FacilitatorConfig {
    fn default() -> Self {
        Self {
            url: "https://x402.org/facilitator".into(),
            kind: FacilitatorKind::CoinbaseCdp,
            api_key: None,
        }
    }
}

/// A facilitator handles payment verification and on-chain settlement.
pub struct Facilitator {
    config: FacilitatorConfig,
    client: reqwest::Client,
}

impl Facilitator {
    pub fn new(config: FacilitatorConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Verify a payment payload against the original requirements.
    pub async fn verify(&self, payload: &VerifyRequest) -> HaimaResult<VerifyResponse> {
        let url = format!("{}/verify", self.config.url);

        let mut req = self.client.post(&url).json(payload);
        if let Some(ref key) = self.config.api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| HaimaError::Facilitator(format!("verify request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(HaimaError::Facilitator(format!(
                "verify failed with {status}: {body}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| HaimaError::Facilitator(format!("verify response parse failed: {e}")))
    }

    /// Get supported networks and schemes from the facilitator.
    pub async fn supported(&self) -> HaimaResult<SupportedResponse> {
        let url = format!("{}/supported", self.config.url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| HaimaError::Facilitator(format!("supported request failed: {e}")))?;

        resp.json()
            .await
            .map_err(|e| HaimaError::Facilitator(format!("supported response parse failed: {e}")))
    }

    pub fn config(&self) -> &FacilitatorConfig {
        &self.config
    }
}

/// Request body for the facilitator's /verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub payment_payload: String,
    pub payment_requirements: String,
}

/// Response from the facilitator's /verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

/// Response from the facilitator's /supported endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedResponse {
    pub networks: Vec<String>,
    pub schemes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Facilitator endpoint types (self-hosted facilitator server)
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/facilitate`.
///
/// Clients send this to have the facilitator verify a payment header
/// and return a settlement receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitateRequest {
    /// Base64-encoded x402 payment signature header.
    pub payment_header: String,
    /// The resource URL the payment is for.
    pub resource_url: String,
    /// Expected payment amount in micro-USD (1 USD = 1,000,000 micro-USD).
    pub amount_micro_usd: u64,
    /// Optional agent ID for credit-gated facilitation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

/// Response body for `POST /v1/facilitate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitateResponse {
    /// The facilitation status.
    pub status: FacilitationStatus,
    /// Settlement receipt (present when status is `Settled`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<SettlementReceipt>,
    /// Facilitator fee in basis points (present when status is `Settled`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facilitator_fee_bps: Option<u32>,
    /// Optional trust attestation (reserved for future use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_attestation: Option<serde_json::Value>,
    /// Rejection reason (present when status is `Rejected`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Rejection details (present when status is `Rejected`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Facilitation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacilitationStatus {
    /// Payment verified and settled on-chain.
    Settled,
    /// Payment verification failed.
    Rejected,
    /// Payment is being processed (async settlement).
    Pending,
}

/// On-chain settlement receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementReceipt {
    /// Transaction hash.
    pub tx_hash: String,
    /// Payer address.
    pub payer: String,
    /// Payee (recipient) address.
    pub payee: String,
    /// Amount in micro-USD.
    pub amount_micro_usd: u64,
    /// Chain where settlement occurred.
    pub chain: String,
    /// When settlement was confirmed.
    pub settled_at: DateTime<Utc>,
}

/// In-memory facilitator statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitatorStats {
    /// Total transactions processed.
    pub total_transactions: u64,
    /// Total volume in micro-USD.
    pub total_volume_micro_usd: u64,
    /// Total fees collected in micro-USD.
    pub total_fees_micro_usd: u64,
    /// Total rejected transactions.
    pub total_rejected: u64,
}

/// Thread-safe facilitator statistics counters.
#[derive(Debug)]
pub struct FacilitatorStatsCounter {
    total_transactions: AtomicU64,
    total_volume_micro_usd: AtomicU64,
    total_fees_micro_usd: AtomicU64,
    total_rejected: AtomicU64,
}

impl Default for FacilitatorStatsCounter {
    fn default() -> Self {
        Self {
            total_transactions: AtomicU64::new(0),
            total_volume_micro_usd: AtomicU64::new(0),
            total_fees_micro_usd: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
        }
    }
}

impl FacilitatorStatsCounter {
    /// Create a new stats counter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful facilitation.
    pub fn record_settled(&self, amount_micro_usd: u64, fee_micro_usd: u64) {
        self.total_transactions.fetch_add(1, Ordering::Relaxed);
        self.total_volume_micro_usd
            .fetch_add(amount_micro_usd, Ordering::Relaxed);
        self.total_fees_micro_usd
            .fetch_add(fee_micro_usd, Ordering::Relaxed);
    }

    /// Record a rejected facilitation.
    pub fn record_rejected(&self) {
        self.total_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the current stats.
    pub fn snapshot(&self) -> FacilitatorStats {
        FacilitatorStats {
            total_transactions: self.total_transactions.load(Ordering::Relaxed),
            total_volume_micro_usd: self.total_volume_micro_usd.load(Ordering::Relaxed),
            total_fees_micro_usd: self.total_fees_micro_usd.load(Ordering::Relaxed),
            total_rejected: self.total_rejected.load(Ordering::Relaxed),
        }
    }
}

/// Default facilitator fee in basis points (15 bps = 0.15%).
pub const DEFAULT_FEE_BPS: u32 = 15;

/// Calculate fee in micro-USD given an amount and basis points.
pub fn calculate_fee(amount_micro_usd: u64, fee_bps: u32) -> u64 {
    // fee = amount * bps / 10_000
    (amount_micro_usd as u128 * fee_bps as u128 / 10_000) as u64
}

/// Verify a payment header and produce a facilitation response.
///
/// This function:
/// 1. Decodes the base64 payment header as a `PaymentSignatureHeader`
/// 2. Validates the header structure (scheme, network, non-empty payload)
/// 3. Validates the payload is valid hex-encoded data
/// 4. On success, returns a settlement receipt with a deterministic tx hash
///
/// Full on-chain verification (RPC provider integration) is stubbed with a
/// deterministic hash. The structural validation ensures the payment header
/// is well-formed before any on-chain work would happen.
pub fn verify_payment_header(
    request: &FacilitateRequest,
    fee_bps: u32,
    stats: &FacilitatorStatsCounter,
) -> FacilitateResponse {
    use crate::header::parse_payment_signature;

    // Step 1: Parse the base64-encoded payment signature header.
    let sig_header = match parse_payment_signature(&request.payment_header) {
        Ok(h) => h,
        Err(e) => {
            warn!(
                resource_url = %request.resource_url,
                error = %e,
                "facilitate: failed to parse payment header"
            );
            stats.record_rejected();
            return FacilitateResponse {
                status: FacilitationStatus::Rejected,
                receipt: None,
                facilitator_fee_bps: None,
                trust_attestation: None,
                reason: Some("invalid_header".into()),
                details: Some(format!("Failed to parse payment header: {e}")),
            };
        }
    };

    // Step 2: Validate the scheme — only "exact" on EVM networks is supported.
    if sig_header.scheme != "exact" {
        stats.record_rejected();
        return FacilitateResponse {
            status: FacilitationStatus::Rejected,
            receipt: None,
            facilitator_fee_bps: None,
            trust_attestation: None,
            reason: Some("unsupported_scheme".into()),
            details: Some(format!(
                "Scheme '{}' is not supported, expected 'exact'",
                sig_header.scheme
            )),
        };
    }

    if !sig_header.network.starts_with("eip155:") {
        stats.record_rejected();
        return FacilitateResponse {
            status: FacilitationStatus::Rejected,
            receipt: None,
            facilitator_fee_bps: None,
            trust_attestation: None,
            reason: Some("unsupported_network".into()),
            details: Some(format!(
                "Network '{}' is not supported, expected EVM (eip155:*)",
                sig_header.network
            )),
        };
    }

    // Step 3: Validate the payload is non-empty and valid hex.
    if sig_header.payload.is_empty() {
        stats.record_rejected();
        return FacilitateResponse {
            status: FacilitationStatus::Rejected,
            receipt: None,
            facilitator_fee_bps: None,
            trust_attestation: None,
            reason: Some("empty_payload".into()),
            details: Some("Payment signature payload is empty".into()),
        };
    }

    let payload_bytes = match hex::decode(&sig_header.payload) {
        Ok(b) => b,
        Err(e) => {
            stats.record_rejected();
            return FacilitateResponse {
                status: FacilitationStatus::Rejected,
                receipt: None,
                facilitator_fee_bps: None,
                trust_attestation: None,
                reason: Some("invalid_signature".into()),
                details: Some(format!("Payment header signature is not valid hex: {e}")),
            };
        }
    };

    // Step 4: Validate minimum signature length (ECDSA signatures are 64-65 bytes).
    if payload_bytes.len() < 64 {
        stats.record_rejected();
        return FacilitateResponse {
            status: FacilitationStatus::Rejected,
            receipt: None,
            facilitator_fee_bps: None,
            trust_attestation: None,
            reason: Some("invalid_signature".into()),
            details: Some(format!(
                "Signature too short: {} bytes, expected at least 64",
                payload_bytes.len()
            )),
        };
    }

    // Step 5: Derive a deterministic payer address from the payload for the receipt.
    // In production, this would be recovered from the ECDSA signature via ecrecover.
    // For now, we use a hash of the payload as a placeholder.
    let payer_hash = hex::encode(&payload_bytes[..20]);
    let payer_address = format!("0x{payer_hash}");

    // Step 6: Generate a deterministic tx hash.
    // In production, this would come from the on-chain transaction.
    let tx_hash = format!(
        "0x{}",
        hex::encode(&payload_bytes[..32.min(payload_bytes.len())])
    );

    let fee_micro_usd = calculate_fee(request.amount_micro_usd, fee_bps);

    // Determine chain from network (strip eip155: prefix for display).
    let chain = if sig_header.network == "eip155:8453" {
        "base".to_string()
    } else {
        sig_header.network
    };

    info!(
        resource_url = %request.resource_url,
        amount_micro_usd = request.amount_micro_usd,
        fee_micro_usd,
        payer = %payer_address,
        chain = %chain,
        "facilitate: payment verified and settled"
    );

    stats.record_settled(request.amount_micro_usd, fee_micro_usd);

    FacilitateResponse {
        status: FacilitationStatus::Settled,
        receipt: Some(SettlementReceipt {
            tx_hash,
            payer: payer_address,
            payee: request.resource_url.clone(),
            amount_micro_usd: request.amount_micro_usd,
            chain,
            settled_at: Utc::now(),
        }),
        facilitator_fee_bps: Some(fee_bps),
        trust_attestation: None,
        reason: None,
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{PaymentSignatureHeader, encode_payment_signature};

    #[test]
    fn default_config() {
        let config = FacilitatorConfig::default();
        assert!(matches!(config.kind, FacilitatorKind::CoinbaseCdp));
        assert!(config.api_key.is_none());
    }

    #[test]
    fn verify_response_serde() {
        let resp = VerifyResponse {
            valid: true,
            tx_hash: Some("0xabc123".into()),
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: VerifyResponse = serde_json::from_str(&json).unwrap();
        assert!(back.valid);
        assert_eq!(back.tx_hash.unwrap(), "0xabc123");
    }

    // -- Facilitator endpoint types serde --

    #[test]
    fn facilitate_request_serde_roundtrip() {
        let req = FacilitateRequest {
            payment_header: "dGVzdA==".into(),
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 1000,
            agent_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: FacilitateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount_micro_usd, 1000);
        assert_eq!(back.resource_url, "https://api.example.com/data");
    }

    #[test]
    fn facilitate_response_settled_serde() {
        let resp = FacilitateResponse {
            status: FacilitationStatus::Settled,
            receipt: Some(SettlementReceipt {
                tx_hash: "0xabc".into(),
                payer: "0xpayer".into(),
                payee: "0xpayee".into(),
                amount_micro_usd: 1000,
                chain: "base".into(),
                settled_at: Utc::now(),
            }),
            facilitator_fee_bps: Some(15),
            trust_attestation: None,
            reason: None,
            details: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: FacilitateResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, FacilitationStatus::Settled);
        assert!(back.receipt.is_some());
        assert!(back.reason.is_none());
    }

    #[test]
    fn facilitate_response_rejected_serde() {
        let resp = FacilitateResponse {
            status: FacilitationStatus::Rejected,
            receipt: None,
            facilitator_fee_bps: None,
            trust_attestation: None,
            reason: Some("invalid_signature".into()),
            details: Some("bad sig".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: FacilitateResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, FacilitationStatus::Rejected);
        assert_eq!(back.reason.unwrap(), "invalid_signature");
        assert!(back.receipt.is_none());
    }

    #[test]
    fn facilitation_status_serde() {
        let settled: FacilitationStatus = serde_json::from_str("\"settled\"").unwrap();
        assert_eq!(settled, FacilitationStatus::Settled);
        let rejected: FacilitationStatus = serde_json::from_str("\"rejected\"").unwrap();
        assert_eq!(rejected, FacilitationStatus::Rejected);
        let pending: FacilitationStatus = serde_json::from_str("\"pending\"").unwrap();
        assert_eq!(pending, FacilitationStatus::Pending);
    }

    // -- Fee calculation --

    #[test]
    fn calculate_fee_at_15_bps() {
        // 15 bps of 1,000,000 micro-USD = 1,500
        assert_eq!(calculate_fee(1_000_000, 15), 1_500);
    }

    #[test]
    fn calculate_fee_at_zero_bps() {
        assert_eq!(calculate_fee(1_000_000, 0), 0);
    }

    #[test]
    fn calculate_fee_small_amount() {
        // 15 bps of 1000 micro-USD = 1 (rounds down)
        assert_eq!(calculate_fee(1000, 15), 1);
    }

    #[test]
    fn calculate_fee_very_small_rounds_to_zero() {
        // 15 bps of 100 micro-USD = 0 (rounds down)
        assert_eq!(calculate_fee(100, 15), 0);
    }

    // -- Stats counter --

    #[test]
    fn stats_counter_default() {
        let stats = FacilitatorStatsCounter::new();
        let snap = stats.snapshot();
        assert_eq!(snap.total_transactions, 0);
        assert_eq!(snap.total_volume_micro_usd, 0);
        assert_eq!(snap.total_fees_micro_usd, 0);
        assert_eq!(snap.total_rejected, 0);
    }

    #[test]
    fn stats_counter_record_settled() {
        let stats = FacilitatorStatsCounter::new();
        stats.record_settled(1_000_000, 1_500);
        stats.record_settled(500_000, 750);
        let snap = stats.snapshot();
        assert_eq!(snap.total_transactions, 2);
        assert_eq!(snap.total_volume_micro_usd, 1_500_000);
        assert_eq!(snap.total_fees_micro_usd, 2_250);
    }

    #[test]
    fn stats_counter_record_rejected() {
        let stats = FacilitatorStatsCounter::new();
        stats.record_rejected();
        stats.record_rejected();
        let snap = stats.snapshot();
        assert_eq!(snap.total_rejected, 2);
        assert_eq!(snap.total_transactions, 0);
    }

    // -- Payment header verification --

    fn make_valid_payment_header() -> String {
        // Create a valid PaymentSignatureHeader with a 64-byte hex payload
        let sig = PaymentSignatureHeader {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            payload: hex::encode([0xabu8; 64]),
            authorization: None,
        };
        encode_payment_signature(&sig).unwrap()
    }

    #[test]
    fn verify_valid_payment_header() {
        let stats = FacilitatorStatsCounter::new();
        let req = FacilitateRequest {
            payment_header: make_valid_payment_header(),
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 1000,
            agent_id: None,
        };
        let resp = verify_payment_header(&req, DEFAULT_FEE_BPS, &stats);
        assert_eq!(resp.status, FacilitationStatus::Settled);
        assert!(resp.receipt.is_some());
        let receipt = resp.receipt.unwrap();
        assert_eq!(receipt.amount_micro_usd, 1000);
        assert_eq!(receipt.chain, "base");
        assert!(receipt.tx_hash.starts_with("0x"));
        assert!(receipt.payer.starts_with("0x"));
        assert_eq!(resp.facilitator_fee_bps, Some(DEFAULT_FEE_BPS));

        let snap = stats.snapshot();
        assert_eq!(snap.total_transactions, 1);
        assert_eq!(snap.total_volume_micro_usd, 1000);
    }

    #[test]
    fn verify_invalid_base64_header() {
        let stats = FacilitatorStatsCounter::new();
        let req = FacilitateRequest {
            payment_header: "not-valid-base64!!!".into(),
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 1000,
            agent_id: None,
        };
        let resp = verify_payment_header(&req, DEFAULT_FEE_BPS, &stats);
        assert_eq!(resp.status, FacilitationStatus::Rejected);
        assert_eq!(resp.reason.unwrap(), "invalid_header");
        assert_eq!(stats.snapshot().total_rejected, 1);
    }

    #[test]
    fn verify_unsupported_scheme() {
        let sig = PaymentSignatureHeader {
            scheme: "streaming".into(),
            network: "eip155:8453".into(),
            payload: hex::encode([0xabu8; 64]),
            authorization: None,
        };
        let header = encode_payment_signature(&sig).unwrap();

        let stats = FacilitatorStatsCounter::new();
        let req = FacilitateRequest {
            payment_header: header,
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 1000,
            agent_id: None,
        };
        let resp = verify_payment_header(&req, DEFAULT_FEE_BPS, &stats);
        assert_eq!(resp.status, FacilitationStatus::Rejected);
        assert_eq!(resp.reason.unwrap(), "unsupported_scheme");
    }

    #[test]
    fn verify_unsupported_network() {
        let sig = PaymentSignatureHeader {
            scheme: "exact".into(),
            network: "solana:mainnet".into(),
            payload: hex::encode([0xabu8; 64]),
            authorization: None,
        };
        let header = encode_payment_signature(&sig).unwrap();

        let stats = FacilitatorStatsCounter::new();
        let req = FacilitateRequest {
            payment_header: header,
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 1000,
            agent_id: None,
        };
        let resp = verify_payment_header(&req, DEFAULT_FEE_BPS, &stats);
        assert_eq!(resp.status, FacilitationStatus::Rejected);
        assert_eq!(resp.reason.unwrap(), "unsupported_network");
    }

    #[test]
    fn verify_empty_payload() {
        let sig = PaymentSignatureHeader {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            payload: String::new(),
            authorization: None,
        };
        let header = encode_payment_signature(&sig).unwrap();

        let stats = FacilitatorStatsCounter::new();
        let req = FacilitateRequest {
            payment_header: header,
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 1000,
            agent_id: None,
        };
        let resp = verify_payment_header(&req, DEFAULT_FEE_BPS, &stats);
        assert_eq!(resp.status, FacilitationStatus::Rejected);
        assert_eq!(resp.reason.unwrap(), "empty_payload");
    }

    #[test]
    fn verify_short_signature() {
        let sig = PaymentSignatureHeader {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            payload: hex::encode([0xabu8; 10]), // Too short
            authorization: None,
        };
        let header = encode_payment_signature(&sig).unwrap();

        let stats = FacilitatorStatsCounter::new();
        let req = FacilitateRequest {
            payment_header: header,
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 1000,
            agent_id: None,
        };
        let resp = verify_payment_header(&req, DEFAULT_FEE_BPS, &stats);
        assert_eq!(resp.status, FacilitationStatus::Rejected);
        assert_eq!(resp.reason.unwrap(), "invalid_signature");
        assert!(resp.details.unwrap().contains("too short"));
    }

    #[test]
    fn verify_invalid_hex_payload() {
        let sig = PaymentSignatureHeader {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            payload: "not-valid-hex!@#$".into(),
            authorization: None,
        };
        let header = encode_payment_signature(&sig).unwrap();

        let stats = FacilitatorStatsCounter::new();
        let req = FacilitateRequest {
            payment_header: header,
            resource_url: "https://api.example.com/data".into(),
            amount_micro_usd: 1000,
            agent_id: None,
        };
        let resp = verify_payment_header(&req, DEFAULT_FEE_BPS, &stats);
        assert_eq!(resp.status, FacilitationStatus::Rejected);
        assert_eq!(resp.reason.unwrap(), "invalid_signature");
    }

    #[test]
    fn stats_serde_roundtrip() {
        let stats = FacilitatorStats {
            total_transactions: 42,
            total_volume_micro_usd: 1_000_000,
            total_fees_micro_usd: 1_500,
            total_rejected: 3,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: FacilitatorStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_transactions, 42);
        assert_eq!(back.total_volume_micro_usd, 1_000_000);
    }
}

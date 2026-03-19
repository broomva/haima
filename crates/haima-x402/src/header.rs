//! x402 HTTP header parsing and serialization.
//!
//! The x402 protocol uses three custom HTTP headers:
//! - `PAYMENT-REQUIRED`: Server → Client (payment terms in 402 response)
//! - `PAYMENT-SIGNATURE`: Client → Server (signed payment authorization)
//! - `PAYMENT-RESPONSE`: Server → Client (settlement confirmation in 200 response)

use base64::Engine;
use haima_core::HaimaResult;
use serde::{Deserialize, Serialize};

/// Header name for payment requirements (402 response).
pub const PAYMENT_REQUIRED_HEADER: &str = "payment-required";

/// Header name for payment signature (retry request).
pub const PAYMENT_SIGNATURE_HEADER: &str = "payment-signature";

/// Header name for payment response (200 response after settlement).
pub const PAYMENT_RESPONSE_HEADER: &str = "payment-response";

/// Payment requirements from a 402 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequiredHeader {
    /// Accepted payment schemes.
    pub schemes: Vec<SchemeRequirement>,
    /// Protocol version (e.g., "v2").
    pub version: String,
}

/// A single scheme requirement within the payment-required header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemeRequirement {
    /// Scheme type (e.g., "exact").
    pub scheme: String,
    /// Network in CAIP-2 format (e.g., "eip155:8453").
    pub network: String,
    /// Token contract address.
    pub token: String,
    /// Amount in the token's smallest unit.
    pub amount: String,
    /// Recipient address.
    pub recipient: String,
    /// Facilitator URL.
    pub facilitator: String,
}

/// Payment signature sent with a retry request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSignatureHeader {
    /// The scheme used for this payment.
    pub scheme: String,
    /// Network in CAIP-2 format.
    pub network: String,
    /// The cryptographic payload (base64-encoded signed authorization).
    pub payload: String,
}

/// Settlement confirmation from a 200 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponseHeader {
    /// Transaction hash.
    pub tx_hash: String,
    /// Network where settlement occurred.
    pub network: String,
    /// Whether settlement is confirmed.
    pub settled: bool,
}

/// Parse a base64-encoded JSON payment-required header value.
pub fn parse_payment_required(header_value: &str) -> HaimaResult<PaymentRequiredHeader> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(header_value.trim())
        .map_err(|e| haima_core::HaimaError::Protocol(format!("base64 decode failed: {e}")))?;
    let parsed = serde_json::from_slice(&decoded)?;
    Ok(parsed)
}

/// Encode a payment signature header to base64 JSON.
pub fn encode_payment_signature(sig: &PaymentSignatureHeader) -> HaimaResult<String> {
    let json = serde_json::to_vec(sig)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let header = PaymentRequiredHeader {
            schemes: vec![SchemeRequirement {
                scheme: "exact".into(),
                network: "eip155:8453".into(),
                token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
                amount: "10000".into(),
                recipient: "0xrecipient".into(),
                facilitator: "https://x402.org/facilitator".into(),
            }],
            version: "v2".into(),
        };
        let json = serde_json::to_vec(&header).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        let parsed = parse_payment_required(&encoded).unwrap();
        assert_eq!(parsed.schemes.len(), 1);
        assert_eq!(parsed.schemes[0].scheme, "exact");
    }
}

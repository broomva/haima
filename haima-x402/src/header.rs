//! x402 HTTP header parsing and serialization.
//!
//! The x402 protocol uses three custom HTTP headers:
//! - `PAYMENT-REQUIRED`: Server -> Client (payment terms in 402 response)
//! - `PAYMENT-SIGNATURE`: Client -> Server (signed payment authorization)
//! - `PAYMENT-RESPONSE`: Server -> Client (settlement confirmation in 200 response)
//!
//! All headers are encoded as base64(JSON). This module provides symmetric
//! parse/encode functions for each header type, enabling the full x402 flow.

use base64::Engine;
use haima_core::HaimaResult;
use serde::{Deserialize, Serialize};

/// Header name for payment requirements (402 response).
pub const PAYMENT_REQUIRED_HEADER: &str = "payment-required";

/// Header name for payment signature (retry request).
pub const PAYMENT_SIGNATURE_HEADER: &str = "payment-signature";

/// Header name for payment response (200 response after settlement).
pub const PAYMENT_RESPONSE_HEADER: &str = "payment-response";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Payment requirements from a 402 response.
///
/// Contains one or more accepted payment schemes that the client can fulfill.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymentRequiredHeader {
    /// Accepted payment schemes.
    pub schemes: Vec<SchemeRequirement>,
    /// Protocol version (e.g., "v2").
    pub version: String,
}

/// A single scheme requirement within the payment-required header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemeRequirement {
    /// Scheme type (e.g., "exact").
    pub scheme: String,
    /// Network in CAIP-2 format (e.g., "eip155:8453").
    pub network: String,
    /// Token contract address.
    pub token: String,
    /// Amount in the token's smallest unit (string to avoid precision issues).
    pub amount: String,
    /// Recipient address.
    pub recipient: String,
    /// Facilitator URL.
    pub facilitator: String,
    /// Seconds of validity for the signed authorization. Defaults to 600 (10 min).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_timeout_seconds: Option<u64>,
}

/// Payment signature sent with a retry request.
///
/// The client constructs this after signing the payment authorization
/// with the agent's wallet and sends it as the `payment-signature` header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymentSignatureHeader {
    /// The scheme used for this payment.
    pub scheme: String,
    /// Network in CAIP-2 format.
    pub network: String,
    /// The cryptographic payload — hex-encoded (r || s || v) recoverable ECDSA
    /// signature over the EIP-712 digest of [`authorization`](Self::authorization).
    pub payload: String,
    /// EIP-3009 authorization context that the signature authorizes.
    ///
    /// Absent for legacy EIP-191 canonical-string signatures produced before
    /// Phase F1. Facilitators reject authorizations that do not match the
    /// signed digest when this field is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Eip3009Authorization>,
}

/// EIP-3009 `TransferWithAuthorization` fields carried alongside the signature.
///
/// Uses string encoding for `uint256` values to avoid JSON precision issues and
/// hex encoding for addresses and nonces to match the x402 on-wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Eip3009Authorization {
    /// Payer address (`0x`-prefixed hex).
    pub from: String,
    /// Recipient address (`0x`-prefixed hex).
    pub to: String,
    /// Token amount in smallest unit (decimal string).
    pub value: String,
    /// Unix timestamp when the authorization becomes valid (decimal string).
    pub valid_after: String,
    /// Unix timestamp when the authorization expires (decimal string).
    pub valid_before: String,
    /// 32-byte nonce (`0x`-prefixed hex, 66 chars total).
    pub nonce: String,
}

/// Settlement confirmation from a 200 response.
///
/// Returned by the server after the facilitator confirms on-chain settlement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymentResponseHeader {
    /// Transaction hash.
    pub tx_hash: String,
    /// Network where settlement occurred.
    pub network: String,
    /// Whether settlement is confirmed.
    pub settled: bool,
}

// ---------------------------------------------------------------------------
// Encoding helpers (shared)
// ---------------------------------------------------------------------------

/// Decode a base64-encoded JSON header value into a typed struct.
fn decode_header<T: serde::de::DeserializeOwned>(header_value: &str) -> HaimaResult<T> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(header_value.trim())
        .map_err(|e| haima_core::HaimaError::Protocol(format!("base64 decode failed: {e}")))?;
    let parsed = serde_json::from_slice(&decoded)?;
    Ok(parsed)
}

/// Encode a typed struct as base64(JSON) for use as an HTTP header value.
fn encode_header<T: serde::Serialize>(value: &T) -> HaimaResult<String> {
    let json = serde_json::to_vec(value)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

// ---------------------------------------------------------------------------
// PAYMENT-REQUIRED header (402 response)
// ---------------------------------------------------------------------------

/// Parse a base64-encoded JSON `payment-required` header value.
///
/// The server sends this in an HTTP 402 response to describe what payment
/// the client must make to access the resource.
pub fn parse_payment_required(header_value: &str) -> HaimaResult<PaymentRequiredHeader> {
    decode_header(header_value)
}

/// Encode a `PaymentRequiredHeader` as base64(JSON) for the `payment-required` header.
///
/// Used by servers (or tests) to generate the 402 response header.
pub fn encode_payment_required(header: &PaymentRequiredHeader) -> HaimaResult<String> {
    encode_header(header)
}

// ---------------------------------------------------------------------------
// PAYMENT-SIGNATURE header (retry request)
// ---------------------------------------------------------------------------

/// Parse a base64-encoded JSON `payment-signature` header value.
///
/// The server uses this to extract the client's signed payment authorization
/// before forwarding it to the facilitator for verification and settlement.
pub fn parse_payment_signature(header_value: &str) -> HaimaResult<PaymentSignatureHeader> {
    decode_header(header_value)
}

/// Encode a `PaymentSignatureHeader` as base64(JSON) for the `payment-signature` header.
///
/// The client uses this to attach the signed payment to the retry request.
pub fn encode_payment_signature(sig: &PaymentSignatureHeader) -> HaimaResult<String> {
    encode_header(sig)
}

// ---------------------------------------------------------------------------
// PAYMENT-RESPONSE header (200 response after settlement)
// ---------------------------------------------------------------------------

/// Parse a base64-encoded JSON `payment-response` header value.
///
/// The client reads this from the 200 response to confirm on-chain settlement
/// and extract the transaction hash.
pub fn parse_payment_response(header_value: &str) -> HaimaResult<PaymentResponseHeader> {
    decode_header(header_value)
}

/// Encode a `PaymentResponseHeader` as base64(JSON) for the `payment-response` header.
///
/// The server uses this to attach settlement confirmation to the 200 response.
pub fn encode_payment_response(response: &PaymentResponseHeader) -> HaimaResult<String> {
    encode_header(response)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- PaymentRequiredHeader round-trip --

    fn sample_payment_required() -> PaymentRequiredHeader {
        PaymentRequiredHeader {
            schemes: vec![SchemeRequirement {
                scheme: "exact".into(),
                network: "eip155:8453".into(),
                token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
                amount: "10000".into(),
                recipient: "0xrecipient".into(),
                facilitator: "https://x402.org/facilitator".into(),
                max_timeout_seconds: None,
            }],
            version: "v2".into(),
        }
    }

    #[test]
    fn payment_required_roundtrip() {
        let original = sample_payment_required();
        let encoded = encode_payment_required(&original).unwrap();
        let decoded = parse_payment_required(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn payment_required_multiple_schemes() {
        let header = PaymentRequiredHeader {
            schemes: vec![
                SchemeRequirement {
                    scheme: "exact".into(),
                    network: "eip155:8453".into(),
                    token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
                    amount: "10000".into(),
                    recipient: "0xrecipient".into(),
                    facilitator: "https://x402.org/facilitator".into(),
                    max_timeout_seconds: None,
                },
                SchemeRequirement {
                    scheme: "exact".into(),
                    network: "eip155:1".into(),
                    token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".into(),
                    amount: "10000".into(),
                    recipient: "0xrecipient".into(),
                    facilitator: "https://x402.org/facilitator".into(),
                    max_timeout_seconds: None,
                },
            ],
            version: "v2".into(),
        };
        let encoded = encode_payment_required(&header).unwrap();
        let decoded = parse_payment_required(&encoded).unwrap();
        assert_eq!(decoded.schemes.len(), 2);
        assert_eq!(decoded.schemes[0].network, "eip155:8453");
        assert_eq!(decoded.schemes[1].network, "eip155:1");
    }

    #[test]
    fn payment_required_invalid_base64() {
        let result = parse_payment_required("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn payment_required_invalid_json() {
        // Valid base64 but not valid JSON for our type
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"not json");
        let result = parse_payment_required(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn payment_required_trims_whitespace() {
        let original = sample_payment_required();
        let encoded = encode_payment_required(&original).unwrap();
        // Add whitespace around the value (as HTTP headers sometimes have)
        let padded = format!("  {encoded}  ");
        let decoded = parse_payment_required(&padded).unwrap();
        assert_eq!(original, decoded);
    }

    // -- PaymentSignatureHeader round-trip --

    fn sample_payment_signature() -> PaymentSignatureHeader {
        PaymentSignatureHeader {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            payload: "0xdeadbeef1234567890abcdef".into(),
            authorization: None,
        }
    }

    #[test]
    fn payment_signature_roundtrip() {
        let original = sample_payment_signature();
        let encoded = encode_payment_signature(&original).unwrap();
        let decoded = parse_payment_signature(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn payment_signature_invalid_base64() {
        let result = parse_payment_signature("%%%invalid%%%");
        assert!(result.is_err());
    }

    // -- PaymentResponseHeader round-trip --

    fn sample_payment_response() -> PaymentResponseHeader {
        PaymentResponseHeader {
            tx_hash: "0xabc123def456789".into(),
            network: "eip155:8453".into(),
            settled: true,
        }
    }

    #[test]
    fn payment_response_roundtrip() {
        let original = sample_payment_response();
        let encoded = encode_payment_response(&original).unwrap();
        let decoded = parse_payment_response(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn payment_response_unsettled() {
        let response = PaymentResponseHeader {
            tx_hash: "0xpending".into(),
            network: "eip155:8453".into(),
            settled: false,
        };
        let encoded = encode_payment_response(&response).unwrap();
        let decoded = parse_payment_response(&encoded).unwrap();
        assert!(!decoded.settled);
        assert_eq!(decoded.tx_hash, "0xpending");
    }

    #[test]
    fn payment_response_invalid_base64() {
        let result = parse_payment_response("not-base64");
        assert!(result.is_err());
    }

    // -- Cross-type safety: ensure headers don't accidentally deserialize as wrong type --

    #[test]
    fn cross_type_mismatch_fails() {
        // Encode a PaymentResponseHeader and try to parse it as PaymentRequiredHeader
        let response = sample_payment_response();
        let encoded = encode_payment_response(&response).unwrap();
        let result = parse_payment_required(&encoded);
        // Should fail because PaymentRequiredHeader expects "schemes" and "version" fields
        assert!(result.is_err());
    }
}

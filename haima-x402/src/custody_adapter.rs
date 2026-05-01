//! Spec D D-Sub-A — custody-backed `WalletBackend` adapter.
//!
//! Glue between `anima_identity::AnimaCustody` and `haima_wallet::WalletBackend`
//! so the `X402Client` can consume an `Arc<dyn AnimaCustody>` instead of a
//! `LocalSigner` (raw secp256k1 private key in process memory).
//!
//! The adapter forwards every wallet operation through the custody trait:
//! - `sign_transfer_authorization` — packs the EIP-3009 fields into a JSON
//!   message and calls `custody.sign_eip712()`.
//! - `sign_typed_data` — currently unsupported through the trait abstraction
//!   (see `// SPEC-D-DEVIATION` in `anima_identity::custody`); returns a
//!   `Crypto` error so callers fall back to `LocalSigner` for non-EIP-3009
//!   typed-data signing in D-Sub-A.
//! - `sign_message` — same: returns a `Crypto` error in D-Sub-A; lifted in
//!   a follow-up sub-phase (the only `sign_message` consumer today is x402
//!   debug paths that aren't on the production hot path).
//!
//! Feature-gated under `custody-adapter` to keep the haima-x402 dep graph
//! lean for callers that don't need anima.

use std::sync::Arc;

use anima_identity::custody::{AnimaCustody, Eip712Domain};
use async_trait::async_trait;
use haima_core::{HaimaError, HaimaResult, WalletAddress};
use haima_wallet::{USDC_BASE_MAINNET, USDC_BASE_SEPOLIA, WalletBackend};

/// `WalletBackend` impl backed by an `Arc<dyn AnimaCustody>`.
///
/// Every wallet-half operation goes through the custody trait. The auth
/// half is intentionally NOT exposed — payment flows only need the wallet
/// half.
pub struct CustodyWalletAdapter {
    custody: Arc<dyn AnimaCustody>,
    address: WalletAddress,
}

impl CustodyWalletAdapter {
    /// Construct from an `Arc<dyn AnimaCustody>`. Errors if the custody
    /// backend has no resolved wallet half (e.g., a bare `WebCryptoAnima`
    /// that hasn't been paired with a `RemoteAnima` yet).
    pub fn from_custody(custody: Arc<dyn AnimaCustody>) -> HaimaResult<Self> {
        let address = custody.wallet_address().cloned().ok_or_else(|| {
            HaimaError::Crypto(
                "custody backend did not resolve a wallet address (browser-only deployments \
                     must pair with a server-side wallet backend)"
                    .to_string(),
            )
        })?;
        Ok(Self { custody, address })
    }
}

#[async_trait]
impl WalletBackend for CustodyWalletAdapter {
    fn address(&self) -> &WalletAddress {
        &self.address
    }

    async fn sign_message(&self, _message: &[u8]) -> HaimaResult<Vec<u8>> {
        // Spec D L4-D7 keeps wallet ops on secp256k1 + EIP-712 / EIP-3009.
        // Generic EIP-191 personal-sign isn't on the D-Sub-A trait surface;
        // callers needing it should fall back to `LocalSigner`.
        Err(HaimaError::Crypto(
            "custody-backed sign_message: deferred to D-Sub-B (use LocalSigner for personal-sign)"
                .to_string(),
        ))
    }

    async fn sign_typed_data(&self, _hash: &[u8; 32]) -> HaimaResult<Vec<u8>> {
        // The custody trait signs typed-data through `sign_eip712`, which
        // takes the structured payload (not a pre-computed digest). Generic
        // pre-computed-digest signing is not exposed (would defeat the
        // KMS abstraction's audit log).
        Err(HaimaError::Crypto(
            "custody-backed sign_typed_data: not supported in D-Sub-A (use sign_eip712)"
                .to_string(),
        ))
    }

    async fn sign_transfer_authorization(
        &self,
        from: &str,
        to: &str,
        value: u64,
        valid_after: u64,
        valid_before: u64,
        nonce: &[u8; 32],
    ) -> HaimaResult<Vec<u8>> {
        // Pick the USDC EIP-712 domain for the wallet's chain.
        let domain = match self.address.chain.0.as_str() {
            "eip155:8453" => USDC_BASE_MAINNET,
            "eip155:84532" => USDC_BASE_SEPOLIA,
            other => {
                return Err(HaimaError::Crypto(format!(
                    "no USDC EIP-712 domain registered for chain {other}"
                )));
            }
        };
        // The custody trait takes `&Eip712Domain` (re-exported from
        // haima-wallet), so the cast is direct.
        let domain_ref: &Eip712Domain = &domain;

        let types = serde_json::json!({
            "primaryType": "TransferWithAuthorization",
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"}
            ]
        });
        let message = serde_json::json!({
            "from": from,
            "to": to,
            "value": value.to_string(),
            "validAfter": valid_after.to_string(),
            "validBefore": valid_before.to_string(),
            "nonce": format!("0x{}", hex::encode(nonce)),
        });

        let sig = self
            .custody
            .sign_eip712(domain_ref, &types, &message)
            .map_err(|e| HaimaError::Crypto(format!("custody sign_eip712: {e}")))?;
        Ok(sig.bytes)
    }

    fn backend_type(&self) -> &str {
        "custody-adapter"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anima_identity::InProcessAnima;

    #[tokio::test]
    async fn adapter_signs_eip3009_via_custody() {
        let custody = InProcessAnima::generate_dev().unwrap();
        let adapter = CustodyWalletAdapter::from_custody(custody.clone()).unwrap();

        let from = adapter.address().address.clone();
        let to = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
        let nonce = [0x42u8; 32];

        let sig = adapter
            .sign_transfer_authorization(&from, to, 100, 1_700_000_000, 1_700_000_600, &nonce)
            .await
            .unwrap();
        assert_eq!(sig.len(), 65);
        let v = sig[64];
        assert!(v == 27 || v == 28);
    }

    #[tokio::test]
    async fn adapter_returns_wallet_address_from_custody() {
        let custody = InProcessAnima::generate_dev().unwrap();
        let adapter = CustodyWalletAdapter::from_custody(custody.clone()).unwrap();

        let expected = custody.wallet_address().unwrap().address.clone();
        assert_eq!(adapter.address().address, expected);
        assert_eq!(adapter.backend_type(), "custody-adapter");
    }

    #[tokio::test]
    async fn adapter_sign_message_returns_deferred_error() {
        let custody = InProcessAnima::generate_dev().unwrap();
        let adapter = CustodyWalletAdapter::from_custody(custody).unwrap();
        let result = adapter.sign_message(b"hello").await;
        assert!(result.is_err());
    }
}

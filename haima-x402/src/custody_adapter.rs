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
use haima_core::{ChainId, HaimaError, HaimaResult, WalletAddress};
use haima_wallet::{WalletBackend, usdc_domain_for_chain};

/// `WalletBackend` impl backed by an `Arc<dyn AnimaCustody>`.
///
/// Every wallet-half operation goes through the custody trait. The auth
/// half is intentionally NOT exposed — payment flows only need the wallet
/// half.
pub struct CustodyWalletAdapter {
    custody: Arc<dyn AnimaCustody>,
    address: WalletAddress,
    signing_chain: ChainId,
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
        let signing_chain = address.chain.clone();
        Ok(Self {
            custody,
            address,
            signing_chain,
        })
    }

    /// Construct a custody-backed wallet adapter that signs for an explicit
    /// payment network.
    ///
    /// The custody backend's canonical [`WalletAddress`] may carry a different
    /// CAIP-2 label than the payment network being signed. For EVM wallets this
    /// is valid: the secp256k1 key controls the same 20-byte address on every
    /// EVM chain, while the EIP-712 domain's `chainId` must match the payment
    /// network being authorized.
    pub fn from_custody_on_network(
        custody: Arc<dyn AnimaCustody>,
        network: ChainId,
    ) -> HaimaResult<Self> {
        let address = custody.wallet_address().cloned().ok_or_else(|| {
            HaimaError::Crypto(
                "custody backend did not resolve a wallet address (browser-only deployments \
                     must pair with a server-side wallet backend)"
                    .to_string(),
            )
        })?;
        Ok(Self {
            custody,
            address,
            signing_chain: network,
        })
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
        // Pick the USDC EIP-712 domain for the target payment network, which
        // may differ from the custody wallet's canonical CAIP-2 label.
        let domain = usdc_domain_for_chain(&self.signing_chain)?;
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
    use haima_wallet::{
        USDC_BASE_MAINNET, USDC_BASE_SEPOLIA, hash_transfer_authorization, parse_eth_address,
    };
    use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    fn recover_address(signature_bytes: &[u8], digest: &[u8; 32]) -> String {
        let signature = EcdsaSignature::from_slice(&signature_bytes[..64]).unwrap();
        let recid = RecoveryId::try_from(signature_bytes[64] - 27).unwrap();
        let recovered = VerifyingKey::recover_from_prehash(digest, &signature, recid).unwrap();
        let pubkey = recovered.to_encoded_point(false);
        let hash = Keccak256::digest(&pubkey.as_bytes()[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

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
    async fn adapter_signs_base_sepolia_with_sepolia_domain() {
        let custody = InProcessAnima::generate_dev().unwrap();
        let sepolia_adapter =
            CustodyWalletAdapter::from_custody_on_network(custody.clone(), ChainId::base_sepolia())
                .unwrap();
        let mainnet_adapter =
            CustodyWalletAdapter::from_custody_on_network(custody.clone(), ChainId::base())
                .unwrap();

        let from = sepolia_adapter.address().address.clone();
        let to = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
        let nonce = [0x11u8; 32];
        let value = 123u64;
        let valid_after = 1_700_000_000u64;
        let valid_before = 1_700_000_600u64;

        let sepolia_sig = sepolia_adapter
            .sign_transfer_authorization(&from, to, value, valid_after, valid_before, &nonce)
            .await
            .unwrap();
        let mainnet_sig = mainnet_adapter
            .sign_transfer_authorization(&from, to, value, valid_after, valid_before, &nonce)
            .await
            .unwrap();

        assert_eq!(sepolia_sig.len(), 65);
        assert!(matches!(sepolia_sig[64], 27 | 28));
        assert_ne!(
            sepolia_sig, mainnet_sig,
            "different EIP-712 domains must produce different signatures"
        );

        let from_bytes = parse_eth_address(&from).unwrap();
        let to_bytes = parse_eth_address(to).unwrap();
        let sepolia_digest = hash_transfer_authorization(
            &USDC_BASE_SEPOLIA,
            &from_bytes,
            &to_bytes,
            value,
            valid_after,
            valid_before,
            &nonce,
        );
        let mainnet_digest = hash_transfer_authorization(
            &USDC_BASE_MAINNET,
            &from_bytes,
            &to_bytes,
            value,
            valid_after,
            valid_before,
            &nonce,
        );

        let recovered = recover_address(&sepolia_sig, &sepolia_digest);
        assert_eq!(recovered.to_lowercase(), from.to_lowercase());
        assert_ne!(
            recover_address(&sepolia_sig, &mainnet_digest).to_lowercase(),
            from.to_lowercase(),
            "a sepolia-domain signature must not validate against the mainnet domain digest"
        );
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

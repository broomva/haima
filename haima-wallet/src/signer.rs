//! Local signer — implements `WalletBackend` using a local secp256k1 private key.

use async_trait::async_trait;
use haima_core::HaimaResult;
use haima_core::wallet::WalletAddress;
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::backend::WalletBackend;
use crate::eip712::{hash_transfer_authorization, parse_eth_address, usdc_domain_for_chain};
use crate::evm::derive_address;

/// A local wallet that signs with an in-memory secp256k1 private key.
///
/// The private key is zeroized on drop to prevent leakage.
pub struct LocalSigner {
    signing_key: SigningKey,
    address: WalletAddress,
}

impl LocalSigner {
    /// Create a signer from raw private key bytes.
    pub fn from_bytes(
        private_key: &Zeroizing<Vec<u8>>,
        chain: haima_core::wallet::ChainId,
    ) -> HaimaResult<Self> {
        let signing_key = SigningKey::from_bytes(private_key.as_slice().into())
            .map_err(|e| haima_core::HaimaError::Crypto(format!("invalid private key: {e}")))?;
        let addr = derive_address(&signing_key);
        Ok(Self {
            signing_key,
            address: WalletAddress {
                address: addr,
                chain,
            },
        })
    }

    /// Create a new signer with a randomly generated keypair.
    pub fn generate(chain: haima_core::wallet::ChainId) -> HaimaResult<Self> {
        let (key_bytes, _) = crate::evm::generate_keypair()?;
        Self::from_bytes(&key_bytes, chain)
    }
}

#[async_trait]
impl WalletBackend for LocalSigner {
    fn address(&self) -> &WalletAddress {
        &self.address
    }

    async fn sign_message(&self, message: &[u8]) -> HaimaResult<Vec<u8>> {
        // EIP-191 personal sign: hash with prefix
        let prefixed = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefixed.as_bytes());
        hasher.update(message);
        let hash = hasher.finalize();

        let signature: Signature = self.signing_key.sign(&hash);
        Ok(signature.to_vec())
    }

    async fn sign_typed_data(&self, hash: &[u8; 32]) -> HaimaResult<Vec<u8>> {
        let signature: Signature = self.signing_key.sign(hash);
        Ok(signature.to_vec())
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
        // Resolve the USDC EIP-712 domain for this signer's chain.
        let domain = usdc_domain_for_chain(&self.address.chain)?;
        let from_bytes = parse_eth_address(from)?;
        let to_bytes = parse_eth_address(to)?;

        let digest = hash_transfer_authorization(
            &domain,
            &from_bytes,
            &to_bytes,
            value,
            valid_after,
            valid_before,
            nonce,
        );

        // Recoverable ECDSA over secp256k1 — produces (r, s, recovery_id).
        // Callers / facilitators reconstruct the signer's address via ecrecover,
        // so the recovery byte must be present.
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .map_err(|e| haima_core::HaimaError::Crypto(format!("EIP-3009 signing failed: {e}")))?;

        // Concatenate r (32) || s (32) || v (1). Use the legacy v encoding
        // ({27, 28}) that EIP-3009 verifiers and ecrecover both accept.
        let rs = sig.to_bytes();
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(rs.as_slice());
        out.push(recid.to_byte() + 27);
        Ok(out)
    }

    fn backend_type(&self) -> &str {
        "local"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eip712::{USDC_BASE_MAINNET, hash_transfer_authorization};
    use haima_core::wallet::ChainId;
    use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey};
    use zeroize::Zeroizing;

    #[test]
    fn local_signer_from_bytes() {
        let key = Zeroizing::new(vec![1u8; 32]);
        let signer = LocalSigner::from_bytes(&key, ChainId::base()).unwrap();
        assert!(signer.address().address.starts_with("0x"));
        assert_eq!(signer.backend_type(), "local");
    }

    #[test]
    fn local_signer_generate() {
        let signer = LocalSigner::generate(ChainId::base()).unwrap();
        assert!(signer.address().address.starts_with("0x"));
        assert_eq!(signer.address().address.len(), 42);
    }

    #[tokio::test]
    async fn sign_message_produces_output() {
        let signer = LocalSigner::generate(ChainId::base()).unwrap();
        let sig = signer.sign_message(b"hello haima").await.unwrap();
        assert!(!sig.is_empty());
    }

    #[tokio::test]
    async fn sign_transfer_authorization_returns_65_byte_recoverable_signature() {
        let signer = LocalSigner::generate(ChainId::base()).unwrap();
        let from = signer.address().address.clone();
        let to = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
        let nonce = [0x42u8; 32];
        let sig = signer
            .sign_transfer_authorization(&from, to, 1_000_000, 1_700_000_000, 1_700_000_600, &nonce)
            .await
            .unwrap();
        assert_eq!(sig.len(), 65, "recoverable ECDSA is r||s||v = 65 bytes");
        let v = sig[64];
        assert!(v == 27 || v == 28, "v must be 27 or 28 (legacy encoding)");
    }

    #[tokio::test]
    async fn sign_transfer_authorization_round_trips_via_ecrecover() {
        // This is the functional test: the signature must recover to the
        // signer's own address. If EIP-712 digest computation, signing, or
        // v-byte encoding is off, this fails.
        let signer = LocalSigner::generate(ChainId::base()).unwrap();
        let from = signer.address().address.clone();
        let to = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
        let nonce = [0x13u8; 32];
        let value = 50_000u64;
        let valid_after = 1_700_000_000u64;
        let valid_before = 1_700_000_600u64;

        let sig_bytes = signer
            .sign_transfer_authorization(&from, to, value, valid_after, valid_before, &nonce)
            .await
            .unwrap();

        let from_bytes = crate::eip712::parse_eth_address(&from).unwrap();
        let to_bytes = crate::eip712::parse_eth_address(to).unwrap();
        let digest = hash_transfer_authorization(
            &USDC_BASE_MAINNET,
            &from_bytes,
            &to_bytes,
            value,
            valid_after,
            valid_before,
            &nonce,
        );

        let signature = EcdsaSignature::from_slice(&sig_bytes[..64]).unwrap();
        let recid = RecoveryId::try_from(sig_bytes[64] - 27).unwrap();
        let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, recid)
            .expect("signature must recover");

        // Derive EVM address from the recovered public key and compare to the
        // signer's address. If the digest, signing, or v byte is wrong, this
        // fails.
        let pubkey = recovered.to_encoded_point(false);
        let hash = Keccak256::digest(&pubkey.as_bytes()[1..]);
        let recovered_address = format!("0x{}", hex::encode(&hash[12..]));
        assert_eq!(recovered_address.to_lowercase(), from.to_lowercase());
    }

    #[tokio::test]
    async fn sign_transfer_authorization_rejects_unsupported_chain() {
        let signer = LocalSigner::generate(ChainId::ethereum()).unwrap();
        let result = signer
            .sign_transfer_authorization(
                "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                100,
                0,
                u64::MAX,
                &[0u8; 32],
            )
            .await;
        assert!(
            result.is_err(),
            "ethereum mainnet USDC domain not registered"
        );
    }

    #[tokio::test]
    async fn sign_transfer_authorization_rejects_malformed_address() {
        let signer = LocalSigner::generate(ChainId::base()).unwrap();
        let result = signer
            .sign_transfer_authorization(
                "not-an-address",
                "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                100,
                0,
                u64::MAX,
                &[0u8; 32],
            )
            .await;
        assert!(result.is_err());
    }
}

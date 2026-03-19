//! Local signer — implements WalletBackend using a local secp256k1 private key.

use async_trait::async_trait;
use haima_core::wallet::WalletAddress;
use haima_core::HaimaResult;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::backend::WalletBackend;
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
        _from: &str,
        _to: &str,
        _value: u64,
        _valid_after: u64,
        _valid_before: u64,
        _nonce: &[u8; 32],
    ) -> HaimaResult<Vec<u8>> {
        // EIP-3009 transferWithAuthorization signing.
        // Full implementation requires EIP-712 typed data hashing with the
        // USDC contract's domain separator. Stubbed for Phase F0 — will be
        // completed when integrating x402-rs in Phase F1.
        Err(haima_core::HaimaError::Crypto(
            "EIP-3009 signing not yet implemented — pending x402-rs integration".into(),
        ))
    }

    fn backend_type(&self) -> &str {
        "local"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use haima_core::wallet::ChainId;
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
}

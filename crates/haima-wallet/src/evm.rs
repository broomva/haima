//! EVM wallet — secp256k1 keypair generation and Ethereum address derivation.

use haima_core::wallet::{ChainId, WalletAddress};
use haima_core::HaimaResult;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// Generate a new random secp256k1 keypair and derive the EVM address.
pub fn generate_keypair() -> HaimaResult<(Zeroizing<Vec<u8>>, WalletAddress)> {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::random(&mut rng);
    let private_key_bytes = Zeroizing::new(signing_key.to_bytes().to_vec());
    let address = derive_address(&signing_key);
    let wallet = WalletAddress {
        address,
        chain: ChainId::base(),
    };
    Ok((private_key_bytes, wallet))
}

/// Derive an Ethereum-compatible address from a secp256k1 signing key.
///
/// Address = `0x` + last 20 bytes of `keccak256(uncompressed_public_key[1..])`.
pub fn derive_address(signing_key: &SigningKey) -> String {
    #[allow(unused_imports)]
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    // Skip the 0x04 prefix byte, hash the remaining 64 bytes
    let hash = Keccak256::digest(&public_key.as_bytes()[1..]);
    // Take the last 20 bytes as the address
    let address_bytes = &hash[12..];
    format!("0x{}", hex::encode(address_bytes))
}

/// Encrypt a private key using ChaCha20-Poly1305 with a derived key.
///
/// Returns `(nonce, ciphertext)` suitable for storage as a Lago blob.
pub fn encrypt_private_key(
    private_key: &[u8],
    encryption_key: &[u8; 32],
) -> HaimaResult<(Vec<u8>, Vec<u8>)> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    let cipher = ChaCha20Poly1305::new(encryption_key.into());
    let nonce_bytes: [u8; 12] = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, private_key)
        .map_err(|e| haima_core::HaimaError::Crypto(format!("encryption failed: {e}")))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt a private key from ChaCha20-Poly1305 ciphertext.
pub fn decrypt_private_key(
    nonce: &[u8],
    ciphertext: &[u8],
    encryption_key: &[u8; 32],
) -> HaimaResult<Zeroizing<Vec<u8>>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    let cipher = ChaCha20Poly1305::new(encryption_key.into());
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| haima_core::HaimaError::Crypto(format!("decryption failed: {e}")))?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_address() {
        let (key, wallet) = generate_keypair().unwrap();
        assert!(!key.is_empty());
        assert!(wallet.address.starts_with("0x"));
        assert_eq!(wallet.address.len(), 42); // 0x + 40 hex chars
        assert!(wallet.chain.is_evm());
    }

    #[test]
    fn derive_address_deterministic() {
        let signing_key =
            SigningKey::from_bytes(&[1u8; 32].into()).unwrap();
        let addr1 = derive_address(&signing_key);
        let addr2 = derive_address(&signing_key);
        assert_eq!(addr1, addr2);
        assert!(addr1.starts_with("0x"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let private_key = b"test_private_key_32_bytes_long!!";
        let encryption_key = &[42u8; 32];

        let (nonce, ciphertext) =
            encrypt_private_key(private_key, encryption_key).unwrap();
        let decrypted =
            decrypt_private_key(&nonce, &ciphertext, encryption_key).unwrap();

        assert_eq!(&*decrypted, private_key);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let private_key = b"test_private_key_32_bytes_long!!";
        let encryption_key = &[42u8; 32];
        let wrong_key = &[0u8; 32];

        let (nonce, ciphertext) =
            encrypt_private_key(private_key, encryption_key).unwrap();
        let result = decrypt_private_key(&nonce, &ciphertext, wrong_key);
        assert!(result.is_err());
    }
}

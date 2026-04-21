//! EIP-712 typed-data hashing for EIP-3009 `transferWithAuthorization`.
//!
//! This module implements just enough of [EIP-712] and [EIP-3009] to produce
//! the 32-byte digest that Haima signs when authorizing USDC transfers for
//! x402 payments. The digest is built as:
//!
//! ```text
//! digest = keccak256("\x19\x01" || domainSeparator || structHash)
//! ```
//!
//! where:
//!
//! ```text
//! domainSeparator = keccak256(abi.encode(
//!     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
//!     keccak256(name), keccak256(version), chainId, verifyingContract))
//!
//! structHash = keccak256(abi.encode(
//!     keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"),
//!     from, to, value, validAfter, validBefore, nonce))
//! ```
//!
//! Solidity `abi.encode` left-pads `address` and `uint256` values to 32 bytes.
//!
//! Only Base mainnet and Base Sepolia USDC domains are registered here; other
//! chains return [`HaimaError::Crypto`] from [`usdc_domain_for_chain`].
//!
//! [EIP-712]: https://eips.ethereum.org/EIPS/eip-712
//! [EIP-3009]: https://eips.ethereum.org/EIPS/eip-3009

use haima_core::wallet::ChainId;
use haima_core::{HaimaError, HaimaResult};
use sha3::{Digest, Keccak256};

/// USDC on Base mainnet (`eip155:8453`, [FiatTokenV2][usdc]).
///
/// [usdc]: https://basescan.org/address/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
pub const USDC_BASE_MAINNET: Eip712Domain = Eip712Domain {
    name: "USD Coin",
    version: "2",
    chain_id: 8453,
    verifying_contract: [
        0x83, 0x35, 0x89, 0xfc, 0xd6, 0xed, 0xb6, 0xe0, 0x8f, 0x4c, 0x7c, 0x32, 0xd4, 0xf7, 0x1b,
        0x54, 0xbd, 0xa0, 0x29, 0x13,
    ],
};

/// USDC on Base Sepolia (`eip155:84532`, [FiatTokenV2][usdc]).
///
/// [usdc]: https://sepolia.basescan.org/address/0x036CbD53842c5426634e7929541eC2318f3dCF7e
pub const USDC_BASE_SEPOLIA: Eip712Domain = Eip712Domain {
    name: "USDC",
    version: "2",
    chain_id: 84532,
    verifying_contract: [
        0x03, 0x6c, 0xbd, 0x53, 0x84, 0x2c, 0x54, 0x26, 0x63, 0x4e, 0x79, 0x29, 0x54, 0x1e, 0xc2,
        0x31, 0x8f, 0x3d, 0xcf, 0x7e,
    ],
};

/// Parameters that parameterize an EIP-712 domain separator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eip712Domain {
    /// Contract `name` (EIP-712 string field).
    pub name: &'static str,
    /// Contract `version` (EIP-712 string field).
    pub version: &'static str,
    /// EVM chain id.
    pub chain_id: u64,
    /// 20-byte verifying contract address.
    pub verifying_contract: [u8; 20],
}

impl Eip712Domain {
    /// Compute the EIP-712 domain separator for this domain.
    pub fn separator(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(5 * 32);
        buf.extend_from_slice(&domain_type_hash());
        buf.extend_from_slice(&keccak256(self.name.as_bytes()));
        buf.extend_from_slice(&keccak256(self.version.as_bytes()));
        buf.extend_from_slice(&u64_as_u256_be(self.chain_id));
        buf.extend_from_slice(&address_padded(&self.verifying_contract));
        keccak256(&buf)
    }
}

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
pub fn domain_type_hash() -> [u8; 32] {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

/// `keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")`.
///
/// Matches the constant in Circle's [FiatTokenV2][fiat] USDC contract.
///
/// [fiat]: https://github.com/circlefin/stablecoin-evm/blob/master/contracts/v2/FiatTokenV2.sol
pub fn transfer_with_authorization_typehash() -> [u8; 32] {
    keccak256(
        b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    )
}

/// Compute the EIP-712 digest for an EIP-3009 `transferWithAuthorization`.
///
/// Returns the 32-byte prehash ready to be signed with a recoverable ECDSA
/// signature over secp256k1.
pub fn hash_transfer_authorization(
    domain: &Eip712Domain,
    from: &[u8; 20],
    to: &[u8; 20],
    value: u64,
    valid_after: u64,
    valid_before: u64,
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut struct_buf = Vec::with_capacity(7 * 32);
    struct_buf.extend_from_slice(&transfer_with_authorization_typehash());
    struct_buf.extend_from_slice(&address_padded(from));
    struct_buf.extend_from_slice(&address_padded(to));
    struct_buf.extend_from_slice(&u64_as_u256_be(value));
    struct_buf.extend_from_slice(&u64_as_u256_be(valid_after));
    struct_buf.extend_from_slice(&u64_as_u256_be(valid_before));
    struct_buf.extend_from_slice(nonce);
    let struct_hash = keccak256(&struct_buf);

    let mut digest_buf = Vec::with_capacity(2 + 64);
    digest_buf.extend_from_slice(b"\x19\x01");
    digest_buf.extend_from_slice(&domain.separator());
    digest_buf.extend_from_slice(&struct_hash);
    keccak256(&digest_buf)
}

/// Pick the USDC EIP-712 domain registered for a chain id.
pub fn usdc_domain_for_chain(chain: &ChainId) -> HaimaResult<Eip712Domain> {
    match chain.0.as_str() {
        "eip155:8453" => Ok(USDC_BASE_MAINNET),
        "eip155:84532" => Ok(USDC_BASE_SEPOLIA),
        other => Err(HaimaError::Crypto(format!(
            "no USDC EIP-712 domain registered for chain {other}"
        ))),
    }
}

/// Parse a `0x`-prefixed Ethereum address into 20 raw bytes.
pub fn parse_eth_address(s: &str) -> HaimaResult<[u8; 20]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed)
        .map_err(|e| HaimaError::Crypto(format!("invalid hex in address '{s}': {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        HaimaError::Crypto(format!("address must be 20 bytes, got {}", v.len()))
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn keccak256(data: &[u8]) -> [u8; 32] {
    let result = Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn u64_as_u256_be(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn address_padded(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str.trim_start_matches("0x")).expect("valid hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// Well-known EIP-712 constant — any deviation means our keccak256 wiring
    /// is wrong, not the spec.
    #[test]
    fn domain_type_hash_matches_eip712_spec() {
        let expected = hex32("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");
        assert_eq!(domain_type_hash(), expected);
    }

    /// Matches the `TRANSFER_WITH_AUTHORIZATION_TYPEHASH` constant baked into
    /// every Circle FiatTokenV2 deployment.
    #[test]
    fn transfer_with_authorization_typehash_matches_circle_fiattokenv2() {
        let expected = hex32("7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267");
        assert_eq!(transfer_with_authorization_typehash(), expected);
    }

    /// Domain separator must depend on every field — flipping one byte of the
    /// verifying contract must produce a different separator.
    #[test]
    fn domain_separator_is_sensitive_to_every_field() {
        let base = USDC_BASE_MAINNET;
        let base_sep = base.separator();

        let mut mutated = base;
        mutated.verifying_contract[0] ^= 0x01;
        let mutated_sep = mutated.separator();
        assert_ne!(base_sep, mutated_sep);

        let mut mutated_chain = base;
        mutated_chain.chain_id = 1;
        assert_ne!(base_sep, mutated_chain.separator());

        let mut mutated_name = base;
        mutated_name.name = "Tether";
        assert_ne!(base_sep, mutated_name.separator());

        let mut mutated_version = base;
        mutated_version.version = "1";
        assert_ne!(base_sep, mutated_version.separator());
    }

    /// Mainnet and Sepolia must produce different separators (chain id differs).
    #[test]
    fn mainnet_and_sepolia_separators_differ() {
        assert_ne!(USDC_BASE_MAINNET.separator(), USDC_BASE_SEPOLIA.separator());
    }

    /// Deterministic: same inputs produce the same digest.
    #[test]
    fn transfer_authorization_digest_is_deterministic() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let nonce = [0x33u8; 32];
        let d1 = hash_transfer_authorization(
            &USDC_BASE_MAINNET,
            &from,
            &to,
            1_000_000,
            1_700_000_000,
            1_700_000_600,
            &nonce,
        );
        let d2 = hash_transfer_authorization(
            &USDC_BASE_MAINNET,
            &from,
            &to,
            1_000_000,
            1_700_000_000,
            1_700_000_600,
            &nonce,
        );
        assert_eq!(d1, d2);
    }

    /// Digest is sensitive to each input — changing nonce changes digest.
    #[test]
    fn transfer_authorization_digest_is_nonce_sensitive() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let d1 = hash_transfer_authorization(
            &USDC_BASE_MAINNET,
            &from,
            &to,
            1_000_000,
            1_700_000_000,
            1_700_000_600,
            &[0x33u8; 32],
        );
        let d2 = hash_transfer_authorization(
            &USDC_BASE_MAINNET,
            &from,
            &to,
            1_000_000,
            1_700_000_000,
            1_700_000_600,
            &[0x44u8; 32],
        );
        assert_ne!(d1, d2);
    }

    /// Same EIP-3009 struct on different chains must produce different digests
    /// (replay protection across chains).
    #[test]
    fn transfer_authorization_digest_is_chain_scoped() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let nonce = [0x33u8; 32];
        let mainnet = hash_transfer_authorization(
            &USDC_BASE_MAINNET,
            &from,
            &to,
            1_000_000,
            1_700_000_000,
            1_700_000_600,
            &nonce,
        );
        let sepolia = hash_transfer_authorization(
            &USDC_BASE_SEPOLIA,
            &from,
            &to,
            1_000_000,
            1_700_000_000,
            1_700_000_600,
            &nonce,
        );
        assert_ne!(mainnet, sepolia);
    }

    #[test]
    fn usdc_domain_for_chain_supports_base_mainnet() {
        let d = usdc_domain_for_chain(&ChainId::base()).unwrap();
        assert_eq!(d.chain_id, 8453);
    }

    #[test]
    fn usdc_domain_for_chain_supports_base_sepolia() {
        let d = usdc_domain_for_chain(&ChainId::base_sepolia()).unwrap();
        assert_eq!(d.chain_id, 84532);
    }

    #[test]
    fn usdc_domain_for_chain_rejects_unsupported() {
        let eth = ChainId::ethereum();
        assert!(usdc_domain_for_chain(&eth).is_err());
    }

    #[test]
    fn parse_eth_address_accepts_checksummed_and_lowercase() {
        let a = parse_eth_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").unwrap();
        let b = parse_eth_address("833589fcd6edb6e08f4c7c32d4f71b54bda02913").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, USDC_BASE_MAINNET.verifying_contract);
    }

    #[test]
    fn parse_eth_address_rejects_wrong_length() {
        assert!(parse_eth_address("0xdead").is_err());
    }
}

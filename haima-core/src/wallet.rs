//! Wallet address and on-chain balance types.

use serde::{Deserialize, Serialize};

/// A blockchain network identifier using CAIP-2 format.
///
/// Examples: `eip155:8453` (Base), `eip155:1` (Ethereum mainnet),
/// `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` (Solana mainnet).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub String);

impl ChainId {
    /// Base mainnet (Coinbase L2).
    pub fn base() -> Self {
        Self("eip155:8453".into())
    }

    /// Base Sepolia testnet.
    pub fn base_sepolia() -> Self {
        Self("eip155:84532".into())
    }

    /// Ethereum mainnet.
    pub fn ethereum() -> Self {
        Self("eip155:1".into())
    }

    /// Whether this is an EVM-compatible chain.
    pub fn is_evm(&self) -> bool {
        self.0.starts_with("eip155:")
    }

    /// Whether this is a Solana chain.
    pub fn is_solana(&self) -> bool {
        self.0.starts_with("solana:")
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An on-chain wallet address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WalletAddress {
    /// The address string (hex for EVM, base58 for Solana).
    pub address: String,
    /// The chain this address belongs to.
    pub chain: ChainId,
}

impl std::fmt::Display for WalletAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.address, self.chain)
    }
}

/// On-chain balance for a wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainBalance {
    /// Wallet address.
    pub wallet: WalletAddress,
    /// Token symbol (e.g., "USDC").
    pub token: String,
    /// Balance in the token's smallest unit (e.g., 6 decimals for USDC).
    pub raw_amount: u64,
    /// Balance in human-readable units (e.g., 10.50 USDC).
    pub display_amount: f64,
    /// Equivalent in micro-credits (using configured exchange rate).
    pub micro_credits: i64,
    /// Timestamp when this balance was last synced.
    pub synced_at_ms: u64,
}

/// Default exchange rate: 1 USDC = 1,000,000 micro-credits.
pub const USDC_TO_MICRO_CREDITS: i64 = 1_000_000;

/// Convert USDC raw amount (6 decimals) to micro-credits.
pub fn usdc_raw_to_micro_credits(raw_amount: u64) -> i64 {
    // USDC has 6 decimals, micro-credits map 1:1 to USDC's smallest unit.
    // 1 USDC = 1_000_000 raw = 1_000_000 micro-credits.
    raw_amount as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_id_constructors() {
        assert!(ChainId::base().is_evm());
        assert!(ChainId::base_sepolia().is_evm());
        assert!(ChainId::ethereum().is_evm());
        assert!(!ChainId::base().is_solana());
    }

    #[test]
    fn usdc_conversion() {
        // 1 USDC = 1_000_000 raw units = 1_000_000 micro-credits
        assert_eq!(usdc_raw_to_micro_credits(1_000_000), 1_000_000);
        // 0.01 USDC = 10_000 raw = 10_000 micro-credits
        assert_eq!(usdc_raw_to_micro_credits(10_000), 10_000);
        // 0.000001 USDC = 1 raw = 1 micro-credit
        assert_eq!(usdc_raw_to_micro_credits(1), 1);
    }

    #[test]
    fn wallet_address_display() {
        let addr = WalletAddress {
            address: "0xdeadbeef".into(),
            chain: ChainId::base(),
        };
        assert_eq!(addr.to_string(), "0xdeadbeef@eip155:8453");
    }

    #[test]
    fn chain_id_serde_roundtrip() {
        let chain = ChainId::base();
        let json = serde_json::to_string(&chain).unwrap();
        let back: ChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, back);
    }
}

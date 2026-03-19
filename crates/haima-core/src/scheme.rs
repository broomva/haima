//! Payment schemes supported by the x402 protocol.

use serde::{Deserialize, Serialize};

use crate::wallet::{ChainId, WalletAddress};

/// A payment scheme defines how a payment is structured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PaymentScheme {
    /// Exact amount transfer — the only production scheme today.
    Exact {
        /// Amount in the token's smallest unit.
        amount: u64,
        /// Token contract address (e.g., USDC on Base).
        token: TokenInfo,
        /// Recipient address.
        recipient: WalletAddress,
        /// Facilitator URL for verification and settlement.
        facilitator_url: String,
    },
}

/// Token information for a payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token symbol (e.g., "USDC").
    pub symbol: String,
    /// Token contract address on the target chain.
    pub contract_address: String,
    /// Number of decimal places.
    pub decimals: u8,
    /// Chain where this token lives.
    pub chain: ChainId,
}

impl TokenInfo {
    /// USDC on Base mainnet.
    pub fn usdc_base() -> Self {
        Self {
            symbol: "USDC".into(),
            contract_address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            decimals: 6,
            chain: ChainId::base(),
        }
    }

    /// USDC on Base Sepolia testnet.
    pub fn usdc_base_sepolia() -> Self {
        Self {
            symbol: "USDC".into(),
            contract_address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".into(),
            decimals: 6,
            chain: ChainId::base_sepolia(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_info_usdc_base() {
        let token = TokenInfo::usdc_base();
        assert_eq!(token.symbol, "USDC");
        assert_eq!(token.decimals, 6);
        assert!(token.chain.is_evm());
    }

    #[test]
    fn payment_scheme_serde_roundtrip() {
        let scheme = PaymentScheme::Exact {
            amount: 10_000,
            token: TokenInfo::usdc_base(),
            recipient: WalletAddress {
                address: "0xrecipient".into(),
                chain: ChainId::base(),
            },
            facilitator_url: "https://x402.org/facilitator".into(),
        };
        let json = serde_json::to_string(&scheme).unwrap();
        let back: PaymentScheme = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, PaymentScheme::Exact { .. }));
    }
}

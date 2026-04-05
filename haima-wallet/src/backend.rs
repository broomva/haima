//! Wallet backend trait — abstraction over local and MPC wallets.

use async_trait::async_trait;
use haima_core::{HaimaResult, WalletAddress};

/// Wallet backend abstraction.
///
/// Local wallets sign directly with a private key.
/// MPC wallets delegate signing to a remote service (e.g., Coinbase CDP).
/// This trait unifies both behind a single interface.
#[async_trait]
pub trait WalletBackend: Send + Sync {
    /// Get the wallet's on-chain address.
    fn address(&self) -> &WalletAddress;

    /// Sign an arbitrary message (EIP-191 personal sign for EVM).
    async fn sign_message(&self, message: &[u8]) -> HaimaResult<Vec<u8>>;

    /// Sign a typed data hash (EIP-712 for EVM).
    async fn sign_typed_data(&self, hash: &[u8; 32]) -> HaimaResult<Vec<u8>>;

    /// Sign an EIP-3009 `transferWithAuthorization` for USDC payments.
    /// This is the primary signing operation for x402 exact payments.
    async fn sign_transfer_authorization(
        &self,
        from: &str,
        to: &str,
        value: u64,
        valid_after: u64,
        valid_before: u64,
        nonce: &[u8; 32],
    ) -> HaimaResult<Vec<u8>>;

    /// Wallet backend type identifier.
    fn backend_type(&self) -> &str;
}

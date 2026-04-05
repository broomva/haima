//! Wallet management for Haima.
//!
//! Provides secp256k1 keypair generation, EVM-compatible address derivation,
//! encrypted private key storage, and signing operations.
//!
//! The wallet is local-first: private keys are encrypted with ChaCha20-Poly1305
//! and stored as Lago blobs. The abstraction layer supports future MPC wallet
//! backends (e.g., Coinbase CDP MPC) through the `WalletBackend` trait.

pub mod backend;
pub mod evm;
pub mod signer;

pub use backend::WalletBackend;
pub use evm::{decrypt_private_key, derive_address, encrypt_private_key, generate_keypair};
pub use signer::LocalSigner;

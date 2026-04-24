//! HTTP API DTOs for haimad.
//!
//! This crate is schema-only — no runtime code. It re-exports the canonical
//! wire types from `aios-protocol::finance` so `life-kernel-facade` and other
//! callers can depend on typed request/response shapes without pulling in the
//! full `haimad` server runtime.

#![forbid(unsafe_code)]

pub use aios_protocol::finance::{
    PaymentAuthRequest, PaymentAuthorization, SettlementReceipt, TimeWindow, TransactionFilter,
    TransactionRecord, TransactionStatus, UsageReport, WalletManifest, WalletPolicy,
};

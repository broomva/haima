//! Haima daemon library — exposed surfaces consumed by the haimad
//! binary (`src/main.rs`) and by integration tests.
//!
//! ## Layout
//!
//! - `state` — in-memory wallet + ledger registry (`HaimaState`).
//! - `substrate` — `haima.v1.WalletSubstrate` gRPC server impl
//!   (BRO-1018, Phase 3 of the Topology B substrate-stub gap close).
//!
//! The HTTP `:3003` x402 / facilitator surface stays in
//! `haima-api` and is wired from `main.rs`. The substrate-plane gRPC
//! server is opt-in via the `--uds-socket` flag (env
//! `HAIMA_UDS_SOCKET`).
//!
//! Reference: `research/entities/concept/topology-b-substrate-stub-gap.md`.

pub mod state;
pub mod substrate;

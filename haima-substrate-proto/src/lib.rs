//! Generated `haima.v1` proto types — the substrate-plane wire
//! contract between lifed (via `haima-proxy`) and haimad.
//!
//! All types live under `haima::v1` (the proto package path). The
//! generated client + server stubs are used by `haima-proxy` and the
//! `haimad::substrate` UDS server respectively. `aios.v1.*` types are
//! re-exported from `aios-proto` via `extern_path` (Spec C₂ §10.3).
//!
//! Reference: `docs/superpowers/specs/2026-04-25-life-runtime-architecture-spec.md`
//! and BRO-1018 (closes Phase 3 of the Topology-B substrate-stub gap
//! audit captured in `research/entities/concept/topology-b-substrate-stub-gap.md`).
//! Sibling of `arcan-substrate-proto` (BRO-1016).

#![deny(unsafe_code)]
#![allow(missing_docs)] // generated code

#[allow(unused_qualifications, clippy::all)]
pub mod haima {
    pub mod v1 {
        tonic::include_proto!("haima.v1");
    }
}

// Re-export aios-proto for callers that want a single import path.
pub use aios_proto::aios as aios_v1;

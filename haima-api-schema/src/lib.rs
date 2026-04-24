//! HTTP API DTOs for haimad — schema-only crate.
//!
//! This crate intentionally contains **no runtime code**. It exists so
//! `life-kernel-facade` can depend on typed request/response shapes without
//! pulling in haimad's server runtime. Types are filled in by Phase 0 tasks
//! that mirror the canonical HTTP surface at
//! `core/life/crates/haima/haimad/src/`.

#![forbid(unsafe_code)]

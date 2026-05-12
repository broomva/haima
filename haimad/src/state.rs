//! Haima substrate state — in-memory wallet binding + ledger registry
//! consumed by `haimad::substrate::SubstrateService` under Topology B.
//!
//! Phase 3 (BRO-1018) scope:
//! - One wallet per `(user_id, project_id)` pair. Wallets are
//!   secp256k1-backed and live in process memory for the lifetime of
//!   the daemon.
//! - Per-wallet ledger entries (debits + transfers). Entries are
//!   ULID-ordered so the substrate `Statement` RPC can serve a stable
//!   stream.
//! - Per-session binding lookup so the saga compensation path
//!   (`UnbindWallet`) can find the wallet by id.
//!
//! What this is NOT (yet):
//! - On-chain. The local secp256k1 backend produces real EVM
//!   addresses, but balances are off-chain and start with a default
//!   credit so demos / tests have something to debit. Replacing the
//!   default with a `BalanceSynced` flow against a real provider is
//!   tracked under haima Phase F4.
//! - Persistent. `haima-lago::FinancePublisher` is the durable path
//!   (Phase F2) — currently a no-op stub. Once F2 ships, every
//!   ledger entry written here also fans out to lago via
//!   `EventKind::Custom("finance.*", ...)`.
//!
//! Concurrency: `HaimaState` is internally locked (`std::sync::RwLock`
//! over a tokio-friendly granularity — we never hold the lock across
//! `await`). All public methods are synchronous and intentionally
//! cheap (no I/O). The substrate handlers wrap them inside async fns
//! so the trait shape stays uniform with the proxy.

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use haima_core::wallet::ChainId;
use haima_wallet::evm::generate_keypair;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

/// Default starting balance for a freshly-bound wallet, in
/// micro-credits. 1 USDC; matches the proxy stub's pre-BRO-1018
/// return shape so the wire change is invisible to lifed's tests.
pub const DEFAULT_BIND_BALANCE_MICROS: u64 = 1_000_000;

/// The currency ticker emitted for every Balance the substrate
/// returns under Phase 3. Wallets are USDC-only today.
pub const DEFAULT_CURRENCY: &str = "USDC";

#[derive(Debug, Error)]
pub enum HaimaStateError {
    #[error("wallet not found: {0}")]
    WalletNotFound(String),
    #[error("insufficient balance: have {have} micros, want {want}")]
    InsufficientBalance { have: u64, want: u64 },
    #[error("crypto: {0}")]
    Crypto(String),
}

pub type HaimaStateResult<T> = Result<T, HaimaStateError>;

/// A wallet bound to a `(user_id, project_id)` pair.
///
/// The on-chain `address` is derived from a freshly generated
/// secp256k1 keypair on bind. The private key is held by the daemon
/// only — proxy callers never see it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletRecord {
    pub wallet_id: String,
    pub user_id: String,
    pub project_id: String,
    pub address: String,
    pub chain: String,
    pub balance_micros: u64,
    pub bound_at: DateTime<Utc>,
}

/// A single ledger entry — credit or debit. Positive `delta_micros`
/// is a credit (transfer-in); negative is a debit (transfer-out).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub entry_id: String,
    pub wallet_id: String,
    pub at: DateTime<Utc>,
    pub delta_micros: i64,
    pub reason: String,
    pub sid: String,
}

#[derive(Debug, Default)]
struct StateInner {
    /// Wallets indexed by deterministic wallet_id (`wallet-{sid}-{project}`).
    /// Mirrors the proxy's pre-BRO-1018 shape so external introspection
    /// tooling that scrapes ids stays compatible.
    wallets: HashMap<String, WalletRecord>,
    /// Per-wallet ledger entries, in append order. Entries are scoped
    /// by `wallet_id`; the `Statement` RPC walks the vec and filters
    /// on the requested time window.
    ledger: HashMap<String, Vec<LedgerEntry>>,
}

/// Process-wide haima substrate state. Cheap to clone (internally
/// `Arc<RwLock<…>>`). Constructed once in haimad bootstrap and shared
/// by every `SubstrateService` instance.
#[derive(Debug, Default)]
pub struct HaimaState {
    inner: RwLock<StateInner>,
}

impl HaimaState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deterministic wallet id derived from `(sid, project_id)`. The
    /// shape mirrors the proxy's pre-BRO-1018 return value so callers
    /// that key on it (e.g. `BindWallet` saga compensation passes
    /// `wallet-{sid}` style ids back to `UnbindWallet`) don't break.
    pub fn wallet_id_for(sid: &str, project_id: &str) -> String {
        format!("wallet-{sid}-{project_id}")
    }

    /// Idempotent bind: returns the existing wallet if `(sid, project)`
    /// is already bound, otherwise mints a new secp256k1 keypair,
    /// derives the EVM address, and stores the record with a default
    /// 1 USDC balance.
    pub fn bind_wallet(&self, sid: &str, project_id: &str) -> HaimaStateResult<WalletRecord> {
        let wallet_id = Self::wallet_id_for(sid, project_id);

        // Fast path: already bound.
        {
            let guard = self.inner.read().expect("poisoned");
            if let Some(existing) = guard.wallets.get(&wallet_id) {
                return Ok(existing.clone());
            }
        }

        // Generate the keypair OUTSIDE the lock to keep the critical
        // section short. `_priv` is dropped here — Phase 3 does not
        // need to retain it because no sign operations route through
        // the substrate yet (signing stays in haima-wallet's
        // LocalSigner which haima-x402 owns).
        let (_priv, addr) =
            generate_keypair().map_err(|e| HaimaStateError::Crypto(e.to_string()))?;
        let now = Utc::now();
        let record = WalletRecord {
            wallet_id: wallet_id.clone(),
            user_id: String::new(), // populated on first user-scoped op
            project_id: project_id.to_string(),
            address: addr.address,
            chain: ChainId::base().to_string(),
            balance_micros: DEFAULT_BIND_BALANCE_MICROS,
            bound_at: now,
        };

        let mut guard = self.inner.write().expect("poisoned");
        // Re-check under the write lock — another caller may have
        // bound concurrently between the read drop and the write
        // acquire. Idempotency is the contract.
        Ok(guard.wallets.entry(wallet_id).or_insert(record).clone())
    }

    /// Idempotent unbind. Removes the wallet record and drops its
    /// ledger. Missing wallets return Ok (saga compensation paths
    /// stay clean — Spec C₂ §4.2).
    pub fn unbind_wallet(&self, wallet_id: &str) {
        let mut guard = self.inner.write().expect("poisoned");
        guard.wallets.remove(wallet_id);
        guard.ledger.remove(wallet_id);
    }

    /// Look up a wallet by `(user_id, project_id)`. Materializes a
    /// default-bound wallet on first access so substrate callers
    /// always see a balance (matches the proxy's pre-BRO-1018
    /// fallback shape). Tracks the user_id on the record so callers
    /// can introspect later.
    pub fn get_or_create_user_wallet(
        &self,
        user_id: &str,
        project_id: &str,
    ) -> HaimaStateResult<WalletRecord> {
        // Use `user_id` as the sid for the deterministic id since
        // GetBalance / Debit / Transfer all flow through (user_id,
        // project_id) — the sid is a per-session context, not the
        // wallet key. This mirrors the proxy's pre-BRO-1018 stub
        // signature exactly.
        let wallet_id = Self::wallet_id_for(user_id, project_id);
        // Fast read path.
        {
            let guard = self.inner.read().expect("poisoned");
            if let Some(existing) = guard.wallets.get(&wallet_id) {
                return Ok(existing.clone());
            }
        }

        // Generate outside the lock.
        let (_priv, addr) =
            generate_keypair().map_err(|e| HaimaStateError::Crypto(e.to_string()))?;
        let now = Utc::now();
        let record = WalletRecord {
            wallet_id: wallet_id.clone(),
            user_id: user_id.to_string(),
            project_id: project_id.to_string(),
            address: addr.address,
            chain: ChainId::base().to_string(),
            balance_micros: DEFAULT_BIND_BALANCE_MICROS,
            bound_at: now,
        };

        let mut guard = self.inner.write().expect("poisoned");
        // Re-check under the write lock; another caller may have
        // raced ahead. Re-set user_id if the existing record was
        // bound via `bind_wallet` without a user (initial value was
        // empty string).
        let entry = guard.wallets.entry(wallet_id).or_insert(record);
        if entry.user_id.is_empty() {
            entry.user_id = user_id.to_string();
        }
        Ok(entry.clone())
    }

    /// Apply a debit. Errors if the wallet doesn't exist OR if the
    /// balance would go negative. Records a ledger entry on success.
    pub fn debit(
        &self,
        user_id: &str,
        project_id: &str,
        amount_micros: u64,
        sid: &str,
        reason: &str,
    ) -> HaimaStateResult<(LedgerEntry, WalletRecord)> {
        let wallet_id = Self::wallet_id_for(user_id, project_id);
        // Materialize the wallet outside the write lock so we don't
        // hold the lock across keypair gen on the cold path.
        let _ = self.get_or_create_user_wallet(user_id, project_id)?;

        let mut guard = self.inner.write().expect("poisoned");
        let wallet = guard
            .wallets
            .get_mut(&wallet_id)
            .ok_or_else(|| HaimaStateError::WalletNotFound(wallet_id.clone()))?;
        if wallet.balance_micros < amount_micros {
            return Err(HaimaStateError::InsufficientBalance {
                have: wallet.balance_micros,
                want: amount_micros,
            });
        }
        wallet.balance_micros -= amount_micros;
        let updated = wallet.clone();
        let entry = LedgerEntry {
            entry_id: Ulid::new().to_string(),
            wallet_id: wallet_id.clone(),
            at: Utc::now(),
            delta_micros: -(amount_micros as i64),
            reason: reason.to_string(),
            sid: sid.to_string(),
        };
        guard
            .ledger
            .entry(wallet_id)
            .or_default()
            .push(entry.clone());
        Ok((entry, updated))
    }

    /// Apply a transfer between two `(user, project)` wallets. Both
    /// wallets are materialized on demand; both legs land in the
    /// ledger atomically under a single write lock.
    pub fn transfer(
        &self,
        from_user: &str,
        from_project: &str,
        to_user: &str,
        to_project: &str,
        amount_micros: u64,
        memo: &str,
    ) -> HaimaStateResult<(LedgerEntry, WalletRecord, WalletRecord)> {
        // Materialize both wallets first (outside the write lock).
        let _ = self.get_or_create_user_wallet(from_user, from_project)?;
        let _ = self.get_or_create_user_wallet(to_user, to_project)?;

        let from_id = Self::wallet_id_for(from_user, from_project);
        let to_id = Self::wallet_id_for(to_user, to_project);
        let entry_id = Ulid::new().to_string();
        let now = Utc::now();

        let mut guard = self.inner.write().expect("poisoned");

        // Pull balances + perform the credit/debit. We avoid two
        // simultaneous &mut into `wallets` by reading the from-balance
        // first and writing both legs sequentially.
        let from_have = guard
            .wallets
            .get(&from_id)
            .map(|w| w.balance_micros)
            .ok_or_else(|| HaimaStateError::WalletNotFound(from_id.clone()))?;
        if from_have < amount_micros {
            return Err(HaimaStateError::InsufficientBalance {
                have: from_have,
                want: amount_micros,
            });
        }

        let from_updated = {
            let from = guard
                .wallets
                .get_mut(&from_id)
                .ok_or_else(|| HaimaStateError::WalletNotFound(from_id.clone()))?;
            from.balance_micros -= amount_micros;
            from.clone()
        };
        let to_updated = {
            let to = guard
                .wallets
                .get_mut(&to_id)
                .ok_or_else(|| HaimaStateError::WalletNotFound(to_id.clone()))?;
            to.balance_micros += amount_micros;
            to.clone()
        };

        // Record BOTH legs in the ledger so Statement returns a
        // symmetric trail.
        let debit_entry = LedgerEntry {
            entry_id: entry_id.clone(),
            wallet_id: from_id.clone(),
            at: now,
            delta_micros: -(amount_micros as i64),
            reason: format!("transfer:{memo}"),
            sid: String::new(),
        };
        let credit_entry = LedgerEntry {
            entry_id: entry_id.clone(),
            wallet_id: to_id.clone(),
            at: now,
            delta_micros: amount_micros as i64,
            reason: format!("transfer:{memo}"),
            sid: String::new(),
        };
        guard
            .ledger
            .entry(from_id)
            .or_default()
            .push(debit_entry.clone());
        guard.ledger.entry(to_id).or_default().push(credit_entry);

        Ok((debit_entry, from_updated, to_updated))
    }

    /// Snapshot the ledger for a `(user, project)` wallet within the
    /// time window. Bounds are inclusive on `since_ms` and exclusive
    /// on `until_ms` (matches the proxy semantics).
    pub fn statement(
        &self,
        user_id: &str,
        project_id: &str,
        since_ms: i64,
        until_ms: i64,
        limit: u32,
    ) -> Vec<LedgerEntry> {
        let wallet_id = Self::wallet_id_for(user_id, project_id);
        let guard = self.inner.read().expect("poisoned");
        let Some(entries) = guard.ledger.get(&wallet_id) else {
            return Vec::new();
        };
        let cap = if limit == 0 {
            usize::MAX
        } else {
            limit as usize
        };
        entries
            .iter()
            .filter(|e| {
                let ms = e.at.timestamp_millis();
                ms >= since_ms && ms < until_ms
            })
            .take(cap)
            .cloned()
            .collect()
    }

    /// Direct balance probe. Returns 0 + default currency if the
    /// wallet has never been bound. Used by `GetBalance` so a cold
    /// call doesn't materialize the wallet — `get_or_create_user_wallet`
    /// is reserved for callers that need a `WalletRecord` back.
    pub fn balance(&self, user_id: &str, project_id: &str) -> (u64, String) {
        let wallet_id = Self::wallet_id_for(user_id, project_id);
        let guard = self.inner.read().expect("poisoned");
        match guard.wallets.get(&wallet_id) {
            Some(w) => (w.balance_micros, DEFAULT_CURRENCY.to_string()),
            None => (0, DEFAULT_CURRENCY.to_string()),
        }
    }

    /// Test-only probe.
    #[doc(hidden)]
    pub fn wallet_count(&self) -> usize {
        self.inner.read().expect("poisoned").wallets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_is_idempotent() {
        let st = HaimaState::new();
        let a = st.bind_wallet("sid-1", "proj-1").expect("bind");
        let b = st.bind_wallet("sid-1", "proj-1").expect("rebind");
        assert_eq!(a.wallet_id, b.wallet_id);
        assert_eq!(a.address, b.address);
        assert_eq!(st.wallet_count(), 1);
    }

    #[test]
    fn unbind_drops_wallet_and_ledger() {
        let st = HaimaState::new();
        let w = st.bind_wallet("sid-2", "proj-2").expect("bind");
        // Touch a ledger entry to make sure unbind clears it too.
        let _ = st
            .debit("sid-2", "proj-2", 1, "sid-2", "test")
            .expect("debit");
        st.unbind_wallet(&w.wallet_id);
        assert_eq!(st.wallet_count(), 0);
        assert!(st.statement("sid-2", "proj-2", 0, i64::MAX, 0).is_empty());
        // Idempotent: second unbind doesn't blow up.
        st.unbind_wallet(&w.wallet_id);
    }

    #[test]
    fn debit_respects_balance() {
        let st = HaimaState::new();
        let _ = st.bind_wallet("u", "p").expect("bind");
        // 1 USDC = 1_000_000 micros. Debit 600k → 400k remains.
        let (e, w) = st.debit("u", "p", 600_000, "sid-x", "fee").expect("debit");
        assert_eq!(w.balance_micros, 400_000);
        assert_eq!(e.delta_micros, -600_000);
        // Over-debit should fail.
        let err = st
            .debit("u", "p", 500_000, "sid-x", "fee2")
            .expect_err("over-debit");
        assert!(matches!(err, HaimaStateError::InsufficientBalance { .. }));
    }

    #[test]
    fn transfer_moves_balance_and_records_both_legs() {
        let st = HaimaState::new();
        let _from = st
            .get_or_create_user_wallet("alice", "proj-A")
            .expect("from");
        let _to = st.get_or_create_user_wallet("bob", "proj-B").expect("to");

        let (entry, from_after, to_after) = st
            .transfer("alice", "proj-A", "bob", "proj-B", 100_000, "drinks")
            .expect("transfer");
        assert_eq!(from_after.balance_micros, 900_000);
        assert_eq!(to_after.balance_micros, 1_100_000);
        assert_eq!(entry.delta_micros, -100_000);

        // Both legs landed in the ledger.
        let from_stmt = st.statement("alice", "proj-A", 0, i64::MAX, 0);
        let to_stmt = st.statement("bob", "proj-B", 0, i64::MAX, 0);
        assert_eq!(from_stmt.len(), 1);
        assert_eq!(to_stmt.len(), 1);
        assert_eq!(from_stmt[0].delta_micros, -100_000);
        assert_eq!(to_stmt[0].delta_micros, 100_000);
    }

    #[test]
    fn balance_returns_zero_for_unknown_wallet() {
        let st = HaimaState::new();
        let (m, c) = st.balance("ghost", "void");
        assert_eq!(m, 0);
        assert_eq!(c, DEFAULT_CURRENCY);
    }

    #[test]
    fn statement_filters_window() {
        let st = HaimaState::new();
        let _ = st.bind_wallet("u", "p").expect("bind");
        // Three quick debits.
        for i in 0..3 {
            let _ = st
                .debit("u", "p", 100, "sid", &format!("n{i}"))
                .expect("debit");
        }
        let all = st.statement("u", "p", 0, i64::MAX, 0);
        assert_eq!(all.len(), 3);
        let limited = st.statement("u", "p", 0, i64::MAX, 2);
        assert_eq!(limited.len(), 2);
        // A pre-history window returns empty.
        let none = st.statement("u", "p", 0, 1, 0);
        assert!(none.is_empty());
    }
}

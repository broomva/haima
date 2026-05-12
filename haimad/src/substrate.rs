//! Substrate-plane gRPC service for haimad.
//!
//! Implements `haima.v1.WalletSubstrate` (defined in
//! `proto/haima/v1/substrate.proto`, generated in
//! `haima-substrate-proto`). This is the UDS-bound entry point that
//! lifed reaches via `haima-proxy` under Topology B. It is ADDITIVE
//! to haimad's existing HTTP `:3003` server (Topology A x402 routes)
//! — both can run concurrently behind a shared `Arc<HaimaState>`.
//!
//! Phase 3 scope (BRO-1018):
//! - `BindWallet`: idempotent session binding via `HaimaState`.
//! - `UnbindWallet`: idempotent compensation hook.
//! - `GetBalance`: cold balance probe (no materialization).
//! - `Statement`: server-streaming ledger window.
//! - `Debit`: ledger sink (lifed enforces idempotency at the public plane).
//! - `Transfer`: ledger sink, atomic two-leg.
//!
//! Phase 4 (separate ticket) will wire `haima-lago::FinancePublisher`
//! into every mutating RPC so each ledger entry also produces a
//! `EventKind::Custom("finance.*", ...)` lago event. Today the
//! publisher stays in haima's F2 backlog; HaimaState is the only
//! source of truth for the wire.

use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use futures::Stream;
use haima_substrate_proto::haima::v1::{
    self as haima_pb, wallet_substrate_server::WalletSubstrate,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::state::{HaimaState, HaimaStateError};

/// Bounded channel capacity for the `Statement` server-streaming
/// response. Mirrors arcand's BRO-1016 capacity choice — 64 is more
/// than enough headroom for slow consumers given Statement's bounded
/// nature (no live tail; entries are produced from an in-memory vec).
const STATEMENT_CHANNEL_CAPACITY: usize = 64;

/// haimad's `haima.v1.WalletSubstrate` impl. Holds an `Arc<HaimaState>`
/// so every RPC reuses the same in-memory wallet + ledger registry
/// that the HTTP plane will (eventually) project from when the F2
/// lago integration lands.
pub struct SubstrateService {
    state: Arc<HaimaState>,
}

impl SubstrateService {
    pub fn new(state: Arc<HaimaState>) -> Self {
        Self { state }
    }

    /// Expose the underlying state — integration tests + the daemon
    /// bootstrap need to share the `Arc<HaimaState>` so they can
    /// observe the side effects of substrate-plane writes.
    pub fn state(&self) -> &Arc<HaimaState> {
        &self.state
    }
}

#[tonic::async_trait]
impl WalletSubstrate for SubstrateService {
    type StatementStream =
        Pin<Box<dyn Stream<Item = Result<haima_pb::LedgerEntry, Status>> + Send + 'static>>;

    async fn bind_wallet(
        &self,
        req: Request<haima_pb::BindWalletReq>,
    ) -> Result<Response<haima_pb::BindWalletResp>, Status> {
        let body = req.into_inner();
        let sid_proto = body
            .sid
            .ok_or_else(|| Status::invalid_argument("missing sid"))?;
        if sid_proto.value.is_empty() {
            return Err(Status::invalid_argument("empty sid"));
        }
        if body.project_id.is_empty() {
            return Err(Status::invalid_argument("empty project_id"));
        }
        let record = self
            .state
            .bind_wallet(&sid_proto.value, &body.project_id)
            .map_err(map_state_error)?;
        Ok(Response::new(haima_pb::BindWalletResp {
            wallet_id: record.wallet_id,
            address: record.address,
            bound_at: Some(prost_types::Timestamp::from(SystemTime::now())),
        }))
    }

    async fn unbind_wallet(
        &self,
        req: Request<haima_pb::UnbindWalletReq>,
    ) -> Result<Response<haima_pb::UnbindWalletResp>, Status> {
        let body = req.into_inner();
        // Idempotent: unknown wallets unbind to Ok(empty). Saga
        // compensation paths stay clean (Spec C₂ §4.2).
        self.state.unbind_wallet(&body.wallet_id);
        Ok(Response::new(haima_pb::UnbindWalletResp {}))
    }

    async fn get_balance(
        &self,
        req: Request<haima_pb::GetBalanceReq>,
    ) -> Result<Response<haima_pb::Balance>, Status> {
        let body = req.into_inner();
        if body.user_id.is_empty() {
            return Err(Status::invalid_argument("empty user_id"));
        }
        if body.project_id.is_empty() {
            return Err(Status::invalid_argument("empty project_id"));
        }
        let (micros, currency) = self.state.balance(&body.user_id, &body.project_id);
        Ok(Response::new(haima_pb::Balance {
            micros,
            currency,
            as_of: Some(prost_types::Timestamp::from(SystemTime::now())),
        }))
    }

    async fn statement(
        &self,
        req: Request<haima_pb::StatementReq>,
    ) -> Result<Response<Self::StatementStream>, Status> {
        let body = req.into_inner();
        if body.user_id.is_empty() {
            return Err(Status::invalid_argument("empty user_id"));
        }
        if body.project_id.is_empty() {
            return Err(Status::invalid_argument("empty project_id"));
        }
        // Snapshot first so the lock isn't held across the spawn.
        let entries = self.state.statement(
            &body.user_id,
            &body.project_id,
            body.since_ms,
            // Treat 0 as "no upper bound" — matches the proxy's
            // default when the public-plane caller omits `until`.
            if body.until_ms == 0 {
                i64::MAX
            } else {
                body.until_ms
            },
            body.limit,
        );

        let (tx, rx) =
            mpsc::channel::<Result<haima_pb::LedgerEntry, Status>>(STATEMENT_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            for entry in entries {
                let proto_entry = haima_pb::LedgerEntry {
                    entry_id: entry.entry_id,
                    at_unix_ms: entry.at.timestamp_millis(),
                    delta_micros: entry.delta_micros,
                    reason: entry.reason,
                    sid: entry.sid,
                };
                if tx.send(Ok(proto_entry)).await.is_err() {
                    // Receiver dropped — stop early.
                    break;
                }
            }
            // Drop tx so the stream terminates cleanly.
            drop(tx);
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::StatementStream))
    }

    async fn debit(
        &self,
        req: Request<haima_pb::DebitReq>,
    ) -> Result<Response<haima_pb::DebitReceipt>, Status> {
        let body = req.into_inner();
        if body.user_id.is_empty() {
            return Err(Status::invalid_argument("empty user_id"));
        }
        if body.project_id.is_empty() {
            return Err(Status::invalid_argument("empty project_id"));
        }
        let (entry, wallet) = self
            .state
            .debit(
                &body.user_id,
                &body.project_id,
                body.amount_micros,
                &body.sid,
                &body.reason,
            )
            .map_err(map_state_error)?;
        Ok(Response::new(haima_pb::DebitReceipt {
            entry_id: entry.entry_id,
            new_balance: Some(haima_pb::Balance {
                micros: wallet.balance_micros,
                currency: crate::state::DEFAULT_CURRENCY.to_string(),
                as_of: Some(prost_types::Timestamp::from(SystemTime::now())),
            }),
        }))
    }

    async fn transfer(
        &self,
        req: Request<haima_pb::TransferReq>,
    ) -> Result<Response<haima_pb::TransferReceipt>, Status> {
        let body = req.into_inner();
        if body.from_user.is_empty()
            || body.from_project.is_empty()
            || body.to_user.is_empty()
            || body.to_project.is_empty()
        {
            return Err(Status::invalid_argument(
                "from/to user_id and project_id are required",
            ));
        }
        let (entry, from, to) = self
            .state
            .transfer(
                &body.from_user,
                &body.from_project,
                &body.to_user,
                &body.to_project,
                body.amount_micros,
                &body.memo,
            )
            .map_err(map_state_error)?;
        Ok(Response::new(haima_pb::TransferReceipt {
            entry_id: entry.entry_id,
            from_balance: Some(haima_pb::Balance {
                micros: from.balance_micros,
                currency: crate::state::DEFAULT_CURRENCY.to_string(),
                as_of: Some(prost_types::Timestamp::from(SystemTime::now())),
            }),
            to_balance: Some(haima_pb::Balance {
                micros: to.balance_micros,
                currency: crate::state::DEFAULT_CURRENCY.to_string(),
                as_of: Some(prost_types::Timestamp::from(SystemTime::now())),
            }),
        }))
    }
}

/// Map `HaimaStateError` to a `tonic::Status`. Permanent failures
/// (insufficient balance, malformed input) become `failed_precondition`
/// or `invalid_argument`; infrastructure failures become `internal`.
fn map_state_error(err: HaimaStateError) -> Status {
    match err {
        HaimaStateError::WalletNotFound(id) => Status::not_found(format!("wallet not found: {id}")),
        HaimaStateError::InsufficientBalance { have, want } => Status::failed_precondition(
            format!("insufficient balance: have {have} micros, want {want}"),
        ),
        HaimaStateError::Crypto(e) => Status::internal(format!("crypto: {e}")),
    }
}

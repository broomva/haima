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

use anima_identity::InProcessAnima;
use anima_identity::seed::MasterSeed;
use futures::Stream;
use haima_core::HaimaError;
use haima_core::wallet::ChainId;
use haima_substrate_proto::haima::v1::{
    self as haima_pb, wallet_substrate_server::WalletSubstrate,
};
use haima_x402::{
    CustodyWalletAdapter, Facilitator, FacilitatorConfig, X402Client, X402PayResult, pay_x402,
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::state::{HaimaState, HaimaStateError};

/// HTTP status the substrate reports for a settled payment — the
/// paid-resource fetch is always a 200 once settlement succeeds.
const SETTLED_RESOURCE_STATUS: u32 = 200;

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

    /// Initiate an x402 payment from the user's Anima-custodied wallet
    /// (BRO-1354, slice 2 of the BRO-1341 x402 epic).
    ///
    /// Flow: resolve the user's custody backend → wrap it in a
    /// [`CustodyWalletAdapter`] so EIP-3009 `transferWithAuthorization`
    /// signing routes through the user's secp256k1 key → build an
    /// [`X402Client`] → drive [`pay_x402`] (GET → 402 → policy/cap gate
    /// → sign → retry → settlement + resource).
    ///
    /// **P1 custody (documented deviation):** the custody backend is a
    /// per-`(user_id, project_id)` deterministic [`InProcessAnima`]
    /// (seeded from the pair), NOT yet the soma-resident Anima wallet
    /// shown on `/account`. This exercises the full sign + policy +
    /// settlement path on base-sepolia. Binding to the production
    /// soma-custodied key is a localized follow-up (slice 2b): swap
    /// [`resolve_custody`] to `SomaCustody` / `RemoteAnima` behind the
    /// same handler — no wire change.
    ///
    /// **base-sepolia only.** `network = "base"` (mainnet) is rejected
    /// with `failed_precondition`; mainnet is the slice-3 financial
    /// control gate's concern.
    async fn x402_pay(
        &self,
        req: Request<haima_pb::X402PayReq>,
    ) -> Result<Response<haima_pb::X402PayResp>, Status> {
        let body = req.into_inner();
        if body.user_id.is_empty() {
            return Err(Status::invalid_argument("empty user_id"));
        }
        if body.project_id.is_empty() {
            return Err(Status::invalid_argument("empty project_id"));
        }
        if body.resource_url.is_empty() {
            return Err(Status::invalid_argument("empty resource_url"));
        }

        // Resolve the signing network. P1 = base-sepolia only.
        let network = resolve_network(&body.network)?;

        // Resolve the user's custody backend and wrap it so x402 signs
        // EIP-3009 authorizations from the user's wallet half.
        let custody = resolve_custody(&body.user_id, &body.project_id)?;
        let adapter = CustodyWalletAdapter::from_custody_on_network(custody, network)
            .map_err(map_haima_error)?;

        // P1 uses the default facilitator + policy. The facilitator is
        // not contacted on the client happy-path (the resource server
        // returns the settlement in its `payment-response` header); a
        // configurable per-deployment facilitator is a follow-up.
        let client = X402Client::new(
            Arc::new(adapter),
            Facilitator::new(FacilitatorConfig::default()),
            haima_core::policy::PaymentPolicy::default(),
        );
        let http = reqwest::Client::new();

        let result = pay_x402(&client, &http, &body.resource_url, body.max_amount_micros)
            .await
            .map_err(map_haima_error)?;

        Ok(Response::new(map_pay_result(result)))
    }
}

/// Resolve the per-`(user_id, project_id)` custody backend used to sign
/// the x402 payment. P1: a deterministic [`InProcessAnima`] seeded from
/// the pair (stable wallet address across calls). See
/// [`SubstrateService::x402_pay`] for the production-binding follow-up.
fn resolve_custody(
    user_id: &str,
    project_id: &str,
) -> Result<Arc<dyn anima_identity::custody::AnimaCustody>, Status> {
    let seed = derive_custody_seed(user_id, project_id);
    InProcessAnima::from_seed_arc(seed)
        .map_err(|e| Status::internal(format!("resolve custody: {e}")))
}

/// Deterministically derive a 32-byte [`MasterSeed`] from
/// `(user_id, project_id)` so the same pair always resolves the same
/// wallet. Domain-separated with an `x402:` prefix so this seed never
/// collides with other per-user key derivations.
fn derive_custody_seed(user_id: &str, project_id: &str) -> MasterSeed {
    let mut hasher = Sha256::new();
    hasher.update(b"x402:v1:");
    hasher.update(user_id.as_bytes());
    hasher.update(b":");
    hasher.update(project_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    MasterSeed::from_bytes(bytes)
}

/// Resolve the payment network label to a [`ChainId`]. P1 accepts only
/// base-sepolia (the empty string defaults to it); `base` (mainnet) is
/// rejected behind the slice-3 financial control gate.
fn resolve_network(network: &str) -> Result<ChainId, Status> {
    match network {
        "" | "base-sepolia" => Ok(ChainId::base_sepolia()),
        "base" => Err(Status::failed_precondition(
            "network 'base' (mainnet) is gated behind the slice-3 financial control gate; \
             P1 supports base-sepolia only",
        )),
        other => Err(Status::invalid_argument(format!(
            "unknown network '{other}'; expected 'base-sepolia'"
        ))),
    }
}

/// Map a [`X402PayResult`] onto the flat wire `X402PayResp`. The
/// `status` discriminant tells the caller which fields are populated.
fn map_pay_result(result: X402PayResult) -> haima_pb::X402PayResp {
    match result {
        X402PayResult::NotRequired {
            status,
            resource_body,
        } => haima_pb::X402PayResp {
            status: "not_required".to_string(),
            resource_body,
            resource_status: u32::from(status),
            ..Default::default()
        },
        X402PayResult::Paid(outcome) => haima_pb::X402PayResp {
            status: "settled".to_string(),
            tx_hash: outcome.tx_hash.unwrap_or_default(),
            network: outcome.network,
            recipient: outcome.recipient,
            micro_credits: outcome.micro_credits,
            settled: outcome.settled,
            resource_body: outcome.resource_body,
            resource_status: SETTLED_RESOURCE_STATUS,
            ..Default::default()
        },
        X402PayResult::Declined {
            reason,
            micro_credits,
        } => haima_pb::X402PayResp {
            status: "declined".to_string(),
            declined_reason: reason,
            micro_credits,
            ..Default::default()
        },
    }
}

/// Map a [`HaimaError`] from the x402 engine to a `tonic::Status`.
/// Transport faults (`Http`) become `unavailable` (retryable upstream);
/// everything else is `internal`.
fn map_haima_error(err: HaimaError) -> Status {
    match &err {
        HaimaError::Http(_) => Status::unavailable(format!("x402 upstream: {err}")),
        _ => Status::internal(format!("x402 pay: {err}")),
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

#[cfg(test)]
mod x402_tests {
    use super::*;
    use crate::state::HaimaState;
    use haima_x402::{
        PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER,
        PaymentRequiredHeader, PaymentResponseHeader, SchemeRequirement, encode_payment_required,
        encode_payment_response,
    };
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // A base-sepolia x402 recipient + USDC token (the canonical
    // base-sepolia USDC test address used across haima-x402's suite).
    const TEST_RECIPIENT: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
    const USDC_BASE_SEPOLIA_ADDR: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
    // base-sepolia CAIP-2 chain reference.
    const BASE_SEPOLIA_CAIP2: &str = "eip155:84532";

    fn service() -> SubstrateService {
        SubstrateService::new(Arc::new(HaimaState::new()))
    }

    fn payment_required_header(amount: &str) -> String {
        let header = PaymentRequiredHeader {
            schemes: vec![SchemeRequirement {
                scheme: "exact".into(),
                network: BASE_SEPOLIA_CAIP2.into(),
                token: USDC_BASE_SEPOLIA_ADDR.into(),
                amount: amount.into(),
                recipient: TEST_RECIPIENT.into(),
                facilitator: "https://x402.org/facilitator".into(),
                max_timeout_seconds: Some(300),
            }],
            version: "v2".into(),
        };
        encode_payment_required(&header).expect("encode header")
    }

    /// Mount the 402 (first GET) leg.
    async fn mount_402(server: &MockServer, amount: &str) {
        Mock::given(method("GET"))
            .and(path("/api/data"))
            .respond_with(
                ResponseTemplate::new(402)
                    .insert_header(PAYMENT_REQUIRED_HEADER, payment_required_header(amount)),
            )
            .up_to_n_times(1)
            .mount(server)
            .await;
    }

    /// Mount the 200 + payment-response (retry-with-signature) leg.
    async fn mount_paid(server: &MockServer) {
        let resp = PaymentResponseHeader {
            tx_hash: "0xfeedface".into(),
            network: BASE_SEPOLIA_CAIP2.into(),
            settled: true,
        };
        let encoded = encode_payment_response(&resp).expect("encode response");
        Mock::given(method("GET"))
            .and(path("/api/data"))
            .and(header_exists(PAYMENT_SIGNATURE_HEADER))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(PAYMENT_RESPONSE_HEADER, encoded)
                    .set_body_string("{\"ok\":true}"),
            )
            .mount(server)
            .await;
    }

    fn req(server_uri: &str, network: &str, max: Option<i64>) -> haima_pb::X402PayReq {
        haima_pb::X402PayReq {
            user_id: "alice".into(),
            project_id: "proj".into(),
            resource_url: format!("{server_uri}/api/data"),
            network: network.into(),
            max_amount_micros: max,
        }
    }

    #[tokio::test]
    async fn x402_pay_settles_on_base_sepolia() {
        let server = MockServer::start().await;
        mount_402(&server, "50").await; // 50 μc < 100 auto-approve cap
        mount_paid(&server).await;

        let resp = service()
            .x402_pay(Request::new(req(&server.uri(), "base-sepolia", None)))
            .await
            .expect("x402_pay")
            .into_inner();

        assert_eq!(resp.status, "settled");
        assert_eq!(resp.tx_hash, "0xfeedface");
        assert!(resp.settled);
        assert_eq!(resp.network, BASE_SEPOLIA_CAIP2);
        assert_eq!(resp.recipient.to_lowercase(), TEST_RECIPIENT.to_lowercase());
        assert_eq!(resp.micro_credits, 50);
        assert_eq!(resp.resource_body, b"{\"ok\":true}");
        assert_eq!(resp.resource_status, 200);
    }

    #[tokio::test]
    async fn x402_pay_declines_over_cap_before_signing() {
        let server = MockServer::start().await;
        // Only the 402 leg — if it signed + retried, the request would
        // 404 (no matching signed mock). Getting Declined proves the
        // cap short-circuited before signing.
        mount_402(&server, "50").await;

        let resp = service()
            .x402_pay(Request::new(req(&server.uri(), "base-sepolia", Some(10))))
            .await
            .expect("x402_pay")
            .into_inner();

        assert_eq!(resp.status, "declined");
        assert_eq!(resp.micro_credits, 50);
        assert!(resp.declined_reason.contains("max_amount"));
    }

    #[tokio::test]
    async fn x402_pay_not_required_when_unpaywalled() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data"))
            .respond_with(ResponseTemplate::new(200).set_body_string("free"))
            .mount(&server)
            .await;

        // Empty network defaults to base-sepolia.
        let resp = service()
            .x402_pay(Request::new(req(&server.uri(), "", None)))
            .await
            .expect("x402_pay")
            .into_inner();

        assert_eq!(resp.status, "not_required");
        assert_eq!(resp.resource_status, 200);
        assert_eq!(resp.resource_body, b"free");
    }

    #[tokio::test]
    async fn x402_pay_rejects_mainnet_behind_gate() {
        let err = service()
            .x402_pay(Request::new(req("https://example.com", "base", None)))
            .await
            .expect_err("mainnet must be gated");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn x402_pay_rejects_unknown_network() {
        let err = service()
            .x402_pay(Request::new(req("https://example.com", "solana", None)))
            .await
            .expect_err("unknown network must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn x402_pay_rejects_empty_resource_url() {
        let mut r = req("https://example.com", "base-sepolia", None);
        r.resource_url = String::new();
        let err = service()
            .x402_pay(Request::new(r))
            .await
            .expect_err("empty resource_url must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn derive_custody_seed_is_deterministic_and_scoped() {
        // Same (user, project) → same wallet address; different user →
        // different address. The x402 signing key is stable per pair.
        let wa1 = InProcessAnima::from_seed_arc(derive_custody_seed("alice", "proj")).unwrap();
        let wa2 = InProcessAnima::from_seed_arc(derive_custody_seed("alice", "proj")).unwrap();
        let wb = InProcessAnima::from_seed_arc(derive_custody_seed("bob", "proj")).unwrap();
        let addr1 = wa1.wallet_address().unwrap().address.clone();
        let addr2 = wa2.wallet_address().unwrap().address.clone();
        let addrb = wb.wallet_address().unwrap().address.clone();
        assert_eq!(addr1, addr2, "same pair must resolve the same wallet");
        assert_ne!(
            addr1, addrb,
            "different user must resolve a different wallet"
        );
    }

    #[test]
    fn resolve_network_maps_base_sepolia_and_gates_mainnet() {
        assert!(resolve_network("").is_ok());
        assert!(resolve_network("base-sepolia").is_ok());
        assert_eq!(
            resolve_network("base").unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            resolve_network("ethereum").unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
}

//! Topology-B end-to-end wire test for BRO-1018.
//!
//! Boots a minimal `HaimaState`, exposes `haima.v1.WalletSubstrate`
//! on a tempdir UDS, dials it via `haima-proxy`'s `HaimaProxy`
//! builder, and asserts that:
//!
//! 1. `HaimaProxy::bind_wallet(sid, project_id)` actually causes the
//!    underlying `HaimaState` to gain that wallet — proving the wire
//!    moves args through the substrate (not a hardcoded shape).
//! 2. `HaimaProxy::transfer(...)` actually mutates the real substrate
//!    ledger (both legs land), proving the wire transports the
//!    operation end-to-end. The F2 lago publisher integration is out
//!    of scope for Phase 3 — substrate state IS the source of truth
//!    until F2 wires `haima-lago::FinancePublisher`.
//! 3. Proxy → server round-trip: bind → debit → statement → transfer
//!    composes against the same in-memory state, with each call
//!    visible to the next.
//!
//! This is the contract the four-PR Topology-B audit (entity page
//! `research/entities/concept/topology-b-substrate-stub-gap.md`)
//! demanded a real wire for. Lifed isn't wired in here — adding it
//! would pull haima-core / haima-wallet into the `lifed`/`haima-proxy`
//! dep tree and break `scripts/verify_dependencies_lifed.sh`. The
//! lifed → haima-proxy boundary is already covered by lifed's own
//! integration suite (it exercises the `HaimaCall` trait), so
//! end-to-end coverage in production is the COMPOSITION of those two
//! suites — same pattern as BRO-1016's
//! `topology_b_e2e_arcan.rs`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use haima_proxy::HaimaProxy;
use haima_substrate_proto::haima::v1::wallet_substrate_server::WalletSubstrateServer;
use haimad::state::HaimaState;
use haimad::substrate::SubstrateService;
use tempfile::TempDir;
use tokio::sync::oneshot;

/// Spin up the substrate gRPC server on a tempdir UDS socket and
/// return the socket path + shutdown handle. The server consumes a
/// shared `Arc<HaimaState>` so the test can read its state after
/// driving calls through the proxy.
struct SubstrateUnderTest {
    socket: PathBuf,
    _tempdir: TempDir,
    state: Arc<HaimaState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SubstrateUnderTest {
    async fn start() -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let socket = tempdir.path().join("haimad.sock");
        let state = Arc::new(HaimaState::new());

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let service = SubstrateService::new(Arc::clone(&state));
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind UDS");
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

        let server_handle = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(WalletSubstrateServer::new(service))
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        // Wait for the socket to appear.
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(socket.exists(), "substrate socket bound");

        Self {
            socket,
            _tempdir: tempdir,
            state,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
        }
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.server_handle.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
    }
}

#[tokio::test]
async fn bind_wallet_creates_real_wallet() {
    let env = SubstrateUnderTest::start().await;
    let proxy = HaimaProxy::connect(env.socket.clone())
        .await
        .expect("dial substrate UDS");

    let wallet_id = proxy
        .bind_wallet("bro-1018-bind-sid", "proj-bind")
        .await
        .expect("bind_wallet");

    // Substrate-side proof: BEFORE BRO-1018 this would have stayed at
    // 0 wallets because the proxy returned `format!("wallet-{sid}-{project_id}")`
    // without touching the substrate. AFTER BRO-1018 the substrate
    // HaimaState now has the wallet — and its id matches the proxy
    // return value.
    assert_eq!(
        env.state.wallet_count(),
        1,
        "wallet materialised substrate-side"
    );
    assert_eq!(
        wallet_id,
        HaimaState::wallet_id_for("bro-1018-bind-sid", "proj-bind"),
        "wallet_id mirrors the deterministic substrate shape"
    );

    // Idempotency: re-binding the same (sid, project_id) returns the
    // same wallet_id and does NOT create a duplicate substrate-side.
    let wallet_id_again = proxy
        .bind_wallet("bro-1018-bind-sid", "proj-bind")
        .await
        .expect("re-bind idempotent");
    assert_eq!(wallet_id, wallet_id_again);
    assert_eq!(
        env.state.wallet_count(),
        1,
        "still one wallet after idempotent re-bind"
    );

    // Unbind drops the wallet on the substrate side — saga
    // compensation path proven.
    proxy
        .unbind_wallet(&wallet_id)
        .await
        .expect("unbind_wallet");
    assert_eq!(env.state.wallet_count(), 0, "wallet dropped substrate-side");
    // Idempotent: a second unbind on an unknown wallet still returns Ok.
    proxy
        .unbind_wallet("wallet-never-existed")
        .await
        .expect("unbind unknown wallet ok");

    env.shutdown().await;
}

#[tokio::test]
async fn transfer_mutates_real_substrate_state() {
    let env = SubstrateUnderTest::start().await;
    let proxy = HaimaProxy::connect(env.socket.clone())
        .await
        .expect("dial substrate UDS");

    // Both wallets are materialised on demand by `transfer` (the
    // substrate's `get_or_create_user_wallet` covers cold reads).
    let (entry_id, from_after, to_after) = proxy
        .transfer(
            "alice",
            "proj-A",
            "bob",
            "proj-B",
            100_000, // 0.1 USDC
            "memo-test",
        )
        .await
        .expect("transfer");
    assert!(!entry_id.is_empty(), "entry_id non-empty");

    // Default starting balance is 1_000_000 micros; alice should be
    // down 100k and bob should be up 100k.
    assert_eq!(from_after.micros, 900_000);
    assert_eq!(to_after.micros, 1_100_000);

    // Substrate-side proof: F2 lago publisher is stubbed, so the
    // wire contract for BRO-1018 is "the substrate's in-memory
    // ledger actually changed." Before BRO-1018, the proxy returned
    // hardcoded balances (999_000 / 100_000) regardless of args.
    // After BRO-1018, balances and entries are derived from the
    // server-side HaimaState.
    let bal_alice = env.state.balance("alice", "proj-A");
    let bal_bob = env.state.balance("bob", "proj-B");
    assert_eq!(bal_alice.0, 900_000);
    assert_eq!(bal_bob.0, 1_100_000);

    // Both legs landed in the server-side ledger.
    let alice_ledger = env.state.statement("alice", "proj-A", 0, i64::MAX, 0);
    let bob_ledger = env.state.statement("bob", "proj-B", 0, i64::MAX, 0);
    assert_eq!(alice_ledger.len(), 1);
    assert_eq!(bob_ledger.len(), 1);
    assert_eq!(alice_ledger[0].delta_micros, -100_000);
    assert_eq!(bob_ledger[0].delta_micros, 100_000);
    // Memo flows through.
    assert!(alice_ledger[0].reason.contains("memo-test"));

    env.shutdown().await;
}

#[tokio::test]
async fn proxy_to_server_round_trip() {
    let env = SubstrateUnderTest::start().await;
    let proxy = HaimaProxy::connect(env.socket.clone())
        .await
        .expect("dial substrate UDS");

    // Compose the typical lifed saga path: bind → debit → statement.
    let _wallet_id = proxy.bind_wallet("sid-rt", "proj-rt").await.expect("bind");

    // BindWallet uses (sid, project_id); Debit / GetBalance /
    // Transfer use (user_id, project_id). Use the same string for
    // both axes so the ids align with the deterministic shape
    // `wallet-{sid}-{project_id}`.
    let (entry_id, balance_after) = proxy
        .debit("sid-rt", "proj-rt", 250_000, "sid-rt", "round-trip")
        .await
        .expect("debit");
    assert!(!entry_id.is_empty());
    // 1_000_000 - 250_000 = 750_000.
    assert_eq!(balance_after.micros, 750_000);
    assert_eq!(balance_after.currency, "USDC");

    // GetBalance probes substrate-side state directly. Mirrors the
    // post-debit value because the wire just exposes HaimaState.
    let probed = proxy
        .get_balance("sid-rt", "proj-rt")
        .await
        .expect("get_balance");
    assert_eq!(probed.micros, 750_000);

    // Statement streams the one entry we just produced.
    let mut stmt = proxy
        .statement("sid-rt", "proj-rt", 0, i64::MAX, 0)
        .await
        .expect("statement");
    let first = stmt
        .next()
        .await
        .expect("≥1 entry")
        .expect("stream item ok");
    assert_eq!(first.delta_micros, -250_000);
    assert_eq!(first.reason, "round-trip");
    // No second entry — the cap is one debit.
    assert!(stmt.next().await.is_none());
    drop(stmt);

    env.shutdown().await;
}

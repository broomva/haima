# Haima — Agentic Finance Engine for the Agent OS

**Version**: 0.1.0 | **Date**: 2026-03-19 | **Status**: Phase F0 COMPLETE (Foundation)
**Tests**: 45 passing | 6 crates | Rust 2024 Edition (MSRV 1.85)

Haima (αἷμα, Greek for "blood") is the circulatory system of the Agent OS —
distributing economic resources (payments, revenue, credits) throughout the
organism. It implements the x402 protocol for machine-to-machine payments
at the HTTP layer, enabling agents to pay for resources and charge for services
without human intervention.

## Build & Verify
```bash
cargo fmt && cargo clippy --workspace -- -D warnings && cargo test --workspace
```

## Stack
Rust 2024 | axum (HTTP API) | k256 (secp256k1) | x402 protocol | aios-protocol (canonical contract) | lago (event journal)

## Crates
- `haima-core` (19 tests) — Types, traits, errors: payment schemes, receipts, wallets, policies, finance events
- `haima-wallet` (7 tests) — secp256k1 keypair generation, EVM address derivation, ChaCha20-Poly1305 encrypted key storage, WalletBackend trait (local + MPC abstraction)
- `haima-x402` (7 tests) — x402 protocol integration: client middleware (auto-pay on 402), server middleware (protect routes), facilitator client (Coinbase CDP / self-hosted)
- `haima-lago` (8 tests) — Lago bridge: finance event publishing, deterministic projection fold → FinancialState
- `haima-api` (2 tests) — axum HTTP server: /health, /state endpoints
- `haimad` (2 tests) — Daemon binary with CLI args, config, optional Lago journal

## Running

```bash
# Standalone mode (empty projections, for testing)
cargo run -p haimad -- --bind 127.0.0.1:3003

# With Lago persistence (production — reads events from journal)
cargo run -p haimad -- --bind 127.0.0.1:3003 --lago-data-dir /path/to/data
```

### API Endpoints
- `GET /health` — health check
- `GET /state` — full financial state projection

## Architecture

### x402 Protocol Flow (Agent as Client)
```
Agent (Arcan) → HTTP request → 402 + PAYMENT-REQUIRED header
  → Haima parses payment terms
  → Evaluates against PaymentPolicy (auto-approve ≤100μc / approval / deny >1Mc)
  → Signs with agent's secp256k1 wallet (WalletBackend)
  → Retries with PAYMENT-SIGNATURE header
  → Receives 200 + PAYMENT-RESPONSE (settlement confirmation)
  → Records finance.payment_settled event to Lago
  → Autonomic updates EconomicState
```

### x402 Protocol Flow (Agent as Server)
```
External client → HTTP request to agent's paid endpoint
  → Haima middleware returns 402 + PAYMENT-REQUIRED
  → Client signs and retries with payment
  → Facilitator verifies and settles on-chain
  → Revenue recorded as finance.revenue_received
  → Task billing: per-task pricing via finance.task_billed events
```

### Revenue Model
Per-task billing. Agent completes a task, creates a `TaskBilled` event with price.
When client pays, `RevenueReceived` clears the bill and credits the agent's balance.

### Economic Bridge
```
1 USDC = 1,000,000 micro-credits (μc)
Default auto-approve cap: 100 μc ($0.0001)
Default hard cap per tx: 1,000,000 μc ($1.00)
Default session spend cap: 10,000,000 μc ($10.00)
```

Autonomic's `EconomicState.balance_micro_credits` maps directly to on-chain USDC balance.
Periodic `BalanceSynced` events reconcile internal ledger with on-chain state.

## Critical Patterns
- **All events use `EventKind::Custom` with `"finance."` namespace** (forward-compatible through Lago)
- **WalletBackend trait abstracts local vs MPC wallets** — local uses k256 + ChaCha20-Poly1305; MPC (Coinbase CDP) planned for later
- **PaymentPolicy evaluates every payment** — auto-approve, require-approval, or deny based on amount, mode, and session caps
- **FinancialState is a projection** — never mutated directly, only recomputed by fold over events
- **Chain support**: Base (EVM, eip155:8453) first. Solana planned for later.
- **Facilitator**: Coinbase CDP default. Abstractions support self-hosted and Stripe.
- **Economic modes interact**: Hibernate blocks payments, Hustle allows only auto-approve, Sovereign/Conserving allow all

## Dependency Order
```
aios-protocol (canonical contract)
    |
haima-core (types + traits + events + policy)
    |          \
haima-wallet    haima-lago (+ lago-core, lago-journal)
    |          /
haima-x402 (x402 protocol: client, server, facilitator)
    |
haima-api (axum HTTP)
    |
haimad (binary)
```

## Relationship to Agent OS

```
aiOS (kernel contract)
  ├── Arcan (cognition) ── arcan-haima bridge → Haima (payments)
  ├── Autonomic (homeostasis) ← CostReason::ExternalPayment events
  └── Lago (persistence) ← finance.* events via EventKind::Custom
```

Arcan consults Haima when:
1. Tool execution encounters HTTP 402 (client-side payment)
2. Agent completes a task and prices it (server-side billing)
3. Session starts (load financial state from Lago projection)

Autonomic consults Haima's events for:
1. Real payment costs (not just model inference estimates)
2. Revenue tracking (burn-rate calculations include income)
3. On-chain balance reconciliation (drift detection)

## Phase Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **F0: Foundation** | Core types, wallet (k256), policy, events, API scaffold, projection fold | COMPLETE |
| **F1: x402 Client** | x402-rs integration, header parsing, signing, facilitator settlement | PLANNED |
| **F2: Ledger** | Wire to Lago EventStorePort, autonomic CostReason integration | PLANNED |
| **F3: x402 Server** | Axum middleware, task billing, revenue collection | PLANNED |
| **F4: Daemon** | Full haimad with Lago persistence, balance sync, transaction history | PLANNED |
| **F5: Solana** | Solana chain support via x402-chain-solana | PLANNED |
| **F6: MPP** | Stripe Machine Payments Protocol (when Rust SDK ships) | FUTURE |

## Known Gaps (Post Phase F0)

- x402 header parsing and signing stubbed (pending x402-rs integration in F1)
- EIP-3009 transferWithAuthorization signing not implemented
- Lago EventStorePort not wired (publisher logs only)
- No arcan-haima bridge crate yet
- No CLI commands (lago-cli style)
- No on-chain balance query (requires RPC provider)
- Identity not connected to Autonomic's EconomicIdentity

## Rules
- **Formatting**: `cargo fmt` before every commit
- **Linting**: `cargo clippy --workspace -- -D warnings`
- **Testing**: All new code requires tests; `cargo test --workspace` must pass
- **Safe Rust**: No `unsafe` unless absolutely necessary
- **Error handling**: `thiserror` for libraries, `anyhow` for binaries
- **Naming**: `snake_case` (functions/files), `PascalCase` (types/traits), `SCREAMING_SNAKE_CASE` (constants)
- **Rust 2024 Edition**: `gen` is reserved keyword; `set_var`/`remove_var` are `unsafe`
- **Module style**: Use `name.rs` file-based modules (not `mod.rs`)
- **Private keys**: Always zeroize on drop; never log key material
- **Financial events**: Always use `"finance."` namespace prefix for `EventKind::Custom`

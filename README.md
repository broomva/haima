# Haima

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](#)
[![docs](https://img.shields.io/badge/docs-broomva.tech-purple.svg)](https://docs.broomva.tech/docs/life/haima)

**Agentic finance engine for the Life Agent OS** -- the circulatory system that distributes economic resources throughout the organism.

Haima (Greek: blood) implements the [x402 protocol](https://www.x402.org/) for machine-to-machine payments at the HTTP layer, enabling agents to pay for resources and charge for services without human intervention.

## Architecture

```
                          +------------------+
                          |    Arcan (Agent)  |
                          +--------+---------+
                                   |
                    HTTP 402 / Payment Required
                                   |
                          +--------v---------+
                          |   haima-x402     |
                          |  (client/server) |
                          +--------+---------+
                                   |
                 +-----------------+-----------------+
                 |                                   |
        +--------v---------+              +----------v--------+
        |   haima-wallet   |              |    haima-core      |
        | secp256k1 keypair|              | types, policy,     |
        | EVM address      |              | events, receipts   |
        | ChaCha20 encrypt |              +----------+--------+
        +------------------+                         |
                                           +---------v--------+
                                           |   haima-lago     |
                                           | event publishing |
                                           | projection fold  |
                                           +------------------+
                                                     |
                                              +------v------+
                                              |    Lago     |
                                              | (journal)   |
                                              +-------------+
```

## x402 Protocol Flow

### Agent as Client (paying for resources)

```
Agent (Arcan) --> HTTP request --> 402 + PAYMENT-REQUIRED header
  --> Haima parses payment terms
  --> Evaluates against PaymentPolicy (auto-approve / approval / deny)
  --> Signs with agent's secp256k1 wallet
  --> Retries with PAYMENT-SIGNATURE header
  --> Receives 200 + PAYMENT-RESPONSE (settlement confirmation)
  --> Records finance.payment_settled event to Lago
```

### Agent as Server (charging for services)

```
External client --> HTTP request to agent's paid endpoint
  --> Haima middleware returns 402 + PAYMENT-REQUIRED
  --> Client signs and retries with payment
  --> Facilitator verifies and settles on-chain
  --> Revenue recorded as finance.revenue_received
  --> Per-task billing via finance.task_billed events
```

## Crates

| Crate | Tests | Purpose |
|-------|-------|---------|
| `haima-core` | 19 | Types, traits, errors: payment schemes, receipts, wallets, policies, finance events |
| `haima-wallet` | 7 | secp256k1 keypair generation, EVM address derivation, ChaCha20-Poly1305 encrypted key storage |
| `haima-x402` | 7 | x402 protocol: client middleware (auto-pay on 402), server middleware, facilitator client |
| `haima-lago` | 8 | Lago bridge: finance event publishing, deterministic projection fold to FinancialState |
| `haima-api` | 2 | axum HTTP server: /health, /state endpoints |
| `haimad` | 2 | Daemon binary with CLI args, config, optional Lago journal |

## Quick Start

```bash
# Standalone mode (in-memory projections, for testing)
cargo run -p haimad -- --bind 127.0.0.1:3003

# With Lago persistence (production -- reads events from journal)
cargo run -p haimad -- --bind 127.0.0.1:3003 --lago-data-dir /path/to/data
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/state` | Full financial state projection |
| `POST` | `/v1/facilitate` | Submit a payment for facilitator settlement |
| `GET` | `/v1/credit/{id}` | Query credit balance for an agent |
| `GET` | `/v1/bureau/{id}` | Query bureau status (credit history) |
| `POST` | `/v1/credit/{id}/line` | Open or modify a credit line |

## Payment Policy

Every payment is evaluated against a `PaymentPolicy`:

| Threshold | Action | Default |
|-----------|--------|---------|
| Auto-approve | Proceed without confirmation | <= 100 micro-credits ($0.0001) |
| Require approval | Queue for human/agent review | 100 - 1,000,000 micro-credits |
| Deny | Reject payment | > 1,000,000 micro-credits ($1.00) |

Session spend cap: 10,000,000 micro-credits ($10.00).

Economic bridge: **1 USDC = 1,000,000 micro-credits**.

## Build and Test

```bash
# Full verification
cargo fmt && cargo clippy --workspace -- -D warnings && cargo test --workspace

# Run tests only
cargo test --workspace

# Build release
cargo build --workspace --release
```

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

## Chain Support

- **Primary**: Base (EVM, eip155:8453)
- **Planned**: Solana
- **Facilitator**: Coinbase CDP default; self-hosted and Stripe abstractions ready

## Documentation

Full documentation: [docs.broomva.tech/docs/life/haima](https://docs.broomva.tech/docs/life/haima)

## License

[MIT](LICENSE)

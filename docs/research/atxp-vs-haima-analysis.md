# ATXP.ai vs Haima: Agentic Finance Architecture Analysis

> Research date: 2026-03-26
> Source: https://docs.atxp.ai/
> Purpose: Evaluate whether Haima can benefit from ATXP's patterns, either by inheriting ideas or leveraging infrastructure

---

## 1. Executive Summary

**ATXP** (Agent Transaction Protocol) and **Haima** both solve the same fundamental problem: giving AI agents financial agency — the ability to discover, pay for, and monetize services autonomously. They arrive at the solution from opposite directions.

| | ATXP | Haima |
|---|------|-------|
| **Philosophy** | Centralized marketplace SaaS | Self-sovereign event-sourced substrate |
| **Payment protocol** | Custom OAuth + centralized billing | x402 (HTTP 402 native, standards-based) |
| **Wallet model** | Custodial (ATXP holds funds) | Self-custodial (secp256k1 + ChaCha20-Poly1305) |
| **State model** | Mutable custodial balance | Deterministic projection from Lago event journal |
| **Language** | TypeScript (npm ecosystem) | Rust (Cargo workspace) |

ATXP validates the market for agent-to-agent commerce and has excellent developer ergonomics. Haima has deeper architecture (event sourcing, credit scoring, insurance, outcome-based pricing) but can learn from ATXP's onboarding UX and middleware patterns.

**Recommendation**: Don't adopt ATXP's custodial model. Instead, (1) steal the MCP payment middleware DX, (2) build prepaid credit channels, (3) add LLM gateway billing, (4) ensure x402 interop with ATXP's `@atxp/x402` bridge, and (5) ship a `haima agent init` one-liner.

---

## 2. ATXP Platform Overview

### 2.1 What ATXP Is

ATXP is a **two-sided marketplace** for AI agent economic transactions. Rather than "agentic commerce" (agents buying goods for humans), ATXP enables **agent-to-agent economic transactions** — agents paying for their own compute, tools, and sub-agent services.

Core thesis: agents should have wallets and pay for services, rather than relying on pre-configured credentials. This removes the bottleneck of credential provisioning and enables nested payment layers (humans fund agents, agents fund sub-agents, recursively).

### 2.2 Architecture Components

```
+------------------+     +------------------+     +------------------+
|  Agent (Client)  |     |  ATXP Platform   |     | Tool (MCP Server)|
|                  |     |                  |     |                  |
| @atxp/client     |---->| OAuth + Billing  |---->| @atxp/express    |
| ATXPAccount      |     | Account Ledger   |     | requirePayment() |
| approvePayment() |     | Settlement       |     | BigNumber price  |
+------------------+     +------------------+     +------------------+
        |                        |                        |
        v                        v                        v
  Connection Token        USDC Settlement          MCP SSE Transport
  (Bearer auth)       (Base/Solana/Polygon)    (Streamable HTTP)
```

**Key components**:

1. **LLM Gateway** (`llm.atxp.ai/v1`) — OpenAI-compatible endpoint routing to Claude, GPT, Gemini, Llama. Single `ATXP_CONNECTION` bearer token, no per-vendor keys.

2. **Paid MCP Tools** — 12+ tools (search, browse, image, music, video, code sandbox, email, filestore), each as a separate MCP server with per-use billing.

3. **Agent Identity** — Self-registration (`npx atxp agent register`), each agent gets email, Ethereum wallet, $5 credit, connection token.

4. **SDK Packages** — 8 npm packages for both consuming and monetizing tools.

5. **ATXP Skill** — Installable as Claude Code / Cursor / VS Code skill.

### 2.3 SDK Package Map

| Package | Purpose |
|---------|---------|
| `@atxp/client` | MCP client with OAuth + payment handling |
| `@atxp/express` | Express middleware for monetized MCP servers |
| `@atxp/server` | Support package (requirePayment, atxpAccountId helpers) |
| `@atxp/cloudflare` | Cloudflare Workers adapter for monetized MCP servers |
| `@atxp/common` | Shared types: Account, PaymentData, AuthorizationData, errors |
| `@atxp/base` | Coinbase Base Mini App integration (ephemeral wallets, spend permissions) |
| `@atxp/solana` | Solana wallet integration |
| `@atxp/sqlite` / `@atxp/redis` | Persistent OAuth token storage backends |
| `@atxp/x402` | Bridge adapter to x402-compatible MCP servers |

---

## 3. ATXP Technical Deep Dive

### 3.1 Payment Flow

**Client side** (agent paying for a tool):

```typescript
import { atxpClient, ATXPAccount } from '@atxp/client';

const client = await atxpClient({
  mcpServer: 'https://search.mcp.atxp.ai/',
  account: new ATXPAccount(process.env.ATXP_CONNECTION),
  onPayment: (paymentData) => { /* success callback */ },
  onPaymentFailure: (error) => { /* failure callback */ },
  approvePayment: (request) => {
    // Optional: custom approval logic (budget caps, user confirmation)
    // If omitted, all payments auto-approve
    return request.amount.lte(BigNumber(1.00)); // cap at $1
  },
});

const result = await client.callTool({
  name: 'search_search',
  arguments: { query: 'latest AI research' },
});
```

**Server side** (developer monetizing a tool):

```typescript
import { atxpExpress, requirePayment, ATXPAccount } from '@atxp/express';
import BigNumber from "bignumber.js";

// Mount ATXP middleware
app.use(atxpExpress({
  destination: new ATXPAccount(process.env.ATXP_CONNECTION),
  payeeName: 'My Tool Server',
  minimumPayment: BigNumber(0.50), // enables batch prepayment
}));

// Per-tool pricing
server.tool("upcase", "Convert text to uppercase",
  { text: z.string() },
  async ({ text }) => {
    await requirePayment({ price: BigNumber(0.01) }); // $0.01 USDC
    return { content: [{ type: "text", text: text.toUpperCase() }] };
  }
);
```

**Cloudflare Workers variant**:

```typescript
import { requirePayment, atxpCloudflare } from "@atxp/cloudflare";
import { ATXPAccount } from "@atxp/server";

export class MyMCP extends McpAgent<Env, unknown, ATXPMCPAgentProps> {
  server = new McpServer({ name: "My Server", version: "1.0.0" });

  async init() {
    this.server.tool("hello_world", { name: z.string().optional() },
      async ({ name }) => {
        await requirePayment(
          { price: new BigNumber(0.01) },
          createOptions(this.env),
          this.props,
        );
        return { content: [{ type: "text", text: `Hello, ${name}!` }] };
      }
    );
  }
}
```

### 3.2 Batch / Prepaid Payments

To reduce per-call latency and payment prompts:

```typescript
app.use(atxpExpress({
  destination: new ATXPAccount(process.env.ATXP_CONNECTION),
  payeeName: 'My Server',
  minimumPayment: BigNumber(0.50), // prepay $0.50
}));

// Each call charges $0.05 against prepaid balance
server.tool("analyze", ..., async (args) => {
  await requirePayment({ price: BigNumber(0.05) });
  // ...
});
```

On first call, the user pays `max(minimumPayment, price)`. Subsequent calls deduct from balance. New prompt when balance depletes. Balance tracking via `@atxp/sqlite` or `@atxp/redis`.

### 3.3 x402 Interoperability

ATXP treats x402 as an **external ecosystem to bridge into**, not as its core protocol:

```typescript
import { wrapWithX402 } from '@atxp/x402';

const client = await atxpClient({
  mcpServer: 'https://some-x402-server.example.com',
  account: new ATXPAccount(process.env.ATXP_CONNECTION),
  fetchFn: wrapWithX402(config), // intercepts HTTP 402 responses
});
```

**Key insight**: ATXP's own payment flow is OAuth-based (connection string + centralized billing), not HTTP 402 based. The x402 adapter is an interoperability layer, not the core mechanism.

### 3.4 LLM Gateway

OpenAI-compatible, works with any OpenAI client:

```typescript
// Direct OpenAI SDK
const openai = new OpenAI({
  apiKey: process.env.ATXP_CONNECTION,
  baseURL: 'https://llm.atxp.ai/v1'
});

// Vercel AI SDK
const atxp = createOpenAICompatible({
  name: 'atxp-llm',
  apiKey: process.env.ATXP_CONNECTION,
  baseURL: 'https://llm.atxp.ai/v1'
});
const { text } = await generateText({
  model: atxp('gpt-4.1'),
  prompt: 'What is the capital of France?',
});

// Python
client = OpenAI(
    api_key=os.environ.get("ATXP_CONNECTION"),
    base_url="https://llm.atxp.ai/v1",
)
```

### 3.5 Agent Identity & Wallets

```bash
npx atxp agent register
# -> Agent ID, email ({id}@atxp.email), Ethereum wallet, $5 credit, connection token

npx atxp fund
# -> Crypto deposit addresses (Base, World, Polygon) + Stripe payment link
```

- Identity: Google OAuth + connection string (no DIDs, no decentralized identity)
- Wallet: Platform-managed Ethereum wallet (custodial, not self-custodial)
- Auth: Connection string as Bearer token

### 3.6 Shared Types (`@atxp/common`)

```typescript
interface PaymentData {
  amount: BigNumber;
  currency: string;
  transactionId: string;
  timestamp: Date;
  toolName?: string;
}

interface PaymentRequest {
  amount: BigNumber;
  currency: string;
  toolName?: string;
  description?: string;
}

interface AuthorizationData {
  userId: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: Date;
}
```

### 3.7 Settlement Mechanics

- **Currency**: USDC (all `requirePayment` amounts in USDC)
- **Chains**: Base (Ethereum L2), Solana, Polygon, Worldchain, EVM-compatible
- **Default**: Custodial through ATXP (centralized ledger)
- **Alternative**: On-chain via `@atxp/base` (ephemeral wallet with spend permissions) or `@atxp/solana`

### 3.8 MCP Proxy (for non-native clients)

```
https://accounts.atxp.ai?connection_token=<secret>&account_id=<id>&server=image.mcp.atxp.ai
```

Auto-handles payments for clients that don't support OAuth/payments natively.

### 3.9 Tool Catalog

| Tool | MCP Server | Tool Name |
|------|-----------|-----------|
| Search | `search.mcp.atxp.ai` | `search_search` |
| Browse | `browse.mcp.atxp.ai` | `atxp_browse` |
| Image | `image.mcp.atxp.ai` | `image_create_image` |
| Music | `music.mcp.atxp.ai` | `music_create` |
| Video | `video.mcp.atxp.ai` | `create_video` |
| X Live Search | `x-live-search.mcp.atxp.ai` | `x_live_search` |
| Email | `email.mcp.atxp.ai` | `email_check_inbox`, `email_send_email` |
| PaaS | `paas.mcp.atxp.ai` | Functions, databases, storage |
| Code | (sandbox) | JS, Python, TS execution |

---

## 4. Haima Current State (Phase F0)

### 4.1 Architecture

Haima is the **circulatory system** of the Life Agent OS — distributing economic resources via x402 machine-to-machine payments. Every financial action becomes an immutable Lago event.

```
+------------------+     +------------------+     +------------------+
|  Arcan (Runtime) |     |  Haima Engine    |     |  External Service|
|                  |     |                  |     |                  |
| Encounters 402   |---->| PaymentPolicy    |---->| x402 Server      |
| or bills a task  |     | WalletBackend    |     | HTTP 402 + Header|
|                  |     | Lago Publisher   |     |                  |
+------------------+     +------------------+     +------------------+
        |                        |                        |
        v                        v                        v
  Agent Loop              Event Journal            On-chain USDC
  (reconstruct->          (deterministic           (Coinbase CDP
   provide->execute)       projection)              facilitator)
```

### 4.2 Crate Structure

| Crate | Tests | Purpose |
|-------|-------|---------|
| `haima-core` | 19 | Core types, policy, schemes, receipts, events (21 kinds), credit, lending, insurance, marketplace |
| `haima-wallet` | 7 | secp256k1 keypair, ChaCha20-Poly1305 encryption, WalletBackend trait, LocalSigner |
| `haima-x402` | 7 | x402 HTTP protocol: client middleware (402 -> sign -> retry), server middleware, facilitators |
| `haima-lago` | 8 | Lago event journal bridge, deterministic FinancialState projection, insurance/outcome state |
| `haima-api` | 2 | Axum REST API: facilitation, credit bureau, outcome contracts, insurance marketplace |
| `haimad` | 2 | Daemon binary, CLI, tracing, JWT auth, background SLA monitor |

**Total**: 45 tests, ~15K LOC across 6 crates.

### 4.3 Micro-Credit Economy

```
1 USDC = 1,000,000 micro-credits (uc)
```

**Policy verdict thresholds** (default):
- <= 100 uc ($0.0001) -> `AutoApproved` (instant, no gate)
- 100 - 1,000,000 uc ($0.0001 - $1) -> `RequiresApproval` (human/agent gate)
- \> 1,000,000 uc ($1) -> `Denied`
- Session cap: 10,000,000 uc ($10)
- Rate limit: 10 tx/minute
- Economic mode gating: Hibernate blocks all, Hustle allows only auto-approve

### 4.4 x402 Payment Flow

**Client flow** (agent paying):
1. HTTP request to external service
2. Receive HTTP 402 + `PAYMENT-REQUIRED` header (base64 JSON)
3. Parse `PaymentRequiredHeader` -> select scheme -> convert amount to uc
4. Evaluate against `PaymentPolicy` (auto-approve / approval / deny)
5. If auto-approved: `sign_payment()` -> `PaymentSignatureHeader` (base64 JSON)
6. Retry request with `PAYMENT-SIGNATURE` header
7. Receive 200 + `PAYMENT-RESPONSE` -> settlement confirmation + tx hash
8. Publish `PaymentSettled` event to Lago journal

**Server flow** (agent charging):
- x402 middleware returns 402 for protected routes with accepted schemes
- Client signs and retries with payment signature
- Facilitator verifies signature and settles on-chain
- Publish `RevenueReceived` event to Lago journal

### 4.5 Advanced Features (beyond ATXP)

**Credit Scoring (Behavioral)**:
```
Tier      Score Range   Credit Limit
None      < 0.3         $0 (prepay only)
Micro     0.3 - 0.5     $0.001
Standard  0.5 - 0.75    $0.10
Premium   >= 0.75       $10.00
```
Factors: trust score (from Autonomic), payment history, transaction volume, account age, economic stability.

**Revolving Credit Lines**:
- Micro: 15% APR (1500 bps)
- Standard: 10% APR (1000 bps)
- Premium: 5% APR (500 bps)

**Outcome-Based Pricing**: Task types (code review, data pipeline, support ticket, document generation) with complexity tiers driving price multipliers. Success criteria verification and SLA-based automatic refunds.

**Insurance Marketplace**: Self-insurance pool (network-funded, 2.5% management fee) + licensed MGA partners. Products: task failure, financial error, data breach, SLA penalty.

### 4.6 Event Taxonomy (21 Finance Events)

```
PaymentRequested, PaymentAuthorized, PaymentSettled, PaymentFailed,
RevenueReceived, WalletCreated, BalanceSynced, TaskBilled, PaymentAttempted,
CreditInsufficient, TaskContracted, TaskVerified, TaskRefunded,
PolicyIssued, PremiumCollected, ClaimSubmitted, ClaimVerified, ClaimPaid,
ClaimDenied, PoolContribution, PoolPayout, RiskAssessed
```

All published as `EventKind::Custom("finance.*")` to Lago journal for forward-compatible persistence.

### 4.7 Integration Points

| System | Integration |
|--------|-------------|
| **Arcan** | Consult Haima on HTTP 402, record task billing, load financial state on session start |
| **Autonomic** | Read trust scores + economic mode for policy evaluation, receive real cost data for burn-rate |
| **Lago** | All finance events persisted as Custom entries, FinancialState projected deterministically |
| **Spaces** | Planned: publish financial events to agent-logs channel |

### 4.8 Known Gaps (Post F0)

- [ ] x402 header signing (pending x402-rs integration)
- [ ] EIP-3009 `transferWithAuthorization` implementation
- [ ] Lago EventStorePort wiring (publisher logs only)
- [ ] `arcan-haima` bridge crate
- [ ] CLI commands (`haima agent init` style)
- [ ] On-chain balance query via RPC
- [ ] Identity connection to Autonomic's EconomicIdentity
- [ ] Solana chain support
- [ ] LLM gateway billing integration

---

## 5. Head-to-Head Comparison

### 5.1 Protocol & Payment Architecture

| Dimension | ATXP | Haima |
|-----------|------|-------|
| **Core protocol** | Custom OAuth + centralized billing | x402 (HTTP 402 native) |
| **Standards compliance** | Proprietary | HTTP/x402 standard, CAIP-2 chain IDs |
| **Payment trigger** | `requirePayment()` in tool handler | HTTP 402 response + headers |
| **Payment resolution** | Server-side await (centralized ledger debit) | Client-side sign + retry + on-chain settle |
| **Latency** | Low (centralized ledger) | Higher (402 round-trip + on-chain) |
| **Interop** | Requires ATXP account | Any x402-compliant client/server |
| **x402 support** | Via adapter (`@atxp/x402`) | Native core protocol |

**Verdict**: x402 is the right bet for protocol — it's standards-based, decentralized, and doesn't require a platform account. ATXP's latency advantage can be closed with prepaid credit channels.

### 5.2 Wallet & Identity

| Dimension | ATXP | Haima |
|-----------|------|-------|
| **Wallet model** | Custodial (ATXP holds keys) | Self-custodial (local secp256k1) |
| **Key management** | Platform-managed | ChaCha20-Poly1305 encrypted, zeroized on drop |
| **Identity** | Google OAuth + connection string | secp256k1 keypair (self-sovereign) |
| **Agent email** | `{id}@atxp.email` (platform-assigned) | None (Spaces identity planned) |
| **Onboarding** | `npx atxp agent register` (instant) | `generate_keypair()` (requires wiring) |

**Verdict**: Haima's self-custodial model is architecturally superior for autonomous agents. ATXP's onboarding UX is better. Haima needs a `haima agent init` one-liner.

### 5.3 State Management

| Dimension | ATXP | Haima |
|-----------|------|-------|
| **State model** | Mutable custodial balance | Event-sourced (Lago journal) |
| **Auditability** | Platform dashboard | Full event replay, time-travel debugging |
| **Projection** | N/A (mutable) | Deterministic fold over events |
| **Persistence** | ATXP servers | Local Lago journal (redb + zstd blobs) |

**Verdict**: Haima's event-sourced model is definitively better for agent autonomy, auditability, and debugging.

### 5.4 Economics & Pricing

| Dimension | ATXP | Haima |
|-----------|------|-------|
| **Pricing model** | Per-token (LLM) + per-call (tools) | Outcome-based (per-task + SLA refunds) |
| **Credit system** | None (prepay only) | 4-tier behavioral scoring + revolving credit |
| **Insurance** | None | Self-insurance pool + MGA partners |
| **Revenue model** | Platform takes a cut (undisclosed) | Peer-to-peer (facilitator fee only) |
| **Economic modes** | None | Sovereign/Conserving/Hustle/Hibernate via Autonomic |

**Verdict**: Haima is significantly more sophisticated. Credit scoring enables bootstrapping new agents. Outcome-based pricing aligns payment with value. Economic modes prevent runaway spend.

### 5.5 Developer Experience

| Dimension | ATXP | Haima |
|-----------|------|-------|
| **Monetize a tool** | 3 lines of JS (`atxpExpress` + `requirePayment`) | Implement x402 server middleware (more setup) |
| **Pay for a tool** | `atxpClient()` with connection string | x402 client middleware on HTTP requests |
| **Language support** | TypeScript (npm), Python (OpenAI compat) | Rust (Cargo), TypeScript/Python SDKs in progress |
| **Framework support** | Express, Cloudflare Workers, Vercel AI SDK | Axum (Rust), SDK wrappers planned |
| **Onboarding** | `npx atxp agent register` -> instant | Manual keypair generation + config |

**Verdict**: ATXP wins on developer ergonomics. This is the primary gap Haima needs to close.

---

## 6. What Haima Should Adopt from ATXP

### 6.1 MCP Payment Middleware DX Pattern

ATXP's `requirePayment()` pattern is the gold standard for developer ergonomics:

```typescript
// ATXP: 1 line to monetize any tool
await requirePayment({ price: BigNumber(0.01) });
```

**Haima equivalent to build** — a Rust attribute macro:

```rust
// Target DX for Haima
#[haima::paid(amount_uc = 10_000)] // 10K uc = $0.01 USDC
async fn my_tool(req: ToolRequest) -> ToolResult {
    // tool implementation — x402 middleware handles payment automatically
}
```

And for the TypeScript SDK:

```typescript
// haima-ts equivalent
import { haimaMiddleware, requirePayment } from 'haima';

app.use(haimaMiddleware({ wallet: process.env.HAIMA_WALLET }));

server.tool("analyze", schema, async (args) => {
  await requirePayment({ amount_uc: 10_000 }); // $0.01
  // ...
});
```

### 6.2 Prepaid Credit Channel (Session Pools)

ATXP's `minimumPayment` batch pattern eliminates per-call latency. Haima should build an equivalent using the existing micro-credit system:

```
Agent starts session
  -> Deposit N uc into session credit pool (single x402 payment)
  -> Each tool call deducts from pool (no 402 round-trip)
  -> When pool < threshold, trigger x402 replenishment
  -> Session end: refund unused balance
```

This maps naturally to Haima's existing `PaymentPolicy`:
- Auto-approve tier (<=100 uc) already acts as a micro-pool
- Extend to support explicit session-scoped prepaid pools
- Pool state lives in Lago as `SessionPoolCreated`, `SessionPoolDepleted`, `SessionPoolRefunded` events

### 6.3 LLM Gateway Billing

ATXP wraps LLM inference behind a single endpoint + billing. Haima should add an LLM proxy that:

1. Proxies requests to any provider (Anthropic, OpenAI, etc.)
2. Records per-token cost as `finance.llm_inference` Lago events
3. Lets Autonomic's economic mode gate inference spend
4. Feeds real cost data back to burn-rate controller
5. Enables agents to bill downstream consumers for inference

This could be a thin `haima-llm` crate wrapping the existing provider abstraction in `arcan-provider`.

### 6.4 Agent Self-Registration UX

Target: one command to go from zero to operational agent wallet:

```bash
haima agent init
# -> Generate secp256k1 keypair
# -> Encrypt and store wallet locally
# -> Register identity with Spaces
# -> Allocate initial micro-credit
# -> Output wallet address + connection info
# -> Ready to consume x402 services
```

### 6.5 Interoperability via x402 Bridge

ATXP has an `@atxp/x402` bridge package. This means a Haima-powered agent can consume ATXP tools transparently:

```
Haima Agent -> HTTP request to ATXP tool
           -> Receives HTTP 402 (via @atxp/x402 bridge)
           -> Haima's x402 client middleware handles payment
           -> Signs with local secp256k1 wallet
           -> Settles via Coinbase CDP facilitator
           -> Tool executes, agent gets result
```

No ATXP account needed. The agent pays on-chain via standard x402. This is a strong selling point for Haima's standards-based approach.

---

## 7. What Haima Already Does Better (Do Not Regress)

### 7.1 Self-Sovereign Wallet

ATXP's custodial model creates a single point of failure and requires platform trust. Haima's local secp256k1 + ChaCha20-Poly1305 encryption means:
- No platform can freeze an agent's funds
- Private keys never leave the agent's environment
- Zeroization on drop prevents key material leakage
- Future MPC backend (Coinbase CDP) adds multi-party security without custodial trust

### 7.2 Event-Sourced Financial State

ATXP's mutable custodial balance is opaque. Haima's deterministic Lago projection enables:
- Full audit trail of every financial action
- Time-travel debugging (replay events to any point)
- Multi-agent financial state aggregation
- Insurance claim verification via event replay
- Zero reconciliation errors (state = fold(events))

### 7.3 Behavioral Credit Scoring

ATXP is prepay-only — agents need funds before they can act. Haima's credit system enables:
- New agents to operate on micro-credit before earning
- Trust building over time (payment history -> higher limits)
- Tiered interest rates incentivizing good behavior
- Integration with Autonomic's trust assessment

### 7.4 Economic Mode Integration

Haima's policy engine is context-aware via Autonomic:
- **Sovereign**: all payments allowed
- **Conserving**: normal operations, higher scrutiny
- **Hustle**: only auto-approve tier
- **Hibernate**: all payments blocked

ATXP has no equivalent — its agents spend blindly until balance hits zero.

### 7.5 Outcome-Based Pricing

ATXP charges per-call regardless of outcome. Haima can:
- Charge based on task completion (not just execution)
- Apply complexity multipliers (simple -> critical)
- Auto-refund on SLA timeout
- Verify success criteria before settlement
- This aligns payment with value delivered, not resources consumed

---

## 8. Strategic Roadmap: Haima F1-F3

Based on this analysis, the recommended next phases:

### F1: Developer Ergonomics (Close the DX gap)

- [ ] `#[haima::paid(amount_uc = N)]` attribute macro for Rust tools
- [ ] `haima agent init` CLI command (wallet + identity + micro-credit)
- [ ] haima-ts SDK: `requirePayment()` equivalent for TypeScript MCP servers
- [ ] haima-py SDK: Python wrapper for x402 client/server

### F2: Prepaid Credit Channels (Close the latency gap)

- [ ] Session-scoped credit pools with single x402 deposit
- [ ] Pool deduction on tool call (no 402 round-trip for pool-covered amounts)
- [ ] Automatic pool replenishment on threshold breach
- [ ] Pool state as Lago events (`SessionPoolCreated/Depleted/Refunded`)

### F3: LLM Gateway Billing (New revenue surface)

- [ ] `haima-llm` proxy crate wrapping provider calls
- [ ] Per-token cost recording as Lago events
- [ ] Autonomic economic mode gating on inference spend
- [ ] Downstream billing (agents charging other agents for inference)

### Deferred: What NOT to adopt from ATXP

- **Custodial wallets**: Conflicts with self-sovereign agent design
- **Centralized billing ledger**: Event sourcing is superior
- **Platform-managed identity**: Rely on secp256k1 + Spaces instead
- **Agent email service**: Nice-to-have but not core; Spaces provides communication
- **Tool registry as platform feature**: Use MCP discovery + x402 pricing instead

---

## 9. ATXP as Ecosystem Partner (Not Competitor)

The most valuable relationship with ATXP is **interoperability, not competition**:

1. **Haima agents can consume ATXP tools** via x402 — no ATXP account needed
2. **ATXP agents can consume Haima-powered tools** via their `@atxp/x402` bridge
3. **ATXP validates the market** for agent-to-agent commerce, de-risking Haima's approach
4. **Different target segments**: ATXP targets TS/JS developers wanting quick setup; Haima targets the Rust Agent OS ecosystem wanting deep integration and sovereignty

The market is large enough for both. ATXP's centralized model will attract developers who want fast time-to-market. Haima's self-sovereign model will attract agents that need autonomy, auditability, and financial sophistication beyond prepaid balances.

---

## Appendix A: ATXP Design Decisions Summary

| Decision | ATXP Approach |
|----------|--------------|
| Payment protocol | Custodial OAuth + centralized billing (NOT HTTP 402 native) |
| x402 support | Via adapter package `@atxp/x402` (bridge, not core) |
| Identity | Google OAuth + connection string (no DIDs) |
| Wallet | Platform-managed Ethereum wallet (custodial) |
| Pricing enforcement | `requirePayment()` blocks tool execution server-side |
| Settlement currency | USDC |
| Settlement chains | Base, Solana, Polygon, Worldchain, EVM |
| Tool discovery | Hardcoded MCP server URLs (no registry protocol) |
| MCP transport | Streamable HTTP (SSE) |
| Client approval | Optional `approvePayment` callback; auto-approve by default |
| Token persistence | In-memory default, SQLite or Redis optional |
| Batch payments | `minimumPayment` config for prepaid balance |
| Framework support | Express, Cloudflare Workers, Vercel AI SDK |
| Platform fee | Undisclosed |

## Appendix B: Products & Services

- **atxp.ai** — Main platform
- **atxp.chat** — Chat service (consumer-facing)
- **clowd.bot** — Bot service
- **accounts.atxp.ai** — Account portal for wallet/funding/usage management
- **docs.atxp.ai** — Documentation (well-structured, 6+ sections)
- **llms.txt** — Machine-readable index at `https://docs.atxp.ai/llms.txt`

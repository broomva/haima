//! API route handlers.
//!
//! - `GET /health` — public (no auth, used by Railway health checks)
//! - `GET /state` — protected (requires JWT when auth is enabled)
//! - `POST /v1/facilitate` — x402 payment facilitation (public, credit-gated)
//! - `GET /v1/facilitator/stats` — facilitator dashboard stats (public)
//! - `GET /v1/credit/:agent_id` — get agent credit score and tier (public)
//! - `POST /v1/credit/:agent_id/check` — check if agent can spend amount (public)
//! - `POST /v1/credit/:agent_id/open` — open a credit line (public)
//! - `POST /v1/credit/:agent_id/draw` — draw against credit line (public)
//! - `POST /v1/credit/:agent_id/repay` — record repayment (public)
//! - `GET /v1/credit/:agent_id/line` — get credit line status (public)
//! - `GET /v1/bureau/:agent_id` — agent credit bureau report (public)

use axum::Router;
use axum::extract::{Path, State};
use axum::response::Json;
use axum::routing::{get, post};
use haima_core::bureau::{CreditLineSummary, generate_credit_report};
use haima_core::credit::{CreditFactors, check_credit, compute_credit_score};
use haima_core::lending;
use haima_x402::{FacilitateRequest, verify_payment_header};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::require_auth;

pub fn routes(state: AppState) -> Router {
    // Protected routes — JWT required when auth is enabled
    let protected = Router::new()
        .route("/state", get(financial_state))
        .layer(axum::middleware::from_fn_with_state(
            state.auth_config.clone(),
            require_auth,
        ))
        .with_state(state.clone());

    // Public routes — no auth
    let public = Router::new()
        .route("/health", get(health))
        .route("/v1/facilitate", post(facilitate))
        .route("/v1/facilitator/stats", get(facilitator_stats))
        .route("/v1/credit/{agent_id}", get(get_credit_score))
        .route("/v1/credit/{agent_id}/check", post(check_credit_endpoint))
        .route(
            "/v1/credit/{agent_id}/open",
            post(open_credit_line_endpoint),
        )
        .route("/v1/credit/{agent_id}/draw", post(draw_credit_endpoint))
        .route("/v1/credit/{agent_id}/repay", post(repay_credit_endpoint))
        .route("/v1/credit/{agent_id}/line", get(get_credit_line_endpoint))
        .route("/v1/bureau/{agent_id}", get(get_bureau_report))
        .with_state(state);

    // Merge: public routes are NOT behind the auth layer
    public.merge(protected)
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "haimad",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn financial_state(State(state): State<AppState>) -> Json<Value> {
    let fs = state.financial_state.read().await;
    Json(json!({
        "total_expenses": fs.total_expenses,
        "total_revenue": fs.total_revenue,
        "net_balance": fs.net_balance,
        "payment_count": fs.payment_count,
        "revenue_count": fs.revenue_count,
        "failed_count": fs.failed_count,
        "session_spend": fs.session_spend,
        "wallet_address": fs.wallet_address,
        "on_chain_balance": fs.on_chain_balance,
        "pending_bills": fs.pending_bills.len(),
    }))
}

/// `POST /v1/facilitate` — Verify an x402 payment header and return a settlement receipt.
///
/// If `agent_id` is provided in the request body, the facilitator checks the
/// agent's credit score before processing. Insufficient credit results in rejection.
async fn facilitate(
    State(state): State<AppState>,
    Json(request): Json<FacilitateRequest>,
) -> Json<Value> {
    // If an agent_id is provided, check credit before proceeding.
    if let Some(ref agent_id) = request.agent_id {
        let scores = state.credit_scores.read().await;
        if let Some(credit) = scores.get(agent_id) {
            let result = check_credit(credit, request.amount_micro_usd);
            if !result.approved {
                return Json(json!({
                    "status": "rejected",
                    "reason": "insufficient_credit",
                    "details": format!(
                        "agent {} has tier '{}' with remaining limit {}",
                        agent_id, result.tier, result.remaining_limit
                    )
                }));
            }
        }
        // If no credit score cached for this agent, allow the transaction
        // (the facilitate endpoint also serves agents without credit profiles).
    }

    let response = verify_payment_header(
        &request,
        state.facilitator_fee_bps,
        &state.facilitator_stats,
    );
    Json(serde_json::to_value(response).unwrap_or_else(|_| {
        json!({
            "status": "rejected",
            "reason": "internal_error",
            "details": "Failed to serialize response"
        })
    }))
}

/// `GET /v1/facilitator/stats` — Return facilitator dashboard statistics.
async fn facilitator_stats(State(state): State<AppState>) -> Json<Value> {
    let stats = state.facilitator_stats.snapshot();
    Json(serde_json::to_value(stats).unwrap_or_else(|_| json!({})))
}

/// `GET /v1/credit/:agent_id` — Return the credit score and tier for an agent.
///
/// If no credit score is cached for the agent, a default score is computed from
/// empty factors (tier = None, score = 0.0).
async fn get_credit_score(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Json<Value> {
    let scores = state.credit_scores.read().await;
    let credit = scores
        .get(&agent_id)
        .cloned()
        .unwrap_or_else(|| compute_credit_score(&agent_id, &CreditFactors::default()));
    Json(serde_json::to_value(&credit).unwrap_or_else(|_| json!({})))
}

/// Request body for `POST /v1/credit/:agent_id/check`.
#[derive(Debug, Deserialize)]
struct CreditCheckRequest {
    /// Amount to check in micro-USD.
    amount_micro_usd: u64,
}

/// `POST /v1/credit/:agent_id/check` — Check whether an agent can spend a given amount.
async fn check_credit_endpoint(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<CreditCheckRequest>,
) -> Json<Value> {
    let scores = state.credit_scores.read().await;
    let credit = scores
        .get(&agent_id)
        .cloned()
        .unwrap_or_else(|| compute_credit_score(&agent_id, &CreditFactors::default()));
    let result = check_credit(&credit, request.amount_micro_usd);
    Json(serde_json::to_value(&result).unwrap_or_else(|_| json!({})))
}

// ---------------------------------------------------------------------------
// Lending endpoints
// ---------------------------------------------------------------------------

/// `POST /v1/credit/:agent_id/open` — Open a credit line for an agent.
///
/// Requires a cached credit score with a non-None tier. If the agent already
/// has a credit line, returns the existing one.
async fn open_credit_line_endpoint(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Json<Value> {
    // Check if credit line already exists
    {
        let lines = state.credit_lines.read().await;
        if let Some(line) = lines.get(&agent_id) {
            return Json(json!({
                "status": "exists",
                "credit_line": serde_json::to_value(line).unwrap_or_default()
            }));
        }
    }

    // Look up credit score
    let scores = state.credit_scores.read().await;
    let credit = scores
        .get(&agent_id)
        .cloned()
        .unwrap_or_else(|| compute_credit_score(&agent_id, &CreditFactors::default()));
    drop(scores);

    match lending::open_credit_line(&agent_id, &credit) {
        Some(line) => {
            let response = json!({
                "status": "opened",
                "credit_line": serde_json::to_value(&line).unwrap_or_default()
            });
            let mut lines = state.credit_lines.write().await;
            lines.insert(agent_id, line);
            Json(response)
        }
        None => Json(json!({
            "status": "rejected",
            "reason": "insufficient_credit_score",
            "details": format!(
                "agent {} has tier 'none' (score {:.2}) — credit line requires at least micro tier",
                agent_id, credit.score
            )
        })),
    }
}

/// Request body for `POST /v1/credit/:agent_id/draw`.
#[derive(Debug, Deserialize)]
struct DrawCreditRequest {
    /// Amount to draw in micro-USD.
    amount_micro_usd: u64,
    /// Purpose: `task_payment`, `prepay`, `overdraft`.
    #[serde(default = "default_purpose")]
    purpose: String,
}

fn default_purpose() -> String {
    "task_payment".to_string()
}

/// `POST /v1/credit/:agent_id/draw` — Draw against an agent's credit line.
async fn draw_credit_endpoint(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<DrawCreditRequest>,
) -> Json<Value> {
    let mut lines = state.credit_lines.write().await;
    match lines.get_mut(&agent_id) {
        Some(line) => {
            let result = lending::draw(line, request.amount_micro_usd, &request.purpose);
            Json(serde_json::to_value(&result).unwrap_or_default())
        }
        None => Json(json!({
            "approved": false,
            "drawn_amount": 0,
            "new_balance": 0,
            "available": 0,
            "interest_accrued": 0,
            "reason": format!("no_credit_line: agent {} has no open credit line", agent_id)
        })),
    }
}

/// Request body for `POST /v1/credit/:agent_id/repay`.
#[derive(Debug, Deserialize)]
struct RepayCreditRequest {
    /// Amount to repay in micro-USD.
    amount_micro_usd: u64,
}

/// `POST /v1/credit/:agent_id/repay` — Record a repayment against a credit line.
async fn repay_credit_endpoint(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<RepayCreditRequest>,
) -> Json<Value> {
    let mut lines = state.credit_lines.write().await;
    match lines.get_mut(&agent_id) {
        Some(line) => {
            let record = lending::repay(line, request.amount_micro_usd);
            Json(serde_json::to_value(&record).unwrap_or_default())
        }
        None => Json(json!({
            "status": "error",
            "reason": format!("no_credit_line: agent {} has no open credit line", agent_id)
        })),
    }
}

/// `GET /v1/credit/:agent_id/line` — Get the current credit line status.
async fn get_credit_line_endpoint(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Json<Value> {
    let lines = state.credit_lines.read().await;
    match lines.get(&agent_id) {
        Some(line) => Json(serde_json::to_value(line).unwrap_or_default()),
        None => Json(json!({
            "status": "not_found",
            "reason": format!("no credit line for agent {}", agent_id)
        })),
    }
}

// ---------------------------------------------------------------------------
// Bureau endpoint
// ---------------------------------------------------------------------------

/// `GET /v1/bureau/:agent_id` — Generate and return a full credit bureau report.
///
/// Aggregates credit score, trust context, payment history, and credit lines
/// into a comprehensive `AgentCreditReport` with risk flags and risk rating.
///
/// If no data is cached for the agent, defaults are used (score 0, tier None,
/// trust unverified, empty payment history).
async fn get_bureau_report(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Json<Value> {
    // Read credit score (or compute default)
    let scores = state.credit_scores.read().await;
    let credit = scores
        .get(&agent_id)
        .cloned()
        .unwrap_or_else(|| compute_credit_score(&agent_id, &CreditFactors::default()));
    let credit_score = credit.score;
    let credit_tier = credit.tier;
    drop(scores);

    // Read trust context (or use default)
    let trusts = state.trust_contexts.read().await;
    let trust_context = trusts.get(&agent_id).cloned().unwrap_or_default();
    drop(trusts);

    // Read payment history (or use default)
    let histories = state.payment_histories.read().await;
    let payment_history = histories.get(&agent_id).cloned().unwrap_or_default();
    drop(histories);

    // Build credit line summaries from lending credit lines
    let lines = state.credit_lines.read().await;
    let credit_lines: Vec<CreditLineSummary> = lines
        .get(&agent_id)
        .map(|line| {
            let utilization = if line.limit_micro_usd > 0 {
                line.drawn_micro_usd as f64 / line.limit_micro_usd as f64
            } else {
                0.0
            };
            vec![CreditLineSummary {
                limit_micro_usd: line.limit_micro_usd,
                drawn_micro_usd: line.drawn_micro_usd,
                utilization_ratio: utilization,
                status: line.status.to_string(),
            }]
        })
        .unwrap_or_default();
    drop(lines);

    let report = generate_credit_report(
        &agent_id,
        None, // DID not yet wired
        credit_score,
        credit_tier,
        &trust_context,
        &payment_history,
        credit_lines,
    );

    Json(serde_json::to_value(&report).unwrap_or_else(|_| json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use haima_x402::header::{PaymentSignatureHeader, encode_payment_signature};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use lago_auth::BroomvaClaims;
    use tower::ServiceExt;

    const TEST_SECRET: &str = "test-haima-secret-key";

    fn make_token(sub: &str, email: &str, secret: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = BroomvaClaims {
            sub: sub.to_string(),
            email: email.to_string(),
            exp: now + 3600,
            iat: now,
            tenant_id: None,
            tenant_tier: None,
        };
        let key = EncodingKey::from_secret(secret.as_bytes());
        encode(&Header::default(), &claims, &key).unwrap()
    }

    fn make_valid_payment_header() -> String {
        let sig = PaymentSignatureHeader {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            payload: hex::encode([0xabu8; 64]),
        };
        encode_payment_signature(&sig).unwrap()
    }

    // --- Health endpoint (always public) ---

    #[tokio::test]
    async fn health_without_token_returns_200() {
        let state = AppState::new(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let app = routes(state);
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- State endpoint (protected) ---

    #[tokio::test]
    async fn state_without_token_auth_enabled_returns_401() {
        let state = AppState::new(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let app = routes(state);
        let req = Request::builder()
            .uri("/state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn state_with_valid_token_returns_200() {
        let state = AppState::new(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let app = routes(state);
        let token = make_token("user1", "user1@broomva.tech", TEST_SECRET);
        let req = Request::builder()
            .uri("/state")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn state_with_wrong_secret_returns_401() {
        let state = AppState::new(AuthConfig {
            jwt_secret: Some(TEST_SECRET.to_string()),
        });
        let app = routes(state);
        let token = make_token("user1", "user1@broomva.tech", "wrong-secret");
        let req = Request::builder()
            .uri("/state")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Auth disabled (local dev mode) ---

    #[tokio::test]
    async fn state_without_token_auth_disabled_returns_200() {
        let state = AppState::new(AuthConfig { jwt_secret: None });
        let app = routes(state);
        let req = Request::builder()
            .uri("/state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- Facilitate endpoint (public) ---

    #[tokio::test]
    async fn facilitate_valid_payment_returns_settled() {
        let state = AppState::default();
        let app = routes(state);

        let body = serde_json::json!({
            "payment_header": make_valid_payment_header(),
            "resource_url": "https://api.example.com/data",
            "amount_micro_usd": 1000
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/facilitate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "settled");
        assert!(json["receipt"].is_object());
        assert_eq!(json["receipt"]["amount_micro_usd"], 1000);
        assert_eq!(json["receipt"]["chain"], "base");
        assert_eq!(json["facilitator_fee_bps"], 15);
    }

    #[tokio::test]
    async fn facilitate_invalid_header_returns_rejected() {
        let state = AppState::default();
        let app = routes(state);

        let body = serde_json::json!({
            "payment_header": "not-valid-base64!!!",
            "resource_url": "https://api.example.com/data",
            "amount_micro_usd": 1000
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/facilitate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "rejected");
        assert_eq!(json["reason"], "invalid_header");
    }

    #[tokio::test]
    async fn facilitate_updates_stats() {
        let state = AppState::default();
        let stats = state.facilitator_stats.clone();
        let app = routes(state);

        let body = serde_json::json!({
            "payment_header": make_valid_payment_header(),
            "resource_url": "https://api.example.com/data",
            "amount_micro_usd": 5000
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/facilitate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let _resp = app.oneshot(req).await.unwrap();

        let snap = stats.snapshot();
        assert_eq!(snap.total_transactions, 1);
        assert_eq!(snap.total_volume_micro_usd, 5000);
    }

    // --- Facilitator stats endpoint (public) ---

    #[tokio::test]
    async fn facilitator_stats_returns_200() {
        let state = AppState::default();
        // Record some stats before querying
        state.facilitator_stats.record_settled(1_000_000, 1_500);
        state.facilitator_stats.record_rejected();
        let app = routes(state);

        let req = Request::builder()
            .uri("/v1/facilitator/stats")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total_transactions"], 1);
        assert_eq!(json["total_volume_micro_usd"], 1_000_000);
        assert_eq!(json["total_fees_micro_usd"], 1_500);
        assert_eq!(json["total_rejected"], 1);
    }

    // --- Credit score endpoint ---

    #[tokio::test]
    async fn credit_score_unknown_agent_returns_default() {
        let state = AppState::default();
        let app = routes(state);

        let req = Request::builder()
            .uri("/v1/credit/agent-unknown")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["agent_id"], "agent-unknown");
        assert_eq!(json["tier"], "none");
        assert_eq!(json["score"], 0.0);
        assert_eq!(json["spending_limit_micro_usd"], 0);
    }

    #[tokio::test]
    async fn credit_score_cached_agent_returns_cached() {
        use haima_core::credit::{CreditFactors, CreditTier};

        let state = AppState::default();
        // Insert a cached credit score
        {
            let mut scores = state.credit_scores.write().await;
            let factors = CreditFactors {
                trust_score: 0.8,
                payment_history: 0.9,
                transaction_volume: 1_000_000,
                account_age_days: 60,
                economic_stability: 0.7,
            };
            let credit = compute_credit_score("agent-cached", &factors);
            scores.insert("agent-cached".to_string(), credit);
        }
        let app = routes(state);

        let req = Request::builder()
            .uri("/v1/credit/agent-cached")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["agent_id"], "agent-cached");
        // With those factors, agent should have at least Standard tier
        let tier: CreditTier = serde_json::from_value(json["tier"].clone()).unwrap();
        assert!(tier == CreditTier::Standard || tier == CreditTier::Premium);
    }

    // --- Credit check endpoint ---

    #[tokio::test]
    async fn credit_check_unknown_agent_always_rejected() {
        let state = AppState::default();
        let app = routes(state);

        let body = serde_json::json!({ "amount_micro_usd": 100 });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-unknown/check")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        // Unknown agent has tier=none, limit=0 so any amount is rejected
        assert_eq!(json["approved"], false);
        assert_eq!(json["tier"], "none");
    }

    #[tokio::test]
    async fn credit_check_cached_agent_approved() {
        use haima_core::credit::CreditFactors;

        let state = AppState::default();
        {
            let mut scores = state.credit_scores.write().await;
            let factors = CreditFactors {
                trust_score: 1.0,
                payment_history: 1.0,
                transaction_volume: 10_000_000,
                account_age_days: 90,
                economic_stability: 1.0,
            };
            let credit = compute_credit_score("agent-premium", &factors);
            scores.insert("agent-premium".to_string(), credit);
        }
        let app = routes(state);

        let body = serde_json::json!({ "amount_micro_usd": 5000 });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-premium/check")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], true);
        assert_eq!(json["tier"], "premium");
        assert_eq!(json["remaining_limit"], 10_000_000 - 5000);
    }

    // --- Credit-gated facilitate ---

    #[tokio::test]
    async fn facilitate_with_insufficient_credit_rejected() {
        use haima_core::credit::CreditFactors;

        let state = AppState::default();
        // Insert a credit score with Micro tier (limit = 1000)
        {
            let mut scores = state.credit_scores.write().await;
            let factors = CreditFactors {
                trust_score: 0.4,
                payment_history: 0.5,
                transaction_volume: 10_000,
                account_age_days: 7,
                economic_stability: 0.3,
            };
            let credit = compute_credit_score("agent-low", &factors);
            scores.insert("agent-low".to_string(), credit);
        }
        let app = routes(state);

        let body = serde_json::json!({
            "payment_header": make_valid_payment_header(),
            "resource_url": "https://api.example.com/data",
            "amount_micro_usd": 5000,
            "agent_id": "agent-low"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/facilitate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "rejected");
        assert_eq!(json["reason"], "insufficient_credit");
    }

    #[tokio::test]
    async fn facilitate_with_sufficient_credit_passes_through() {
        use haima_core::credit::CreditFactors;

        let state = AppState::default();
        // Insert a credit score with Premium tier (limit = 10M)
        {
            let mut scores = state.credit_scores.write().await;
            let factors = CreditFactors {
                trust_score: 1.0,
                payment_history: 1.0,
                transaction_volume: 10_000_000,
                account_age_days: 90,
                economic_stability: 1.0,
            };
            let credit = compute_credit_score("agent-premium", &factors);
            scores.insert("agent-premium".to_string(), credit);
        }
        let app = routes(state);

        let body = serde_json::json!({
            "payment_header": make_valid_payment_header(),
            "resource_url": "https://api.example.com/data",
            "amount_micro_usd": 1000,
            "agent_id": "agent-premium"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/facilitate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        // Should pass through to normal facilitation (settled)
        assert_eq!(json["status"], "settled");
    }

    #[tokio::test]
    async fn facilitate_without_agent_id_skips_credit_check() {
        let state = AppState::default();
        let app = routes(state);

        // No agent_id in request — should proceed without credit check
        let body = serde_json::json!({
            "payment_header": make_valid_payment_header(),
            "resource_url": "https://api.example.com/data",
            "amount_micro_usd": 1000
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/facilitate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "settled");
    }

    // --- Lending endpoints ---

    /// Helper: insert a premium credit score for an agent into state.
    async fn insert_premium_score(state: &AppState, agent_id: &str) {
        let mut scores = state.credit_scores.write().await;
        let factors = CreditFactors {
            trust_score: 1.0,
            payment_history: 1.0,
            transaction_volume: 10_000_000,
            account_age_days: 90,
            economic_stability: 1.0,
        };
        let credit = compute_credit_score(agent_id, &factors);
        scores.insert(agent_id.to_string(), credit);
    }

    #[tokio::test]
    async fn open_credit_line_for_premium_agent() {
        let state = AppState::default();
        insert_premium_score(&state, "agent-lending").await;
        let app = routes(state);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-lending/open")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "opened");
        assert_eq!(json["credit_line"]["tier"], "premium");
        assert_eq!(json["credit_line"]["limit_micro_usd"], 10_000_000);
        assert_eq!(json["credit_line"]["drawn_micro_usd"], 0);
        assert_eq!(json["credit_line"]["status"], "active");
    }

    #[tokio::test]
    async fn open_credit_line_unknown_agent_rejected() {
        let state = AppState::default();
        let app = routes(state);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-unknown/open")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "rejected");
        assert_eq!(json["reason"], "insufficient_credit_score");
    }

    #[tokio::test]
    async fn open_credit_line_already_exists_returns_existing() {
        let state = AppState::default();
        insert_premium_score(&state, "agent-exists").await;

        // Open the first credit line
        {
            let scores = state.credit_scores.read().await;
            let credit = scores.get("agent-exists").unwrap();
            let line = haima_core::lending::open_credit_line("agent-exists", credit).unwrap();
            let mut lines = state.credit_lines.write().await;
            lines.insert("agent-exists".to_string(), line);
        }

        let app = routes(state);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-exists/open")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "exists");
    }

    #[tokio::test]
    async fn draw_against_credit_line() {
        let state = AppState::default();
        insert_premium_score(&state, "agent-draw-api").await;

        // Open credit line
        {
            let scores = state.credit_scores.read().await;
            let credit = scores.get("agent-draw-api").unwrap();
            let line = haima_core::lending::open_credit_line("agent-draw-api", credit).unwrap();
            let mut lines = state.credit_lines.write().await;
            lines.insert("agent-draw-api".to_string(), line);
        }

        let app = routes(state);

        let body = serde_json::json!({
            "amount_micro_usd": 5_000,
            "purpose": "task_payment"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-draw-api/draw")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], true);
        assert_eq!(json["drawn_amount"], 5_000);
        assert_eq!(json["new_balance"], 5_000);
        assert_eq!(json["available"], 10_000_000 - 5_000);
    }

    #[tokio::test]
    async fn draw_no_credit_line_rejected() {
        let state = AppState::default();
        let app = routes(state);

        let body = serde_json::json!({
            "amount_micro_usd": 1_000,
            "purpose": "task_payment"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-no-line/draw")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], false);
    }

    #[tokio::test]
    async fn repay_reduces_balance() {
        let state = AppState::default();
        insert_premium_score(&state, "agent-repay-api").await;

        // Open credit line and draw
        {
            let scores = state.credit_scores.read().await;
            let credit = scores.get("agent-repay-api").unwrap();
            let mut line =
                haima_core::lending::open_credit_line("agent-repay-api", credit).unwrap();
            haima_core::lending::draw(&mut line, 10_000, "task_payment");
            let mut lines = state.credit_lines.write().await;
            lines.insert("agent-repay-api".to_string(), line);
        }

        let app = routes(state);

        let body = serde_json::json!({ "amount_micro_usd": 5_000 });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-repay-api/repay")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["agent_id"], "agent-repay-api");
        assert_eq!(json["principal_portion"], 5_000);
        assert_eq!(json["remaining_balance"], 5_000);
    }

    #[tokio::test]
    async fn repay_no_credit_line_returns_error() {
        let state = AppState::default();
        let app = routes(state);

        let body = serde_json::json!({ "amount_micro_usd": 1_000 });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/credit/agent-no-line/repay")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "error");
    }

    #[tokio::test]
    async fn get_credit_line_returns_status() {
        let state = AppState::default();
        insert_premium_score(&state, "agent-line-api").await;

        // Open credit line
        {
            let scores = state.credit_scores.read().await;
            let credit = scores.get("agent-line-api").unwrap();
            let line = haima_core::lending::open_credit_line("agent-line-api", credit).unwrap();
            let mut lines = state.credit_lines.write().await;
            lines.insert("agent-line-api".to_string(), line);
        }

        let app = routes(state);

        let req = Request::builder()
            .uri("/v1/credit/agent-line-api/line")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["agent_id"], "agent-line-api");
        assert_eq!(json["tier"], "premium");
        assert_eq!(json["status"], "active");
        assert_eq!(json["limit_micro_usd"], 10_000_000);
    }

    #[tokio::test]
    async fn get_credit_line_not_found() {
        let state = AppState::default();
        let app = routes(state);

        let req = Request::builder()
            .uri("/v1/credit/agent-no-line/line")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "not_found");
    }

    #[tokio::test]
    async fn full_lending_lifecycle_via_api() {
        let state = AppState::default();
        insert_premium_score(&state, "agent-lifecycle-api").await;

        // 1. Open credit line
        {
            let app = routes(state.clone());
            let req = Request::builder()
                .method("POST")
                .uri("/v1/credit/agent-lifecycle-api/open")
                .header("content-type", "application/json")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["status"], "opened");
        }

        // 2. Draw
        {
            let app = routes(state.clone());
            let body = serde_json::json!({
                "amount_micro_usd": 50_000,
                "purpose": "task_payment"
            });
            let req = Request::builder()
                .method("POST")
                .uri("/v1/credit/agent-lifecycle-api/draw")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["approved"], true);
            assert_eq!(json["drawn_amount"], 50_000);
        }

        // 3. Check line status
        {
            let app = routes(state.clone());
            let req = Request::builder()
                .uri("/v1/credit/agent-lifecycle-api/line")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["drawn_micro_usd"], 50_000);
            assert_eq!(json["available_micro_usd"], 10_000_000 - 50_000);
        }

        // 4. Repay
        {
            let app = routes(state.clone());
            let body = serde_json::json!({ "amount_micro_usd": 50_000 });
            let req = Request::builder()
                .method("POST")
                .uri("/v1/credit/agent-lifecycle-api/repay")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["remaining_balance"], 0);
        }

        // 5. Verify line is back to full availability
        {
            let app = routes(state.clone());
            let req = Request::builder()
                .uri("/v1/credit/agent-lifecycle-api/line")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["drawn_micro_usd"], 0);
            assert_eq!(json["available_micro_usd"], 10_000_000);
        }
    }

    // --- Bureau endpoint ---

    #[tokio::test]
    async fn bureau_unknown_agent_returns_default_report() {
        let state = AppState::default();
        let app = routes(state);

        let req = Request::builder()
            .uri("/v1/bureau/agent-unknown")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["agent_id"], "agent-unknown");
        assert_eq!(json["credit_tier"], "none");
        assert_eq!(json["credit_score"], 0.0);
        assert_eq!(json["trust_score"], 0.0);
        assert_eq!(json["trust_tier"], "unverified");
        assert_eq!(json["risk_rating"], "critical");
        // Should have NewAgent flag since no history
        let flags = json["flags"].as_array().unwrap();
        assert!(
            flags.iter().any(|f| f["flag_type"] == "new_agent"),
            "Expected new_agent flag in default report"
        );
    }

    #[tokio::test]
    async fn bureau_with_cached_data_returns_full_report() {
        use haima_core::bureau::{PaymentHistory, TrustContext, TrustTrajectory};

        let state = AppState::default();

        // Insert credit score
        insert_premium_score(&state, "agent-bureau").await;

        // Insert trust context
        {
            let mut trusts = state.trust_contexts.write().await;
            trusts.insert(
                "agent-bureau".to_string(),
                TrustContext {
                    score: 0.92,
                    tier: "certified".to_string(),
                    trajectory: TrustTrajectory::Stable,
                },
            );
        }

        // Insert payment history
        {
            let mut histories = state.payment_histories.write().await;
            histories.insert(
                "agent-bureau".to_string(),
                PaymentHistory {
                    total_transactions: 200,
                    total_volume_micro_usd: 5_000_000,
                    on_time_rate: 0.99,
                    average_settlement_time_ms: 500,
                    defaults: 0,
                    oldest_transaction_at: Some(chrono::Utc::now() - chrono::Duration::days(180)),
                    has_recent_default: false,
                    rapid_spending: false,
                    economic_hibernate: false,
                },
            );
        }

        let app = routes(state);

        let req = Request::builder()
            .uri("/v1/bureau/agent-bureau")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["agent_id"], "agent-bureau");
        assert_eq!(json["credit_tier"], "premium");
        assert_eq!(json["trust_tier"], "certified");
        assert_eq!(json["risk_rating"], "low");
        assert_eq!(json["payment_summary"]["total_transactions"], 200);
        assert_eq!(json["payment_summary"]["on_time_rate"], 0.99);
        let flags = json["flags"].as_array().unwrap();
        assert!(flags.is_empty(), "Expected no flags for healthy agent");
    }

    #[tokio::test]
    async fn bureau_includes_credit_line_from_lending() {
        use haima_core::bureau::{PaymentHistory, TrustContext, TrustTrajectory};

        let state = AppState::default();
        insert_premium_score(&state, "agent-bureau-line").await;

        // Open credit line and draw
        {
            let scores = state.credit_scores.read().await;
            let credit = scores.get("agent-bureau-line").unwrap();
            let mut line =
                haima_core::lending::open_credit_line("agent-bureau-line", credit).unwrap();
            haima_core::lending::draw(&mut line, 8_500_000, "task_payment");
            let mut lines = state.credit_lines.write().await;
            lines.insert("agent-bureau-line".to_string(), line);
        }

        // Insert trust + history to avoid NewAgent flags
        {
            let mut trusts = state.trust_contexts.write().await;
            trusts.insert(
                "agent-bureau-line".to_string(),
                TrustContext {
                    score: 0.85,
                    tier: "trusted".to_string(),
                    trajectory: TrustTrajectory::Stable,
                },
            );
        }
        {
            let mut histories = state.payment_histories.write().await;
            histories.insert(
                "agent-bureau-line".to_string(),
                PaymentHistory {
                    total_transactions: 100,
                    total_volume_micro_usd: 2_000_000,
                    on_time_rate: 0.95,
                    average_settlement_time_ms: 700,
                    defaults: 0,
                    oldest_transaction_at: Some(chrono::Utc::now() - chrono::Duration::days(60)),
                    has_recent_default: false,
                    rapid_spending: false,
                    economic_hibernate: false,
                },
            );
        }

        let app = routes(state);

        let req = Request::builder()
            .uri("/v1/bureau/agent-bureau-line")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["agent_id"], "agent-bureau-line");
        // Should have a credit line with high utilization
        let credit_lines = json["credit_lines"].as_array().unwrap();
        assert_eq!(credit_lines.len(), 1);
        assert_eq!(credit_lines[0]["limit_micro_usd"], 10_000_000);
        assert_eq!(credit_lines[0]["drawn_micro_usd"], 8_500_000);
        assert_eq!(credit_lines[0]["status"], "active");
        // 85% utilization should trigger HighUtilization flag
        let flags = json["flags"].as_array().unwrap();
        assert!(
            flags.iter().any(|f| f["flag_type"] == "high_utilization"),
            "Expected high_utilization flag for 85% utilization, got: {flags:?}"
        );
    }
}

//! Insurance marketplace API endpoints.
//!
//! - `GET  /v1/insurance/products`           — list available products
//! - `POST /v1/insurance/quotes`             — get an insurance quote
//! - `POST /v1/insurance/policies`           — bind a quote into a policy
//! - `GET  /v1/insurance/policies`           — list policies for an agent
//! - `POST /v1/insurance/claims`             — submit a claim
//! - `GET  /v1/insurance/claims/:claim_id`   — get claim details
//! - `POST /v1/insurance/claims/:claim_id/verify` — trigger claim verification
//! - `GET  /v1/insurance/risk/:agent_id`     — get risk assessment
//! - `POST /v1/insurance/pool/contribute`    — contribute to self-insurance pool
//! - `GET  /v1/insurance/pool`               — pool status
//! - `GET  /v1/insurance/providers`          — list providers
//! - `GET  /v1/insurance/dashboard`          — marketplace dashboard

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use chrono::Utc;
use haima_core::event::FinanceEventKind;
use haima_core::insurance::{BindRequest, ClaimRequest, PoolContributionRequest, QuoteRequest};
use haima_core::marketplace;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;

/// Build the insurance marketplace routes.
pub fn insurance_routes(state: AppState) -> Router {
    Router::new()
        .route("/v1/insurance/products", get(list_products))
        .route("/v1/insurance/quotes", post(get_quote))
        .route("/v1/insurance/policies", post(bind_quote))
        .route("/v1/insurance/policies", get(list_policies))
        .route("/v1/insurance/claims", post(submit_claim))
        .route("/v1/insurance/claims/{claim_id}", get(get_claim))
        .route(
            "/v1/insurance/claims/{claim_id}/verify",
            post(verify_claim_endpoint),
        )
        .route("/v1/insurance/risk/{agent_id}", get(risk_assessment))
        .route("/v1/insurance/pool/contribute", post(pool_contribute))
        .route("/v1/insurance/pool", get(pool_status))
        .route("/v1/insurance/providers", get(list_providers))
        .route("/v1/insurance/dashboard", get(dashboard))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AgentQuery {
    agent_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProductTypeQuery {
    product_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /v1/insurance/products` — List available insurance products.
///
/// Optional `?product_type=task_failure` filter.
async fn list_products(
    State(state): State<AppState>,
    Query(query): Query<ProductTypeQuery>,
) -> Json<Value> {
    let insurance = state.insurance_state.read().await;
    let products: Vec<_> = insurance
        .products
        .values()
        .filter(|p| {
            p.active
                && query
                    .product_type
                    .as_ref()
                    .map(|t| p.product_type.to_string() == *t)
                    .unwrap_or(true)
        })
        .collect();

    Json(json!({
        "products": serde_json::to_value(&products).unwrap_or_default(),
        "count": products.len()
    }))
}

/// `POST /v1/insurance/quotes` — Generate an insurance quote for an agent.
///
/// Performs risk assessment using trust + credit data, then prices coverage.
async fn get_quote(
    State(state): State<AppState>,
    Json(request): Json<QuoteRequest>,
) -> Json<Value> {
    // Look up product.
    let insurance = state.insurance_state.read().await;
    let product = insurance
        .products
        .values()
        .find(|p| p.product_type == request.product_type && p.active);

    let product = match product {
        Some(p) => p.clone(),
        None => {
            return Json(json!({
                "error": "no active product found for this coverage type"
            }));
        }
    };

    // Get claims history for this agent.
    let claims_history = insurance
        .agent_claims
        .get(&request.agent_id)
        .cloned()
        .unwrap_or_default();
    drop(insurance);

    // Look up trust and credit data.
    let trust_contexts = state.trust_contexts.read().await;
    let trust = trust_contexts.get(&request.agent_id);

    let credit_scores = state.credit_scores.read().await;
    let credit = credit_scores.get(&request.agent_id);

    // Assess risk.
    let assessment = marketplace::assess_risk(&request.agent_id, trust, credit, &claims_history);

    drop(trust_contexts);
    drop(credit_scores);

    // Generate quote.
    match marketplace::generate_quote(&request, &product, &assessment) {
        Some(quote) => {
            let response = json!({
                "status": "quoted",
                "quote": serde_json::to_value(&quote).unwrap_or_default()
            });
            // Store quote for later binding.
            let mut insurance = state.insurance_state.write().await;
            insurance.quotes.insert(quote.quote_id.clone(), quote);
            Json(response)
        }
        None => Json(json!({
            "status": "declined",
            "risk_assessment": serde_json::to_value(&assessment).unwrap_or_default(),
            "reason": assessment.denial_reason.unwrap_or_else(|| "coverage out of bounds or trust tier insufficient".into())
        })),
    }
}

/// `POST /v1/insurance/policies` — Bind a quote into an active policy.
async fn bind_quote(
    State(state): State<AppState>,
    Json(request): Json<BindRequest>,
) -> Json<Value> {
    let mut insurance = state.insurance_state.write().await;

    let Some(quote) = insurance.quotes.remove(&request.quote_id) else {
        return Json(json!({
            "error": "quote not found or already used"
        }));
    };

    if quote.agent_id != request.agent_id {
        // Re-insert the quote since agent doesn't match.
        insurance.quotes.insert(quote.quote_id.clone(), quote);
        return Json(json!({
            "error": "agent_id does not match quote"
        }));
    }

    match marketplace::bind_policy(&quote) {
        Some(policy) => {
            // Look up provider commission rate.
            let commission_bps = insurance
                .providers
                .get(&policy.provider_id)
                .map(|p| p.commission_rate_bps)
                .unwrap_or(1500); // default 15%
            let commission =
                (policy.premium_micro_usd as f64 * commission_bps as f64 / 10_000.0).round() as i64;

            // Store the full policy for claim verification.
            insurance.store_policy(policy.clone());

            // Emit events.
            let issue_event = FinanceEventKind::PolicyIssued {
                policy_id: policy.policy_id.clone(),
                agent_id: policy.agent_id.clone(),
                product_type: policy.product_type.to_string(),
                coverage_micro_usd: policy.coverage_limit_micro_usd,
                premium_micro_usd: policy.premium_micro_usd,
                provider_id: policy.provider_id.clone(),
            };
            insurance.apply(&issue_event, Utc::now());

            let premium_event = FinanceEventKind::PremiumCollected {
                policy_id: policy.policy_id.clone(),
                agent_id: policy.agent_id.clone(),
                amount_micro_usd: policy.premium_micro_usd,
                commission_micro_usd: commission,
            };
            insurance.apply(&premium_event, Utc::now());

            Json(json!({
                "status": "bound",
                "policy": serde_json::to_value(&policy).unwrap_or_default(),
                "premium_collected": policy.premium_micro_usd,
                "commission": commission,
                "commission_rate_bps": commission_bps
            }))
        }
        None => Json(json!({
            "error": "quote has expired"
        })),
    }
}

/// `GET /v1/insurance/policies?agent_id=agent-1` — List policies for an agent.
async fn list_policies(
    State(state): State<AppState>,
    Query(query): Query<AgentQuery>,
) -> Json<Value> {
    let insurance = state.insurance_state.read().await;
    match query.agent_id {
        Some(ref agent_id) => {
            let policy_ids = insurance
                .policies_by_agent
                .get(agent_id)
                .cloned()
                .unwrap_or_default();
            Json(json!({
                "agent_id": agent_id,
                "policy_ids": policy_ids,
                "count": policy_ids.len()
            }))
        }
        None => Json(json!({
            "active_policies": insurance.active_policies,
            "agents_with_policies": insurance.policies_by_agent.len()
        })),
    }
}

/// `POST /v1/insurance/claims` — Submit an insurance claim.
///
/// Validates against the stored policy before accepting the claim.
async fn submit_claim(
    State(state): State<AppState>,
    Json(request): Json<ClaimRequest>,
) -> Json<Value> {
    let mut insurance = state.insurance_state.write().await;

    // Look up the policy to validate the claim.
    let policy = match insurance.get_policy(&request.policy_id) {
        Some(p) => p.clone(),
        None => {
            return Json(json!({
                "error": "policy not found",
                "policy_id": request.policy_id
            }));
        }
    };

    // Validate the claim against the policy using haima-insurance logic.
    let claim_id = format!("claim-{}", Utc::now().timestamp_millis());
    match haima_insurance::claims::process_claim(&request, &policy, &claim_id) {
        Ok(claim) => {
            // Store the full claim for later verification.
            insurance.store_claim(claim);

            let event = FinanceEventKind::ClaimSubmitted {
                claim_id: claim_id.clone(),
                policy_id: request.policy_id.clone(),
                agent_id: request.agent_id.clone(),
                incident_type: request.incident_type.to_string(),
                claimed_amount_micro_usd: request.claimed_amount_micro_usd,
            };
            insurance.apply(&event, Utc::now());

            Json(json!({
                "status": "submitted",
                "claim_id": claim_id,
                "policy_id": request.policy_id,
                "claimed_amount_micro_usd": request.claimed_amount_micro_usd
            }))
        }
        Err(e) => Json(json!({
            "error": e.to_string(),
            "policy_id": request.policy_id
        })),
    }
}

/// `GET /v1/insurance/claims/:claim_id` — Get claim details.
async fn get_claim(State(state): State<AppState>, Path(claim_id): Path<String>) -> Json<Value> {
    let insurance = state.insurance_state.read().await;
    match insurance.get_claim(&claim_id) {
        Some(claim) => Json(serde_json::to_value(claim).unwrap_or_default()),
        None => Json(json!({
            "error": "claim not found",
            "claim_id": claim_id
        })),
    }
}

/// Request body for claim verification trigger.
#[derive(Debug, Deserialize)]
struct VerifyClaimRequest {
    /// Number of evidence events validated against Lago journal.
    /// If not provided, defaults to the count of `evidence_event_ids` on the claim
    /// (simulating full automated validation).
    evidence_valid_count: Option<u32>,
}

/// `POST /v1/insurance/claims/:claim_id/verify` — Trigger claim verification.
///
/// Verifies the claim against the stored policy using automated logic.
/// If `evidence_valid_count` is not provided, assumes all evidence events
/// were validated (full automated verification from Lago journal).
async fn verify_claim_endpoint(
    State(state): State<AppState>,
    Path(claim_id): Path<String>,
    Json(request): Json<VerifyClaimRequest>,
) -> Json<Value> {
    let mut insurance = state.insurance_state.write().await;

    // Look up the stored claim.
    let claim = match insurance.get_claim(&claim_id) {
        Some(c) => c.clone(),
        None => {
            return Json(json!({
                "error": "claim not found",
                "claim_id": claim_id
            }));
        }
    };

    // Look up the policy for this claim.
    let policy = match insurance.get_policy(&claim.policy_id) {
        Some(p) => p.clone(),
        None => {
            return Json(json!({
                "error": "policy not found for claim",
                "claim_id": claim_id,
                "policy_id": claim.policy_id
            }));
        }
    };

    // Determine evidence valid count — default to all submitted evidence
    // (simulates automated Lago journal verification).
    let evidence_valid_count = request
        .evidence_valid_count
        .unwrap_or(claim.evidence_event_ids.len() as u32);

    // Use the haima-insurance verification engine.
    let verification = haima_insurance::claims::verify_claim(&claim, &policy, evidence_valid_count);

    let approved = verification.incident_confirmed
        && verification.amount_consistent
        && verification.policy_active_at_incident
        && verification.confidence >= 0.7;

    let event = FinanceEventKind::ClaimVerified {
        claim_id: claim_id.clone(),
        policy_id: claim.policy_id.clone(),
        incident_confirmed: verification.incident_confirmed,
        confidence: verification.confidence,
        evidence_events_validated: evidence_valid_count,
    };
    insurance.apply(&event, Utc::now());

    // If approved, calculate payout and process.
    if approved {
        let payout = haima_insurance::claims::calculate_payout(
            claim.claimed_amount_micro_usd,
            policy.deductible_micro_usd,
            policy.coverage_limit_micro_usd - policy.claims_paid_micro_usd,
        );

        // Process pool payout if pool-backed.
        let source = if let Some(ref pool) = insurance.pool {
            if pool.pool_id == policy.provider_id {
                "pool".to_string()
            } else {
                policy.provider_id.clone()
            }
        } else {
            policy.provider_id.clone()
        };

        // Emit payout events.
        if source == "pool" {
            if let Some(ref mut pool) = insurance.pool
                && pool.reserves_micro_usd >= payout
            {
                pool.reserves_micro_usd -= payout;
                pool.total_payouts_micro_usd += payout;
            }
            let pool_reserves = insurance
                .pool
                .as_ref()
                .map(|p| p.reserves_micro_usd)
                .unwrap_or(0);
            let pool_event = FinanceEventKind::PoolPayout {
                pool_id: policy.provider_id,
                claim_id: claim_id.clone(),
                amount_micro_usd: payout,
                reserves_after_micro_usd: pool_reserves,
            };
            insurance.apply(&pool_event, Utc::now());
        }

        let paid_event = FinanceEventKind::ClaimPaid {
            claim_id: claim_id.clone(),
            policy_id: claim.policy_id.clone(),
            agent_id: claim.agent_id,
            payout_micro_usd: payout,
            source: source.clone(),
        };
        insurance.apply(&paid_event, Utc::now());

        // Update stored claim with verification.
        if let Some(stored_claim) = insurance.get_claim_mut(&claim_id) {
            stored_claim.verification = Some(verification.clone());
        }

        return Json(json!({
            "status": "approved_and_paid",
            "claim_id": claim_id,
            "verification": serde_json::to_value(&verification).unwrap_or_default(),
            "payout_micro_usd": payout,
            "source": source
        }));
    }

    // Not auto-approved — update claim with verification result.
    let status = if verification.confidence < 0.3 {
        let deny_event = FinanceEventKind::ClaimDenied {
            claim_id: claim_id.clone(),
            policy_id: claim.policy_id,
            reason: "automated verification failed — insufficient evidence".into(),
        };
        insurance.apply(&deny_event, Utc::now());
        "denied"
    } else {
        "under_review"
    };

    if let Some(stored_claim) = insurance.get_claim_mut(&claim_id) {
        stored_claim.verification = Some(verification.clone());
    }

    Json(json!({
        "status": status,
        "claim_id": claim_id,
        "verification": serde_json::to_value(&verification).unwrap_or_default()
    }))
}

/// `GET /v1/insurance/risk/:agent_id` — Get risk assessment for an agent.
///
/// Powered by Autonomic trust scores + Haima credit data.
async fn risk_assessment(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Json<Value> {
    let insurance = state.insurance_state.read().await;
    let claims_history = insurance
        .agent_claims
        .get(&agent_id)
        .cloned()
        .unwrap_or_default();
    drop(insurance);

    let trust_contexts = state.trust_contexts.read().await;
    let trust = trust_contexts.get(&agent_id);

    let credit_scores = state.credit_scores.read().await;
    let credit = credit_scores.get(&agent_id);

    let assessment = marketplace::assess_risk(&agent_id, trust, credit, &claims_history);

    // Emit risk assessment event.
    let event = FinanceEventKind::RiskAssessed {
        agent_id: agent_id.clone(),
        risk_score: assessment.risk_score,
        risk_rating: assessment.risk_rating.to_string(),
        premium_multiplier: assessment.premium_multiplier,
        insurable: assessment.insurable,
    };
    drop(trust_contexts);
    drop(credit_scores);

    let mut insurance = state.insurance_state.write().await;
    insurance.apply(&event, Utc::now());

    Json(serde_json::to_value(&assessment).unwrap_or_default())
}

/// `POST /v1/insurance/pool/contribute` — Contribute to the self-insurance pool.
async fn pool_contribute(
    State(state): State<AppState>,
    Json(request): Json<PoolContributionRequest>,
) -> Json<Value> {
    let mut insurance = state.insurance_state.write().await;

    let pool_id = match &insurance.pool {
        Some(pool) => pool.pool_id.clone(),
        None => {
            return Json(json!({
                "error": "no self-insurance pool initialized"
            }));
        }
    };

    let event = FinanceEventKind::PoolContribution {
        pool_id: pool_id.clone(),
        agent_id: request.agent_id.clone(),
        amount_micro_usd: request.amount_micro_usd,
    };
    insurance.apply(&event, Utc::now());

    let reserves = insurance
        .pool
        .as_ref()
        .map(|p| p.reserves_micro_usd)
        .unwrap_or(0);

    Json(json!({
        "status": "contributed",
        "pool_id": pool_id,
        "amount_micro_usd": request.amount_micro_usd,
        "pool_reserves_after": reserves
    }))
}

/// `GET /v1/insurance/pool` — Get self-insurance pool status.
async fn pool_status(State(state): State<AppState>) -> Json<Value> {
    let insurance = state.insurance_state.read().await;
    match &insurance.pool {
        Some(pool) => Json(serde_json::to_value(pool).unwrap_or_default()),
        None => Json(json!({"error": "no pool initialized"})),
    }
}

/// `GET /v1/insurance/providers` — List registered insurance providers.
async fn list_providers(State(state): State<AppState>) -> Json<Value> {
    let insurance = state.insurance_state.read().await;
    let providers: Vec<_> = insurance.providers.values().collect();
    Json(json!({
        "providers": serde_json::to_value(&providers).unwrap_or_default(),
        "count": providers.len()
    }))
}

/// `GET /v1/insurance/dashboard` — Insurance marketplace dashboard.
async fn dashboard(State(state): State<AppState>) -> Json<Value> {
    let insurance = state.insurance_state.read().await;
    let dashboard = insurance.dashboard();
    Json(serde_json::to_value(&dashboard).unwrap_or_else(|_| json!({})))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_app() -> Router {
        let state = AppState::default();
        insurance_routes(state)
    }

    #[tokio::test]
    async fn list_products_empty() {
        let app = test_app();
        let req = Request::builder()
            .uri("/v1/insurance/products")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_empty() {
        let app = test_app();
        let req = Request::builder()
            .uri("/v1/insurance/dashboard")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn pool_status_no_pool() {
        let app = test_app();
        let req = Request::builder()
            .uri("/v1/insurance/pool")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn risk_assessment_unknown_agent() {
        let app = test_app();
        let req = Request::builder()
            .uri("/v1/insurance/risk/unknown-agent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_providers_empty() {
        let app = test_app();
        let req = Request::builder()
            .uri("/v1/insurance/providers")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

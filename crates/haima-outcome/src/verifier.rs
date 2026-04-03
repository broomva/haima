//! Success verification — trait and built-in verifiers for automated outcome checking.
//!
//! Three built-in verifiers cover the most common task types:
//! - [`TestsPassedVerifier`] — calls a CI/webhook endpoint to check test results
//! - [`DataValidatedVerifier`] — calls a validation endpoint to check data output
//! - [`WebhookConfirmedVerifier`] — calls an arbitrary webhook and checks for 2xx

use async_trait::async_trait;
use chrono::Utc;
use haima_core::outcome::{CriterionResult, SuccessCriterion};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// A pluggable verifier that checks whether a single success criterion has been met.
///
/// Implementations must be `Send + Sync` so they can be used across async tasks.
#[async_trait]
pub trait SuccessVerifier: Send + Sync {
    /// Human-readable name for this verifier (e.g., "tests_passed", "webhook").
    fn name(&self) -> &str;

    /// Check whether the criterion is satisfied for the given task.
    ///
    /// Returns a [`CriterionResult`] with `passed` = true/false and optional details.
    async fn verify(&self, task_id: &str, criterion: &SuccessCriterion) -> CriterionResult;
}

// ---------------------------------------------------------------------------
// Tests Passed Verifier
// ---------------------------------------------------------------------------

/// Verifies that tests passed by calling a CI status endpoint.
///
/// Expects the endpoint to return JSON with a `"passed": true/false` field.
/// If the endpoint is unreachable, the criterion fails.
///
/// # Endpoint contract
///
/// ```text
/// GET {base_url}/status?task_id={task_id}&scope={scope}
/// → { "passed": bool, "details": "optional message" }
/// ```
pub struct TestsPassedVerifier {
    /// Base URL for the CI status API (e.g., `http://localhost:8080/ci`).
    pub base_url: String,
    /// HTTP client (shared across calls).
    client: reqwest::Client,
}

impl TestsPassedVerifier {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }
}

/// Response from the CI status endpoint.
#[derive(Debug, Deserialize)]
struct TestStatusResponse {
    passed: bool,
    #[serde(default)]
    details: Option<String>,
}

#[async_trait]
impl SuccessVerifier for TestsPassedVerifier {
    fn name(&self) -> &str {
        "tests_passed"
    }

    async fn verify(&self, task_id: &str, criterion: &SuccessCriterion) -> CriterionResult {
        let scope = match criterion {
            SuccessCriterion::TestsPassed { scope } => scope.clone(),
            _ => "unknown".to_string(),
        };

        let url = format!(
            "{}/status?task_id={}&scope={}",
            self.base_url, task_id, scope
        );

        match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<TestStatusResponse>().await {
                    Ok(body) => CriterionResult {
                        criterion: criterion.clone(),
                        passed: body.passed,
                        details: body.details,
                        checked_at: Utc::now(),
                    },
                    Err(e) => CriterionResult {
                        criterion: criterion.clone(),
                        passed: false,
                        details: Some(format!("failed to parse CI response: {e}")),
                        checked_at: Utc::now(),
                    },
                }
            }
            Ok(resp) => CriterionResult {
                criterion: criterion.clone(),
                passed: false,
                details: Some(format!("CI endpoint returned status {}", resp.status())),
                checked_at: Utc::now(),
            },
            Err(e) => CriterionResult {
                criterion: criterion.clone(),
                passed: false,
                details: Some(format!("CI endpoint unreachable: {e}")),
                checked_at: Utc::now(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Data Validated Verifier
// ---------------------------------------------------------------------------

/// Verifies that output data passes validation against a schema or rule set.
///
/// Calls a validation service endpoint that checks task output.
///
/// # Endpoint contract
///
/// ```text
/// POST {base_url}/validate
/// Body: { "task_id": "...", "rule_id": "..." }
/// → { "valid": bool, "details": "optional message" }
/// ```
pub struct DataValidatedVerifier {
    /// Base URL for the validation service.
    pub base_url: String,
    client: reqwest::Client,
}

impl DataValidatedVerifier {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }
}

/// Request body for the validation endpoint.
#[derive(Debug, Serialize)]
struct ValidateRequest<'a> {
    task_id: &'a str,
    rule_id: &'a str,
}

/// Response from the validation endpoint.
#[derive(Debug, Deserialize)]
struct ValidateResponse {
    valid: bool,
    #[serde(default)]
    details: Option<String>,
}

#[async_trait]
impl SuccessVerifier for DataValidatedVerifier {
    fn name(&self) -> &str {
        "data_validated"
    }

    async fn verify(&self, task_id: &str, criterion: &SuccessCriterion) -> CriterionResult {
        let rule_id = match criterion {
            SuccessCriterion::DataValidated { rule_id } => rule_id.clone(),
            _ => "unknown".to_string(),
        };

        let url = format!("{}/validate", self.base_url);
        let body = ValidateRequest {
            task_id,
            rule_id: &rule_id,
        };

        match self.client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<ValidateResponse>().await {
                Ok(body) => CriterionResult {
                    criterion: criterion.clone(),
                    passed: body.valid,
                    details: body.details,
                    checked_at: Utc::now(),
                },
                Err(e) => CriterionResult {
                    criterion: criterion.clone(),
                    passed: false,
                    details: Some(format!("failed to parse validation response: {e}")),
                    checked_at: Utc::now(),
                },
            },
            Ok(resp) => CriterionResult {
                criterion: criterion.clone(),
                passed: false,
                details: Some(format!(
                    "validation endpoint returned status {}",
                    resp.status()
                )),
                checked_at: Utc::now(),
            },
            Err(e) => CriterionResult {
                criterion: criterion.clone(),
                passed: false,
                details: Some(format!("validation endpoint unreachable: {e}")),
                checked_at: Utc::now(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook Confirmed Verifier
// ---------------------------------------------------------------------------

/// Verifies task success by calling a webhook URL and checking for a 2xx response.
///
/// The webhook receives a JSON payload with the task ID and is expected to return
/// a 2xx status if the criterion is met.
///
/// # Webhook contract
///
/// ```text
/// POST {url}
/// Body: { "task_id": "...", "action": "verify" }
/// → 2xx = passed, anything else = failed
/// ```
pub struct WebhookConfirmedVerifier {
    client: reqwest::Client,
}

impl WebhookConfirmedVerifier {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for WebhookConfirmedVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Payload sent to the webhook.
#[derive(Debug, Serialize)]
struct WebhookPayload<'a> {
    task_id: &'a str,
    action: &'a str,
}

#[async_trait]
impl SuccessVerifier for WebhookConfirmedVerifier {
    fn name(&self) -> &str {
        "webhook_confirmed"
    }

    async fn verify(&self, task_id: &str, criterion: &SuccessCriterion) -> CriterionResult {
        let url = match criterion {
            SuccessCriterion::WebhookConfirmed { url } => url.clone(),
            _ => {
                return CriterionResult {
                    criterion: criterion.clone(),
                    passed: false,
                    details: Some("criterion is not WebhookConfirmed".to_string()),
                    checked_at: Utc::now(),
                };
            }
        };

        let payload = WebhookPayload {
            task_id,
            action: "verify",
        };

        match self.client.post(&url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => CriterionResult {
                criterion: criterion.clone(),
                passed: true,
                details: Some(format!("webhook returned {}", resp.status())),
                checked_at: Utc::now(),
            },
            Ok(resp) => CriterionResult {
                criterion: criterion.clone(),
                passed: false,
                details: Some(format!("webhook returned {}", resp.status())),
                checked_at: Utc::now(),
            },
            Err(e) => CriterionResult {
                criterion: criterion.clone(),
                passed: false,
                details: Some(format!("webhook unreachable: {e}")),
                checked_at: Utc::now(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Manual Approval Verifier (pass-through)
// ---------------------------------------------------------------------------

/// A no-op verifier for manual approval criteria.
///
/// Manual approvals cannot be checked automatically — they always return `false`
/// (pending) until an explicit approval is submitted via the API. The engine
/// uses this as a fallback to record that the criterion exists but needs
/// human input.
pub struct ManualApprovalVerifier;

#[async_trait]
impl SuccessVerifier for ManualApprovalVerifier {
    fn name(&self) -> &str {
        "manual_approval"
    }

    async fn verify(&self, _task_id: &str, criterion: &SuccessCriterion) -> CriterionResult {
        CriterionResult {
            criterion: criterion.clone(),
            passed: false,
            details: Some("awaiting manual approval".to_string()),
            checked_at: Utc::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_names() {
        let tests = TestsPassedVerifier::new("http://localhost".into());
        assert_eq!(tests.name(), "tests_passed");

        let data = DataValidatedVerifier::new("http://localhost".into());
        assert_eq!(data.name(), "data_validated");

        let webhook = WebhookConfirmedVerifier::new();
        assert_eq!(webhook.name(), "webhook_confirmed");

        let manual = ManualApprovalVerifier;
        assert_eq!(manual.name(), "manual_approval");
    }

    #[tokio::test]
    async fn manual_approval_always_pending() {
        let verifier = ManualApprovalVerifier;
        let criterion = SuccessCriterion::ManualApproval {
            approver: "reviewer".into(),
        };
        let result = verifier.verify("task-1", &criterion).await;
        assert!(!result.passed);
        assert!(result.details.unwrap().contains("manual approval"));
    }

    #[tokio::test]
    async fn webhook_wrong_criterion_type() {
        let verifier = WebhookConfirmedVerifier::new();
        let criterion = SuccessCriterion::TestsPassed {
            scope: "unit".into(),
        };
        let result = verifier.verify("task-1", &criterion).await;
        assert!(!result.passed);
        assert!(result.details.unwrap().contains("not WebhookConfirmed"));
    }

    #[tokio::test]
    async fn tests_verifier_unreachable() {
        let verifier = TestsPassedVerifier::new("http://127.0.0.1:1".into());
        let criterion = SuccessCriterion::TestsPassed {
            scope: "unit".into(),
        };
        let result = verifier.verify("task-1", &criterion).await;
        assert!(!result.passed);
        assert!(result.details.unwrap().contains("unreachable"));
    }

    #[tokio::test]
    async fn data_verifier_unreachable() {
        let verifier = DataValidatedVerifier::new("http://127.0.0.1:1".into());
        let criterion = SuccessCriterion::DataValidated {
            rule_id: "schema-1".into(),
        };
        let result = verifier.verify("task-1", &criterion).await;
        assert!(!result.passed);
        assert!(result.details.unwrap().contains("unreachable"));
    }
}

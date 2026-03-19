//! Facilitator client — communicates with payment facilitators for
//! verification and on-chain settlement.
//!
//! Supported facilitators:
//! - **Coinbase CDP** (default): Free tier 1K tx/month, then $0.001/tx
//! - **Self-hosted**: Reference facilitator for testing and sovereignty

use haima_core::{HaimaError, HaimaResult};
use serde::{Deserialize, Serialize};

/// Facilitator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitatorConfig {
    /// Facilitator base URL.
    pub url: String,
    /// Facilitator type.
    pub kind: FacilitatorKind,
    /// API key (required for Coinbase CDP).
    pub api_key: Option<String>,
}

/// Supported facilitator types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacilitatorKind {
    /// Coinbase CDP facilitator.
    CoinbaseCdp,
    /// Self-hosted reference facilitator.
    SelfHosted,
    /// Stripe facilitator.
    Stripe,
}

impl Default for FacilitatorConfig {
    fn default() -> Self {
        Self {
            url: "https://x402.org/facilitator".into(),
            kind: FacilitatorKind::CoinbaseCdp,
            api_key: None,
        }
    }
}

/// A facilitator handles payment verification and on-chain settlement.
pub struct Facilitator {
    config: FacilitatorConfig,
    client: reqwest::Client,
}

impl Facilitator {
    pub fn new(config: FacilitatorConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Verify a payment payload against the original requirements.
    pub async fn verify(&self, payload: &VerifyRequest) -> HaimaResult<VerifyResponse> {
        let url = format!("{}/verify", self.config.url);

        let mut req = self.client.post(&url).json(payload);
        if let Some(ref key) = self.config.api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| HaimaError::Facilitator(format!("verify request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(HaimaError::Facilitator(format!(
                "verify failed with {status}: {body}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| HaimaError::Facilitator(format!("verify response parse failed: {e}")))
    }

    /// Get supported networks and schemes from the facilitator.
    pub async fn supported(&self) -> HaimaResult<SupportedResponse> {
        let url = format!("{}/supported", self.config.url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| HaimaError::Facilitator(format!("supported request failed: {e}")))?;

        resp.json()
            .await
            .map_err(|e| HaimaError::Facilitator(format!("supported response parse failed: {e}")))
    }

    pub fn config(&self) -> &FacilitatorConfig {
        &self.config
    }
}

/// Request body for the facilitator's /verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub payment_payload: String,
    pub payment_requirements: String,
}

/// Response from the facilitator's /verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

/// Response from the facilitator's /supported endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedResponse {
    pub networks: Vec<String>,
    pub schemes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = FacilitatorConfig::default();
        assert!(matches!(config.kind, FacilitatorKind::CoinbaseCdp));
        assert!(config.api_key.is_none());
    }

    #[test]
    fn verify_response_serde() {
        let resp = VerifyResponse {
            valid: true,
            tx_hash: Some("0xabc123".into()),
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: VerifyResponse = serde_json::from_str(&json).unwrap();
        assert!(back.valid);
        assert_eq!(back.tx_hash.unwrap(), "0xabc123");
    }
}

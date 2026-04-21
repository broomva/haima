//! agentic.market bazaar discovery client.
//!
//! The [agentic.market] bazaar is a directory of x402-enabled HTTP endpoints.
//! It hosts a catalog of services that accept payment via the x402 protocol,
//! exposed through two simple endpoints:
//!
//! - `GET /v1/services` — full catalog
//! - `GET /v1/services/search?q=…` — BM25 search over the catalog
//!
//! The bazaar never touches funds; it is purely a discovery layer. Consumer
//! wallets sign x402 payment authorizations and send them directly to the
//! listed services, which settle through whichever facilitator they choose.
//!
//! [`BazaarClient`] wraps these endpoints with a TTL cache (default 10 min)
//! so Haima agents can look up services without hammering the upstream.
//! Cache is process-local and opt-in per client.
//!
//! # Graceful degradation
//!
//! - On a cold cache + network failure → [`HaimaError::BazaarUnavailable`].
//! - On a warm cache + expired TTL + network failure → **stale cache is
//!   returned** (the `services` endpoint is idempotent and a stale directory
//!   is strictly better than failing a payment-gated flow).
//!
//! [agentic.market]: https://agentic.market

use std::sync::Arc;
use std::time::{Duration, Instant};

use haima_core::{HaimaError, HaimaResult};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Default base URL for the agentic.market bazaar.
pub const DEFAULT_BAZAAR_URL: &str = "https://agentic.market";

/// Default cache TTL (10 minutes).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(600);

/// A single x402-enabled service listed in the bazaar.
///
/// Fields are `#[serde(default)]` because the upstream schema evolves and we
/// never want a schema drift to break discovery entirely — unknown fields are
/// ignored and missing optional ones default sensibly.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ServiceEntry {
    /// Human-readable service name.
    pub name: String,
    /// Base URL or endpoint where a consumer sends the paid request.
    pub url: String,
    /// Category tag (e.g., `"inference"`, `"data"`, `"search"`).
    pub category: String,
    /// Short description.
    pub description: String,
    /// Human-readable price band (e.g., `"$0.001–$0.01"`). Varies in upstream
    /// representation; kept as a free-form string.
    pub price_range: String,
    /// Networks this service accepts payment on (CAIP-2 format when known).
    pub networks: Vec<String>,
    /// Payment methods accepted (typically contains `"x402"`).
    pub payment_methods: Vec<String>,
}

/// Response envelope for `GET /v1/services` and `/v1/services/search`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServicesEnvelope {
    #[serde(default)]
    services: Vec<ServiceEntry>,
}

/// Bazaar client with TTL cache.
///
/// Cheap to clone (`Arc` internally) and safe to share across async tasks.
#[derive(Debug, Clone)]
pub struct BazaarClient {
    base_url: String,
    http: reqwest::Client,
    cache: Arc<RwLock<CacheState>>,
    ttl: Duration,
}

#[derive(Debug, Default)]
struct CacheState {
    services: Option<CachedServices>,
}

#[derive(Debug, Clone)]
struct CachedServices {
    data: Vec<ServiceEntry>,
    fetched_at: Instant,
}

impl BazaarClient {
    /// Create a client pointed at the default `https://agentic.market` bazaar
    /// with a 10-minute cache TTL.
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BAZAAR_URL)
    }

    /// Create a client pointed at an arbitrary bazaar URL.
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self::builder().base_url(base_url).build()
    }

    /// Builder for customizing the client.
    pub fn builder() -> BazaarClientBuilder {
        BazaarClientBuilder::default()
    }

    /// List all services advertised by the bazaar.
    ///
    /// Serves from cache when fresh (< TTL). On cache miss, fetches from
    /// the upstream and repopulates the cache. If the upstream fails and
    /// stale data is available, returns the stale data with a warning.
    pub async fn services(&self) -> HaimaResult<Vec<ServiceEntry>> {
        if let Some(fresh) = self.cached_fresh().await {
            debug!(count = fresh.len(), "bazaar cache hit for /v1/services");
            return Ok(fresh);
        }

        match self.fetch_services().await {
            Ok(services) => {
                self.store(services.clone()).await;
                Ok(services)
            }
            Err(fetch_err) => {
                if let Some(stale) = self.cached_any().await {
                    warn!(
                        error = %fetch_err,
                        count = stale.len(),
                        "bazaar upstream failed, serving stale cache"
                    );
                    Ok(stale)
                } else {
                    Err(fetch_err)
                }
            }
        }
    }

    /// Search the bazaar for services matching a query.
    ///
    /// Goes directly upstream — search results are not cached (queries are
    /// unbounded and caching them wastes memory for little hit rate).
    pub async fn search(&self, q: &str) -> HaimaResult<Vec<ServiceEntry>> {
        let url = format!("{}/v1/services/search", self.base_url.trim_end_matches('/'));
        debug!(%url, q, "bazaar search");
        let resp = self
            .http
            .get(&url)
            .query(&[("q", q)])
            .send()
            .await
            .map_err(|e| HaimaError::BazaarUnavailable(format!("search '{q}' failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(HaimaError::BazaarUnavailable(format!(
                "search returned HTTP {}",
                resp.status()
            )));
        }

        let envelope: ServicesEnvelope = resp.json().await.map_err(|e| {
            HaimaError::BazaarUnavailable(format!("malformed search response: {e}"))
        })?;
        Ok(envelope.services)
    }

    /// Manually invalidate the services cache. Useful for tests and for
    /// forcing a refresh after a known upstream update.
    pub async fn invalidate_cache(&self) {
        let mut guard = self.cache.write().await;
        guard.services = None;
    }

    // -- internals --

    async fn fetch_services(&self) -> HaimaResult<Vec<ServiceEntry>> {
        let url = format!("{}/v1/services", self.base_url.trim_end_matches('/'));
        debug!(%url, "bazaar fetch");
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| HaimaError::BazaarUnavailable(format!("fetch failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(HaimaError::BazaarUnavailable(format!(
                "fetch returned HTTP {}",
                resp.status()
            )));
        }

        let envelope: ServicesEnvelope = resp.json().await.map_err(|e| {
            HaimaError::BazaarUnavailable(format!("malformed services response: {e}"))
        })?;
        Ok(envelope.services)
    }

    async fn cached_fresh(&self) -> Option<Vec<ServiceEntry>> {
        let guard = self.cache.read().await;
        guard.services.as_ref().and_then(|c| {
            if c.fetched_at.elapsed() < self.ttl {
                Some(c.data.clone())
            } else {
                None
            }
        })
    }

    async fn cached_any(&self) -> Option<Vec<ServiceEntry>> {
        let guard = self.cache.read().await;
        guard.services.as_ref().map(|c| c.data.clone())
    }

    async fn store(&self, data: Vec<ServiceEntry>) {
        let mut guard = self.cache.write().await;
        guard.services = Some(CachedServices {
            data,
            fetched_at: Instant::now(),
        });
    }
}

impl Default for BazaarClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`BazaarClient`].
#[derive(Debug, Default)]
pub struct BazaarClientBuilder {
    base_url: Option<String>,
    ttl: Option<Duration>,
    http: Option<reqwest::Client>,
}

impl BazaarClientBuilder {
    /// Override the base URL (defaults to `https://agentic.market`).
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Override the cache TTL (defaults to 10 minutes).
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Inject a custom `reqwest::Client` (useful for tests with custom timeouts).
    pub fn http(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> BazaarClient {
        BazaarClient {
            base_url: self.base_url.unwrap_or_else(|| DEFAULT_BAZAAR_URL.into()),
            http: self.http.unwrap_or_default(),
            cache: Arc::new(RwLock::new(CacheState::default())),
            ttl: self.ttl.unwrap_or(DEFAULT_CACHE_TTL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_entry_parses_minimal_json() {
        let json = r#"{"name":"Claude","url":"https://api.example.com/claude","category":"inference","description":"","price_range":"$0.001","networks":["eip155:8453"],"payment_methods":["x402"]}"#;
        let entry: ServiceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.name, "Claude");
        assert_eq!(entry.networks, vec!["eip155:8453"]);
        assert_eq!(entry.payment_methods, vec!["x402"]);
    }

    #[test]
    fn service_entry_tolerates_missing_optional_fields() {
        // Upstream drift: no `networks` or `payment_methods` → defaults to empty.
        let json = r#"{"name":"X","url":"https://x","category":"other","description":"","price_range":""}"#;
        let entry: ServiceEntry = serde_json::from_str(json).unwrap();
        assert!(entry.networks.is_empty());
        assert!(entry.payment_methods.is_empty());
    }

    #[test]
    fn service_entry_tolerates_unknown_fields() {
        // Upstream drift: new fields we don't know about must not break parsing.
        let json = r#"{"name":"X","url":"https://x","category":"","description":"","price_range":"","networks":[],"payment_methods":[],"completely_new_field":{"nested":true}}"#;
        let entry: ServiceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.name, "X");
    }

    #[test]
    fn services_envelope_parses_array() {
        let json = r#"{"services":[{"name":"A","url":"https://a","category":"","description":"","price_range":"","networks":[],"payment_methods":[]},{"name":"B","url":"https://b","category":"","description":"","price_range":"","networks":[],"payment_methods":[]}]}"#;
        let envelope: ServicesEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.services.len(), 2);
    }

    #[test]
    fn builder_defaults_to_agentic_market() {
        let c = BazaarClient::new();
        assert_eq!(c.base_url, DEFAULT_BAZAAR_URL);
        assert_eq!(c.ttl, DEFAULT_CACHE_TTL);
    }

    #[test]
    fn builder_overrides_base_and_ttl() {
        let c = BazaarClient::builder()
            .base_url("https://example.test")
            .ttl(Duration::from_secs(30))
            .build();
        assert_eq!(c.base_url, "https://example.test");
        assert_eq!(c.ttl, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn cache_is_empty_initially() {
        let c = BazaarClient::new();
        assert!(c.cached_fresh().await.is_none());
        assert!(c.cached_any().await.is_none());
    }

    #[tokio::test]
    async fn store_then_cached_fresh_returns_data() {
        let c = BazaarClient::builder().ttl(Duration::from_secs(60)).build();
        let entry = ServiceEntry {
            name: "A".into(),
            url: "https://a".into(),
            ..Default::default()
        };
        c.store(vec![entry.clone()]).await;

        let got = c.cached_fresh().await.expect("should be fresh");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], entry);
    }

    #[tokio::test]
    async fn cached_fresh_returns_none_after_ttl_expiry() {
        let c = BazaarClient::builder()
            .ttl(Duration::from_millis(1))
            .build();
        c.store(vec![ServiceEntry::default()]).await;

        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(c.cached_fresh().await.is_none());
        // But stale data still available for graceful degradation.
        assert!(c.cached_any().await.is_some());
    }

    #[tokio::test]
    async fn invalidate_cache_clears_even_fresh_data() {
        let c = BazaarClient::builder().ttl(Duration::from_secs(60)).build();
        c.store(vec![ServiceEntry::default()]).await;
        assert!(c.cached_fresh().await.is_some());

        c.invalidate_cache().await;

        assert!(c.cached_fresh().await.is_none());
        assert!(c.cached_any().await.is_none());
    }

    #[tokio::test]
    async fn services_returns_bazaar_unavailable_when_cold_and_offline() {
        // Point at a definitely-dead local port; no cache → must error.
        let c = BazaarClient::builder()
            .base_url("http://127.0.0.1:1")
            .build();
        let result = c.services().await;
        match result {
            Err(HaimaError::BazaarUnavailable(_)) => {}
            other => panic!("expected BazaarUnavailable, got {other:?}"),
        }
    }
}

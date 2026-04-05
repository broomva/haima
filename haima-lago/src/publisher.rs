//! Finance event publisher — writes Haima events to the Lago journal.

use haima_core::HaimaResult;
use haima_core::event::FinanceEventKind;
use tracing::info;

/// Publishes finance events to the Lago event journal.
///
/// Events are stored as `EventKind::Custom { event_type: "finance.*", data }`.
pub struct FinancePublisher {
    /// Whether publishing is enabled (for testing without Lago).
    enabled: bool,
}

impl FinancePublisher {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Publish a finance event to the Lago journal.
    ///
    /// In production, this calls `EventStorePort::append` with the event
    /// wrapped in `EventKind::Custom`. Stubbed for Phase F0.
    pub async fn publish(&self, event: &FinanceEventKind) -> HaimaResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let event_type = event.event_type();
        info!(event_type = %event_type, "publishing finance event");

        // Phase F2: Wire to lago-journal via EventStorePort.
        // For now, log the event type for tracing.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_when_disabled() {
        let publisher = FinancePublisher::new(false);
        let event = FinanceEventKind::PaymentSettled {
            tx_hash: "0xabc".into(),
            amount_micro_credits: 100,
            chain: "eip155:8453".into(),
            latency_ms: 1200,
            facilitator: "test".into(),
        };
        // Should not error when disabled
        publisher.publish(&event).await.unwrap();
    }

    #[tokio::test]
    async fn publish_when_enabled() {
        let publisher = FinancePublisher::new(true);
        let event = FinanceEventKind::WalletCreated {
            address: "0xtest".into(),
            chain: "eip155:8453".into(),
            key_blob_id: None,
        };
        publisher.publish(&event).await.unwrap();
    }
}

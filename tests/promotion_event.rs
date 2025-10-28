use parking_lot::Mutex;
use std::sync::Arc;

use thenodes::events::{dispatcher, model::LogEvent, sink::LogSink};
use thenodes::security::trust::promote_observed_to_trusted;

struct MemorySink {
    events: Arc<Mutex<Vec<LogEvent>>>,
}

#[async_trait::async_trait]
impl LogSink for MemorySink {
    async fn handle(&self, event: &LogEvent) {
        self.events.lock().push(event.clone());
    }
}

#[tokio::test]
async fn promotion_event_emitted() {
    // Prepare temp dirs
    let tmp = tempfile::tempdir().unwrap();
    let observed = tmp.path().join("observed");
    let trusted = tmp.path().join("trusted");
    std::fs::create_dir_all(&observed).unwrap();

    // Minimal fake cert content (not parsed here, just stored)
    let fingerprint = "deadbeef"; // fake fingerprint for filename
    let pem = b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n";
    std::fs::write(observed.join(format!("{}.pem", fingerprint)), pem).unwrap();

    // Init events with memory sink
    let mem = Arc::new(MemorySink {
        events: Arc::new(Mutex::new(Vec::new())),
    });
    dispatcher::init_events(vec![mem.clone()], 32).await;

    // Perform promotion
    let promoted = promote_observed_to_trusted(
        observed.to_str().unwrap(),
        trusted.to_str().unwrap(),
        fingerprint,
    )
    .unwrap();
    assert!(promoted, "expected promotion to succeed");

    // Allow dispatch loop to process
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let evts = mem.events.lock();
    let has_promotion = evts
        .iter()
        .any(|e| matches!(e, LogEvent::Promotion(pe) if pe.fingerprint == fingerprint));
    assert!(
        has_promotion,
        "expected a PromotionEvent with matching fingerprint, got: {:?}",
        *evts
    );
}

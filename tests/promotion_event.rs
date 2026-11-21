use parking_lot::Mutex;
use std::sync::Arc;

use thenodes::events::{dispatcher, model::LogEvent, sink::LogSink};
use thenodes::security::trust::{promote_rejected_to_trusted, KeyStore};

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
    let rejected = tmp.path().join("rejected");
    let trusted = tmp.path().join("trusted");
    std::fs::create_dir_all(&rejected).unwrap();

    // Minimal fake cert content (not parsed here, just stored)
    let fingerprint = "deadbeef".repeat(8); // fake SHA-256 fingerprint for filename
    let pem = b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n";
    std::fs::write(rejected.join(format!("{}.pem", fingerprint)), pem).unwrap();

    // Init events with memory sink
    let mem = Arc::new(MemorySink {
        events: Arc::new(Mutex::new(Vec::new())),
    });
    dispatcher::init_events(vec![mem.clone()], 32).await;

    // Perform promotion
    let store = KeyStore {
        backend: "tls",
        extension: "pem",
        trusted_dir: Some(trusted.to_string_lossy().into_owned()),
        rejected_dir: Some(rejected.to_string_lossy().into_owned()),
    };
    let promoted = promote_rejected_to_trusted(&store, &fingerprint).unwrap();
    assert!(promoted, "expected promotion to succeed");
    // Promotion moves the certificate out of the rejected directory.
    assert!(trusted.join(format!("{}.pem", fingerprint)).exists());
    assert!(!rejected.join(format!("{}.pem", fingerprint)).exists());

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

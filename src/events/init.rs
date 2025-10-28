use crate::events::dispatcher::init_events;
use crate::events::model::LogLevel;
use crate::events::sink::{ConsoleSink, JsonFileSink, LogSink};
use std::sync::Arc;

/// Initialize events with defaults
pub async fn init_default_events() {
    init_events_with_options(None, None).await
}

/// Initialize events using optional logging config
pub async fn init_events_from_config(logging: Option<&crate::config::LoggingConfig>) {
    init_events_with_options(logging, None).await
}

/// Initialize events using optional logging config and console minimum level filter
pub async fn init_events_with_options(
    logging: Option<&crate::config::LoggingConfig>,
    console_min_level: Option<LogLevel>,
) {
    let mut sinks: Vec<Arc<dyn LogSink>> = Vec::new();

    let disable_console = logging.and_then(|l| l.disable_console).unwrap_or(false);
    if !disable_console {
        sinks.push(Arc::new(ConsoleSink::new(console_min_level)));
    }

    let json_path = logging
        .and_then(|l| l.json_path.clone())
        .unwrap_or_else(|| "logs/trust_audit.jsonl".into());
    let max_bytes = logging
        .and_then(|l| l.json_max_bytes)
        .unwrap_or(5 * 1024 * 1024);
    let rotate = logging.and_then(|l| l.json_rotate).unwrap_or(3);
    if let Ok(json_sink) = JsonFileSink::new(&json_path, true, max_bytes as u64, rotate).await {
        sinks.push(Arc::new(json_sink));
    }
    init_events(sinks, 1024).await;
}

// Back-compat helpers removed for v0 initial release.

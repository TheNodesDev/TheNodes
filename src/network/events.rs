use crate::events::{
    dispatcher,
    model::{LogEvent, LogLevel, NetworkEvent},
};

/// Emit a structured network event with optional console output suppression.
pub(crate) fn emit_network_event(
    component: &'static str,
    level: LogLevel,
    action: &str,
    addr: Option<String>,
    detail: Option<String>,
    allow_console: bool,
) {
    let mut meta = dispatcher::meta(component, level);
    meta.corr_id = Some(dispatcher::correlation_id());
    if !allow_console {
        meta.suppress_console = true;
    }
    dispatcher::emit(LogEvent::Network(NetworkEvent {
        meta,
        action: action.to_string(),
        addr,
        detail,
    }));
}

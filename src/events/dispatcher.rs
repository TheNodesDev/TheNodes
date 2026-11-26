use crate::events::model::{EventMeta, LogEvent, LogLevel};
use crate::events::sink::LogSink;
use crate::plugin_host::runtime::HostServices;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;
use uuid::Uuid;

static DISPATCHER: OnceCell<EventDispatcher> = OnceCell::new();

pub struct EventDispatcher {
    pub tx: mpsc::Sender<LogEvent>,
    pub session_id: String,
    sinks: RwLock<Vec<Arc<dyn LogSink>>>,
    policy_checksum: RwLock<Option<String>>,
}

/// Lightweight handle exposed to external callers (e.g., plugins) so they can
/// emit events or register additional sinks without exposing internal locks.
///
/// A handle from [`handle`] uses the global dispatcher of the calling code
/// copy. Native plugin contexts carry a host-bound handle instead, which
/// submits events to the host's dispatcher through host services; a native
/// library's own global dispatcher is never initialized.
#[derive(Clone, Default)]
pub struct EventHandle {
    host: Option<Arc<dyn HostServices>>,
}

/// Why a sink could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkRegistrationError {
    /// The event dispatcher has not been initialized.
    DispatcherNotInitialized,
    /// Native plugins cannot register sinks: the dispatcher would poll futures
    /// created by plugin code on the host runtime.
    NotAvailableInNativePlugin,
}

impl std::fmt::Display for SinkRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SinkRegistrationError::DispatcherNotInitialized => {
                write!(f, "event dispatcher is not initialized")
            }
            SinkRegistrationError::NotAvailableInNativePlugin => {
                write!(f, "native plugins cannot register event sinks")
            }
        }
    }
}

impl std::error::Error for SinkRegistrationError {}

impl EventHandle {
    pub(crate) fn host_bound(host: Arc<dyn HostServices>) -> Self {
        Self { host: Some(host) }
    }

    pub fn emit(&self, event: LogEvent) {
        match &self.host {
            Some(host) => host.submit_event(event),
            None => super::dispatcher::emit(event),
        }
    }
    pub fn register_sink(&self, sink: Arc<dyn LogSink>) -> Result<(), SinkRegistrationError> {
        if self.host.is_some() {
            return Err(SinkRegistrationError::NotAvailableInNativePlugin);
        }
        let dispatcher =
            EventDispatcher::global().ok_or(SinkRegistrationError::DispatcherNotInitialized)?;
        dispatcher.register_sink(sink);
        Ok(())
    }
    pub fn correlation_id(&self) -> String {
        correlation_id()
    }
    pub fn session_id(&self) -> Option<String> {
        match &self.host {
            Some(host) => host.session_id(),
            None => EventDispatcher::global().map(|d| d.session_id.clone()),
        }
    }
}

impl EventDispatcher {
    pub fn global() -> Option<&'static EventDispatcher> {
        DISPATCHER.get()
    }
    pub fn set_policy_checksum(&self, sum: Option<String>) {
        *self.policy_checksum.write() = sum;
    }
    pub fn policy_checksum(&self) -> Option<String> {
        self.policy_checksum.read().clone()
    }
    pub fn register_sink(&self, sink: Arc<dyn LogSink>) {
        self.sinks.write().push(sink);
    }
}

pub async fn init_events(sinks: Vec<Arc<dyn LogSink>>, capacity: usize) {
    let (tx, mut rx) = mpsc::channel::<LogEvent>(capacity);
    let dispatcher = EventDispatcher {
        tx: tx.clone(),
        session_id: Uuid::new_v4().to_string(),
        sinks: RwLock::new(sinks),
        policy_checksum: RwLock::new(None),
    };
    let _ = DISPATCHER.set(dispatcher);
    tokio::spawn(async move {
        while let Some(evt) = rx.recv().await {
            if let Some(d) = EventDispatcher::global() {
                let sinks = d.sinks.read().clone();
                for sink in sinks {
                    sink.handle(&evt).await;
                }
            }
        }
    });
}

pub fn correlation_id() -> String {
    Uuid::new_v4().to_string()[..8].to_string()
}

pub fn meta(component: &'static str, level: LogLevel) -> EventMeta {
    if let Some(d) = EventDispatcher::global() {
        EventMeta {
            ts: SystemTime::now(),
            level,
            corr_id: None,
            session_id: d.session_id.clone(),
            component,
            policy_checksum: d.policy_checksum(),
            suppress_console: false,
        }
    } else {
        EventMeta {
            ts: SystemTime::now(),
            level,
            corr_id: None,
            session_id: "unknown".into(),
            component,
            policy_checksum: None,
            suppress_console: false,
        }
    }
}

pub fn emit(event: LogEvent) {
    if let Some(d) = EventDispatcher::global() {
        let _ = d.tx.try_send(event);
    }
}

pub fn handle() -> EventHandle {
    EventHandle::default()
}

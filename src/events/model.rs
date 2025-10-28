use serde::Serialize;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionRole {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BindingStatus {
    Passed,
    Failed,
    NotApplied,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventMeta {
    pub ts: SystemTime,
    pub level: LogLevel,
    pub corr_id: Option<String>,
    pub session_id: String,
    pub component: &'static str,
    pub policy_checksum: Option<String>,
    pub suppress_console: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustDecisionEvent {
    pub meta: EventMeta,
    pub role: ConnectionRole,
    pub decision: String,
    pub reason: String,
    pub mode: String,
    pub fingerprint: Option<String>,
    pub pinned_fingerprint_match: Option<bool>,
    pub pinned_subject_match: Option<bool>,
    pub realm_binding: BindingStatus,
    pub chain_valid: Option<bool>,
    pub chain_reason: Option<String>,
    pub time_valid: Option<bool>,
    pub time_reason: Option<String>,
    pub stored: Option<String>,
    pub peer_addr: Option<String>,
    pub realm: Option<String>,
    pub dry_run: bool,
    pub override_action: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromotionEvent {
    pub meta: EventMeta,
    pub fingerprint: String,
    pub from_store: String,
    pub to_store: String,
    pub operator: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkEvent {
    pub meta: EventMeta,
    pub action: String,
    pub addr: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginEvent {
    pub meta: EventMeta,
    pub plugin: String,
    pub action: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemEvent {
    pub meta: EventMeta,
    pub action: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogEvent {
    TrustDecision(TrustDecisionEvent),
    Promotion(PromotionEvent),
    Network(NetworkEvent),
    Plugin(PluginEvent),
    System(SystemEvent),
}

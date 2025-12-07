// src/network/message.rs

use crate::realms::RealmInfo;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    #[serde(rename = "HELLO")]
    Hello {
        node_id: String,
        listen_addr: Option<String>,
        // Optional protocol branding and version for compatibility signaling
        protocol: Option<String>,
        version: Option<String>,
        // Optional realm-defined node type label (e.g., "daemon", "admin")
        node_type: Option<String>,
        // Optional capability flags advertised during handshake
        capabilities: Option<Vec<String>>,
    },
    #[serde(rename = "TEXT")]
    Text(String),
    #[serde(rename = "PEER_REQUEST")]
    PeerRequest { want: u16 },
    #[serde(rename = "PEER_LIST")]
    PeerList { peers: Vec<String> },
    /// Relay bind control opcode (wire token: "RELAY_BIND")
    #[serde(rename = "RELAY_BIND")]
    RelayBind {
        target: String,
        want_store_forward: Option<bool>,
        qos: Option<String>,
        nonce: Option<u64>,
        expires_at: Option<u64>,
    },
    /// Relay bind acknowledgement (wire token: "RELAY_BIND_ACK")
    #[serde(rename = "RELAY_BIND_ACK")]
    RelayBindAck {
        ok: bool,
        reason: Option<Reason>,
        binding_id: Option<String>,
        peer_present: Option<bool>,
        nonce: Option<u64>,
    },
    /// Opaque forwarding frame routed via relay (wire token: "RELAY_FWD")
    #[serde(rename = "RELAY_FWD")]
    RelayForward {
        to: String,
        from: String,
        sequence: Option<u64>,
    },
    /// Explicit unbind to close relay binding (wire token: "RELAY_UNBIND")
    #[serde(rename = "RELAY_UNBIND")]
    RelayUnbind { binding_id: String },
    /// Lifecycle notification from relay (wire token: "RELAY_NOTIFY")
    #[serde(rename = "RELAY_NOTIFY")]
    RelayNotify {
        notif_type: Reason,
        binding_id: Option<String>,
        detail: Option<String>,
    },
    /// Delivery acknowledgement for reliable QoS (wire token: "ACK")
    #[serde(rename = "ACK")]
    Ack {
        to: String,
        from: String,
        sequence: u64,
        status: Option<String>, // "ok" | "dup" | "error"
    },
    #[serde(rename = "DATA_REQUEST")]
    DataRequest,
    #[serde(rename = "DATA_RESPONSE")]
    DataResponse,
    #[serde(rename = "HEARTBEAT")]
    Heartbeat,
    #[serde(rename = "DISCONNECT")]
    Disconnect,
    #[serde(rename = "EXTENSION")]
    Extension { kind: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    PolicyDenied,
    Timeout,
    AlreadyBound,
    UnknownTarget,
    Overload,
    PeerLeft,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Payload {
    Text(String),
    Json(Value),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub from: String,
    pub to: String,
    pub msg_type: MessageType,
    pub payload: Option<Payload>,
    pub realm: Option<RealmInfo>,
}

impl Message {
    pub fn new(
        from: &str,
        to: &str,
        msg_type: MessageType,
        payload: Option<Payload>,
        realm: Option<RealmInfo>,
    ) -> Self {
        Self {
            from: from.to_string(),
            to: to.to_string(),
            msg_type,
            payload,
            realm,
        }
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

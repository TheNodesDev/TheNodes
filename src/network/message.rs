// src/network/message.rs

use crate::realms::RealmInfo;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Hello {
        node_id: String,
        listen_addr: Option<String>,
        // Optional protocol branding and version for compatibility signaling
        protocol: Option<String>,
        version: Option<String>,
        // Optional realm-defined node type label (e.g., "daemon", "admin")
        node_type: Option<String>,
    },
    Text(String),
    PeerRequest {
        want: u16,
    },
    PeerList {
        peers: Vec<String>,
    },
    DataRequest,
    DataResponse,
    Heartbeat,
    Disconnect,
    Extension {
        kind: String,
    },
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

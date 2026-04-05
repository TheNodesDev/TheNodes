// src/network/message.rs

use crate::network::delivery::{DeliveryClass, MessageId};
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
        // Optional UDP (Noise) listen address advertised for direct encrypted UDP transport.
        // Format: "ip:port".  Absent when UDP transport is disabled.  (ADR-0004)
        #[serde(skip_serializing_if = "Option::is_none")]
        udp_listen_addr: Option<String>,
        // Optional observed public UDP address discovered via TNCF OBSERVE_RESP.  (ADR-0005 §2)
        // Populated after at least one successful observation round-trip.
        #[serde(skip_serializing_if = "Option::is_none")]
        udp_observed_addr: Option<String>,
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
    /// End-to-end framework acknowledgement for ADR-0006 delivery.
    #[serde(rename = "DELIVERY_ACK")]
    DeliveryAck {
        message_id: String,
        status: Option<String>, // "ok" | "duplicate" | "error"
    },
    /// Initiator asks a rendezvous node to coordinate a UDP hole punch.  (ADR-0005 §3)
    #[serde(rename = "PUNCH_COORDINATE")]
    PunchCoordinate {
        attempt_id: String,
        /// Target node ID to punch through to.
        target: String,
        /// Maximum time budget for the entire punch sequence (ms).
        timeout_ms: Option<u64>,
    },
    /// Rendezvous invites the responder to participate in a punch.  (ADR-0005 §3)
    #[serde(rename = "PUNCH_INVITE")]
    PunchInvite {
        attempt_id: String,
        /// Node ID of the initiator who requested the punch.
        from_node_id: String,
        /// Time budget inherited from PunchCoordinate (ms).
        timeout_ms: u64,
    },
    /// Responder replies to rendezvous: ready (or not) to accept the punch.  (ADR-0005 §3)
    #[serde(rename = "PUNCH_READY")]
    PunchReady {
        attempt_id: String,
        /// Node ID of the initiator (echoed from PunchInvite.from_node_id).
        target: String,
        /// Whether the responder is willing and able to participate.
        ok: bool,
    },
    /// Rendezvous delivers observed addresses and a synchronized start time to both peers.
    /// Both sides must fire `probe_count` KEEPALIVE probes at `start_at_ms`.  (ADR-0005 §3)
    #[serde(rename = "PUNCH_GO")]
    PunchGo {
        attempt_id: String,
        initiator: String,
        responder: String,
        initiator_observed_addr: String,
        responder_observed_addr: String,
        /// Unix epoch milliseconds; both peers fire probes simultaneously starting here.
        start_at_ms: u64,
        timeout_ms: u64,
    },
    /// Rendezvous or peer signals failure or cancellation.  (ADR-0005 §3)
    #[serde(rename = "PUNCH_ABORT")]
    PunchAbort {
        attempt_id: String,
        target: String,
        reason: Option<Reason>,
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
    NoObservedAddr,
    CapabilityMissing,
    Declined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Payload {
    Text(String),
    Json(Value),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryMetadata {
    pub message_id: MessageId,
    pub class: DeliveryClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordering_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordering_sequence: Option<u64>,
}

impl DeliveryMetadata {
    pub fn new(class: DeliveryClass) -> Self {
        Self {
            message_id: MessageId::generate(),
            class,
            ordering_key: None,
            ordering_sequence: None,
        }
    }

    pub fn with_ordering_key(mut self, ordering_key: impl Into<String>) -> Self {
        self.ordering_key = Some(ordering_key.into());
        self
    }

    pub fn with_ordering_sequence(mut self, ordering_sequence: u64) -> Self {
        self.ordering_sequence = Some(ordering_sequence);
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.class {
            DeliveryClass::OrderedReliable => {
                if self
                    .ordering_key
                    .as_ref()
                    .map(|value| value.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err(
                        "OrderedReliable delivery requires a non-empty ordering_key".to_string()
                    );
                }
                if self.ordering_sequence.is_some_and(|sequence| sequence == 0) {
                    return Err(
                        "OrderedReliable delivery requires ordering_sequence to start at 1"
                            .to_string(),
                    );
                }
            }
            DeliveryClass::FireAndForget | DeliveryClass::Reliable => {
                if self.ordering_key.is_some() || self.ordering_sequence.is_some() {
                    return Err(
                        "ordering metadata is only valid for OrderedReliable delivery".to_string(),
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub from: String,
    pub to: String,
    pub msg_type: MessageType,
    pub payload: Option<Payload>,
    pub realm: Option<RealmInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryMetadata>,
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
            delivery: None,
        }
    }

    pub fn with_delivery(mut self, delivery: DeliveryMetadata) -> Result<Self, String> {
        delivery.validate()?;
        self.delivery = Some(delivery);
        Ok(self)
    }

    pub fn validate_delivery(&self) -> Result<(), String> {
        if let Some(delivery) = &self.delivery {
            delivery.validate()?;
        }

        Ok(())
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn from_json(json: &str) -> Option<Self> {
        let message: Self = serde_json::from_str(json).ok()?;
        message.validate_delivery().ok()?;
        Some(message)
    }
}

#[cfg(test)]
mod tests {
    use super::{DeliveryMetadata, Message, MessageType};
    use crate::network::delivery::DeliveryClass;

    #[test]
    fn ordered_reliable_requires_ordering_key() {
        let message = Message::new("from", "to", MessageType::Heartbeat, None, None)
            .with_delivery(DeliveryMetadata::new(DeliveryClass::OrderedReliable));

        assert!(message.is_err());
    }

    #[test]
    fn reliable_rejects_ordering_key() {
        let message = Message::new("from", "to", MessageType::Heartbeat, None, None).with_delivery(
            DeliveryMetadata::new(DeliveryClass::Reliable).with_ordering_key("stream-a"),
        );

        assert!(message.is_err());
    }

    #[test]
    fn fire_and_forget_rejects_ordering_sequence() {
        let message = Message::new("from", "to", MessageType::Heartbeat, None, None).with_delivery(
            DeliveryMetadata::new(DeliveryClass::FireAndForget).with_ordering_sequence(1),
        );

        assert!(message.is_err());
    }

    #[test]
    fn message_round_trip_preserves_delivery_metadata() {
        let message = Message::new("from", "to", MessageType::Heartbeat, None, None)
            .with_delivery(
                DeliveryMetadata::new(DeliveryClass::OrderedReliable).with_ordering_key("stream-a"),
            )
            .expect("ordered delivery metadata should validate");

        let encoded = message.as_json();
        let decoded = Message::from_json(&encoded).expect("message should deserialize");

        assert_eq!(decoded.delivery, message.delivery);
    }
}

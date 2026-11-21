use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{Config, DeliveryConfig};
use crate::events::model::LogLevel;
use crate::network::events::emit_network_event;
use crate::network::message::{
    decode_relay_opaque_payload_utf8, encode_relay_opaque_payload, DeliveryMetadata, Message,
    MessageOrigin, MessageType, Payload,
};
use crate::network::peer::Peer;
use crate::network::peer_manager::PeerManager;
use crate::network::transport::{connect_to_peer, ConnectToPeerParams};
use crate::network::PeerStore;
use crate::network::{connect_with_policy, ConnectionOutcome, ConnectionPolicy};
use crate::plugin_host::manager::PluginManager;
use crate::realms::RealmInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryClass {
    FireAndForget,
    Reliable,
    OrderedReliable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    LocalAccepted,
    ForwardedToTransport,
    AcknowledgedByPeer,
    DeliveryFailed { reason: DeliveryFailureReason },
    Expired,
    UnsupportedOnPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryFailureReason {
    NoRoute,
    PolicyDenied,
    RetryBudgetExhausted,
    PathLostDuringDelivery,
    /// The sending plugin or host has not been activated yet.
    NotReady,
    /// The host is stopping and no longer accepts plugin sends.
    Stopping,
    /// The sending plugin failed or the host no longer exists.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryTransportPreference {
    Tcp,
    Udp,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DeliveryPathConstraints {
    pub preferred_transport: Option<DeliveryTransportPreference>,
    pub require_bidirectional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryOptions {
    pub class: DeliveryClass,
    pub timeout: Option<Duration>,
    pub retry_budget: Option<u32>,
    pub ordering_key: Option<String>,
    pub path_constraints: Option<DeliveryPathConstraints>,
}

impl DeliveryOptions {
    pub fn new(class: DeliveryClass) -> Self {
        Self {
            class,
            timeout: None,
            retry_budget: None,
            ordering_key: None,
            path_constraints: None,
        }
    }

    pub fn with_ordering_key(mut self, ordering_key: impl Into<String>) -> Self {
        self.ordering_key = Some(ordering_key.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_retry_budget(mut self, retry_budget: u32) -> Self {
        self.retry_budget = Some(retry_budget);
        self
    }

    pub fn with_path_constraints(mut self, path_constraints: DeliveryPathConstraints) -> Self {
        self.path_constraints = Some(path_constraints);
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
            }
            DeliveryClass::FireAndForget | DeliveryClass::Reliable => {
                if self.ordering_key.is_some() {
                    return Err(
                        "ordering_key is only valid for OrderedReliable delivery".to_string()
                    );
                }
            }
        }
        check_ordering_key_len(self.ordering_key.as_deref())
    }
}

/// Longest `message_id` a node accepts, in bytes. Generated IDs are 36-byte
/// UUIDs. Receivers keep IDs for duplicate suppression, so the limit bounds
/// that state.
pub const MAX_MESSAGE_ID_LEN: usize = 128;

/// Longest `ordering_key` a node accepts, in bytes. Receivers keep a key for
/// every ordered scope.
pub const MAX_ORDERING_KEY_LEN: usize = 256;

pub(crate) fn check_ordering_key_len(ordering_key: Option<&str>) -> Result<(), String> {
    match ordering_key {
        Some(key) if key.len() > MAX_ORDERING_KEY_LEN => Err(format!(
            "ordering_key is {} bytes, at most {MAX_ORDERING_KEY_LEN} are allowed",
            key.len()
        )),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(String);

impl MessageId {
    pub fn generate() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for MessageId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for MessageId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Clone)]
pub struct DeliveryRuntime {
    pub peer_manager: PeerManager,
    pub plugin_manager: Arc<PluginManager>,
    pub config: Config,
    pub local_node_id: String,
    pub peer_store: Option<PeerStore>,
    pub allow_console: bool,
}

impl DeliveryRuntime {
    pub fn new(
        peer_manager: PeerManager,
        plugin_manager: Arc<PluginManager>,
        config: Config,
        local_node_id: String,
        peer_store: Option<PeerStore>,
        allow_console: bool,
    ) -> Self {
        Self {
            peer_manager,
            plugin_manager,
            config,
            local_node_id,
            peer_store,
            allow_console,
        }
    }

    pub async fn deliver_message(
        &self,
        mut message: Message,
        options: DeliveryOptions,
    ) -> DeliveryOutcome {
        // This node is the origin of everything it delivers; ordering and
        // relay sequences are keyed on it.
        message.from.clone_from(&self.local_node_id);
        if options.validate().is_err() {
            return DeliveryOutcome::DeliveryFailed {
                reason: DeliveryFailureReason::PolicyDenied,
            };
        }

        let delivery_cfg = delivery_config(&self.config);
        let timeout = resolved_timeout(&delivery_cfg, &options);
        let retry_budget = resolved_retry_budget(&delivery_cfg, &options);
        let retry_interval = Duration::from_millis(delivery_cfg.retry_interval_ms.unwrap_or(500));
        let deadline = Instant::now() + timeout;

        let message = prepare_message_for_delivery(&self.peer_manager, message, &options).await;
        let delivery = match message.delivery.clone() {
            Some(delivery) => delivery,
            None => {
                return DeliveryOutcome::DeliveryFailed {
                    reason: DeliveryFailureReason::PolicyDenied,
                }
            }
        };

        self.peer_manager
            .record_delivery_attempt(&delivery.message_id, delivery.class, &message.to, deadline)
            .await;

        let relay_sequence = if matches!(
            delivery.class,
            DeliveryClass::Reliable | DeliveryClass::OrderedReliable
        ) {
            Some(
                self.peer_manager
                    .next_relay_sequence(&message.from, &message.to)
                    .await,
            )
        } else {
            None
        };

        let result = match delivery.class {
            DeliveryClass::FireAndForget => {
                match self
                    .dispatch_message(&message, &options, relay_sequence)
                    .await
                {
                    Ok(()) => DeliveryOutcome::LocalAccepted,
                    Err(outcome) => outcome,
                }
            }
            DeliveryClass::Reliable | DeliveryClass::OrderedReliable => 'delivery_attempts: loop {
                if Instant::now() >= deadline
                    || self
                        .peer_manager
                        .delivery_expired(&delivery.message_id)
                        .await
                {
                    break DeliveryOutcome::Expired;
                }

                let attempts = self
                    .peer_manager
                    .increment_delivery_attempts(&delivery.message_id)
                    .await
                    .unwrap_or(1);

                if attempts > retry_budget.saturating_add(1) {
                    break DeliveryOutcome::DeliveryFailed {
                        reason: DeliveryFailureReason::RetryBudgetExhausted,
                    };
                }

                match self
                    .dispatch_message(&message, &options, relay_sequence)
                    .await
                {
                    Ok(()) => {
                        self.peer_manager
                            .set_delivery_outcome(
                                &delivery.message_id,
                                DeliveryOutcome::ForwardedToTransport,
                            )
                            .await;
                    }
                    Err(outcome) => {
                        if matches!(outcome, DeliveryOutcome::DeliveryFailed { .. })
                            && attempts > retry_budget
                        {
                            break DeliveryOutcome::DeliveryFailed {
                                reason: DeliveryFailureReason::RetryBudgetExhausted,
                            };
                        }
                        tokio::time::sleep(retry_interval).await;
                        continue;
                    }
                }

                let wait_until = std::cmp::min(Instant::now() + retry_interval, deadline);
                loop {
                    if let Some(DeliveryOutcome::AcknowledgedByPeer) = self
                        .peer_manager
                        .delivery_outcome(&delivery.message_id)
                        .await
                    {
                        break 'delivery_attempts DeliveryOutcome::AcknowledgedByPeer;
                    }

                    if Instant::now() >= deadline {
                        break 'delivery_attempts DeliveryOutcome::Expired;
                    }

                    if Instant::now() >= wait_until {
                        break;
                    }

                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            },
        };

        self.peer_manager
            .set_delivery_outcome(&delivery.message_id, result)
            .await;
        self.peer_manager
            .clear_delivery_attempt(&delivery.message_id)
            .await;
        result
    }

    async fn dispatch_message(
        &self,
        message: &Message,
        options: &DeliveryOptions,
        relay_sequence: Option<u64>,
    ) -> Result<(), DeliveryOutcome> {
        let route = self.select_route(&message.to, options).await?;
        let health_route = match &route {
            DeliveryRoute::Connected | DeliveryRoute::DirectTcp { .. } => {
                (message.to.clone(), crate::network::RouteKind::Tcp)
            }
            DeliveryRoute::Udp | DeliveryRoute::Punch { .. } => {
                (message.to.clone(), crate::network::RouteKind::Udp)
            }
            DeliveryRoute::Relay { relay_node_id } => {
                (relay_node_id.clone(), crate::network::RouteKind::Relay)
            }
        };
        let result = match route {
            DeliveryRoute::Connected => self
                .peer_manager
                .send_to_node_id(&message.to, message.clone())
                .await
                .map_err(|_| DeliveryOutcome::DeliveryFailed {
                    reason: DeliveryFailureReason::PathLostDuringDelivery,
                }),
            DeliveryRoute::DirectTcp { addr } => {
                self.ensure_direct_connection(&message.to, addr).await?;
                self.peer_manager
                    .send_to_node_id(&message.to, message.clone())
                    .await
                    .map_err(|_| DeliveryOutcome::DeliveryFailed {
                        reason: DeliveryFailureReason::PathLostDuringDelivery,
                    })
            }
            DeliveryRoute::Udp => {
                self.ensure_udp_session(&message.to).await?;
                self.peer_manager
                    .send_udp_message_to_node(&message.to, message.clone())
                    .await
                    .map_err(|_| DeliveryOutcome::DeliveryFailed {
                        reason: DeliveryFailureReason::PathLostDuringDelivery,
                    })
            }
            DeliveryRoute::Relay { relay_node_id } => {
                self.dispatch_via_relay(&relay_node_id, message, options, relay_sequence)
                    .await
            }
            DeliveryRoute::Punch {
                relay_node_id,
                timeout,
            } => {
                self.dispatch_via_hole_punch(&relay_node_id, message, timeout)
                    .await
            }
        };
        if result.is_ok() {
            self.peer_manager
                .mark_route_success(&health_route.0, health_route.1)
                .await;
        } else {
            self.peer_manager
                .mark_route_failure(&health_route.0, health_route.1)
                .await;
        }
        result
    }

    async fn select_route(
        &self,
        target_node_id: &str,
        options: &DeliveryOptions,
    ) -> Result<DeliveryRoute, DeliveryOutcome> {
        let preferred_transport = options
            .path_constraints
            .as_ref()
            .and_then(|constraints| constraints.preferred_transport);
        let require_bidirectional = options
            .path_constraints
            .as_ref()
            .map(|constraints| constraints.require_bidirectional)
            .unwrap_or(false);

        if matches!(
            preferred_transport,
            Some(DeliveryTransportPreference::Relay)
        ) {
            return self
                .relay_node_id()
                .await
                .map(|relay_node_id| DeliveryRoute::Relay { relay_node_id })
                .ok_or(DeliveryOutcome::DeliveryFailed {
                    reason: DeliveryFailureReason::NoRoute,
                });
        }

        if matches!(preferred_transport, Some(DeliveryTransportPreference::Tcp)) {
            if self.peer_manager.has_node_id(target_node_id).await
                && self
                    .peer_manager
                    .route_health(target_node_id, crate::network::RouteKind::Tcp)
                    .await
                    != crate::network::RouteHealth::Unresponsive
            {
                return Ok(DeliveryRoute::Connected);
            }
            return self
                .peer_manager
                .tcp_listen_addr_for(target_node_id)
                .await
                .and_then(|addr| addr.parse::<SocketAddr>().ok())
                .map(|addr| DeliveryRoute::DirectTcp { addr })
                .ok_or(DeliveryOutcome::DeliveryFailed {
                    reason: DeliveryFailureReason::NoRoute,
                });
        }

        if matches!(preferred_transport, Some(DeliveryTransportPreference::Udp)) {
            return self
                .select_udp_route(target_node_id, require_bidirectional)
                .await;
        }

        let policy = ConnectionPolicy::from_network_config(&self.config);
        match connect_with_policy(target_node_id, &policy, &self.peer_manager, &self.config).await {
            ConnectionOutcome::AlreadyConnected => Ok(DeliveryRoute::Connected),
            ConnectionOutcome::DirectTcp { addr } => Ok(DeliveryRoute::DirectTcp { addr }),
            ConnectionOutcome::DirectUdp { addr } => {
                if require_bidirectional
                    && self
                        .peer_manager
                        .udp_session_id_for(target_node_id)
                        .await
                        .is_none()
                {
                    Err(DeliveryOutcome::UnsupportedOnPath)
                } else {
                    let _ = addr;
                    Ok(DeliveryRoute::Udp)
                }
            }
            ConnectionOutcome::HolePunchUdp { relay_node_id, .. } => Ok(DeliveryRoute::Punch {
                relay_node_id,
                timeout: Duration::from_millis(policy.punch_timeout_ms),
            }),
            ConnectionOutcome::ViaRelay { relay_node_id } => {
                Ok(DeliveryRoute::Relay { relay_node_id })
            }
            ConnectionOutcome::NoRoute { .. } => Err(DeliveryOutcome::DeliveryFailed {
                reason: DeliveryFailureReason::NoRoute,
            }),
        }
    }

    async fn ensure_direct_connection(
        &self,
        target_node_id: &str,
        addr: SocketAddr,
    ) -> Result<(), DeliveryOutcome> {
        if self.peer_manager.has_node_id(target_node_id).await {
            return Ok(());
        }

        let peer = Peer::new(format!("delivery-{}", target_node_id), addr.to_string());
        let our_realm = self.config.realm.clone().unwrap_or_else(RealmInfo::default);
        connect_to_peer(ConnectToPeerParams {
            peer: &peer,
            our_realm,
            our_port: self.config.port,
            peer_manager: self.peer_manager.clone(),
            plugin_manager: self.plugin_manager.clone(),
            allow_console: self.allow_console,
            config: self.config.clone(),
            local_node_id: self.local_node_id.clone(),
            peer_store: self.peer_store.clone(),
        })
        .await
        .map_err(|_| DeliveryOutcome::DeliveryFailed {
            reason: DeliveryFailureReason::NoRoute,
        })
    }

    async fn ensure_udp_session(&self, target_node_id: &str) -> Result<(), DeliveryOutcome> {
        self.peer_manager
            .ensure_udp_session(target_node_id, &self.local_node_id, Duration::from_secs(5))
            .await
            .map(|_| ())
            .map_err(|_| DeliveryOutcome::DeliveryFailed {
                reason: DeliveryFailureReason::NoRoute,
            })
    }

    async fn select_udp_route(
        &self,
        target_node_id: &str,
        require_bidirectional: bool,
    ) -> Result<DeliveryRoute, DeliveryOutcome> {
        let has_udp_session = self
            .peer_manager
            .udp_session_id_for(target_node_id)
            .await
            .is_some();
        let has_udp_addr = self
            .peer_manager
            .udp_listen_addr_for(target_node_id)
            .await
            .is_some();

        if has_udp_session {
            return Ok(DeliveryRoute::Udp);
        }

        if has_udp_addr && !require_bidirectional {
            return self
                .peer_manager
                .udp_listen_addr_for(target_node_id)
                .await
                .and_then(|addr| addr.parse::<SocketAddr>().ok())
                .map(|_| DeliveryRoute::Udp)
                .ok_or(DeliveryOutcome::DeliveryFailed {
                    reason: DeliveryFailureReason::NoRoute,
                });
        }

        if has_udp_addr && require_bidirectional {
            return Err(DeliveryOutcome::UnsupportedOnPath);
        }

        Err(DeliveryOutcome::DeliveryFailed {
            reason: DeliveryFailureReason::NoRoute,
        })
    }

    async fn relay_node_id(&self) -> Option<String> {
        let node_ids = self.peer_manager.list_node_ids().await;
        for node_id in node_ids {
            if self.config.relay_allowed(&node_id)
                && self
                    .peer_manager
                    .peer_has_capability(&node_id, "relay")
                    .await
            {
                return Some(node_id);
            }
        }
        None
    }

    async fn dispatch_via_relay(
        &self,
        relay_node_id: &str,
        message: &Message,
        options: &DeliveryOptions,
        relay_sequence: Option<u64>,
    ) -> Result<(), DeliveryOutcome> {
        let qos = match options.class {
            DeliveryClass::FireAndForget => Some("low_latency".to_string()),
            DeliveryClass::Reliable | DeliveryClass::OrderedReliable => {
                Some("reliable".to_string())
            }
        };
        let want_store_forward = !matches!(options.class, DeliveryClass::FireAndForget);

        let bind = Message::outbound(
            MessageType::RelayBind {
                target: message.to.clone(),
                want_store_forward: Some(want_store_forward),
                qos,
                nonce: Some(now_secs()),
                expires_at: None,
            },
            None,
            message.realm.clone(),
        );
        self.peer_manager
            .send_to_node_id(relay_node_id, bind)
            .await
            .map_err(|_| DeliveryOutcome::DeliveryFailed {
                reason: DeliveryFailureReason::PathLostDuringDelivery,
            })?;

        // The tunnel carries the message as a frame from this node to its
        // final destination; the relay hop is addressed by the connection.
        let outer = Message::outbound(
            MessageType::RelayForward {
                to: message.to.clone(),
                from: self.local_node_id.clone(),
                sequence: relay_sequence,
                opaque_payload_b64: encode_relay_opaque_payload(
                    message.clone().into_frame(&self.local_node_id, &message.to),
                ),
            },
            None,
            message.realm.clone(),
        );
        self.peer_manager
            .send_to_node_id(relay_node_id, outer)
            .await
            .map_err(|_| DeliveryOutcome::DeliveryFailed {
                reason: DeliveryFailureReason::PathLostDuringDelivery,
            })
    }

    async fn dispatch_via_hole_punch(
        &self,
        relay_node_id: &str,
        message: &Message,
        timeout: Duration,
    ) -> Result<(), DeliveryOutcome> {
        let attempt_id = MessageId::generate().as_str().to_string();
        // Only a PUNCH_GO from this rendezvous for this attempt is followed
        // (ADR-0015).
        let agreed = self
            .peer_manager
            .expect_punch(
                &attempt_id,
                crate::network::peer_manager::ExpectedPunch {
                    rendezvous_node_id: relay_node_id.to_string(),
                    initiator_node_id: self.local_node_id.clone(),
                    responder_node_id: message.to.clone(),
                    expires_at: Instant::now() + timeout,
                },
            )
            .await;
        if !agreed {
            return Err(DeliveryOutcome::DeliveryFailed {
                reason: DeliveryFailureReason::NoRoute,
            });
        }
        let coordinate = Message::outbound(
            MessageType::PunchCoordinate {
                attempt_id: attempt_id.clone(),
                target: message.to.clone(),
                timeout_ms: Some(timeout.as_millis() as u64),
            },
            None,
            message.realm.clone(),
        );
        self.peer_manager
            .send_to_node_id(relay_node_id, coordinate)
            .await
            .map_err(|_| DeliveryOutcome::DeliveryFailed {
                reason: DeliveryFailureReason::PathLostDuringDelivery,
            })?;

        let deadline = Instant::now() + timeout;
        loop {
            if self
                .peer_manager
                .udp_session_id_for(&message.to)
                .await
                .is_some()
            {
                return self
                    .peer_manager
                    .send_udp_message_to_node(&message.to, message.clone())
                    .await
                    .map_err(|_| DeliveryOutcome::DeliveryFailed {
                        reason: DeliveryFailureReason::PathLostDuringDelivery,
                    });
            }
            if Instant::now() >= deadline {
                return Err(DeliveryOutcome::DeliveryFailed {
                    reason: DeliveryFailureReason::NoRoute,
                });
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

#[derive(Debug, Clone)]
pub enum IncomingMessageDisposition {
    Consumed,
    Dispatch(Vec<Message>),
}

/// Application messages: the types plugins act on, and the only types a relay
/// tunnel may carry to this node. Control-plane messages (HELLO, peer lists,
/// relay and punch signalling, heartbeats, nested tunnels) are accepted only
/// from the peer that sends them, never through a relay.
fn is_application_message(msg_type: &MessageType) -> bool {
    matches!(
        msg_type,
        MessageType::Text(_)
            | MessageType::DataRequest
            | MessageType::DataResponse
            | MessageType::Extension { .. }
            | MessageType::DeliveryAck { .. }
    )
}

/// Attribute a received frame to the peer that delivered it (ADR-0012).
///
/// Every frame names the two ends of the connection or session that carried
/// it: `from` must be `delivered_by.peer` and `to` must be this node. A
/// `RELAY_FWD` addressed to this node is unwrapped when its payload is a
/// message: the inner message keeps the origin it claims, is marked with
/// `relayed_from`, and must be an application message whose `from` and `to`
/// match the tunnel. A tunnel with an opaque payload is delivered as the
/// `RELAY_FWD` itself. Returns a rejection reason for frames that break
/// these rules.
pub fn attribute_incoming_message(
    mut message: Message,
    delivered_by: MessageOrigin,
    local_node_id: &str,
) -> Result<Message, &'static str> {
    if message.from != delivered_by.peer {
        return Err("sender-mismatch");
    }
    if message.to != local_node_id {
        return Err("destination-mismatch");
    }
    if let MessageType::RelayForward {
        to,
        from,
        opaque_payload_b64,
        ..
    } = &message.msg_type
    {
        if to == local_node_id {
            let origin = MessageOrigin {
                relayed_from: Some(from.clone()),
                ..delivered_by
            };
            let inner = decode_relay_opaque_payload_utf8(opaque_payload_b64)
                .and_then(|inner| Message::from_json(&inner));
            let Some(mut inner) = inner else {
                message.set_origin(origin);
                return Ok(message);
            };
            if !is_application_message(&inner.msg_type) {
                return Err("tunnel-message-type-not-allowed");
            }
            if Some(&inner.from) != origin.relayed_from.as_ref() {
                return Err("tunnel-origin-mismatch");
            }
            if inner.to != local_node_id {
                return Err("tunnel-destination-mismatch");
            }
            inner.set_origin(origin);
            return Ok(inner);
        }
    }
    message.set_origin(delivered_by);
    Ok(message)
}

pub async fn process_incoming_message(
    peer_manager: &PeerManager,
    local_node_id: &str,
    // The node bound to the connection or session this frame arrived on (TCP:
    // `PeerManager::origin_for_addr`; UDP: the Noise session's node). The
    // frame's own `from` must name the same node.
    delivered_by: MessageOrigin,
    message: Message,
) -> IncomingMessageDisposition {
    let delivering_peer = delivered_by.peer.clone();
    let message = match attribute_incoming_message(message, delivered_by, local_node_id) {
        Ok(message) => message,
        Err(reason) => {
            emit_network_event(
                "delivery",
                LogLevel::Warn,
                "message_rejected",
                None,
                Some(format!("peer={delivering_peer} reason={reason}")),
                false,
            );
            return IncomingMessageDisposition::Consumed;
        }
    };
    let Some(origin) = message.origin().cloned() else {
        return IncomingMessageDisposition::Consumed;
    };

    // Only credit liveness/health for the connection that actually delivered the
    // message. Trusting a relayed origin would let any connected peer (or a
    // multi-hop relayed message) keep another peer's liveness deadline refreshed
    // indefinitely, masking a real disconnect and defeating the ADR-0007
    // liveness monitor.
    let sender_verified = origin.relayed_from.is_none();
    if sender_verified {
        peer_manager
            .record_peer_activity_on_preferred_route(&message.from)
            .await;
    }

    if matches!(message.msg_type, MessageType::Heartbeat) {
        match &message.payload {
            Some(Payload::Text(kind)) if kind == "liveness_probe_v1" => {
                if sender_verified {
                    let response = Message::outbound(
                        MessageType::Heartbeat,
                        Some(Payload::Text("liveness_response_v1".to_string())),
                        message.realm.clone(),
                    );
                    if peer_manager.has_node_id(&message.from).await {
                        let _ = peer_manager.send_to_node_id(&message.from, response).await;
                    } else if peer_manager
                        .udp_session_id_for(&message.from)
                        .await
                        .is_some()
                    {
                        let _ = peer_manager
                            .send_udp_message_to_node(&message.from, response)
                            .await;
                    }
                }
                return IncomingMessageDisposition::Consumed;
            }
            Some(Payload::Text(kind)) if kind == "liveness_response_v1" => {
                return IncomingMessageDisposition::Consumed;
            }
            _ => {}
        }
    }

    if let MessageType::DeliveryAck { message_id, .. } = &message.msg_type {
        // `from` is the delivering peer, or for a tunnel the origin the relay
        // accepted from its own peer.
        let message_id = MessageId::from(message_id.clone());
        if let Err(reason @ "not-destination") = peer_manager
            .acknowledge_delivery(&message_id, &message.from)
            .await
        {
            emit_network_event(
                "delivery",
                LogLevel::Warn,
                "delivery_ack_rejected",
                None,
                Some(format!(
                    "peer={} acked_by={} message_id={} reason={reason}",
                    origin.peer,
                    message.from,
                    message_id.as_str()
                )),
                false,
            );
        }
        return IncomingMessageDisposition::Consumed;
    }

    let Some(delivery) = message.delivery.clone() else {
        return IncomingMessageDisposition::Dispatch(vec![message]);
    };

    if matches!(delivery.class, DeliveryClass::FireAndForget) {
        return IncomingMessageDisposition::Dispatch(vec![message]);
    }

    let dedup_window = Duration::from_secs(peer_manager.delivery_dedup_window_secs());
    peer_manager.prune_delivery_dedup(dedup_window).await;
    peer_manager.prune_ordered_inbound(dedup_window).await;

    if peer_manager
        .delivery_seen(&message.from, &delivery.message_id)
        .await
    {
        let _ = send_framework_ack(peer_manager, local_node_id, &message, "duplicate").await;
        return IncomingMessageDisposition::Consumed;
    }

    // A message is acknowledged only once this node has taken it: an ordered
    // message that cannot be buffered is left for its sender to retry.
    let ordered_ready = match delivery.class {
        DeliveryClass::OrderedReliable => {
            let Some(ordering_key) = delivery.ordering_key.clone() else {
                return IncomingMessageDisposition::Consumed;
            };
            let Some(ordering_sequence) = delivery.ordering_sequence else {
                return IncomingMessageDisposition::Consumed;
            };
            match peer_manager
                .accept_ordered_incoming(
                    &message.from,
                    &message.to,
                    &ordering_key,
                    ordering_sequence,
                    message.clone(),
                    peer_manager.delivery_ordered_buffer_limit(),
                )
                .await
            {
                Ok(ready) => Some(ready),
                Err(reason) => {
                    emit_network_event(
                        "delivery",
                        LogLevel::Warn,
                        "ordered_delivery_deferred",
                        None,
                        Some(format!(
                            "origin={} ordering_key={} sequence={} reason={reason}",
                            message.from, ordering_key, ordering_sequence
                        )),
                        false,
                    );
                    return IncomingMessageDisposition::Consumed;
                }
            }
        }
        DeliveryClass::Reliable | DeliveryClass::FireAndForget => None,
    };

    peer_manager
        .record_delivery_receipt(&message.from, &delivery.message_id)
        .await;
    let _ = send_framework_ack(peer_manager, local_node_id, &message, "ok").await;
    match ordered_ready {
        Some(ready) if ready.is_empty() => IncomingMessageDisposition::Consumed,
        Some(ready) => IncomingMessageDisposition::Dispatch(ready),
        None => IncomingMessageDisposition::Dispatch(vec![message]),
    }
}

async fn send_framework_ack(
    peer_manager: &PeerManager,
    local_node_id: &str,
    original_message: &Message,
    status: &str,
) -> Result<(), String> {
    let delivery = match original_message.delivery.as_ref() {
        Some(delivery) => delivery,
        None => return Ok(()),
    };

    let ack = Message::new(
        local_node_id,
        &original_message.from,
        MessageType::DeliveryAck {
            message_id: delivery.message_id.as_str().to_string(),
            status: Some(status.to_string()),
        },
        None,
        original_message.realm.clone(),
    );

    // Answer along the path the message took: a tunneled message through the
    // relay that delivered it, a direct one to the peer itself. A sender this
    // node cannot reach that way gets no acknowledgement.
    if let Some(relay_node_id) = original_message
        .origin()
        .filter(|origin| origin.relayed_from.is_some())
        .map(|origin| origin.peer.clone())
    {
        let bind = Message::outbound(
            MessageType::RelayBind {
                target: original_message.from.clone(),
                want_store_forward: Some(false),
                qos: Some("low_latency".to_string()),
                nonce: Some(now_secs()),
                expires_at: None,
            },
            None,
            original_message.realm.clone(),
        );
        peer_manager.send_to_node_id(&relay_node_id, bind).await?;

        let outer = Message::outbound(
            MessageType::RelayForward {
                to: original_message.from.clone(),
                from: local_node_id.to_string(),
                sequence: Some(
                    peer_manager
                        .next_relay_sequence(local_node_id, &original_message.from)
                        .await,
                ),
                opaque_payload_b64: encode_relay_opaque_payload(ack.as_json()),
            },
            None,
            original_message.realm.clone(),
        );
        return peer_manager.send_to_node_id(&relay_node_id, outer).await;
    }

    if peer_manager.has_node_id(&original_message.from).await {
        return peer_manager
            .send_to_node_id(&original_message.from, ack)
            .await;
    }

    if peer_manager
        .udp_session_id_for(&original_message.from)
        .await
        .is_some()
    {
        return peer_manager
            .send_udp_message_to_node(&original_message.from, ack)
            .await;
    }

    Err("no route available for framework delivery ack".to_string())
}

async fn prepare_message_for_delivery(
    peer_manager: &PeerManager,
    mut message: Message,
    options: &DeliveryOptions,
) -> Message {
    let mut delivery = DeliveryMetadata::new(options.class);
    delivery.ordering_key = options.ordering_key.clone();
    if let Some(existing) = message.delivery.clone() {
        delivery.message_id = existing.message_id;
    }
    if matches!(options.class, DeliveryClass::OrderedReliable) {
        if let Some(ordering_key) = delivery.ordering_key.clone() {
            let sequence = peer_manager
                .next_ordering_sequence(&message.from, &message.to, &ordering_key)
                .await;
            delivery.ordering_sequence = Some(sequence);
        }
    }
    delivery
        .validate()
        .unwrap_or_else(|err| panic!("invalid delivery metadata: {err}"));
    message.delivery = Some(delivery);
    message
}

fn delivery_config(config: &Config) -> DeliveryConfig {
    config
        .network
        .as_ref()
        .and_then(|network| network.delivery.clone())
        .unwrap_or_default()
}

fn resolved_timeout(config: &DeliveryConfig, options: &DeliveryOptions) -> Duration {
    if let Some(timeout) = options.timeout {
        return timeout;
    }

    match options.class {
        DeliveryClass::FireAndForget => {
            Duration::from_millis(config.fire_and_forget_timeout_ms.unwrap_or(1000))
        }
        DeliveryClass::Reliable => {
            Duration::from_millis(config.reliable_timeout_ms.unwrap_or(5000))
        }
        DeliveryClass::OrderedReliable => {
            Duration::from_millis(config.ordered_reliable_timeout_ms.unwrap_or(10000))
        }
    }
}

fn resolved_retry_budget(config: &DeliveryConfig, options: &DeliveryOptions) -> u32 {
    if let Some(retry_budget) = options.retry_budget {
        return retry_budget;
    }

    match options.class {
        DeliveryClass::FireAndForget => 0,
        DeliveryClass::Reliable => config.reliable_retry_budget.unwrap_or(3),
        DeliveryClass::OrderedReliable => config.ordered_reliable_retry_budget.unwrap_or(3),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

enum DeliveryRoute {
    Connected,
    DirectTcp {
        addr: SocketAddr,
    },
    Udp,
    Relay {
        relay_node_id: String,
    },
    Punch {
        relay_node_id: String,
        timeout: Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::{
        attribute_incoming_message, process_incoming_message, DeliveryClass, DeliveryOptions,
        DeliveryOutcome, DeliveryPathConstraints, DeliveryRuntime, DeliveryTransportPreference,
        IncomingMessageDisposition, MessageId,
    };
    use crate::config::{Config, DeliveryConfig};
    use crate::network::message::{
        decode_relay_opaque_payload_utf8, encode_relay_opaque_payload, DeliveryMetadata, Message,
        MessageOrigin, MessageType,
    };
    use crate::network::peer_manager::PeerManager;
    use crate::plugin_host::manager::PluginManager;
    use std::sync::Arc;

    fn direct(peer: &str) -> MessageOrigin {
        MessageOrigin::direct(peer, None)
    }

    fn tunnel(relay_from: &str, inner: &Message) -> Message {
        Message::new(
            "relay-1",
            "node-b",
            MessageType::RelayForward {
                to: "node-b".into(),
                from: relay_from.into(),
                sequence: None,
                opaque_payload_b64: encode_relay_opaque_payload(inner.as_json()),
            },
            None,
            None,
        )
    }

    #[test]
    fn direct_message_must_name_both_ends_of_the_connection() {
        let text = |from: &str, to: &str| {
            Message::new(from, to, MessageType::Text("x".into()), None, None)
        };
        let delivered_by = MessageOrigin::direct("node-a", Some("ab".repeat(32)));
        let message =
            attribute_incoming_message(text("node-a", "node-b"), delivered_by.clone(), "node-b")
                .unwrap();
        assert_eq!(message.origin(), Some(&delivered_by));
        assert_eq!(
            message.origin().unwrap().authenticated_sender(),
            Some("node-a")
        );
        // Without a bound transport identity nobody is authenticated.
        let unbound = attribute_incoming_message(message, direct("node-a"), "node-b").unwrap();
        assert_eq!(unbound.origin().unwrap().authenticated_sender(), None);

        for (frame, reason) in [
            (text("admin", "node-b"), "sender-mismatch"),
            (text("node-a", "node-c"), "destination-mismatch"),
            (text("node-a", ""), "destination-mismatch"),
        ] {
            assert_eq!(
                attribute_incoming_message(frame, delivered_by.clone(), "node-b").unwrap_err(),
                reason
            );
        }
    }

    #[test]
    fn tunnel_delivers_application_messages_marked_as_relayed() {
        let inner = Message::new("ceo", "node-b", MessageType::Text("hi".into()), None, None);
        let message = attribute_incoming_message(
            tunnel("ceo", &inner),
            MessageOrigin::direct("relay-1", Some("cd".repeat(32))),
            "node-b",
        )
        .unwrap();
        assert!(matches!(message.msg_type, MessageType::Text(ref text) if text == "hi"));
        assert_eq!(message.from, "ceo");
        let origin = message.origin().unwrap();
        assert_eq!(origin.peer, "relay-1");
        assert_eq!(origin.relayed_from.as_deref(), Some("ceo"));
        assert_eq!(origin.authenticated_sender(), None);
    }

    #[test]
    fn tunnel_rejects_control_messages_nesting_and_mismatches() {
        let peer_list = Message::new(
            "ceo",
            "node-b",
            MessageType::PeerList {
                peers: vec!["10.0.0.5:22".into()],
            },
            None,
            None,
        );
        let mut nested = tunnel(
            "ceo",
            &Message::new("ceo", "node-b", MessageType::Text("x".into()), None, None),
        );
        nested.from = "ceo".into();
        for (frame, reason) in [
            (tunnel("ceo", &peer_list), "tunnel-message-type-not-allowed"),
            (tunnel("ceo", &nested), "tunnel-message-type-not-allowed"),
            (
                tunnel(
                    "someone-else",
                    &Message::new("ceo", "node-b", MessageType::Text("x".into()), None, None),
                ),
                "tunnel-origin-mismatch",
            ),
            (
                tunnel(
                    "ceo",
                    &Message::new("ceo", "node-c", MessageType::Text("x".into()), None, None),
                ),
                "tunnel-destination-mismatch",
            ),
        ] {
            assert_eq!(
                attribute_incoming_message(frame, direct("relay-1"), "node-b").unwrap_err(),
                reason
            );
        }
    }

    #[test]
    fn tunnel_with_opaque_payload_is_delivered_as_relay_frame() {
        let mut frame = tunnel(
            "ceo",
            &Message::new("ceo", "node-b", MessageType::Text("x".into()), None, None),
        );
        if let MessageType::RelayForward {
            opaque_payload_b64, ..
        } = &mut frame.msg_type
        {
            *opaque_payload_b64 = encode_relay_opaque_payload(b"raw bytes");
        }
        let message = attribute_incoming_message(frame, direct("relay-1"), "node-b").unwrap();
        assert!(matches!(message.msg_type, MessageType::RelayForward { .. }));
        assert_eq!(message.from, "relay-1");
        assert_eq!(
            message.origin().unwrap().relayed_from.as_deref(),
            Some("ceo")
        );
    }

    #[test]
    fn ordered_reliable_validation_requires_ordering_key() {
        let options = DeliveryOptions::new(DeliveryClass::OrderedReliable);

        assert!(options.validate().is_err());
    }

    #[test]
    fn reliable_validation_rejects_ordering_key() {
        let options = DeliveryOptions::new(DeliveryClass::Reliable).with_ordering_key("lane-a");

        assert!(options.validate().is_err());
    }

    #[test]
    fn generated_message_ids_use_uuid_v7_strings() {
        let message_id = MessageId::generate();

        let parsed = uuid::Uuid::parse_str(message_id.as_str()).expect("valid uuid");
        assert_eq!(parsed.get_version_num(), 7);
    }

    #[tokio::test]
    async fn incoming_reliable_duplicate_is_consumed_after_first_delivery() {
        let peer_manager = PeerManager::new();
        let message = Message::new("node-a", "node-b", MessageType::Heartbeat, None, None)
            .with_delivery(DeliveryMetadata::new(DeliveryClass::Reliable))
            .expect("valid delivery metadata");

        let first =
            process_incoming_message(&peer_manager, "node-b", direct("node-a"), message.clone())
                .await;
        let second =
            process_incoming_message(&peer_manager, "node-b", direct("node-a"), message).await;

        assert!(matches!(first, IncomingMessageDisposition::Dispatch(_)));
        assert!(matches!(second, IncomingMessageDisposition::Consumed));
    }

    #[tokio::test]
    async fn ordered_messages_release_when_gap_is_filled() {
        let peer_manager = PeerManager::new();
        let second = Message::new("node-a", "node-b", MessageType::Heartbeat, None, None)
            .with_delivery(
                DeliveryMetadata::new(DeliveryClass::OrderedReliable)
                    .with_ordering_key("lane-a")
                    .with_ordering_sequence(2),
            )
            .expect("valid ordered metadata");
        let first = Message::new(
            "node-a",
            "node-b",
            MessageType::Text("ok".into()),
            None,
            None,
        )
        .with_delivery(
            DeliveryMetadata::new(DeliveryClass::OrderedReliable)
                .with_ordering_key("lane-a")
                .with_ordering_sequence(1),
        )
        .expect("valid ordered metadata");

        let buffered =
            process_incoming_message(&peer_manager, "node-b", direct("node-a"), second).await;
        let released =
            process_incoming_message(&peer_manager, "node-b", direct("node-a"), first).await;

        assert!(matches!(buffered, IncomingMessageDisposition::Consumed));
        match released {
            IncomingMessageDisposition::Dispatch(messages) => assert_eq!(messages.len(), 2),
            IncomingMessageDisposition::Consumed => panic!("expected ordered release"),
        }
    }

    #[tokio::test]
    async fn reliable_delivery_to_connected_peer_acknowledges() {
        let peer_manager = PeerManager::new();
        let plugin_manager = Arc::new(PluginManager::new());
        let runtime = DeliveryRuntime::new(
            peer_manager.clone(),
            plugin_manager,
            Config::default(),
            "node-a".to_string(),
            None,
            false,
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(4);
        let addr: std::net::SocketAddr = "127.0.0.1:9001".parse().unwrap();
        peer_manager
            .add_peer(addr, tx, "node-b".to_string())
            .await
            .expect("peer should register");

        let pm_for_ack = peer_manager.clone();
        tokio::spawn(async move {
            if let Some(outbound) = rx.recv().await {
                let message_id = outbound
                    .delivery
                    .as_ref()
                    .map(|delivery| delivery.message_id.clone())
                    .expect("delivery metadata present");
                pm_for_ack
                    .set_delivery_outcome(&message_id, DeliveryOutcome::AcknowledgedByPeer)
                    .await;
            }
        });

        let outcome = runtime
            .deliver_message(
                Message::new(
                    "node-a",
                    "node-b",
                    MessageType::Text("hi".into()),
                    None,
                    None,
                ),
                DeliveryOptions::new(DeliveryClass::Reliable),
            )
            .await;

        assert_eq!(outcome, DeliveryOutcome::AcknowledgedByPeer);
    }

    #[tokio::test]
    async fn delivery_ack_counts_only_from_the_destination() {
        let peer_manager = PeerManager::new();
        let runtime = DeliveryRuntime::new(
            peer_manager.clone(),
            Arc::new(PluginManager::new()),
            Config::default(),
            "node-a".to_string(),
            None,
            false,
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(4);
        let addr: std::net::SocketAddr = "127.0.0.1:9002".parse().unwrap();
        peer_manager
            .add_peer(addr, tx, "node-b".to_string())
            .await
            .expect("peer should register");

        let pm_for_ack = peer_manager.clone();
        let acks = tokio::spawn(async move {
            let outbound = rx.recv().await.expect("message sent to node-b");
            let message_id = outbound.delivery.as_ref().unwrap().message_id.clone();
            let ack = |from: &str| {
                Message::new(
                    from,
                    "node-a",
                    MessageType::DeliveryAck {
                        message_id: message_id.as_str().to_string(),
                        status: Some("ok".into()),
                    },
                    None,
                    None,
                )
            };
            process_incoming_message(&pm_for_ack, "node-a", direct("node-c"), ack("node-c")).await;
            let after_foreign_ack = pm_for_ack.delivery_outcome(&message_id).await;
            process_incoming_message(&pm_for_ack, "node-a", direct("node-b"), ack("node-b")).await;
            (outbound.from, after_foreign_ack)
        });

        let outcome = runtime
            .deliver_message(
                Message::new(
                    "someone-else",
                    "node-b",
                    MessageType::Text("hi".into()),
                    None,
                    None,
                ),
                DeliveryOptions::new(DeliveryClass::Reliable),
            )
            .await;

        let (sent_from, after_foreign_ack) = acks.await.unwrap();
        // The runtime sends as this node, whatever `from` the caller wrote.
        assert_eq!(sent_from, "node-a");
        assert_ne!(after_foreign_ack, Some(DeliveryOutcome::AcknowledgedByPeer));
        assert_eq!(outcome, DeliveryOutcome::AcknowledgedByPeer);
    }

    #[tokio::test]
    async fn tunneled_message_is_acknowledged_through_the_delivering_relay() {
        let peer_manager = PeerManager::new();
        let (delivering_tx, mut delivering_rx) = tokio::sync::mpsc::channel::<Message>(4);
        let (other_tx, mut other_rx) = tokio::sync::mpsc::channel::<Message>(4);
        peer_manager
            .add_peer(
                "127.0.0.1:9020".parse().unwrap(),
                delivering_tx,
                "relay-2".to_string(),
            )
            .await
            .unwrap();
        peer_manager
            .add_peer(
                "127.0.0.1:9021".parse().unwrap(),
                other_tx,
                "relay-1".to_string(),
            )
            .await
            .unwrap();
        // The first relay this node knows is not the one that delivered.
        peer_manager
            .set_peer_capabilities("relay-1", Some(vec!["relay".to_string()]))
            .await;

        let inner = Message::new(
            "node-a",
            "node-b",
            MessageType::Text("hi".into()),
            None,
            None,
        )
        .with_delivery(DeliveryMetadata::new(DeliveryClass::Reliable))
        .unwrap();
        let frame = Message::new(
            "relay-2",
            "node-b",
            MessageType::RelayForward {
                to: "node-b".into(),
                from: "node-a".into(),
                sequence: None,
                opaque_payload_b64: encode_relay_opaque_payload(inner.as_json()),
            },
            None,
            None,
        );
        let disposition =
            process_incoming_message(&peer_manager, "node-b", direct("relay-2"), frame).await;
        assert!(matches!(
            disposition,
            IncomingMessageDisposition::Dispatch(ref messages) if messages.len() == 1
        ));

        let bind = delivering_rx
            .try_recv()
            .expect("bind sent to the delivering relay");
        assert!(matches!(
            bind.msg_type,
            MessageType::RelayBind { ref target, .. } if target == "node-a"
        ));
        let forward = delivering_rx
            .try_recv()
            .expect("ack tunneled through the delivering relay");
        assert!(matches!(
            forward.msg_type,
            MessageType::RelayForward { ref to, .. } if to == "node-a"
        ));
        assert!(other_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn ordered_message_that_cannot_be_buffered_is_not_acknowledged() {
        let peer_manager = PeerManager::new();
        peer_manager.set_delivery_config(Some(DeliveryConfig {
            ordered_max_buffered_messages: Some(1),
            ..DeliveryConfig::default()
        }));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(4);
        peer_manager
            .add_peer("127.0.0.1:9030".parse().unwrap(), tx, "node-a".to_string())
            .await
            .unwrap();
        let ordered = |sequence| {
            Message::new(
                "node-a",
                "node-b",
                MessageType::Text("x".into()),
                None,
                None,
            )
            .with_delivery(
                DeliveryMetadata::new(DeliveryClass::OrderedReliable)
                    .with_ordering_key("lane")
                    .with_ordering_sequence(sequence),
            )
            .unwrap()
        };
        // Sequence 2 waits for 1 and is acknowledged; 3 does not fit.
        for sequence in [2, 3] {
            let disposition = process_incoming_message(
                &peer_manager,
                "node-b",
                direct("node-a"),
                ordered(sequence),
            )
            .await;
            assert!(matches!(disposition, IncomingMessageDisposition::Consumed));
        }
        let acks: Vec<Message> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(acks.len(), 1);
        assert!(matches!(acks[0].msg_type, MessageType::DeliveryAck { .. }));
    }

    #[tokio::test]
    async fn reliable_delivery_via_relay_acknowledges() {
        let peer_manager = PeerManager::new();
        let plugin_manager = Arc::new(PluginManager::new());
        let runtime = DeliveryRuntime::new(
            peer_manager.clone(),
            plugin_manager,
            Config::default(),
            "node-a".to_string(),
            None,
            false,
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(8);
        let addr: std::net::SocketAddr = "127.0.0.1:9010".parse().unwrap();
        peer_manager
            .add_peer(addr, tx, "relay-1".to_string())
            .await
            .expect("relay should register");
        peer_manager
            .set_peer_capabilities("relay-1", Some(vec!["relay".to_string()]))
            .await;

        let pm_for_ack = peer_manager.clone();
        tokio::spawn(async move {
            while let Some(outbound) = rx.recv().await {
                if let MessageType::RelayForward {
                    opaque_payload_b64, ..
                } = &outbound.msg_type
                {
                    let inner = decode_relay_opaque_payload_utf8(opaque_payload_b64)
                        .expect("relay payload should decode to inner message");
                    let inner = Message::from_json(&inner).expect("valid inner message");
                    let message_id = inner
                        .delivery
                        .as_ref()
                        .map(|delivery| delivery.message_id.clone())
                        .expect("delivery metadata present");
                    pm_for_ack
                        .set_delivery_outcome(&message_id, DeliveryOutcome::AcknowledgedByPeer)
                        .await;
                    break;
                }
            }
        });

        let outcome = runtime
            .deliver_message(
                Message::new(
                    "node-a",
                    "node-b",
                    MessageType::Text("relay".into()),
                    None,
                    None,
                ),
                DeliveryOptions::new(DeliveryClass::Reliable),
            )
            .await;

        assert_eq!(outcome, DeliveryOutcome::AcknowledgedByPeer);
    }

    #[tokio::test]
    async fn preferred_udp_requires_bidirectional_session() {
        const TARGET_NODE_ID: &str = "node-b";
        const ADVERTISED_UDP_ADDR: &str = "127.0.0.1:9011";

        let peer_manager = PeerManager::new();
        peer_manager
            .add_udp_listen_addr(TARGET_NODE_ID, ADVERTISED_UDP_ADDR)
            .await;

        let runtime = DeliveryRuntime::new(
            peer_manager,
            Arc::new(PluginManager::new()),
            Config::default(),
            "node-a".to_string(),
            None,
            false,
        );

        let outcome = runtime
            .select_route(
                TARGET_NODE_ID,
                &DeliveryOptions::new(DeliveryClass::Reliable).with_path_constraints(
                    DeliveryPathConstraints {
                        preferred_transport: Some(DeliveryTransportPreference::Udp),
                        require_bidirectional: true,
                    },
                ),
            )
            .await;

        assert!(matches!(outcome, Err(DeliveryOutcome::UnsupportedOnPath)));
    }

    #[tokio::test]
    async fn ordered_buffer_limit_from_config_is_applied() {
        let peer_manager = PeerManager::new();
        peer_manager.set_delivery_config(Some(DeliveryConfig {
            ordered_max_buffered_messages: Some(1),
            ..DeliveryConfig::default()
        }));

        let third = Message::new("node-a", "node-b", MessageType::Heartbeat, None, None)
            .with_delivery(
                DeliveryMetadata::new(DeliveryClass::OrderedReliable)
                    .with_ordering_key("lane-a")
                    .with_ordering_sequence(3),
            )
            .expect("valid ordered metadata");
        let second = Message::new("node-a", "node-b", MessageType::Heartbeat, None, None)
            .with_delivery(
                DeliveryMetadata::new(DeliveryClass::OrderedReliable)
                    .with_ordering_key("lane-a")
                    .with_ordering_sequence(2),
            )
            .expect("valid ordered metadata");
        let first = Message::new("node-a", "node-b", MessageType::Heartbeat, None, None)
            .with_delivery(
                DeliveryMetadata::new(DeliveryClass::OrderedReliable)
                    .with_ordering_key("lane-a")
                    .with_ordering_sequence(1),
            )
            .expect("valid ordered metadata");

        let _ = process_incoming_message(&peer_manager, "node-b", direct("node-a"), third).await;
        let _ = process_incoming_message(&peer_manager, "node-b", direct("node-a"), second).await;
        let released =
            process_incoming_message(&peer_manager, "node-b", direct("node-a"), first).await;

        match released {
            IncomingMessageDisposition::Dispatch(messages) => assert_eq!(messages.len(), 1),
            IncomingMessageDisposition::Consumed => panic!("expected buffered ordered release"),
        }
    }

    /// The relay used to be the first peer that announced `relay`; with
    /// `[network.relay] allowed_relays` set, only the peers it names are used.
    #[tokio::test]
    async fn only_allowed_relays_carry_messages() {
        let peer_manager = PeerManager::new();
        let mut receivers = Vec::new();
        for (port, node_id) in [(9030, "relay-a"), (9031, "relay-b")] {
            let (tx, rx) = tokio::sync::mpsc::channel::<Message>(1);
            receivers.push(rx);
            let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            peer_manager
                .add_peer(addr, tx, node_id.to_string())
                .await
                .unwrap();
            peer_manager
                .set_peer_capabilities(node_id, Some(vec!["relay".to_string()]))
                .await;
        }
        let relay_for = |allowed: Option<Vec<String>>| {
            let mut config = Config::default();
            config.network.as_mut().unwrap().relay = Some(crate::config::RelayConfig {
                allowed_relays: allowed,
                ..Default::default()
            });
            let runtime = DeliveryRuntime::new(
                peer_manager.clone(),
                Arc::new(PluginManager::new()),
                config,
                "node-a".to_string(),
                None,
                false,
            );
            async move { runtime.relay_node_id().await }
        };

        assert!(relay_for(None).await.is_some());
        assert_eq!(
            relay_for(Some(vec!["relay-b".into()])).await.as_deref(),
            Some("relay-b")
        );
        assert_eq!(relay_for(Some(vec!["relay-c".into()])).await, None);
        assert_eq!(relay_for(Some(Vec::new())).await, None);
    }
}

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{Config, DeliveryConfig};
use crate::network::message::{DeliveryMetadata, Message, MessageType, Payload};
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

        Ok(())
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
        message: Message,
        options: DeliveryOptions,
    ) -> DeliveryOutcome {
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
            .record_delivery_attempt(&delivery.message_id, delivery.class, deadline)
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
        match self.select_route(&message.to, options).await? {
            DeliveryRoute::Connected => self
                .peer_manager
                .send_to_node_id(&message.to, message.as_json())
                .await
                .map_err(|_| DeliveryOutcome::DeliveryFailed {
                    reason: DeliveryFailureReason::PathLostDuringDelivery,
                }),
            DeliveryRoute::DirectTcp { addr } => {
                self.ensure_direct_connection(&message.to, addr).await?;
                self.peer_manager
                    .send_to_node_id(&message.to, message.as_json())
                    .await
                    .map_err(|_| DeliveryOutcome::DeliveryFailed {
                        reason: DeliveryFailureReason::PathLostDuringDelivery,
                    })
            }
            DeliveryRoute::Udp => {
                self.ensure_udp_session(&message.to).await?;
                self.peer_manager
                    .send_udp_message_to_node(&message.to, message.as_json().as_bytes())
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
        }
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

        if self.peer_manager.has_node_id(target_node_id).await {
            return Ok(DeliveryRoute::Connected);
        }

        if matches!(preferred_transport, Some(DeliveryTransportPreference::Tcp)) {
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
            if self
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

        let bind = Message::new(
            &message.from,
            relay_node_id,
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
            .send_to_node_id(relay_node_id, bind.as_json())
            .await
            .map_err(|_| DeliveryOutcome::DeliveryFailed {
                reason: DeliveryFailureReason::PathLostDuringDelivery,
            })?;

        let outer = Message::new(
            &message.from,
            relay_node_id,
            MessageType::RelayForward {
                to: message.to.clone(),
                from: message.from.clone(),
                sequence: relay_sequence,
            },
            Some(Payload::Text(message.as_json())),
            message.realm.clone(),
        );
        self.peer_manager
            .send_to_node_id(relay_node_id, outer.as_json())
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
        let coordinate = Message::new(
            &self.local_node_id,
            relay_node_id,
            MessageType::PunchCoordinate {
                attempt_id: attempt_id.clone(),
                target: message.to.clone(),
                timeout_ms: Some(timeout.as_millis() as u64),
            },
            None,
            message.realm.clone(),
        );
        self.peer_manager
            .send_to_node_id(relay_node_id, coordinate.as_json())
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
                    .send_udp_message_to_node(&message.to, message.as_json().as_bytes())
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

pub fn unwrap_tunneled_message(message: &Message, local_node_id: &str) -> Option<Message> {
    if let MessageType::RelayForward { to, .. } = &message.msg_type {
        if to == local_node_id {
            if let Some(Payload::Text(inner)) = &message.payload {
                return Message::from_json(inner);
            }
        }
    }
    None
}

pub async fn process_incoming_message(
    peer_manager: &PeerManager,
    local_node_id: &str,
    message: Message,
) -> IncomingMessageDisposition {
    if let MessageType::DeliveryAck { message_id, .. } = &message.msg_type {
        let message_id = MessageId::from(message_id.clone());
        peer_manager
            .set_delivery_outcome(&message_id, DeliveryOutcome::AcknowledgedByPeer)
            .await;
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

    let is_new = peer_manager
        .record_delivery_receipt(&message.from, &delivery.message_id)
        .await;
    let ack_status = if is_new { "ok" } else { "duplicate" };
    let _ = send_framework_ack(peer_manager, local_node_id, &message, ack_status).await;

    if !is_new {
        return IncomingMessageDisposition::Consumed;
    }

    match delivery.class {
        DeliveryClass::Reliable => IncomingMessageDisposition::Dispatch(vec![message]),
        DeliveryClass::OrderedReliable => {
            let Some(ordering_key) = delivery.ordering_key.clone() else {
                return IncomingMessageDisposition::Consumed;
            };
            let Some(ordering_sequence) = delivery.ordering_sequence else {
                return IncomingMessageDisposition::Consumed;
            };
            let origin_node_id = message.from.clone();
            let destination_node_id = message.to.clone();

            let ready = peer_manager
                .accept_ordered_incoming(
                    &origin_node_id,
                    &destination_node_id,
                    &ordering_key,
                    ordering_sequence,
                    message,
                    peer_manager.delivery_ordered_buffer_limit(),
                )
                .await;
            if ready.is_empty() {
                IncomingMessageDisposition::Consumed
            } else {
                IncomingMessageDisposition::Dispatch(ready)
            }
        }
        DeliveryClass::FireAndForget => IncomingMessageDisposition::Dispatch(vec![message]),
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

    if peer_manager.has_node_id(&original_message.from).await {
        return peer_manager
            .send_to_node_id(&original_message.from, ack.as_json())
            .await;
    }

    if peer_manager
        .udp_session_id_for(&original_message.from)
        .await
        .is_some()
    {
        return peer_manager
            .send_udp_message_to_node(&original_message.from, ack.as_json().as_bytes())
            .await;
    }

    let relay_node_id = {
        let node_ids = peer_manager.list_node_ids().await;
        let mut relay = None;
        for node_id in node_ids {
            if peer_manager.peer_has_capability(&node_id, "relay").await {
                relay = Some(node_id);
                break;
            }
        }
        relay
    };

    if let Some(relay_node_id) = relay_node_id {
        let bind = Message::new(
            local_node_id,
            &relay_node_id,
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
        peer_manager
            .send_to_node_id(&relay_node_id, bind.as_json())
            .await?;

        let outer = Message::new(
            local_node_id,
            &relay_node_id,
            MessageType::RelayForward {
                to: original_message.from.clone(),
                from: local_node_id.to_string(),
                sequence: Some(
                    peer_manager
                        .next_relay_sequence(local_node_id, &original_message.from)
                        .await,
                ),
            },
            Some(Payload::Text(ack.as_json())),
            original_message.realm.clone(),
        );
        return peer_manager
            .send_to_node_id(&relay_node_id, outer.as_json())
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
        process_incoming_message, DeliveryClass, DeliveryOptions, DeliveryOutcome,
        DeliveryPathConstraints, DeliveryRuntime, DeliveryTransportPreference,
        IncomingMessageDisposition, MessageId,
    };
    use crate::config::{Config, DeliveryConfig};
    use crate::network::message::{DeliveryMetadata, Message, MessageType};
    use crate::network::peer_manager::PeerManager;
    use crate::plugin_host::manager::PluginManager;
    use std::sync::Arc;

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

        let first = process_incoming_message(&peer_manager, "node-b", message.clone()).await;
        let second = process_incoming_message(&peer_manager, "node-b", message).await;

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

        let buffered = process_incoming_message(&peer_manager, "node-b", second).await;
        let released = process_incoming_message(&peer_manager, "node-b", first).await;

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
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(4);
        let addr: std::net::SocketAddr = "127.0.0.1:9001".parse().unwrap();
        peer_manager
            .add_peer(addr, tx, "node-b".to_string())
            .await
            .expect("peer should register");

        let pm_for_ack = peer_manager.clone();
        tokio::spawn(async move {
            if let Some(json) = rx.recv().await {
                let outbound = Message::from_json(&json).expect("valid message");
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
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
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
            while let Some(json) = rx.recv().await {
                let outbound = Message::from_json(&json).expect("valid relay frame");
                if let MessageType::RelayForward { .. } = outbound.msg_type {
                    let inner = outbound
                        .payload
                        .and_then(|payload| match payload {
                            crate::network::message::Payload::Text(text) => Some(text),
                            _ => None,
                        })
                        .expect("relay payload should contain inner message");
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

        let _ = process_incoming_message(&peer_manager, "node-b", third).await;
        let _ = process_incoming_message(&peer_manager, "node-b", second).await;
        let released = process_incoming_message(&peer_manager, "node-b", first).await;

        match released {
            IncomingMessageDisposition::Dispatch(messages) => assert_eq!(messages.len(), 1),
            IncomingMessageDisposition::Consumed => panic!("expected buffered ordered release"),
        }
    }
}

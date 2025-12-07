use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::events::dispatcher;
use crate::events::model::{LogEvent, LogLevel, SystemEvent};
use crate::network::message::{Message, MessageType, Reason};
use crate::network::peer_manager::PeerManager;
use crate::realms::RealmInfo;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Deterministic relay selection via Rendezvous (HRW) hashing
async fn rendezvous_select(
    pm: &PeerManager,
    key: &str,
    require_store_forward: bool,
) -> Option<String> {
    use std::hash::{Hash, Hasher};
    let candidates = pm.list_node_ids().await;
    let mut best_id: Option<String> = None;
    let mut best_score: u64 = 0;
    for nid in candidates {
        // Capability gating: must have relay, and optionally relay_store_forward
        if !pm.peer_has_capability(&nid, "relay").await {
            continue;
        }
        if require_store_forward && !pm.peer_has_capability(&nid, "relay_store_forward").await {
            continue;
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (key, &nid).hash(&mut hasher);
        let score = hasher.finish();
        if score > best_score {
            best_score = score;
            best_id = Some(nid);
        }
    }
    best_id
}

pub async fn handle_bind(
    msg: &Message,
    addr: &SocketAddr,
    peer_manager: &PeerManager,
    relay_enabled: bool,
    relay_store_forward_enabled: bool,
    _allow_console: bool,
) {
    if !relay_enabled {
        return;
    }
    if let MessageType::RelayBind {
        target,
        want_store_forward,
        qos,
        nonce,
        expires_at,
    } = &msg.msg_type
    {
        let mut ok = true;
        let mut reason: Option<Reason> = None;
        if want_store_forward.as_ref().cloned().unwrap_or(false) && !relay_store_forward_enabled {
            ok = false;
            reason = Some(Reason::PolicyDenied);
        }
        if ok {
            if let Some(exp) = expires_at.as_ref().cloned() {
                if exp <= now_secs() {
                    ok = false;
                    reason = Some(Reason::Timeout);
                }
            }
        }
        if ok && peer_manager.is_bound(&msg.from, target).await {
            ok = false;
            reason = Some(Reason::AlreadyBound);
        }
        if ok {
            let t = target.trim();
            if t.is_empty() || t == msg.from {
                ok = false;
                reason = Some(Reason::UnknownTarget);
            }
        }
        if ok
            && want_store_forward.as_ref().cloned().unwrap_or(false)
            && !peer_manager.can_enqueue_store_forward(target).await
        {
            ok = false;
            reason = Some(Reason::Overload);
        }
        let present = peer_manager.has_node_id(target).await;
        let reason_snapshot = reason.clone();
        let ack = Message::new(
            &addr.to_string(),
            &addr.to_string(),
            MessageType::RelayBindAck {
                ok,
                reason,
                binding_id: if ok {
                    Some(format!(
                        "bind:{}:{}:{}",
                        msg.from,
                        target,
                        nonce.unwrap_or(0)
                    ))
                } else {
                    None
                },
                peer_present: Some(present),
                nonce: *nonce,
            },
            None,
            msg.realm.clone(),
        );
        let _ = peer_manager.send_to_addr(addr, ack.as_json()).await;
        if !ok && matches!(reason_snapshot, Some(Reason::Overload)) {
            let notify = Message::new(
                &addr.to_string(),
                &addr.to_string(),
                MessageType::RelayNotify {
                    notif_type: Reason::Overload,
                    binding_id: None,
                    detail: Some(format!("target={}", target)),
                },
                None,
                msg.realm.clone(),
            );
            let _ = peer_manager.send_to_addr(addr, notify.as_json()).await;
        }
        if ok {
            let store_fwd = relay_store_forward_enabled
                && want_store_forward.as_ref().cloned().unwrap_or(false);
            let exp = expires_at.as_ref().cloned();
            peer_manager
                .set_binding(&msg.from, target, store_fwd, exp, qos.clone())
                .await;
            if let Some(bid) = nonce.map(|n| format!("bind:{}:{}:{}", msg.from, target, n)) {
                peer_manager.add_binding_id(&bid, &msg.from, target).await;
            }
        }
        // Emit simple system event for traceability
        let mut meta = dispatcher::meta("relay", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: "relay_bind_processed".into(),
            detail: Some(format!("from={} target={} ok={}", msg.from, target, ok)),
        }));
    }
}

// Ergonomic builders

pub struct RelayBindBuilder {
    to: String,
    want_store_forward: Option<bool>,
    qos: Option<String>,
    ttl_secs: Option<u64>,
}

impl RelayBindBuilder {
    pub fn new(_from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            to: to.into(),
            want_store_forward: None,
            qos: None,
            ttl_secs: None,
        }
    }
    pub fn store_forward(mut self, enable: bool) -> Self {
        self.want_store_forward = Some(enable);
        self
    }
    pub fn qos(mut self, qos: impl Into<String>) -> Self {
        self.qos = Some(qos.into());
        self
    }
    pub fn ttl(mut self, secs: u64) -> Self {
        self.ttl_secs = Some(secs);
        self
    }
    pub async fn send(
        self,
        peer_manager: &PeerManager,
        addr: &SocketAddr,
        realm: Option<RealmInfo>,
    ) {
        let nonce = Some(now_secs());
        let expires_at = self.ttl_secs.map(|t| now_secs() + t);
        let msg = Message::new(
            &addr.to_string(),
            &addr.to_string(),
            MessageType::RelayBind {
                target: self.to.clone(),
                want_store_forward: self.want_store_forward,
                qos: self.qos,
                nonce,
                expires_at,
            },
            None,
            realm,
        );
        let _ = peer_manager.send_to_addr(addr, msg.as_json()).await;
    }
}

pub struct RelayForwardBuilder {
    from: String,
    to: String,
    sequence: Option<u64>,
    payload: Option<crate::network::message::Payload>,
}

impl RelayForwardBuilder {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            sequence: None,
            payload: None,
        }
    }
    pub fn sequence(mut self, seq: u64) -> Self {
        self.sequence = Some(seq);
        self
    }
    pub fn payload_text(mut self, text: impl Into<String>) -> Self {
        self.payload = Some(crate::network::message::Payload::Text(text.into()));
        self
    }
    pub fn payload_json(mut self, json: serde_json::Value) -> Self {
        self.payload = Some(crate::network::message::Payload::Json(json));
        self
    }
    pub fn payload_binary(mut self, bytes: Vec<u8>) -> Self {
        self.payload = Some(crate::network::message::Payload::Binary(bytes));
        self
    }
    pub async fn send(
        self,
        peer_manager: &PeerManager,
        addr: &SocketAddr,
        realm: Option<RealmInfo>,
    ) {
        let msg = Message::new(
            &addr.to_string(),
            &addr.to_string(),
            MessageType::RelayForward {
                to: self.to.clone(),
                from: self.from.clone(),
                sequence: self.sequence,
            },
            self.payload,
            realm,
        );
        let _ = peer_manager.send_to_addr(addr, msg.as_json()).await;
    }
}

pub async fn handle_forward(
    msg: &Message,
    addr: &SocketAddr,
    peer_manager: &PeerManager,
    relay_enabled: bool,
    relay_store_forward_enabled: bool,
    relay_selection_enabled: bool,
    _allow_console: bool,
) {
    if !relay_enabled {
        return;
    }
    if let MessageType::RelayForward { to, from, sequence } = &msg.msg_type {
        // Dedup/order enforcement: drop if sequence <= last seen
        if let Some(seq) = *sequence {
            if let Some(last) = peer_manager.last_sequence(from, to).await {
                if seq <= last {
                    // Duplicate or out-of-order: drop silently
                    return;
                }
            }
            peer_manager.update_sequence(from, to, seq).await;
        }
        if peer_manager.has_node_id(to).await {
            let _ = peer_manager
                .send_to_node_id(to.as_str(), msg.as_json())
                .await;
            if let Some(seq) = *sequence {
                if peer_manager.binding_qos(&msg.from, to).await.as_deref() == Some("reliable") {
                    peer_manager.add_inflight(&msg.from, to, seq).await;
                    // Schedule a simple timeout-based retry if ACK not received
                    let pm_clone = peer_manager.clone();
                    let addr_clone = *addr;
                    let realm_clone = msg.realm.clone();
                    let to_clone = to.clone();
                    let from_clone = msg.from.clone();
                    // Optional: disable background retry via env for deterministic tests
                    if std::env::var("THENODES_DISABLE_RETRY").is_err() {
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            if pm_clone.is_inflight(&from_clone, &to_clone, seq).await {
                                // Retry once
                                let retry = Message::new(
                                    &addr_clone.to_string(),
                                    &addr_clone.to_string(),
                                    MessageType::RelayForward {
                                        to: to_clone.clone(),
                                        from: from_clone.clone(),
                                        sequence: Some(seq),
                                    },
                                    None,
                                    realm_clone.clone(),
                                );
                                let _ = pm_clone
                                    .send_to_node_id(to_clone.as_str(), retry.as_json())
                                    .await;
                            }
                        });
                    }
                }
            }
            peer_manager.inc_relay_forwarded();
        } else {
            // Try forwarding to a deterministically selected relay peer when enabled
            if relay_selection_enabled {
                if let Some(relay_id) =
                    rendezvous_select(peer_manager, to, relay_store_forward_enabled).await
                {
                    let qos = peer_manager.binding_qos(&msg.from, to).await;
                    let first = peer_manager
                        .send_to_node_id(relay_id.as_str(), msg.as_json())
                        .await;
                    if first.is_err() && qos.as_deref() == Some("reliable") {
                        // Basic Reliable QoS: single retry on immediate send failure
                        let _ = peer_manager
                            .send_to_node_id(relay_id.as_str(), msg.as_json())
                            .await;
                    }
                    // Consider this forwarded via relay
                    peer_manager.inc_relay_forwarded();
                    return;
                }
            }
            peer_manager.inc_relay_dropped();
            // Check QoS: low_latency avoids enqueue
            let qos = peer_manager.binding_qos(&msg.from, to).await;
            if relay_store_forward_enabled
                && peer_manager.binding_store_forward(&msg.from, to).await
                && qos.as_deref() != Some("low_latency")
            {
                let exp = peer_manager.binding_expires_at(&msg.from, to).await;
                if !peer_manager.can_enqueue_store_forward(to).await {
                    let notify = Message::new(
                        &addr.to_string(),
                        &addr.to_string(),
                        MessageType::RelayNotify {
                            notif_type: Reason::Overload,
                            binding_id: None,
                            detail: Some(format!("target={}", to)),
                        },
                        None,
                        msg.realm.clone(),
                    );
                    let _ = peer_manager.send_to_addr(addr, notify.as_json()).await;
                } else if let Some(e) = exp {
                    let now = now_secs();
                    if e <= now {
                        let notify = Message::new(
                            &addr.to_string(),
                            &addr.to_string(),
                            MessageType::RelayNotify {
                                notif_type: Reason::Timeout,
                                binding_id: None,
                                detail: Some(format!("target={}", to)),
                            },
                            None,
                            msg.realm.clone(),
                        );
                        let _ = peer_manager.send_to_addr(addr, notify.as_json()).await;
                    } else {
                        let priority_front = qos.as_deref() == Some("high_throughput");
                        let soft_drop_bulk = qos.as_deref() == Some("bulk");
                        let enq = peer_manager
                            .enqueue_store_forward(
                                to,
                                msg.as_json(),
                                Some(e),
                                priority_front,
                                soft_drop_bulk,
                                Some(msg.from.clone()),
                            )
                            .await;
                        if !enq {
                            let notify = Message::new(
                                &addr.to_string(),
                                &addr.to_string(),
                                MessageType::RelayNotify {
                                    notif_type: Reason::Overload,
                                    binding_id: None,
                                    detail: Some(format!("target={}", to)),
                                },
                                None,
                                msg.realm.clone(),
                            );
                            let _ = peer_manager.send_to_addr(addr, notify.as_json()).await;
                        }
                    }
                } else {
                    let priority_front = qos.as_deref() == Some("high_throughput");
                    let soft_drop_bulk = qos.as_deref() == Some("bulk");
                    let enq = peer_manager
                        .enqueue_store_forward(
                            to,
                            msg.as_json(),
                            None,
                            priority_front,
                            soft_drop_bulk,
                            Some(msg.from.clone()),
                        )
                        .await;
                    if !enq {
                        let notify = Message::new(
                            &addr.to_string(),
                            &addr.to_string(),
                            MessageType::RelayNotify {
                                notif_type: Reason::Overload,
                                binding_id: None,
                                detail: Some(format!("target={}", to)),
                            },
                            None,
                            msg.realm.clone(),
                        );
                        let _ = peer_manager.send_to_addr(addr, notify.as_json()).await;
                    }
                }
            } else {
                let notify = Message::new(
                    &addr.to_string(),
                    &addr.to_string(),
                    MessageType::RelayNotify {
                        notif_type: Reason::Timeout,
                        binding_id: None,
                        detail: Some(format!(
                            "target={} policy=store_forward_disabled_or_low_latency",
                            to
                        )),
                    },
                    None,
                    msg.realm.clone(),
                );
                let _ = peer_manager.send_to_addr(addr, notify.as_json()).await;
            }
        }
    }
}

pub async fn handle_unbind(
    msg: &Message,
    addr: &SocketAddr,
    peer_manager: &PeerManager,
    _allow_console: bool,
) {
    if let MessageType::RelayUnbind { binding_id } = &msg.msg_type {
        if let Some((_from, _to)) = peer_manager.remove_binding_by_id(binding_id).await {
            let notify = Message::new(
                &addr.to_string(),
                &addr.to_string(),
                MessageType::RelayNotify {
                    notif_type: Reason::PeerLeft,
                    binding_id: Some(binding_id.clone()),
                    detail: None,
                },
                None,
                msg.realm.clone(),
            );
            let _ = peer_manager.send_to_addr(addr, notify.as_json()).await;
        }
        let mut meta = dispatcher::meta("relay", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: "relay_unbind_processed".into(),
            detail: Some(format!("binding_id={}", binding_id)),
        }));
    }
}

pub async fn handle_ack(msg: &Message, _addr: &SocketAddr, peer_manager: &PeerManager) {
    if let MessageType::Ack {
        to, from, sequence, ..
    } = &msg.msg_type
    {
        peer_manager.remove_inflight(from, to, *sequence).await;
    }
}

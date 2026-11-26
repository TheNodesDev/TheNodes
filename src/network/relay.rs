use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::events::dispatcher;
use crate::events::model::{LogEvent, LogLevel, SystemEvent};
use crate::network::message::{encode_relay_opaque_payload, Message, MessageType, Reason};
use crate::network::peer_manager::PeerManager;
use crate::realms::RealmInfo;

/// Bindings one client may hold on this relay.
pub const MAX_BINDINGS_PER_CLIENT: usize = 64;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        // An expired binding no longer forwards (see `handle_forward`), so it
        // may be replaced.
        let binding_live = peer_manager.is_bound(&msg.from, target).await
            && !peer_manager
                .binding_expires_at(&msg.from, target)
                .await
                .is_some_and(|exp| exp <= now_secs());
        if ok && binding_live {
            ok = false;
            reason = Some(Reason::AlreadyBound);
        }
        // Targets are arbitrary strings, so each client's bindings are capped.
        // Replacing an expired binding does not add one.
        if ok
            && !peer_manager.is_bound(&msg.from, target).await
            && peer_manager.binding_count_from(&msg.from).await >= MAX_BINDINGS_PER_CLIENT
        {
            ok = false;
            reason = Some(Reason::Overload);
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
        // Random, so a binding cannot be named by anyone who did not see the
        // acknowledgement; `handle_unbind` also checks the owner.
        let binding_id = ok.then(|| format!("bind:{}", uuid::Uuid::new_v4().simple()));
        let ack = Message::outbound(
            MessageType::RelayBindAck {
                ok,
                reason,
                binding_id: binding_id.clone(),
                peer_present: Some(present),
                nonce: *nonce,
            },
            None,
            msg.realm.clone(),
        );
        let _ = peer_manager.send_to_addr(addr, ack).await;
        if !ok && matches!(reason_snapshot, Some(Reason::Overload)) {
            let notify = Message::outbound(
                MessageType::RelayNotify {
                    notif_type: Reason::Overload,
                    binding_id: None,
                    detail: Some(format!("target={}", target)),
                },
                None,
                msg.realm.clone(),
            );
            let _ = peer_manager.send_to_addr(addr, notify).await;
        }
        if ok {
            let store_fwd = relay_store_forward_enabled
                && want_store_forward.as_ref().cloned().unwrap_or(false);
            let exp = expires_at.as_ref().cloned();
            peer_manager
                .set_binding(&msg.from, target, store_fwd, exp, qos.clone())
                .await;
            if let Some(binding_id) = &binding_id {
                peer_manager
                    .add_binding_id(binding_id, &msg.from, target)
                    .await;
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
        let msg = Message::outbound(
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
        let _ = peer_manager.send_to_addr(addr, msg).await;
    }
}

pub struct RelayForwardBuilder {
    from: String,
    to: String,
    sequence: Option<u64>,
    opaque_payload_b64: String,
}

impl RelayForwardBuilder {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            sequence: None,
            opaque_payload_b64: String::new(),
        }
    }
    pub fn sequence(mut self, seq: u64) -> Self {
        self.sequence = Some(seq);
        self
    }
    pub fn payload_text(mut self, text: impl Into<String>) -> Self {
        self.opaque_payload_b64 = encode_relay_opaque_payload(text.into());
        self
    }
    pub fn payload_json(mut self, json: serde_json::Value) -> Self {
        self.opaque_payload_b64 = encode_relay_opaque_payload(json.to_string());
        self
    }
    pub fn payload_binary(mut self, bytes: Vec<u8>) -> Self {
        self.opaque_payload_b64 = encode_relay_opaque_payload(bytes);
        self
    }
    pub async fn send(
        self,
        peer_manager: &PeerManager,
        addr: &SocketAddr,
        realm: Option<RealmInfo>,
    ) {
        let msg = Message::outbound(
            MessageType::RelayForward {
                to: self.to.clone(),
                from: self.from.clone(),
                sequence: self.sequence,
                opaque_payload_b64: self.opaque_payload_b64,
            },
            None,
            realm,
        );
        let _ = peer_manager.send_to_addr(addr, msg).await;
    }
}

/// Why a relay refuses to forward a frame, as a notification reason and an
/// event reason.
fn forward_refusal(
    msg: &Message,
    from: &str,
    bound: bool,
    expires_at: Option<u64>,
) -> Option<(Reason, &'static str)> {
    // `msg.from` is the peer on this connection (ADR-0012); the tunnel may
    // name only that peer as its origin.
    if from != msg.from {
        return Some((Reason::PolicyDenied, "origin-mismatch"));
    }
    if !bound {
        return Some((Reason::PolicyDenied, "not-bound"));
    }
    if expires_at.is_some_and(|expires_at| expires_at <= now_secs()) {
        return Some((Reason::Timeout, "binding-expired"));
    }
    None
}

fn relay_notify(notif_type: Reason, detail: String, msg: &Message) -> Message {
    Message::outbound(
        MessageType::RelayNotify {
            notif_type,
            binding_id: None,
            detail: Some(detail),
        },
        None,
        msg.realm.clone(),
    )
}

/// Forward a `RELAY_FWD` from a bound peer to its target, or queue it for
/// store-and-forward. The relay forwards only to targets connected to it; it
/// never hands a frame on to another relay.
pub async fn handle_forward(
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
    if let MessageType::RelayForward {
        to,
        from,
        sequence,
        opaque_payload_b64,
    } = &msg.msg_type
    {
        let bound = peer_manager.is_bound(from, to).await;
        let expires_at = peer_manager.binding_expires_at(from, to).await;
        if let Some((reason, code)) = forward_refusal(msg, from, bound, expires_at) {
            let mut meta = dispatcher::meta("relay", LogLevel::Warn);
            meta.corr_id = Some(dispatcher::correlation_id());
            dispatcher::emit(LogEvent::System(SystemEvent {
                meta,
                action: "relay_forward_rejected".into(),
                detail: Some(format!(
                    "peer={} origin={} target={} reason={}",
                    msg.from, from, to, code
                )),
            }));
            let notify = relay_notify(reason, format!("target={to} reason={code}"), msg);
            let _ = peer_manager.send_to_addr(addr, notify).await;
            return;
        }
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
            let _ = peer_manager.send_to_node_id(to.as_str(), msg.clone()).await;
            if let Some(seq) = *sequence {
                if peer_manager.binding_qos(from, to).await.as_deref() == Some("reliable") {
                    peer_manager.add_inflight(from, to, seq).await;
                    // Schedule a simple timeout-based retry if ACK not received
                    let pm_clone = peer_manager.clone();
                    let realm_clone = msg.realm.clone();
                    let to_clone = to.clone();
                    let from_clone = from.clone();
                    let opaque_payload_b64_clone = opaque_payload_b64.clone();
                    // Optional: disable background retry via env for deterministic tests
                    if std::env::var("THENODES_DISABLE_RETRY").is_err() {
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            if pm_clone.is_inflight(&from_clone, &to_clone, seq).await {
                                // Retry once
                                let retry = Message::outbound(
                                    MessageType::RelayForward {
                                        to: to_clone.clone(),
                                        from: from_clone.clone(),
                                        sequence: Some(seq),
                                        opaque_payload_b64: opaque_payload_b64_clone.clone(),
                                    },
                                    None,
                                    realm_clone.clone(),
                                );
                                let _ = pm_clone.send_to_node_id(to_clone.as_str(), retry).await;
                                // The one retry is spent; a late ACK has nothing to cancel.
                                pm_clone.remove_inflight(&from_clone, &to_clone, seq).await;
                            }
                        });
                    }
                }
            }
            peer_manager.inc_relay_forwarded();
            return;
        }

        peer_manager.inc_relay_dropped();
        // Check QoS: low_latency avoids enqueue
        let qos = peer_manager.binding_qos(from, to).await;
        if relay_store_forward_enabled
            && peer_manager.binding_store_forward(from, to).await
            && qos.as_deref() != Some("low_latency")
        {
            let priority_front = qos.as_deref() == Some("high_throughput");
            let soft_drop_bulk = qos.as_deref() == Some("bulk");
            let enqueued = peer_manager.can_enqueue_store_forward(to).await
                && peer_manager
                    .enqueue_store_forward(
                        to,
                        msg.as_json(),
                        expires_at,
                        priority_front,
                        soft_drop_bulk,
                        Some(from.clone()),
                    )
                    .await;
            if !enqueued {
                let notify = relay_notify(Reason::Overload, format!("target={to}"), msg);
                let _ = peer_manager.send_to_addr(addr, notify).await;
            }
        } else {
            let notify = relay_notify(
                Reason::Timeout,
                format!("target={to} policy=store_forward_disabled_or_low_latency"),
                msg,
            );
            let _ = peer_manager.send_to_addr(addr, notify).await;
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
        // Only the node that created a binding can remove it.
        let removed = peer_manager
            .remove_binding_by_id(binding_id, &msg.from)
            .await
            .is_some();
        if removed {
            let notify = Message::outbound(
                MessageType::RelayNotify {
                    notif_type: Reason::PeerLeft,
                    binding_id: Some(binding_id.clone()),
                    detail: None,
                },
                None,
                msg.realm.clone(),
            );
            let _ = peer_manager.send_to_addr(addr, notify).await;
        }
        let mut meta = dispatcher::meta("relay", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: "relay_unbind_processed".into(),
            detail: Some(format!(
                "peer={} binding_id={} removed={}",
                msg.from, binding_id, removed
            )),
        }));
    }
}

pub async fn handle_ack(msg: &Message, _addr: &SocketAddr, peer_manager: &PeerManager) {
    if let MessageType::Ack {
        to, from, sequence, ..
    } = &msg.msg_type
    {
        // Only the target a frame was forwarded to acknowledges it.
        if msg.from != *to {
            let mut meta = dispatcher::meta("relay", LogLevel::Warn);
            meta.corr_id = Some(dispatcher::correlation_id());
            dispatcher::emit(LogEvent::System(SystemEvent {
                meta,
                action: "relay_ack_rejected".into(),
                detail: Some(format!("peer={} target={} origin={}", msg.from, to, from)),
            }));
            return;
        }
        peer_manager.remove_inflight(from, to, *sequence).await;
    }
}

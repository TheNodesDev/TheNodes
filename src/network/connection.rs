// src/network/connection.rs
//! Connection preference policy and transport route resolution (ADR-0005).
//!
//! [`connect_with_policy`] queries [`PeerManager`] state and returns a
//! [`ConnectionOutcome`] describing the best transport route to the target peer.
//! It performs **no network I/O**; the caller decides how to act on the outcome.
//!
//! ## Phase scope
//! - Phase 1: strategy dispatch, direct TCP / direct UDP / relay.
//! - Phase 2: `udp_observed_addr` integration (resolved from PeerManager).
//! - Phase 3: relay-coordinated UDP hole punching (`direct_then_punch_then_relay`).

use std::net::SocketAddr;

use crate::config::{Config, ConnectionPolicyConfig};
use crate::network::peer_manager::PeerManager;

// ─── Strategy ───────────────────────────────────────────────────────────────────

/// Parsed transport strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStrategy {
    /// Try direct TCP only; no UDP, no relay.
    DirectOnly,
    /// Try TCP; fall back to relay.  **Default.**
    DirectThenRelay,
    /// Try TCP, then direct UDP if the peer advertises it, then relay.
    DirectThenUdpThenRelay,
    /// Skip all direct paths; use relay immediately.
    RelayOnly,
    /// TCP → direct UDP → relay-coordinated hole punch → relay.
    DirectThenPunchThenRelay,
}

impl ConnectionStrategy {
    fn from_str(s: &str) -> Self {
        match s {
            "direct_only" => Self::DirectOnly,
            "direct_then_udp_then_relay" => Self::DirectThenUdpThenRelay,
            "direct_then_punch_then_relay" => Self::DirectThenPunchThenRelay,
            "relay_only" => Self::RelayOnly,
            _ => Self::DirectThenRelay,
        }
    }
}

// ─── Policy ─────────────────────────────────────────────────────────────────────

/// Resolved connection policy built from [`ConnectionPolicyConfig`].
#[derive(Debug, Clone)]
pub struct ConnectionPolicy {
    pub strategy: ConnectionStrategy,
    /// Timeout for a direct TCP connect attempt (ms).
    pub direct_tcp_timeout_ms: u64,
    /// Timeout for a direct UDP session attempt (ms).
    pub direct_udp_timeout_ms: u64,
    /// Time budget for relay-coordinated UDP hole-punching (ms).  Phase 3.
    pub punch_timeout_ms: u64,
}

impl ConnectionPolicy {
    /// Build from an explicit [`ConnectionPolicyConfig`].
    pub fn from_config(cfg: &ConnectionPolicyConfig) -> Self {
        Self {
            strategy: ConnectionStrategy::from_str(
                cfg.strategy.as_deref().unwrap_or("direct_then_relay"),
            ),
            direct_tcp_timeout_ms: cfg.direct_tcp_timeout_ms.unwrap_or(3000),
            direct_udp_timeout_ms: cfg.direct_udp_timeout_ms.unwrap_or(1000),
            punch_timeout_ms: cfg.punch_timeout_ms.unwrap_or(5000),
        }
    }

    /// Derive from the full [`Config`]; falls back to defaults when the section
    /// is absent.
    pub fn from_network_config(config: &Config) -> Self {
        if let Some(policy_cfg) = config
            .network
            .as_ref()
            .and_then(|n| n.connection_policy.as_ref())
        {
            Self::from_config(policy_cfg)
        } else {
            Self::default()
        }
    }
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            strategy: ConnectionStrategy::DirectThenRelay,
            direct_tcp_timeout_ms: 3000,
            direct_udp_timeout_ms: 1000,
            punch_timeout_ms: 5000,
        }
    }
}

// ─── Outcome ────────────────────────────────────────────────────────────────────

/// Result of [`connect_with_policy`]: the recommended route to reach the target peer.
///
/// The caller is responsible for acting on this outcome — establishing the connection
/// or delivering the message.
#[derive(Debug, Clone)]
pub enum ConnectionOutcome {
    /// Peer is already reachable through an active TCP connection.
    /// Use `PeerManager::send_to_node_id` to deliver.
    AlreadyConnected,
    /// Connect (or reconnect) to the peer via TCP at this address.
    /// Pass `addr` to `connect_to_peer`.
    DirectTcp { addr: SocketAddr },
    /// Send via an established UDP Noise session; use `send_udp` with the
    /// session ID mapped in `PeerManager`.
    DirectUdp { addr: SocketAddr },
    /// Initiate a relay-coordinated UDP hole punch via the selected rendezvous node.
    HolePunchUdp {
        relay_node_id: String,
        addr: SocketAddr,
    },
    /// Route the message through this relay node.
    ViaRelay { relay_node_id: String },
    /// No viable route could be determined.
    NoRoute { reason: String },
}

// ─── Route resolution ────────────────────────────────────────────────────────────

/// Resolve the preferred transport route to `target_node_id`.
///
/// Queries current [`PeerManager`] state and returns the recommended
/// [`ConnectionOutcome`].  Performs no network I/O.
///
/// The effective policy is read from `config.network.connection_policy`; the
/// default strategy is `direct_then_relay`.
pub async fn connect_with_policy(
    target_node_id: &str,
    policy: &ConnectionPolicy,
    peer_manager: &PeerManager,
    config: &Config,
) -> ConnectionOutcome {
    // Peer already has an active TCP or UDP connection.
    if peer_manager.has_node_id(target_node_id).await
        || peer_manager
            .udp_session_id_for(target_node_id)
            .await
            .is_some()
    {
        return ConnectionOutcome::AlreadyConnected;
    }

    match policy.strategy {
        ConnectionStrategy::RelayOnly => relay_route(peer_manager).await,

        ConnectionStrategy::DirectOnly => resolve_tcp(peer_manager, target_node_id)
            .await
            .map(|addr| ConnectionOutcome::DirectTcp { addr })
            .unwrap_or_else(|| ConnectionOutcome::NoRoute {
                reason: "no TCP address known for peer (direct_only)".to_string(),
            }),

        ConnectionStrategy::DirectThenRelay => {
            if let Some(addr) = resolve_tcp(peer_manager, target_node_id).await {
                ConnectionOutcome::DirectTcp { addr }
            } else {
                relay_route(peer_manager).await
            }
        }

        ConnectionStrategy::DirectThenUdpThenRelay => {
            // 1. TCP address known?
            if let Some(addr) = resolve_tcp(peer_manager, target_node_id).await {
                return ConnectionOutcome::DirectTcp { addr };
            }
            // 2. Active UDP Noise session?
            if peer_manager
                .udp_session_id_for(target_node_id)
                .await
                .is_some()
            {
                let udp_addr = peer_manager
                    .udp_listen_addr_for(target_node_id)
                    .await
                    .unwrap_or_default();
                if let Ok(addr) = udp_addr.parse::<SocketAddr>() {
                    return ConnectionOutcome::DirectUdp { addr };
                }
            }
            // 3. Peer advertises UDP and we know their UDP listen address — initiate session.
            if peer_manager
                .peer_has_capability(target_node_id, "udp")
                .await
            {
                if let Some(udp_addr) = peer_manager.udp_listen_addr_for(target_node_id).await {
                    if let Ok(addr) = udp_addr.parse::<SocketAddr>() {
                        return ConnectionOutcome::DirectUdp { addr };
                    }
                }
            }
            // 4. Relay fallback.
            relay_route(peer_manager).await
        }

        // Phase 3: hole-punch via relay-coordinated observed addresses.
        ConnectionStrategy::DirectThenPunchThenRelay => {
            let observed_addr_max_age_secs = observed_addr_max_age_secs(config);

            // 1. Direct TCP.
            if let Some(addr) = resolve_tcp(peer_manager, target_node_id).await {
                return ConnectionOutcome::DirectTcp { addr };
            }
            // 2. Active UDP Noise session already established.
            if peer_manager
                .udp_session_id_for(target_node_id)
                .await
                .is_some()
            {
                let udp_addr = peer_manager
                    .udp_listen_addr_for(target_node_id)
                    .await
                    .unwrap_or_default();
                if let Ok(addr) = udp_addr.parse::<SocketAddr>() {
                    return ConnectionOutcome::DirectUdp { addr };
                }
            }
            // 3. Direct UDP via advertised listen address.
            if peer_manager
                .peer_has_capability(target_node_id, "udp")
                .await
            {
                if let Some(udp_addr) = peer_manager.udp_listen_addr_for(target_node_id).await {
                    if let Ok(addr) = udp_addr.parse::<SocketAddr>() {
                        return ConnectionOutcome::DirectUdp { addr };
                    }
                }
            }
            // 4. Relay-coordinated hole punch via observed addresses.
            if local_punch_enabled(config)
                && peer_manager
                    .peer_has_capability(target_node_id, "punch")
                    .await
            {
                if let Some(obs_addr) = peer_manager
                    .udp_observed_addr_for_if_fresh(target_node_id, observed_addr_max_age_secs)
                    .await
                {
                    if let Some(relay_node_id) = punch_rendezvous_route(peer_manager).await {
                        if let Ok(addr) = obs_addr.parse::<SocketAddr>() {
                            return ConnectionOutcome::HolePunchUdp {
                                relay_node_id,
                                addr,
                            };
                        }
                    }
                }
            }
            // 5. Relay fallback.
            relay_route(peer_manager).await
        }
    }
}

/// Return the TCP listen address advertised by `node_id` in their HELLO, if known.
async fn resolve_tcp(peer_manager: &PeerManager, node_id: &str) -> Option<SocketAddr> {
    let addr_str = peer_manager.tcp_listen_addr_for(node_id).await?;
    addr_str.parse::<SocketAddr>().ok()
}

/// Find a connected peer advertising the `"relay"` capability.
async fn relay_route(peer_manager: &PeerManager) -> ConnectionOutcome {
    let node_ids = peer_manager.list_node_ids().await;
    for nid in node_ids {
        if peer_manager.peer_has_capability(&nid, "relay").await {
            return ConnectionOutcome::ViaRelay { relay_node_id: nid };
        }
    }
    ConnectionOutcome::NoRoute {
        reason: "no relay peer available".to_string(),
    }
}

async fn punch_rendezvous_route(peer_manager: &PeerManager) -> Option<String> {
    let node_ids = peer_manager.list_node_ids().await;
    for nid in node_ids {
        if peer_manager
            .peer_has_capability(&nid, "punch_rendezvous")
            .await
        {
            return Some(nid);
        }
    }
    None
}

fn observed_addr_max_age_secs(config: &Config) -> u64 {
    config
        .network
        .as_ref()
        .and_then(|n| n.nat_traversal.as_ref())
        .and_then(|nat| nat.refresh_secs)
        .unwrap_or(300)
}

fn local_punch_enabled(config: &Config) -> bool {
    if !cfg!(feature = "noise") {
        return false;
    }

    let udp_enabled = config
        .network
        .as_ref()
        .and_then(|n| n.udp.as_ref())
        .and_then(|udp| udp.enabled)
        .unwrap_or(false);
    let nat_enabled = config
        .network
        .as_ref()
        .and_then(|n| n.nat_traversal.as_ref())
        .and_then(|nat| nat.enabled)
        .unwrap_or(false);

    udp_enabled && nat_enabled
}

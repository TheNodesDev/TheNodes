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
use std::time::Duration;

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

/// Transport route tracked by the connection lifecycle policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteKind {
    Tcp,
    Udp,
    Relay,
}

/// Coarse runtime health used to re-evaluate otherwise valid policy routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteHealth {
    #[default]
    Unknown,
    Healthy,
    Suspect,
    Unresponsive,
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
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub reconnect_base_delay: Duration,
    pub reconnect_multiplier: f64,
    pub reconnect_max_delay: Duration,
    pub reconnect_max_attempts: u32,
    pub reconnect_jitter_ratio: f64,
}

impl ConnectionPolicy {
    /// Build from an explicit [`ConnectionPolicyConfig`].
    pub fn from_config(cfg: &ConnectionPolicyConfig) -> Self {
        let heartbeat_interval_ms = cfg.heartbeat_interval_ms.unwrap_or(30_000).max(1);
        let reconnect_base_delay_ms = cfg.reconnect_base_delay_ms.unwrap_or(1_000).max(1);
        let reconnect_multiplier = cfg.reconnect_multiplier.unwrap_or(2.0);
        let reconnect_jitter_ratio = cfg.reconnect_jitter_ratio.unwrap_or(0.2);
        Self {
            strategy: ConnectionStrategy::from_str(
                cfg.strategy.as_deref().unwrap_or("direct_then_relay"),
            ),
            direct_tcp_timeout_ms: cfg.direct_tcp_timeout_ms.unwrap_or(3000),
            direct_udp_timeout_ms: cfg.direct_udp_timeout_ms.unwrap_or(1000),
            punch_timeout_ms: cfg.punch_timeout_ms.unwrap_or(5000),
            heartbeat_interval: Duration::from_millis(heartbeat_interval_ms),
            heartbeat_timeout: Duration::from_millis(
                cfg.heartbeat_timeout_ms
                    .unwrap_or(90_000)
                    .max(heartbeat_interval_ms),
            ),
            reconnect_base_delay: Duration::from_millis(reconnect_base_delay_ms),
            reconnect_multiplier: if reconnect_multiplier.is_finite() {
                reconnect_multiplier.max(1.0)
            } else {
                2.0
            },
            reconnect_max_delay: Duration::from_millis(
                cfg.reconnect_max_delay_ms
                    .unwrap_or(60_000)
                    .max(reconnect_base_delay_ms),
            ),
            reconnect_max_attempts: cfg.reconnect_max_attempts.unwrap_or(8),
            reconnect_jitter_ratio: if reconnect_jitter_ratio.is_finite() {
                reconnect_jitter_ratio.clamp(0.0, 1.0)
            } else {
                0.2
            },
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

    /// Calculate the delay for a one-based reconnect attempt.
    ///
    /// `jitter_sample` is clamped to `-1.0..=1.0`; zero produces the exact
    /// exponential progression and makes the calculation deterministic in tests.
    pub fn reconnect_delay(&self, attempt: u32, jitter_sample: f64) -> Duration {
        let base_delay_ms = self.reconnect_base_delay.as_secs_f64() * 1_000.0;
        let max_delay_ms = self.reconnect_max_delay.as_secs_f64() * 1_000.0;
        let uncapped_delay = base_delay_ms
            * self
                .reconnect_multiplier
                .powf(f64::from(attempt.saturating_sub(1)));
        let delay_ms = if uncapped_delay.is_finite() {
            uncapped_delay.min(max_delay_ms)
        } else {
            max_delay_ms
        };
        let jitter_sample = if jitter_sample.is_finite() {
            jitter_sample.clamp(-1.0, 1.0)
        } else {
            0.0
        };
        let jitter_factor = 1.0 + self.reconnect_jitter_ratio * jitter_sample;
        Duration::from_secs_f64((delay_ms * jitter_factor).max(1.0) / 1_000.0)
    }

    pub fn reconnect_delay_with_random_jitter(&self, attempt: u32) -> Duration {
        self.reconnect_delay(attempt, rand::random::<f64>() * 2.0 - 1.0)
    }
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            strategy: ConnectionStrategy::DirectThenRelay,
            direct_tcp_timeout_ms: 3000,
            direct_udp_timeout_ms: 1000,
            punch_timeout_ms: 5000,
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
            reconnect_base_delay: Duration::from_secs(1),
            reconnect_multiplier: 2.0,
            reconnect_max_delay: Duration::from_secs(60),
            reconnect_max_attempts: 8,
            reconnect_jitter_ratio: 0.2,
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
    let mut candidates = Vec::new();

    if !matches!(policy.strategy, ConnectionStrategy::RelayOnly) {
        if let Some(candidate) = tcp_candidate(peer_manager, target_node_id).await {
            candidates.push(candidate);
        }
    }

    if matches!(
        policy.strategy,
        ConnectionStrategy::DirectThenUdpThenRelay | ConnectionStrategy::DirectThenPunchThenRelay
    ) {
        if let Some(candidate) = udp_candidate(peer_manager, target_node_id).await {
            candidates.push(candidate);
        }
    }

    if matches!(
        policy.strategy,
        ConnectionStrategy::DirectThenPunchThenRelay
    ) && local_punch_enabled(config)
        && peer_manager
            .peer_has_capability(target_node_id, "punch")
            .await
    {
        if let Some(obs_addr) = peer_manager
            .udp_observed_addr_for_if_fresh(target_node_id, observed_addr_max_age_secs(config))
            .await
        {
            if let (Some(relay_node_id), Ok(addr)) = (
                punch_rendezvous_route(peer_manager).await,
                obs_addr.parse::<SocketAddr>(),
            ) {
                candidates.push(RouteCandidate {
                    health_node_id: relay_node_id.clone(),
                    kind: RouteKind::Relay,
                    outcome: ConnectionOutcome::HolePunchUdp {
                        relay_node_id,
                        addr,
                    },
                });
            }
        }
    }

    if !matches!(policy.strategy, ConnectionStrategy::DirectOnly) {
        candidates.extend(relay_candidates(peer_manager).await);
    }

    choose_healthiest_route(peer_manager, candidates)
        .await
        .unwrap_or_else(|| ConnectionOutcome::NoRoute {
            reason: format!("no healthy route available for {:?}", policy.strategy),
        })
}

struct RouteCandidate {
    health_node_id: String,
    kind: RouteKind,
    outcome: ConnectionOutcome,
}

async fn tcp_candidate(peer_manager: &PeerManager, node_id: &str) -> Option<RouteCandidate> {
    let outcome = if peer_manager.has_node_id(node_id).await {
        ConnectionOutcome::AlreadyConnected
    } else {
        ConnectionOutcome::DirectTcp {
            addr: resolve_tcp(peer_manager, node_id).await?,
        }
    };
    Some(RouteCandidate {
        health_node_id: node_id.to_string(),
        kind: RouteKind::Tcp,
        outcome,
    })
}

async fn udp_candidate(peer_manager: &PeerManager, node_id: &str) -> Option<RouteCandidate> {
    let has_session = peer_manager.udp_session_id_for(node_id).await.is_some();
    if !has_session && !peer_manager.peer_has_capability(node_id, "udp").await {
        return None;
    }
    let addr = peer_manager
        .udp_listen_addr_for(node_id)
        .await?
        .parse::<SocketAddr>()
        .ok()?;
    Some(RouteCandidate {
        health_node_id: node_id.to_string(),
        kind: RouteKind::Udp,
        outcome: ConnectionOutcome::DirectUdp { addr },
    })
}

async fn relay_candidates(peer_manager: &PeerManager) -> Vec<RouteCandidate> {
    let mut candidates = Vec::new();
    for node_id in peer_manager.list_node_ids().await {
        if peer_manager.peer_has_capability(&node_id, "relay").await {
            candidates.push(RouteCandidate {
                health_node_id: node_id.clone(),
                kind: RouteKind::Relay,
                outcome: ConnectionOutcome::ViaRelay {
                    relay_node_id: node_id,
                },
            });
        }
    }
    candidates
}

async fn choose_healthiest_route(
    peer_manager: &PeerManager,
    candidates: Vec<RouteCandidate>,
) -> Option<ConnectionOutcome> {
    let mut best: Option<(u8, ConnectionOutcome)> = None;
    for candidate in candidates {
        let health = peer_manager
            .route_health(&candidate.health_node_id, candidate.kind)
            .await;
        if health == RouteHealth::Unresponsive {
            continue;
        }
        let rank = match health {
            RouteHealth::Healthy | RouteHealth::Unknown => 0,
            RouteHealth::Suspect => 1,
            RouteHealth::Unresponsive => unreachable!(),
        };
        if best.as_ref().is_none_or(|(best_rank, _)| rank < *best_rank) {
            best = Some((rank, candidate.outcome));
        }
    }
    best.map(|(_, outcome)| outcome)
}

/// Return the TCP listen address advertised by `node_id` in their HELLO, if known.
async fn resolve_tcp(peer_manager: &PeerManager, node_id: &str) -> Option<SocketAddr> {
    let addr_str = peer_manager.tcp_listen_addr_for(node_id).await?;
    addr_str.parse::<SocketAddr>().ok()
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

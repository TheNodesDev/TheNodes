pub mod bootstrap;
pub mod connection;
pub mod delivery;
pub(crate) mod events;
pub mod listener;
pub mod message;
#[cfg(feature = "noise")]
pub mod nat_traversal;
pub mod peer;
pub mod peer_manager;
pub mod peer_store;
pub mod relay;
pub mod transport;
#[cfg(feature = "noise")]
pub mod udp_listener;
pub mod udp_session;

pub use bootstrap::connect_to_bootstrap_nodes;
pub use connection::{
    connect_with_policy, ConnectionOutcome, ConnectionPolicy, ConnectionStrategy,
};
pub use delivery::{
    DeliveryClass, DeliveryFailureReason, DeliveryOptions, DeliveryOutcome,
    DeliveryPathConstraints, DeliveryRuntime, DeliveryTransportPreference,
    IncomingMessageDisposition, MessageId,
};
pub use listener::start_listener;
pub use message::{DeliveryMetadata, Message, MessageType};
pub use peer::Peer;
pub use peer_manager::PeerManager;
pub use peer_store::{PeerSource, PeerStore};
pub use transport::connect_to_peer;

pub(crate) fn advertised_capabilities(config: &crate::config::Config) -> Option<Vec<String>> {
    let mut caps = Vec::new();
    if let Some(relay) = config.network.as_ref().and_then(|n| n.relay.as_ref()) {
        if relay.enabled.unwrap_or(false) {
            caps.push("relay".to_string());
            if relay.store_forward.unwrap_or(false) {
                caps.push("relay_store_forward".to_string());
            }
        }
    }
    if cfg!(feature = "noise") {
        if let Some(udp) = config.network.as_ref().and_then(|n| n.udp.as_ref()) {
            if udp.enabled.unwrap_or(false) {
                caps.push("udp".to_string());

                // ADR-0005 Phase 2+: punch capabilities gated on nat_traversal config.
                if let Some(nat) = config
                    .network
                    .as_ref()
                    .and_then(|n| n.nat_traversal.as_ref())
                {
                    if nat.enabled.unwrap_or(false) {
                        caps.push("punch".to_string());
                        // punch_rendezvous also requires relay.
                        let relay_on = config
                            .network
                            .as_ref()
                            .and_then(|n| n.relay.as_ref())
                            .map(|r| r.enabled.unwrap_or(false))
                            .unwrap_or(false);
                        if relay_on && nat.serve.unwrap_or(false) {
                            caps.push("punch_rendezvous".to_string());
                        }
                    }
                }
            }
        }
    }
    if caps.is_empty() {
        None
    } else {
        Some(caps)
    }
}

/// Compute the UDP listen address to advertise in HELLO messages.
///
/// Returns `Some("ip:port")` when the UDP transport is enabled in `config`, using `local_ip`
/// as the IP part and either the configured port or TCP port + 1 as the port.
pub(crate) fn udp_hello_addr(
    config: &crate::config::Config,
    local_ip: std::net::IpAddr,
) -> Option<String> {
    if !cfg!(feature = "noise") {
        return None;
    }
    let udp_cfg = config.network.as_ref()?.udp.as_ref()?;
    if !udp_cfg.enabled.unwrap_or(false) {
        return None;
    }
    let port = udp_cfg.listen_port.unwrap_or(config.port + 1);
    Some(format!("{}:{}", local_ip, port))
}

// Quality-of-Service preferences for relay bindings and forwards
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum QoS {
    // Prioritize lowest latency; bypass queues when possible
    LowLatency,
    // Favor throughput; enqueue at front for faster draining
    HighThroughput,
    // Deprioritized traffic; enqueue at back and soft-drop under pressure
    Bulk,
}

pub struct Network {
    pub peers: Vec<String>, // Placeholder
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

impl Network {
    pub fn new() -> Self {
        Self { peers: vec![] }
    }

    pub fn add_peer(&mut self, peer: String) {
        self.peers.push(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::{advertised_capabilities, udp_hello_addr};
    use crate::config::{Config, UdpConfig};

    fn config_with_udp(enabled: bool, listen_port: Option<u16>) -> Config {
        let mut config = Config::default();
        if let Some(network) = config.network.as_mut() {
            network.udp = Some(UdpConfig {
                enabled: Some(enabled),
                listen_port,
                max_datagram_bytes: Some(1200),
                max_app_payload_bytes: Some(1176),
            });
        }
        config
    }

    #[test]
    fn udp_capability_respects_feature_and_config() {
        let disabled_cfg = config_with_udp(false, Some(4444));
        let disabled_caps = advertised_capabilities(&disabled_cfg).unwrap_or_default();
        assert!(!disabled_caps.iter().any(|cap| cap == "udp"));

        let enabled_cfg = config_with_udp(true, Some(4444));
        let enabled_caps = advertised_capabilities(&enabled_cfg).unwrap_or_default();

        if cfg!(feature = "noise") {
            assert!(enabled_caps.iter().any(|cap| cap == "udp"));
        } else {
            assert!(!enabled_caps.iter().any(|cap| cap == "udp"));
        }
    }

    #[test]
    fn udp_hello_addr_respects_feature_and_ports() {
        let local_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        let disabled_cfg = config_with_udp(false, Some(4444));
        assert_eq!(udp_hello_addr(&disabled_cfg, local_ip), None);

        let enabled_cfg_with_port = config_with_udp(true, Some(4444));
        if cfg!(feature = "noise") {
            assert_eq!(
                udp_hello_addr(&enabled_cfg_with_port, local_ip),
                Some("127.0.0.1:4444".to_string())
            );
        } else {
            assert_eq!(udp_hello_addr(&enabled_cfg_with_port, local_ip), None);
        }

        let enabled_cfg_default_port = config_with_udp(true, None);
        if cfg!(feature = "noise") {
            assert_eq!(
                udp_hello_addr(&enabled_cfg_default_port, local_ip),
                Some(format!("127.0.0.1:{}", enabled_cfg_default_port.port + 1))
            );
        } else {
            assert_eq!(udp_hello_addr(&enabled_cfg_default_port, local_ip), None);
        }
    }
}

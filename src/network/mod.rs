pub mod bootstrap;
pub(crate) mod events;
pub mod listener;
pub mod message;
pub mod peer;
pub mod peer_manager;
pub mod peer_store;
pub mod relay;
pub mod transport;

pub use bootstrap::connect_to_bootstrap_nodes;
pub use listener::start_listener;
pub use message::{Message, MessageType};
pub use peer::Peer;
pub use peer_manager::PeerManager;
pub use peer_store::{PeerSource, PeerStore};
pub use transport::connect_to_peer;

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

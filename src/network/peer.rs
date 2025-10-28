// src/network/peer.rs

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub address: String,
}

impl Peer {
    pub fn new(id: &str, address: &str) -> Self {
        Self {
            id: id.to_string(),
            address: address.to_string(),
        }
    }

    pub fn display(&self) -> String {
        format!("Peer[id: {}, address: {}]", self.id, self.address)
    }
}

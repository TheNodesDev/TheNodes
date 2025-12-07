// src/network/peer.rs

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub address: String,
    pub capabilities: Option<Vec<String>>, // from HELLO; used to gate features
}

impl Peer {
    pub fn new(id: String, address: String) -> Self {
        Self {
            id,
            address,
            capabilities: None,
        }
    }

    pub fn set_capabilities(&mut self, caps: Option<Vec<String>>) {
        self.capabilities = caps;
    }

    pub fn has_capability(&self, cap: &str) -> bool {
        match &self.capabilities {
            Some(v) => v.iter().any(|c| c == cap),
            None => false,
        }
    }

    pub fn display(&self) -> String {
        format!("Peer[id: {}, address: {}]", self.id, self.address)
    }
}

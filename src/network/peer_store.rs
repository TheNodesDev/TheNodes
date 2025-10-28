// src/network/peer_store.rs
// Simple in-memory peer candidate store for discovery.
// Future: persistence, scoring, backoff.

use rand::seq::IteratorRandom;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerSource {
    Bootstrap,
    Handshake,
    Gossip,
    Manual,
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub addr: SocketAddr,
    pub source: PeerSource,
    pub failures: u32,
    pub last_success_epoch: Option<u64>,
}

#[derive(Clone)]
pub struct PeerStore {
    inner: Arc<RwLock<HashMap<SocketAddr, PeerRecord>>>,
}

impl PeerStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, addr: SocketAddr, source: PeerSource) {
        let mut map = self.inner.write().await;
        map.entry(addr).or_insert(PeerRecord {
            addr,
            source,
            failures: 0,
            last_success_epoch: None,
        });
    }

    pub async fn bulk_insert<I: IntoIterator<Item = SocketAddr>>(&self, it: I, source: PeerSource) {
        let mut map = self.inner.write().await;
        for addr in it {
            map.entry(addr).or_insert(PeerRecord {
                addr,
                source,
                failures: 0,
                last_success_epoch: None,
            });
        }
    }

    pub async fn mark_success(&self, addr: &SocketAddr) {
        let mut map = self.inner.write().await;
        if let Some(rec) = map.get_mut(addr) {
            rec.last_success_epoch = Some(Self::epoch());
            rec.failures = 0;
        }
    }

    pub async fn mark_failure(&self, addr: &SocketAddr) {
        let mut map = self.inner.write().await;
        if let Some(rec) = map.get_mut(addr) {
            rec.failures += 1;
        }
    }

    pub async fn sample(&self, k: usize, exclude: &HashSet<SocketAddr>) -> Vec<SocketAddr> {
        let map = self.inner.read().await;
        let mut rng = rand::thread_rng();
        map.values()
            .filter(|r| !exclude.contains(&r.addr))
            .map(|r| r.addr)
            .choose_multiple(&mut rng, k)
    }

    pub async fn all(&self) -> Vec<SocketAddr> {
        self.inner.read().await.keys().cloned().collect()
    }

    fn epoch() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// src/network/peer_store.rs
// Simple in-memory peer candidate store for discovery.
// Future: persistence, scoring, backoff.

use crate::config::Config;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerSource {
    Bootstrap,
    Handshake,
    Gossip,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub addr: SocketAddr,
    pub source: PeerSource,
    pub failures: u32,
    pub last_success_epoch: Option<u64>,
    /// Optional node identifier (populated on successful handshake)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Optional capability flags advertised by peer
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

#[derive(Clone)]
pub struct PeerStore {
    inner: Arc<RwLock<HashMap<SocketAddr, PeerRecord>>>,
}

impl Default for PeerStore {
    fn default() -> Self {
        Self::new()
    }
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
            node_id: None,
            capabilities: None,
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
                node_id: None,
                capabilities: None,
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

    /// Mark peer as successfully connected and update metadata from HELLO
    pub async fn mark_success_with_meta(
        &self,
        addr: &SocketAddr,
        node_id: Option<String>,
        capabilities: Option<Vec<String>>,
    ) {
        let mut map = self.inner.write().await;
        if let Some(rec) = map.get_mut(addr) {
            rec.last_success_epoch = Some(Self::epoch());
            rec.failures = 0;
            if node_id.is_some() {
                rec.node_id = node_id;
            }
            if capabilities.is_some() {
                rec.capabilities = capabilities;
            }
        } else {
            // Insert new record if not present
            map.insert(
                *addr,
                PeerRecord {
                    addr: *addr,
                    source: PeerSource::Handshake,
                    failures: 0,
                    last_success_epoch: Some(Self::epoch()),
                    node_id,
                    capabilities,
                },
            );
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

    // Persistence API
    const DEFAULT_FILENAME: &str = "peers.json";

    pub async fn load_from_file(path: &str, ttl_secs: u64, max_entries: usize) -> Self {
        let store = Self::new();
        if let Ok(bytes) = fs::read(path).await {
            let entries: Vec<PeerRecord> = serde_json::from_slice(&bytes).unwrap_or_default();
            let now = Self::epoch();
            let mut count = 0usize;
            for rec in entries.into_iter() {
                let age_ok = rec
                    .last_success_epoch
                    .map(|t| now.saturating_sub(t) <= ttl_secs)
                    .unwrap_or(true);
                if age_ok {
                    store.insert(rec.addr, rec.source).await;
                    count += 1;
                    if count >= max_entries {
                        break;
                    }
                }
            }
        }
        store
    }

    pub async fn save_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let map = self.inner.read().await;
        let mut entries: Vec<PeerRecord> = map.values().cloned().collect();
        // Prefer recent successes first
        entries.sort_by_key(|r| std::cmp::Reverse(r.last_success_epoch.unwrap_or(0)));
        let json = serde_json::to_vec_pretty(&entries).map_err(std::io::Error::other)?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            fs::create_dir_all(parent).await.ok();
        }
        let mut f = fs::File::create(path).await?;
        f.write_all(&json).await?;
        Ok(())
    }

    pub async fn spawn_periodic_save(self, path: String, interval_secs: u64) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                let _ = self.save_to_file(&path).await;
            }
        });
    }

    /// Construct and optionally start periodic saves based on runtime config.
    /// Uses `node.state_dir` to derive path when not explicitly provided.
    pub async fn from_config(cfg: &Config) -> Self {
        if let Some(p) = cfg.network.as_ref().and_then(|n| n.persistence.as_ref()) {
            let enabled = p.enabled.unwrap_or(false);
            let max_entries = p.max_entries.unwrap_or(1024);
            let ttl_secs = p.ttl_secs.unwrap_or(7 * 24 * 3600);
            let base_dir = cfg
                .node
                .as_ref()
                .and_then(|n| n.state_dir.clone())
                .unwrap_or_else(|| "data".to_string());
            let path = p
                .path
                .clone()
                .unwrap_or_else(|| format!("{}/{}", base_dir, Self::DEFAULT_FILENAME));
            let store = Self::load_from_file(&path, ttl_secs, max_entries).await;
            if enabled {
                let interval = p.save_interval_secs.unwrap_or(60);
                store.clone().spawn_periodic_save(path, interval).await;
            }
            store
        } else {
            Self::new()
        }
    }

    /// Save to derived path if persistence enabled in config.
    pub async fn save_if_enabled(&self, cfg: &Config) {
        if let Some(p) = cfg.network.as_ref().and_then(|n| n.persistence.as_ref()) {
            if p.enabled.unwrap_or(false) {
                let base_dir = cfg
                    .node
                    .as_ref()
                    .and_then(|n| n.state_dir.clone())
                    .unwrap_or_else(|| "data".to_string());
                let path = p
                    .path
                    .clone()
                    .unwrap_or_else(|| format!("{}/{}", base_dir, Self::DEFAULT_FILENAME));
                let _ = self.save_to_file(&path).await;
            }
        }
    }

    fn epoch() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

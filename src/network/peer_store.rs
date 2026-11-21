// src/network/peer_store.rs
// In-memory peer candidate and reconnect-attempt store.

use crate::config::Config;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
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

/// Records a store keeps unless `[network.persistence].max_entries` says otherwise.
pub const DEFAULT_MAX_ENTRIES: usize = 1024;

#[derive(Clone)]
pub struct PeerStore {
    inner: Arc<RwLock<HashMap<SocketAddr, PeerRecord>>>,
    reconnect_attempts: Arc<RwLock<HashMap<SocketAddr, u32>>>,
    /// Records kept at runtime, not only when loading from disk.
    max_entries: usize,
}

impl Default for PeerStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerStore {
    pub fn new() -> Self {
        Self::with_max_entries(DEFAULT_MAX_ENTRIES)
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            reconnect_attempts: Arc::new(RwLock::new(HashMap::new())),
            max_entries: max_entries.max(1),
        }
    }

    /// Make room for one more record. A full store drops a candidate this node
    /// has never connected to, gossiped ones first; it returns `false` when
    /// every record is a node this node has reached.
    fn make_room(map: &mut HashMap<SocketAddr, PeerRecord>, max_entries: usize) -> bool {
        if map.len() < max_entries {
            return true;
        }
        let candidate = map
            .values()
            .filter(|record| record.last_success_epoch.is_none())
            .max_by_key(|record| (record.source == PeerSource::Gossip, record.failures))
            .map(|record| record.addr);
        candidate.is_some_and(|addr| map.remove(&addr).is_some())
    }

    fn insert_candidate(
        map: &mut HashMap<SocketAddr, PeerRecord>,
        max_entries: usize,
        addr: SocketAddr,
        source: PeerSource,
    ) {
        if map.contains_key(&addr) || !Self::make_room(map, max_entries) {
            return;
        }
        map.insert(
            addr,
            PeerRecord {
                addr,
                source,
                failures: 0,
                last_success_epoch: None,
                node_id: None,
                capabilities: None,
            },
        );
    }

    pub async fn insert(&self, addr: SocketAddr, source: PeerSource) {
        let mut map = self.inner.write().await;
        Self::insert_candidate(&mut map, self.max_entries, addr, source);
    }

    pub async fn bulk_insert<I: IntoIterator<Item = SocketAddr>>(&self, it: I, source: PeerSource) {
        let mut map = self.inner.write().await;
        for addr in it {
            Self::insert_candidate(&mut map, self.max_entries, addr, source);
        }
    }

    pub async fn mark_success(&self, addr: &SocketAddr) {
        let mut map = self.inner.write().await;
        if let Some(rec) = map.get_mut(addr) {
            rec.last_success_epoch = Some(Self::epoch());
            rec.failures = 0;
        }
        drop(map);
        self.reset_reconnect(addr).await;
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
            // A node just reached is worth more than any record: when nothing
            // unverified can go, drop the one reached longest ago.
            if !Self::make_room(&mut map, self.max_entries) {
                let oldest = map
                    .values()
                    .min_by_key(|record| record.last_success_epoch)
                    .map(|record| record.addr);
                if let Some(oldest) = oldest {
                    map.remove(&oldest);
                }
            }
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
        drop(map);
        self.reset_reconnect(addr).await;
    }

    pub async fn mark_failure(&self, addr: &SocketAddr) {
        let mut map = self.inner.write().await;
        if let Some(rec) = map.get_mut(addr) {
            rec.failures = rec.failures.saturating_add(1);
        }
    }

    /// Reserve the next reconnect attempt number, starting at one.
    ///
    /// Returns `None` when the configured consecutive-attempt budget is exhausted.
    pub async fn next_reconnect_attempt(
        &self,
        addr: &SocketAddr,
        max_attempts: u32,
    ) -> Option<u32> {
        let mut attempts = self.reconnect_attempts.write().await;
        let current = attempts.get(addr).copied().unwrap_or(0);
        if current >= max_attempts {
            return None;
        }
        let next = current.saturating_add(1);
        attempts.insert(*addr, next);
        Some(next)
    }

    pub async fn reset_reconnect(&self, addr: &SocketAddr) {
        self.reconnect_attempts.write().await.remove(addr);
    }

    pub async fn reconnect_attempts(&self, addr: &SocketAddr) -> u32 {
        self.reconnect_attempts
            .read()
            .await
            .get(addr)
            .copied()
            .unwrap_or(0)
    }

    /// Up to `k` random addresses this node has connected to, for answering
    /// `PEER_REQUEST`. Candidates it has only heard about are not passed on.
    pub async fn sample(&self, k: usize, exclude: &HashSet<SocketAddr>) -> Vec<SocketAddr> {
        let map = self.inner.read().await;
        let mut rng = rand::thread_rng();
        map.values()
            .filter(|r| r.last_success_epoch.is_some() && !exclude.contains(&r.addr))
            .map(|r| r.addr)
            .choose_multiple(&mut rng, k)
    }

    pub async fn all(&self) -> Vec<SocketAddr> {
        self.inner.read().await.keys().cloned().collect()
    }

    // Persistence API
    const DEFAULT_FILENAME: &str = "peers.json";

    pub async fn load_from_file(path: &str, ttl_secs: u64, max_entries: usize) -> Self {
        let store = Self::with_max_entries(max_entries);
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

    /// Write the store to `path`. The file is replaced, never rewritten in
    /// place, so an interrupted save leaves the previous file instead of an
    /// empty or truncated one that the next start would read as no peers.
    pub async fn save_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = {
            let map = self.inner.read().await;
            let mut entries: Vec<PeerRecord> = map.values().cloned().collect();
            // Prefer recent successes first
            entries.sort_by_key(|r| std::cmp::Reverse(r.last_success_epoch.unwrap_or(0)));
            serde_json::to_vec_pretty(&entries).map_err(std::io::Error::other)?
        };
        let path = path.to_string();
        tokio::task::spawn_blocking(move || replace_file(Path::new(&path), &json))
            .await
            .map_err(std::io::Error::other)?
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

/// How far an address reaches, from most to least local.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AddrScope {
    Loopback,
    LinkLocal,
    Private,
    Public,
}

/// `None` for addresses no peer can be reached at.
fn addr_scope(ip: IpAddr) -> Option<AddrScope> {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() {
                None
            } else if v4.is_loopback() {
                Some(AddrScope::Loopback)
            } else if v4.is_link_local() {
                Some(AddrScope::LinkLocal)
            } else if v4.is_private() || (v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64) {
                // RFC 1918 and carrier-grade NAT (100.64.0.0/10).
                Some(AddrScope::Private)
            } else {
                Some(AddrScope::Public)
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_multicast() {
                None
            } else if v6.is_loopback() {
                Some(AddrScope::Loopback)
            } else if v6.segments()[0] & 0xffc0 == 0xfe80 {
                Some(AddrScope::LinkLocal)
            } else if v6.segments()[0] & 0xfe00 == 0xfc00 {
                // Unique local addresses (fc00::/7).
                Some(AddrScope::Private)
            } else {
                Some(AddrScope::Public)
            }
        }
    }
}

/// Whether a `PEER_LIST` from the peer at `reporter` may add `candidate`: an
/// address no more local than the reporter itself. A peer on a public address
/// can only name public addresses, so it cannot point this node at its own
/// LAN or loopback services; a peer on the LAN can name LAN and public ones.
pub fn gossip_addr_allowed(candidate: SocketAddr, reporter: SocketAddr) -> bool {
    if candidate.port() == 0 {
        return false;
    }
    match (addr_scope(candidate.ip()), addr_scope(reporter.ip())) {
        (Some(candidate), Some(reporter)) => candidate >= reporter,
        _ => false,
    }
}

/// Replace the file at `path` with `bytes`, so that readers and the next
/// start after a crash see the old content or the new, never part of it: the
/// bytes go to a temporary file in the same directory, which is synced and
/// renamed over `path`. The new file keeps the permissions of the old one.
fn replace_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} names no file", path.display()),
        )
    })?;
    std::fs::create_dir_all(dir)?;
    let temp = dir.join(format!(
        ".{}.{}-{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        if let Ok(existing) = std::fs::metadata(path) {
            file.set_permissions(existing.permissions())?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
        return written;
    }
    // The rename survives a power loss once the directory is synced. Not every
    // file system can sync a directory, and the new file is in place already.
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn gossip_addresses_must_be_no_more_local_than_the_reporter() {
        let public = addr("198.51.100.4:50000");
        let lan = addr("192.168.1.20:50000");
        let loopback = addr("127.0.0.1:50000");
        for candidate in ["203.0.113.9:1234", "[2001:db8::1]:1234"] {
            assert!(gossip_addr_allowed(addr(candidate), public), "{candidate}");
            assert!(gossip_addr_allowed(addr(candidate), lan), "{candidate}");
        }
        for candidate in [
            "10.0.0.5:22",
            "100.64.1.1:22",
            "169.254.0.1:22",
            "127.0.0.1:22",
            "[fd00::1]:22",
            "[fe80::1]:22",
            "[::1]:22",
            "[::ffff:10.0.0.5]:22",
        ] {
            assert!(!gossip_addr_allowed(addr(candidate), public), "{candidate}");
        }
        assert!(gossip_addr_allowed(addr("10.0.0.5:50000"), lan));
        assert!(!gossip_addr_allowed(addr("127.0.0.1:50000"), lan));
        assert!(gossip_addr_allowed(addr("10.0.0.5:50000"), loopback));
        for never in [
            "0.0.0.0:50000",
            "255.255.255.255:50000",
            "224.0.0.1:50000",
            "[ff02::1]:50000",
            "203.0.113.9:0",
        ] {
            assert!(!gossip_addr_allowed(addr(never), loopback), "{never}");
        }
    }

    #[tokio::test]
    async fn full_store_keeps_reached_nodes_and_drops_unverified_candidates() {
        let store = PeerStore::with_max_entries(2);
        let reached = addr("198.51.100.1:1");
        store.insert(reached, PeerSource::Bootstrap).await;
        store.mark_success(&reached).await;
        store
            .insert(addr("198.51.100.2:1"), PeerSource::Gossip)
            .await;
        // Full: a new candidate replaces the unverified one, never the reached one.
        store
            .insert(addr("198.51.100.3:1"), PeerSource::Gossip)
            .await;
        let all: HashSet<_> = store.all().await.into_iter().collect();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&reached));

        // Only reached nodes are shared with other peers.
        let shared = store.sample(10, &HashSet::new()).await;
        assert_eq!(shared, vec![reached]);

        // A newly reached node still gets in when everything else was reached.
        store.mark_success(&addr("198.51.100.3:1")).await;
        let newly = addr("198.51.100.4:1");
        store.mark_success_with_meta(&newly, None, None).await;
        let all: HashSet<_> = store.all().await.into_iter().collect();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&newly));
    }

    /// Regression test: the store was saved by truncating the file and
    /// writing it again, so a reader, or a start after an interrupted save,
    /// could see an empty or partial file and load no peers.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saving_replaces_the_file_whole() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join(PeerStore::DEFAULT_FILENAME);
        let path_str = path.to_str().unwrap().to_string();
        let store = PeerStore::with_max_entries(4096);
        for i in 0..2000u16 {
            let candidate = addr(&format!("198.51.{}.{}:{}", i / 250, i % 250 + 1, 40000 + i));
            store.insert(candidate, PeerSource::Gossip).await;
        }
        store.save_to_file(&path_str).await.unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let (path, stop) = (path.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut reads = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    let bytes = std::fs::read(&path).expect("the file is always there");
                    let entries: Vec<PeerRecord> =
                        serde_json::from_slice(&bytes).expect("a partial store was visible");
                    assert_eq!(entries.len(), 2000);
                    reads += 1;
                }
                reads
            })
        };
        for _ in 0..50 {
            store.save_to_file(&path_str).await.unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the saved file keeps its permissions");
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            [PeerStore::DEFAULT_FILENAME],
            "no temporary file is left"
        );
        let loaded = PeerStore::load_from_file(&path_str, u64::MAX, 4096).await;
        assert_eq!(loaded.all().await.len(), 2000);
    }
}

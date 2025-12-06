use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

use thenodes::events::{
    dispatcher,
    model::{LogEvent, SystemEvent},
    sink::LogSink,
};
use thenodes::network::peer::Peer;
use thenodes::network::peer_manager::PeerManager;
use thenodes::network::peer_store::PeerStore;
use thenodes::plugin_host::manager::PluginManager;
use thenodes::realms::RealmInfo;

struct MemorySink {
    events: Arc<Mutex<Vec<LogEvent>>>,
}

#[async_trait::async_trait]
impl LogSink for MemorySink {
    async fn handle(&self, event: &LogEvent) {
        self.events.lock().push(event.clone());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_id_self_and_duplicate_rejections() {
    // Init memory sink for events
    let mem = Arc::new(MemorySink {
        events: Arc::new(Mutex::new(Vec::new())),
    });
    dispatcher::init_events(vec![mem.clone()], 64).await;

    // Prepare shared components
    let realm = RealmInfo::new("uniq-test", "1");
    let peer_manager = PeerManager::new();
    let plugin_manager = Arc::new(PluginManager::new());
    let cfg = thenodes::config::Config {
        port: 39210,
        ..Default::default()
    };

    // Spawn listener with node id A
    let realm_listener = realm.clone();
    let pm_listener = peer_manager.clone();
    let pm_plugins = plugin_manager.clone();
    let cfg_clone = cfg.clone();
    let peer_store = PeerStore::new();
    tokio::spawn(async move {
        if let Err(e) = thenodes::network::listener::start_listener(
            cfg_clone.port,
            realm_listener,
            pm_listener,
            pm_plugins,
            &cfg_clone,
            "node-A".to_string(),
            peer_store,
            true,
        )
        .await
        {
            eprintln!("Listener error: {}", e);
        }
    });

    // Allow listener start
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 1. Self-id rejection: connect outbound using same node id as listener
    let peer = Peer {
        id: "srv".into(),
        address: format!("127.0.0.1:{}", cfg.port),
    };
    let res_self = thenodes::network::transport::connect_to_peer(
        thenodes::network::transport::ConnectToPeerParams {
            peer: &peer,
            our_realm: realm.clone(),
            our_port: cfg.port,
            peer_manager: peer_manager.clone(),
            plugin_manager: plugin_manager.clone(),
            allow_console: false,
            config: cfg.clone(),
            local_node_id: "node-A".into(),
        },
    )
    .await;
    assert!(res_self.is_err(), "expected self-id rejection");
    let err_txt = format!("{:?}", res_self.err());
    assert!(
        err_txt.contains("matches our own"),
        "unexpected error: {}",
        err_txt
    );

    // 2. Successful connect with different node id B (spawned to avoid blocking receive loop)
    let pm_for_wait = peer_manager.clone();
    let realm2 = realm.clone();
    let plugin2 = plugin_manager.clone();
    let cfg2 = cfg.clone();
    let peer_for_ok = peer.clone();
    let handle_ok = tokio::spawn(async move {
        let _ = thenodes::network::transport::connect_to_peer(
            thenodes::network::transport::ConnectToPeerParams {
                peer: &peer_for_ok,
                our_realm: realm2,
                our_port: cfg.port,
                peer_manager: pm_for_wait.clone(),
                plugin_manager: plugin2,
                allow_console: false,
                config: cfg2,
                local_node_id: "node-B".into(),
            },
        )
        .await;
    });
    // Wait until outbound side registers the remote (node-A) or timeout
    let mut waited = 0u32;
    loop {
        if peer_manager.has_node_id("node-A").await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += 1;
        if waited > 40 {
            break;
        } // ~2s
    }

    // 3. Duplicate suppression (same remote node id already registered) using node id C locally
    // Expect Ok(()) with an event indicating suppression
    let res_dup = tokio::time::timeout(
        Duration::from_secs(5),
        thenodes::network::transport::connect_to_peer(
            thenodes::network::transport::ConnectToPeerParams {
                peer: &peer,
                our_realm: realm.clone(),
                our_port: cfg.port,
                peer_manager: peer_manager.clone(),
                plugin_manager: plugin_manager.clone(),
                allow_console: false,
                config: cfg.clone(),
                local_node_id: "node-C".into(),
            },
        ),
    )
    .await
    .expect("duplicate connect timed out");
    assert!(
        res_dup.is_ok(),
        "expected duplicate connect to be suppressed and return Ok, got: {:?}",
        res_dup.err()
    );

    // Allow events to flush
    tokio::time::sleep(Duration::from_millis(150)).await;
    let evts = mem.events.lock();
    let self_evt = evts.iter().filter(|e| matches!(e, LogEvent::System(SystemEvent { action, .. }) if action == "peer_reject_self_id")).count();
    let sup_already = evts.iter().filter(|e| matches!(e, LogEvent::System(SystemEvent { action, .. }) if action == "peer_already_connected")).count();
    let sup_cross = evts.iter().filter(|e| matches!(e, LogEvent::System(SystemEvent { action, .. }) if action == "peer_cross_connect_suppressed")).count();
    assert!(
        self_evt >= 1,
        "expected at least one peer_reject_self_id event, got {} (events = {:?})",
        self_evt,
        evts.len()
    );
    assert!(sup_already + sup_cross >= 1, "expected a suppression event (peer_already_connected or peer_cross_connect_suppressed); events = {:?}", evts.len());

    // Cleanup background client task
    handle_ok.abort();
}

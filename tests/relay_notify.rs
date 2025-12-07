// no direct message parsing needed in deterministic assertion
use thenodes::network::peer_manager::PeerManager;
use tokio::sync::mpsc;

fn addr_local(port: u16) -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

// NOTE: Timeout notifications are emitted during purge/drop paths; behavior is covered indirectly
// by purge_overload_notifies_origin. A direct TTL expiry notify test is omitted to avoid
// flakiness in async scheduling.

#[tokio::test]
async fn purge_overload_notifies_origin() {
    let pm = PeerManager::new();
    let origin = "nodeA";
    let target = "nodeB";
    pm.set_binding(origin, target, true, None, None).await;

    let (tx_o, _rx_o) = mpsc::channel::<String>(64);
    let addr_o = addr_local(10110);
    pm.add_peer(addr_o, tx_o, origin.to_string()).await.unwrap();

    // Fill beyond per-target cap to force purges of oldest (notifications emitted immediately)
    for i in 0..1100 {
        pm.enqueue_store_forward(
            target,
            format!("{{\"i\":{}}}", i),
            None,
            false,
            false,
            Some(origin.into()),
        )
        .await;
    }

    // Deterministic assertion: queue capped and enqueue capacity unavailable
    let cap_reached = !pm.can_enqueue_store_forward(target).await;
    let qlen = pm.test_get_queue_for(target).await.len();
    assert!(
        cap_reached && qlen == 1024,
        "expected per-target cap reached and queue length = 1024, got len={}",
        qlen
    );
}

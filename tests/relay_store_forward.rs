use std::net::SocketAddr;
use thenodes::network::peer_manager::PeerManager;
use tokio::sync::mpsc;

fn addr_local(port: u16) -> SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

#[tokio::test]
async fn relay_store_forward_delivers_on_connect() {
    let pm = PeerManager::new();

    // Bind from A -> B with store-forward enabled, no expiry
    pm.set_binding("nodeA", "nodeB", true, None, None).await;

    // Enqueue a frame targeting B while B is offline
    pm.enqueue_store_forward(
        "nodeB",
        "{\"dummy\":1}".to_string(),
        None,
        false,
        false,
        None,
    )
    .await;

    // Connect B and drain the queue
    let (tx, mut rx) = mpsc::channel::<String>(8);
    let addr_b = addr_local(10001);
    pm.add_peer(addr_b, tx, "nodeB".to_string()).await.unwrap();

    // Expect one frame delivered
    let got = rx.recv().await.expect("expected one forwarded frame");
    assert!(got.contains("dummy"));
}

#[tokio::test]
async fn relay_store_forward_respects_expiry() {
    let pm = PeerManager::new();

    // Small TTL: expires quickly
    let now = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let expires = now + 1; // 1 second TTL

    pm.set_binding("nodeA", "nodeB", true, Some(expires), None)
        .await;
    pm.enqueue_store_forward(
        "nodeB",
        "{\"ttl\":1}".to_string(),
        Some(expires),
        false,
        false,
        None,
    )
    .await;

    // Wait past expiry
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Connect B; expired frames should be purged and not delivered
    let (tx, mut rx) = mpsc::channel::<String>(8);
    let addr_b = addr_local(10002);
    pm.add_peer(addr_b, tx, "nodeB".to_string()).await.unwrap();

    // No frames should be delivered; timeout quickly
    let res = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(res.is_err(), "expired frames should not be delivered");
}

#[tokio::test]
async fn relay_store_forward_per_target_cap_drops_oldest() {
    let pm = PeerManager::new();

    // Enable store-forward
    pm.set_binding("nodeA", "nodeB", true, None, None).await;

    // Enqueue more than per-target cap (1024) to ensure oldest-drop kicks in
    let over = 1030usize;
    for i in 0..over {
        pm.enqueue_store_forward(
            "nodeB",
            format!("{{\"seq\":{}}}", i),
            None,
            false,
            false,
            None,
        )
        .await;
    }

    // Connect B and drain
    let (tx, mut rx) = mpsc::channel::<String>(1200);
    let addr_b = addr_local(10003);
    pm.add_peer(addr_b, tx, "nodeB".to_string()).await.unwrap();

    // Expect only the most recent 1024 frames delivered
    let mut frames: Vec<String> = Vec::new();
    while let Ok(msg) = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await
    {
        if let Some(m) = msg {
            frames.push(m);
        } else {
            break;
        }
        if frames.len() >= 1024 {
            break;
        }
    }
    assert_eq!(frames.len(), 1024, "should deliver up to per-target cap");
    // Oldest dropped: first delivered should be over - 1024
    let first_expected = over as i64 - 1024;
    let last_expected = over as i64 - 1;
    let first_seq: i64 = serde_json::from_str::<serde_json::Value>(&frames[0]).unwrap()["seq"]
        .as_i64()
        .unwrap();
    let last_seq: i64 = serde_json::from_str::<serde_json::Value>(&frames[1023]).unwrap()["seq"]
        .as_i64()
        .unwrap();
    assert_eq!(first_seq, first_expected);
    assert_eq!(last_seq, last_expected);
}

#[tokio::test]
async fn relay_store_forward_global_cap_limits_total() {
    let pm = PeerManager::new();
    pm.set_binding("nodeA", "nodeB1", true, None, None).await;
    pm.set_binding("nodeA", "nodeB2", true, None, None).await;
    pm.set_binding("nodeA", "nodeB3", true, None, None).await;
    pm.set_binding("nodeA", "nodeB4", true, None, None).await;
    pm.set_binding("nodeA", "nodeB5", true, None, None).await;
    pm.set_binding("nodeA", "nodeB6", true, None, None).await;
    pm.set_binding("nodeA", "nodeB7", true, None, None).await;
    pm.set_binding("nodeA", "nodeB8", true, None, None).await;
    pm.set_binding("nodeA", "nodeB9", true, None, None).await;

    // Fill 9 targets; per-target cap keeps each at 1024; total would be 9216 > global cap 8192
    for t in 1..=9 {
        let to = format!("nodeB{}", t);
        for i in 0..1300 {
            // attempt to enqueue more than per-target cap
            pm.enqueue_store_forward(
                &to,
                format!("{{\"t\":{},\"i\":{}}}", t, i),
                None,
                false,
                false,
                None,
            )
            .await;
        }
    }

    // Connect all and drain counts
    let mut rxs: Vec<mpsc::Receiver<String>> = Vec::new();
    for t in 1..=9 {
        let (tx, rx) = mpsc::channel::<String>(1400);
        let addr = addr_local(11000 + t);
        let node_id = format!("nodeB{}", t);
        pm.add_peer(addr, tx, node_id).await.unwrap();
        rxs.push(rx);
    }

    // Collect all delivered frames with a timeout
    let mut total = 0usize;
    for rx in rxs.iter_mut() {
        loop {
            match tokio::time::timeout(std::time::Duration::from_millis(10), rx.recv()).await {
                Ok(Some(_m)) => total += 1,
                _ => break,
            }
            if total >= 9000 {
                break;
            }
        }
    }
    assert_eq!(
        total, 8192,
        "global cap should limit total delivered frames to 8192"
    );
}

#[tokio::test]
async fn relay_store_forward_global_cap_affects_distribution() {
    let pm = PeerManager::new();
    // Bind 9 targets
    for t in 1..=9 {
        pm.set_binding("nodeA", &format!("nodeB{}", t), true, None, None)
            .await;
    }
    // Enqueue 1300 per target
    for t in 1..=9 {
        let to = format!("nodeB{}", t);
        for i in 0..1300 {
            pm.enqueue_store_forward(
                &to,
                format!("{{\"t\":{},\"i\":{}}}", t, i),
                None,
                false,
                false,
                None,
            )
            .await;
        }
    }
    // Connect all
    let mut rxs: Vec<(usize, mpsc::Receiver<String>)> = Vec::new();
    for t in 1..=9 {
        let (tx, rx) = mpsc::channel::<String>(1400);
        let addr = addr_local(12000 + t);
        let node_id = format!("nodeB{}", t);
        pm.add_peer(addr, tx, node_id).await.unwrap();
        rxs.push((t as usize, rx));
    }
    // Count per-target deliveries
    let mut per_target: [usize; 9] = [0; 9];
    for (idx, rx) in rxs.iter_mut() {
        loop {
            match tokio::time::timeout(std::time::Duration::from_millis(5), rx.recv()).await {
                Ok(Some(_)) => per_target[*idx - 1] += 1,
                _ => break,
            }
            if per_target[*idx - 1] >= 1024 {
                break;
            }
        }
    }
    // Some targets should be below 1024 due to global cap trimming
    let below_cap = per_target.iter().filter(|&&c| c < 1024).count();
    assert!(
        below_cap > 0,
        "global cap should reduce some targets below per-target cap"
    );
    // Total should still equal 8192
    let total: usize = per_target.iter().sum();
    assert_eq!(total, 8192);
}

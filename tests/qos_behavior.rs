use thenodes::network::peer_manager::PeerManager;

#[tokio::test]
async fn qos_priority_and_bulk_soft_drop() {
    let pm = PeerManager::new();
    // Set bindings with different QoS
    pm.set_binding("fromA", "toHT", true, None, Some("high_throughput".into()))
        .await;
    pm.set_binding("fromA", "toBulk", true, None, Some("bulk".into()))
        .await;

    // Enqueue enough items to hit per-target cap behavior
    // High throughput should be inserted at front
    for i in 0..10 {
        pm.enqueue_store_forward("toHT", format!("msg-ht-{}", i), None, true, false, None)
            .await;
    }
    // Bulk should soft-drop when at cap; simulate cap by pushing many first
    for i in 0..1024 {
        pm.enqueue_store_forward("toBulk", format!("msg-bulk-{}", i), None, false, true, None)
            .await;
    }
    // Add one more bulk; should be dropped silently
    pm.enqueue_store_forward("toBulk", "msg-bulk-extra".into(), None, false, true, None)
        .await;

    // Validate ordering for high throughput: newest at front
    let ht_q = pm.test_get_queue_for("toHT").await;
    assert_eq!(ht_q.first().unwrap().0, "msg-ht-9");
    assert_eq!(ht_q.last().unwrap().0, "msg-ht-0");
    let bulk_q = pm.test_get_queue_for("toBulk").await;
    // Bulk size should be capped at 1024; extra was soft-dropped
    assert_eq!(bulk_q.len(), 1024);
}

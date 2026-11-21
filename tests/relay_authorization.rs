//! Relay forwarding rules (ADR-0012): a relay forwards only for its
//! own peer's live bindings, only with that peer named as the tunnel's origin,
//! and only a binding's owner can remove it.

use std::net::SocketAddr;

use thenodes::network::message::{encode_relay_opaque_payload, Message, MessageType, Reason};
use thenodes::network::peer_manager::PeerManager;
use thenodes::network::relay::{
    handle_bind, handle_forward, handle_unbind, MAX_BINDINGS_PER_CLIENT,
};
use tokio::sync::mpsc;

struct Peer {
    addr: SocketAddr,
    rx: mpsc::Receiver<Message>,
}

impl Peer {
    fn drain(&mut self) -> Vec<Message> {
        std::iter::from_fn(|| self.rx.try_recv().ok()).collect()
    }
}

async fn connect(pm: &PeerManager, port: u16, node_id: &str) -> Peer {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (tx, rx) = mpsc::channel(8);
    pm.add_peer(addr, tx, node_id.to_string()).await.unwrap();
    Peer { addr, rx }
}

/// A `RELAY_FWD` frame from the relay's peer `sender` naming `origin`.
fn forward(sender: &str, origin: &str, target: &str) -> Message {
    Message::new(
        sender,
        "relay",
        MessageType::RelayForward {
            to: target.to_string(),
            from: origin.to_string(),
            sequence: None,
            opaque_payload_b64: encode_relay_opaque_payload("x"),
        },
        None,
        None,
    )
}

fn bind(sender: &str, target: &str) -> Message {
    Message::new(
        sender,
        "relay",
        MessageType::RelayBind {
            target: target.to_string(),
            want_store_forward: None,
            qos: None,
            nonce: Some(7),
            expires_at: None,
        },
        None,
        None,
    )
}

/// The `reason=` codes of the relay notifications in `messages`.
fn refusals(messages: &[Message]) -> Vec<(Reason, String)> {
    messages
        .iter()
        .filter_map(|message| match &message.msg_type {
            MessageType::RelayNotify {
                notif_type, detail, ..
            } => {
                let code = detail.as_deref()?.split("reason=").nth(1)?;
                Some((notif_type.clone(), code.to_string()))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn relay_forwards_only_for_the_senders_live_binding() {
    let pm = PeerManager::new();
    let mut client = connect(&pm, 13001, "node-a").await;
    let mut target = connect(&pm, 13002, "node-b").await;

    // Without a binding, and bound but naming another node as origin.
    handle_forward(
        &forward("node-a", "node-a", "node-b"),
        &client.addr,
        &pm,
        true,
        false,
        false,
    )
    .await;
    pm.set_binding("node-a", "node-b", false, None, None).await;
    pm.set_binding("node-c", "node-b", false, None, None).await;
    handle_forward(
        &forward("node-a", "node-c", "node-b"),
        &client.addr,
        &pm,
        true,
        false,
        false,
    )
    .await;
    assert!(target.drain().is_empty());
    assert_eq!(
        refusals(&client.drain()),
        [
            (Reason::PolicyDenied, "not-bound".to_string()),
            (Reason::PolicyDenied, "origin-mismatch".to_string()),
        ]
    );

    // The sender's own binding forwards, with the sender as origin.
    handle_forward(
        &forward("node-a", "node-a", "node-b"),
        &client.addr,
        &pm,
        true,
        false,
        false,
    )
    .await;
    let delivered = target.drain();
    assert_eq!(delivered.len(), 1);
    assert!(matches!(
        delivered[0].msg_type,
        MessageType::RelayForward { ref from, .. } if from == "node-a"
    ));

    // An expired binding forwards nothing, and can be replaced.
    pm.set_binding("node-a", "node-b", false, Some(1), None)
        .await;
    handle_forward(
        &forward("node-a", "node-a", "node-b"),
        &client.addr,
        &pm,
        true,
        false,
        false,
    )
    .await;
    assert!(target.drain().is_empty());
    assert_eq!(
        refusals(&client.drain()),
        [(Reason::Timeout, "binding-expired".to_string())]
    );
    handle_bind(
        &bind("node-a", "node-b"),
        &client.addr,
        &pm,
        true,
        false,
        false,
    )
    .await;
    assert!(client
        .drain()
        .iter()
        .any(|message| matches!(message.msg_type, MessageType::RelayBindAck { ok: true, .. })));
    handle_forward(
        &forward("node-a", "node-a", "node-b"),
        &client.addr,
        &pm,
        true,
        false,
        false,
    )
    .await;
    assert_eq!(target.drain().len(), 1);
}

#[tokio::test]
async fn only_the_owner_can_remove_a_binding() {
    let pm = PeerManager::new();
    let mut client = connect(&pm, 13011, "node-a").await;
    let other = connect(&pm, 13012, "node-c").await;

    handle_bind(
        &bind("node-a", "node-b"),
        &client.addr,
        &pm,
        true,
        false,
        false,
    )
    .await;
    let binding_id = client
        .drain()
        .into_iter()
        .find_map(|message| match message.msg_type {
            MessageType::RelayBindAck {
                ok: true,
                binding_id,
                ..
            } => binding_id,
            _ => None,
        })
        .expect("bind acknowledged with an id");
    // Not derived from the endpoints or the client's nonce.
    assert!(!binding_id.contains("node-a"));
    assert!(!binding_id.contains("node-b"));
    assert!(!binding_id.ends_with(":7"));

    let unbind = |sender: &str| {
        Message::new(
            sender,
            "relay",
            MessageType::RelayUnbind {
                binding_id: binding_id.clone(),
            },
            None,
            None,
        )
    };
    handle_unbind(&unbind("node-c"), &other.addr, &pm, false).await;
    assert!(pm.is_bound("node-a", "node-b").await);
    handle_unbind(&unbind("node-a"), &client.addr, &pm, false).await;
    assert!(!pm.is_bound("node-a", "node-b").await);
}

#[tokio::test]
async fn bindings_are_capped_per_client_and_end_with_its_connection() {
    let pm = PeerManager::new();
    let mut client = connect(&pm, 13021, "node-a").await;
    for i in 0..MAX_BINDINGS_PER_CLIENT {
        handle_bind(
            &bind("node-a", &format!("target-{i}")),
            &client.addr,
            &pm,
            true,
            false,
            false,
        )
        .await;
        client.drain();
    }
    handle_bind(
        &bind("node-a", "one-too-many"),
        &client.addr,
        &pm,
        true,
        false,
        false,
    )
    .await;
    assert!(client.drain().iter().any(|message| matches!(
        message.msg_type,
        MessageType::RelayBindAck {
            ok: false,
            reason: Some(Reason::Overload),
            ..
        }
    )));
    assert_eq!(
        pm.binding_count_from("node-a").await,
        MAX_BINDINGS_PER_CLIENT
    );

    // The client's bindings go with its connection.
    pm.remove_peer(&client.addr).await;
    assert_eq!(pm.binding_count_from("node-a").await, 0);
}

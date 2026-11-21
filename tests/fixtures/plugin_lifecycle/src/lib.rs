//! Native plugin fixture for the lifecycle integration tests.
//!
//! The library registers two handlers that share one library runtime:
//! `fixture.alpha` and `fixture.beta`. The `FIXTURE_MODE` environment variable,
//! read at registration, selects failure behavior. Each test scenario runs in
//! its own process, so the mode never changes while the library is loaded.
//!
//! Handlers report what they observe as plugin events through their context's
//! event handle, which submits to the host's dispatcher.

use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use thenodes::config::ConfigDefaults;
use thenodes::events::dispatcher::{self, EventHandle};
use thenodes::events::model::{LogEvent, LogLevel, PluginEvent};
use thenodes::network::delivery::{DeliveryClass, DeliveryOptions};
use thenodes::network::message::{Message, MessageType, Payload};
use thenodes::plugin_host::{
    NativeRegistrar, Plugin, PluginContext, PluginError, PluginRegistrationError,
};
use thenodes::realms::RealmInfo;

const ALPHA: &str = "fixture.alpha";
const BETA: &str = "fixture.beta";

fn mode() -> String {
    std::env::var("FIXTURE_MODE").unwrap_or_else(|_| "normal".to_string())
}

/// Signalled when `fixture.beta` enters its start hook, so a task of the
/// already started `fixture.alpha` can fail while startup is still running.
fn beta_starting() -> &'static tokio::sync::Notify {
    static BETA_STARTING: OnceLock<tokio::sync::Notify> = OnceLock::new();
    BETA_STARTING.get_or_init(tokio::sync::Notify::new)
}

fn thread_name() -> String {
    std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .to_string()
}

fn emit(events: &EventHandle, plugin: &str, action: &str, detail: String) {
    let meta = dispatcher::meta("fixture", LogLevel::Info);
    events.emit(LogEvent::Plugin(PluginEvent {
        meta,
        plugin: plugin.to_string(),
        action: action.to_string(),
        detail: Some(detail),
    }));
}

/// Emits an event when dropped, to observe future destruction.
struct DropSignal {
    events: EventHandle,
    action: &'static str,
}

impl Drop for DropSignal {
    fn drop(&mut self) {
        emit(&self.events, ALPHA, self.action, String::new());
    }
}

fn target_from(message: &Message) -> String {
    match &message.payload {
        Some(Payload::Json(value)) => value["to"].as_str().unwrap_or_default().to_string(),
        _ => String::new(),
    }
}

/// Spin without yielding. Only escalation and process exit end it.
fn spin_forever() -> ! {
    loop {
        std::hint::spin_loop();
    }
}

/// Block the worker thread. Only escalation and process exit end it.
fn block_forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

struct Alpha {
    mode: String,
}

impl Alpha {
    /// Exercise the plugin runtime: timer, interval, filesystem, and UDP.
    async fn runtime_proof(&self, ctx: &PluginContext) -> Result<String, PluginError> {
        let thread = thread_name();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let mut interval = tokio::time::interval(Duration::from_millis(2));
        interval.tick().await;
        interval.tick().await;

        let dir = ctx.plugin_data_dir().await?;
        tokio::fs::write(dir.join("probe.txt"), b"ok").await?;
        let fs_ok = tokio::fs::read(dir.join("probe.txt")).await? == b"ok";

        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        sender.send_to(b"ping", receiver.local_addr()?).await?;
        let mut buf = [0u8; 8];
        let (len, _) = receiver.recv_from(&mut buf).await?;
        let udp_ok = &buf[..len] == b"ping";

        Ok(format!(
            "thread={thread} timer=ok interval=ok fs={fs_ok} udp={udp_ok} low_level={} node_id={} plugin_id={}",
            ctx.peer_manager().is_some(),
            ctx.local_node_id,
            ctx.plugin_id().unwrap_or("none"),
        ))
    }
}

#[async_trait]
impl Plugin for Alpha {
    fn plugin_id(&self) -> &'static str {
        ALPHA
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        Some(&[
            "fixture.stall",
            "fixture.panic",
            "fixture.send",
            "fixture.send-reliable",
        ])
    }

    fn prompt_prefix(&self) -> Option<&str> {
        Some("alpha")
    }

    fn early_config_defaults(&self) -> Option<ConfigDefaults> {
        (self.mode == "conflicting-defaults").then(|| ConfigDefaults {
            realm: Some(RealmInfo::new("fixture-a", "1")),
            ..Default::default()
        })
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        match self.mode.as_str() {
            "start-panic" => panic!("fixture start panic"),
            "start-error" => return Err(PluginError::new("fixture start error")),
            "hang-start-spin" => {
                // Announce that the hook is running, so the test does not
                // race a cancellation that lands before the first poll.
                emit(&ctx.events, ALPHA, "fixture_start_spinning", String::new());
                spin_forever()
            }
            _ => {}
        }
        let proof = self.runtime_proof(ctx).await?;
        emit(&ctx.events, ALPHA, "fixture_runtime_proof", proof);

        if self.mode == "start-task-panic" {
            ctx.spawn_task("fails-during-startup", |_task| async {
                beta_starting().notified().await;
                panic!("fixture task panic during startup");
            })
            .map_err(|error| PluginError::new(error.to_string()))?;
        }

        let events = ctx.events.clone();
        let mode = self.mode.clone();
        ctx.spawn_task("activation-waiter", move |task| async move {
            if task.activated().await.is_err() {
                return Ok(());
            }
            emit(
                &events,
                ALPHA,
                "fixture_task_activated",
                format!("thread={}", thread_name()),
            );
            match mode.as_str() {
                "task-panic" => panic!("fixture task panic"),
                "task-error" => return Err(PluginError::new("fixture task error")),
                _ => {}
            }
            task.cancelled().await;
            emit(&events, ALPHA, "fixture_task_cancelled", String::new());
            Ok(())
        })
        .map_err(|error| PluginError::new(error.to_string()))?;
        Ok(())
    }

    async fn on_message(&self, message: &Message, ctx: &PluginContext) {
        let MessageType::Extension { kind } = &message.msg_type else {
            return;
        };
        match kind.as_str() {
            "fixture.stall" => {
                let _signal = DropSignal {
                    events: ctx.events.clone(),
                    action: "fixture_stall_dropped",
                };
                emit(&ctx.events, ALPHA, "fixture_stalled", String::new());
                std::future::pending::<()>().await;
            }
            "fixture.panic" => panic!("fixture message panic"),
            "fixture.send" => {
                let to = target_from(message);
                let hello = Message::new(
                    "",
                    &to,
                    MessageType::Extension {
                        kind: "fixture.hello".to_string(),
                    },
                    Some(Payload::Json(json!({ "thread": thread_name() }))),
                    None,
                );
                let outcome = ctx
                    .send_message(
                        &to,
                        hello,
                        DeliveryOptions::new(DeliveryClass::FireAndForget),
                    )
                    .await;
                emit(
                    &ctx.events,
                    ALPHA,
                    "fixture_send_outcome",
                    format!("outcome={outcome:?}"),
                );
            }
            "fixture.send-reliable" => {
                let to = target_from(message);
                let probe = Message::new(
                    "",
                    &to,
                    MessageType::Extension {
                        kind: "fixture.hello".to_string(),
                    },
                    None,
                    None,
                );
                emit(&ctx.events, ALPHA, "fixture_send_started", String::new());
                let outcome = ctx
                    .send_message(
                        &to,
                        probe,
                        DeliveryOptions::new(DeliveryClass::Reliable)
                            .with_retry_budget(6)
                            .with_timeout(Duration::from_secs(30)),
                    )
                    .await;
                emit(
                    &ctx.events,
                    ALPHA,
                    "fixture_send_finished",
                    format!("outcome={outcome:?}"),
                );
            }
            _ => {}
        }
    }

    async fn on_prompt(&self, input: &str, ctx: &PluginContext) -> Option<String> {
        match input {
            "panic" => panic!("fixture prompt panic"),
            "wait" => {
                let _signal = DropSignal {
                    events: ctx.events.clone(),
                    action: "fixture_prompt_dropped",
                };
                emit(&ctx.events, ALPHA, "fixture_prompt_waiting", String::new());
                std::future::pending::<()>().await;
                None
            }
            other => Some(format!("alpha:{other} thread={}", thread_name())),
        }
    }

    async fn on_stop(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        match self.mode.as_str() {
            "stop-panic" => panic!("fixture stop panic"),
            "stop-error" => Err(PluginError::new("fixture stop error")),
            "hang-stop-spin" => spin_forever(),
            "hang-stop-block" => block_forever(),
            _ => {
                emit(&ctx.events, ALPHA, "fixture_stopped", String::new());
                Ok(())
            }
        }
    }
}

struct Beta {
    mode: String,
}

#[async_trait]
impl Plugin for Beta {
    fn plugin_id(&self) -> &'static str {
        BETA
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        Some(&["fixture.ping"])
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        if self.mode == "start-task-panic" {
            beta_starting().notify_one();
            emit(
                &ctx.events,
                BETA,
                "fixture_beta_start_waiting",
                String::new(),
            );
            // Cooperative: returns only when startup is cancelled.
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    fn early_config_defaults(&self) -> Option<ConfigDefaults> {
        (self.mode == "conflicting-defaults").then(|| ConfigDefaults {
            realm: Some(RealmInfo::new("fixture-b", "1")),
            ..Default::default()
        })
    }

    async fn on_message(&self, _message: &Message, ctx: &PluginContext) {
        emit(
            &ctx.events,
            BETA,
            "fixture_pong",
            format!("thread={}", thread_name()),
        );
    }

    async fn on_stop(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        emit(&ctx.events, BETA, "fixture_stopped", String::new());
        Ok(())
    }
}

/// A handler whose ID the host must reject.
struct InvalidId;

#[async_trait]
impl Plugin for InvalidId {
    fn plugin_id(&self) -> &'static str {
        "fixture/invalid"
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}
}

fn register(registrar: &mut NativeRegistrar) -> Result<(), PluginRegistrationError> {
    let mode = mode();
    match mode.as_str() {
        "register-panic" => panic!("fixture registration panic"),
        "register-error" => {
            return Err(PluginRegistrationError::Plugin(
                "fixture registration error".to_string(),
            ))
        }
        "empty" => return Ok(()),
        "zero-workers" => registrar.set_runtime_workers(0)?,
        _ => registrar.set_runtime_workers(2)?,
    }
    match mode.as_str() {
        "invalid-id" => registrar.register(Box::new(InvalidId)),
        "partial" => {
            registrar.register(Box::new(Alpha { mode: mode.clone() }));
            registrar.register(Box::new(InvalidId));
        }
        "duplicate-id" => {
            registrar.register(Box::new(Alpha { mode: mode.clone() }));
            registrar.register(Box::new(Alpha { mode: mode.clone() }));
        }
        _ => {
            registrar.register(Box::new(Alpha { mode: mode.clone() }));
            registrar.register(Box::new(Beta { mode }));
        }
    }
    Ok(())
}

thenodes::export_plugin!(register);

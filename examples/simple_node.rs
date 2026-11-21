// examples/simple_node.rs (Standalone App Using TheNodes in CAL mode)
//
// Shows the explicit plugin host lifecycle: register plugins, finalize the
// context, start, decide what to do about a failed plugin, activate, dispatch,
// and shut down. Networking is left out; a real host binds its required
// listeners between `start_all` and `activate`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thenodes::config::Config;
use thenodes::network::message::{Message, MessageType};
use thenodes::network::{PeerManager, PeerStore};
use thenodes::plugin_host::{
    Plugin, PluginContext, PluginError, PluginManager, PluginRegistrar, ShutdownMode, StartPolicy,
    StartResult,
};

/// Handles text messages and runs a managed background task.
struct Greeter;

#[async_trait]
impl Plugin for Greeter {
    fn plugin_id(&self) -> &'static str {
        "example.greeter"
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        // Background work belongs in the plugin's task scope. Sends are only
        // allowed after activation, so the task waits for it.
        ctx.spawn_task("greeter-status", |task| async move {
            if task.activated().await.is_err() {
                return Ok(());
            }
            println!("[greeter] host activated; background task running");
            task.cancelled().await;
            println!("[greeter] background task cancelled by shutdown");
            Ok(())
        })
        .map_err(|error| PluginError::new(error.to_string()))?;
        Ok(())
    }

    async fn on_message(&self, message: &Message, _ctx: &PluginContext) {
        if let MessageType::Text(text) = &message.msg_type {
            println!("[greeter] received: {text}");
        }
    }

    async fn on_stop(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        println!("[greeter] stopped");
        Ok(())
    }
}

/// An optional plugin whose initialization fails, for example because a local
/// resource is missing.
struct Cache;

#[async_trait]
impl Plugin for Cache {
    fn plugin_id(&self) -> &'static str {
        "example.cache"
    }

    async fn on_start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Err(PluginError::new("cache directory is not writable"))
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let mut manager = PluginManager::new();
    manager.register_handler(Box::new(Greeter))?;
    manager.register_handler(Box::new(Cache))?;
    // The context must hold the final configuration before startup.
    manager.set_context(PluginContext::new(
        Arc::new(PeerManager::new()),
        PeerStore::new(),
        thenodes::events::dispatcher::handle(),
        "example-node".to_string(),
        config,
        true,
    ));
    let manager = Arc::new(manager);

    let report = manager.start_all(StartPolicy::ContinueOnFailure).await?;
    for outcome in &report.outcomes {
        println!("start {}: {:?}", outcome.plugin_id, outcome.result);
    }

    // Failure policy belongs to the host. This host treats the cache as
    // optional and continues without it explicitly; any other failure stops it.
    for outcome in &report.outcomes {
        if let StartResult::Failed(failure) = &outcome.result {
            if failure.plugin_id == "example.cache" {
                println!("continuing without optional plugin: {failure}");
                manager.acknowledge_failure(&failure.plugin_id)?;
            } else {
                manager.shutdown(ShutdownMode::Discard).await?;
                return Err(failure.to_string().into());
            }
        }
    }

    // A real host binds its required listeners here, then activates.
    manager.activate()?;

    let dispatch = manager.dispatch_message(&Message::new(
        "peer",
        "example-node",
        MessageType::Text("hello".to_string()),
        None,
        None,
    ));
    println!(
        "dispatch admitted={} rejected={:?}",
        dispatch.admitted, dispatch.rejected
    );

    // TheNodes imposes no shutdown deadline. This application chooses one and
    // escalates if plugins do not finish in time.
    let shutdown = manager.begin_shutdown(ShutdownMode::Drain);
    let wait = shutdown.wait();
    tokio::pin!(wait);
    let report = tokio::select! {
        report = &mut wait => report?,
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            manager.escalate();
            wait.await?
        }
    };
    for plugin in &report.plugins {
        println!(
            "stop {}: state={:?} stop={:?}",
            plugin.plugin_id, plugin.final_state, plugin.stop
        );
    }
    Ok(())
}

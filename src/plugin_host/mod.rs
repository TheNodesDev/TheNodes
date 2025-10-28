pub mod loader;
pub mod manager;

pub use loader::{PluginApiError, PluginLoader, PluginRegistrarApi, PLUGIN_ABI_VERSION};
pub use manager::PluginManager;

use crate::network::message::Message;

use crate::events::dispatcher::EventHandle;
use crate::network::peer_manager::PeerManager;
use crate::network::PeerStore;
/// Trait that all plugins must implement.
use std::sync::Arc;

/// Context passed to plugins for host interaction (e.g., broadcasting)
pub struct PluginContext {
    pub peer_manager: Arc<PeerManager>,
    pub peer_store: PeerStore,
    pub events: EventHandle,
}

#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn on_message(&self, message: &Message, ctx: &PluginContext);

    /// Called when user enters a prompt for this plugin. Can return a response and optionally broadcast.
    async fn on_prompt(&self, _input: &str, _ctx: &PluginContext) -> Option<String> {
        None
    }

    fn prompt_prefix(&self) -> Option<&str> {
        None
    }

    /// Optional early configuration defaults hook.
    /// Lets a plugin supply default values (realm / port / app name / other config fields)
    /// before networking is initialized. Only used when the operator hasn't
    /// specified those fields explicitly. Pure, side‑effect free.
    /// Last plugin wins for the same field when multiple defaults are provided.
    fn early_config_defaults(&self) -> Option<crate::config::ConfigDefaults> {
        None
    }
}

/// Trait passed to plugins so they can register themselves.
pub trait PluginRegistrar {
    fn register_handler(&mut self, plugin: Box<dyn Plugin>);
}

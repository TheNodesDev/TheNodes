pub mod loader;
pub mod manager;

pub use loader::{PluginApiError, PluginLoader, PluginRegistrarApi, PLUGIN_ABI_VERSION};
pub use manager::PluginManager;

use crate::config::Config;
use crate::network::delivery::{DeliveryOptions, DeliveryOutcome, DeliveryRuntime};
use crate::network::message::Message;

use crate::events::dispatcher::EventHandle;
use crate::network::peer_manager::PeerManager;
use crate::network::PeerStore;
/// Trait that all plugins must implement.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Context passed to plugins for host interaction (e.g., broadcasting)
#[derive(Clone)]
pub struct PluginContext {
    pub peer_manager: Arc<PeerManager>,
    pub peer_store: PeerStore,
    pub events: EventHandle,
    pub local_node_id: String,
    pub config: Config,
    pub allow_console: bool,
    plugin_manager: Arc<RwLock<Option<Arc<PluginManager>>>>,
    plugin_id: Option<String>,
}

impl PluginContext {
    pub fn new(
        peer_manager: Arc<PeerManager>,
        peer_store: PeerStore,
        events: EventHandle,
        local_node_id: String,
        config: Config,
        allow_console: bool,
    ) -> Self {
        Self {
            peer_manager,
            peer_store,
            events,
            local_node_id,
            config,
            allow_console,
            plugin_manager: Arc::new(RwLock::new(None)),
            plugin_id: None,
        }
    }

    pub async fn set_plugin_manager(&self, plugin_manager: Arc<PluginManager>) {
        *self.plugin_manager.write().await = Some(plugin_manager);
    }

    pub fn for_plugin(&self, plugin_id: &str) -> io::Result<Self> {
        Self::validate_plugin_id(plugin_id)?;
        let mut ctx = self.clone();
        ctx.plugin_id = Some(plugin_id.to_string());
        Ok(ctx)
    }

    pub fn plugin_id(&self) -> Option<&str> {
        self.plugin_id.as_deref()
    }

    pub async fn plugin_data_dir(&self) -> io::Result<PathBuf> {
        let plugin_id = self.plugin_id.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "plugin data dir requires a plugin-bound context",
            )
        })?;
        let dir = self.node_data_dir().join("plugins").join(plugin_id);
        tokio::fs::create_dir_all(&dir).await?;
        Ok(dir)
    }

    fn node_data_dir(&self) -> PathBuf {
        self.config
            .node
            .as_ref()
            .and_then(|node| node.state_dir.as_ref())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data"))
    }

    pub(crate) fn validate_plugin_id(plugin_id: &str) -> io::Result<()> {
        if plugin_id.is_empty() || plugin_id.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plugin IDs must be 1-128 characters long",
            ));
        }
        if matches!(plugin_id, "." | "..")
            || !plugin_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plugin IDs may only contain ASCII letters, numbers, '.', '-' or '_'",
            ));
        }
        Ok(())
    }

    pub async fn deliver_message(
        &self,
        message: Message,
        options: DeliveryOptions,
    ) -> DeliveryOutcome {
        let plugin_manager = self.plugin_manager.read().await.clone();
        let Some(plugin_manager) = plugin_manager else {
            return DeliveryOutcome::DeliveryFailed {
                reason: crate::network::delivery::DeliveryFailureReason::PolicyDenied,
            };
        };

        DeliveryRuntime::new(
            (*self.peer_manager).clone(),
            plugin_manager,
            self.config.clone(),
            self.local_node_id.clone(),
            Some(self.peer_store.clone()),
            self.allow_console,
        )
        .deliver_message(message, options)
        .await
    }

    pub async fn send_message(
        &self,
        to: &str,
        message: Message,
        options: DeliveryOptions,
    ) -> DeliveryOutcome {
        let mut outbound = message;
        outbound.from = self.local_node_id.clone();
        outbound.to = to.to_string();
        self.deliver_message(outbound, options).await
    }
}

#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn plugin_id(&self) -> &'static str;

    async fn on_message(&self, message: &Message, ctx: &PluginContext);

    /// Extension kinds this plugin wants to receive.
    ///
    /// `None` preserves the default behavior of receiving every extension kind.
    /// `Some(&[])` opts out of all extension messages.
    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        None
    }

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

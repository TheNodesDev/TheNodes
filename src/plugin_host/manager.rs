use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::{Plugin, PluginContext, PluginRegistrar};
use crate::events::model::{LogEvent, LogLevel, SystemEvent};
use crate::network::message::{Message, MessageType};

/// Upper bound on how long a single plugin's `on_message` may run before dispatch
/// gives up on it and moves on. Without this, one slow or hung plugin could stall
/// message processing indefinitely for every other plugin and, on the UDP receive
/// path, for every other peer on the node.
const PLUGIN_DISPATCH_TIMEOUT: Duration = Duration::from_secs(5);

struct RegisteredPlugin {
    id: String,
    plugin: Arc<dyn Plugin>,
}

pub struct PluginManager {
    plugins: Vec<RegisteredPlugin>,
    prompt_map: HashMap<String, usize>,
    pub context: Option<PluginContext>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            prompt_map: HashMap::new(),
            context: None,
        }
    }

    pub fn with_context(context: PluginContext) -> Self {
        Self {
            plugins: Vec::new(),
            prompt_map: HashMap::new(),
            context: Some(context),
        }
    }

    pub async fn dispatch_message(&self, message: &Message) {
        if let Some(ctx) = &self.context {
            for registered in &self.plugins {
                let Ok(plugin_ctx) = ctx.for_plugin(&registered.id) else {
                    continue;
                };
                let accepts_message = match &message.msg_type {
                    MessageType::Extension { kind } => {
                        match registered.plugin.subscribed_extension_kinds() {
                            Some(kinds) => kinds.contains(&kind.as_str()),
                            None => true,
                        }
                    }
                    _ => true,
                };

                if accepts_message {
                    let dispatch = tokio::time::timeout(
                        PLUGIN_DISPATCH_TIMEOUT,
                        registered.plugin.on_message(message, &plugin_ctx),
                    );
                    if dispatch.await.is_err() {
                        let mut meta =
                            crate::events::dispatcher::meta("plugin_host", LogLevel::Warn);
                        meta.corr_id = Some(crate::events::dispatcher::correlation_id());
                        ctx.events.emit(LogEvent::System(SystemEvent {
                            meta,
                            action: "plugin_dispatch_timeout".to_string(),
                            detail: Some(format!(
                                "plugin={} timeout_ms={}",
                                registered.id,
                                PLUGIN_DISPATCH_TIMEOUT.as_millis()
                            )),
                        }));
                    }
                }
            }
        }
    }

    pub fn get_prompt_plugin(&self, prefix: &str) -> Option<(Arc<dyn Plugin>, PluginContext)> {
        let index = *self.prompt_map.get(prefix)?;
        let registered = self.plugins.get(index)?;
        let context = self.context.as_ref()?.for_plugin(&registered.id).ok()?;
        Some((registered.plugin.clone(), context))
    }

    pub fn all_prompt_prefixes(&self) -> Vec<String> {
        self.prompt_map.keys().cloned().collect()
    }

    /// Collect configuration defaults from all plugins. Last plugin wins on conflicts.
    pub fn collect_config_defaults(&self) -> crate::config::ConfigDefaults {
        let mut merged = crate::config::ConfigDefaults::default();
        for registered in &self.plugins {
            if let Some(over) = registered.plugin.early_config_defaults() {
                if let Some(v) = over.port {
                    merged.port = Some(v);
                }
                if let Some(v) = over.realm {
                    merged.realm = Some(v);
                }
                if let Some(v) = over.app_name {
                    merged.app_name = Some(v);
                }
                if let Some(v) = over.encryption {
                    merged.encryption = Some(v);
                }
                if let Some(v) = over.bootstrap_nodes {
                    merged.bootstrap_nodes = Some(v);
                }
                if let Some(v) = over.bootstrap_nodes_extend {
                    merged.bootstrap_nodes_extend = Some(v);
                }
                if let Some(v) = over.logging {
                    merged.logging = Some(v);
                }
                if let Some(v) = over.node {
                    merged.node = Some(v);
                }
                if let Some(v) = over.discovery {
                    merged.discovery = Some(v);
                }
            }
        }
        merged
    }
}

impl PluginRegistrar for PluginManager {
    fn register_handler(&mut self, plugin: Box<dyn Plugin>) {
        let plugin_id = plugin.plugin_id().to_string();
        if let Err(err) = PluginContext::validate_plugin_id(&plugin_id) {
            eprintln!("❌ Refusing to register plugin with invalid id '{plugin_id}': {err}");
            return;
        }
        if self
            .plugins
            .iter()
            .any(|registered| registered.id == plugin_id)
        {
            eprintln!(
                "❌ Refusing to register plugin with duplicate id '{plugin_id}': \
                 another registered plugin already owns this id and its data directory."
            );
            return;
        }

        println!("🔧 Registering plugin: {}.", plugin_id);
        let arc: Arc<dyn Plugin> = Arc::from(plugin);
        let index = self.plugins.len();

        // Register plugin for prompt mode if it supports it
        if let Some(prefix) = arc.prompt_prefix().map(str::to_string) {
            self.prompt_map.insert(prefix, index);
        }

        self.plugins.push(RegisteredPlugin {
            id: plugin_id,
            plugin: arc,
        });
    }
}

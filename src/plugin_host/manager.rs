use std::collections::HashMap;
use std::sync::Arc; // Mutex unused

use super::{Plugin, PluginContext, PluginRegistrar};
use crate::network::message::Message;

pub struct PluginManager {
    plugins: Vec<Arc<dyn Plugin>>,
    prompt_map: HashMap<String, Arc<dyn Plugin>>,
    pub context: Option<PluginContext>,
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

    pub fn dispatch_message(&self, message: &Message) {
        if let Some(ctx) = &self.context {
            for plugin in &self.plugins {
                plugin.on_message(message, ctx);
            }
        }
    }

    pub fn get_prompt_plugin(&self, prefix: &str) -> Option<Arc<dyn Plugin>> {
        self.prompt_map.get(prefix).cloned()
    }

    pub fn all_prompt_prefixes(&self) -> Vec<String> {
        self.prompt_map.keys().cloned().collect()
    }

    /// Collect configuration defaults from all plugins. Last plugin wins on conflicts.
    pub fn collect_config_defaults(&self) -> crate::config::ConfigDefaults {
        let mut merged = crate::config::ConfigDefaults::default();
        for p in &self.plugins {
            if let Some(over) = p.early_config_defaults() {
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
        println!("🔧 Registering plugin.");
        let arc: Arc<dyn Plugin> = Arc::from(plugin);

        // Register plugin for prompt mode if it supports it
        if let Some(prefix) = arc.prompt_prefix().map(str::to_string) {
            self.prompt_map.insert(prefix, arc.clone());
        }

        self.plugins.push(arc);
    }
}

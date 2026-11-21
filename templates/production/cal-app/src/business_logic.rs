use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thenodes::plugin_host::{Plugin, PluginContext, PluginError, TaskContext};
use thenodes::prelude::*;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Your custom business logic that integrates with TheNodes
#[derive(Clone)]
pub struct BusinessLogic {
    config: Config,
    state: Arc<RwLock<BusinessState>>,
}

#[derive(Debug, Clone)]
pub struct BusinessState {
    pub id: Uuid,
    pub data: std::collections::HashMap<String, String>,
    pub peer_count: usize,
}

impl BusinessLogic {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(BusinessState {
                id: Uuid::new_v4(),
                data: std::collections::HashMap::new(),
                peer_count: 0,
            })),
        }
    }

    /// Periodic status reporting. Runs as a managed task: it stops when the
    /// plugin's task scope is cancelled during shutdown.
    async fn report_status(state: Arc<RwLock<BusinessState>>, task: TaskContext) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let state_guard = state.read().await;
                    log::info!(
                        "📊 Status {}: {} data items, {} peers",
                        state_guard.id,
                        state_guard.data.len(),
                        state_guard.peer_count
                    );
                }
                _ = task.cancelled() => return,
            }
        }
    }

    /// Example of application-specific background work.
    async fn handle_business_events(state: Arc<RwLock<BusinessState>>, task: TaskContext) {
        // This is where you'd implement your custom business logic, for example
        // processing custom events or managing application-specific state.
        log::info!("💼 Business event handler started");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mut state = state.write().await;
                    let key = format!("data_{}", state.data.len());
                    let value = format!("value_at_{}", unix_timestamp());
                    state.data.insert(key.clone(), value.clone());
                    log::debug!("📝 Added: {} = {}", key, value);
                }
                _ = task.cancelled() => return,
            }
        }
    }

    /// Handle messages received from TheNodes network
    async fn handle_network_message(&self, message: &Message) {
        log::debug!("📨 Received message: {:?}", message);

        match &message.msg_type {
            MessageType::Extension { kind } if kind == "business_data" => {
                if let Some(Payload::Json(data)) = &message.payload {
                    self.handle_business_data(data).await;
                }
            }
            _ => {
                log::debug!("🔄 Ignoring non-business message: {:?}", message.msg_type);
            }
        }
    }

    async fn handle_business_data(&self, data: &serde_json::Value) {
        // Handle your custom business data
        log::info!("💼 Processing business data: {:?}", data);

        // Example: Store data from network
        if let (Some(key), Some(value)) = (
            data.get("key").and_then(|k| k.as_str()),
            data.get("value").and_then(|v| v.as_str()),
        ) {
            let mut state = self.state.write().await;
            state.data.insert(key.to_string(), value.to_string());
            log::info!("📝 Stored network data: {} = {}", key, value);
        }
    }
}

#[async_trait::async_trait]
impl Plugin for BusinessLogic {
    fn plugin_id(&self) -> &'static str {
        "business_logic"
    }

    /// Start background work in the plugin's managed task scope. The tasks
    /// wait for host activation and end when the scope is cancelled.
    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        log::info!(
            "🔧 Starting business logic for {}",
            self.config
                .app_name
                .as_ref()
                .unwrap_or(&"Unknown".to_string())
        );
        let state = self.state.clone();
        ctx.spawn_task("status", move |task| async move {
            if task.activated().await.is_ok() {
                Self::report_status(state, task).await;
            }
            Ok(())
        })
        .map_err(|error| PluginError::new(error.to_string()))?;
        let state = self.state.clone();
        ctx.spawn_task("business-events", move |task| async move {
            if task.activated().await.is_ok() {
                Self::handle_business_events(state, task).await;
            }
            Ok(())
        })
        .map_err(|error| PluginError::new(error.to_string()))?;
        Ok(())
    }

    async fn on_message(&self, message: &Message, _ctx: &PluginContext) {
        self.handle_network_message(message).await;
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        Some(&["business_data"])
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

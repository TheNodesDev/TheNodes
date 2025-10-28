use std::sync::Arc;
use tokio::sync::RwLock;
use thenodes::prelude::*;
use uuid::Uuid;

/// Your custom business logic that integrates with TheNodes
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

    /// Start your custom business logic
    pub async fn start(&self) {
        log::info!("🔧 Starting business logic for {}", self.config.app_name.as_ref().unwrap_or(&"Unknown".to_string()));

        // Example: Periodic task
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let state_guard = state.read().await;
                log::info!("📊 Status: {} data items, {} peers", 
                    state_guard.data.len(), 
                    state_guard.peer_count
                );
            }
        });

        // Example: Handle custom business events
        self.handle_business_events().await;
    }

    async fn handle_business_events(&self) {
        // This is where you'd implement your custom business logic
        // For example:
        // - Processing custom messages from peers
        // - Handling custom events
        // - Managing application-specific state
        
        log::info!("💼 Business event handler started");

        // Example custom logic
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            
            // Example: Add some data periodically
            {
                let mut state = self.state.write().await;
                let key = format!("data_{}", state.data.len());
                let value = format!("value_at_{}", chrono::Utc::now().timestamp());
                state.data.insert(key.clone(), value.clone());
                log::debug!("📝 Added: {} = {}", key, value);
            }
        }
    }

    /// Handle messages received from TheNodes network
    pub async fn handle_network_message(&self, message: Message) {
        log::debug!("📨 Received message: {:?}", message);
        
        match message.msg_type {
            MessageType::Custom(ref msg_type) if msg_type == "business_data" => {
                if let Some(Payload::Json(data)) = message.payload {
                    self.handle_business_data(data).await;
                }
            }
            _ => {
                log::debug!("🔄 Ignoring non-business message: {:?}", message.msg_type);
            }
        }
    }

    async fn handle_business_data(&self, data: serde_json::Value) {
        // Handle your custom business data
        log::info!("💼 Processing business data: {:?}", data);
        
        // Example: Store data from network
        if let (Some(key), Some(value)) = (
            data.get("key").and_then(|k| k.as_str()),
            data.get("value").and_then(|v| v.as_str())
        ) {
            let mut state = self.state.write().await;
            state.data.insert(key.to_string(), value.to_string());
            log::info!("📝 Stored network data: {} = {}", key, value);
        }
    }

    /// Send custom business data to the network
    pub async fn send_business_data(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let message = Message {
            from: format!("app:{}", self.config.app_name.as_ref().unwrap_or(&"unknown".to_string())),
            to: "*".to_string(),
            msg_type: MessageType::Custom("business_data".to_string()),
            payload: Some(Payload::Json(serde_json::json!({
                "key": key,
                "value": value,
                "timestamp": chrono::Utc::now().timestamp()
            }))),
            realm: self.config.realm.clone(),
        };

        log::info!("📤 Sending business data: {} = {}", key, value);
        
        // Note: In a real implementation, you'd send this through TheNodes network
        // For now, this is a placeholder that shows the structure
        
        Ok(())
    }

    /// Get current business state
    pub async fn get_state(&self) -> BusinessState {
        self.state.read().await.clone()
    }
}
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use thenodes::plugin_host::{Plugin, PluginContext, PluginRegistrarApi};
use thenodes::network::message::{Message, MessageType, Payload};
use serde_json::json;
use async_trait::async_trait;

#[derive(Default)]
pub struct KvStorePlugin {
    store: Arc<Mutex<HashMap<String, String>>>,
}

impl KvStorePlugin {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Plugin for KvStorePlugin {
    fn on_message(&self, message: &Message, _ctx: &PluginContext) {
        println!("[kvstore_plugin] on_message: self={:p} message={:?}", self, message);
        match &message.msg_type {
            MessageType::Extension { kind } => match kind.as_str() {
                "kvstore.put" => {
                    if let Some(Payload::Json(json)) = &message.payload {
                        let key = json["key"].as_str().unwrap_or_default();
                        let value = json["value"].as_str().unwrap_or_default();
                        println!("📝 Storing: {} = {}", key, value);
                        self.store.lock().unwrap().insert(key.to_string(), value.to_string());
                    }
                }
                "kvstore.get" => {
                    if let Some(Payload::Json(json)) = &message.payload {
                        let key = json["key"].as_str().unwrap_or_default();
                        let result = self.store.lock().unwrap().get(key).cloned();
                        println!("🔍 Lookup for '{}': {:?}", key, result);
                    }
                }
                _ => {
                    println!("⚠️ Unknown extension kind: {}", kind);
                }
            },
            MessageType::Text(text) => {
                // Optional: parse simple prompt-style messages sent as Text
                if text.starts_with("!kvstore ") {
                    let parts: Vec<&str> = text.trim().splitn(3, ' ').collect();
                    if parts.len() == 3 && parts[1] == "get" {
                        let key = parts[2];
                        let result = self.store.lock().unwrap().get(key).cloned();
                        println!("🔍 (Text) Lookup for '{}': {:?}", key, result);
                    }
                }
            }
            _ => {}
        }
    }

    fn prompt_prefix(&self) -> Option<&str> {
        Some("kvstore")
    }

    async fn on_prompt(&self, input: &str, ctx: &PluginContext) -> Option<String> {
        println!("[kvstore_plugin] on_prompt: self={:p} input={:?}", self, input);
        let parts: Vec<&str> = input.trim().splitn(3, ' ').collect();
        match parts.as_slice() {
            ["put", key, value] => {
                self.store.lock().unwrap().insert(key.to_string(), value.to_string());
                // Broadcast to all peers
                let msg = Message::new(
                    "plugin:kvstore",
                    "*",
                    MessageType::Extension { kind: "kvstore.put".to_string() },
                    Some(Payload::Json(json!({"key": key, "value": value}))),
                    None,
                );
                let json_msg = msg.as_json();
                ctx.peer_manager.broadcast(&json_msg).await;
                Some(format!("📝 Stored and broadcast: {} = {}", key, value))
            }
            ["get", key] => {
                let result = self.store.lock().unwrap().get(*key).cloned();
                Some(format!("🔍 Result: {:?}", result))
            }
            ["list"] => {
                let map = self.store.lock().unwrap();
                let list = map.iter().map(|(k, v)| format!("{k} = {v}")).collect::<Vec<_>>().join("\n");
                Some(format!("📦 All entries:\n{}", list))
            }
            _ => Some(format!("⚠️ Unknown command: '{}'", input)),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn register_plugin(api: *const PluginRegistrarApi) {
    let api = match PluginRegistrarApi::from_raw(api) {
        Ok(api) => api,
        Err(err) => {
            eprintln!("[kvstore_plugin] invalid registrar API: {err}");
            return;
        }
    };
    if let Err(err) = api.register_plugin(Box::new(KvStorePlugin::new())) {
        eprintln!("[kvstore_plugin] failed to register: {err}");
    }
}

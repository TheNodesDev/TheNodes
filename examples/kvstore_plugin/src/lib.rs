use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::json;
use thenodes::network::message::{Message, MessageType, Payload};
use thenodes::plugin_host::{Plugin, PluginContext, PluginRegistrarApi};

const PLUGIN_ID: &str = "kvstore_plugin";
const PROMPT_PREFIX: &str = "kvstore";

#[derive(Default)]
pub struct KvStorePlugin {
    store: DurableKvStore,
}

impl KvStorePlugin {
    pub fn new() -> Self {
        Self::default()
    }

    async fn put(&self, ctx: &PluginContext, key: &str, value: &str) -> io::Result<()> {
        let data_dir = ctx.plugin_data_dir().await?;
        self.store.put(&data_dir, key, value).await
    }

    async fn get(&self, ctx: &PluginContext, key: &str) -> io::Result<Option<String>> {
        let data_dir = ctx.plugin_data_dir().await?;
        self.store.get(&data_dir, key).await
    }

    async fn list(&self, ctx: &PluginContext) -> io::Result<Vec<(String, String)>> {
        let data_dir = ctx.plugin_data_dir().await?;
        self.store.list(&data_dir).await
    }

    async fn handle_command(&self, input: &str, ctx: &PluginContext) -> Option<String> {
        let parts: Vec<&str> = input.trim().splitn(3, ' ').collect();
        match parts.as_slice() {
            ["put", key, value] => match self.put(ctx, key, value).await {
                Ok(()) => {
                    let msg = Message::new(
                        "plugin:kvstore",
                        "*",
                        MessageType::Extension {
                            kind: "kvstore.put".to_string(),
                        },
                        Some(Payload::Json(json!({"key": key, "value": value}))),
                        None,
                    );
                    let json_msg = msg.as_json();
                    ctx.peer_manager.broadcast(&json_msg).await;
                    Some(format!("📝 Stored and broadcast: {} = {}", key, value))
                }
                Err(err) => Some(format!("❌ Failed to store value: {err}")),
            },
            ["get", key] => match self.get(ctx, key).await {
                Ok(result) => Some(format!("🔍 Result: {:?}", result)),
                Err(err) => Some(format!("❌ Failed to read value: {err}")),
            },
            ["list"] => match self.list(ctx).await {
                Ok(entries) if entries.is_empty() => Some("📦 All entries:\n(none)".to_string()),
                Ok(entries) => Some(format!(
                    "📦 All entries:\n{}",
                    entries
                        .into_iter()
                        .map(|(key, value)| format!("{key} = {value}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                )),
                Err(err) => Some(format!("❌ Failed to list values: {err}")),
            },
            _ => Some(format!("⚠️ Unknown command: '{}'", input)),
        }
    }
}

#[derive(Default)]
struct DurableKvStore {
    io_lock: tokio::sync::Mutex<()>,
}

impl DurableKvStore {
    const STORE_FILE: &str = "kvstore.json";

    async fn put(&self, data_dir: &Path, key: &str, value: &str) -> io::Result<()> {
        let _guard = self.io_lock.lock().await;
        let path = Self::store_path(data_dir);
        let mut entries = Self::load_entries(&path).await?;
        entries.insert(key.to_string(), value.to_string());
        Self::save_entries(&path, &entries).await
    }

    async fn get(&self, data_dir: &Path, key: &str) -> io::Result<Option<String>> {
        let _guard = self.io_lock.lock().await;
        let path = Self::store_path(data_dir);
        let entries = Self::load_entries(&path).await?;
        Ok(entries.get(key).cloned())
    }

    async fn list(&self, data_dir: &Path) -> io::Result<Vec<(String, String)>> {
        let _guard = self.io_lock.lock().await;
        let path = Self::store_path(data_dir);
        let entries = Self::load_entries(&path).await?;
        Ok(entries.into_iter().collect())
    }

    fn store_path(data_dir: &Path) -> PathBuf {
        data_dir.join(Self::STORE_FILE)
    }

    async fn load_entries(path: &Path) -> io::Result<BTreeMap<String, String>> {
        match tokio::fs::read(path).await {
            Ok(bytes) if bytes.is_empty() => Ok(BTreeMap::new()),
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse store at {}: {err}", path.display()),
                )
            }),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(err) => Err(err),
        }
    }

    async fn save_entries(path: &Path, entries: &BTreeMap<String, String>) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(entries).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize store at {}: {err}", path.display()),
            )
        })?;
        tokio::fs::write(path, bytes).await
    }
}

#[async_trait]
impl Plugin for KvStorePlugin {
    fn plugin_id(&self) -> &'static str {
        PLUGIN_ID
    }

    async fn on_message(&self, message: &Message, ctx: &PluginContext) {
        println!(
            "[kvstore_plugin] on_message: self={:p} message={:?}",
            self, message
        );
        match &message.msg_type {
            MessageType::Extension { kind } => match kind.as_str() {
                "kvstore.put" => {
                    if let Some(Payload::Json(json)) = &message.payload {
                        let key = json["key"].as_str().unwrap_or_default();
                        let value = json["value"].as_str().unwrap_or_default();
                        match self.put(ctx, key, value).await {
                            Ok(()) => println!("📝 Storing: {} = {}", key, value),
                            Err(err) => {
                                eprintln!("[kvstore_plugin] failed to persist '{}': {err}", key)
                            }
                        }
                    }
                }
                "kvstore.get" => {
                    if let Some(Payload::Json(json)) = &message.payload {
                        let key = json["key"].as_str().unwrap_or_default();
                        match self.get(ctx, key).await {
                            Ok(result) => println!("🔍 Lookup for '{}': {:?}", key, result),
                            Err(err) => {
                                eprintln!("[kvstore_plugin] failed to load '{}': {err}", key)
                            }
                        }
                    }
                }
                _ => {
                    println!("⚠️ Unknown extension kind: {}", kind);
                }
            },
            MessageType::Text(text) if text.starts_with("!kvstore ") => {
                if let Some(reply) = self
                    .handle_command(text.trim_start_matches("!kvstore ").trim(), ctx)
                    .await
                {
                    println!("{}", reply);
                }
            }
            _ => {}
        }
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        Some(&["kvstore.put", "kvstore.get"])
    }

    fn prompt_prefix(&self) -> Option<&str> {
        Some(PROMPT_PREFIX)
    }

    async fn on_prompt(&self, input: &str, ctx: &PluginContext) -> Option<String> {
        println!(
            "[kvstore_plugin] on_prompt: self={:p} input={:?}",
            self, input
        );
        self.handle_command(input, ctx).await
    }
}

/// # Safety
///
/// `api` must be a valid pointer to the host's plugin registrar API for ABI v3
/// and remain valid for the duration of this call.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use thenodes::config::{Config, NodeConfig};
    use thenodes::network::{PeerManager, PeerStore};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos();
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("test-artifacts")
                .join(format!("{prefix}-{nanos}-{unique}"));
            std::fs::create_dir_all(&path).expect("test directory should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn plugin_context(state_dir: &Path) -> PluginContext {
        let mut config = Config::default();
        config
            .node
            .get_or_insert_with(NodeConfig::default)
            .state_dir = Some(state_dir.display().to_string());
        PluginContext::new(
            Arc::new(PeerManager::new()),
            PeerStore::new(),
            thenodes::events::dispatcher::handle(),
            "local-node".to_string(),
            config,
            false,
        )
    }

    #[tokio::test]
    async fn prompt_store_persists_across_plugin_restarts() {
        let sandbox = TestDir::new("kvstore-plugin");
        let state_dir = sandbox.path().join("node-data");
        let ctx = plugin_context(&state_dir)
            .for_plugin(PLUGIN_ID)
            .expect("plugin context should bind plugin id");

        let first = KvStorePlugin::new();
        assert_eq!(
            first.on_prompt("put color blue", &ctx).await,
            Some("📝 Stored and broadcast: color = blue".to_string())
        );

        let restarted = KvStorePlugin::new();
        assert_eq!(
            restarted.on_prompt("get color", &ctx).await,
            Some("🔍 Result: Some(\"blue\")".to_string())
        );

        let store_file = ctx
            .plugin_data_dir()
            .await
            .expect("plugin data dir should resolve")
            .join(DurableKvStore::STORE_FILE);
        let persisted: BTreeMap<String, String> = serde_json::from_slice(
            &tokio::fs::read(&store_file)
                .await
                .expect("store file should be readable"),
        )
        .expect("store file should contain valid json");
        assert_eq!(persisted.get("color"), Some(&"blue".to_string()));
    }
}

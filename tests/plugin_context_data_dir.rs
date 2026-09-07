use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use thenodes::config::{Config, NodeConfig};
use thenodes::network::{PeerManager, PeerStore};
use thenodes::plugin_host::PluginContext;

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
async fn plugin_data_dir_is_lazy_and_stable_across_contexts() {
    let sandbox = TestDir::new("plugin-data-dir-stable");
    let state_dir = sandbox.path().join("node-data");
    let base_ctx = plugin_context(&state_dir);

    assert!(
        !state_dir.exists(),
        "plugin data directories should not exist before first access"
    );

    let ctx = base_ctx
        .for_plugin("example.plugin_1")
        .expect("plugin id should be valid");
    let first = ctx
        .plugin_data_dir()
        .await
        .expect("plugin data dir should be created");
    assert_eq!(first, state_dir.join("plugins").join("example.plugin_1"));
    assert!(first.is_dir());

    let second = ctx
        .plugin_data_dir()
        .await
        .expect("existing plugin data dir should still resolve");
    assert_eq!(first, second);

    let restarted_ctx = plugin_context(&state_dir)
        .for_plugin("example.plugin_1")
        .expect("plugin id should still be valid");
    let restarted = restarted_ctx
        .plugin_data_dir()
        .await
        .expect("restarted context should resolve same plugin data dir");
    assert_eq!(first, restarted);
}

#[tokio::test]
async fn plugin_data_dir_is_isolated_per_valid_plugin_id() {
    let sandbox = TestDir::new("plugin-data-dir-isolated");
    let state_dir = sandbox.path().join("node-data");
    let alpha_ctx = plugin_context(&state_dir)
        .for_plugin("alpha.plugin")
        .expect("alpha plugin id should be valid");
    let beta_ctx = plugin_context(&state_dir)
        .for_plugin("beta.plugin")
        .expect("beta plugin id should be valid");

    let alpha_dir = alpha_ctx
        .plugin_data_dir()
        .await
        .expect("alpha data dir should resolve");
    let beta_dir = beta_ctx
        .plugin_data_dir()
        .await
        .expect("beta data dir should resolve");

    assert_ne!(alpha_dir, beta_dir);

    let alpha_file = alpha_dir.join("state.json");
    tokio::fs::write(&alpha_file, br#"{"owner":"alpha"}"#)
        .await
        .expect("alpha file should be written");

    assert!(alpha_file.exists());
    assert!(
        !beta_dir.join("state.json").exists(),
        "plugin directories must not share files"
    );
}

#[tokio::test]
async fn plugin_data_dir_requires_plugin_bound_context() {
    let sandbox = TestDir::new("plugin-data-dir-unbound");
    let state_dir = sandbox.path().join("node-data");
    let ctx = plugin_context(&state_dir);

    let err = ctx
        .plugin_data_dir()
        .await
        .expect_err("unbound contexts must not resolve plugin data dirs");
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn plugin_binding_rejects_path_traversal_ids() {
    let sandbox = TestDir::new("plugin-data-dir-invalid");
    let state_dir = sandbox.path().join("node-data");
    let ctx = plugin_context(&state_dir);

    for plugin_id in [
        "",
        ".",
        "..",
        "../escape",
        "nested/name",
        "nested\\name",
        "/abs",
    ] {
        let err = match ctx.for_plugin(plugin_id) {
            Ok(_) => panic!("invalid plugin id should be rejected: {plugin_id}"),
            Err(err) => err,
        };
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidInput,
            "unexpected error for {plugin_id}"
        );
    }

    assert!(
        !state_dir.join("plugins").exists(),
        "invalid plugin ids must not create plugin directories"
    );
}

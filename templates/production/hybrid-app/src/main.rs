use clap::Parser;
use std::future;
use std::path::PathBuf;
use std::sync::Arc;
use thenodes::{config::Config, plugin_host::{PluginManager, PluginLoader}, events, constants::ICON_PLACEHOLDER};
mod app_identity;

#[derive(Parser, Debug)]
#[command(name = "{{APP_NAME}}", about = "{{APP_DESCRIPTION}}")]
struct Args {
    /// Path to config file (TOML)
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    /// Plugin directory to load (.so/.dylib/.dll)
    #[arg(long, default_value = "plugins")] 
    plugins: PathBuf,

    /// Start an interactive prompt
    #[arg(long, default_value_t = false)]
    prompt: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load config
    let cfg_text = std::fs::read_to_string(&args.config)?;
    let mut cfg: Config = toml::from_str(&cfg_text)?;

    // Apply developer hardcoded identity (non-overridable)
    app_identity::hardcoded().apply(&mut cfg)?;

    // Initialize events (console + json)
    events::init::init_events_from_config(cfg.logging.as_ref()).await;

    // Load plugins (NEP) using TheNodes plugin host
    println!("{}Loading plugins from {}", ICON_PLACEHOLDER, args.plugins.display());
    let mut plugin_manager = PluginManager::new();
    let mut loader = PluginLoader::new();
    loader.load_plugins(&args.plugins, &mut plugin_manager)?;

    // Start networking listener and bootstrap peers
    // Use the existing main entry points in the library to align with current project structure
    let realm = cfg.realm.clone().unwrap_or_else(|| thenodes::realms::RealmInfo::default());
    let port = cfg.port;
    let node_cfg = cfg.node.clone().unwrap_or_default();
    let node_id = node_cfg.resolve_node_id();

    // Peer manager and plugin manager arc
    let peer_manager = thenodes::network::peer_manager::PeerManager::new();
    let plugin_manager_arc = Arc::new(plugin_manager);

    // Start listener
    let peer_store = thenodes::network::peer_store::PeerStore::new();
    let emit_listener_errors = !args.prompt;
    let _listen_task = tokio::spawn({
        let pm = peer_manager.clone();
        let pmgr = plugin_manager_arc.clone();
        let realm = realm.clone();
        let cfg_clone = cfg.clone();
        let node_id = node_id.clone();
        let peer_store = peer_store.clone();
        let emit_console_errors = emit_listener_errors;
        async move {
            if let Err(e) = thenodes::network::listener::start_listener(
                port,
                realm,
                pm,
                pmgr,
                &cfg_clone,
                node_id,
                peer_store,
                emit_console_errors,
            ).await {
                eprintln!("listener error: {}", e);
            }
        }
    });

    // Bootstrap outbound connections if present
    if cfg.bootstrap_nodes.is_some() {
        use tokio::sync::Mutex as TokioMutex;
        let error_buffer = Arc::new(TokioMutex::new(Vec::new()));
        thenodes::network::bootstrap::connect_to_bootstrap_nodes(
            &cfg,
            realm.clone(),
            peer_manager.clone(),
            plugin_manager_arc.clone(),
            error_buffer,
            !args.prompt,
            node_id.clone(),
            peer_store.clone(),
        ).await;
    }

    // Optional interactive prompt
    if args.prompt {
        thenodes::prompt::run_prompt_mode(plugin_manager_arc.clone(), cfg.clone()).await;
    }

    // Park main; services run on tasks
    future::pending::<()>().await;
    Ok(())
}

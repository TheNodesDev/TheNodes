use clap::Parser;
use std::fs;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex as TokioMutex;

// Import TheNodes framework via prelude
use thenodes::network::{
    connect_to_bootstrap_nodes, peer_manager::PeerManager, start_listener, PeerStore,
};
use thenodes::plugin_host::{PluginContext, PluginManager, PluginRegistrar};
use thenodes::prelude::*;

mod business_logic;
use business_logic::BusinessLogic;
mod app_identity;

#[derive(Parser, Debug)]
#[command(author, version, about = env!("CARGO_PKG_DESCRIPTION"))]
struct Args {
    /// Path to configuration file (TOML)
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();

    // Load configuration
    let mut config = load_config(&args.config)?;
    // Apply developer hardcoded values (non-overridable)
    app_identity::hardcoded().apply(&mut config)?;
    log::info!("Starting {{APP_NAME}} with config: {:?}", config.app_name);

    // Initialize TheNodes framework
    thenodes::events::init_events_from_config(config.logging.as_ref()).await;
    let realm = config.realm.clone().unwrap_or_default();
    let node_id = config
        .node
        .as_ref()
        .map(|node| node.resolve_node_id())
        .unwrap_or_else(|| "unknown-node".to_string());
    let peer_store = PeerStore::from_config(&config).await;
    let peer_manager = Arc::new(PeerManager::new());
    peer_manager.set_delivery_config(
        config
            .network
            .as_ref()
            .and_then(|network| network.delivery.clone()),
    );

    // Initialize your custom business logic
    let business_logic = BusinessLogic::new(config.clone());
    let plugin_context = PluginContext::new(
        peer_manager.clone(),
        peer_store.clone(),
        thenodes::events::dispatcher::handle(),
        node_id.clone(),
        config.clone(),
        true,
    );
    let mut plugin_manager = PluginManager::with_context(plugin_context);
    plugin_manager.register_handler(Box::new(business_logic.clone()));
    let plugin_manager = Arc::new(plugin_manager);
    if let Some(context) = &plugin_manager.context {
        context.set_plugin_manager(plugin_manager.clone()).await;
    }
    peer_manager
        .configure_connection_lifecycle(
            config.clone(),
            node_id.clone(),
            &plugin_manager,
            peer_store.clone(),
            true,
        )
        .await;

    // Start TheNodes networking
    let listener_handle = tokio::spawn({
        let peer_manager = peer_manager.clone();
        let plugin_manager = plugin_manager.clone();
        let config = config.clone();
        let realm = realm.clone();
        let node_id = node_id.clone();
        let peer_store = peer_store.clone();
        async move {
            if let Err(e) = start_listener(
                config.port,
                realm,
                (*peer_manager).clone(),
                plugin_manager,
                &config,
                node_id,
                peer_store,
                true,
            )
            .await
            {
                log::error!("Listener failed: {}", e);
            }
        }
    });

    // Connect to bootstrap nodes
    let error_buffer = Arc::new(TokioMutex::new(Vec::new()));
    connect_to_bootstrap_nodes(
        &config,
        realm,
        (*peer_manager).clone(),
        plugin_manager,
        error_buffer,
        true,
        node_id,
        peer_store,
    )
    .await;

    // Start your custom business logic
    let business_handle = tokio::spawn({
        async move {
            business_logic.start().await;
        }
    });

    log::info!("🚀 {{APP_NAME}} is running. Press Ctrl+C to shutdown...");

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    log::info!("🛑 Shutting down {{APP_NAME}}...");

    // Cleanup
    listener_handle.abort();
    business_handle.abort();

    log::info!("✅ {{APP_NAME}} shutdown complete");
    Ok(())
}

fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file '{}': {}", path, e))?;

    let config: Config = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config file '{}': {}", path, e))?;

    Ok(config)
}

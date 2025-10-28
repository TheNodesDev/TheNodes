use clap::Parser;
use std::fs;
use std::sync::Arc;
use tokio::signal;

// Import TheNodes framework via prelude
use thenodes::prelude::*;
use thenodes::network::{start_listener, connect_to_bootstrap_nodes, PeerStore, peer_manager::PeerManager};
use thenodes::plugin_host::PluginManager;

mod business_logic;
use business_logic::BusinessLogic;
mod app_identity;

#[derive(Parser, Debug)]
#[command(author, version, about = "{{APP_DESCRIPTION}}")]
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
    let peer_store = Arc::new(PeerStore::new());
    let peer_manager = Arc::new(PeerManager::new(peer_store.clone()));
    let plugin_manager = Arc::new(PluginManager::new());

    // Initialize your custom business logic
    let business_logic = Arc::new(BusinessLogic::new(config.clone()));

    // Start TheNodes networking
    let listener_handle = tokio::spawn({
        let peer_manager = peer_manager.clone();
        let plugin_manager = plugin_manager.clone();
        let business_logic = business_logic.clone();
        async move {
            if let Err(e) = start_listener(
                config.port,
                peer_manager,
                plugin_manager,
                Some(business_logic)
            ).await {
                log::error!("Listener failed: {}", e);
            }
        }
    });

    // Connect to bootstrap nodes
    if let Some(bootstrap_nodes) = &config.bootstrap_nodes {
        let bootstrap_handle = tokio::spawn({
            let peer_manager = peer_manager.clone();
            let bootstrap_nodes = bootstrap_nodes.clone();
            async move {
                if let Err(e) = connect_to_bootstrap_nodes(&bootstrap_nodes, peer_manager).await {
                    log::error!("Bootstrap connection failed: {}", e);
                }
            }
        });

        // Wait a bit for bootstrap connections
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    // Start your custom business logic
    let business_handle = tokio::spawn({
        let business_logic = business_logic.clone();
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
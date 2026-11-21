use clap::Parser;
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

// Import TheNodes framework via prelude
use thenodes::network::{
    bind_listener, connect_to_bootstrap_nodes, peer_manager::PeerManager, run_listener, PeerStore,
};
use thenodes::plugin_host::{
    PluginContext, PluginManager, PluginRegistrar, ShutdownMode, StartPolicy,
};
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

    // Register your business logic as a plugin. The context holds the final
    // configuration before any plugin starts.
    let plugin_context = PluginContext::new(
        peer_manager.clone(),
        peer_store.clone(),
        thenodes::events::dispatcher::handle(),
        node_id.clone(),
        config.clone(),
        true,
    );
    let mut plugin_manager = PluginManager::with_context(plugin_context);
    plugin_manager.register_handler(Box::new(BusinessLogic::new(config.clone())))?;
    let plugin_manager = Arc::new(plugin_manager);
    let mut failures = plugin_manager.subscribe_failures();
    peer_manager
        .configure_connection_lifecycle(
            config.clone(),
            node_id.clone(),
            &plugin_manager,
            peer_store.clone(),
            true,
        )
        .await;

    // 1. Start plugins. Every plugin in this application is required.
    let report = plugin_manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await?;
    if !report.all_started() {
        for failure in report.failures() {
            log::error!("{failure}");
        }
        plugin_manager.shutdown(ShutdownMode::Discard).await?;
        return Err("plugin startup failed".into());
    }

    // 2. Bind the listener and observe the result before activation.
    let listener = match bind_listener(config.port, true).await {
        Ok(listener) => listener,
        Err(error) => {
            plugin_manager.shutdown(ShutdownMode::Discard).await?;
            return Err(error.into());
        }
    };
    let listener_handle = tokio::spawn({
        let peer_manager = peer_manager.clone();
        let plugin_manager = plugin_manager.clone();
        let config = config.clone();
        let realm = realm.clone();
        let node_id = node_id.clone();
        let peer_store = peer_store.clone();
        async move {
            if let Err(e) = run_listener(
                listener,
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

    // 3. Activate plugin admission, then begin outbound networking.
    plugin_manager.activate()?;
    let error_buffer = Arc::new(TokioMutex::new(Vec::new()));
    connect_to_bootstrap_nodes(
        &config,
        realm,
        (*peer_manager).clone(),
        plugin_manager.clone(),
        error_buffer,
        true,
        node_id,
        peer_store,
    )
    .await;

    log::info!("🚀 {{APP_NAME}} is running. Press Ctrl+C to shutdown...");

    // 4. Run until Ctrl+C or a plugin failure. Failure policy is yours: this
    // application stops when any plugin fails.
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            log::info!("🛑 Shutting down {{APP_NAME}}...");
        }
        failure = failures.recv() => {
            if let Some(failure) = failure {
                log::error!("{failure}; shutting down {{APP_NAME}}");
            }
        }
    }

    // 5. One cleanup path. TheNodes imposes no deadline; a second Ctrl+C
    // escalates and stops waiting on uncooperative plugin work.
    let shutdown = plugin_manager.begin_shutdown(ShutdownMode::Drain);
    listener_handle.abort();
    let _ = listener_handle.await;
    let wait = shutdown.wait();
    tokio::pin!(wait);
    let report = tokio::select! {
        report = &mut wait => report?,
        _ = tokio::signal::ctrl_c() => {
            log::warn!("Second Ctrl+C: escalating shutdown");
            plugin_manager.escalate();
            wait.await?
        }
    };
    if !report.is_clean() {
        log::warn!("Plugin shutdown report: {:?}", report);
    }

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

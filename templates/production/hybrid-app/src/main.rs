use clap::Parser;
use std::future;
use std::path::PathBuf;
use std::sync::Arc;
use thenodes::{
    config::Config,
    constants::ICON_PLACEHOLDER,
    events,
    plugin_host::{PluginContext, PluginLoader, PluginManager},
};
mod app_identity;

#[derive(Parser, Debug)]
#[command(name = env!("CARGO_PKG_NAME"), about = env!("CARGO_PKG_DESCRIPTION"))]
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

    // Start networking listener and bootstrap peers
    let realm = cfg.realm.clone().unwrap_or_default();
    let port = cfg.port;
    let node_cfg = cfg.node.clone().unwrap_or_default();
    let node_id = node_cfg.resolve_node_id();

    let peer_store = thenodes::network::peer_store::PeerStore::from_config(&cfg).await;
    let peer_manager = Arc::new(thenodes::network::peer_manager::PeerManager::new());
    peer_manager.set_delivery_config(
        cfg.network
            .as_ref()
            .and_then(|network| network.delivery.clone()),
    );

    // Load plugins (NEP) using a context connected to the runtime.
    println!(
        "{}Loading plugins from {}",
        ICON_PLACEHOLDER,
        args.plugins.display()
    );
    let plugin_context = PluginContext::new(
        peer_manager.clone(),
        peer_store.clone(),
        events::dispatcher::handle(),
        node_id.clone(),
        cfg.clone(),
        !args.prompt,
    );
    let mut plugin_manager = PluginManager::with_context(plugin_context);
    let mut loader = PluginLoader::new();
    loader.load_plugins(&args.plugins, &mut plugin_manager)?;
    let plugin_manager_arc = Arc::new(plugin_manager);
    if let Some(context) = &plugin_manager_arc.context {
        context.set_plugin_manager(plugin_manager_arc.clone()).await;
    }
    peer_manager
        .configure_connection_lifecycle(
            cfg.clone(),
            node_id.clone(),
            &plugin_manager_arc,
            peer_store.clone(),
            !args.prompt,
        )
        .await;

    // Start listener
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
                (*pm).clone(),
                pmgr,
                &cfg_clone,
                node_id,
                peer_store,
                emit_console_errors,
            )
            .await
            {
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
            (*peer_manager).clone(),
            plugin_manager_arc.clone(),
            error_buffer,
            !args.prompt,
            node_id.clone(),
            peer_store.clone(),
        )
        .await;
    }

    // Optional interactive prompt
    if args.prompt {
        thenodes::prompt::run_prompt_mode(plugin_manager_arc.clone(), cfg.clone()).await;
    }

    // Park main; services run on tasks
    future::pending::<()>().await;
    Ok(())
}

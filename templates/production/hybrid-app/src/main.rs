use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use thenodes::{
    config::Config,
    constants::ICON_PLACEHOLDER,
    events,
    network::{bind_listener, run_listener},
    plugin_host::{
        PluginContext, PluginLoadError, PluginLoader, PluginManager, ShutdownMode, StartPolicy,
    },
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

    let realm = cfg.realm.clone().unwrap_or_default();
    let node_cfg = cfg.node.clone().unwrap_or_default();
    let node_id = node_cfg.resolve_node_id();

    let peer_store = thenodes::network::peer_store::PeerStore::from_config(&cfg).await;
    let peer_manager = Arc::new(thenodes::network::peer_manager::PeerManager::new());
    peer_manager.set_delivery_config(
        cfg.network
            .as_ref()
            .and_then(|network| network.delivery.clone()),
    );

    // Load native plugins (NEP). Each library must be built with this host's
    // TheNodes release, toolchain, lockfile, and features. Every plugin is
    // required: a library that fails to register stops the application.
    println!(
        "{}Loading plugins from {}",
        ICON_PLACEHOLDER,
        args.plugins.display()
    );
    let mut plugin_manager = PluginManager::with_context(PluginContext::new(
        peer_manager.clone(),
        peer_store.clone(),
        events::dispatcher::handle(),
        node_id.clone(),
        cfg.clone(),
        !args.prompt,
    ));
    match PluginLoader::new().load_plugins(&args.plugins, &mut plugin_manager) {
        Ok(_) => {}
        Err(PluginLoadError::Discover { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            println!(
                "{}No plugin directory; running without plugins",
                ICON_PLACEHOLDER
            );
        }
        Err(error) => return Err(error.into()),
    }
    let plugin_manager = Arc::new(plugin_manager);
    let mut failures = plugin_manager.subscribe_failures();
    peer_manager
        .configure_connection_lifecycle(
            cfg.clone(),
            node_id.clone(),
            &plugin_manager,
            peer_store.clone(),
            !args.prompt,
        )
        .await;

    // Start plugins, bind the listener, then activate.
    let report = plugin_manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await?;
    if !report.all_started() {
        plugin_manager.shutdown(ShutdownMode::Discard).await?;
        anyhow::bail!("plugin startup failed: {:?}", report.outcomes);
    }
    let listener = match bind_listener(cfg.port, !args.prompt).await {
        Ok(listener) => listener,
        Err(error) => {
            plugin_manager.shutdown(ShutdownMode::Discard).await?;
            return Err(error.into());
        }
    };
    let listen_task = tokio::spawn({
        let pm = peer_manager.clone();
        let pmgr = plugin_manager.clone();
        let realm = realm.clone();
        let cfg_clone = cfg.clone();
        let node_id = node_id.clone();
        let peer_store = peer_store.clone();
        let emit_console_errors = !args.prompt;
        async move {
            if let Err(e) = run_listener(
                listener,
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
    plugin_manager.activate()?;

    // Bootstrap outbound connections if present
    if cfg.bootstrap_nodes.is_some() {
        use tokio::sync::Mutex as TokioMutex;
        let error_buffer = Arc::new(TokioMutex::new(Vec::new()));
        thenodes::network::bootstrap::connect_to_bootstrap_nodes(
            &cfg,
            realm.clone(),
            (*peer_manager).clone(),
            plugin_manager.clone(),
            error_buffer,
            !args.prompt,
            node_id.clone(),
            peer_store.clone(),
        )
        .await;
    }

    // Run until the prompt exits, Ctrl+C, or a plugin failure.
    if args.prompt {
        thenodes::prompt::run_prompt_mode(plugin_manager.clone(), cfg.clone()).await;
    } else {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            failure = failures.recv() => {
                if let Some(failure) = failure {
                    eprintln!("{failure}; shutting down");
                }
            }
        }
    }

    // One cleanup path. A second Ctrl+C escalates.
    let shutdown = plugin_manager.begin_shutdown(ShutdownMode::Drain);
    listen_task.abort();
    let _ = listen_task.await;
    let wait = shutdown.wait();
    tokio::pin!(wait);
    let report = tokio::select! {
        report = &mut wait => report?,
        _ = tokio::signal::ctrl_c() => {
            plugin_manager.escalate();
            wait.await?
        }
    };
    println!(
        "{}Plugin shutdown clean: {}",
        ICON_PLACEHOLDER,
        report.is_clean()
    );
    if !report.is_clean() {
        // Escalated work may still be running in pinned plugin code.
        std::process::exit(1);
    }
    Ok(())
}

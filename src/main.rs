use clap::Parser;
use std::fs;
use tokio::signal;
// use std::sync::Arc; // Already imported above
use std::sync::Arc;
use thenodes::{
    config::Config,
    constants::*, // Import all constants
    network::{connect_to_bootstrap_nodes, peer_manager::PeerManager, start_listener, PeerStore},
    //plugin_loader::load_plugins,
    plugin_host::{PluginLoader, PluginManager},
    prompt::run_prompt_mode_with_errors,
    realms::RealmInfo,
};
use tokio::sync::Mutex as TokioMutex; // keep (used for error buffer)
                                      // Removed unused io + AsyncBufReadExt imports (legacy prompt code commented out)

#[derive(Parser, Debug)]
#[command(author, version, about = "TheNodes Plugin Host (NEP Mode)")]
struct Args {
    /// Optional path to config file (TOML)
    #[arg(short, long)]
    config: Option<String>,

    /// Enable interactive prompt mode
    #[arg(long)]
    prompt: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Shared buffer for bootstrap connection errors
    let error_buffer: Arc<TokioMutex<Vec<String>>> = Arc::new(TokioMutex::new(Vec::new()));
    let error_buffer_clone = error_buffer.clone();

    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| "config.toml".to_string());
    let config = match fs::read_to_string(&config_path) {
        Ok(content) => match toml::from_str::<Config>(&content) {
            Ok(cfg) => {
                println!("{}Loaded config from: {}", ICON_PLACEHOLDER, config_path);
                cfg
            }
            Err(err) => {
                eprintln!("❌ Failed to parse config file '{}': {}", config_path, err);
                std::process::exit(1);
            }
        },
        Err(_) => {
            println!(
                "⚠️ No config file found at '{}', falling back to default config.",
                config_path
            );
            Config::default()
        }
    };

    // Initialize events AFTER config is loaded so custom logging path can be applied
    if let Some(log_cfg) = config.logging.as_ref() {
        thenodes::events::init_events_from_config(Some(log_cfg)).await;
    } else {
        thenodes::events::init_default_events().await;
    }

    // Resolve node identity early
    let node_id = config
        .node
        .as_ref()
        .map(|n| n.resolve_node_id())
        .unwrap_or_else(|| "unknown-node".to_string());
    println!("{}Node identity resolved: {}", ICON_PLACEHOLDER, node_id);
    {
        use thenodes::events::{
            dispatcher,
            model::{LogEvent, LogLevel, SystemEvent},
        };
        let mut meta = dispatcher::meta("node", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: "identity_resolved".into(),
            detail: Some(format!("id={}", node_id)),
        }));
    }

    // Instantiate basic managers prior to plugin load (needed for context)
    let peer_manager = Arc::new(PeerManager::new());
    let peer_store_for_plugins = PeerStore::new();

    // Dynamically load plugins from `plugins/`
    let plugin_context = thenodes::plugin_host::PluginContext {
        peer_manager: peer_manager.clone(),
        peer_store: peer_store_for_plugins.clone(),
        events: thenodes::events::dispatcher::handle(),
    };
    let mut raw_manager = PluginManager::with_context(plugin_context);
    let mut plugin_loader = PluginLoader::new();

    if let Err(e) = plugin_loader.load_plugins("plugins", &mut raw_manager) {
        eprintln!("❌ Plugin loading failed: {}", e);
    }
    // Collect early config defaults from plugins (realm, port, app name)
    let overrides = raw_manager.collect_config_defaults();
    let mut config = config; // make mutable to apply overrides
                             // Apply plugin overrides ONLY for fields not explicitly set by user config.
                             // Precedence order now: user config > plugin override > library default.
    let mut applied: Vec<&'static str> = Vec::new();
    if let Some(p) = overrides.port {
        // Detect if user provided the port (by comparing to default AND whether file existed) is tricky.
        // Simpler heuristic: only apply if config was loaded from missing file fallback OR port equals default AND no explicit env var.
        // For now: do NOT overwrite if the user-provided config file existed (we know because earlier we printed Loaded config from:).
        // We didn't persist that flag; assume if app_name or realm is Some from the parsed file we treat port as user-specified if it differs from default.
        // Minimal safe rule: only apply if port still equals default (50000) and user didn't set a different one.
        if config.port == 50000 {
            config.port = p;
            applied.push("port");
        }
    }
    if let Some(r) = overrides.realm.clone() {
        if config.realm.is_none() {
            config.realm = Some(r);
            applied.push("realm");
        }
    }
    if let Some(a) = overrides.app_name.clone() {
        if config.app_name.is_none() {
            config.app_name = Some(a);
            applied.push("app_name");
        }
    }
    if let Some(enc) = overrides.encryption.clone() {
        if config.encryption.is_none() {
            config.encryption = Some(enc);
            applied.push("encryption");
        }
    }
    if let Some(bs) = overrides.bootstrap_nodes.clone() {
        if config.bootstrap_nodes.is_none() {
            config.bootstrap_nodes = Some(bs);
            applied.push("bootstrap_nodes");
        }
    }
    // Append semantics for bootstrap_nodes_extend (dedupe, preserve order preference: existing first)
    if let Some(extra) = overrides.bootstrap_nodes_extend.clone() {
        if !extra.is_empty() {
            use std::collections::HashSet;
            match config.bootstrap_nodes.as_mut() {
                Some(existing) => {
                    let mut seen: HashSet<String> = existing.iter().cloned().collect();
                    let mut added = 0u32;
                    for e in extra {
                        if seen.insert(e.clone()) {
                            existing.push(e);
                            added += 1;
                        }
                    }
                    if added > 0 {
                        applied.push("bootstrap_nodes_extend");
                    }
                }
                None => {
                    // No existing list; treat as normal bootstrap_nodes default
                    config.bootstrap_nodes = Some(extra);
                    applied.push("bootstrap_nodes");
                }
            }
        }
    }
    if let Some(logcfg) = overrides.logging.clone() {
        if config.logging.is_none() {
            config.logging = Some(logcfg);
            applied.push("logging");
        }
    }
    if let Some(nodecfg) = overrides.node.clone() {
        if config.node.is_none() {
            config.node = Some(nodecfg);
            applied.push("node");
        }
    }
    if let Some(disc) = overrides.discovery.clone() {
        if config.discovery.is_none() {
            config.discovery = Some(disc);
            applied.push("discovery");
        }
    }
    if !applied.is_empty() {
        println!(
            "⚙️ Applied plugin-supplied config defaults (user config precedence preserved): {:?}",
            applied
        );
        use thenodes::events::{
            dispatcher,
            model::{LogEvent, LogLevel, SystemEvent},
        };
        let mut meta = dispatcher::meta("config", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: "plugin_config_defaults_applied".into(),
            detail: Some(format!("fields={:?}", applied)),
        }));
    }

    // Initialize runtime peer store from final config (ADR-0002 persistence integration)
    let peer_store = PeerStore::from_config(&config).await;
    if let Some(ctx) = raw_manager.context.as_mut() {
        ctx.peer_store = peer_store.clone();
    }

    if let Some(relay) = config.network.as_ref().and_then(|n| n.relay.as_ref()) {
        let (per_target, global) =
            peer_manager.set_relay_queue_caps(relay.queue_max_per_target, relay.queue_max_global);
        println!(
            "{}Relay queue caps: per_target={}, global={}",
            ICON_PLACEHOLDER, per_target, global
        );
    }

    let plugin_manager = Arc::new(raw_manager);

    // Load RealmInfo after overrides
    let realm = config.realm.clone().unwrap_or_else(RealmInfo::default);
    // Don't print full config here as it is ugly and may contain sensitive info.
    //println!("{}Loaded config (post overrides): {:?}", ICON_PLACEHOLDER, config);
    println!("{}Realm: {:?}", ICON_PLACEHOLDER, realm);

    // Start listener in the background
    let port = config.port;
    let listener_manager = peer_manager.clone();
    let listener_realm = realm.clone();
    let plugin_manager_for_listener = plugin_manager.clone();

    let config_clone = config.clone();
    let node_id_clone_for_listener = node_id.clone();
    let peer_store_for_listener = peer_store.clone();
    let emit_listener_errors = !args.prompt;
    tokio::spawn(async move {
        let emit_console_errors = emit_listener_errors;
        if let Err(e) = start_listener(
            port,
            listener_realm,
            (*listener_manager).clone(),
            plugin_manager_for_listener,
            &config_clone,
            node_id_clone_for_listener,
            peer_store_for_listener,
            emit_console_errors,
        )
        .await
        {
            eprintln!("❌ Listener error: {}", e);
        }
    });

    // Connect to bootstrap nodes, pass error buffer
    connect_to_bootstrap_nodes(
        &config,
        realm.clone(),
        (*peer_manager).clone(),
        plugin_manager.clone(),
        error_buffer_clone,
        !args.prompt,
        node_id.clone(),
        peer_store.clone(),
    )
    .await;

    let app_name = config.app_name.as_deref().unwrap_or(DEFAULT_APP_NAME);
    println!("🟢 {} is running. Press Ctrl+C to shut down...", app_name);

    // Prompt mode
    if args.prompt {
        run_prompt_mode_with_errors(
            plugin_manager.clone(),
            config.clone(),
            Some(error_buffer.clone()),
        )
        .await;
        // Avoid unloading dynamic plugin libraries during shutdown, which can segfault
        // if any background tasks or drop glue touch plugin code after dlclose.
        // It's acceptable to leak on process exit.
        std::mem::forget(plugin_loader);
        return;
    }

    // Wait for Ctrl+C
    signal::ctrl_c()
        .await
        .expect("Failed to listen for shutdown signal");
    println!("🛑 {} shutting down gracefully.", app_name);

    // Prevent unloading of dynamic plugin libraries on shutdown to avoid segfaults
    // from destructor ordering or background tasks touching plugin code.
    std::mem::forget(plugin_loader);

    // TODO: start networking etc.
}

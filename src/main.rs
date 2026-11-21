use clap::Parser;
use std::fs;
use std::io::Write;
use std::sync::Arc;
use thenodes::{
    config::{Config, ConfigDefaults},
    constants::*, // Import all constants
    events::{
        dispatcher,
        model::{LogEvent, LogLevel, SystemEvent},
    },
    network::{
        bind_listener_on, connect_to_bootstrap_nodes, peer_manager::PeerManager, run_listener,
        PeerStore,
    },
    plugin_host::{
        PluginContext, PluginFailure, PluginFailureSubscription, PluginLoadError, PluginLoader,
        PluginManager, ShutdownMode, ShutdownReport, StartPolicy, StartResult,
    },
    prompt::run_prompt_mode_with_errors,
    realms::RealmInfo,
};
use tokio::sync::Mutex as TokioMutex; // keep (used for error buffer)
use tokio::task::JoinHandle;

#[derive(Parser, Debug)]
#[command(author, version, about = "TheNodes Plugin Host (NEP Mode)")]
struct Args {
    /// Optional path to config file (TOML)
    #[arg(short, long)]
    config: Option<String>,

    /// Enable interactive prompt mode
    #[arg(long)]
    prompt: bool,

    /// Run with built-in defaults (plaintext, open trust) when the config file
    /// is missing, instead of refusing to start
    #[arg(long)]
    allow_default_config: bool,
}

/// Why the host enters its common cleanup path.
enum ShutdownCause {
    Signal,
    PromptExit,
    PluginFailure(PluginFailure),
    Startup(String),
}

impl ShutdownCause {
    fn is_failure(&self) -> bool {
        matches!(
            self,
            ShutdownCause::PluginFailure(_) | ShutdownCause::Startup(_)
        )
    }
}

impl std::fmt::Display for ShutdownCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownCause::Signal => write!(f, "shutdown requested"),
            ShutdownCause::PromptExit => write!(f, "prompt exited"),
            ShutdownCause::PluginFailure(failure) => write!(f, "{failure}"),
            ShutdownCause::Startup(reason) => write!(f, "startup failed: {reason}"),
        }
    }
}

/// Shutdown requests: Ctrl+C (SIGINT) and, on Unix, SIGTERM. The first request
/// starts shutdown; a second one escalates. Created before anything else so
/// no request is missed.
struct ShutdownRequests {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl ShutdownRequests {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                ctrl_c: tokio::signal::windows::ctrl_c()?,
            })
        }
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            let received = tokio::select! {
                received = self.interrupt.recv() => received,
                received = self.terminate.recv() => received,
            };
            if received.is_none() {
                std::future::pending::<()>().await;
            }
        }
        #[cfg(windows)]
        {
            if self.ctrl_c.recv().await.is_none() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let code = run(Args::parse()).await;
    let _ = std::io::stdout().flush();
    // Exit without tearing down the runtime: native plugin code is pinned and
    // threads created outside the managed task scope must not keep the
    // process alive after the shutdown report.
    std::process::exit(code);
}

async fn run(args: Args) -> i32 {
    let mut requests = match ShutdownRequests::new() {
        Ok(requests) => requests,
        Err(err) => {
            eprintln!("❌ Failed to install shutdown signal handlers: {}", err);
            return 1;
        }
    };

    // Shared buffer for bootstrap connection errors
    let error_buffer: Arc<TokioMutex<Vec<String>>> = Arc::new(TokioMutex::new(Vec::new()));

    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| "config.toml".to_string());
    let config = match fs::read_to_string(&config_path) {
        Ok(content) => match Config::from_toml_str(&content) {
            Ok(cfg) => {
                println!("{}Loaded config from: {}", ICON_PLACEHOLDER, config_path);
                cfg
            }
            Err(err) => {
                eprintln!("❌ Failed to parse config file '{}': {}", config_path, err);
                return 1;
            }
        },
        // A typo in --config must not start an unprotected node.
        Err(err) if args.allow_default_config => {
            println!(
                "⚠️ Cannot read config file '{}' ({}); running with the default config (--allow-default-config).",
                config_path, err
            );
            Config::default()
        }
        Err(err) => {
            eprintln!(
                "❌ Cannot read config file '{}': {}. Pass --allow-default-config to run with built-in defaults.",
                config_path, err
            );
            return 1;
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
    emit_system("node", "identity_resolved", format!("id={}", node_id));

    // Load plugin libraries from `plugins/`. Every plugin is required: a library
    // that fails to load or register stops the host.
    let mut manager = PluginManager::new();
    let mut plugin_loader = PluginLoader::new();
    match plugin_loader.load_plugins("plugins", &mut manager) {
        Ok(_) => {}
        Err(PluginLoadError::Discover { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            println!(
                "{}No plugins directory found; running without plugins.",
                ICON_PLACEHOLDER
            );
        }
        Err(err) => {
            eprintln!("❌ Plugin loading failed: {}", err);
            return 1;
        }
    }

    // Apply plugin-supplied defaults ONLY for fields not explicitly set by user config.
    // Precedence order: user config > plugin override > library default.
    let mut config = config;
    let applied = apply_plugin_defaults(&mut config, manager.collect_config_defaults());
    if !applied.is_empty() {
        println!(
            "⚙️ Applied plugin-supplied config defaults (user config precedence preserved): {:?}",
            applied
        );
        emit_system(
            "config",
            "plugin_config_defaults_applied",
            format!("fields={:?}", applied),
        );
    }
    // A plugin default can configure encryption, or turn it off, when the
    // config file does not set it.
    if applied.contains(&"encryption") {
        let encryption = config.encryption.as_ref();
        let detail = format!(
            "enabled={} backend={}",
            encryption.is_some_and(|encryption| encryption.enabled),
            encryption
                .and_then(|encryption| encryption.backend.as_deref())
                .unwrap_or("unset")
        );
        println!(
            "⚠️ A plugin configured [encryption] ({}); set [encryption] in the config file to decide it yourself.",
            detail
        );
        let mut meta = dispatcher::meta("config", LogLevel::Warn);
        meta.corr_id = Some(dispatcher::correlation_id());
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: "plugin_default_encryption_applied".into(),
            detail: Some(detail),
        }));
    }

    // Finalize stores and the plugin context before any start hook runs.
    let peer_manager = Arc::new(PeerManager::new());
    let peer_store = PeerStore::from_config(&config).await;
    manager.set_context(PluginContext::new(
        peer_manager.clone(),
        peer_store.clone(),
        thenodes::events::dispatcher::handle(),
        node_id.clone(),
        config.clone(),
        !args.prompt,
    ));

    peer_manager.set_delivery_config(
        config
            .network
            .as_ref()
            .and_then(|network| network.delivery.clone()),
    );

    if let Some(relay) = config.network.as_ref().and_then(|n| n.relay.as_ref()) {
        let (per_target, global, max_bytes) = peer_manager.set_relay_queue_caps(
            relay.queue_max_per_target,
            relay.queue_max_global,
            relay.queue_max_bytes,
        );
        println!(
            "{}Relay queue caps: per_target={}, global={}, max_bytes={}",
            ICON_PLACEHOLDER, per_target, global, max_bytes
        );
    }

    // Build node identity binding from the final config before any connection,
    // so an invalid section stops startup instead of rejecting every peer.
    match peer_manager.node_identity(&config).policy() {
        Ok(policy) => println!(
            "{}Node identity binding: mode={:?}",
            ICON_PLACEHOLDER, policy.mode
        ),
        Err(error) => {
            eprintln!(
                "❌ Invalid [encryption.node_identity] configuration: {}",
                error
            );
            return 1;
        }
    }

    // A trust mode that cannot work with the configured directories stops
    // startup instead of trusting or recording nothing (ADR-0016).
    if let Err(error) = thenodes::security::trust::check_trust_config(&config) {
        eprintln!("❌ Invalid trust configuration: {}", error);
        return 1;
    }
    // CRL directories that would protect nothing, or CRLs that cannot be
    // read, stop startup (ADR-0014).
    match thenodes::security::encryption::check_revocation_config(&config) {
        Ok(warnings) => {
            for warning in warnings {
                eprintln!("⚠️ {}", warning);
                let mut meta = dispatcher::meta("trust", LogLevel::Warn);
                meta.corr_id = Some(dispatcher::correlation_id());
                dispatcher::emit(LogEvent::System(SystemEvent {
                    meta,
                    action: "crl_outdated".into(),
                    detail: Some(warning),
                }));
            }
        }
        Err(error) => {
            eprintln!("❌ Invalid CRL configuration: {}", error);
            return 1;
        }
    }

    let plugin_manager = Arc::new(manager);
    let mut failures = plugin_manager.subscribe_failures();
    peer_manager
        .configure_connection_lifecycle(
            config.clone(),
            node_id.clone(),
            &plugin_manager,
            peer_store.clone(),
            !args.prompt,
        )
        .await;

    // Load RealmInfo after overrides
    let realm = config.realm.clone().unwrap_or_else(RealmInfo::default);
    // Don't print full config here as it is ugly and may contain sensitive info.
    println!("{}Realm: {:?}", ICON_PLACEHOLDER, realm);

    // Start plugins in registration order. A shutdown request, or a failure of
    // a plugin that already started (for example in one of its managed tasks),
    // cancels startup and joins the common cleanup path.
    let start = plugin_manager.start_all(StartPolicy::StopOnFirstFailure);
    tokio::pin!(start);
    let start_report = tokio::select! {
        report = &mut start => report,
        _ = requests.recv() => {
            return shutdown_host(&plugin_manager, Vec::new(), &mut requests, ShutdownCause::Signal).await;
        }
        failure = next_failure(&mut failures) => {
            let cause = ShutdownCause::Startup(failure.to_string());
            return shutdown_host(&plugin_manager, Vec::new(), &mut requests, cause).await;
        }
    };
    let start_report = match start_report {
        Ok(report) => report,
        Err(err) => {
            let cause = ShutdownCause::Startup(err.to_string());
            return shutdown_host(&plugin_manager, Vec::new(), &mut requests, cause).await;
        }
    };
    for outcome in &start_report.outcomes {
        if let StartResult::Failed(failure) = &outcome.result {
            eprintln!("❌ {}", failure);
        }
    }
    if !start_report.all_started() {
        let failed: Vec<&str> = start_report
            .outcomes
            .iter()
            .filter(|outcome| outcome.result != StartResult::Started)
            .map(|outcome| outcome.plugin_id.as_str())
            .collect();
        let cause = ShutdownCause::Startup(format!("plugins not started: {}", failed.join(", ")));
        return shutdown_host(&plugin_manager, Vec::new(), &mut requests, cause).await;
    }

    #[cfg(feature = "upnp")]
    if let Some(nat_cfg) = config
        .network
        .as_ref()
        .and_then(|network| network.nat.as_ref())
    {
        thenodes::network::nat_portmap::initialize_port_mapping(
            peer_manager.as_ref(),
            nat_cfg,
            config.port,
            !args.prompt,
        )
        .await;
    }

    // Bind required local listeners and observe the result before activation.
    let mut listeners: Vec<JoinHandle<()>> = Vec::new();
    let tcp_bind_addr = std::net::SocketAddr::new(config.bind_ip(), config.port);
    let tcp_listener = match bind_listener_on(tcp_bind_addr, !args.prompt).await {
        Ok(listener) => listener,
        Err(err) => {
            let cause = ShutdownCause::Startup(format!(
                "TCP listener failed to bind port {}: {}",
                config.port, err
            ));
            return shutdown_host(&plugin_manager, listeners, &mut requests, cause).await;
        }
    };
    listeners.push(tokio::spawn({
        let peer_manager = (*peer_manager).clone();
        let plugin_manager = plugin_manager.clone();
        let realm = realm.clone();
        let config = config.clone();
        let node_id = node_id.clone();
        let peer_store = peer_store.clone();
        let emit_console_errors = !args.prompt;
        async move {
            if let Err(e) = run_listener(
                tcp_listener,
                realm,
                peer_manager,
                plugin_manager,
                &config,
                node_id,
                peer_store,
                emit_console_errors,
            )
            .await
            {
                eprintln!("❌ Listener error: {}", e);
            }
        }
    }));

    // UDP Noise listener (ADR-0004 Phase 1) + NAT traversal (ADR-0005 Phase 2+3) when enabled.
    // A configured UDP transport is required: failing to start it fails startup.
    #[cfg(feature = "noise")]
    {
        let udp_enabled = config
            .network
            .as_ref()
            .and_then(|n| n.udp.as_ref())
            .and_then(|u| u.enabled)
            .unwrap_or(false);
        if udp_enabled {
            if let Err(reason) =
                start_udp_transport(&config, &peer_manager, &plugin_manager, &node_id).await
            {
                let cause = ShutdownCause::Startup(reason);
                return shutdown_host(&plugin_manager, listeners, &mut requests, cause).await;
            }
        }
    }

    if let Err(err) = plugin_manager.activate() {
        let cause = ShutdownCause::Startup(err.to_string());
        return shutdown_host(&plugin_manager, listeners, &mut requests, cause).await;
    }

    // Connect to bootstrap nodes, pass error buffer
    connect_to_bootstrap_nodes(
        &config,
        realm.clone(),
        (*peer_manager).clone(),
        plugin_manager.clone(),
        error_buffer.clone(),
        !args.prompt,
        node_id.clone(),
        peer_store.clone(),
    )
    .await;

    let app_name = config
        .app_name
        .clone()
        .unwrap_or_else(|| DEFAULT_APP_NAME.to_string());
    println!("🟢 {} is running. Press Ctrl+C to shut down...", app_name);
    emit_system("node", "node_running", format!("node_id={}", node_id));

    let next_failure = next_failure(&mut failures);
    let cause = if args.prompt {
        // The interactive prompt blocks on terminal input, so it runs on a
        // blocking thread while this task keeps watching for failures and signals.
        let handle = tokio::runtime::Handle::current();
        let prompt_manager = plugin_manager.clone();
        let prompt_config = config.clone();
        let prompt = tokio::task::spawn_blocking(move || {
            handle.block_on(run_prompt_mode_with_errors(
                prompt_manager,
                prompt_config,
                Some(error_buffer),
            ))
        });
        tokio::select! {
            _ = prompt => ShutdownCause::PromptExit,
            failure = next_failure => ShutdownCause::PluginFailure(failure),
            _ = requests.recv() => ShutdownCause::Signal,
        }
    } else {
        tokio::select! {
            failure = next_failure => ShutdownCause::PluginFailure(failure),
            _ = requests.recv() => ShutdownCause::Signal,
        }
    };

    shutdown_host(&plugin_manager, listeners, &mut requests, cause).await
}

/// The next plugin failure. The subscription only ends when the manager is
/// dropped, which cannot happen while the host runs.
async fn next_failure(failures: &mut PluginFailureSubscription) -> PluginFailure {
    match failures.recv().await {
        Some(failure) => failure,
        None => std::future::pending().await,
    }
}

/// Common cleanup path for normal shutdown, prompt exit, failed startup, and
/// plugin failure. A second shutdown request escalates: the host stops waiting
/// on uncooperative plugin work, reports it, and exits unsuccessfully.
async fn shutdown_host(
    plugin_manager: &Arc<PluginManager>,
    listeners: Vec<JoinHandle<()>>,
    requests: &mut ShutdownRequests,
    cause: ShutdownCause,
) -> i32 {
    if cause.is_failure() {
        eprintln!("❌ {}; shutting down.", cause);
    } else {
        println!("🛑 Shutting down ({}).", cause);
    }
    let shutdown = plugin_manager.begin_shutdown(ShutdownMode::Drain);
    for listener in listeners {
        listener.abort();
        let _ = listener.await;
    }

    let wait = shutdown.wait();
    tokio::pin!(wait);
    let report = tokio::select! {
        report = &mut wait => report,
        _ = requests.recv() => {
            println!("🛑 Second shutdown request: escalating; no longer waiting on plugin work.");
            plugin_manager.escalate();
            wait.await
        }
    };

    match report {
        Ok(report) => {
            print_report(&report);
            if cause.is_failure() || !report.is_clean() {
                1
            } else {
                println!("✅ Shutdown complete.");
                0
            }
        }
        Err(err) => {
            eprintln!("❌ Shutdown did not produce a report: {}", err);
            1
        }
    }
}

fn print_report(report: &ShutdownReport) {
    println!(
        "{}Plugin shutdown report: clean={} escalated={} runtimes_released={} runtimes_retained={} elapsed_ms={}",
        ICON_PLACEHOLDER,
        report.is_clean(),
        report.escalated,
        report.runtimes_released,
        report.runtimes_retained,
        report.elapsed.as_millis()
    );
    for plugin in &report.plugins {
        let failure = plugin
            .failure
            .as_ref()
            .map(|failure| failure.to_string())
            .unwrap_or_else(|| "none".to_string());
        println!(
            "{}  plugin={} state={:?} stop={:?} discarded_messages={} aborted_tasks={} failure={}",
            ICON_PLACEHOLDER,
            plugin.plugin_id,
            plugin.final_state,
            plugin.stop,
            plugin.discarded_messages,
            plugin.aborted_tasks,
            failure
        );
    }
    if report.escalated {
        println!(
            "{}Escalated: plugin work listed as FailedToQuiesce was not observed to end; its code stays loaded until the process exits.",
            ICON_PLACEHOLDER
        );
    }
}

fn emit_system(component: &'static str, action: &str, detail: String) {
    let mut meta = dispatcher::meta(component, LogLevel::Info);
    meta.corr_id = Some(dispatcher::correlation_id());
    dispatcher::emit(LogEvent::System(SystemEvent {
        meta,
        action: action.into(),
        detail: Some(detail),
    }));
}

/// Apply plugin defaults to fields the operator did not set. Returns the
/// names of the fields that were applied.
fn apply_plugin_defaults(config: &mut Config, overrides: ConfigDefaults) -> Vec<&'static str> {
    let mut applied: Vec<&'static str> = Vec::new();
    if let Some(p) = overrides.port {
        // Only apply if the port still equals the library default (50000).
        if config.port == 50000 {
            config.port = p;
            applied.push("port");
        }
    }
    if let Some(r) = overrides.realm {
        if config.realm.is_none() {
            config.realm = Some(r);
            applied.push("realm");
        }
    }
    if let Some(a) = overrides.app_name {
        if config.app_name.is_none() {
            config.app_name = Some(a);
            applied.push("app_name");
        }
    }
    if let Some(enc) = overrides.encryption {
        if config.encryption.is_none() {
            config.encryption = Some(enc);
            applied.push("encryption");
        }
    }
    if let Some(bs) = overrides.bootstrap_nodes {
        if config.bootstrap_nodes.is_none() {
            config.bootstrap_nodes = Some(bs);
            applied.push("bootstrap_nodes");
        }
    }
    // Append semantics for bootstrap_nodes_extend (dedupe, preserve order preference: existing first)
    if let Some(extra) = overrides.bootstrap_nodes_extend {
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
    if let Some(logcfg) = overrides.logging {
        if config.logging.is_none() {
            config.logging = Some(logcfg);
            applied.push("logging");
        }
    }
    if let Some(nodecfg) = overrides.node {
        if config.node.is_none() {
            config.node = Some(nodecfg);
            applied.push("node");
        }
    }
    if let Some(disc) = overrides.discovery {
        if config.discovery.is_none() {
            config.discovery = Some(disc);
            applied.push("discovery");
        }
    }
    applied
}

#[cfg(feature = "noise")]
async fn start_udp_transport(
    config: &Config,
    peer_manager: &Arc<PeerManager>,
    plugin_manager: &Arc<PluginManager>,
    node_id: &str,
) -> Result<(), String> {
    // Build NatState from config when nat_traversal is enabled (ADR-0005).
    let nat_state_opt: Option<Arc<thenodes::network::nat_traversal::NatState>> = config
        .network
        .as_ref()
        .and_then(|n| n.nat_traversal.as_ref())
        .filter(|nt| nt.enabled.unwrap_or(false))
        .map(|nt| Arc::new(thenodes::network::nat_traversal::NatState::from_config(nt)));

    if let Some(ref nat) = nat_state_opt {
        peer_manager.set_nat_state(nat.clone()).await;
    }

    let (static_private, _static_public) = thenodes::network::udp_listener::load_static_key(config)
        .map_err(|e| format!("failed to load Noise static keypair: {}", e))?;
    let udp_port = config
        .network
        .as_ref()
        .and_then(|n| n.udp.as_ref())
        .and_then(|u| u.listen_port)
        .unwrap_or(config.port + 1);
    let bind_addr = std::net::SocketAddr::new(config.bind_ip(), udp_port);
    let (socket, sessions) = thenodes::network::udp_listener::spawn_udp_listener(
        bind_addr,
        (**peer_manager).clone(),
        plugin_manager.clone(),
        node_id.to_string(),
        config.clone(),
        static_private,
        nat_state_opt.clone(),
    )
    .await
    .map_err(|e| format!("UDP listener failed to bind port {}: {}", udp_port, e))?;
    println!(
        "{}UDP Noise listener bound on {}",
        ICON_PLACEHOLDER, bind_addr
    );
    thenodes::network::udp_listener::spawn_session_reaper(sessions);
    // Spawn observation refresh loop when NAT traversal is enabled.
    if let Some(nat) = nat_state_opt {
        thenodes::network::nat_traversal::spawn_observation_refresh_loop(
            nat,
            (**peer_manager).clone(),
            socket,
        );
    }
    Ok(())
}

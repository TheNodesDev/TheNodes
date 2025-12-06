use std::io::Write;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

use crate::config::Config;
use crate::constants::{
    build_timestamp, git_commit, APP_VERSION, ICON_PLACEHOLDER, PROTOCOL_VERSION,
};
use crate::plugin_host::manager::PluginManager;

pub async fn run_prompt_mode(plugin_manager: Arc<PluginManager>, config: Config) {
    run_prompt_mode_with_shells(plugin_manager, config, None, false, false, None).await
}

/// Prompt runner with optional error buffer for status reporting.
pub async fn run_prompt_mode_with_errors(
    plugin_manager: Arc<PluginManager>,
    config: Config,
    error_buffer: Option<Arc<TokioMutex<Vec<String>>>>,
) {
    run_prompt_mode_with_shells(plugin_manager, config, None, false, false, error_buffer).await
}

/// Branded prompt runner: provide a brand (e.g., "MyApp") to replace the default label (single shell).
pub async fn run_prompt_mode_with_branding(
    plugin_manager: Arc<PluginManager>,
    config: Config,
    brand: Option<String>,
) {
    run_prompt_mode_with_shells(plugin_manager, config, brand, false, false, None).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellKind {
    App,
    Core,
}

/// Dual-shell prompt runner. When `dual_shells` is true, users can switch between App and Core shells via
/// `shell app` and `shell core`. `start_in_core` controls the initial shell when dual is enabled.
pub async fn run_prompt_mode_with_shells(
    plugin_manager: Arc<PluginManager>,
    config: Config,
    brand: Option<String>,
    dual_shells: bool,
    start_in_core: bool,
    error_buffer: Option<Arc<TokioMutex<Vec<String>>>>,
) {
    let mut stdout = std::io::stdout();
    let mut current_plugin: Option<Arc<dyn crate::plugin_host::Plugin>> = None;
    let mut current_prefix: Option<String> = None;
    let mut shell = if dual_shells && start_in_core {
        ShellKind::Core
    } else {
        ShellKind::App
    };

    // Setup line editor with completion
    use rustyline::{CompletionType, Config as RLConfig, Editor};
    let rl_cfg = RLConfig::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .build();
    let mut rl: Editor<PromptCompleter, rustyline::history::DefaultHistory> =
        Editor::with_config(rl_cfg).expect("rustyline init");
    let helper = PromptCompleter {
        config: config.clone(),
        plugin_prefixes: plugin_manager.all_prompt_prefixes(),
        builtins: vec![
            "version".into(),
            "/version".into(),
            "about".into(),
            "/about".into(),
            "help".into(),
            "/help".into(),
            "exit".into(),
            "quit".into(),
            "/quit".into(),
            "peers".into(),
            "/peers".into(),
            "status".into(),
            "/status".into(),
            "trust".into(),
            // shell management
            "shell".into(),
            "shell app".into(),
            "shell core".into(),
        ],
        in_plugin: false,
        plugin_builtins: vec!["exit".into(), "help".into(), "/help".into()],
    };
    rl.set_helper(Some(helper));

    let peer_manager = plugin_manager
        .context
        .as_ref()
        .map(|ctx| ctx.peer_manager.clone());
    let peer_store = plugin_manager
        .context
        .as_ref()
        .map(|ctx| ctx.peer_store.clone());

    // Load history from HOME/USERPROFILE if available; fallback to local file
    let hist_path = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(|home| std::path::PathBuf::from(home).join(".thenodes_history"))
        .unwrap_or_else(|_| std::path::PathBuf::from(".thenodes_history"));
    let _ = rl.load_history(hist_path.as_path());

    loop {
        let app_label = brand
            .clone()
            .or(config.app_name.clone())
            .unwrap_or_else(|| "TheNodes".to_string());
        let core_label = "TheNodes".to_string();
        let prompt_label = if let Some(ref prefix) = current_prefix {
            format!("{}> ", prefix)
        } else {
            match (dual_shells, shell) {
                (true, ShellKind::App) => format!("{}> ", app_label),
                (true, ShellKind::Core) => format!("{}> ", core_label),
                _ => match &brand {
                    Some(b) => format!("{}> ", b),
                    None => "TheNodes> ".to_string(),
                },
            }
        };
        stdout.flush().unwrap();
        let readline = rl.readline(&prompt_label);
        let input_owned = match readline {
            Ok(mut l) => {
                l.truncate(l.trim_end().len());
                l
            }
            Err(rustyline::error::ReadlineError::Eof)
            | Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("👋 Exiting.");
                break;
            }
            Err(e) => {
                println!("❌ Read error: {}", e);
                break;
            }
        };
        let input = input_owned.trim();

        if input.is_empty() {
            continue;
        }

        if input == "exit" || input == "/quit" || input == "quit" {
            if current_plugin.is_some() {
                println!("{}Leaving plugin prompt", ICON_PLACEHOLDER);
                current_plugin = None;
                current_prefix = None;
                if let Some(h) = rl.helper_mut() {
                    h.in_plugin = false;
                }
                continue;
            } else {
                // Confirm exit/quit at root
                match rl.readline("Confirm exit? [y/N] ") {
                    Ok(ans) => {
                        let a = ans.trim().to_lowercase();
                        if a == "y" || a == "yes" {
                            println!("👋 Exiting.");
                            break;
                        } else {
                            println!("Abort.");
                            continue;
                        }
                    }
                    Err(_) => {
                        println!("👋 Exiting.");
                        break;
                    }
                }
            }
        }

        if current_plugin.is_none() {
            // Root-level commands (not inside a plugin)
            match input {
                "version" | "/version" | "about" | "/about" => {
                    println!(
                        "{}TheNodes version v{} (protocol={})\ncommit: {}\nbuilt: {}",
                        ICON_PLACEHOLDER,
                        APP_VERSION,
                        PROTOCOL_VERSION,
                        git_commit(),
                        build_timestamp()
                    );
                    continue;
                }
                "help" | "/help" => {
                    // Compose help dynamically to include plugin prefixes
                    let cmds: Vec<&str> = vec![
                        "version, /version   Show version & build info",
                        "about, /about       Alias of version",
                        "help, /help         Show this help",
                        "peers, /peers       List connected peers",
                        "status, /status     Show peers and recent connection errors",
                        if dual_shells {
                            "shell app           Switch to application shell"
                        } else {
                            ""
                        },
                        if dual_shells {
                            "shell core          Switch to core/admin shell"
                        } else {
                            ""
                        },
                        "exit                Leave plugin; at root, confirm + exit app",
                        "quit, /quit         Confirm + exit app",
                        "trust observed list List observed cert fingerprints",
                        "trust trusted list  List trusted cert filenames",
                        "trust promote <fp>  Promote observed fingerprint to trusted",
                        "trust own list      List own cert fingerprints",
                    ];
                    println!("Available commands:");
                    for c in &cmds {
                        if !c.is_empty() {
                            println!("  {}", c);
                        }
                    }
                    let prefixes = plugin_manager.all_prompt_prefixes();
                    if !prefixes.is_empty() {
                        println!("\nPlugins (enter to switch):");
                        for p in prefixes {
                            println!("  {}", p);
                        }
                    }
                    println!("\nTips: Use Tab to autocomplete commands and trust fingerprints.");
                    continue;
                }
                "peers" | "/peers" => {
                    if let Some(pm) = peer_manager.as_ref() {
                        let peers = pm.list_peers().await;
                        if peers.is_empty() {
                            println!("No connected peers.");
                        } else {
                            println!("Connected peers:");
                            for addr in peers {
                                println!("  {}", addr);
                            }
                        }
                    } else {
                        println!("Peer manager unavailable (not initialized).");
                    }
                    continue;
                }
                "status" | "/status" => {
                    println!("--- Connection Status ---");
                    if let Some(pm) = peer_manager.as_ref() {
                        let peers = pm.list_peers().await;
                        if peers.is_empty() {
                            println!("No connected peers.");
                        } else {
                            println!("Connected peers:");
                            for addr in peers {
                                println!("  {}", addr);
                            }
                        }
                    } else {
                        println!("Peer manager unavailable (not initialized).");
                    }
                    if let Some(buf) = &error_buffer {
                        let errors = buf.lock().await;
                        if errors.is_empty() {
                            println!("No recent connection errors.");
                        } else {
                            println!("Recent connection errors:");
                            for err in errors.iter().rev().take(5) {
                                println!("  {}", err);
                            }
                        }
                    } else {
                        println!("Error buffer unavailable.");
                    }
                    println!("-------------------------");
                    continue;
                }
                cmd if cmd.starts_with("shell ") && dual_shells => {
                    match cmd.split_whitespace().nth(1) {
                        Some("app") => {
                            shell = ShellKind::App;
                            println!("{}Switched to application shell", ICON_PLACEHOLDER);
                        }
                        Some("core") => {
                            shell = ShellKind::Core;
                            println!("{}Switched to core shell", ICON_PLACEHOLDER);
                        }
                        _ => println!("{}Usage: shell [app|core]", ICON_PLACEHOLDER),
                    }
                    continue;
                }
                cmd if cmd.starts_with("trust ") || cmd == "trust" => {
                    // trust commands: list observed|trusted, promote <fingerprint>
                    // Resolve dirs from config
                    let enc = config.encryption.as_ref();
                    let tp = enc.and_then(|e| e.trust_policy.as_ref());
                    let paths = enc.and_then(|e| e.paths.as_ref());
                    let observed_dir = tp
                        .and_then(|t| t.paths.as_ref())
                        .and_then(|p| p.observed_dir.as_deref());
                    let trusted_dir = paths.and_then(|p| p.trusted_cert_dir.as_deref());

                    let parts: Vec<&str> = cmd.split_whitespace().collect();
                    if parts.len() == 1 {
                        println!("{}Usage:\n      trust observed list\n      trust trusted list\n      trust promote <spki_sha256_fingerprint>\n      trust own list", ICON_PLACEHOLDER);
                        continue;
                    }
                    match (
                        parts.get(1).copied(),
                        parts.get(2).copied(),
                        parts.get(3).copied(),
                    ) {
                        (Some("observed"), Some("list"), _) => {
                            if let Some(dir) = observed_dir {
                                match std::fs::read_dir(dir) {
                                    Ok(entries) => {
                                        println!("{}Observed certs in {}:", ICON_PLACEHOLDER, dir);
                                        let mut count = 0u32;
                                        for e in entries.flatten() {
                                            if let Some(name) = e.file_name().to_str() {
                                                if name.ends_with(".pem") {
                                                    println!(
                                                        "{}  {}",
                                                        ICON_PLACEHOLDER,
                                                        name.trim_end_matches(".pem")
                                                    );
                                                    count += 1;
                                                }
                                            }
                                        }
                                        if count == 0 {
                                            println!("{}  <none>", ICON_PLACEHOLDER);
                                        }
                                    }
                                    Err(e) => eprintln!("❌ Failed to read {}: {}", dir, e),
                                }
                            } else {
                                println!("{}observed_dir not configured. Set [encryption.trust_policy.paths].observed_dir", ICON_PLACEHOLDER);
                            }
                            continue;
                        }
                        (Some("trusted"), Some("list"), _) => {
                            if let Some(dir) = trusted_dir {
                                match std::fs::read_dir(dir) {
                                    Ok(entries) => {
                                        println!("Trusted certs in {}:", dir);
                                        let mut any = false;
                                        for e in entries.flatten() {
                                            if let Some(name) = e.file_name().to_str() {
                                                if name.ends_with(".pem") {
                                                    println!("  {}", name);
                                                    any = true;
                                                }
                                            }
                                        }
                                        if !any {
                                            println!("  <none>");
                                        }
                                    }
                                    Err(e) => eprintln!("❌ Failed to read {}: {}", dir, e),
                                }
                            } else {
                                println!("{}trusted_cert_dir not configured. Set [encryption.paths].trusted_cert_dir", ICON_PLACEHOLDER);
                            }
                            continue;
                        }
                        (Some("promote"), Some(fp), _) => {
                            if fp.len() < 6 {
                                eprintln!("❌ Fingerprint looks too short");
                                continue;
                            }
                            if let (Some(obs), Some(tru)) = (observed_dir, trusted_dir) {
                                match crate::security::trust::promote_observed_to_trusted(
                                    obs, tru, fp,
                                ) {
                                    Ok(true) => {
                                        println!("✅ Promoted {} to trusted", fp);
                                        if let (Some(pm), Some(store)) =
                                            (peer_manager.clone(), peer_store.clone())
                                        {
                                            // Spawn reconnects in the background so the prompt
                                            // remains responsive after a promotion.
                                            let pm_clone = pm.clone();
                                            let plugin_manager_clone = plugin_manager.clone();
                                            let store_clone = store.clone();
                                            let config_clone = config.clone();
                                            println!(
                                                "{}Reconnecting to known peers in background...",
                                                ICON_PLACEHOLDER
                                            );
                                            tokio::spawn(async move {
                                                pm_clone
                                                    .reconnect_known_peers(
                                                        plugin_manager_clone,
                                                        store_clone,
                                                        &config_clone,
                                                    )
                                                    .await;
                                            });
                                        } else {
                                            println!(
                                                "{} Peer reconnect skipped (state unavailable).",
                                                ICON_PLACEHOLDER
                                            );
                                        }
                                    }
                                    Ok(false) => println!(
                                        "ℹ️ Nothing to do (missing in observed or already trusted)"
                                    ),
                                    Err(e) => eprintln!("❌ Promotion failed: {}", e),
                                }
                            } else {
                                println!(
                                    "{}Both observed_dir and trusted_cert_dir must be configured.",
                                    ICON_PLACEHOLDER
                                );
                            }
                            continue;
                        }
                        (Some("own"), Some("list"), _) => {
                            if let Some(paths_cfg) = paths {
                                if let Some(path_str) = &paths_cfg.own_certificate {
                                    let path = std::path::Path::new(path_str);
                                    if path.is_dir() {
                                        match std::fs::read_dir(path) {
                                            Ok(entries) => {
                                                println!(
                                                    "{}Own certs in {}:",
                                                    ICON_PLACEHOLDER,
                                                    path.display()
                                                );
                                                let mut any = false;
                                                for e in entries.flatten() {
                                                    let entry_path = e.path();
                                                    if entry_path
                                                        .extension()
                                                        .and_then(|ext| ext.to_str())
                                                        .map(|ext| {
                                                            ext.eq_ignore_ascii_case("pem")
                                                                || ext.eq_ignore_ascii_case("crt")
                                                        })
                                                        .unwrap_or(false)
                                                    {
                                                        let name = entry_path
                                                            .file_name()
                                                            .and_then(|n| n.to_str())
                                                            .unwrap_or("<unknown>");
                                                        let fp = match crate::security::trust::spki_fingerprint_from_pem_file(&entry_path) {
                                                            Ok(fp) => fp,
                                                            Err(_) => "unknown".to_string(),
                                                        };
                                                        println!(
                                                            "{}  {} (fingerprint: {})",
                                                            ICON_PLACEHOLDER, name, fp
                                                        );
                                                        any = true;
                                                    }
                                                }
                                                if !any {
                                                    println!("{}  <none>", ICON_PLACEHOLDER);
                                                }
                                            }
                                            Err(e) => eprintln!(
                                                "❌ Failed to read {}: {}",
                                                path.display(),
                                                e
                                            ),
                                        }
                                    } else if path.is_file() {
                                        match crate::security::trust::spki_fingerprint_from_pem_file(
                                            path,
                                        ) {
                                            Ok(fp) => {
                                                println!(
                                                    "{}Own certificate {} fingerprint: {}",
                                                    ICON_PLACEHOLDER,
                                                    path.display(),
                                                    fp
                                                );
                                            }
                                            Err(e) => eprintln!(
                                                "❌ Failed to compute fingerprint for {}: {}",
                                                path.display(),
                                                e
                                            ),
                                        }
                                    } else {
                                        println!(
                                            "{}Configured own_certificate path '{}' does not exist.",
                                            ICON_PLACEHOLDER,
                                            path.display()
                                        );
                                    }
                                } else {
                                    println!("{}own_certificate path not configured. Set [encryption.paths].own_certificate", ICON_PLACEHOLDER);
                                }
                            } else {
                                println!("{}encryption.paths not configured.", ICON_PLACEHOLDER);
                            }
                            continue;
                        }
                        _ => {
                            println!("{}Usage:\n      trust observed list\n      trust trusted list\n      trust promote <spki_sha256_fingerprint>\n      trust own list", ICON_PLACEHOLDER);
                            continue;
                        }
                    }
                }
                _ => {}
            }
            if let Some(plugin) = plugin_manager.get_prompt_plugin(input) {
                println!("{}Entering plugin: {}", ICON_PLACEHOLDER, input);
                current_prefix = Some(input.to_string());
                current_plugin = Some(plugin);
                if let Some(h) = rl.helper_mut() {
                    h.in_plugin = true;
                }
                continue;
            } else {
                println!(
                    "⚠️ Unknown command or plugin: '{}'. Available: {:?}",
                    input,
                    plugin_manager.all_prompt_prefixes()
                );
                continue;
            }
        }

        if let Some(ref plugin) = current_plugin {
            if let Some(ctx) = &plugin_manager.context {
                match plugin.on_prompt(input, ctx).await {
                    Some(reply) => println!("{}", reply),
                    None => println!("⚠️ Unhandled input: '{}'", input),
                }
            } else {
                println!("❌ Plugin context unavailable.");
            }
        }
    }

    // Save history on exit
    let _ = rl.save_history(&hist_path);
}

// Back-compat alias removed for initial release.

// Simple completer for trust commands and observed fingerprints
struct PromptCompleter {
    config: Config,
    plugin_prefixes: Vec<String>,
    builtins: Vec<String>,
    in_plugin: bool,
    plugin_builtins: Vec<String>,
}

impl rustyline::Helper for PromptCompleter {}

impl rustyline::hint::Hinter for PromptCompleter {
    type Hint = String;
    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<Self::Hint> {
        None
    }
}

impl rustyline::highlight::Highlighter for PromptCompleter {}

impl rustyline::validate::Validator for PromptCompleter {}

impl rustyline::completion::Completer for PromptCompleter {
    type Candidate = rustyline::completion::Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> Result<(usize, Vec<Self::Candidate>), rustyline::error::ReadlineError> {
        let before = &line[..pos];
        let mut out: Vec<Self::Candidate> = Vec::new();

        // Determine the current token start position
        let token_start = before
            .rfind(char::is_whitespace)
            .map(|i| i + 1)
            .unwrap_or(0);
        let current = &before[token_start..];

        // If first token or empty current token, offer built-ins + plugin prefixes (root) or plugin builtins (plugin scope)
        let first_space = before.find(char::is_whitespace);
        if first_space.is_none() {
            if self.in_plugin {
                for s in &self.plugin_builtins {
                    if s.starts_with(current) {
                        out.push(rustyline::completion::Pair {
                            display: s.clone(),
                            replacement: s.clone(),
                        });
                    }
                }
            } else {
                for s in self.builtins.iter().chain(self.plugin_prefixes.iter()) {
                    if s.starts_with(current) {
                        out.push(rustyline::completion::Pair {
                            display: s.clone(),
                            replacement: s.clone(),
                        });
                    }
                }
            }
            return Ok((token_start, out));
        }

        // Parse tokens to specialize completion sets
        let parts: Vec<&str> = before.split_whitespace().collect();
        if !self.in_plugin && parts.first().copied() == Some("trust") {
            match parts.get(1).copied().unwrap_or("") {
                sub if sub.is_empty() || "observed".starts_with(sub) || sub.starts_with("o") => {
                    let opts = ["observed list"];
                    for o in opts {
                        if o.starts_with(sub) {
                            out.push(rustyline::completion::Pair {
                                display: o.into(),
                                replacement: o.into(),
                            });
                        }
                    }
                    return Ok((token_start, out));
                }
                sub if "trusted".starts_with(sub) || sub.starts_with("t") => {
                    let opts = ["trusted list"];
                    for o in opts {
                        if o.starts_with(sub) {
                            out.push(rustyline::completion::Pair {
                                display: o.into(),
                                replacement: o.into(),
                            });
                        }
                    }
                    return Ok((token_start, out));
                }
                sub if "promote".starts_with(sub) || sub.starts_with("p") => {
                    // If only typing the word promote, complete it
                    if parts.len() < 3 && !before.ends_with(' ') {
                        out.push(rustyline::completion::Pair {
                            display: "promote ".into(),
                            replacement: "promote ".into(),
                        });
                        return Ok((token_start, out));
                    }
                    // If user typed 'trust promote <partial>', offer fingerprints
                    if let Some(fp_prefix) = parts.get(2).copied() {
                        let enc = self.config.encryption.as_ref();
                        let tp = enc.and_then(|e| e.trust_policy.as_ref());
                        let observed_dir = tp
                            .and_then(|t| t.paths.as_ref())
                            .and_then(|p| p.observed_dir.as_deref());
                        if let Some(dir) = observed_dir {
                            if let Ok(entries) = std::fs::read_dir(dir) {
                                for e in entries.flatten() {
                                    if let Some(name) = e.file_name().to_str() {
                                        if name.ends_with(".pem") {
                                            let fp = name.trim_end_matches(".pem");
                                            if fp.starts_with(fp_prefix) {
                                                out.push(rustyline::completion::Pair {
                                                    display: fp.into(),
                                                    replacement: fp.into(),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        return Ok((token_start, out));
                    }
                }
                _ => {}
            }
            return Ok((token_start, out));
        }

        // Default: no suggestions
        Ok((token_start, out))
    }
}

use std::io::Write;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

use crate::config::Config;
use crate::constants::{
    build_timestamp, git_commit, APP_VERSION, ICON_PLACEHOLDER, PROTOCOL_VERSION,
};
use crate::plugin_host::manager::{PluginManager, PromptTarget};

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
    let mut current_plugin: Option<PromptTarget> = None;
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
        .and_then(|ctx| ctx.peer_manager().cloned());
    let peer_store = plugin_manager
        .context
        .as_ref()
        .and_then(|ctx| ctx.peer_store().cloned());

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
                        "trust rejected list List rejected keys (TLS and Noise)",
                        "trust trusted list  List trusted keys (TLS and Noise)",
                        "trust promote <fp>  Move a rejected key to trusted",
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
                    // trust commands: list rejected|trusted, promote <fingerprint>
                    let paths = config.tls().and_then(|t| t.paths.as_ref());
                    let stores = crate::security::trust::key_stores(&config);

                    let parts: Vec<&str> = cmd.split_whitespace().collect();
                    if parts.len() == 1 {
                        println!("{}Usage:\n      trust rejected list\n      trust trusted list\n      trust promote <sha256_fingerprint>\n      trust own list", ICON_PLACEHOLDER);
                        continue;
                    }
                    match (
                        parts.get(1).copied(),
                        parts.get(2).copied(),
                        parts.get(3).copied(),
                    ) {
                        (Some(which @ ("rejected" | "trusted")), Some("list"), _) => {
                            let mut configured = false;
                            for store in &stores {
                                let dir = if which == "rejected" {
                                    &store.rejected_dir
                                } else {
                                    &store.trusted_dir
                                };
                                let Some(dir) = dir else { continue };
                                configured = true;
                                match crate::security::trust::list_key_files(dir, store.extension) {
                                    Ok(names) => {
                                        println!(
                                            "{}{} {} keys in {}:",
                                            ICON_PLACEHOLDER, store.backend, which, dir
                                        );
                                        if names.is_empty() {
                                            println!("{}  <none>", ICON_PLACEHOLDER);
                                        }
                                        for name in names {
                                            println!("{}  {}", ICON_PLACEHOLDER, name);
                                        }
                                    }
                                    Err(e) => eprintln!("❌ Failed to read {}: {}", dir, e),
                                }
                            }
                            if !configured {
                                println!(
                                    "{}No {} directory configured. Set it in [encryption.tls.paths] or [encryption.noise.paths]",
                                    ICON_PLACEHOLDER, which
                                );
                            }
                            continue;
                        }
                        (Some("promote"), Some(fp), _) => {
                            let mut outcome = Ok(None);
                            for store in &stores {
                                match crate::security::trust::promote_rejected_to_trusted(store, fp)
                                {
                                    Ok(true) => {
                                        outcome = Ok(Some(store.backend));
                                        break;
                                    }
                                    Ok(false) => {}
                                    Err(e) => {
                                        outcome = Err(e);
                                        break;
                                    }
                                }
                            }
                            match outcome {
                                Ok(Some(backend)) => {
                                    println!("✅ Promoted {} to trusted ({})", fp, backend);
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
                                Ok(None) => println!(
                                    "ℹ️ Nothing to do ({} is in no rejected directory, or a trusted directory is missing)",
                                    fp
                                ),
                                Err(e) => eprintln!("❌ Promotion failed: {}", e),
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
                                    println!("{}own_certificate path not configured. Set [encryption.tls.paths].own_certificate", ICON_PLACEHOLDER);
                                }
                            } else {
                                println!(
                                    "{}encryption.tls.paths not configured.",
                                    ICON_PLACEHOLDER
                                );
                            }
                            continue;
                        }
                        _ => {
                            println!("{}Usage:\n      trust rejected list\n      trust trusted list\n      trust promote <sha256_fingerprint>\n      trust own list", ICON_PLACEHOLDER);
                            continue;
                        }
                    }
                }
                _ => {}
            }
            if let Some(target) = plugin_manager.resolve_prompt(input) {
                println!("{}Entering plugin: {}", ICON_PLACEHOLDER, input);
                current_prefix = Some(input.to_string());
                current_plugin = Some(target);
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

        if let Some(target) = &current_plugin {
            // Every call goes through managed admission; a retained selection
            // cannot invoke a plugin that is stopping or has failed.
            match plugin_manager.dispatch_prompt(target, input).await {
                Ok(Some(reply)) => println!("{}", reply),
                Ok(None) => println!("⚠️ Unhandled input: '{}'", input),
                Err(error) => println!("⚠️ Plugin '{}' {}", target.plugin_id(), error),
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
                sub if sub.is_empty() || "rejected".starts_with(sub) || sub.starts_with("r") => {
                    let opts = ["rejected list"];
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
                        for store in crate::security::trust::key_stores(&self.config) {
                            let Some(dir) = store.rejected_dir.as_deref() else {
                                continue;
                            };
                            let names =
                                crate::security::trust::list_key_files(dir, store.extension)
                                    .unwrap_or_default();
                            for name in names {
                                let fp = name
                                    .strip_suffix(&format!(".{}", store.extension))
                                    .unwrap_or(&name);
                                if fp.starts_with(fp_prefix) {
                                    out.push(rustyline::completion::Pair {
                                        display: fp.into(),
                                        replacement: fp.into(),
                                    });
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

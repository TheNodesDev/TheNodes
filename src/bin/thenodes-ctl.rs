use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// thenodes-ctl: Admin CLI for TheNodes daemon operations (trust/cert management)
///
/// This tool manages PKI/trust state via the filesystem based on a TheNodes config file.
/// It does not require the daemon to be started in --prompt mode and works offline.
#[derive(Parser, Debug)]
#[command(
    name = "thenodes-ctl",
    version,
    about = "Admin CLI for TheNodes (trust/certs)"
)]
struct Cli {
    /// Path to TheNodes config file (TOML)
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Trust store operations
    Trust {
        #[command(subcommand)]
        cmd: TrustCmd,
    },
    /// Certificate operations (own cert, fingerprints, etc.)
    Cert {
        #[command(subcommand)]
        cmd: CertCmd,
    },
    /// Node identity bindings ([encryption.node_identity].bindings_file)
    NodeBinding {
        #[command(subcommand)]
        cmd: NodeBindingCmd,
    },
}

#[derive(Subcommand, Debug)]
enum NodeBindingCmd {
    /// List persisted TOFU bindings
    List,
    /// Forget every binding for a node ID, e.g. after it rotated its key.
    /// A running node keeps its in-memory bindings until it restarts.
    Forget { node_id: String },
}

#[derive(Subcommand, Debug)]
enum TrustCmd {
    /// List rejected keys (TLS rejected_dir, Noise rejected_dir)
    RejectedList,
    /// List trusted keys (TLS trusted_cert_dir, Noise trusted_dir)
    TrustedList,
    /// Move a rejected key, by fingerprint, into the trusted directory
    Promote { fingerprint: String },
}

#[derive(Subcommand, Debug)]
enum CertCmd {
    /// Show the SPKI SHA-256 fingerprint of the node's own certificate
    Fingerprint {
        /// Override certificate path (defaults to [encryption.tls.paths].own_certificate or pki/own/cert.pem)
        #[arg(long)]
        cert: Option<PathBuf>,
    },
}

fn load_config(path: &PathBuf) -> thenodes::config::Config {
    match std::fs::read_to_string(path) {
        Ok(content) => match thenodes::config::Config::from_toml_str(&content) {
            Ok(cfg) => cfg,
            Err(err) => {
                eprintln!(
                    "❌ Failed to parse config file '{}': {}",
                    path.display(),
                    err
                );
                std::process::exit(2);
            }
        },
        Err(err) => {
            eprintln!(
                "❌ Failed to read config file '{}': {}",
                path.display(),
                err
            );
            std::process::exit(2);
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let config = load_config(&cli.config);

    match cli.command {
        Commands::Trust { cmd } => {
            use thenodes::security::trust::{
                key_stores, list_key_files, promote_rejected_to_trusted,
            };
            let stores = key_stores(&config);
            match cmd {
                TrustCmd::RejectedList | TrustCmd::TrustedList => {
                    let rejected = matches!(cmd, TrustCmd::RejectedList);
                    let mut configured = false;
                    for store in &stores {
                        let dir = if rejected {
                            &store.rejected_dir
                        } else {
                            &store.trusted_dir
                        };
                        let Some(dir) = dir else { continue };
                        configured = true;
                        match list_key_files(dir, store.extension) {
                            Ok(names) if names.is_empty() => {
                                println!("{} <none> ({dir})", store.backend)
                            }
                            Ok(names) => {
                                for name in names {
                                    println!("{} {name}", store.backend);
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to read {}: {}", dir, e);
                                std::process::exit(1);
                            }
                        }
                    }
                    if !configured {
                        let (tls, noise) = if rejected {
                            ("rejected_dir", "rejected_dir")
                        } else {
                            ("trusted_cert_dir", "trusted_dir")
                        };
                        eprintln!(
                            "No directory configured. Set [encryption.tls.paths] {tls} or [encryption.noise.paths] {noise} in {}",
                            cli.config.display()
                        );
                        std::process::exit(2);
                    }
                }
                TrustCmd::Promote { fingerprint } => {
                    let mut promoted = None;
                    for store in &stores {
                        match promote_rejected_to_trusted(store, &fingerprint) {
                            Ok(true) => {
                                promoted = Some(store.backend);
                                break;
                            }
                            Ok(false) => {}
                            Err(e) => {
                                eprintln!("❌ Promotion failed: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                    match promoted {
                        Some(backend) => println!("Promoted {fingerprint} to trusted ({backend})"),
                        None => println!(
                            "No-op: {fingerprint} is in no rejected directory (both rejected and trusted directories must be configured)"
                        ),
                    }
                }
            }
        }
        Commands::NodeBinding { cmd } => {
            let Some(path) = config
                .encryption
                .as_ref()
                .and_then(|enc| enc.node_identity.as_ref())
                .and_then(|identity| identity.bindings_file.as_ref())
                .map(PathBuf::from)
            else {
                eprintln!(
                    "bindings_file not configured. Set [encryption.node_identity].bindings_file in {}",
                    cli.config.display()
                );
                std::process::exit(2);
            };
            match cmd {
                NodeBindingCmd::List => {
                    match thenodes::security::node_identity::load_bindings_file(&path) {
                        Ok(bindings) if bindings.is_empty() => println!("<none>"),
                        Ok(bindings) => {
                            for binding in bindings {
                                println!(
                                    "{} {:?} {}",
                                    binding.node_id, binding.kind, binding.fingerprint
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to read {}: {}", path.display(), e);
                            std::process::exit(1);
                        }
                    }
                }
                NodeBindingCmd::Forget { node_id } => {
                    match thenodes::security::node_identity::forget_node_bindings(&path, &node_id) {
                        Ok(0) => println!("No-op: no binding for {}", node_id),
                        Ok(removed) => println!(
                            "Forgot {} binding(s) for {}; restart the node to apply",
                            removed, node_id
                        ),
                        Err(e) => {
                            eprintln!("❌ Failed to update {}: {}", path.display(), e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        Commands::Cert { cmd } => match cmd {
            CertCmd::Fingerprint { cert } => {
                let configured_path = config
                    .tls()
                    .and_then(|tls| tls.paths.as_ref())
                    .and_then(|paths| paths.own_certificate.as_ref())
                    .map(PathBuf::from);
                let cert_path = cert
                    .or(configured_path)
                    .unwrap_or_else(|| PathBuf::from("pki/own/cert.pem"));

                match thenodes::security::trust::spki_fingerprint_from_pem_file(&cert_path) {
                    Ok(fp) => {
                        println!("Fingerprint (spki_sha256): {}", fp);
                        println!("Source: {}", cert_path.display());
                    }
                    Err(err) => {
                        eprintln!(
                            "❌ Failed to compute fingerprint from {}: {}",
                            cert_path.display(),
                            err
                        );
                        std::process::exit(1);
                    }
                }
            }
        },
    }
}

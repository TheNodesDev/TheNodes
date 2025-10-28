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
}

#[derive(Subcommand, Debug)]
enum TrustCmd {
    /// List observed certificate fingerprints (from observed_dir)
    ObservedList,
    /// List trusted certificate filenames (from trusted_cert_dir)
    TrustedList,
    /// Promote an observed fingerprint to trusted
    Promote { fingerprint: String },
}

#[derive(Subcommand, Debug)]
enum CertCmd {
    /// Show the SPKI SHA-256 fingerprint of the node's own certificate
    Fingerprint {
        /// Override certificate path (defaults to [encryption.paths].own_certificate or pki/own/cert.pem)
        #[arg(long)]
        cert: Option<PathBuf>,
    },
}

fn load_config(path: &PathBuf) -> thenodes::config::Config {
    match std::fs::read_to_string(path) {
        Ok(content) => match toml::from_str::<thenodes::config::Config>(&content) {
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
            // Resolve dirs from config
            let enc = config.encryption.as_ref();
            let tp = enc.and_then(|e| e.trust_policy.as_ref());
            let paths = enc.and_then(|e| e.paths.as_ref());
            let observed_dir = tp
                .and_then(|t| t.paths.as_ref())
                .and_then(|p| p.observed_dir.as_deref());
            let trusted_dir = paths.and_then(|p| p.trusted_cert_dir.as_deref());

            match cmd {
                TrustCmd::ObservedList => {
                    if let Some(dir) = observed_dir {
                        match std::fs::read_dir(dir) {
                            Ok(entries) => {
                                let mut count = 0u32;
                                for e in entries.flatten() {
                                    if let Some(name) = e.file_name().to_str() {
                                        if name.ends_with(".pem") {
                                            println!("{}", name.trim_end_matches(".pem"));
                                            count += 1;
                                        }
                                    }
                                }
                                if count == 0 {
                                    println!("<none>");
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to read {}: {}", dir, e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        eprintln!("observed_dir not configured. Set [encryption.trust_policy.paths].observed_dir in {}", cli.config.display());
                        std::process::exit(2);
                    }
                }
                TrustCmd::TrustedList => {
                    if let Some(dir) = trusted_dir {
                        match std::fs::read_dir(dir) {
                            Ok(entries) => {
                                let mut any = false;
                                for e in entries.flatten() {
                                    if let Some(name) = e.file_name().to_str() {
                                        if name.ends_with(".pem") {
                                            println!("{}", name);
                                            any = true;
                                        }
                                    }
                                }
                                if !any {
                                    println!("<none>");
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to read {}: {}", dir, e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        eprintln!("trusted_cert_dir not configured. Set [encryption.paths].trusted_cert_dir in {}", cli.config.display());
                        std::process::exit(2);
                    }
                }
                TrustCmd::Promote { fingerprint } => {
                    if fingerprint.len() < 6 {
                        eprintln!("❌ Fingerprint looks too short");
                        std::process::exit(2);
                    }
                    if let (Some(obs), Some(tru)) = (observed_dir, trusted_dir) {
                        match thenodes::security::trust::promote_observed_to_trusted(
                            obs,
                            tru,
                            &fingerprint,
                        ) {
                            Ok(true) => {
                                println!("Promoted {} to trusted", fingerprint);
                            }
                            Ok(false) => {
                                println!("No-op: missing in observed or already trusted");
                            }
                            Err(e) => {
                                eprintln!("❌ Promotion failed: {}", e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        eprintln!(
                            "Both observed_dir and trusted_cert_dir must be configured in {}",
                            cli.config.display()
                        );
                        std::process::exit(2);
                    }
                }
            }
        }
        Commands::Cert { cmd } => match cmd {
            CertCmd::Fingerprint { cert } => {
                let configured_path = config
                    .encryption
                    .as_ref()
                    .and_then(|enc| enc.paths.as_ref())
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

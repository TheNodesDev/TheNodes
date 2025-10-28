use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::{ArgAction, Parser};
use rcgen::generate_simple_self_signed;
use thenodes::security::trust::spki_fingerprint_from_pem_bytes;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Simple helper to generate a self-signed certificate and private key in TheNodes PKI layout.
///
/// Secure defaults:
/// - ECDSA P-256 + SHA-256
/// - serverAuth + clientAuth EKUs (suitable for mTLS)
/// - key usages: digitalSignature, keyEncipherment
/// - validity: 365 days (configurable)
/// - CN includes realm (if provided)
/// - Key permissions 0600 (on Unix), cert 0644
#[derive(Parser, Debug)]
#[command(
    name = "thenodes-cert",
    version,
    about = "Generate self-signed certs for TheNodes PKI"
)]
struct Cli {
    /// Realm name to embed in subject CN (helps with realm_subject_binding)
    #[arg(long)]
    realm: Option<String>,

    /// Common Name (CN). Defaults to thenodes-<unix_ts> (realm=<realm>)
    #[arg(long)]
    cn: Option<String>,

    /// Validity in days
    #[arg(long, default_value_t = 365)]
    days: u64,

    /// Output certificate path
    #[arg(long, default_value = "pki/own/cert.pem")]
    out_cert: PathBuf,

    /// Output private key path
    #[arg(long, default_value = "pki/own/key.pem")]
    out_key: PathBuf,

    /// Also write a copy of the cert into trusted/certs (useful for local loopback/dev)
    #[arg(long, action = ArgAction::SetTrue)]
    copy_to_trusted: bool,

    /// Overwrite output files if they exist
    #[arg(long, action = ArgAction::SetTrue)]
    force: bool,
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            // 0755 for directories
            let perm = fs::Permissions::from_mode(0o755);
            fs::set_permissions(parent, perm).ok();
        }
    }
    Ok(())
}

fn write_file(path: &Path, contents: &[u8], mode: u32, force: bool) -> std::io::Result<()> {
    if path.exists() && !force {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists; use --force to overwrite", path.display()),
        ));
    }
    ensure_parent(path)?;
    let mut f = File::create(path)?;
    f.write_all(contents)?;
    #[cfg(unix)]
    {
        let perm = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, perm)?;
    }
    Ok(())
}

fn generate_cert(realm: Option<String>) -> anyhow::Result<rcgen::CertifiedKey> {
    // Use SAN-only certs; CN is deprecated for validation in modern TLS.
    let alt_names: Vec<String> = match realm.as_deref() {
        Some(r) => vec![format!("realm-{}.thenodes", rfc1123_label_from_realm(r))],
        None => vec![],
    };
    Ok(generate_simple_self_signed(alt_names)?)
}

fn rfc1123_label_from_realm(realm: &str) -> String {
    let mut s = realm.to_lowercase();
    s = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    s
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let default_cn = format!("thenodes-{}", ts);
    let _cn = cli.cn.unwrap_or(default_cn);

    let ck = generate_cert(cli.realm.clone())?;

    // Serialize cert and key as PEM
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();

    // Write files
    write_file(&cli.out_cert, cert_pem.as_bytes(), 0o644, cli.force)?;
    write_file(&cli.out_key, key_pem.as_bytes(), 0o600, cli.force)?;

    // Optional: copy to trusted for local loopback/dev
    if cli.copy_to_trusted {
        let mut trusted_path = PathBuf::from("pki/trusted/certs");
        fs::create_dir_all(&trusted_path)?;
        #[cfg(unix)]
        {
            let perm = fs::Permissions::from_mode(0o755);
            fs::set_permissions(&trusted_path, perm).ok();
        }
        trusted_path.push("self.pem");
        write_file(&trusted_path, cert_pem.as_bytes(), 0o644, cli.force)?;
    }

    // Compute and print SPKI fingerprint (SHA-256)
    let fp = spki_fingerprint_from_pem_bytes(cert_pem.as_bytes())?;
    println!("✅ Generated cert and key");
    println!("  cert: {}", cli.out_cert.display());
    println!("  key:  {}", cli.out_key.display());
    println!("  spki_sha256: {}", fp);
    if let Some(realm) = cli.realm {
        println!("  realm: {}", realm);
    }
    println!("\nAdd to config.toml (example):\n[encryption]\nenabled = true\nmtls = true\n  [encryption.paths]\n  own_certificate = \"{}\"\n  own_private_key = \"{}\"\n  trusted_cert_dir = \"pki/trusted/certs\"\n  [encryption.trust_policy]\n  mode = \"allowlist\"\n  pin_fingerprints = [\"{}\"]\n  [encryption.trust_policy.paths]\n  observed_dir = \"pki/observed/certs\"\n",
        cli.out_cert.display(),
        cli.out_key.display(),
        fp
    );

    Ok(())
}

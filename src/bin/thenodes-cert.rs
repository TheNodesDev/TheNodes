use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::{ArgAction, Parser};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use thenodes::security::node_identity::{is_valid_node_id, node_name_uri};
use thenodes::security::trust::spki_fingerprint_from_pem_bytes;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Simple helper to generate a self-signed certificate and private key in TheNodes PKI layout.
///
/// Secure defaults:
/// - ECDSA P-256 + SHA-256
/// - serverAuth + clientAuth EKUs (suitable for mTLS)
/// - key usages: digitalSignature, keyEncipherment
/// - validity: 365 days (configurable)
/// - subject CN from `--cn`, otherwise the node ID or `thenodes-<unix_ts>`
/// - optional `URI:node://<realm>/<id>` SAN naming the node in its realm (ADR-0012)
/// - Key permissions 0600 (on Unix), cert 0644
#[derive(Parser, Debug)]
#[command(
    name = "thenodes-cert",
    version,
    about = "Generate self-signed certs for TheNodes PKI"
)]
struct Cli {
    /// Canonical code of the realm the node belongs to: the namespace of the
    /// node name (`node://<realm-code>/<node-id>`). It is `[realm] code` when
    /// set, otherwise `[realm] name` in lowercase ASCII with every other
    /// character as `-`; a node logs its own as `realm` in its trust events.
    #[arg(long)]
    realm_code: Option<String>,

    /// Common Name (CN) of the certificate's subject. Defaults to the node ID
    /// given with `--node-id`, otherwise `thenodes-<unix_ts>`.
    #[arg(long)]
    cn: Option<String>,

    /// Node ID to name in a `node://<realm-code>/<id>` URI SAN; requires
    /// `--realm-code`. Peers in that realm enforce it in every node
    /// identity mode; it binds the node ID by itself only when a CA that peers
    /// trust signs the certificate.
    #[arg(long)]
    node_id: Option<String>,

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
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut f = options.open(path)?;
    // The mode above applies only to a new file; restrict an existing one
    // before writing the key into it.
    #[cfg(unix)]
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.write_all(contents)?;
    Ok(())
}

fn generate_cert(cn: &str, node_name: Option<&str>) -> anyhow::Result<rcgen::CertifiedKey> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    if let Some(node_name) = node_name {
        params
            .subject_alt_names
            .push(SanType::URI(node_name.try_into()?));
    }
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok(rcgen::CertifiedKey { cert, key_pair })
}

/// The subject CN: `--cn`, otherwise the node ID, otherwise `thenodes-<unix_ts>`.
fn common_name(cn: Option<&str>, node_id: Option<&str>, ts: u64) -> anyhow::Result<String> {
    match (cn, node_id) {
        (Some(cn), _) if cn.trim().is_empty() => anyhow::bail!("--cn must not be empty"),
        (Some(cn), _) => Ok(cn.to_string()),
        (None, Some(node_id)) => Ok(node_id.to_string()),
        (None, None) => Ok(format!("thenodes-{ts}")),
    }
}

/// Check a realm code for use as the node name's URI authority, which allows
/// unreserved characters only.
fn check_realm_code(code: &str) -> anyhow::Result<()> {
    let valid = !code.is_empty()
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    if !valid {
        anyhow::bail!("--realm-code {code:?} must be ASCII letters, digits, '-', '.', '_' or '~'");
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if let Some(code) = cli.realm_code.as_deref() {
        check_realm_code(code)?;
    }
    let node_name = match (cli.node_id.as_deref(), cli.realm_code.as_deref()) {
        (Some(node_id), _) if !is_valid_node_id(node_id) => anyhow::bail!(
            "--node-id must be 1-128 ASCII letters, digits, '-', '_' or '.': {node_id:?}"
        ),
        (Some(node_id), Some(code)) => Some(node_name_uri(code, node_id)),
        // Each realm is its own namespace: a node name needs one.
        (Some(_), None) => anyhow::bail!("--node-id requires --realm-code"),
        (None, Some(_)) => {
            eprintln!(
                "⚠️ --realm-code only takes effect with --node-id, which names the node in it"
            );
            None
        }
        (None, None) => None,
    };
    let cn = common_name(cli.cn.as_deref(), cli.node_id.as_deref(), ts)?;
    let ck = generate_cert(&cn, node_name.as_deref())?;

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
    println!("  subject: CN={cn}");
    println!("  spki_sha256: {}", fp);
    if let Some(node_name) = &node_name {
        println!("  node name: {node_name}");
    }
    println!("\nAdd to config.toml (example):\n[encryption]\nenabled = true\n  [encryption.tls]\n  mtls = true\n  [encryption.tls.paths]\n  own_certificate = \"{}\"\n  own_private_key = \"{}\"\n  trusted_cert_dir = \"pki/trusted/certs\"\n  rejected_dir = \"pki/rejected\"\n  [encryption.tls.trust_policy]\n  mode = \"allowlist\"\n  pin_fingerprints = [\"{}\"]\n",
        cli.out_cert.display(),
        cli.out_key.display(),
        fp
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(certified: &rcgen::CertifiedKey) -> String {
        let der = certified.cert.der();
        let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        parsed.tbs_certificate.subject.to_string()
    }

    /// Regression test: `--cn` was parsed and ignored, so every
    /// certificate had rcgen's default subject.
    #[test]
    fn the_subject_cn_is_the_given_cn_or_the_node_id() {
        assert_eq!(
            common_name(Some("gateway-1"), Some("node-a"), 7).unwrap(),
            "gateway-1"
        );
        assert_eq!(common_name(None, Some("node-a"), 7).unwrap(), "node-a");
        assert_eq!(common_name(None, None, 7).unwrap(), "thenodes-7");
        assert!(common_name(Some(" "), None, 7).is_err());

        let certified = generate_cert("gateway-1", Some("node://railway-net/node-a")).unwrap();
        assert_eq!(subject(&certified), "CN=gateway-1");
    }
}

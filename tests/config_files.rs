//! The configuration is fail-closed: every config file shipped with TheNodes
//! parses, and a key the node does not know stops it instead of being ignored.

use std::path::{Path, PathBuf};
use thenodes::config::Config;
use thenodes::security::encryption::check_revocation_config;
use thenodes::security::trust::check_trust_config;

/// The config files in the repository. Other files under `config/` are local
/// and ignored by git.
fn shipped_config_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    [
        "config/example.toml",
        "templates/development/custom-host/config.toml",
        "templates/production/cal-app/config.toml",
        "templates/production/hybrid-app/config.toml",
    ]
    .into_iter()
    .map(|path| root.join(path))
    .collect()
}

#[test]
fn shipped_config_files_parse_and_pass_startup_checks() {
    for path in shipped_config_files() {
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("{{APP_NAME}}", "app");
        let config = match Config::from_toml_str(&text) {
            Ok(config) => config,
            Err(err) => panic!("{}: {err}", path.display()),
        };
        // The examples must also pass the startup checks.
        if let Err(err) = check_revocation_config(&config) {
            panic!("{}: {err}", path.display());
        }
        if let Err(err) = check_trust_config(&config) {
            panic!("{}: {err}", path.display());
        }
    }
}

#[test]
fn unknown_keys_are_refused() {
    for (text, key) in [
        ("port = 1\nprot = 2\n", "prot"),
        (
            "port = 1\n[encryption]\nenabled = true\nenable = true\n",
            "enable",
        ),
        (
            "port = 1\n[encryption]\nenabled = true\n[encryption.tls.trust_polcy]\nmode = \"tofu\"\n",
            "trust_polcy",
        ),
        // Removed in 0.5.0 together with relay-to-relay forwarding.
        (
            "port = 1\n[network.relay]\nselection = \"rendezvous\"\n",
            "selection",
        ),
    ] {
        let err = toml::from_str::<Config>(text).unwrap_err().to_string();
        assert!(err.contains(key), "{key}: {err}");
    }
}

/// Regression test: an unknown trust mode used to mean `open`.
#[test]
fn unknown_security_values_are_refused() {
    for (section, value) in [
        ("[encryption]\nenabled = true\nbackend = \"tsl\"\n", "tsl"),
        (
            "[encryption]\nenabled = true\n[encryption.tls.trust_policy]\nmode = \"allowlst\"\n",
            "allowlst",
        ),
        (
            "[encryption]\nenabled = true\n[encryption.tls.trust_policy]\npin_fp_algo = \"sha1\"\n",
            "sha1",
        ),
        (
            "[encryption]\nenabled = true\n[encryption.noise.trust_policy]\nmode = \"allowlst\"\n",
            "allowlst",
        ),
        (
            "[encryption]\nenabled = true\n[encryption.noise]\npattern = \"NK\"\n",
            "NK",
        ),
        (
            "[encryption]\nenabled = true\n[encryption.node_identity]\nmode = \"pined\"\n",
            "pined",
        ),
    ] {
        let text = format!("port = 1\n{section}");
        let err = toml::from_str::<Config>(&text).unwrap_err().to_string();
        assert!(err.contains(&format!("{value:?}")), "{value}: {err}");
    }

    // Known values are accepted in any case.
    toml::from_str::<Config>(
        "port = 1\n[encryption]\nenabled = true\nbackend = \"TLS\"\n[encryption.tls.trust_policy]\nmode = \"Allowlist\"\n",
    )
    .unwrap();
}

/// 0.5.0 moved the TLS settings to `[encryption.tls]` and replaced the
/// observed store (ADR-0016); a 0.4 config says where each setting
/// went instead of only that it is unknown.
#[test]
fn moved_settings_are_named_in_the_error() {
    let old = "port = 1\n[encryption]\nenabled = true\nmtls = true\naccept_self_signed = true\n\
        [encryption.paths]\ntrusted_cert_dir = \"pki/trusted/certs\"\n\
        [encryption.trust_policy]\nstore_new_certs = \"observed\"\n\
        [encryption.trust_policy.paths]\nobserved_dir = \"pki/observed/certs\"\n\
        [encryption.noise]\nstatic_key_path = \"pki/noise/static.key\"\n\
        [encryption.noise.trust_policy]\nstore_new = \"observed\"\n\
        [encryption.noise.trust_policy.paths]\nallowlist_dir = \"pki/noise/trusted\"\n";
    let err = Config::from_toml_str(old).unwrap_err();
    for hint in [
        "`encryption.mtls` moved to `[encryption.tls] mtls`",
        "`encryption.paths` moved to `[encryption.tls.paths]`",
        "`encryption.trust_policy` moved to `[encryption.tls.trust_policy]`",
        "`encryption.accept_self_signed` was never read",
        "`encryption.trust_policy.store_new_certs` is removed",
        "`encryption.trust_policy.paths` is removed",
        "`encryption.noise.static_key_path` moved to `[encryption.noise.paths] static_key`",
        "`encryption.noise.trust_policy.store_new` is removed",
        "`allowlist_dir` moved to `[encryption.noise.paths] trusted_dir`",
    ] {
        assert!(err.contains(hint), "{hint}: {err}");
    }

    let new = "port = 1\n[encryption]\nenabled = true\n[encryption.tls]\nmtls = true\n\
        [encryption.tls.paths]\ntrusted_cert_dir = \"pki/trusted/certs\"\nrejected_dir = \"pki/rejected\"\n\
        [encryption.tls.trust_policy]\naccept_self_signed = true\n\
        [encryption.noise.paths]\nstatic_key = \"pki/noise/static.key\"\ntrusted_dir = \"pki/noise/trusted\"\n";
    let config = Config::from_toml_str(new).unwrap();
    let tls = config.tls().unwrap();
    assert_eq!(tls.mtls, Some(true));
    assert_eq!(
        tls.paths.as_ref().unwrap().rejected_dir.as_deref(),
        Some("pki/rejected")
    );
    let noise = config.encryption.as_ref().unwrap().noise.as_ref().unwrap();
    assert_eq!(noise.static_key_path(), "pki/noise/static.key");
}

/// A trust mode that cannot work with the configured directories stops the
/// node instead of trusting or recording nothing (ADR-0016).
#[test]
fn trust_modes_need_their_directories() {
    let check = |text: &str| check_trust_config(&Config::from_toml_str(text).unwrap());
    let base = "port = 1\n[encryption]\nenabled = true\n";
    for (section, needed) in [
        (
            "[encryption.tls.trust_policy]\nmode = \"tofu\"\n",
            "trusted_cert_dir",
        ),
        (
            "[encryption.noise.trust_policy]\nmode = \"tofu\"\n",
            "[encryption.noise.paths] trusted_dir",
        ),
        (
            "[encryption.tls.trust_policy]\nmode = \"observe\"\n",
            "[encryption.tls.paths] rejected_dir",
        ),
        (
            "[encryption.noise.trust_policy]\nmode = \"observe\"\n",
            "[encryption.noise.paths] rejected_dir",
        ),
        (
            "[encryption.tls.paths]\ntrusted_cert_dir = \"t\"\n[encryption.tls.trust_policy]\nmode = \"tofu\"\n[encryption.node_identity]\nmode = \"off\"\n",
            "node identity binding",
        ),
        (
            "[encryption.tls.paths]\ntrusted_cert_dir = \"t\"\n[encryption.tls.trust_policy]\nenforce_ca_chain = true\n",
            "issuer_cert_dir",
        ),
    ] {
        let err = check(&format!("{base}{section}")).unwrap_err();
        assert!(err.contains(needed), "{needed}: {err}");
    }

    check(&format!(
        "{base}[encryption.tls.paths]\ntrusted_cert_dir = \"t\"\nrejected_dir = \"r\"\n\
         [encryption.tls.trust_policy]\nmode = \"tofu\"\n"
    ))
    .unwrap();
    check(&format!(
        "{base}[encryption.tls.paths]\nissuer_cert_dir = \"i\"\n[encryption.tls.trust_policy]\nenforce_ca_chain = true\n"
    ))
    .unwrap();
}

#[test]
fn listeners_bind_to_the_configured_address() {
    let default: Config = toml::from_str("port = 1\n").unwrap();
    assert_eq!(default.bind_ip().to_string(), "0.0.0.0");
    let loopback: Config =
        toml::from_str("port = 1\n[network]\nbind_ip = \"127.0.0.1\"\n").unwrap();
    assert_eq!(loopback.bind_ip().to_string(), "127.0.0.1");
}

/// `realm_subject_binding` was replaced by `require_realm_node_name`; a config
/// that still sets it fails to load and is told which setting replaced it.
#[test]
fn realm_subject_binding_names_its_replacement() {
    let old = "port = 1\n[encryption]\nenabled = true\n\
        [encryption.tls.trust_policy]\nrealm_subject_binding = true\n";
    let err = Config::from_toml_str(old).unwrap_err();
    assert!(err.contains("require_realm_node_name"), "{err}");

    let new = "port = 1\n[encryption]\nenabled = true\n\
        [encryption.tls.trust_policy]\nrequire_realm_node_name = true\n";
    let config = Config::from_toml_str(new).unwrap();
    let policy = config.tls().unwrap().trust_policy.as_ref().unwrap();
    assert_eq!(policy.require_realm_node_name, Some(true));
}

/// The relay and rendezvous lists hold node IDs; an entry that cannot be one
/// is an error rather than a list that never matches.
#[test]
fn relay_and_rendezvous_lists_hold_node_ids() {
    let config = Config::from_toml_str(
        "port = 1\n[network.relay]\nallowed_relays = [\"relay-1\"]\n\
         [network.nat_traversal]\nallowed_rendezvous = []\n",
    )
    .unwrap();
    assert!(config.relay_allowed("relay-1"));
    assert!(!config.relay_allowed("relay-2"));
    assert!(!config.rendezvous_allowed("relay-1"));
    let unset = Config::from_toml_str("port = 1\n").unwrap();
    assert!(unset.relay_allowed("relay-2") && unset.rendezvous_allowed("relay-2"));

    for invalid in [
        "[network.relay]\nallowed_relays = [\"relay 1\"]",
        "[network.nat_traversal]\nallowed_rendezvous = [\"\"]",
    ] {
        let err = Config::from_toml_str(&format!("port = 1\n{invalid}\n")).unwrap_err();
        assert!(err.contains("is not a node ID"), "{invalid}: {err}");
    }
}

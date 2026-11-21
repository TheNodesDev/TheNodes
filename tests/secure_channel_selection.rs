use thenodes::config::{Config, EncryptionConfig};
use thenodes::security::secure_channel::make_secure_channel;

#[test]
fn noise_selection_requires_compiled_support() {
    let config = Config {
        encryption: Some(EncryptionConfig {
            enabled: true,
            backend: Some(" Noise ".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let result = make_secure_channel(&config);
    #[cfg(feature = "noise")]
    assert!(result.is_ok());
    #[cfg(not(feature = "noise"))]
    match result {
        Ok(_) => panic!("Noise must never downgrade to plaintext"),
        Err(error) => assert!(error.to_string().contains("--features noise")),
    }
}

#[test]
fn explicit_plaintext_and_tls_remain_available() {
    for backend in ["plaintext", "none", "tls"] {
        let config = Config {
            encryption: Some(EncryptionConfig {
                backend: Some(backend.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(make_secure_channel(&config).is_ok(), "{backend}");
    }
}

/// A config file cannot name an unknown backend; one set in code is an error
/// rather than another backend.
#[test]
fn an_unknown_backend_is_an_error() {
    let config = Config {
        encryption: Some(EncryptionConfig {
            enabled: true,
            backend: Some("tsl".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    match make_secure_channel(&config) {
        Ok(_) => panic!("an unknown backend must not select one"),
        Err(error) => assert!(error.to_string().contains("tsl"), "{error}"),
    }
}

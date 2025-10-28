//! Central place for application-wide constants and default values.

/// Default application name (can be overridden in config)
pub const DEFAULT_APP_NAME: &str = "TheNodes";

/// Left padding used to align log lines with those that include emoji prefixes.
/// Keep this to a fixed width matching the emoji prefix you use elsewhere.
pub const ICON_PLACEHOLDER: &str = "   "; // Three spaces for alignment

/// Protocol branding shown in HELLO and logs
pub const PROTOCOL_NAME: &str = "TheNodes";
/// Protocol version for compatibility checks (bump when wire format changes)
pub const PROTOCOL_VERSION: &str = "1";

/// Application / crate version (populated from Cargo.toml via env! macro)
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Optional short git commit hash (set via build script or cargo:rustc-env). Falls back to "unknown".
pub fn git_commit() -> &'static str {
    option_env!("GIT_COMMIT").unwrap_or("unknown")
}

/// Optional build timestamp in RFC3339 (set via build script). Falls back to "unknown".
pub fn build_timestamp() -> &'static str {
    option_env!("BUILD_TIMESTAMP").unwrap_or("unknown")
}

/// Human friendly composite version string used in prompts / logs.
/// Cannot use concat! with non-literal (PROTOCOL_VERSION variable), so build at runtime via function.
pub fn full_version() -> String {
    format!("v{} (protocol={})", APP_VERSION, PROTOCOL_VERSION)
}

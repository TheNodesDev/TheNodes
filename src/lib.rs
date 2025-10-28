//! # TheNodes Core Library
//!
//! Modular, plugin-driven P2P node framework supporting two operation modes:
//!
//! * **NEP (Node-Embedded Plugins):** Host binary loads dynamic plugins at runtime.
//! * **CAL (Core-as-a-Library):** Embed core logic in another application.
//!
//! ## Design Principles
//! * Async-first: all I/O paths are non-blocking (Tokio + async traits).
//! * Pluggable extension surface via `plugin_host`.
//! * Realm isolation for logical network partitioning.
//! * Optional encryption & trust policy with PKI directory model.
//! * Event-driven instrumentation (JSON line audit log + console).
//! * Progressive enhancement: features (discovery, trust policy depth, roles) can be enabled incrementally.
//!
//! ## Key Modules
//! * `config` – Runtime configuration & plugin-provided defaults.
//! * `network` – Transport, peer management, discovery, protocol messages.
//! * `security` – Encryption (TLS optional) & trust policy scaffolding.
//! * `plugin_host` – Dynamic plugin loading + dispatch context.
//! * `realms` – RealmInfo definitions for segmentation.
//! * `events` – Structured logging/events dispatcher.
//! * `prompt` – Optional interactive prompt integration.
//!
//! ## Changelog
//! See `CHANGELOG.md` for unreleased changes while pre-1.0.
//!
//! ## Status
//! Pre-initial public release. APIs may change without notice until version 0.1.0 is tagged.
//!
//! ## Roadmap (High-Level)
//! * Policy-based role / node_type communication matrix (incl. data diode semantics)
//! * Reliability tiers (WAL, replay, at-least/exactly-once event durability)
//! * Extended transport support (QUIC) & crypto plugin strategy
//! * Capability negotiation in handshake
//! * Enhanced discovery gossip strategies

pub mod config;
pub mod constants;
pub mod events;
pub mod network;
pub mod plugin_host;
pub mod prelude; // curated stable-intent re-exports
pub mod prompt;
pub mod realms;
pub mod security;
pub mod utils; // common helpers (naming, etc.)

/// TheNodes Core Struct
pub struct TheNodes {
    pub config: config::Config,
}

impl TheNodes {
    /// Initializes the node system
    pub fn new(config: config::Config) -> Self {
        Self { config }
    }

    /// Starts the P2P node
    pub async fn start(&self) {
        println!("Starting TheNodes...");
        // TODO: Implement networking logic
    }
}

/// Exports for NEP (Node-Embedded Plugin)
#[no_mangle]
pub extern "C" fn create_instance() -> *mut TheNodes {
    let config = config::Config::default();
    let instance = Box::new(TheNodes::new(config));
    Box::into_raw(instance)
}

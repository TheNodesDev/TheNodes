# Plugin Authoring Guide

This document explains how to build and ship plugins for TheNodes. It focuses on NEP (Node-Embedded Plugin) deployments where the host binary dynamically loads `.so` / `.dylib` / `.dll` artifacts. The same concepts apply when you embed TheNodes as a library (CAL mode) and still want to keep a plugin-style boundary.

## 1. Prerequisites

- Rust 1.74 or newer with the `cargo` toolchain (matches this repo's MSRV in CI).
- Access to a TheNodes checkout (until the crate is published on crates.io).
- Familiarity with basic Rust crate structure, `cargo build`, and dynamic library basics for your platform.
- Optional: OpenSSL or other tooling if you plan to test TLS locally.

## 2. Project Layout

A plugin is a normal Rust library crate that compiles to a dynamic library. Minimum `Cargo.toml`:

```toml
[package]
name = "kvstore_plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
thenodes = { path = "../../" } # replace with `thenodes = "0.1"` once published
async-trait = "0.1"            # only if you use async hooks
serde = { version = "1", features = ["derive"] } # plugin-specific
```

Key points:
- `crate-type = ["cdylib"]` (under `[lib]`) ensures `cargo build --release` emits a shared library that the host can load.
- Use `path = "../../"` or a fixed version depending on how you include TheNodes.
- Keep dependencies minimal; the plugin shares the host process, so version conflicts can propagate.

## 3. Implementing the `Plugin` Trait

Every plugin provides one or more handlers implementing `thenodes::plugin_host::Plugin`. The trait lives in the host crate and is intentionally small:

```rust
use thenodes::plugin_host::{Plugin, PluginContext};
use thenodes::network::message::Message;

pub struct MyPlugin;

#[async_trait::async_trait]
impl Plugin for MyPlugin {
    fn on_message(&self, message: &Message, ctx: &PluginContext) {
        // handle inbound messages
    }

    async fn on_prompt(&self, input: &str, ctx: &PluginContext) -> Option<String> {
        // optional prompt handling when host runs with --prompt
        None
    }

    fn prompt_prefix(&self) -> Option<&str> {
        Some("my") // type `my` at the root prompt to enter the plugin shell
    }

    fn early_config_defaults(&self) -> Option<thenodes::config::ConfigDefaults> {
        None
    }
}
```

Notes:
- `on_prompt` is async; if you implement it, add `async-trait` to your dependencies. If you don’t override it, you can omit `async-trait`.

`PluginContext` exposes shared facilities (peer manager, event dispatcher). Avoid long blocking work inside handlers; spawn async tasks via Tokio if needed.

## 4. Registration Entry Point (FFI ABI)

The host discovers plugins by looking for an exported function named `register_plugin`. The signature **must** follow the C-compatible ABI provided by `PluginRegistrarApi`:

```rust
use thenodes::plugin_host::{PluginRegistrarApi, Plugin};

#[no_mangle]
pub unsafe extern "C" fn register_plugin(api: *const PluginRegistrarApi) {
    let api = match PluginRegistrarApi::from_raw(api) {
        Ok(api) => api,
        Err(err) => {
            eprintln!("[my_plugin] invalid registrar API: {err}");
            return;
        }
    };

    if let Err(err) = api.register_plugin(Box::new(MyPlugin)) {
        eprintln!("[my_plugin] failed to register: {err}");
    }
}
```

Important details:
- `PluginRegistrarApi::from_raw` validates the pointer. Always check the result and log meaningful errors.
- `register_plugin` consumes a boxed plugin and passes it back to the host. Ownership transfers to TheNodes.
- The helper enforces ABI version matching (see below). If versions diverge, the function returns `PluginApiError::VersionMismatch` and the host logs a rejection.

## 5. ABI Versioning and Compatibility

`thenodes::plugin_host::PLUGIN_ABI_VERSION` is bumped whenever the host changes the layout or semantics of `PluginRegistrarApi`. Steps for plugin authors:

1. Depend on a compatible TheNodes release. Cargo will rebuild when the host updates.
2. Inside your plugin, you can assert the expected version:
   ```rust
   assert_eq!(thenodes::plugin_host::PLUGIN_ABI_VERSION, 1);
   ```
   This guards against accidental mismatches when multiple host binaries exist.
3. During load, `PluginRegistrarApi::register_plugin` validates the version automatically and returns an error if it differs.

If you must support multiple host versions simultaneously, consider building separate plugin artifacts per target ABI or implementing shims keyed on `abi_version()`.

## 6. Building and Installing

1. Compile in release mode:
   ```sh
   cargo build --release
   ```
2. Copy the produced library to the host `plugins/` directory. The filename format differs per OS:
   - Linux: `target/release/libmy_plugin.so`
   - macOS: `target/release/libmy_plugin.dylib`
   - Windows: `target\release\my_plugin.dll`
3. Run TheNodes with your desired config:
   ```sh
   cargo run --bin thenodes -- --config config/config.toml --prompt
   ```
    The loader prints `🔌 Loaded plugin: ...` for each successful registration.

## 7. Testing and Debugging

- Use `cargo test` inside the plugin crate for unit tests. Integration tests can run against an embedded TheNodes instance using CAL mode.
- Enable prompt mode (`--prompt`). From the root prompt, type your plugin’s `prompt_prefix()` value (e.g., `my`) to enter the plugin shell. Use `exit` to return.
- Log messages with `log` crate macros; TheNodes aggregates them alongside core logs when you enable the console sink.
- If loading fails, check host stderr for `PluginApiError` messages. Common issues: missing symbol name, incorrect crate type, or ABI version mismatch.

## 8. Distribution Recommendations

- Version your plugin crate independently; the dynamic library filename can include the version (`libmy_plugin_v1.so`) if you manage multiple generations.
- Ship configuration snippets that operators can drop into `config/` (e.g., prompt prefixes, plugin-specific sections).
- Document the minimum TheNodes release required, along with `PLUGIN_ABI_VERSION` compatibility.
- Consider signing plugin artifacts or distributing them over authenticated channels to reduce tampering risk.

## 9. Security Considerations

- Plugins run in-process with the host and inherit its privileges. Treat them as trusted code.
- Follow least-privilege practices: restrict file access, avoid executing external binaries unless required, and sanitize any user input processed inside the plugin.
- Respect TheNodes logging conventions so that audit trails remain consistent.
- If you build plugins in other languages, ensure the generated function table exactly matches the `PluginRegistrarApi` layout (C layout, little endian). Provide thorough testing before deployment.

## 10. Core Infrastructure APIs

Plugins can interact with core TheNodes infrastructure through `PluginContext`. This section covers key subsystems.

### Peer Store Access

The `PeerStore` maintains known peers with metadata. Plugins can query it for discovery or connection decisions:

```rust
use thenodes::network::{PeerStore, PeerSource};

fn example(ctx: &PluginContext) {
    let store = ctx.peer_store();
    
    // Sample random peers (excluding already-connected)
    let exclude = std::collections::HashSet::new();
    let candidates = store.sample(10, &exclude).await;
    
    // Insert a manually discovered peer
    store.insert("192.168.1.50:7447".parse().unwrap(), PeerSource::Manual).await;
    
    // Query all known peers
    let all = store.all().await;
}
```

`PeerRecord` fields available: `addr`, `source`, `failures`, `last_success_epoch`, `node_id`, `capabilities`.

### Relay Message Builders

Plugins can construct and send relay protocol messages using the builder APIs:

```rust
use thenodes::network::relay::{RelayBindBuilder, RelayForwardBuilder};

async fn bind_via_relay(ctx: &PluginContext, relay_addr: &SocketAddr, target: &str) {
    let pm = ctx.peer_manager();
    
    // Request a relay binding to a target peer
    RelayBindBuilder::new("my-node", target)
        .store_forward(true)      // Enable store-and-forward if target offline
        .qos("reliable")          // QoS: low_latency | high_throughput | bulk | reliable
        .ttl(3600)                // Binding TTL in seconds
        .send(&pm, relay_addr, ctx.realm().cloned())
        .await;
}

async fn send_via_relay(ctx: &PluginContext, relay_addr: &SocketAddr, to: &str) {
    let pm = ctx.peer_manager();
    
    // Send an opaque forwarding frame through the relay
    RelayForwardBuilder::new("my-node", to)
        .sequence(42)                          // Optional sequence number for ordering
        .payload_text("hello via relay")       // Or .payload_json() / .payload_binary()
        .send(&pm, relay_addr, ctx.realm().cloned())
        .await;
}
```

### Advertising Capabilities

Plugins can influence the capabilities advertised in HELLO by providing configuration defaults. Capabilities like `relay` or `relay_store_forward` are used for deterministic relay selection:

```rust
use thenodes::config::ConfigDefaults;

impl Plugin for MyPlugin {
    fn early_config_defaults(&self) -> Option<ConfigDefaults> {
        Some(ConfigDefaults {
            // Advertise that this node can act as a relay
            capabilities: Some(vec!["relay".into(), "my-plugin-feature".into()]),
            ..Default::default()
        })
    }
}
```

Peers advertising `relay` are eligible for Rendezvous (HRW) selection. Add `relay_store_forward` if your node supports store-and-forward buffering.

### Handling Relay Notifications

Plugins receive relay lifecycle events through `on_message`. Handle `RelayNotify` to react to overload, timeout, or peer departure:

```rust
use thenodes::network::message::{Message, MessageType, Reason};

impl Plugin for MyPlugin {
    fn on_message(&self, message: &Message, ctx: &PluginContext) {
        if let MessageType::RelayNotify { notif_type, binding_id, detail } = &message.msg_type {
            match notif_type {
                Reason::Overload => {
                    // Relay queue is full; consider backing off
                }
                Reason::Timeout => {
                    // Message TTL expired before delivery
                }
                Reason::PeerLeft => {
                    // Target peer disconnected from relay
                }
                _ => {}
            }
        }
    }
}
```

## 11. Next Steps and Resources

- Browse `examples/kvstore_plugin` for a working reference implementation.
- The template at `templates/production/nep-plugin` demonstrates a production-ready scaffold with configuration defaults and prompt commands.
- Review `README.md` (Plugin ABI Basics section) for the latest snippets and migration notes.
- Keep an eye on `CHANGELOG.md` for `PLUGIN_ABI_VERSION` bumps or new hooks on the `Plugin` trait.

Questions, suggestions, or contributions are welcome via issues and pull requests in the main repository.

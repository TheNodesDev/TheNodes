# Plugin Authoring Guide

This document explains how to build and ship plugins for TheNodes. It focuses on NEP (Node-Embedded Plugin) deployments where the host binary dynamically loads `.so` / `.dylib` / `.dll` artifacts. The same lifecycle applies when you embed TheNodes as a library (CAL mode) and register plugins statically.

The runtime contract is described in [ADR-0011](adr/0011-plugin-runtime-and-lifecycle.md). Plugins written for plugin ABI 3 must be migrated; see the [ABI 4 migration guide](PLUGIN_ABI_4_MIGRATION.md).

## 1. Prerequisites

- Rust 1.83 or newer with the `cargo` toolchain (matches this repo's declared MSRV and CI).
- A checkout of the TheNodes release that your host runs. Plugins and hosts must be built together (see [Build Contract](#7-abi-version-and-build-contract)).
- Familiarity with basic Rust crate structure, `cargo build`, and dynamic library basics for your platform.

## 2. Project Layout

A plugin is a normal Rust library crate that compiles to a dynamic library. Minimum `Cargo.toml`:

```toml
[package]
name = "my_plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
thenodes = { path = "../TheNodes" } # the exact source release your host uses
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }

# Build with the same TheNodes features as the host.
[features]
noise = ["thenodes/noise"]
upnp = ["thenodes/upnp"]
```

Key points:
- `crate-type = ["cdylib"]` (under `[lib]`) makes `cargo build` emit a shared library the host can load.
- Build the plugin with the host's lockfile so every shared dependency resolves to the same version. The template generator copies the TheNodes `Cargo.lock` into generated projects; in this repository the example plugin is a workspace member for the same reason.
- Keep dependencies minimal; the plugin shares the host process.

## 3. Implementing the `Plugin` Trait

Every plugin provides one or more handlers implementing `thenodes::plugin_host::Plugin`:

```rust
use thenodes::network::message::Message;
use thenodes::plugin_host::{Plugin, PluginContext, PluginError};

pub struct MyPlugin;

#[async_trait::async_trait]
impl Plugin for MyPlugin {
    fn plugin_id(&self) -> &'static str {
        "my-plugin"
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        // Bounded local initialization: open files, load state, spawn managed tasks.
        let _dir = ctx.plugin_data_dir().await?;
        Ok(())
    }

    async fn on_message(&self, message: &Message, ctx: &PluginContext) {
        // Handle one admitted message.
    }

    async fn on_stop(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        // Release resources. Must tolerate incomplete initialization.
        Ok(())
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        Some(&["my.records.updated", "my.records.deleted"])
    }

    async fn on_prompt(&self, input: &str, ctx: &PluginContext) -> Option<String> {
        None // optional prompt handling when the host runs with --prompt
    }

    fn prompt_prefix(&self) -> Option<&str> {
        Some("my") // type `my` at the root prompt to enter the plugin shell
    }
}
```

Notes:
- `plugin_id()` must return a stable, unique ID. Plugin IDs may contain ASCII letters, numbers, `.`, `-`, and `_`.
- The host reads `plugin_id`, `subscribed_extension_kinds`, `prompt_prefix`, `early_config_defaults`, and `max_managed_tasks` once, at registration. Keep them lightweight and pure. `early_config_defaults` must not create a runtime, spawn tasks, access the network, or initialize operational state.
- `subscribed_extension_kinds()` filters only `MessageType::Extension` messages by exact `kind`. `None` (the default) receives every extension kind; `Some(&[])` receives none. Non-extension messages are always offered.
- Two plugins that supply different early defaults for the same single-valued field (port, realm, app name, encryption, bootstrap nodes, logging, node, discovery) fail registration. `bootstrap_nodes_extend` lists are merged. Two plugins may not share a prompt prefix.

## 4. Lifecycle

```text
Registered -> Starting -> Running -> Stopping -> Stopped
                    \          \            \
                     +----------+-------------> Failed
```

1. **Registration.** The host loads libraries and reads plugin metadata. Plugin-supplied configuration defaults are applied, and the host finalizes configuration, identity, and stores.
2. **Start.** `on_start` runs once per plugin, one plugin after another in registration order, with the final plugin-bound context. Return an error if the plugin cannot operate.
3. **Activation.** After every plugin started (or the host explicitly acknowledged each failure) and required listeners are bound, the host activates the node. Only then are messages and prompts delivered and context sends allowed.
4. **Operation.** Messages arrive one at a time in admission order; prompts and managed tasks run alongside.
5. **Stop.** On shutdown the host closes admission, drains or discards admitted messages, cancels managed tasks, and calls `on_stop` in reverse start order.

Rules that follow from this order:

- `on_start` runs before activation. Do not wait in `on_start` for messages or for a send to succeed; sends before activation return `DeliveryFailureReason::NotReady`. Spawn a managed task that waits for activation instead (see below).
- No startup deadline applies. A start hook that does not return keeps the node starting; operators see `plugin_waiting phase=start` events.
- `on_stop` runs whenever `on_start` was entered, including after a failed or cancelled start. Plugins that never started receive no stop hook.
- After shutdown has drained admitted messages, sends return `Stopping`. Stop hooks may do their own cleanup I/O but must not wait for new messages or sends.
- A plugin that fails (a hook error, or a panic in any callback or managed task) is isolated: only that plugin stops receiving work, its cleanup runs, and the host is notified. Whether the node continues is the host's decision. A failed plugin is not restarted in place.

## 5. Runtime, Messages, and Managed Tasks

### Where plugin code runs

Each native library gets its own Tokio runtime, shared by all handlers that library registers. Callbacks and managed tasks run there, so plugin code can use Tokio timers, sockets, and `tokio::fs` without creating a runtime. Set the worker count during registration with `NativeRegistrar::set_runtime_workers` (default 2). Statically registered (CAL) plugins run on the host runtime.

### Messages are queued per plugin

Dispatch places each message into the bounded inbox of every subscribed plugin and returns immediately; there is no dispatch timeout. Each plugin handles its messages one at a time, in admission order. When a plugin's inbox is full (32 messages by default, including the one in progress), further messages for that plugin are rejected with an overload outcome while other plugins continue.

To handle messages concurrently, spawn managed tasks from `on_message`.

**Do not await a message that only your own inbox can deliver**, such as a peer's reply to a request you sent. The reply waits behind the handler that waits for it, forever. Put request/reply waits in a managed task and forward the reply to it from `on_message`:

```rust
async fn on_message(&self, message: &Message, ctx: &PluginContext) {
    match kind(message) {
        "my.request" => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending.lock().unwrap().insert(request_id(message), tx);
            let _ = ctx.spawn_task("await-reply", move |task| async move {
                tokio::select! {
                    reply = rx => { /* use the reply */ }
                    _ = task.cancelled() => {}
                }
                Ok(())
            });
        }
        "my.reply" => {
            if let Some(tx) = self.pending.lock().unwrap().remove(&request_id(message)) {
                let _ = tx.send(message.clone());
            }
        }
        _ => {}
    }
}
```

### Who sent a message

Authorise on `message.origin()`, which the host sets when it receives a message
([ADR-0012](adr/0012-node-identity-binding.md)):

```rust
async fn on_message(&self, message: &Message, ctx: &PluginContext) {
    let Some(sender) = message.origin().and_then(|origin| origin.authenticated_sender()) else {
        return; // unauthenticated connection, relayed, or built locally
    };
    // `sender` is the node ID bound to the TLS or Noise key that delivered this.
}
```

- Every frame names the two ends of the connection that carried it. The host
  drops a frame whose `from` is not the node bound to the connection or whose
  `to` is not this node, so for a direct message `message.from` equals
  `origin().peer`. `authenticated_sender()` returns it only when that node ID
  is bound to a transport key, so not over plaintext.
- A message unwrapped from a relay tunnel keeps its `from`;
  `origin().relayed_from` is set and `origin().peer` is the relay. The relay
  checked the origin against its own connection, but there is no end-to-end
  proof, so trust a relayed sender only as far as you trust the relay.
- Messages your own code builds have no origin.

When you send, the host addresses the message: build it with
`Message::outbound(msg_type, payload, realm)`. `send_message(to, ..)` sets
`from` to this node and `to` to the target, and `broadcast` stamps each copy
with the peer it goes to. Values you put in `from` or `to` are replaced.

### Managed tasks

`PluginContext::spawn_task(name, |task| async move { ... })` starts a background task in the plugin's scope:

- The task runs on the plugin's runtime and counts against the plugin's limit (`Plugin::max_managed_tasks`, default 128). At the limit, `spawn_task` returns `SpawnError::Overloaded`.
- `task.activated().await` waits until the host activates the node, or returns `Err(TaskCancelled)` if the plugin stops first. Use it before sending from tasks started in `on_start`.
- `task.cancelled().await` resolves when the plugin's scope is cancelled during shutdown or isolation. Return promptly; remaining tasks are aborted after `on_stop`.
- Returning `Err(PluginError)` or panicking marks the plugin failed.
- Dropping the returned `TaskHandle` does not detach the task; it stays tracked until it completes or the plugin stops. `TaskHandle::join` waits for observed completion.

```rust
async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
    ctx.spawn_task("heartbeat", |task| async move {
        if task.activated().await.is_err() {
            return Ok(());
        }
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => { /* periodic work, sends are allowed */ }
                _ = task.cancelled() => return Ok(()),
            }
        }
    })
    .map_err(|error| PluginError::new(error.to_string()))?;
    Ok(())
}
```

### Limits of in-process execution

- Raw `tokio::spawn`, `spawn_blocking`, `std::thread`, and other executors used by plugin code are not tracked and get no managed-lifetime guarantees.
- Tokio cannot stop code that blocks or never yields. Such code starves every handler on the same runtime: the other handlers of the same native library, or the whole host for a CAL plugin. Separate native libraries do not share a runtime. During shutdown, the host waits for such code until the operator or embedding application escalates; the work is then reported as `FailedToQuiesce` and the process must exit.
- Plugin timers are fine. TheNodes itself imposes no time limit on any callback; hosts apply their own through cancellation and escalation.

## 6. Registration Entry Point

Native libraries export their entry points with `export_plugin!`:

```rust
use thenodes::plugin_host::{NativeRegistrar, PluginRegistrationError};

fn register(registrar: &mut NativeRegistrar) -> Result<(), PluginRegistrationError> {
    registrar.set_runtime_workers(2)?; // optional
    registrar.register(Box::new(MyPlugin));
    Ok(())
}

thenodes::export_plugin!(register);
```

The macro exports two C-ABI symbols:

- `thenodes_plugin_abi_version() -> u32` reports the plugin ABI of the TheNodes copy the library was built with. The host checks it before calling anything else.
- `register_plugin(api: *const PluginRegistrarApi) -> u32` runs your registration function inside the plugin's code copy, wraps each handler in the native adapter, and returns a status code. Panics in the registration function are caught and reported.

Registration is all or nothing per library: if one handler is rejected (invalid or duplicate ID, duplicate prompt prefix, conflicting defaults) or the function fails, no handler from that library is registered and the loader returns a typed `PluginLoadError`. The registrar is valid only during the registration call.

## 7. ABI Version and Build Contract

`thenodes::plugin_host::PLUGIN_ABI_VERSION` is 4. It changes whenever the native boundary, the `Plugin` trait, or the runtime contract changes. Libraries built for another ABI, or without the version export, are rejected before any of their plugin code is invoked.

The ABI number is a compatibility check, not a guarantee of Rust binary compatibility, and it is not authentication. Loading a library may run its native constructors before the check. Host and plugins must use:

- the same TheNodes source release and the same TheNodes Cargo features;
- the same Rust toolchain and target;
- the same dependency versions (one `Cargo.lock`);
- the same global allocator. The default system allocator satisfies this; a `#[global_allocator]` on only one side is undefined behavior;
- unwinding panics. A plugin built with `panic = "abort"` ends the process on any panic.

Rebuild every plugin whenever the host is rebuilt. Updating only the host or only a plugin is not supported.

## 8. Building and Installing

1. Build with the host's lockfile and features:
   ```sh
   cargo build --release            # add --features noise,upnp to match the host
   ```
2. Copy the produced library to the host `plugins/` directory:
   - Linux: `target/release/libmy_plugin.so`
   - macOS: `target/release/libmy_plugin.dylib`
   - Windows: `target\release\my_plugin.dll`
3. Run TheNodes with your desired config:
   ```sh
   cargo run --bin thenodes -- --config config/config.toml --prompt
   ```
   The loader loads libraries in sorted path order and prints `🔌 Loaded plugin '<id>' from <path>` for each registered handler. Load order is not a dependency mechanism.

The standalone host treats every plugin as required: it stops when a library fails to load or a plugin fails to start, shuts down when a plugin fails later, and exits unsuccessfully in both cases. Press Ctrl+C once to shut down; press it again (or send SIGTERM) to stop waiting on plugin work that does not finish.

## 9. Testing and Debugging

- Unit-test plugin logic inside the plugin crate. For lifecycle tests, register the plugin with a `PluginManager` in CAL mode, call `start_all`, `activate`, and `shutdown`, and synchronize on notifications from the plugin rather than on `dispatch_message` returning.
- Test the built library through `PluginLoader` as well; a source-level test does not exercise the native boundary.
- Enable prompt mode (`--prompt`). Type your plugin's `prompt_prefix()` to enter its shell; `exit` returns.
- Lifecycle events (`plugin_starting`, `plugin_started`, `plugin_start_failed`, `plugin_waiting`, `plugin_stopping`, `plugin_stopped`, `plugin_stop_failed`, `plugin_failed`, `plugin_task_failed`, `plugin_admission_rejected`, `plugin_failed_to_quiesce`) show where a plugin is in its lifecycle.
- If loading fails, the `PluginLoadError` names the library and reason: missing export, ABI mismatch, or a registration error.

## 10. Distribution Recommendations

- Version your plugin crate independently; the library filename can include the version (`libmy_plugin_v1.so`) if you manage several generations.
- Ship configuration snippets that operators can drop into `config/`.
- Document the exact TheNodes release, feature set, and Rust toolchain each artifact was built with.
- Distribute artifacts over authenticated channels and protect the plugin directory; TheNodes does not sign or verify plugins.

## 11. Security Considerations

- Native plugins run in the host process with its privileges. Treat them as trusted code. Separate runtimes, per-plugin inboxes, admission checks, and per-plugin data directories organize trusted code; they are not a sandbox.
- Follow least-privilege practices: restrict file access, avoid executing external binaries unless required, and sanitize input processed inside the plugin.
- Emit events through `ctx.events`. Lifecycle events carry only plugin ID, phase, result category, and elapsed time; do not put secrets or payloads into your own events either.
- Cross-language plugins are not supported: the transferred endpoint is a Rust trait object.

## 12. Core Infrastructure APIs

### Host services (all plugins)

These `PluginContext` methods run in host code on the host runtime and check the plugin's lifecycle state:

| Method | Purpose |
| --- | --- |
| `deliver_message(message, options)` / `send_message(to, message, options)` | Framework-owned delivery with `DeliveryOptions` |
| `broadcast(message)` | Send to every connected peer |
| `connected_peer_ids()` | Node IDs of connected peers |
| `events.emit(event)` | Submit an event to the host's dispatcher |
| `plugin_data_dir()` | The plugin's durable directory under the node state directory |
| `spawn_task(name, task)` | Managed background work |

Delivery work, including reliable-delivery retries, runs on the host runtime and continues even if the plugin stops waiting. Outcomes such as `DeliveryFailureReason::NotReady`, `Stopping`, and `Unavailable` report lifecycle refusals; a transport or peer acknowledgement does not mean the receiving plugin processed the message.

### Low-level access (CAL only)

`PluginContext::peer_manager()` and `PluginContext::peer_store()` return the host's `PeerManager` and `PeerStore` only in contexts that share the host's code copy: the host's own context and statically registered plugins. They return `None` for native plugins, because those objects hold runtime-bound state of the host's Tokio copy. The following two sections therefore apply to CAL plugins only. Native plugins need new host-service operations for these features.

#### Peer Store Access (CAL only)

```rust
use thenodes::network::PeerSource;

async fn example(ctx: &PluginContext) {
    let Some(store) = ctx.peer_store() else { return };

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

#### Relay Message Builders (CAL only)

```rust
use thenodes::network::relay::{RelayBindBuilder, RelayForwardBuilder};

async fn bind_via_relay(ctx: &PluginContext, relay_addr: &SocketAddr, target: &str) {
    let Some(peer_manager) = ctx.peer_manager() else { return };
    // Request a relay binding to a target peer
    RelayBindBuilder::new("my-node", target)
        .store_forward(true)      // Enable store-and-forward if target offline
        .qos("reliable")          // QoS: low_latency | high_throughput | bulk | reliable
        .ttl(3600)                // Binding TTL in seconds
        .send(peer_manager.as_ref(), relay_addr, ctx.config.realm.clone())
        .await;
}

async fn send_via_relay(ctx: &PluginContext, relay_addr: &SocketAddr, to: &str) {
    let Some(peer_manager) = ctx.peer_manager() else { return };
    // Send an opaque forwarding frame through the relay
    RelayForwardBuilder::new("my-node", to)
        .sequence(42)                          // Optional sequence number for ordering
        .payload_text("hello via relay")       // Or .payload_json() / .payload_binary()
        .send(peer_manager.as_ref(), relay_addr, ctx.config.realm.clone())
        .await;
}
```

### Advertised Capabilities

Transport capabilities such as `relay`, `relay_store_forward`, `udp`, `punch`,
and `punch_rendezvous` are derived by the host from runtime configuration and
compiled Cargo features. Plugins cannot add arbitrary HELLO capabilities.

### Handling Relay Notifications

Plugins receive relay lifecycle events through `on_message`. Handle `RelayNotify` to react to overload, timeout, or peer departure:

```rust
use thenodes::network::message::{Message, MessageType, Reason};

#[async_trait::async_trait]
impl Plugin for MyPlugin {
    async fn on_message(&self, message: &Message, ctx: &PluginContext) {
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

### Plugin State and Storage

TheNodes does not provide a generic plugin storage API. Plugins own their state and persistence choices so the core remains application-neutral. Use `plugin_data_dir()` for the location; plugins own formats, locking, migrations, backups, and recovery inside it. The directory organizes state; it does not restrict a native plugin's access to other files.

See [`PLUGIN_STORAGE_DECISION.md`](PLUGIN_STORAGE_DECISION.md) for the scope and rationale.

## 13. Hosting Plugins: Time Limits Are Host Policy

Hosts drive the lifecycle through `PluginManager`: `start_all`, `acknowledge_failure`, `activate`, `dispatch_message`, `resolve_prompt` / `dispatch_prompt`, `subscribe_failures`, `begin_shutdown` / `shutdown`, and `escalate`. TheNodes never times out a plugin. A host that wants a limit applies its own timer and uses these mechanisms:

```rust
let shutdown = manager.begin_shutdown(ShutdownMode::Drain);
let wait = shutdown.wait();
tokio::pin!(wait);
let report = tokio::select! {
    report = &mut wait => report?,
    _ = tokio::time::sleep(my_shutdown_budget) => {
        manager.escalate();   // stop waiting; unfinished work is reported
        wait.await?
    }
};
```

Similarly, a startup limit is a host decision to begin shutdown while `start_all` is still running; a prompt time limit is a host decision to drop the `dispatch_prompt` future, which requests cancellation. After escalation, plugin code that is still running stays loaded; a NEP host should exit the process. See `examples/simple_node.rs` for a complete CAL host.

## 14. Next Steps and Resources

- Browse `examples/kvstore_plugin` for a working native plugin.
- The template at `templates/production/nep-plugin` demonstrates a production scaffold with lifecycle hooks, a managed task, configuration defaults, and prompt commands.
- Keep an eye on `CHANGELOG.md` for `PLUGIN_ABI_VERSION` changes.

Questions, suggestions, or contributions are welcome via issues and pull requests in the main repository.

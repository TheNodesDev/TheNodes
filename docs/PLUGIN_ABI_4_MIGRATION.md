# Migrating to Plugin ABI 4

Plugin ABI 4 replaces the native boundary and adds a managed plugin lifecycle.
ABI 3 libraries are rejected by ABI 4 hosts; there is no compatibility mode.
Rebuild every plugin together with its host. Background and design:
[ADR-0011](adr/0011-plugin-runtime-and-lifecycle.md). Authoring reference:
[Plugin Authoring Guide](PLUGIN_AUTHORING.md).

## Plugin Authors

### 1. Export entry points with `export_plugin!`

Replace the hand-written `register_plugin` function:

```rust
// ABI 3
#[no_mangle]
pub unsafe extern "C" fn register_plugin(api: *const PluginRegistrarApi) {
    let api = PluginRegistrarApi::from_raw(api).unwrap();
    api.register_plugin(Box::new(MyPlugin::new())).unwrap();
}
```

```rust
// ABI 4
use thenodes::plugin_host::{NativeRegistrar, PluginRegistrationError};

fn register(registrar: &mut NativeRegistrar) -> Result<(), PluginRegistrationError> {
    registrar.register(Box::new(MyPlugin::new()));
    Ok(())
}

thenodes::export_plugin!(register);
```

The macro also exports `thenodes_plugin_abi_version`, which the host checks
before registration. `PluginRegistrarApi::register_plugin`, `PluginHandle`, and
`load_plugins_from_dir` no longer exist.

### 2. Remove private runtimes

Callbacks and managed tasks now run on a Tokio runtime owned by your library.
Remove any plugin-local `Runtime`, `OnceLock<Runtime>`, or `Handle` plumbing and
use Tokio APIs directly. Set the worker count with
`registrar.set_runtime_workers(n)` if the default of 2 does not fit.

### 3. Move initialization and cleanup into lifecycle hooks

- Initialization that previously waited for a first message, or for a
  host-specific startup message, belongs in `on_start`. It runs once, with the
  final configuration, before any message is delivered.
- Cleanup belongs in `on_stop`. It also runs after a failed or cancelled start,
  so it must tolerate partial initialization.
- Both return `Result<(), PluginError>`; an error fails the plugin and the host
  is notified.

### 4. Move background loops into managed tasks

Replace `tokio::spawn` loops with `ctx.spawn_task(name, |task| async move { ... })`.
Wait for `task.activated()` before sending, and stop on `task.cancelled()`.
Context sends before activation now return `DeliveryFailureReason::NotReady`
instead of being attempted.

### 5. Replace low-level host access

In native plugins, `PluginContext::peer_manager()` and `peer_store()` return
`None`; the public `peer_manager` and `peer_store` fields are gone.

| ABI 3 | ABI 4 |
| --- | --- |
| `ctx.peer_manager.broadcast(&message.as_json())` | `ctx.broadcast(message).await` |
| `ctx.peer_manager.list_node_ids()` | `ctx.connected_peer_ids().await` |
| `ctx.peer_manager.send_to_node_id(...)` | `ctx.send_message(to, message, options).await` |
| Relay builders, peer-store queries | Not yet available to native plugins (CAL only) |

### 6. Review message handling

- `on_message` calls for one plugin no longer overlap: messages are handled one
  at a time in admission order. Spawn managed tasks for concurrency.
- Never await a reply that arrives through your own `on_message`; wait for it in
  a managed task.
- The five-second dispatch timeout is gone. A slow plugin fills its own inbox
  and further messages for it are rejected as overloaded.
- Events: emit through `ctx.events`. Native plugins cannot register event sinks;
  `EventHandle::register_sink` now returns a `Result`.

### 7. Rebuild with the host

Use the host's TheNodes source, Rust toolchain, target, `Cargo.lock`, and
TheNodes features. Forward features in your manifest (`noise = ["thenodes/noise"]`).
Keep the system allocator and unwinding panics.

## Host Authors

1. **Registration returns results.** `PluginRegistrar::register_handler` returns
   `Result<(), PluginRegistrationError>`. `PluginLoader::load_plugins` and
   `load_library` take `&mut PluginManager` and return typed `PluginLoadError`s,
   including partial-registration and conflicting-default failures. Loaded
   libraries are pinned for the life of the process; remove any
   `std::mem::forget(loader)`.
2. **Finalize the context before startup.** Construct the host context once
   configuration, identity, and stores are final, and install it with
   `PluginManager::with_context` or `set_context`. `PluginContext::set_plugin_manager`
   is gone; the manager installs a weak reference itself.
3. **Drive the lifecycle explicitly:**
   ```rust
   let manager = Arc::new(manager);
   let mut failures = manager.subscribe_failures();
   let report = manager.start_all(StartPolicy::StopOnFirstFailure).await?;
   // Decide about failures: shut down, or acknowledge_failure(id) to continue.
   let listener = thenodes::network::bind_listener(port, true).await?; // observe bind errors
   // spawn run_listener(listener, ...) and keep its JoinHandle
   manager.activate()?;
   // ... run until a signal, prompt exit, or failures.recv() ...
   let report = manager.shutdown(ShutdownMode::Drain).await?;
   ```
4. **Dispatch is admission.** `dispatch_message` is synchronous, returns a
   `DispatchReport`, and does not wait for plugins. Tests that awaited it to
   observe plugin effects must wait on explicit notifications.
5. **Prompts go through the manager.** Replace `get_prompt_plugin` and direct
   `on_prompt` calls with `resolve_prompt(prefix)` and
   `dispatch_prompt(&target, input).await`. Any prompt time limit is now the
   host's own choice: drop the future to request cancellation.
6. **Shutdown and escalation.** Use `begin_shutdown`/`shutdown` on every exit
   path, stop and await your listener handles, and call `escalate()` if your own
   policy decides to stop waiting. After escalation, exit the process if work
   was reported as `FailedToQuiesce`.
7. **Options.** `PluginHostOptions` sets the per-plugin inbox capacity (default
   32) and prompt capacity (default 4) before startup.

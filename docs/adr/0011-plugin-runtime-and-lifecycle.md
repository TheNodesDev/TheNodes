# ADR 0011: Plugin Runtime and Lifecycle

- Status: Proposed
- Date: 2026-10-26
- Target: 0.5.0 (plugin ABI 4)
- Supersedes: the ABI 3 native plugin boundary and the fixed plugin dispatch timeout

## Context

Through plugin ABI 3, a native plugin crossed the library boundary as an async
`Plugin` trait object, and the host polled the futures that plugin code created.
Each native library links its own copy of std, Tokio, and TheNodes, so this had
three consequences:

- A plugin panic during such a poll unwound into the host's copy of std. The
  unwinder treats an exception raised by another std copy as foreign and aborts
  the process.
- A native plugin cannot rely on the host's Tokio thread-local context. Spawning
  tasks or creating timers from plugin code failed with `no reactor running`, so
  plugins had to build and own a private runtime.
- `EventHandle` used the global dispatcher of the calling code copy, which is
  never initialized inside a plugin, so native plugin events were dropped.
  `PluginContext` sends ran the plugin's copy of the delivery code on host-owned
  objects.

Plugins also had no lifecycle: no initialization hook that ran before traffic,
no shutdown hook, no tracked background work, and a five-second dispatch timeout
that abandoned slow handlers. Hosts that needed initialization invented private
startup messages. Loaded libraries were unloaded or forgotten depending on how
the host exited, and the loader opened any library it found, whoever could
have written it.

## Decision

### Mechanism, not policy

TheNodes provides lifecycle mechanisms: explicit outcomes, cancellation,
escalation, and observable progress. It adds no timers or deadlines to plugin
dispatch, prompts, startup, or shutdown. A host or supervisor that wants time
limits applies them by requesting shutdown and escalation. Plugins may use
timers in their own logic. Protocol timers inside networking (heartbeat,
reconnect, reliable-delivery retry) are outside this decision.

Whether a plugin failure stops the node is host policy. TheNodes isolates and
reports a failed plugin; the host decides whether to continue. Continuing is
explicit: activation is refused while any failure is unacknowledged.

### Lifecycle

`Plugin` gains `on_start` and `on_stop` (async, with no-op defaults) returning
`Result<(), PluginError>`, and `max_managed_tasks`. Plugin state progresses
`Registered -> Starting -> Running -> Stopping -> Stopped`, with `Failed`
reachable from `Starting`, `Running`, and `Stopping`. The manager tracks a host
phase: `Registering -> Starting -> Ready -> Active -> Stopping -> Stopped`.

| Operation | Behavior |
| --- | --- |
| `PluginManager::start_all(policy)` | Runs `on_start` sequentially in registration order and returns a `StartReport`. `StopOnFirstFailure` leaves later plugins `NotStarted`. Concurrent or repeated calls join the same startup. |
| `acknowledge_failure(id)` | Records the host's decision to run without a failed plugin. |
| `activate()` | Opens message consumption and outbound context operations. Requires phase `Ready` and every failure acknowledged. |
| `dispatch_message(msg)` | Non-blocking admission into each subscribed plugin's inbox; returns a `DispatchReport`. |
| `resolve_prompt` / `dispatch_prompt` | Prompt lookup returns a `PromptTarget`; execution goes through managed admission on every call. |
| `begin_shutdown(mode)` / `shutdown(mode)` | The common cleanup path; returns a `ShutdownReport`. Repeated calls return the recorded report. |
| `escalate()` | Stops waiting on uncooperative work and records failed quiescence. |
| `subscribe_failures()` | Host failure notifications, independent of event sinks. |

One serialized owner runs each transition as a task on the host runtime.
Callers wait on its recorded result, so a dropped waiter never abandons a
transition. No manager lock is held while plugin code runs.

Startup order is registration order: native libraries are loaded in sorted path
order and handlers keep their order within a library. Order carries no meaning
because plugins cannot interact before activation. Two plugins that supply
different early configuration defaults for the same single-valued field fail
registration; `bootstrap_nodes_extend` stays additive.

### Native endpoint boundary

The registration helper (`export_plugin!` and `NativeRegistrar`) wraps every
handler in an adapter compiled into the plugin's own copy of TheNodes. The host
receives that adapter as a `PluginEndpoint` trait object, never the async
`Plugin` trait object. Endpoint methods are synchronous: each carries owned data
and a completion sink and returns at once. A sink is a boxed closure whose code
belongs to its creator and needs no runtime context on the calling thread.

No future, waker-bound object, Tokio handle, or runtime-bound host object
crosses the boundary. Plugin metadata (ID, subscriptions, prompt prefix, early
defaults, task limit) is read once inside the plugin copy at registration and
transferred as owned data.

### One runtime per native library

Each loaded library owns one multi-thread Tokio runtime shared by every handler
it registers. The runtime is created when the first handler starts, never for
early defaults. The library declares its worker count with
`NativeRegistrar::set_runtime_workers`; the default is 2. All plugin callbacks
and managed tasks run on that runtime; plugin code never runs on host runtime
threads.

Statically registered (CAL) plugins use the same adapter, compiled into the host
and bound to the host runtime. They follow the same lifecycle, admission, task
scope, and failure contract without an extra runtime. A hybrid host selects the
mode at registration: `register_handler` is CAL, the loader is native.

### Panic containment

The adapter runs every callback as a task and observes its join result inside
the plugin's code copy. Synchronous endpoint methods, the registration entry
point, and host-service methods are wrapped in `catch_unwind` on the side that
owns the code. A panic crosses the boundary only as a bounded message. Recovery
from `panic = "abort"`, aborting `extern "C"` panics, undefined behavior,
segmentation faults, `process::exit`, or non-yielding code is not provided.

### Host services

Official context operations (`deliver_message`, `send_message`, `broadcast`,
`connected_peer_ids`, and event submission) delegate to a host-created services
object. It runs in host code, checks lifecycle state, and spawns host work on a
host runtime handle captured when startup begins. Delivery work, including
reliable-delivery retries, belongs to the host runtime and survives plugin
runtime teardown. Results return through plugin-side completion sinks.

A plugin-bound context holds data (node ID, final configuration, plugin ID),
host services, and the plugin's task scope. The services object holds only a
weak manager reference. The low-level `PeerManager` and `PeerStore` are
available through `PluginContext::peer_manager()` and `peer_store()` only in
contexts that share the host's code copy; native contexts return `None`.
Native events go through host services, which stamp the host session; native
plugins cannot register event sinks because the dispatcher would poll their
futures.

### Admission and managed work

Each plugin has a bounded FIFO inbox with one consumer. Admission never waits:
a full inbox returns `Rejection::Overloaded` for that plugin only, and other
plugins continue. The inbox capacity includes the message in progress. Messages
can be admitted while a plugin is starting but are consumed only after
activation. This replaces the dispatch timeout and the `plugin_dispatch_timeout`
event.

Because each plugin handles its messages one at a time, a handler must not
await a message that only its own inbox can deliver. Request/reply waits belong
in managed tasks.

`PluginContext::spawn_task` starts a managed task in the plugin's scope. Tasks
count against the plugin's declared limit (default 128) and stay accounted for
until their completion is observed; dropping a `TaskHandle` does not detach.
`TaskContext::activated` waits for activation or cancellation, and
`TaskContext::cancelled` observes scope cancellation. A task that panics or
returns an error is a plugin failure. Callback jobs are tracked separately from
managed tasks; dropping a host-side waiter requests cancellation of the job and
keeps it tracked until completion is observed. Lifecycle hooks never consume
inbox or task capacity.

Official send paths return `DeliveryFailureReason::NotReady` before activation,
`Stopping` after shutdown drained admitted messages, and `Unavailable` for a
failed plugin or a dropped host. Transport ACKs keep their meaning: receipt by a
peer or transport is not proof of plugin processing.

### Shutdown and escalation

Normal shutdown, prompt exit, failed startup, a fatal plugin failure, and a
local transport-start failure use the same path:

1. Close inbound admission and record stopping.
2. The host stops its listeners and prompt.
3. Drain admitted messages (only after activation) or discard them; managed
   tasks and outbound operations keep working during a drain.
4. Cancel every task scope and in-flight callback; observe callback completion.
5. Run `on_stop` in reverse start order for plugins whose `on_start` was entered.
6. Abort remaining managed tasks and observe their completion.
7. Release each native library runtime with a non-blocking shutdown once all
   of its handlers stopped. Threads created outside the managed scope are not
   waited for.
8. Return a `ShutdownReport` that keeps execution failures separate from cleanup
   results.

While waiting, the manager emits `plugin_waiting` with the phase and plugin.
Escalation is an explicit event: the standalone host escalates on a second
SIGINT or SIGTERM; CAL hosts call `escalate()`. Work not observed to finish is
reported as `StopResult::FailedToQuiesce(phase)`; its code and runtime stay
loaded and the plugin is not reported `Stopped`. The standalone host then exits
unsuccessfully.

A plugin that fails during startup or execution is rolled back alone through
steps 3 to 6 and stays `Failed`. A failed plugin is not restarted in place.
If shutdown begins while such a rollback is running, shutdown joins it; a stop
hook that is already running is never cancelled. A failure recorded while the
host is already stopping cancels that plugin's in-flight callbacks and managed
tasks at once, so a drain never waits on work that depended on the failed
part; shutdown still runs the plugin's stop hook in step 5.

### ABI 4 and loader ownership

`PLUGIN_ABI_VERSION` is 4. A library must export
`thenodes_plugin_abi_version() -> u32`, which the loader checks before calling
`register_plugin(api) -> u32`. A missing export or another version fails loading
without invoking any plugin trait object. Registration outcomes are
authoritative: invalid IDs, duplicate IDs or prompt prefixes, conflicting
defaults, empty registrations, plugin registration errors, and panics are
returned as typed errors. Handlers are staged and committed per library, so a
partial registration never becomes host configuration.

The loader pins every successfully opened library for the life of the process,
before any of its code or objects can escape, including on error paths.
`load_plugins_from_dir` is removed. Process restart is the supported replacement
boundary; hot unload is not supported.

Loading a library runs its code as the node's user, so on Unix the loader
first checks that no other user could have written or replaced it. It
resolves symlinks and refuses the library (`PluginLoadError::UnsafePath`)
unless the file and every directory above it are owned by the node's user or
root and are not writable by other users. Group write is accepted only for
the owner's private group (the owner's primary group, named after the owner,
with no other members: the default under `umask 002`), and on Linux not for
an entry with a POSIX ACL, whose group bits are then the ACL's mask; an ACL
that cannot be read is refused. A directory with the sticky bit, such as
`/tmp`, may be writable by others, who cannot rename or remove entries they do
not own. The library is loaded from the resolved path that was checked.
Windows has no such check, and ACLs on systems other than Linux are not
examined.

### Initial engineering defaults

| Option | Default | Owner |
| --- | --- | --- |
| Native runtime workers | 2 per loaded library | Plugin library (`set_runtime_workers`) |
| Managed tasks | 128 live tasks per plugin | Plugin (`max_managed_tasks`) |
| Inbox capacity | 32 messages per plugin, including the one in progress | Host (`PluginHostOptions`) |
| Prompt capacity | 4 concurrent prompts per plugin | Host (`PluginHostOptions`) |

The integration tests run with these defaults and with smaller host limits. No
option introduces a timeout.

## Invariants

| Area | Invariant |
| --- | --- |
| Readiness | No ordinary callback runs before activation. Once stopping begins no inbound message or prompt is admitted. |
| Readiness | Remote messages cannot invoke lifecycle transitions. |
| Readiness | A host announces running only when every plugin started or each failure was acknowledged. |
| Ownership | Every callback and managed task is accounted for until its completion and destruction are observed; cancellation requests are not evidence. |
| Ownership | Library code stays mapped while plugin objects, futures, vtables, threads, or destructors may reference it. |
| Boundary | No future, waker-bound object, Tokio handle, or runtime-bound host object crosses the native boundary. A native panic never unwinds into host frames. |
| Boundary | Official context operations execute in host code on the host runtime. |
| Failure | A plugin failure changes only that plugin's state; the node continues only by explicit host decision. |
| Bounds | Inboxes, prompt calls, and managed tasks have finite bounds and reject explicitly at capacity. |
| Time | No framework timer or deadline governs dispatch, prompts, startup, or shutdown. |
| Events | Lifecycle events carry plugin ID, phase, result category, and elapsed time; never payloads, configuration, error text, or panic messages. |

## Consequences

- Plugin authors write the async `Plugin` trait and no longer manage a runtime.
  Host and plugins must be rebuilt together; ABI 3 artifacts are rejected.
- Native plugins can no longer reach `PeerManager` or `PeerStore` directly.
  Relay frame sending and peer-store queries need new host-service operations in
  later work.
- `dispatch_message` returns after admission. Code that relied on it returning
  after plugin handling must synchronize on explicit notifications.
- A plugin that blocks or never yields starves the other handlers on its
  runtime: other handlers of the same native library, or the whole host for a
  CAL plugin. Separate libraries do not share a runtime. Raw `tokio::spawn`,
  `spawn_blocking`, `std::thread`, and foreign executors used by plugin code are
  not managed.
- Pinning retains plugin code and statics for the life of the process. Creating
  many dynamic hosts in one long-lived process accumulates pinned libraries.
- Trusted native plugins still run with the process's privileges. Separate
  runtimes, admission checks, and per-plugin data directories are not a sandbox,
  and the ABI version check is not authentication. The ownership check keeps
  other local users from substituting a library; it does not show who built
  it.
- A `plugins/` directory, or any directory above it, that other users or a
  shared group can write to must have its permissions corrected before the
  host loads from it.
- Networking shutdown remains partial: the standalone host stops and joins its
  TCP listener, but discovery, NAT, UDP-session, and connection tasks do not yet
  expose a stop/join API. Their plugin dispatch is refused once stopping begins.

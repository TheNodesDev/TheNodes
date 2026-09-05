# Plugin Storage Decision

## Decision

TheNodes core will not provide a generic plugin storage or key-value API in this step.

Plugins own their state and persistence mechanisms. They may keep in-memory state, use a storage crate directly, or integrate with an external data service according to their own requirements. The async plugin dispatch boundary lets message handlers await I/O, database access, or session/state lookups without blocking the runtime.

## Rationale

- The core remains application-neutral and avoids imposing a data model or storage backend on plugins.
- Storage requirements differ in consistency, durability, transactions, schema evolution, isolation, and operational ownership.
- The existing `PeerStore` persists framework peer-discovery metadata; it is not a general plugin data store.
- A minimal key-value surface without explicit semantics would create an API commitment while leaving important behavior undefined.

## Scope

This decision adds no storage methods to `PluginContext` and does not prevent a future, separately designed storage capability. Any future core-managed storage API should first define ownership, namespacing, concurrency, lifecycle, error handling, and compatibility guarantees.

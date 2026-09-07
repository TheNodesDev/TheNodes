# Plugin Storage Decision

## Decision

TheNodes core provides each plugin with an isolated, durable data directory under the
node state directory. Plugins obtain that location through `PluginContext` and own all
files stored there.

TheNodes does not provide a generic key-value API or storage engine. Plugins may use
flat files, a storage crate, or an external data service according to their own
requirements. The async plugin dispatch boundary lets message handlers await I/O,
database access, or session/state lookups without blocking the runtime.

## Rationale

- The core remains application-neutral and avoids imposing a data model or storage backend on plugins.
- A framework-assigned directory gives plugins a stable, sanctioned location without
  making the framework responsible for their schema or transaction semantics.
- Directory names are derived from validated plugin identifiers so one plugin cannot
  escape its assigned location or overlap another plugin's files.
- Storage requirements differ in consistency, durability, transactions, schema evolution, isolation, and operational ownership.
- The existing `PeerStore` persists framework peer-discovery metadata; it is not a general plugin data store.
- A minimal key-value surface without explicit semantics would create an API commitment while leaving important behavior undefined.

## Scope

`PluginContext::plugin_data_dir()` creates and returns the calling plugin's directory
on first use. The directory remains stable for the same node state directory and
plugin identifier across restarts.

The plugin remains responsible for:

- choosing and configuring its storage engine;
- file locking and concurrent access;
- schemas, migrations, backups, and corruption recovery;
- data retention and deletion.

Any future core-managed storage API would require a separate design that defines
ownership, namespacing, consistency, lifecycle, error handling, and compatibility
guarantees.

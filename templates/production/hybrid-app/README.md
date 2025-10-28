# {{APP_NAME}} (Hybrid: CAL + NEP)

{{APP_DESCRIPTION}}

This application is a hybrid:
- A dedicated binary (CAL) named `{{APP_NAME}}` suited for daemon deployments (e.g., `myrealmd`).
- It loads runtime plugins (NEP) from the `plugins/` directory to add business logic without recompiling.

## Features
- Uses TheNodes as a library (CAL) for networking, security, realms, and events.
- Loads plugins dynamically (NEP) using TheNodes' plugin host.
- TLS/mTLS and trust policy with observed/trusted PKI directories.
- Optional interactive prompt for development (`--prompt`).

## Layout
```
{{APP_NAME}}/
  Cargo.toml
  src/main.rs
  config.toml
  plugins/           # place built plugin libraries here (.so/.dylib/.dll)
  data/              # node_id persistence
  logs/              # audit logs
  pki/               # certificates and keys
```

## Build
```bash
cargo build --release
```

## Run
```bash
# Generate dev certificates (optional helper from TheNodes root; adjust path as needed)
cargo run --bin thenodes-cert -- --realm {{APP_REALM}} --copy-to-trusted

# Start the daemon
./target/release/{{APP_NAME}} --config config.toml --prompt
```

## Writing Plugins
- Build against TheNodes plugin trait and produce a dynamic library.
- Copy the compiled artifact into `plugins/`.
- Restart the daemon; plugins are loaded at startup.

## Notes
- In production, set proper PKI material under `pki/own` and `pki/trusted`.
- To restrict which remote roles may connect, update `[realm_access]` in `config.toml`.

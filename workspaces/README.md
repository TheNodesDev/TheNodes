# Generated Workspaces

This directory contains user applications generated from TheNodes templates. Each subdirectory is a complete Rust workspace for a specific application built with TheNodes.

## Structure

```
workspaces/
├── my-chat-app/           # Generated CAL mode application
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── config/
├── my-plugin/             # Generated NEP mode plugin
│   ├── Cargo.toml
│   ├── src/lib.rs
│   └── README.md
└── ...
```

## Generation

Generate new applications using the template system:

```bash
# From the templates/ directory
cd templates/
./generate_app.sh my-chat-app cal-app --realm my-chat-network
./generate_app.sh my-plugin nep-plugin --realm prod-messaging
```

Generated workspaces will appear here and are ready for development.

## Development

Each generated workspace is independent and can be:
- Built with `cargo build`
- Run with `cargo run`
- Tested with `cargo test`
- Published as a separate project

## Git Handling

Generated workspaces are `.gitignore`d by default to avoid cluttering the main TheNodes repository. To version control a generated workspace:

1. Copy it outside the TheNodes directory
2. Initialize its own git repository
3. Develop it as a standalone project

This keeps user applications separate from TheNodes core development.
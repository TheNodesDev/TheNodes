# NEP Plugin Template

This template creates a plugin for TheNodes NEP (Node-Embedded Plugin) mode.

## What This Creates

A plugin library that:
- Compiles to a dynamic library for loading by a host: `.so` (Linux) / `.dylib` (macOS) / `.dll` (Windows)
- Implements the TheNodes Plugin trait
- Provides configuration defaults
- Handles messages and prompt commands
- Uses local path dependency (until TheNodes is published to crates.io)
  
Security defaults:
- TLS is recommended and enabled by default in production templates; mTLS recommended for production deployments.
- Ensure your host's `config.toml` is configured with PKI paths and a restrictive trust policy (e.g., allowlist or fingerprint pins).
- For local testing, you can quickly generate certs:
   ```bash
   cargo run --bin thenodes-cert -- --realm my-network --copy-to-trusted
   ```
   This prints an SPKI fingerprint you can pin in `[encryption.trust_policy]`.

## Prerequisites

**Current Setup (Development):**
- Clone the TheNodes repository
- Run the generator from the repository checkout
- The generator rewrites the local `path` dependency for the selected output directory

The generated manifest also pins `thenodes = "=0.4.0"`; remove the local `path` key when building solely from crates.io.

## Usage

1. **Generate the plugin:**
   ```bash
   cd templates/
   ./generate_app.sh my-plugin nep-plugin --realm my-network
   ```

2. **Build the plugin:**
   ```bash
   cd ../workspaces/my-plugin/
   cargo build --release
   ```

3. **Deploy the plugin:**
   ```bash
# Copy to the TheNodes host plugins directory (use the correct extension for your OS)
# Linux
cp target/release/libmy_plugin.so /path/to/thenodes/plugins/
# macOS
cp target/release/libmy_plugin.dylib /path/to/thenodes/plugins/
# Windows (PowerShell)
Copy-Item target\release\my_plugin.dll C:\path\to\thenodes\plugins\
   ```

4. **Run with TheNodes binary:**
   ```bash
   # Assuming you have the TheNodes binary installed
   thenodes --config config.toml
   ```

## Key Features

- **Version Pinned:** Targets TheNodes 0.4.0 for plugin ABI compatibility
- **Plugin Defaults:** Provides configuration defaults without overriding user config
- **Message Handling:** Template for custom message processing
- **Prompt Integration:** Commands available in `--prompt` mode
- **Event Emission:** Proper integration with TheNodes event system

## Template Variables

The generator replaces these placeholders:
- `{{APP_NAME}}` - Plugin name (e.g., "my-plugin")
- `{{APP_NAME_PASCAL}}` - PascalCase version (e.g., "MyPlugin")
- `{{APP_REALM}}` - Target realm name

## Distribution Model

This template follows the **production distribution model:**
- TheNodes is an exact library dependency (`thenodes = "=0.4.0"`)
- Plugin compiles independently
- The generated development manifest points to the local TheNodes checkout
- Plugin dynamic library works with any compatible TheNodes binary

## Next Steps

After generation:
1. Customize the plugin logic in `src/lib.rs`
2. Add your message types and handlers
3. Test with the TheNodes binary
4. Deploy to production

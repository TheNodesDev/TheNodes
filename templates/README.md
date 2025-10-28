# TheNodes Application Templates

This directory contains templates for generating new applications built with the TheNodes framework.

## Usage

Use the `generate_app.sh` script to create new applications:

```bash
./generate_app.sh <app-name> <template-type> [options]
```

## Template Categories

### Production Templates (`production/`)
Ready-to-use templates for end-user applications. These use TheNodes as a published crate dependency.

- **cal-app** - Simple P2P application using TheNodes as library (CAL mode)
- **nep-plugin** - Plugin for existing TheNodes host (NEP mode, builds a dynamic library: .so/.dylib/.dll)
- **minimal-app** - Bare minimum integration example
- **hybrid-app** - CAL daemon binary that loads NEP plugins (best of both)

Security defaults:
- Production templates enable TLS by default and include PKI paths; place your certs/keys under the generated `pki/` directories before running.
- To run quickly for local development, you may set `encryption.enabled = false` in the generated `config.toml` (not recommended for production).

Generate self-signed certs for testing:
```bash
cargo run --bin thenodes-cert -- --realm {{APP_REALM}} --copy-to-trusted
```
This creates cert/key under `pki/` and prints an SPKI fingerprint. You can pin it in `[encryption.trust_policy]`.

### Development Templates (`development/`)
Templates for TheNodes core development and advanced customization. These use path dependencies to the TheNodes source.

- **custom-host** - Custom plugin host with interactive interface
- **hybrid-app** - Combined CAL + NEP approach

### 2. `nep-plugin/` - Node-Embedded Plugin (NEP)
**Best for:** Extensible applications, development platforms, complex systems

- Acts as a plugin host for both TheNodes and custom plugins
- Interactive command interface with tab completion
- Trust management commands (observed/trusted list; promote observed → trusted)
- Session management
- Custom message routing
- Extensible architecture

**Example use cases:**
- Plugin-based development platforms
- Extensible P2P applications
- Testing and development tools
- Custom network protocols with plugins

### 3. `hybrid-app/` - Combined Approach
**Best for:** Complex applications needing both approaches

- Combines CAL and NEP patterns
- Core functionality as library integration
- Optional plugin extensibility
- Flexible architecture

### 4. `minimal-app/` - Bare Minimum
**Best for:** Learning, prototyping, minimal footprint
*(Coming Soon)*

- Absolute minimal TheNodes integration
- Educational purposes
- Quick prototypes
- Resource-constrained environments

## Quick Start

### Using the Generator Script

```bash
# From the templates/ directory, generate a new CAL application
cd templates/
./generate_app.sh my-app cal-app

# Generate a new plugin host (will create in parent directory by default)
./generate_app.sh my-platform nep-plugin

# Generate with custom realm and specific output directory
./generate_app.sh my-app cal-app --realm "production-net" --output ~/projects/

# Generate a hybrid daemon that loads plugins
./generate_app.sh myrealmd hybrid-app --realm "prod-realm"
```

> **Note:** By default, generated apps are created in the parent directory (outside of `templates/`) to keep the template directory clean. Use `--output` to specify a different location.

### Developer Config (hardcoded values)

Each production template includes `src/app_identity.rs`. Use it to hardcode values that must not be user-overridable (e.g., realm and app_name). These are applied at startup via `SimpleHardcoded` and intentionally omitted from `config.toml` to avoid accidental overrides.

### Manual Setup

1. **Copy a template:**
   ```bash
   cp -r templates/production/cal-app/ ../my-new-app/
   cd ../my-new-app/
   ```

2. **Customize the template:**
   - Replace `{{APP_NAME}}` with your application name
   - Replace `{{APP_DESCRIPTION}}` with your description  
   - Replace `{{APP_REALM}}` with your realm name
   - Update `Cargo.toml` path to TheNodes dependency

3. **Build and run:**
   ```bash
   cargo build
   cargo run -- --config config.toml
   ```

## Template Comparison

| Feature | cal-app | nep-plugin | hybrid-app | minimal-app |
|---------|-----------|-----------------|------------|-------------|
| **Integration** | Library (CAL) | Plugin Host (NEP) | Both | Library |
| **Complexity** | Low | Medium | High | Minimal |
| **Extensibility** | Code changes | Runtime plugins | Both | Limited |
| **Resource Usage** | Low | Medium | High | Minimal |
| **Learning Curve** | Easy | Medium | Advanced | Beginner |
| **Best For** | Simple apps | Platforms | Complex systems | Learning |

## Architecture Patterns

### CAL Pattern (Core-as-a-Library)
```
Your Application
       ↓
TheNodes Library ←→ Network
       ↓
Custom Business Logic
```

**Pros:**
- Direct integration and control
- Lower resource usage
- Simpler deployment
- Better performance

**Cons:**
- Less extensible
- Requires recompilation for changes
- Tighter coupling

### NEP Pattern (Node-Embedded Plugin) 
```
Your Plugin Host
       ↓
Plugin Manager ←→ TheNodes + Custom Plugins
       ↓
Network ←→ Interactive Interface
```

**Pros:**
- Runtime extensibility
- Plugin ecosystem
- Interactive development
- Loose coupling

**Cons:**
- Higher complexity
- More resource usage
- Plugin management overhead

## Customization Guide

### Common Customizations

1. **Application Name and Branding:**
   - Replace all `{{APP_NAME}}` placeholders
   - Update descriptions and help text
   - Customize logging prefixes

2. **Network Configuration:**
   - Change default ports
   - Configure bootstrap nodes
   - Set up realms and network segmentation

3. **Security Settings:**
   - Enable/disable encryption
   - Configure PKI directory structure
   - Set up trust policies

4. **Custom Business Logic:**
   - Add your domain-specific functionality
   - Integrate with external systems
   - Implement custom protocols

### Template Variables

When using templates, replace these placeholders:

- `{{APP_NAME}}`: Your application name (e.g., "my-chat-app")
- `{{APP_DESCRIPTION}}`: Application description for CLI help
- `{{APP_REALM}}`: Network realm name (e.g., "chat-network")

### Configuration Patterns

#### Basic Configuration
```toml
port = 50001
app_name = "my-app"

[realm]
name = "my-network"
version = "1.0"
```

#### With Encryption (enabled by default in production templates)
```toml
[encryption]
enabled = true

[encryption.paths]
own_certificate = "pki/own/my-app.crt"
own_private_key = "pki/own/my-app.key"
```
For mutual TLS and pinning, see `[encryption.mtls]` and `[encryption.trust_policy]` in the generated config.

#### Production Settings
```toml
[logging]
disable_console = true
json_path = "/var/log/my-app/audit.jsonl"

[node]
state_dir = "/var/lib/my-app"
```

## Development Workflow

### 1. Choose Your Template

- **Building a simple P2P app?** → `cal-app`
- **Need plugin extensibility?** → `nep-plugin`
- **Complex requirements?** → `hybrid-app`
- **Just learning/prototyping?** → `minimal-app`

### 2. Generate and Customize

```bash
# Generate from template
./generate_app.sh my-project cal-app

# Customize configuration
cd my-project
nano config.toml

# Update dependencies if needed
nano Cargo.toml
```

### 3. Develop and Test

```bash
# Build and test
cargo build
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- --config config.toml --verbose
```

### 4. Deploy

```bash
# Production build
cargo build --release

# Package for deployment
tar -czf my-project.tar.gz target/release/my-project config.toml
```

## Best Practices

### Code Organization

- Keep business logic separate from TheNodes integration
- Use modules to organize functionality
- Follow async-first patterns throughout

### Configuration Management

- Use separate configs for dev/test/prod environments
- Document all configuration options
- Validate configuration at startup

### Error Handling

- Use proper error types and propagation
- Log errors with context
- Handle network failures gracefully

### Security

- Enable encryption in production
- Validate all inputs from network
- Follow principle of least privilege
- Keep certificates and keys secure

### Performance

- Use async patterns consistently
- Avoid blocking operations in async contexts
- Monitor resource usage
- Profile and optimize bottlenecks

## Troubleshooting

### Common Issues

1. **Build Errors:**
   ```bash
   # Update TheNodes dependency path
   thenodes = { path = "../../TheNodes" }
   ```

2. **Runtime Errors:**
   ```bash
   # Check configuration
   cargo run -- --config config.toml --verbose
   ```

3. **Network Issues:**
   ```bash
   # Check port availability
   netstat -ln | grep :50001
   ```

### Debug Tips

- Use `RUST_LOG=debug` for detailed logging
- Check configuration file syntax
- Verify network connectivity
- Monitor resource usage

## Contributing

### Adding New Templates

1. Create new template directory
2. Include all necessary files:
   - `Cargo.toml`
   - `src/main.rs` and related code
   - `config.toml`
   - `README.md`
3. Update this main README
4. Test the template thoroughly

### Template Guidelines

- Use placeholder variables for customization
- Include comprehensive documentation
- Provide working examples
- Follow TheNodes best practices
- Test with different configurations

## Support

### Documentation

- [TheNodes Main README](../README.md)
- [Architecture Guide](../docs/)
- [Security Documentation](../docs/SECURITY.md)

### Getting Help

- Check template README files
- Review TheNodes documentation
- Look at example implementations
- Check GitHub issues and discussions

## License

These templates are provided under the same license as TheNodes: Apache-2.0 OR MIT.
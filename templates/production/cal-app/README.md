# {{APP_NAME}}

A custom application built with the TheNodes P2P framework.

## About

This application demonstrates how to build a custom P2P application using TheNodes as a library (CAL - Core-as-a-Library mode). It includes:

- Custom business logic integration
- Network message handling
- Configuration management
- Structured logging
- Graceful shutdown

## Quick Start

1. **Configure your application:**
   ```bash
   # Edit the configuration file
   nano config.toml
   ```

2. **Build and run:**
   ```bash
   cargo build --release
   cargo run -- --config config.toml
   ```

3. **Command line options:**
   ```bash
   # Run with verbose logging
   cargo run -- --config config.toml --verbose
   
   # Use a different config file
   cargo run -- --config my-custom-config.toml
   ```

## Architecture

### Core Components

- **`main.rs`**: Application entry point, initializes TheNodes and starts services
- **`business_logic.rs`**: Your custom application logic that integrates with TheNodes
- **`config.toml`**: Configuration for both TheNodes and your application

### Integration Pattern

This template uses the **Core-as-a-Library (CAL)** pattern:

1. TheNodes provides the P2P networking infrastructure
2. Your business logic runs alongside and integrates with TheNodes
3. Messages can be handled by both TheNodes and your custom logic
4. State is managed independently but can be shared

### Message Flow

```
Network ←→ TheNodes Framework ←→ Your Business Logic
                ↑
            Configuration
```

## Customization

### Adding Custom Message Types

1. Define your message types in `business_logic.rs`:
   ```rust
   MessageType::Custom("my_message_type".to_string())
   ```

2. Handle them in `handle_network_message()`:
   ```rust
   match message.msg_type {
       MessageType::Custom(ref msg_type) if msg_type == "my_message_type" => {
           // Handle your message
       }
       _ => { /* ... */ }
   }
   ```

### Adding Custom Configuration

1. Extend the config structure by adding fields to `config.toml`
2. Access them through `self.config` in your business logic
3. TheNodes will automatically load and validate the configuration

### Adding Custom State

1. Extend the `BusinessState` struct in `business_logic.rs`
2. Update the initialization in `BusinessLogic::new()`
3. Use the async RwLock for thread-safe access

## Security

### Encryption

To enable TLS encryption:

1. Set `encryption.enabled = true` in `config.toml`
2. Generate certificates and place them in the PKI directory structure
3. Configure the trust policy as needed

See the main TheNodes documentation for PKI setup instructions.

### Trust Policy

The trust policy determines which peers are allowed to connect:
- **Allowlist mode**: Only explicitly trusted peers can connect
- **Blacklist mode**: All peers except explicitly rejected ones can connect

## Deployment

### Production Build

```bash
# Build optimized binary
cargo build --release

# The binary will be at target/release/{{APP_NAME}}
```

### Configuration Management

- Keep sensitive configuration (certificates, keys) separate from the main config
- Use environment variables for deployment-specific settings
- Consider using config templates for different environments

### Monitoring

The application logs to both console and JSON audit log:
- Console: Human-readable logs for development
- JSON log: Structured logs for production monitoring

## Development

### Testing

```bash
# Run tests
cargo test

# Run with specific log level
RUST_LOG=debug cargo run -- --config config.toml --verbose
```

### Adding Dependencies

Add new dependencies to `Cargo.toml` as needed. The template includes commonly used crates:
- `tokio`: Async runtime
- `serde`: Serialization
- `clap`: CLI parsing
- `log`: Logging interface

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the `port` setting in `config.toml`
2. **Bootstrap connection failed**: Ensure bootstrap nodes are running and accessible
3. **Certificate errors**: Check PKI directory structure and certificate validity

### Debug Mode

Run with debug logging to see detailed information:
```bash
RUST_LOG=debug cargo run -- --config config.toml --verbose
```

## License

This template is provided under the same license as TheNodes: Apache-2.0 OR MIT.
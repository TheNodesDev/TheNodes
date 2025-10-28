# {{APP_NAME}}

A custom plugin host application built with the TheNodes P2P framework.

## About

This application demonstrates how to build a custom plugin host using TheNodes as a framework (NEP - Node-Embedded Plugin mode). It includes:

- Custom plugin host functionality
- Dynamic plugin loading (both TheNodes and custom plugins)
- Interactive command interface
- Session management
- Custom message routing
- Extensible command system

## Quick Start

1. **Configure your application:**
   ```bash
   # Edit the configuration file
   nano config.toml
   ```

2. **Build and run:**
   ```bash
   cargo build --release
   cargo run -- --config config.toml --prompt
   ```

3. **Command line options:**
   ```bash
   # Run with interactive prompt
   cargo run -- --config config.toml --prompt
   
   # Run with verbose logging
   cargo run -- --config config.toml --verbose --prompt
   
   # Use custom plugin directory
   cargo run -- --config config.toml --plugin-dir custom_plugins --prompt
   ```

## Architecture

### Core Components

- **`main.rs`**: Application entry point and plugin orchestration
- **`custom_plugin_host.rs`**: Custom host logic with session and message management
- **`app_commands.rs`**: Interactive command interface
- **`plugins/`**: Directory for dynamic plugins (`.so` / `.dylib` / `.dll`)

### Plugin System

This template supports multiple types of plugins:

1. **TheNodes Standard Plugins**: Loaded from the plugin directory (e.g., kvstore)
2. **Custom Application Plugins**: Implement the `CustomPlugin` trait
3. **Built-in Commands**: Integrated directly into the host

### Integration Pattern

This template uses the **Node-Embedded Plugin (NEP)** pattern:

```
Your App Host ←→ TheNodes Framework ←→ Network
     ↑                    ↑
Custom Plugins    TheNodes Plugins
```

### Message Flow

```
Network ←→ TheNodes ←→ Plugin Manager ←→ Custom Host ←→ Custom Plugins
                           ↑
                    Interactive Commands
```

## Interactive Commands

When running with `--prompt`, you can use these commands (with tab completion):

### Information Commands
- `help` or `?`: Show available commands
- `status` or `info`: Show host status
- `sessions`: List active sessions
- `plugins`: List loaded plugins

### Data Management
- `data set <key> <value>`: Store custom data
- `data get <key>`: Retrieve custom data
- `data list`: List all stored data

### Messaging
- `send <type> <target> <payload>`: Send custom network message

### Session Management
- `session create <id>`: Create new session
- `session destroy <id>`: Destroy session
- `session list`: List active sessions

### Trust Management
- `trust observed list`: List observed certificate fingerprints
- `trust trusted list`: List trusted certificate filenames
- `trust promote <fingerprint>`: Promote an observed fingerprint to trusted

## Creating Custom Plugins

### 1. Implement the CustomPlugin Trait

```rust
use async_trait::async_trait;

pub struct MyCustomPlugin {
    name: String,
}

#[async_trait]
impl CustomPlugin for MyCustomPlugin {
    fn name(&self) -> &str { &self.name }
    fn version(&self) -> &str { "1.0.0" }
    
    async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize your plugin
        Ok(())
    }
    
    async fn handle_message(&self, message: &Message) -> Result<Option<Message>, Box<dyn std::error::Error>> {
        // Handle network messages
        Ok(None)
    }
    
    async fn handle_command(&self, command: &str, args: Vec<&str>) -> Result<String, Box<dyn std::error::Error>> {
        // Handle interactive commands
        match command {
            "my_command" => Ok("My plugin response".to_string()),
            _ => Err("Unknown command".into()),
        }
    }
    
    async fn status(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Return plugin status
        Ok(serde_json::json!({"status": "running"}))
    }
}
```

### 2. Register Your Plugin

```rust
// In main.rs or during initialization
let my_plugin = Box::new(MyCustomPlugin::new());
custom_host.register_plugin(my_plugin).await?;
```

### 3. Dynamic Plugins (Optional)

For `.so`/`.dll` plugins, follow the TheNodes plugin interface and place them in the `plugins/` directory.

## Customization

### Adding Custom Message Types

1. Define message types in your plugin or host:
   ```rust
   MessageType::Custom("my_message_type".to_string())
   ```

2. Handle them in `handle_network_message()`:
   ```rust
   MessageType::Custom(ref msg_type) if msg_type == "my_message_type" => {
       // Your custom handling
   }
   ```

### Adding Custom Commands

1. Extend the `AppCommands::handle_command()` method
2. Add new command patterns and handlers
3. Update the help text in `show_help()`

### Session Management

The template includes a flexible session system:
- Create/destroy sessions with custom metadata
- Track session activity and lifetime
- Associate sessions with peers and custom data

## Configuration

### Plugin Loading

```toml
# In config.toml, you can specify plugin-related settings
[plugins]
directory = "plugins"
auto_load = true
```

### Custom Settings

Add your own configuration sections:
```toml
[my_app_settings]
feature_x_enabled = true
max_sessions = 100
```

## Security

### Plugin Security

- Only load plugins from trusted sources
- Validate plugin signatures if required
- Consider sandboxing for untrusted plugins
- Monitor plugin resource usage

### Network Security

Same security model as TheNodes:
- Optional TLS encryption
- PKI-based trust policy
- Realm-based network segmentation

## Deployment

### Production Build

```bash
# Build optimized binaries
cargo build --release

# Host binary
target/release/{{APP_NAME}}

# Copy plugins to deployment location
cp plugins/*.so /deployment/path/plugins/
```

### Plugin Management

```bash
# List loaded plugins
./{{APP_NAME}} --config config.toml --prompt
> plugins

# Check plugin status
> status
```

## Development

### Testing Custom Plugins

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --config config.toml --verbose --prompt

# Test plugin loading
> plugins
> status
```

### Plugin Development

1. Create new plugin in `src/plugins/my_plugin.rs`
2. Implement the `CustomPlugin` trait
3. Register in `main.rs`
4. Test with interactive commands

### Debugging

```bash
# Full debug output
RUST_LOG=trace cargo run -- --config config.toml --verbose --prompt

# Plugin-specific debugging
RUST_LOG=my_plugin=debug cargo run -- --config config.toml --prompt
```

## Examples

### Simple Session Workflow

```bash
# Start the host
cargo run -- --config config.toml --prompt

# Create a session
> session create user_123

# Send a message
> send session_data user_123 {"action": "login", "timestamp": 1234567890}

# Check status
> status
> sessions

# Destroy session
> session destroy user_123
```

### Plugin Command Example

```bash
# If you have a "weather" custom plugin
> weather current --location "New York"
> weather forecast --days 5 --location "London"
```

## Troubleshooting

### Plugin Loading Issues

1. Check plugin file permissions
2. Verify plugin directory path
3. Check for missing dependencies
4. Review plugin compatibility

### Common Issues

1. **Plugin not found**: Check `--plugin-dir` path and file extensions
2. **Command not recognized**: Verify plugin registration and command implementation
3. **Session errors**: Check session lifecycle and cleanup logic

## License

This template is provided under the same license as TheNodes: Apache-2.0 OR MIT.
# TheNodes Template System - Design Overview

## Summary

A comprehensive template/boilerplate system for TheNodes that allows developers to quickly create custom applications using the framework. The system supports multiple integration patterns and provides a smooth developer experience.

### 1. Template Directory Structure
```
templates/
├── README.md                     # Main documentation for using templates
├── DESIGN_OVERVIEW.md            # This document
├── generate_app.sh               # Generator script (Linux/macOS bash)
├── production/                   # Templates targeting end-user apps
│   ├── cal-app/                  # CAL: TheNodes as a library
│   ├── nep-plugin/               # NEP: Plugin crate (dynamic lib: .so/.dylib/.dll)
│   └── minimal-app/              # Minimal example
└── development/                  # Templates for framework dev/custom hosts
	└── custom-host/              # Custom plugin host with interactive prompt
```

### 2. Integration Patterns

#### CAL Pattern (production/cal-app)
- **Use Case**: Simple P2P applications, microservices, embedded use
- **Integration**: TheNodes as library dependency
- **Features**: Custom business logic, direct integration, minimal overhead
- **Example**: Chat applications, data sync, protocol implementations

#### NEP Pattern (two sides)
- **Plugin crate (production/nep-plugin)**: Build a dynamic library (.so/.dylib/.dll) implementing the Plugin trait; deploy into a host’s `plugins/` folder.
- **Custom Host (development/custom-host)**: An example host application that loads plugins at runtime and offers an interactive prompt.
	- Features: interactive commands, tab completion, trust management commands, session management, runtime extensibility.

### 3. Generator Script Features

The `generate_app.sh` script provides:
- **Template Selection**: Choose from available templates
- **Variable Substitution**: Automatic replacement of placeholders
- **Directory Management**: Smart handling of existing directories
- **Cross-Platform**: Works on Linux and macOS (Windows users can run under WSL or copy templates manually)
- **Validation**: Input validation and error handling

Usage examples:
```bash
# Basic usage
./generate_app.sh my-chat-app basic-app

# With custom settings
./generate_app.sh my-platform plugin-host-app --realm production-net --output ../projects/

# Force overwrite
./generate_app.sh test-app basic-app --force
```

## Architecture Benefits

### Developer Experience
1. **Quick Start**: Generate working project in seconds
2. **Best Practices**: Templates follow TheNodes conventions
3. **Documentation**: Comprehensive README files for each template
4. **Customization**: Easy to modify and extend

### Integration Patterns
1. **CAL (Core-as-a-Library)**: Direct integration, lower overhead
2. **NEP (Node-Embedded Plugin)**: Runtime extensibility, plugin ecosystem
3. **Template Variables**: Consistent customization across templates
4. **Configuration Management**: Proper TOML configs with all options

### Production Readiness
1. **Security**: TLS encryption with PKI support (enabled by default in production templates; mTLS recommended)
2. **Logging**: Structured JSON logs + console output
3. **Deployment**: Release builds, configuration templates
4. **Monitoring**: Status commands, audit logs

Tip: Use the included certificate helper to bootstrap test credentials:

```bash
cargo run --bin thenodes-cert -- --realm <your-realm> --copy-to-trusted
```
This writes PKI files under `pki/` and prints an SPKI fingerprint you can pin in config.

## Template Comparison

| Aspect | basic-app | plugin-host-app |
|--------|-----------|-----------------|
| **Complexity** | Low | Medium |
| **Resource Usage** | Minimal | Moderate |
| **Extensibility** | Code changes | Runtime plugins |
| **Learning Curve** | Easy | Medium |
| **Interactive Mode** | No | Yes (prompt) |
| **Plugin Support** | No | Yes (custom + TheNodes) |
| **Best For** | Simple apps | Platforms/Tools |

## Key Features

### Template System
- Variable substitution (`{{APP_NAME}}`, `{{APP_REALM}}`, etc.)
- Automatic directory structure creation
- Cross-platform generator script
- Comprehensive documentation
- Input validation and error handling

### CAL Template (basic-app)
- TheNodes library integration
- Custom business logic framework
- Network message handling
- Configuration management
- Async-first architecture

### NEP Templates
- **Plugin crate (nep-plugin)**
	- Implements the TheNodes Plugin trait
	- Compiles to a dynamic library: `.so` (Linux), `.dylib` (macOS), `.dll` (Windows)
	- Provides optional config defaults
- **Custom host (custom-host)**
	- Plugin host implementation with interactive command system
	- Tab completion for core and plugin commands
	- Trust management commands: list observed/trusted, promote observed → trusted
	- Message routing and runtime extensibility

### Developer Tools
- Generator script with options
- Help and usage documentation
- Example configurations
- Debug and troubleshooting guides

## Design Decisions

### 1. Template-Based Approach
**Choice**: Use file templates with variable substitution
**Rationale**: Simple, flexible, easy to maintain and extend
**Alternatives**: Code generation, yeoman-style generators

### 2. Multiple Integration Patterns
**Choice**: Separate templates for CAL vs NEP patterns
**Rationale**: Different use cases need different architectures
**Benefits**: Optimized for specific needs, clearer learning path

### 3. Shell Script Generator
**Choice**: Bash script instead of Rust binary
**Rationale**: Simple to use and modify
**Benefits**: Works immediately on Linux/macOS; Windows users can run via WSL or copy templates manually

### 4. Comprehensive Documentation
**Choice**: Detailed README for each template
**Rationale**: Reduces learning curve, provides guidance
**Benefits**: Self-documenting, reduces support overhead

## Future Enhancements

### Additional Templates
- **hybrid-app**: Combine CAL + NEP approaches (planned)
- **microservice-app**: Optimized for microservice deployments (planned)
- **embedded-app**: Resource-constrained environments (planned)

### Generator Improvements
- **Cargo Integration**: `cargo install thenodes-template`
- **Interactive Mode**: Prompt for configuration options
- **Template Validation**: Verify template integrity
- **Custom Templates**: Support for user-defined templates

### Developer Experience
- **Async-first**: All templates follow async-first patterns for scalability
- **Debugging Tools**: Enhanced debug output and profiling
- **Testing Framework**: Automated testing for generated apps

## Usage Recommendations

### When to Use Each Template

**Choose `basic-app` when:**
- Building a focused P2P application
- Need minimal resource usage
- Want direct control over TheNodes integration
- Don't need runtime plugin extensibility

**Choose `custom-host` (development) when:**
- Building an extensible platform or tools
- Need interactive development/debugging with tab completion
- Want to support custom plugins at runtime

### Best Practices

1. **Start Simple**: Begin with `basic-app`, upgrade to `plugin-host-app` if needed
2. **Custom Realm**: Always use a custom realm name for your network
3. **Security**: Enable encryption in production environments (default in production templates). Consider mTLS and fingerprint pinning.
4. **Documentation**: Maintain your custom documentation alongside templates
5. **Version Control**: Track template modifications for future updates

## Conclusion

This template system provides a solid foundation for developers to build custom applications with TheNodes. It offers multiple integration patterns, comprehensive documentation, and a smooth developer experience. The system is designed to grow with the project and can be easily extended with new templates and features as needed.

The templates demonstrate TheNodes best practices while providing flexibility for customization, making it easy for developers to get started while following established patterns and conventions.
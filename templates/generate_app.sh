#!/bin/bash

# TheNodes Application Template Generator
# Usage: ./generate_app.sh <app-name> <template-type> [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEMPLATE_DIR="$(dirname "$0")"
OUTPUT_DIR="../workspaces/"  # Output to workspaces directory
REALM_NAME=""
DESCRIPTION=""
FORCE=false

# Print usage
usage() {
    echo -e "${BLUE}TheNodes Application Template Generator${NC}"
    echo ""
    echo "Usage: $0 <app-name> <template-type> [options]"
    echo ""
    echo "Arguments:"
    echo "  app-name      Name of your application (e.g., 'my-chat-app')"
    echo "  template-type Available templates:"
    echo "                Production: cal-app, nep-plugin, minimal-app" 
    echo "                Development: custom-host, hybrid-app"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR        Output directory (default: ../workspaces/)"
    echo "  -r, --realm NAME        Realm name (default: derived from app-name)"
    echo "  -d, --description TEXT  Application description (default: generated)"
    echo "  -f, --force             Overwrite existing directory"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 my-chat-app cal-app"
    echo "  $0 my-plugin nep-plugin --realm production-net"
    echo "  $0 test-app cal-app --output ../projects/ --force"
    echo ""
    echo "Production templates (end-user applications):"
    echo "  cal-app        - Simple P2P app using TheNodes as library (CAL)"
    echo "  nep-plugin     - Plugin for existing TheNodes host (NEP)"
    echo "  minimal-app    - Bare minimum integration"
    echo ""
    echo "Development templates (TheNodes core development):"
    echo "  custom-host    - Custom plugin host with interactive interface"
    echo "  hybrid-app     - Combined approach (CAL + NEP)"
}

# Print colored message
log() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check if template exists
check_template() {
    local template=$1
    local template_path=""
    
    # Check production templates first
    if [ -d "$TEMPLATE_DIR/production/$template" ]; then
        template_path="production/$template"
    # Then check development templates
    elif [ -d "$TEMPLATE_DIR/development/$template" ]; then
        template_path="development/$template"
    # Finally check root level (legacy)
    elif [ -d "$TEMPLATE_DIR/$template" ]; then
        template_path="$template"
    else
        log $RED "❌ Error: Template '$template' not found"
        log $YELLOW "Available production templates:"
        find "$TEMPLATE_DIR/production" -maxdepth 1 -type d -exec basename {} \; 2>/dev/null | grep -v "^production$" | sort || true
        log $YELLOW "Available development templates:"
        find "$TEMPLATE_DIR/development" -maxdepth 1 -type d -exec basename {} \; 2>/dev/null | grep -v "^development$" | sort || true
        exit 1
    fi
    
    # Set global variable for use in process_directory
    RESOLVED_TEMPLATE_PATH="$template_path"
}

# Validate app name
validate_app_name() {
    local name=$1
    if [[ ! "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        log $RED "❌ Error: Invalid app name '$name'"
        log $YELLOW "App name must start with a letter and contain only letters, numbers, hyphens, and underscores"
        exit 1
    fi
}

# Generate default description
generate_description() {
    local app_name=$1
    local template=$2
    case "$template" in
        "basic-app")
            echo "A P2P application built with TheNodes framework"
            ;;
        "plugin-host-app")
            echo "An extensible plugin host application built with TheNodes framework"
            ;;
        "hybrid-app")
            echo "A hybrid application combining library and plugin approaches with TheNodes framework"
            ;;
        "minimal-app")
            echo "A minimal P2P application demonstrating TheNodes integration"
            ;;
        *)
            echo "A custom application built with TheNodes framework"
            ;;
    esac
}

# Replace template variables in file
replace_variables() {
    local file=$1
    local app_name=$2
    local realm_name=$3
    local description=$4
    
    # Convert app name to PascalCase for struct names
    local app_name_pascal=$(echo "$app_name" | sed 's/-\([a-z]\)/\U\1/g' | sed 's/^\([a-z]\)/\U\1/')
    
    # Use different sed syntax based on OS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/{{APP_NAME}}/$app_name/g" "$file"
        sed -i '' "s/{{APP_NAME_PASCAL}}/$app_name_pascal/g" "$file"
        sed -i '' "s/{{APP_REALM}}/$realm_name/g" "$file"
        sed -i '' "s/{{APP_DESCRIPTION}}/$description/g" "$file"
    else
        # Linux and others
        sed -i "s/{{APP_NAME}}/$app_name/g" "$file"
        sed -i "s/{{APP_NAME_PASCAL}}/$app_name_pascal/g" "$file"
        sed -i "s/{{APP_REALM}}/$realm_name/g" "$file"
        sed -i "s/{{APP_DESCRIPTION}}/$description/g" "$file"
    fi
}

# Adjust thenodes path dependency in Cargo.toml to point to the TheNodes repo root relative to output path
adjust_thenodes_path_dep() {
    local output_path=$1
    local cargo_file="$output_path/Cargo.toml"
    [ -f "$cargo_file" ] || return 0

    # Detect repo root (one level up from templates/)
    local repo_root
    repo_root=$(cd "$TEMPLATE_DIR/.." && pwd)

    # Compute relative path from output project to repo root
    local out_abs
    out_abs=$(cd "$output_path" && pwd)
    local rel
    if command -v python3 >/dev/null 2>&1; then
        rel=$(python3 - "$repo_root" "$out_abs" <<'PY'
import os, sys
repo = sys.argv[1]
outp = sys.argv[2]
print(os.path.relpath(repo, outp))
PY
)
    elif command -v realpath >/dev/null 2>&1; then
        rel=$(realpath --relative-to="$out_abs" "$repo_root")
    else
        # Fallback assumes default generator location (../workspaces/<app>) → repo root is ../..
        rel="../.."
    fi

    # Update thenodes path dep if present
    if grep -qE '^thenodes\s*=\s*\{\s*path\s*=\s*"' "$cargo_file"; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' -E "s|^thenodes\s*=\s*\{\s*path\s*=\s*\"[^\"]*\"\s*\}|thenodes = { path = \"$rel\" }|" "$cargo_file"
        else
            sed -i -E "s|^thenodes\s*=\s*\{\s*path\s*=\s*\"[^\"]*\"\s*\}|thenodes = { path = \"$rel\" }|" "$cargo_file"
        fi
    fi
}

# Process directory recursively
process_directory() {
    local src_dir=$1
    local dst_dir=$2
    local app_name=$3
    local realm_name=$4
    local description=$5
    
    for item in "$src_dir"/*; do
        if [ ! -e "$item" ]; then
            continue
        fi
        
        local basename=$(basename "$item")
        local dst_path="$dst_dir/$basename"
        
        if [ -d "$item" ]; then
            mkdir -p "$dst_path"
            process_directory "$item" "$dst_path" "$app_name" "$realm_name" "$description"
        else
            cp "$item" "$dst_path"
            # Replace variables in text files
            if file "$dst_path" | grep -q text; then
                replace_variables "$dst_path" "$app_name" "$realm_name" "$description"
            fi
        fi
    done
}

# Create directory structure
create_directories() {
    local output_path=$1
    
    # Create necessary subdirectories
    mkdir -p "$output_path/src"
    mkdir -p "$output_path/data"
    mkdir -p "$output_path/logs"
    
    # Create config-specific directories if needed
    if [ -f "$output_path/config.toml" ]; then
        # Check if config mentions PKI
        if grep -q "pki/" "$output_path/config.toml"; then
            mkdir -p "$output_path/pki/own"
            mkdir -p "$output_path/pki/trusted/certs"
            mkdir -p "$output_path/pki/observed/certs"
        fi
        
        # Check if config mentions plugins
        if grep -q "plugins" "$output_path/config.toml" || [ -d "$output_path/plugins" ]; then
            mkdir -p "$output_path/plugins"
        fi
    fi
}

# Generate project
generate_project() {
    local app_name=$1
    local template=$2
    # Normalize OUTPUT_DIR to avoid trailing slash duplication in paths
    local output_base="${OUTPUT_DIR%/}"
    local output_path="$output_base/$app_name"
    
    # Set default realm if not provided
    if [ -z "$REALM_NAME" ]; then
        REALM_NAME="${app_name}-network"
    fi
    
    # Set default description if not provided
    if [ -z "$DESCRIPTION" ]; then
        DESCRIPTION=$(generate_description "$app_name" "$template")
    fi
    
    log $BLUE "🚀 Generating TheNodes application..."
    log $YELLOW "  App Name: $app_name"
    log $YELLOW "  Template: $template"
    log $YELLOW "  Output: $output_path"
    log $YELLOW "  Realm: $REALM_NAME"
    log $YELLOW "  Description: $DESCRIPTION"
    echo
    
    # Check if output directory exists
    if [ -d "$output_path" ]; then
        if [ "$FORCE" = false ]; then
            log $RED "❌ Error: Directory '$output_path' already exists"
            log $YELLOW "Use --force to overwrite or choose a different name/output directory"
            exit 1
        else
            log $YELLOW "⚠️  Overwriting existing directory: $output_path"
            rm -rf "$output_path"
        fi
    fi
    
    # Create output directory
    mkdir -p "$output_path"
    
    # Copy and process template files
    log $BLUE "📁 Copying template files..."
    process_directory "$TEMPLATE_DIR/$RESOLVED_TEMPLATE_PATH" "$output_path" "$app_name" "$REALM_NAME" "$DESCRIPTION"

    # After processing, rename manifest templates to real Cargo manifests
    if compgen -G "$output_path/**/Cargo.toml.template" > /dev/null; then
        while IFS= read -r -d '' tmpl; do
            mv "$tmpl" "${tmpl%.template}"
        done < <(find "$output_path" -type f -name 'Cargo.toml.template' -print0)
    fi
    
    # Rename any Rust source templates (*.rs.tmpl) back to *.rs
    if compgen -G "$output_path/**/*.rs.tmpl" > /dev/null; then
        while IFS= read -r -d '' tmpl; do
            mv "$tmpl" "${tmpl%.tmpl}"
        done < <(find "$output_path" -type f -name '*.rs.tmpl' -print0)
    fi
    
    # Create additional directory structure
    log $BLUE "🏗️  Creating directory structure..."
    create_directories "$output_path"

    # Normalize thenodes path dependency relative to output location
    adjust_thenodes_path_dep "$output_path"
    
    # Make executable files executable
    if [ -f "$output_path/run.sh" ]; then
        chmod +x "$output_path/run.sh"
    fi
    
    log $GREEN "✅ Successfully generated '$app_name' from '$template' template!"
    echo
    
    # Show next steps
    log $BLUE "🎯 Next steps:"
    echo "  1. cd \"$output_path\""
    echo "  2. # Review and customize config.toml"
    echo "  3. cargo build"
    
    case "$template" in
        "basic-app")
            echo "  4. cargo run -- --config config.toml"
            ;;
        "plugin-host-app")
            echo "  4. cargo run -- --config config.toml --prompt"
            ;;
        *)
            echo "  4. cargo run -- --config config.toml"
            ;;
    esac
    
    echo
    log $YELLOW "📖 For more information, see the README.md in your new project directory."
}

# Parse command line arguments
parse_args() {
    if [ $# -eq 0 ]; then
        usage
        exit 1
    fi
    
    APP_NAME=""
    TEMPLATE_TYPE=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -r|--realm)
                REALM_NAME="$2"
                shift 2
                ;;
            -d|--description)
                DESCRIPTION="$2"
                shift 2
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -*)
                log $RED "❌ Error: Unknown option $1"
                usage
                exit 1
                ;;
            *)
                if [ -z "$APP_NAME" ]; then
                    APP_NAME="$1"
                elif [ -z "$TEMPLATE_TYPE" ]; then
                    TEMPLATE_TYPE="$1"
                else
                    log $RED "❌ Error: Too many arguments"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [ -z "$APP_NAME" ]; then
        log $RED "❌ Error: App name is required"
        usage
        exit 1
    fi
    
    if [ -z "$TEMPLATE_TYPE" ]; then
        log $RED "❌ Error: Template type is required"
        usage
        exit 1
    fi
}

# Main function
main() {
    parse_args "$@"
    
    # Validate inputs
    validate_app_name "$APP_NAME"
    check_template "$TEMPLATE_TYPE"
    
    # Check if output directory is writable
    if [ ! -w "$OUTPUT_DIR" ]; then
        log $RED "❌ Error: Output directory '$OUTPUT_DIR' is not writable"
        exit 1
    fi
    
    # Generate the project
    generate_project "$APP_NAME" "$TEMPLATE_TYPE"
}

# Run main function with all arguments
main "$@"
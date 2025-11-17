#!/bin/bash

# Enhanced Ptrace Plugin Build Script for Radare2
# Automates building and installation of the enhanced ptrace plugin

set -e  # Exit on any error

PLUGIN_NAME="io_ptrace_enhanced"
BUILD_DIR="$(pwd)"
LOGFILE="build.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOGFILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOGFILE"
}

# Check if running on Android/Termux
check_environment() {
    log "Checking environment..."

    if [ -n "$TERMUX_VERSION" ]; then
        log "Detected Termux environment"
        TERMUX_ENV=true
    else
        log "Non-Termux environment detected"
        TERMUX_ENV=false
    fi

    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        log "Running as root - good for testing memory access"
    else
        warn "Not running as root - may have permission issues with ptrace"
    fi
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."

    # Check for radare2
    if ! command -v r2 &> /dev/null; then
        error "radare2 not found. Please install radare2 first."
        exit 1
    fi

    R2_VERSION=$(r2 -v | head -n1)
    log "Found: $R2_VERSION"

    # Check for build tools
    for tool in gcc make pkg-config; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool not found. Please install build-essential package."
            exit 1
        fi
    done

    # Check for r2 development headers
    if ! pkg-config --exists r_io; then
        error "radare2 development headers not found."
        if [ "$TERMUX_ENV" = true ]; then
            error "Try: pkg install radare2-dev"
        else
            error "Install radare2 development package"
        fi
        exit 1
    fi

    log "All dependencies satisfied"
}

# Build the plugin
build_plugin() {
    log "Building plugin..."

    # Clean previous builds
    make clean &>/dev/null || true

    # Build with verbose output
    if make 2>&1 | tee -a "$LOGFILE"; then
        log "Plugin built successfully"
    else
        error "Build failed. Check $LOGFILE for details."
        exit 1
    fi

    # Check if plugin file exists
    PLUGIN_FILE=$(find . -name "${PLUGIN_NAME}.*" | head -n1)
    if [ -z "$PLUGIN_FILE" ]; then
        error "Plugin binary not found after build"
        exit 1
    fi

    log "Plugin binary: $PLUGIN_FILE"
}

# Install the plugin
install_plugin() {
    log "Installing plugin..."

    # Get user plugin directory
    R2_USER_PLUGINS=$(r2 -HR2_USER_PLUGINS 2>/dev/null || echo "$HOME/.local/share/radare2/plugins")

    if [ -z "$R2_USER_PLUGINS" ]; then
        error "Could not determine r2 user plugins directory"
        exit 1
    fi

    log "Plugin directory: $R2_USER_PLUGINS"

    # Create directory if it doesn't exist
    mkdir -p "$R2_USER_PLUGINS"

    # Install plugin
    if make install 2>&1 | tee -a "$LOGFILE"; then
        log "Plugin installed successfully"
    else
        error "Installation failed"
        exit 1
    fi
}

# Test the plugin
test_plugin() {
    log "Testing plugin installation..."

    # Check if plugin appears in r2 listing
    if r2 -L 2>/dev/null | grep -q ptrace_enhanced; then
        log "Plugin successfully loaded by radare2"
    else
        warn "Plugin not found in r2 -L output"
        warn "This might be normal - plugin may load dynamically"
    fi

    # Test basic functionality
    log "Testing basic functionality..."

    # Try to access self process (should work without root)
    SELF_PID=$$
    if timeout 5 r2 -q -c 'q' "ptrace://$SELF_PID" 2>/dev/null; then
        log "Basic ptrace access test passed"
    else
        warn "Basic ptrace test failed - may need root for other processes"
    fi
}

# Main installation flow
main() {
    log "=== Enhanced Ptrace Plugin Build Script ==="
    log "Build directory: $BUILD_DIR"

    check_environment
    check_dependencies
    build_plugin
    install_plugin
    test_plugin

    log "=== Installation Complete ==="
    log ""
    log "Usage:"
    log "  r2 ptrace://PID    # Attach to process"
    log "  =!scan hex PATTERN # Search memory"
    log "  =!dump ADDR SIZE   # Dump memory"
    log ""
    log "Note: Root privileges required for most processes"

    if [ "$EUID" -ne 0 ]; then
        warn "Run as root (su) for full functionality"
    fi
}

# Cleanup on exit
cleanup() {
    if [ -f "$LOGFILE" ]; then
        log "Build log saved to: $LOGFILE"
    fi
}

trap cleanup EXIT

# Run main function
main "$@"

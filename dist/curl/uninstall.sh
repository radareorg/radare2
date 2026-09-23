#!/usr/bin/env sh

set -e

INSTALL_DIR="$HOME/.local/src/radare2"

if [ -d "$INSTALL_DIR" ]; then
    echo "Removing radare2 installation..."
    cd "$INSTALL_DIR"
    # Run the official uninstall script to remove binaries/libs
    ./sys/user-uninstall.sh
    cd -
    # Remove the source directory
    rm -rf "$INSTALL_DIR"
    echo "radare2 has been successfully uninstalled."
else
    echo "radare2 source directory not found in $INSTALL_DIR."
    echo "If you already deleted the source, you may need to manually remove binaries from $HOME/.local/bin and libs from $HOME/.local/lib."
fi

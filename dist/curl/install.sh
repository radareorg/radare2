#!/usr/bin/env sh

set -e

# Default installation path
INSTALL_DIR="$HOME/.local/src/radare2"

if [ ! -d "$INSTALL_DIR" ]; then
    echo "Cloning radare2..."
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --depth=1 https://github.com/radareorg/radare2 "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
./sys/user.sh

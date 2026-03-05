#!/usr/bin/env bash
set -euo pipefail

plugins="${1:-}"
if [ -z "${plugins}" ]; then
	exit 0
fi

if ! command -v r2pm >/dev/null 2>&1; then
	echo "r2pm is not available in PATH" >&2
	exit 1
fi

export HOME=/root
r2pm -U

for plugin in ${plugins}; do
	echo "Installing r2pm plugin: ${plugin}"
	r2pm -ci "${plugin}"
done

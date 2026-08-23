#!/bin/sh
# thin wrapper for compatibility: all the lint checks live in sys/lint.py
exec python3 "$(dirname "$0")/lint.py" "$@"

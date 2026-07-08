"""
Main entry point for radare2 MCP Server when run as a module.

Usage:
    python -m libr.mcp --stdio
    python -m libr.mcp --sse --port 8080
"""

from .server import main

if __name__ == "__main__":
    main()

"""
MCP Server for radare2

This module implements the MCP (Model Context Protocol) Server that exposes
radare2's reverse engineering capabilities to AI Agents.

Usage:
    # Start as standalone server with stdio transport:
    python -m libr.mcp.server --stdio

    # Or with SSE transport:
    python -m libr.mcp.server --sse --port 8080
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any, Dict

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.server.sse import SseServerTransport
    from mcp.types import Tool, TextContent
except ImportError:
    print("Error: MCP SDK not installed. Run: pip install mcp")
    sys.exit(1)

# Import radare2 MCP tools
try:
    from . import tools as r2_tools
except ImportError:
    # Fallback for standalone execution
    import tools as r2_tools


class Radare2MCPServer:
    """
    radare2 MCP Server implementation.

    This server exposes radare2's reverse engineering capabilities
    to AI Agents via the Model Context Protocol.
    """

    def __init__(self, name: str = "radare2-mcp-server"):
        """
        Initialize the MCP Server.

        Args:
            name: Server name for identification
        """
        self.server = Server(name)
        self._setup_handlers()

    def _setup_handlers(self):
        """Set up MCP protocol handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available radare2 tools."""
            tools = []
            for name, tool_info in r2_tools.TOOLS.items():
                tools.append(
                    Tool(
                        name=name,
                        description=tool_info["description"],
                        inputSchema=tool_info["parameters"],
                    )
                )
            return tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> list[TextContent]:
            """Call a radare2 tool with the given arguments."""
            if name not in r2_tools.TOOLS:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps({"error": f"Unknown tool: {name}"})
                    )
                ]

            tool_func = r2_tools.TOOLS[name]["function"]

            try:
                # Call the tool function with arguments
                result = tool_func(**arguments)

                # Return result as JSON text
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(result, indent=2)
                    )
                ]
            except Exception as e:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps({"error": str(e)})
                    )
                ]

    async def run_stdio(self):
        """Run the MCP Server using stdio transport."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream)

    async def run_sse(self, host: str = "0.0.0.0", port: int = 8080):
        """
        Run the MCP Server using SSE transport.

        Args:
            host: Host to bind to (default: 0.0.0.0)
            port: Port to listen on (default: 8080)
        """
        try:
            from starlette.applications import Starlette
            from starlette.routing import Route
            import uvicorn

            sse = SseServerTransport("/messages/")

            async def handle_sse(request):
                async with sse.connect_sse(
                    request.scope,
                    request.receive,
                    request._send,
                ) as streams:
                    await self.server.run(
                        streams[0], streams[1], self.server.create_initialization_options()
                    )

            async def handle_messages(request):
                await sse.handle_post_message(
                    request.scope,
                    request.receive,
                    request._send,
                )

            app = Starlette(
                routes=[
                    Route("/sse", endpoint=handle_sse),
                    Route("/messages/", endpoint=handle_messages, methods=["POST"]),
                ]
            )

            config = uvicorn.Config(app, host=host, port=port, log_level="info")
            server = uvicorn.Server(config)
            await server.serve()

        except ImportError as e:
            print(f"Error: SSE transport requires additional dependencies: {e}")
            print("Install with: pip install uvicorn starlette")
            sys.exit(1)


async def run_stdio_server():
    """Run the MCP Server using stdio transport."""
    server = Radare2MCPServer()
    await server.run_stdio()


async def run_sse_server(host: str = "0.0.0.0", port: int = 8080):
    """Run the MCP Server using SSE transport."""
    server = Radare2MCPServer()
    await server.run_sse(host, port)


def main():
    """Main entry point for the MCP Server."""
    parser = argparse.ArgumentParser(description="radare2 MCP Server")
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Use stdio transport (default)",
    )
    parser.add_argument(
        "--sse",
        action="store_true",
        help="Use SSE transport",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to for SSE transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on for SSE transport (default: 8080)",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List available tools and exit",
    )

    args = parser.parse_args()

    if args.list_tools:
        print("Available radare2 MCP tools:")
        for name, tool_info in r2_tools.TOOLS.items():
            print(f"  - {name}: {tool_info['description']}")
        return

    # Default to stdio transport
    if args.sse:
        asyncio.run(run_sse_server(args.host, args.port))
    else:
        asyncio.run(run_stdio_server())


if __name__ == "__main__":
    main()

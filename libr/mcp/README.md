# radare2 MCP Server

Model Context Protocol (MCP) Server implementation for radare2, exposing reverse engineering capabilities to AI Agents.

## Features

- **Binary Analysis**: Load and analyze binary files with full radare2 analysis
- **Disassembly**: Disassemble code at any address with detailed instruction information
- **Decompilation**: Attempt decompilation of functions (when supported)
- **Function Discovery**: List all functions with metadata (size, complexity, arguments)
- **String Search**: Find all strings in the binary with location information
- **Cross References**: Trace data and code flow with xref analysis
- **Memory Inspection**: Read and inspect memory contents in hex and ASCII
- **Binary Patching**: Modify binary bytes at specific addresses

## Installation

### Prerequisites

1. **radare2**: Install radare2 from https://rada.re/n/
   ```bash
   # macOS
   brew install radare2
   
   # Linux (Debian/Ubuntu)
   sudo apt install radare2
   
   # Windows
   # Download from https://github.com/radareorg/radare2/releases
   ```

2. **Python 3.8+**: Ensure you have Python 3.8 or higher

### Install Dependencies

```bash
# Install r2pipe (Python bindings for radare2)
pip install r2pipe

# Install MCP SDK
pip install mcp

# Optional: For SSE transport
pip install uvicorn starlette
```

### Install radare2 MCP Server

```bash
# Clone the repository
git clone https://github.com/radareorg/radare2.git
cd radare2

# The MCP server is located in libr/mcp/
cd libr/mcp
```

## Usage

### Starting the Server

#### stdio Transport (Default)

```bash
python -m libr.mcp.server --stdio
```

#### SSE Transport

```bash
python -m libr.mcp.server --sse --host 0.0.0.0 --port 8080
```

#### List Available Tools

```bash
python -m libr.mcp.server --list-tools
```

### Available Tools

1. **load_binary**: Load a binary file for analysis
   - Parameters: `filepath` (string)
   - Returns: Success/failure status

2. **get_binary_info**: Get binary information (architecture, entry point, sections)
   - Parameters: none
   - Returns: BinaryInfo object

3. **analyze_all**: Perform full binary analysis (aaa command)
   - Parameters: none
   - Returns: Analysis status

4. **list_functions**: List all functions in the binary
   - Parameters: none
   - Returns: List of Function objects

5. **disassemble**: Disassemble instructions at an address
   - Parameters: `address` (int), `count` (int, default: 10)
   - Returns: List of DisassemblyLine objects

6. **decompile**: Decompile a function (if supported)
   - Parameters: `address` (int)
   - Returns: Decompiled code string

7. **search_strings**: Search for strings in the binary
   - Parameters: `min_length` (int, default: 4)
   - Returns: List of StringEntry objects

8. **get_xrefs**: Get cross references to/from an address
   - Parameters: `address` (int)
   - Returns: List of XRef objects

9. **read_memory**: Read memory at an address
   - Parameters: `address` (int), `size` (int, default: 64)
   - Returns: MemoryContent with hex and ASCII

10. **patch_binary**: Patch binary at an address
    - Parameters: `address` (int), `bytes_hex` (string)
    - Returns: PatchResult with old/new bytes

## AI Agent Integration

### Example: Claude Desktop Configuration

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "radare2": {
      "command": "python",
      "args": [
        "-m",
        "libr.mcp.server",
        "--stdio"
      ],
      "env": {
        "PYTHONPATH": "/path/to/radare2"
      }
    }
  }
}
```

### Example: Python Client

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def analyze_binary():
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "libr.mcp.server", "--stdio"],
        env={"PYTHONPATH": "/path/to/radare2"}
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Load a binary
            result = await session.call_tool(
                "load_binary",
                {"filepath": "/path/to/binary"}
            )
            print("Load result:", result)
            
            # Analyze the binary
            result = await session.call_tool("analyze_all", {})
            print("Analysis:", result)
            
            # Get binary info
            result = await session.call_tool("get_binary_info", {})
            print("Binary info:", result)
            
            # List functions
            result = await session.call_tool("list_functions", {})
            print("Functions:", result)
            
            # Disassemble main function
            result = await session.call_tool(
                "disassemble",
                {"address": 0x401000, "count": 20}
            )
            print("Disassembly:", result)

asyncio.run(analyze_binary())
```

### Example: Common Reverse Engineering Workflow

```python
# 1. Load binary
load_binary("/path/to/suspicious_binary")

# 2. Get basic info
info = get_binary_info()
print(f"Architecture: {info['arch']}, Bits: {info['bits']}")

# 3. Perform full analysis
analyze_all()

# 4. List all functions
functions = list_functions()
for func in functions['functions']:
    print(f"{func['name']} at {func['address']} (size: {func['size']})")

# 5. Search for interesting strings
strings = search_strings(min_length=8)
for s in strings['strings']:
    if "password" in s['string'].lower():
        print(f"Found: {s['string']} at {s['address']}")

# 6. Disassemble suspicious function
disasm = disassemble(address=0x401000, count=50)

# 7. Get cross references to a function
xrefs = get_xrefs(address=0x401000)
print(f"Called from {len(xrefs['xrefs'])} locations")

# 8. Read memory at specific address
mem = read_memory(address=0x402000, size=128)
print(f"Hex: {mem['hex']}")
print(f"ASCII: {mem['ascii']}")
```

## Data Models

### BinaryInfo
```json
{
  "arch": "x86",
  "bits": 64,
  "endian": "little",
  "os": "linux",
  "type": "EXEC",
  "machine": "AMD64",
  "entry": "0x400000",
  "sections": [
    {
      "name": ".text",
      "vaddr": "0x401000",
      "vsize": 4096,
      "paddr": "0x1000",
      "size": 4096,
      "flags": "r-x",
      "perm": "r-x"
    }
  ]
}
```

### Function
```json
{
  "address": "0x401000",
  "name": "main",
  "size": 100,
  "ninstrs": 25,
  "cc": 5,
  "nbbs": 3,
  "edges": 4,
  "calltype": "cdecl",
  "args": 2
}
```

### DisassemblyLine
```json
{
  "address": "0x401000",
  "opcode": "push rbp",
  "mnemonic": "push",
  "operands": "rbp",
  "size": 1,
  "type": "store",
  "family": "cpu"
}
```

### XRef
```json
{
  "source": "0x401050",
  "target": "0x401000",
  "type": "CALL",
  "name": "main"
}
```

## Testing

Run the test suite:

```bash
# Install pytest
pip install pytest

# Run tests
pytest libr/mcp/tests/test_mcp_server.py -v
```

## Architecture

The MCP Server is structured as follows:

```
libr/mcp/
├── __init__.py       # Package initialization
├── server.py         # MCP Server implementation
├── tools.py          # Tool implementations using r2pipe
├── models.py         # Data models (BinaryInfo, Function, etc.)
└── tests/
    └── test_mcp_server.py  # Unit tests
```

### Key Components

- **server.py**: Implements the MCP protocol handlers and transport layers
- **tools.py**: Wraps radare2 commands via r2pipe, returns structured JSON
- **models.py**: Defines data structures for consistent output format
- **r2pipe**: Python bindings that communicate with radare2 processes

## Troubleshooting

### radare2 not found
Ensure radare2 is installed and in your PATH:
```bash
r2 -v
```

### r2pipe import error
Install r2pipe:
```bash
pip install r2pipe
```

### MCP SDK not installed
Install the MCP SDK:
```bash
pip install mcp
```

### Analysis is slow
The `analyze_all` tool runs `aaa` which can be slow for large binaries. Consider:
- Using `aa` for basic analysis instead
- Analyzing specific functions with `af @ address`

### Decompilation not available
The `decompile` tool uses radare2's pseudo-decompiler (`pdc`). For better decompilation:
- Install r2dec: `r2 -i r2dec`
- Use Cutter (radare2's GUI) with Ghidra decompiler

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This MCP Server is part of radare2 and follows the same license. See the main radare2 repository for license details.

## Resources

- [radare2 Documentation](https://radare.git.book/)
- [r2pipe Python Documentation](https://github.com/radareorg/radare2-r2pipe)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [radare2 Book](https://www.gitbook.com/book/radare/radare2-book)

## Support

For issues and questions:
- radare2 GitHub Issues: https://github.com/radareorg/radare2/issues
- radare2 Discord: https://discord.gg/r2
- MCP Documentation: https://modelcontextprotocol.io/

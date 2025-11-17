# Radare2 Enhanced Ptrace IO Plugin for Android

This plugin provides enhanced process memory access capabilities for radare2 on Android, specifically designed for game hacking and reverse engineering. It's based on the original Memscan.c code and integrates advanced memory scanning features into radare2's IO system.

## Features

- **Advanced Memory Access**: Uses `process_vm_readv`/`process_vm_writev` for efficient process memory access
- **Pattern Scanning**: Search for hex patterns and ASCII strings in process memory
- **Memory Dumping**: Dump specific memory regions to files
- **DEX File Detection**: Locate and extract DEX files from Android app memory
- **Module Analysis**: Get base addresses and analyze loaded modules
- **String Extraction**: Extract printable strings from memory regions
- **Root/Termux Compatible**: Works in Termux with proper root permissions

## Requirements

- Radare2 installed on Android (via Termux or native build)
- Root access for process memory access
- Target process PID
- Build tools: `gcc`, `pkg-config`, `make`

## Installation

### 1. Clone or Copy Files

Copy the plugin files to your development directory:
```bash
# Create plugin directory
mkdir -p r2-ptrace-enhanced
cd r2-ptrace-enhanced

# Copy the files:
# - io_ptrace_enhanced.c
# - memscan_helpers.c  
# - Makefile
```

### 2. Build the Plugin

```bash
# Ensure radare2 development headers are available
pkg-config --cflags r_io

# Build the plugin
make

# Install to user plugin directory
make install
```

### 3. Verify Installation

```bash
# Check if plugin is loaded
r2 -L | grep ptrace_enhanced

# Should show:
# rw_ ptrace_enhanced Enhanced ptrace with process_vm_readv for Android game hacking (MIT)
```

## Usage

### Basic Memory Access

```bash
# Attach to a process by PID
r2 ptrace://1234

# Navigate memory
s 0x12345678
px 256

# Read/write memory
wx 41414141 @ 0x12345678
```

### Enhanced Commands

The plugin provides additional system commands accessible via `=!`:

#### Pattern Scanning
```bash
# Search for hex pattern
=!scan hex 41424344

# Search for ASCII string  
=!scan ascii "password"
```

#### Memory Dumping
```bash
# Dump memory range to file
=!dump 0x12345000 0x12346000 /data/local/tmp/dump.bin
```

#### DEX File Analysis
```bash
# Scan and extract DEX files
=!dex /data/local/tmp/dex_dump/
```

#### String Extraction
```bash  
# Extract strings from loaded modules
=!strings libnative.so
```

### Termux Usage Example

```bash
# In Termux as root
su

# Find target process
ps aux | grep com.game.example

# Attach radare2
r2 ptrace://12345

# Analyze binary
aaa

# Search for specific patterns
=!scan hex "48656c6c6f"  # "Hello" in hex

# Dump interesting memory regions  
=!dump 0x7f123456000 0x7f123457000 /data/local/tmp/game_dump.bin
```

## Architecture

### IO Plugin Structure

The plugin follows radare2's IO plugin architecture:

- **URI Handler**: `ptrace://PID` 
- **Read/Write**: Direct memory access via `process_vm_readv/writev`
- **Seek**: Virtual address space navigation
- **System Commands**: Enhanced memory operations

### Key Components

1. **EnhancedPtraceData**: Maintains process context and buffers
2. **Memory Region Parsing**: Reads `/proc/PID/maps` for memory layout
3. **Pattern Scanning**: Efficient memory search algorithms  
4. **DEX Processing**: Android-specific DEX file handling
5. **Error Handling**: Graceful permission and process state management

## Troubleshooting

### Permission Denied
```bash
# Ensure running as root
su

# Check SELinux status
getenforce

# May need to set permissive mode
setenforce 0
```

### Process Not Found
```bash
# Verify process is running
ps aux | grep PID

# Check process permissions
ls -la /proc/PID/
```

### Plugin Not Loading
```bash
# Check radare2 plugin directory
r2 -HR2_USER_PLUGINS

# Verify library extension
r2 -HR2_LIBEXT

# Reinstall plugin
make clean && make && make install
```

## Development

### Extending the Plugin

1. **Add New Commands**: Modify `__system` function in `io_ptrace_enhanced.c`
2. **Enhance Memory Operations**: Extend functions in `memscan_helpers.c`  
3. **Add File Format Support**: Implement new scanning algorithms

### Building from Source

```bash
# Development build with debug info
CFLAGS="-g -DDEBUG" make

# Clean build
make clean && make
```

### Testing

```bash
# Test plugin functionality
make test

# Manual testing with sample process
r2 ptrace://self
```

## Security Considerations

- Requires root privileges for memory access
- Only works on processes with appropriate permissions
- May trigger anti-debugging detection in some applications
- Use responsibly and only on applications you own or have permission to analyze

## License

MIT License - Based on original Memscan.c implementation

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality  
4. Submit pull request with detailed description

## Changelog

### v1.0.0
- Initial release with basic ptrace enhancement
- Pattern scanning support
- Memory dumping functionality
- DEX file detection
- Module analysis tools

---

**Note**: This plugin is designed for legitimate reverse engineering and security research. Ensure you comply with applicable laws and terms of service when analyzing applications.

# XPS Quick Start Guide

## Understanding the Build System

The XPS system uses **Make to discover and aggregate plugins**, then **Meson/Make to build radare2**.

**Important**: Always run `make -C libr/xps` after modifying external plugins - this generates the aggregation files.

## For Users: Building radare2 with r2hermes

### Complete Workflow

```bash
# 1. Clone radare2
git clone https://github.com/radareorg/radare2.git
cd radare2

# 2. Clone r2hermes plugin
git clone https://github.com/radareorg/r2hermes libr/xps/p/r2hermes
cd libr/xps/p/r2hermes && git checkout r2p && cd ../../../..

# 3. Enable the plugin in config.mk
echo "EXTERNAL_PLUGINS+=r2hermes" >> libr/xps/config.mk

# 4. IMPORTANT: Generate aggregation files from plugin definitions
make -C libr/xps

# 5a. Build with Make
./configure
make -j
sudo make install

# OR 5b. Build with Meson
meson setup builddir
meson compile -C builddir
sudo meson install -C builddir

# 6. Verify plugin loaded
r2 -c 'Lc~hbc' /path/to/hermes_bytecode_file
```

### Key Step: `make -C libr/xps`

This command reads your `config.mk` and generates integration files:
- `p/meson.build` - Meson subdirectory list
- `static.cfg` - Aggregated plugin types
- `deps.mk` - Aggregated Make dependencies
- `r2plugins.h` - Aggregated plugin declarations

**Do NOT manually edit these files - they will be overwritten.**

## For Developers: Adding Your Own External Plugin

### Plugin Structure (In Your Repository)

In your plugin repository, provide this structure under `r2plugin/`:

```
your_plugin/
├── r2plugin/
│   ├── static.cfg              # REQUIRED: Plugin type declarations
│   ├── meson.build             # REQUIRED: Meson integration
│   ├── core/                   # (if providing core plugin)
│   │   ├── deps.h              # REQUIRED: Extern declarations
│   │   ├── deps.mk             # REQUIRED: Make dependencies
│   │   └── meson.build         # REQUIRED: Meson config (optional if no type-specific logic)
│   ├── asm/                    # (if providing asm plugin)
│   │   ├── deps.h
│   │   ├── deps.mk
│   │   └── meson.build
│   └── ... other types ...
├── include/                    # Your plugin's public headers
├── src/                        # Your plugin's implementation
└── README.md
```

### Step 1: Create r2plugin/static.cfg

This declares which plugin types your plugin provides. The Make system aggregates these into `libr/xps/static.cfg`.

```
core.your_plugin
asm.your_plugin
arch.your_plugin
```

**Format**: `<type>.<plugin_name>` - one per line

Valid types: `core`, `asm`, `arch`, `bin`, `anal`, `debug`, `lang`, `esil`, `bp`, `bp_hw`, `egg`, `fs`, `io`, `search`, `syscall`, `format`, etc.

### Step 2: Create r2plugin/meson.build

This integrates your sources into Meson. All paths are relative to the r2plugin/ directory.

```meson
# r2plugin/meson.build - REQUIRED FOR MESON BUILD

# Ensure variables exist (initialized by libr/xps/meson.build)
if not is_variable('r_core_additional_inc')
  r_core_additional_inc = []
endif
if not is_variable('r_core_additional_sources')
  r_core_additional_sources = []
endif

# Add your plugin's include directories
include_dirs = include_directories('../include', is_system: false)
r_core_additional_inc += include_dirs

# Add all your plugin's source files
plugin_sources = files(
  '../src/plugin_core.c',
  '../src/plugin_util.c',
  # ... more files ...
)

r_core_additional_sources += plugin_sources
```

### Step 3: For Each Type, Create Type Directories

For each type you declared in `static.cfg`, create `<type>/` with these files:

#### `<type>/deps.h` (REQUIRED FOR MAKE)

Declares your plugin's extern symbols. Make aggregates these into `r2plugins.h`.

```c
// core/deps.h
#ifdef R2_CORE_H
extern RCorePlugin r_core_plugin_your_plugin;
#endif
```

```c
// asm/deps.h
#ifdef R_ASM_H
extern RAsmPlugin r_asm_plugin_your_plugin;
#endif
```

#### `<type>/deps.mk` (REQUIRED FOR MAKE)

Makefile that defines compiler flags, linker paths, and object files.

```makefile
# core/deps.mk - REQUIRED FOR MAKE BUILD
YOUR_PLUGIN_WD=$(LIBR)/xps/p/your_plugin
CFLAGS+=-I$(YOUR_PLUGIN_WD)/include
YOUR_PLUGIN_OBJ=$(YOUR_PLUGIN_WD)/src/plugin_core.o
YOUR_PLUGIN_LIB=$(YOUR_PLUGIN_WD)/build/libyourplugin.a
LDFLAGS+=$(YOUR_PLUGIN_LIB)
EXTERNAL_STATIC_OBJS+=$(YOUR_PLUGIN_OBJ)
```

**Key Variables**:
- `$(LIBR)` - libr/ directory path
- `CFLAGS+=` - Add compiler flags
- `LDFLAGS+=` - Add linker flags
- `EXTERNAL_STATIC_OBJS+=` - Add objects to link

#### `<type>/meson.build` (OPTIONAL)

Type-specific Meson config if you have type-specific sources:

```meson
# asm/meson.build - only if you have asm-specific sources
asm_sources = files('../src/asm_plugin.c')
r_core_additional_sources += asm_sources
```

### Step 4: Integrate into radare2

```bash
# Clone your plugin into libr/xps/p/
cd radare2
git clone https://github.com/yourorg/your_plugin libr/xps/p/your_plugin

# Enable it in config.mk
echo "EXTERNAL_PLUGINS+=your_plugin" >> libr/xps/config.mk

# Generate aggregation files
make -C libr/xps

# Build radare2
./configure && make -j
```

### Do NOT Manually Edit Generated Files

After `make -C libr/xps`, these files are auto-generated - **NEVER** edit them:
- `libr/xps/p/meson.build` - Lists all plugins' r2plugin/ directories
- `libr/xps/static.cfg` - Aggregated plugin types
- `libr/xps/deps.mk` - Aggregated Make dependencies
- `libr/xps/r2plugins.h` - Aggregated extern declarations

If you modify your plugin, just run `make -C libr/xps` again to regenerate them.

## Debugging the Build

### Meson: Check If Plugin Sources Are Included

```bash
# Look for your plugin files in compile_commands.json
grep "your_plugin" builddir/compile_commands.json

# Should see your source files being compiled:
# "../libr/xps/p/your_plugin/src/plugin_core.c"
```

### Meson: Verify Include Paths

```bash
# Look for -I flags pointing to your plugin includes
grep -o "\-I[^ ]*your_plugin[^ ]*" builddir/compile_commands.json
```

### Make: Check Generated Files

```bash
# After running make -C libr/xps, check these files:
cat libr/xps/static.cfg       # Should list your plugin types
cat libr/xps/deps.mk          # Should include your deps.mk
cat libr/xps/r2plugins.h      # Should include your plugin's deps.h
```

### Common Issues

**Meson: "file not found" errors**
- Paths in meson.build must be relative to the meson.build file location
- Use `../../../` to go up directories, not absolute paths

**Meson: "variable not found" errors**
- Always check if `r_core_additional_inc` and `r_core_additional_sources` exist before appending
- See Step 3 example above

**Make: "undefined reference" linker errors**
- Ensure `deps.h` declares all plugin extern symbols
- Verify `deps.mk` includes all object files and static libraries

**Plugin not loading at runtime**
- Check `r2 -c 'Lc~plugin_name'` to verify plugin is registered
- Check `r2 -c 'e asm.plugins'` (or other type) to list available plugins
- Verify plugin type name matches what you declared

## File Organization

Keep this structure for easy integration:

```
your_plugin/
├── README.md                    # Setup instructions
├── Makefile                     # Build your library/tools
├── meson.build                  # Standalone build
├── r2plugin/
│   ├── README.md                # How to integrate with r2
│   ├── meson.build              # Meson integration
│   ├── static.cfg               # Plugin types
│   ├── config.mk                # Make integration
│   └── core/
│       ├── meson.build
│       ├── deps.mk
│       └── deps.h
├── include/hbc/                 # Public headers
└── src/                         # Implementation
```

## Tips

1. **Keep libraries separate**: Build your plugin's library (e.g., `libhbc.a`) independently, then link it into r_core via meson.build
2. **Use relative paths**: All paths in Meson and Make should be relative, not absolute
3. **Version management**: Consider generating version headers at build time using configure_file() in Meson
4. **Test both systems**: Ensure your plugin builds with both Make and Meson before releasing
5. **Document paths**: In your meson.build and deps.mk files, add comments explaining path assumptions

## References

- XPS Documentation: [README.md](README.md)
- Known Issues: [BUGS.md](BUGS.md)
- Implementation Fixes: [FIXES.md](FIXES.md)
- r2hermes Example: https://github.com/radareorg/r2hermes
- radare2 Main Repository: https://github.com/radareorg/radare2


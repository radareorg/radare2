# XPS (eXternal PluginS) - Complete Integration Guide

This document explains how to integrate external radare2 plugins into the main radare2 build using the XPS system. External plugins are compiled and linked statically into radare2, making them available without runtime plugin loading.

## Overview

The XPS system allows third-party plugin repositories to be built as part of radare2. The plugin sources are compiled directly into `libr_core` (and other relevant libraries), and the plugins are registered in the static plugin arrays.

### Supported Plugin Types

- `core` - Core plugins (commands, UI extensions)
- `arch` - Architecture plugins (disassembly/analysis)
- `bin` - Binary format plugins (file parsing)
- `asm` - Assembler plugins
- `anal` - Analysis plugins
- `io` - I/O plugins
- `debug` - Debugger plugins
- `lang` - Language bindings
- `esil` - ESIL plugins
- `bp` - Breakpoint plugins
- `egg` - Shellcode/egg plugins
- `fs` - Filesystem plugins

## Build System Support

XPS supports both Make and Meson build systems:

| Build System | Plugin Discovery | Config Generation | Build Integration |
|--------------|------------------|-------------------|-------------------|
| **Make** | `config.mk` + `make -C libr/xps` | Auto-generates `r2plugins.h`, `deps.mk`, `static.cfg`, `p/meson.build` | Includes deps.mk in core Makefile |
| **Meson** | Uses generated `p/meson.build` | Uses `r2plugins.h.in` template | Appends to `r_core_additional_sources` and `core_plugins` |

**Important**: Always run `make -C libr/xps` before building with either system. This generates the integration files that both build systems use.

## Directory Structure

```
radare2/
└── libr/
    └── xps/
        ├── Makefile              # Generates integration files
        ├── meson.build           # Meson integration entry point
        ├── config.mk             # USER: List of enabled plugins
        ├── config.mk.example     # Template for config.mk
        ├── r2plugins.h.in        # Template for extern declarations (Meson)
        ├── r2plugins.h           # AUTO-GENERATED (Make) - extern declarations
        ├── deps.mk               # AUTO-GENERATED - aggregated Make dependencies
        ├── static.cfg            # AUTO-GENERATED - aggregated plugin types
        └── p/
            ├── meson.build       # AUTO-GENERATED - lists plugin subdirs
            └── <plugin>/         # Your plugin repository
                ├── r2plugin/
                │   ├── meson.build    # REQUIRED: Meson integration
                │   ├── static.cfg     # REQUIRED: Plugin type declarations
                │   ├── config.mk      # OPTIONAL: Make config with clone rules
                │   ├── r2plugins.h    # OPTIONAL: Aggregated deps.h includes
                │   └── <type>/        # One directory per plugin type
                │       ├── deps.h     # REQUIRED: extern declarations
                │       └── deps.mk    # REQUIRED: Make dependencies
                ├── include/           # Plugin headers
                └── src/               # Plugin sources
```

## Step-by-Step: Creating an External Plugin

### Step 1: Create the Plugin Repository Structure

Your plugin repository should have this structure:

```
my_plugin/
├── r2plugin/
│   ├── meson.build
│   ├── static.cfg
│   ├── config.mk
│   └── core/           # (or arch/, bin/, etc.)
│       ├── deps.h
│       └── deps.mk
├── include/
│   └── my_plugin/
│       └── my_plugin.h
└── src/
    └── my_plugin.c
```

### Step 2: Define Plugin Types (static.cfg)

Create `r2plugin/static.cfg` listing the plugin types your plugin provides:

```
core.my_plugin
```

For multiple types:
```
core.my_plugin
arch.my_plugin
bin.my_plugin
```

Format: `<type>.<name>` - one per line.

### Step 3: Create Extern Declarations (deps.h)

For each plugin type, create `r2plugin/<type>/deps.h`:

**`r2plugin/core/deps.h`:**
```c
#ifdef R2_CORE_H
extern RCorePlugin r_core_plugin_my_plugin;
#endif
```

**`r2plugin/arch/deps.h`:**
```c
#ifdef R2_ARCH_H
extern RArchPlugin r_arch_plugin_my_plugin;
#endif
```

**`r2plugin/bin/deps.h`:**
```c
#ifdef R2_BIN_H
extern RBinPlugin r_bin_plugin_my_plugin;
#endif
```

The `#ifdef` guards ensure the declaration only appears when the appropriate radare2 header is included.

### Step 4: Create Make Dependencies (deps.mk)

For each plugin type, create `r2plugin/<type>/deps.mk`:

**`r2plugin/core/deps.mk`:**
```makefile
MY_PLUGIN_WD=$(LIBR)/xps/p/my_plugin
CFLAGS+=-I$(MY_PLUGIN_WD)/include
MY_PLUGIN_OBJ=$(MY_PLUGIN_WD)/src/my_plugin.o
MY_PLUGIN_LIB=$(MY_PLUGIN_WD)/build/libmy_plugin.a
LDFLAGS+=$(MY_PLUGIN_LIB)
EXTERNAL_STATIC_OBJS+=$(MY_PLUGIN_OBJ)
```

Key variables:
- `$(LIBR)` - Path to radare2's libr/ directory
- `CFLAGS+=` - Add include paths
- `LDFLAGS+=` - Add static libraries to link
- `EXTERNAL_STATIC_OBJS+=` - Add object files to link into r_core

### Step 5: Create Meson Integration (meson.build)

Create `r2plugin/meson.build`:

```meson
# Register the plugin in the static plugin array
# This name must match the plugin struct: r_core_plugin_<name>
core_plugins += ['my_plugin']

# For arch plugins, also add:
# arch_plugins += ['my_plugin']

# For bin plugins, also add:
# bin_plugins += ['my_plugin']

# Include directories (paths relative to this meson.build file)
include_dirs = include_directories(join_paths('..', 'include'))
r_core_additional_inc += include_dirs

# Source files (paths relative to this meson.build file)
plugin_sources = files(
  '../src/my_plugin.c',
  '../src/my_plugin_utils.c',
)

r_core_additional_sources += plugin_sources
```

**Critical**: The name added to `core_plugins` (e.g., `'my_plugin'`) must match the plugin struct name pattern. If your struct is `r_core_plugin_my_plugin`, use `'my_plugin'`.

### Step 6: Implement the Plugin

Your plugin source file should define the plugin struct:

**`src/my_plugin.c`:**
```c
#include <r_core.h>
#include <my_plugin/my_plugin.h>

static bool cmd_handler(RCore *core, const char *input) {
    // Handle commands starting with your prefix
    return true;
}

static bool plugin_init(RCorePluginSession *s) {
    // Initialize plugin state
    return true;
}

static bool plugin_fini(RCorePluginSession *s) {
    // Cleanup plugin state
    return true;
}

// The struct name must be r_<type>_plugin_<name>
RCorePlugin r_core_plugin_my_plugin = {
    .meta = {
        .name = "my_plugin",
        .desc = "My plugin description",
        .author = "Your Name",
        .license = "LGPL-3.0-only",
    },
    .call = cmd_handler,
    .init = plugin_init,
    .fini = plugin_fini,
};

// Only include this for standalone/dynamic builds
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_CORE,
    .data = (void *)&r_core_plugin_my_plugin,
    .version = R2_VERSION,
    .abiversion = R2_ABIVERSION
};
#endif
```

### Step 7: Update r2plugins.h.in (For Meson)

Add your plugin's extern declaration to `radare2/libr/xps/r2plugins.h.in`:

```c
#ifdef R2_CORE_H
extern RCorePlugin r_core_plugin_my_plugin;
#endif
```

This is necessary because Meson generates `r2plugins.h` from this template, and the extern declaration must be present for `cplugin.c` to compile.

### Step 8: Enable the Plugin

Create or edit `radare2/libr/xps/config.mk`:

```makefile
EXTERNAL_PLUGINS+=my_plugin

# Optional: Add clone rules
.PHONY: my_plugin

my_plugin: p/my_plugin

p/my_plugin:
	cd p && git clone https://github.com/yourorg/my_plugin
```

### Step 9: Build

```bash
# Clone your plugin into the xps directory
git clone https://github.com/yourorg/my_plugin radare2/libr/xps/p/my_plugin

# Generate integration files (REQUIRED before any build)
make -C radare2/libr/xps

# Build with Make
cd radare2
./configure
make -j

# OR build with Meson
cd radare2
meson setup build
meson compile -C build
```

### Step 10: Verify

```bash
# Check if plugin is loaded
r2 -c 'Lc~my_plugin' --
```

## Multi-Type Plugins

If your plugin provides multiple types (e.g., core + arch + bin), you can use a "one file" approach where a single C file includes all plugin implementations:

**`src/my_plugin_one.c`:**
```c
#define R2_PLUGIN_INCORE 1
#define MY_PLUGIN_REGISTER_PLUGINS 1

#include "bin_my_plugin.c"
#include "arch_my_plugin.c"
#include "core_my_plugin.c"
```

Then in the core plugin's init function, dynamically register the other plugin types:

```c
#ifdef MY_PLUGIN_REGISTER_PLUGINS
extern RArchPlugin r_arch_plugin_my_plugin;
extern RBinPlugin r_bin_plugin_my_plugin;
#endif

static bool plugin_init(RCorePluginSession *s) {
    RCore *core = s->core;
    
#ifdef MY_PLUGIN_REGISTER_PLUGINS
    if (core->anal && core->anal->arch) {
        r_arch_plugin_add(core->anal->arch, (RArchPlugin *)&r_arch_plugin_my_plugin);
    }
    if (core->bin) {
        r_bin_plugin_add(core->bin, (RBinPlugin *)&r_bin_plugin_my_plugin);
    }
#endif
    
    return true;
}
```

This approach:
- Compiles all plugin code into one translation unit
- Only requires registering the core plugin statically
- Dynamically registers arch/bin plugins when the core plugin initializes

## CI Integration Example

For GitHub Actions:

```yaml
- name: Build radare2 with my_plugin
  run: |
    git clone --depth=1 https://github.com/radareorg/radare2.git
    cd radare2
    
    # Setup XPS
    cp -f ../r2plugin/config.mk libr/xps/config.mk
    git clone .. libr/xps/p/my_plugin
    
    # Build plugin prerequisites (if any)
    make -C libr/xps/p/my_plugin
    
    # Generate XPS integration files
    make -C libr/xps
    
    # Build with Meson
    meson setup build --prefix=/usr
    meson compile -C build
    sudo meson install -C build

- name: Verify plugin
  run: |
    r2 -c 'Lc~my_plugin' -- | grep my_plugin
```

## Troubleshooting

### Plugin compiles but doesn't appear in `Lc` output

1. **Check `core_plugins` array**: Ensure `r2plugin/meson.build` adds to `core_plugins`:
   ```meson
   core_plugins += ['my_plugin']
   ```

2. **Check extern declaration**: Ensure `libr/xps/r2plugins.h.in` has:
   ```c
   #ifdef R2_CORE_H
   extern RCorePlugin r_core_plugin_my_plugin;
   #endif
   ```

3. **Check struct name**: The plugin struct must be named `r_core_plugin_<name>` where `<name>` matches what you added to `core_plugins`.

### Meson build fails with "undefined reference"

1. **Check source files**: Ensure all source files are listed in `r_core_additional_sources`:
   ```meson
   r_core_additional_sources += files('../src/my_plugin.c')
   ```

2. **Check include paths**: Ensure include directories are added:
   ```meson
   r_core_additional_inc += include_directories('../include')
   ```

### Make build fails

1. **Check deps.mk**: Ensure `EXTERNAL_STATIC_OBJS` includes your object files
2. **Check LDFLAGS**: Ensure any static libraries are linked
3. **Run `make -C libr/xps`**: This must be run to generate integration files

### "file not found" errors in Meson

All paths in `r2plugin/meson.build` must be relative to that file's location:
- `'../include'` - Goes up to plugin root, then into include/
- `'../src/file.c'` - Goes up to plugin root, then into src/

### Plugin works with Make but not Meson (or vice versa)

The two build systems use different mechanisms:
- **Make**: Uses `deps.mk` for flags and `r2plugins.h` for externs
- **Meson**: Uses `meson.build` for sources and `core_plugins` for registration

Ensure both are properly configured.

## Reference: Variable Summary

### Meson Variables (set in r2plugin/meson.build)

| Variable | Purpose |
|----------|---------|
| `core_plugins` | List of core plugin names for static registration |
| `arch_plugins` | List of arch plugin names |
| `bin_plugins` | List of bin plugin names |
| `r_core_additional_sources` | Source files to compile into r_core |
| `r_core_additional_inc` | Include directories for r_core compilation |

### Make Variables (set in r2plugin/<type>/deps.mk)

| Variable | Purpose |
|----------|---------|
| `CFLAGS+=` | Add compiler flags (include paths) |
| `LDFLAGS+=` | Add linker flags (static libraries) |
| `EXTERNAL_STATIC_OBJS+=` | Object files to link into r_core |

## Reference: Plugin Struct Naming

| Plugin Type | Struct Name Pattern | Example |
|-------------|---------------------|---------|
| core | `r_core_plugin_<name>` | `r_core_plugin_my_plugin` |
| arch | `r_arch_plugin_<name>` | `r_arch_plugin_my_plugin` |
| bin | `r_bin_plugin_<name>` | `r_bin_plugin_my_plugin` |
| asm | `r_asm_plugin_<name>` | `r_asm_plugin_my_plugin` |
| anal | `r_anal_plugin_<name>` | `r_anal_plugin_my_plugin` |
| io | `r_io_plugin_<name>` | `r_io_plugin_my_plugin` |
| debug | `r_debug_plugin_<name>` | `r_debug_plugin_my_plugin` |

## Complete Example: r2hermes

The r2hermes plugin demonstrates all these concepts:

- Repository: `libr/xps/p/r2hermes/`
- Plugin type: core (with dynamic arch/bin registration)
- Source: `src/r2/core_hbc_one.c` (includes arch and bin implementations)
- Meson config: `r2plugin/meson.build`
- Make config: `r2plugin/core/deps.mk`, `r2plugin/core/deps.h`

Key files:
- `r2plugin/meson.build`: Adds `'r2hermes'` to `core_plugins`, sources to `r_core_additional_sources`
- `r2plugin/core/deps.h`: Declares `extern RCorePlugin r_core_plugin_r2hermes;`
- `r2plugin/static.cfg`: Contains `core.r2hermes`
- `src/r2/core_hbc_one.c`: Unified source that includes all plugin implementations

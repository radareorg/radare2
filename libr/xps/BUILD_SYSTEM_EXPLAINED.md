# XPS Build System - Architecture and Workflow

This document explains how the XPS external plugin build system works, clarifying the relationship between Make and Meson.

## Overview

The XPS system uses **two-stage building**:
1. **Make Stage**: Aggregates plugin definitions into integration files
2. **Build Stage**: Either Make or Meson builds radare2 with those aggregated files

## Stage 1: Make Aggregation (make -C libr/xps)

When you run `make -C libr/xps`, the Makefile does the following:

### Input
- `libr/xps/config.mk` - User specifies `EXTERNAL_PLUGINS+=name`
- `libr/xps/p/<plugin>/r2plugin/static.cfg` - Each plugin declares its types
- `libr/xps/p/<plugin>/r2plugin/<type>/deps.mk` - Each type declares Make dependencies
- `libr/xps/p/<plugin>/r2plugin/<type>/deps.h` - Each type declares plugin symbols

### Processing
The Makefile has four rules that generate aggregation files:

```makefile
p/meson.build:
	for each EXTERNAL_PLUGIN:
		echo "subdir('$plugin/r2plugin')" >> p/meson.build

static.cfg:
	for each EXTERNAL_PLUGIN:
		append p/$plugin/r2plugin/static.cfg >> static.cfg

deps.mk:
	for each EXTERNAL_PLUGIN:
		echo "include p/$plugin/r2plugin/deps.mk" >> deps.mk

r2plugins.h:
	for each EXTERNAL_PLUGIN:
		read p/$plugin/r2plugin/static.cfg for types
		for each type:
			append p/$plugin/r2plugin/$type/deps.h >> r2plugins.h
```

### Output
Four auto-generated files that should NEVER be manually edited:
- `libr/xps/p/meson.build` - Lists Meson subdirectories
- `libr/xps/static.cfg` - Aggregated plugin types
- `libr/xps/deps.mk` - Aggregated Make dependencies
- `libr/xps/r2plugins.h` - Aggregated plugin declarations

## Stage 2: Build (Make or Meson)

### Make Build Path

```
make -C libr/xps          # Stage 1: Generate aggregation files
./configure               # Stage 2a: Configure radare2
make -j                   # Stage 2b: Build with Make
```

The Make build process:
1. Includes `libr/xps/deps.mk` in `libr/core/Makefile`
2. This includes each plugin's `<type>/deps.mk` file
3. Each deps.mk sets CFLAGS, LDFLAGS, EXTERNAL_STATIC_OBJS
4. `libr/core/cplugin.c` includes `libr/xps/r2plugins.h`
5. The aggregated r2plugins.h includes all `<type>/deps.h` files from each plugin
6. This causes plugin structs to be linked and registered

### Meson Build Path

```
make -C libr/xps          # Stage 1: Generate aggregation files
meson setup builddir      # Stage 2a: Setup Meson build
meson compile -C builddir # Stage 2b: Build with Meson
```

The Meson build process:
1. `libr/meson.build` calls `subdir('xps')`
2. `libr/xps/meson.build` initializes `r_core_additional_*` variables
3. `libr/xps/meson.build` calls `subdir('p')`
4. `libr/xps/p/meson.build` (auto-generated) calls `subdir()` for each plugin
5. Each plugin's `r2plugin/meson.build` appends sources to `r_core_additional_*`
6. Each plugin's `r2plugin/<type>/meson.build` (optional) may add type-specific sources
7. `libr/core/meson.build` uses `r_core_additional_sources` and `r_core_additional_inc`
8. All plugin sources are compiled directly into r_core

## Plugin Definition Files

### Required Files for Each Plugin

```
libr/xps/p/your_plugin/
└── r2plugin/
    ├── static.cfg                    (REQUIRED)
    ├── meson.build                   (REQUIRED)
    └── <type>/                       (one for each declared type)
        ├── deps.h                    (REQUIRED for Make)
        ├── deps.mk                   (REQUIRED for Make)
        └── meson.build               (OPTIONAL - only if type-specific logic)
```

### static.cfg

Declares which plugin types this plugin provides:

```
core.your_plugin
asm.your_plugin
arch.your_plugin
```

Used by Make to aggregate plugin types, also read by Meson setup.

### <type>/deps.h

C header declaring plugin symbols:

```c
#ifdef R2_CORE_H
extern RCorePlugin r_core_plugin_your_plugin;
#endif
```

Make aggregates these into `r2plugins.h` so core knows about the plugin.

### <type>/deps.mk

Makefile declaring dependencies for Make build:

```makefile
YOUR_PLUGIN_WD=$(LIBR)/xps/p/your_plugin
CFLAGS+=-I$(YOUR_PLUGIN_WD)/include
LDFLAGS+=$(YOUR_PLUGIN_WD)/build/libplugin.a
EXTERNAL_STATIC_OBJS+=$(YOUR_PLUGIN_WD)/src/plugin.o
```

Make includes all these into the core build.

### r2plugin/meson.build

Integrates plugin sources into Meson:

```meson
if not is_variable('r_core_additional_sources')
  r_core_additional_sources = []
endif

include_dirs = include_directories('../include')
r_core_additional_inc += include_dirs

sources = files('../src/plugin.c', '../src/util.c')
r_core_additional_sources += sources
```

Meson appends to the core's source and include lists.

### <type>/meson.build (Optional)

Type-specific Meson config (rarely needed):

```meson
type_sources = files('../src/asm_plugin.c')
r_core_additional_sources += type_sources
```

## File Relationships

```
config.mk
  ↓ (lists plugins)
  ↓
make -C libr/xps
  ├─→ reads EXTERNAL_PLUGINS
  ├─→ reads all static.cfg files
  ├─→ reads all deps.mk files
  ├─→ reads all deps.h files
  ↓
  Generates aggregation files:
  ├─→ p/meson.build (for Meson to discover plugins)
  ├─→ static.cfg (aggregated plugin types)
  ├─→ deps.mk (aggregated Make deps)
  └─→ r2plugins.h (aggregated declarations)

Build stage:
  ├─→ Make path: uses deps.mk and r2plugins.h
  └─→ Meson path: uses p/meson.build and plugin meson.build files
```

## Key Principles

1. **Separation of Concerns**: Plugin definitions are separate from radare2
2. **Aggregation**: Make aggregates all plugins into radare2
3. **Auto-Generation**: Integration files are generated, not maintained
4. **Both Systems Supported**: Same plugins work with Make or Meson
5. **Single Source of Truth**: Plugin definitions are in p/<plugin>/r2plugin/

## Troubleshooting

### Plugin Not Visible in Build

**Symptom**: "Plugin not found" at build time

**Check**:
1. Is it in `config.mk`? → `grep EXTERNAL_PLUGINS libr/xps/config.mk`
2. Did you run `make -C libr/xps`? → Check if `static.cfg` was updated
3. Are the deps.h files correct? → Check `r2plugins.h` includes them
4. Is the plugin structure correct? → Check `libr/xps/p/<plugin>/r2plugin/`

### Meson Says "file not found"

**Symptom**: "File ... does not exist" in Meson build

**Check**:
1. Did you run `make -C libr/xps`? → Generate p/meson.build
2. Are paths in meson.build relative? → Should be relative to r2plugin/
3. Do you have static.cfg? → Required for plugin discovery

### Make Says "undefined reference"

**Symptom**: Linker error for plugin symbols

**Check**:
1. Is deps.h declaring the symbols? → `grep extern libr/xps/p/<plugin>/r2plugin/<type>/deps.h`
2. Is deps.mk linking the library? → `grep LDFLAGS libr/xps/p/<plugin>/r2plugin/<type>/deps.mk`
3. Did Make generate r2plugins.h? → `grep "#include.*deps.h" libr/xps/r2plugins.h`

## Important: Files to NOT Edit

**NEVER** manually edit these files - they are auto-generated:

```
libr/xps/p/meson.build        ← Generated by: make -C libr/xps
libr/xps/static.cfg            ← Generated by: make -C libr/xps
libr/xps/deps.mk               ← Generated by: make -C libr/xps
libr/xps/r2plugins.h           ← Generated by: make -C libr/xps
```

If you need to change them, edit the plugin definition files instead and re-run `make -C libr/xps`.

## Workflow Summary

1. **Create Plugin**: Structure your plugin under `libr/xps/p/your_plugin/r2plugin/`
2. **Define Plugin**: Create `static.cfg`, `deps.h`, `deps.mk`, `meson.build` files
3. **Register Plugin**: Add to `libr/xps/config.mk`: `EXTERNAL_PLUGINS+=your_plugin`
4. **Aggregate**: Run `make -C libr/xps` to generate integration files
5. **Build**: Use either Make or Meson to build radare2
6. **Verify**: Check if plugin loads: `r2 -c 'Lc~your_plugin' /tmp/test`


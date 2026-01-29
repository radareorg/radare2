# XPS: static external plugins

XPS lets radare2 build a third party plugin repository as part of the
radare2 build. The plugin is linked statically, so users do not need a
runtime plugin file.

This guide covers the common setup where the plugin repository is next
to radare2:

```
work/
|-- radare2/
|-- r2hermes/
`-- r2unity/
```

## Quick use

Run these commands from the radare2 repository root.

1. Put the plugin repository under `libr/xps/p/<name>`.

For a local sibling checkout, use a symlink:

```
mkdir -p libr/xps/p
ln -s ../../../../r2hermes libr/xps/p/r2hermes
```

For r2unity, use:

```
mkdir -p libr/xps/p
ln -s ../../../../r2unity libr/xps/p/r2unity
```

You can also clone or copy the repository instead of using a symlink.
The important rule is that this file must exist:

```
libr/xps/p/<name>/r2plugin/static.cfg
```

2. Enable the plugin in `libr/xps/config.mk`.

For r2hermes:

```make
EXTERNAL_PLUGINS+=r2hermes
```

For r2unity:

```make
EXTERNAL_PLUGINS+=r2unity
```

To enable both:

```make
EXTERNAL_PLUGINS+=r2hermes
EXTERNAL_PLUGINS+=r2unity
```

The plugin repository can provide this file as `r2plugin/config.mk`.
For example:

```
cp ../r2hermes/r2plugin/config.mk libr/xps/config.mk
```

When enabling more than one plugin, edit `libr/xps/config.mk` manually
instead of copying one plugin's config over the other.

3. Generate the XPS files.

```
make -C libr/xps
```

This creates:

```
libr/xps/deps.mk
libr/xps/r2plugins.h
libr/xps/static.cfg
libr/xps/p/meson.build
```

Do not edit these generated files. Re-run `make -C libr/xps` after
changing `libr/xps/config.mk` or adding/removing plugins.

4. Build any plugin private library needed by the Make build.

r2hermes needs this because its `r2plugin/core/deps.mk` links
`build/libhbc.a`:

```
make -C libr/xps/p/r2hermes
```

r2unity does not need an extra step in its current XPS setup.

5. Build radare2.

With Make:

```
./configure
make -j > /dev/null
```

With Meson:

```
meson setup build
meson compile -C build
```

If `build` already exists, use:

```
meson setup build --reconfigure
meson compile -C build
```

6. Verify that the plugin is present.

For a Make build:

```
./binr/radare2/radare2 -q -c 'Lc~r2hermes' --
./binr/radare2/radare2 -q -c 'Lc~r2unity' --
```

For a Meson build:

```
./build/binr/radare2/radare2 -q -c 'Lc~r2hermes' --
./build/binr/radare2/radare2 -q -c 'Lc~r2unity' --
```

## Plugin repository contract

Each external plugin repository must provide an `r2plugin` directory.
For a core plugin named `NAME`, use this layout:

```
NAME/
|-- r2plugin/
|   |-- config.mk        # optional helper for libr/xps/config.mk
|   |-- meson.build
|   |-- static.cfg
|   `-- core/
|       |-- deps.h
|       `-- deps.mk
`-- src/
    `-- r2/
        `-- core_NAME.c
```

The name must match everywhere:

```
EXTERNAL_PLUGINS+=NAME
core.NAME
r_core_plugin_NAME
core_plugins += ['NAME']
```

### `r2plugin/static.cfg`

List one static plugin per line:

```
core.NAME
```

Do not list a type unless the matching directory exists, for example
`r2plugin/core/` for `core.NAME`.

### `r2plugin/core/deps.h`

Declare the plugin symbol for Make builds:

```c
#ifdef R2_CORE_H
extern RCorePlugin r_core_plugin_NAME;
#endif
```

### `r2plugin/core/deps.mk`

Tell the Make build which flags, objects, and private libraries are
needed:

```make
NAME_WD=$(LIBR)/xps/p/NAME
CFLAGS+=-I$(NAME_WD)/include
NAME_OBJ=$(NAME_WD)/src/r2/core_NAME.o
EXTERNAL_STATIC_OBJS+=$(NAME_OBJ)
```

If the plugin links a private static library, add it to `LDFLAGS` and
make sure it is built before building radare2:

```make
LDFLAGS+=$(NAME_WD)/build/libname.a
```

### `r2plugin/meson.build`

Tell the Meson build which plugin name, sources, and include paths to
use:

```meson
core_plugins += ['NAME']

r_core_additional_inc += include_directories(join_paths('..', 'include'))

r_core_additional_sources += files(
  '../src/r2/core_NAME.c',
)
```

Meson generates the needed extern declarations from `core_plugins`.
Do not edit `libr/xps/r2plugins.h.in` for normal XPS plugins.

## Notes for non-core code

The least confusing XPS shape is a core plugin entry point. If the
project also has arch, bin, asm, or analysis code, prefer to compile
that code into the core plugin and register it from the core plugin init
function.

r2hermes uses this style: it exposes `core.r2hermes` and builds a single
core source that pulls in the other r2 integration code.

Direct static registration for other plugin types is possible, but it
must update all matching pieces: `static.cfg`, per-type `deps.h`,
per-type `deps.mk`, the matching Meson plugin list, and the owner
library's source list. Use that only when the core-entry style is not
enough.

## Troubleshooting

If the plugin does not appear in `Lc`, check these first:

- `libr/xps/config.mk` contains `EXTERNAL_PLUGINS+=<name>`.
- `libr/xps/p/<name>/r2plugin/static.cfg` exists.
- `make -C libr/xps` was run after enabling the plugin.
- `./configure` or `meson setup build --reconfigure` was run after XPS
  changed.
- The C symbol is named `r_core_plugin_<name>`.
- `r2plugin/meson.build` contains `core_plugins += ['<name>']`.
- `r2plugin/core/deps.mk` lists every object or static archive needed by
  the Make build.

If switching plugins, clean only the generated XPS files:

```
make -C libr/xps clean
make -C libr/xps
```

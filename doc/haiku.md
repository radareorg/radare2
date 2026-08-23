r2 for Haiku
============

Compilation
-----------

On x86_64 Haiku the usual acr/make build works out of the box:

	./configure --prefix=/boot/home/config/non-packaged
	make
	make install

On the 32bit gcc2-hybrid images the modern compiler must be selected:

	HOST_CC=gcc-x86 CC=gcc-x86 ./configure --with-ostype=haiku --prefix=/boot/home/config/non-packaged
	HOST_CC=gcc-x86 make
	make install

The meson build works too: `meson setup b && ninja -C b`.

Debugging
---------

The native debugger uses the Haiku kernel debugging api from
`<kernel/debugger.h>`: r2 installs itself as the team debugger with
`install_team_debugger()` and drives the target through the port based
debug nub protocol (read/write memory, get/set cpu state, continue and
single step). No ptrace, no libdebug and no C++ kits are involved, and
the system `debug_server` is left untouched (installing a team debugger
is exactly what keeps the crash dialog away).

	r2 -d /bin/ls          # spawn a team stopped at the entrypoint
	r2 -d 1234             # attach to a running team by id
	r2 dbg://1234          # same as above

Programs are spawned with `load_image()`, whose main thread starts
suspended, so the debugger is installed before the first instruction
runs. Software breakpoints work through the memory write nub messages;
`dbH` maps hardware breakpoints to the kernel `B_DEBUG_MESSAGE_SET_BREAKPOINT`
request. Memory maps come from `get_next_area_info()` and the module list
from `get_next_image_info()`.

Register profiles are wired in for x86_64 and x86 (`drx` and fpu/sse
register access are not implemented yet); the rest of the backend is
architecture independent.

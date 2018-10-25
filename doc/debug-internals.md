# Radare Debugger Internals

The debugger is designed using a multi-tiered plug-in architecture that allows
overriding functionality for architecture or platform-specific reasons.

The bulk of the debugger functionality within radare core is split between the
"io", "reg", "bp", and "debug". More information on the specific files within
the tree follows.


## libr/include/r_debug.h

This is the main header file for the debugger. It defines all the relevant
structures and top-level functions, APIs, etc. The debugger plug-in API is also
defined in here.


## libr/io/p/io_debug.c

In order to interface with radare IO, a plug-in is provided. This handles, for
example, spawning processes under a debugger.


## libr/reg

The "reg" module provides functionality for reading and writing registers as
well as setting up profiles. (??profiles??)

The functionality lives in the following files:
(?? why so many files? can this be simplified??)

    libr/reg/arena.c        // ?? used by anal and debugger
    libr/reg/cond.c         // condition registers
    libr/reg/double.c       // support for double-precision floating point numbers
    libr/reg/profile.c      // ?? used by anal and debugger
    libr/reg/reg.c          // top-level register specific code (all of r2)
    libr/reg/value.c        // dealing with register values
    libr/reg/t/p.c          // test code for printing general-purpose registers
    libr/reg/t/regdiff.c    // ?? test code for?
    libr/reg/t/test.c       // test code for register handling


## libr/bp

The "bp" subsystem of radare implements all the necessary details for dealing
with breakpoints on any given architecture. It handles managing the list of
breakpoints and more.

Radare supports a multitude of different types of breakpoints.
(`??` is there a list? sw, hw, and trace? anything else??)

    libr/bp/bp.c            // main breakpoint management code
    libr/bp/io.c            // setting and reseting(??) breakpoints
    libr/bp/parser.h        // header for breakpoint parser (??)
    libr/bp/parser.c        // code for breakpoint parser (??)
    libr/bp/plugin.c        // breakpoint plugin management
    libr/bp/traptrace.c     // traptrace (??)
    libr/bp/watch.c         // watch points (mostly not implemented)

For architecture specific-handling, "bp" delegates various functionality to
plugins. The interface for these plugins is much simpler than other plugins
used in the radare debugger -- they only define which byte sequences represent
valid breakpoints for a given architecture.

    libr/bp/p/bp_arm.c      // ARM64, ARM, Thumb, Thumb-2 (big/little endians)
    libr/bp/p/bp_bf.c       // Brainfuck!
    libr/bp/p/bp_mips.c     // MIPS, big/little endian
    libr/bp/p/bp_ppc.c      // PowerPC, big/little endian
    libr/bp/p/bp_sh.c       // SuperH
    libr/bp/p/bp_x86.c      // int3...


## libr/debug/debug.c

The main top-level debugger functionality lives here. It aims to abstract away
the common code flow and integration into radare while delegating more nuanced
system interactions to plug-ins.

    libr/debug/arg.c        // used by the anal engine (??)
    libr/debug/desc.c       // code for handling file descriptors inside an inferior
    libr/debug/esil.c       // ESIL related debugging code (??)
    libr/debug/map.c        // top-level API for dealing with memory maps
    libr/debug/pid.c        // top-level API for dealing with processes
    libr/debug/plugin.c     // top-level debugger plugin API handling
    libr/debug/reg.c        // top-level code for register r/w and display
    libr/debug/signal.c     // top-level functions for signals
    libr/debug/snap.c       // code for saving, restoring, showing memory snapshots
    libr/debug/trace.c      // top-level tracing API (counting insn hits, etc)
    libr/debug/t/main.c     // test code for the debugger API

## libr/core/cmd_debug.c

Most of the time a debugger is used by a human to try to understand subtle
problems with software and/or hardware. That task would be very difficult
without a user interface of some kind. The CLI commands exposed to radare are
implemented in here. To get more information about this interface, consult the
user manual or try "d?" to get a crash course.


## Debugger Plug-Ins

As mentioned before, the platform specific debugger functionality is delegated
to back-end plugins that implement the necessary interactions, protocols, or
otherwise to get the job done. These plug-ins implement the radare2 debugger
plug-in API defined in r_debug.h.


### libr/debug/p/debug_bf.c

A debugger plug-in capable of debugging brainfuck code!

    libr/debug/p/bfvm.c     // Brainfuck VM implementation
    libr/debug/p/bfvm.h


### libr/debug/p/debug_bochs.c

A debugger plug-in that utilizes bochs emulator to control execution.

### libr/debug/p/debug_esil.c

This debugger plug-in enables debugging and tracing radare own intermediate
language, Evaluable Strings Intermediate Language (ESIL).

### libr/debug/p/debug_gdb.c

A radare debugger plug-in that uses a remote GDB server/stub as its backend.
The protocol parsing itself is located at shlr/gdb. And corresponding IO plugin is
located in libr/io/p/io_gdb.c

### libr/debug/p/debug_native.c

The "native" debugger plug-in is a bit of a doozy. It implements functionality
for debugging on the most common platforms available: Windows, OSX, Linux, and
BSD. Much of the underlying debug API between these platforms are similar and
thus much of the code within this plug-in is shared. The parts that are not
shared are implemented by platform-specific functions that are provided in the
following files:

    // architecture-specific debugger code
    libr/debug/p/native/arm.c                       // unused?
    
    // code for handling backtracing
    libr/debug/p/native/bt.c
    libr/debug/p/native/bt/fuzzy-all.c
    libr/debug/p/native/bt/generic-x64.c
    libr/debug/p/native/bt/generic-x86.c
    
    // architecture-specific register handling
    libr/debug/p/native/drx.c                       // x86-specific debug registers
    libr/debug/p/native/reg.c                       // cute include of the files below
    libr/debug/p/native/reg/kfbsd-x64.h
    libr/debug/p/native/reg/kfbsd-x86.h
    libr/debug/p/native/reg/netbsd-x64.h
    libr/debug/p/native/reg/netbsd-x86.h
    libr/debug/p/native/reg/windows-x64.h
    libr/debug/p/native/reg/windows-x86.h
    
    // platform-specific debugger code on Linux
    libr/debug/p/native/linux/linux_debug.c         // main linux-specific debugging code
    libr/debug/p/native/linux/linux_debug.h         // including cute penguin ascii art
    
    // architecture-specific register handling on Linux (?? what is this format??)
    libr/debug/p/native/linux/reg/linux-arm.h
    libr/debug/p/native/linux/reg/linux-arm64.h
    libr/debug/p/native/linux/reg/linux-mips.h
    libr/debug/p/native/linux/reg/linux-ppc.h
    libr/debug/p/native/linux/reg/linux-x64.h
    libr/debug/p/native/linux/reg/linux-x64-32.h
    libr/debug/p/native/linux/reg/linux-x86.h
    
    // platform-specific debugger code on Windows
    libr/debug/p/native/w32.c                       // main code for win32 debugger plugin
    libr/debug/p/native/maps/windows.c              // platform-specific memory map handling
    libr/debug/p/native/windows/windows_debug.c     // !! nothing in here
    libr/debug/p/native/windows/windows_debug.h     // !! nothing in here
    
    // platform-specific debugger code on XNU (OSX/iOS/etc)
    libr/debug/p/native/darwin.c                    // !! not used by anything else
    libr/debug/p/native/maps/darwin.c               // platform-specific memory map handling
    libr/debug/p/native/xnu/xnu_debug.c             // main XNU-specific debugging code
    libr/debug/p/native/xnu/xnu_debug.h             // including cute apple ascii art
    libr/debug/p/native/xnu/trap_arm.c              // ARM family hardware bps (??)
    libr/debug/p/native/xnu/trap_x86.c              // x86 family hardware bps (??)
    libr/debug/p/native/xnu/xnu_excthreads.c        // additional XNU thread handling
    libr/debug/p/native/xnu/xnu_threads.c           // XNU thread and register handling
    libr/debug/p/native/xnu/xnu_threads.h
    
    // architecture-specific register handling on XNU (?? what is this format??)
    libr/debug/p/native/xnu/reg/darwin-x86.h
    libr/debug/p/native/xnu/reg/darwin-arm.h
    libr/debug/p/native/xnu/reg/darwin-ppc.h
    libr/debug/p/native/xnu/reg/darwin-arm64.h
    libr/debug/p/native/xnu/reg/darwin-x64.h


### libr/debug/p/debug_qnx.c

A debugger plug-in that enables debugging code natively on QNX systems. Corresponding
IO plugin is located in libr/io/p/io_qnx.c
See doc/qnx

### libr/debug/p/debug_rap.c

See doc/rap

### libr/debug/p/debug_windbg.c

A debugger plugin that enables debugging code remotely via WinDbg protocol. WinDbg protocol
parser is located in shlr/windbg. Corresponding IO plugin located in libr/io/p/io_windbg.c
See doc/windbg

## Conclusion

Best of luck!

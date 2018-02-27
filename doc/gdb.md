Connecting r2 with gdb
======================

Running gdbserver
-----------------

    $ gdbserver :2345 /bin/ls
    (gdb) target remote localhost:2345

Connecting from r2
------------------

    $ r2 -D gdb gdb://127.0.0.1:2345


Supported implementations
=========================
r2 have support for connecting to remote GDB instances:

                x86-32   x86-64   arm    arm64   sh
    winedbg       x        x       -      -      -
    qemu          x        x       ?      x      -
    gdbserver     x        x       ?      ?      ?

    x = supported
    ? = untested
    - = not supported

Supported Commands
------------------

- read/write memory

  Writing or reading memory is implemented through the m/M packet.

- read registers

  Reading registers is currently implemented through the <g> packet of the gdb protocol.
  It returns the whole register profile at once. 

- write registers

  There are two ways of writing registers. The first one is through the P packet.
  It works like this: `P<register_index>=<register_value>`
  The second one is the G packet, that writes the whole register Profile at once.
  The implementation first tries to use the newer P packet and if it receives a $00# packet (that says not implemented), it tries to write through the G packet.

- stepping (but this is still the softstep mode and for an unknown reason it sill does not call th gdb_write_register function)

Supported Packets:

- `g` : Reads the whole register Profile at once
- `G` : Writes the whole register Profile at once
- `m` : Reads memory 
- `M` : Writes memory
- `vCont,v` : continues execution of the binary
- `P` : Write one register

TODO
----

- Implement GDBserver to allow other apps use r2 debugger 
- Fix that usese the gdb internal stepping version
- Fix softstep, that it finally recoils correct (it just have to reset the eip/rip)
- Add Breakpoints (should be an easy add of the function, because its already implemented in the gdb lib)


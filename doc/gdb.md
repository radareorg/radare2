# GDB remote debugging

Start a GDB Remote Serial Protocol (RSP) stub, then open its endpoint with
radare2:

```sh
gdbserver --once 127.0.0.1:2345 /bin/sleep 30
```

```sh
r2 -D gdb gdb://127.0.0.1:2345
```

Append `/PID` to the TCP URI to request an attach when supported. For a serial
stub, use `gdb:///dev/ttyUSB0@115200`. Use `:?` in the radare2 session to list
the GDB IO commands.

## Client behavior

- The client negotiates features with `qSupported`. An empty reply selects
  the defaults, including acknowledgments and a conservative 64-byte payload
  limit. With an advertised packet size, the client caps payloads at 2048
  bytes and chunks memory operations accordingly. `R2_GDB_PKTSZ` (decimal)
  and `:pktsz bytes` can lower that limit. A value that cannot hold a request
  will make that request fail.
- Acknowledged sessions check the checksum and retry rejected frames with a
  bounded retry count. The client requests no-ack mode when advertised.
- Memory reads use `m` and writes use `M`. Reads stop at the first short or
  invalid reply and return only bytes obtained before it. Larger operations
  respect page boundaries and packet limits.
- Registers are read with `g`, or with individual `p` packets when the stub
  does not implement `g`. Writes use `P`, or use `G` with a complete register
  block. Unavailable register bytes keep their positions in the block and
  prevent an automatic `G` rewrite. LLDB thread suffixes are used when negotiated.
- A negotiated target description supplies register numbers, widths, and
  layout, including included XML features. `:osabi` shows the OS ABI when
  provided. `:tls lm offset` resolves a thread-local address on stubs that
  implement `qGetTLSAddr`. Here `lm` is the target's load-module identifier,
  such as the SVR4 link-map address. `:tib` queries a Windows thread's TIB.
- The debugger uses the remote stub for stepping and continuing. Software and
  hardware breakpoints and read, write, or access watchpoints depend on stub
  support. Watchpoint stops include the access type and the reported address.
  Normal exit status and signal termination are tracked separately.
- In all-stop mode, `O` packets from the target are printed while the client
  continues to wait for a stop. `:monitor command` returns the monitor output.
- `:rd` shows the independent reverse-step and reverse-continue capabilities.
  `:dsb` and `:dcb` use the same stop handling as forward execution.
- `dm` can show negotiated memory-map XML. These regions describe RAM, ROM,
  and flash rather than an OS mapping with file paths and execute permissions.
  `dmm` prefers negotiated library lists and refreshes them at library-change
  stops. Library XML supplies segment or section bases without sizes. For
  SVR4, a relocation bias alone does not give a prelinked image base, so an
  unverified base is shown as unknown. Targets without these XML packets can
  fall back to `/proc/PID/maps` when their stub exposes it.
- `:catch-syscalls all`, `:catch-syscalls off`, or `:catch-syscalls 1 60`
  configure syscall stops if the stub advertises support. Continue with `dc`;
  `di` and `dij` report the syscall number and whether the stop was at entry
  or return.
- All-stop mode is the default. `:nonstop on` opts into non-stop mode on a
  capable stub. In this mode, debugger resume commands operate on the selected
  thread and may report an event from another thread. `:nonstop wait` consumes
  another pending stop or waits for a notification. Use `:nonstop off` to
  return to all-stop mode. Non-stop mode has no runtime `O` console output.

## Serving a native debugger

Radare2 can also launch a native target and serve RSP with `=g`:

```sh
r2 -q -c '=g 2345 /bin/sleep 30' -
```

Connect with `target remote 127.0.0.1:2345` in GDB or
`gdb-remote 127.0.0.1:2345` in LLDB. The server handles memory, registers,
thread selection, paged thread lists, and all-stop resume requests. Its
`vCont` implementation accepts a single continue or step action with an
optional thread ID. It supports software breakpoints, and uses the host
backend for hardware breakpoints. On x86, the server accepts write and access
watchpoints. The server does not advertise non-stop, reverse execution, remote
file IO, or flash programming.

## Interoperability checks

The scripted GDB and LLDB fixtures in `test/unit/test_gdb.c` run offline.
They exercise negotiation, small packet limits, malformed and partial packets,
retransmission, console output, interrupts, and terminal stops.

```sh
make -j2
make -C test/unit bin/test_gdb
./test/unit/bin/test_gdb
```

For a live check, start one of these local stubs and run
`test/scripts/test-gdb-client.sh gdb://127.0.0.1:2345 step` from the radare2
checkout. The script checks that it can read the PC and instruction memory
and that a single step changes the PC. Use `read` for targets that cannot
step. Set `R2_GDB_CLIENT` to select a different radare2 executable.

- GNU GDB: `gdbserver --once 127.0.0.1:2345 /bin/sleep 30`
- LLVM LLDB: `lldb-server gdbserver 127.0.0.1:2345 -- /bin/sleep 30`, or on
  macOS, `debugserver 127.0.0.1:2345 ./binr/rasm2/rasm2 -v`
- mwemu: Create a four-byte x86 Linux guest. This fixture needs no external
  DLLs, libraries, or symbols.

  ```sh
  printf '\220\220\353\376' > /tmp/r2-gdb-x86.raw
  mwemu --arch x86 --sys linux --is_shellcode --filename /tmp/r2-gdb-x86.raw \
    --gdb --gdb-port 2345 --gdb-wait
  ```

  Run the check with `step 90` to also verify the first instruction byte.

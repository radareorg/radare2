What is GProbe?
===============
GProbe is a protocol to communicate with various parts from
Genesis/STMicro/MegaChips that are mostly used in video chipsets.

These chips have an integrated Turbo186 core. With GProbe you can read and write
RAM, reset the CPU, execute code in RAM, ...
There is a proprietary Windows tool to do this, but radare2 offers much more
functionality.

Gprobe got some public attention with the
[MonitorDarkly exploit](https://github.com/RedBalloonShenanigans/MonitorDarkly).

What is implemented?
--------------------
- Serial1 protocol wrapper
- RAM read-/write-access
- Reset
- DebugOn/DebugOff
- RunCode
- GetDeviceId

TODOs
-----
- DDC2Bi3 and DisplayPort AUX Channel protocol wrappers
- Flash commands

What is tested?
---------------
- building with sys/user.sh and sys/mingw32.sh on linux
- running radare2 on Linux and Windows
- communication via FTDI USB serial adaptor
- controlling a MegaChips RD1-4320 DisplayPort 1.2a splitter reference board

How to use for dummies?
-----------------------
radare2 -n -w gprobe:///dev/ttyUSB0
- "/dev/ttyUSB0" is the serial connection, use something like "COM3" on Windows
- "-n" is important to avoid an initial 32k read to identify the binary type
- "-w" if you want to allow writing to RAM

Setup for Turbo186 processor core:
- e asm.bits=16
- e asm.seggrn=8

Now enjoy all the great stuff that r2 offers, like:
- run grobe commands with =!?
- dump memory with px
- Visual mode with V, including cursor mode and insert hexpairs
- dumping segments to file
- disassembly and analysis

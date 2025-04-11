What is GProbe?
===============
GProbe is a protocol to communicate with various parts from
Genesis/STMicro/MegaChips/Kinetic Technologies that are mostly used in video chipsets.

These chips have an integrated Turbo186 core. With GProbe you can read and write
RAM, reset the CPU, execute code in RAM, ...
There is a proprietary Windows tool to do this, but radare2 offers much more
functionality.

Gprobe got some public attention with the
[MonitorDarkly exploit](https://github.com/RedBalloonShenanigans/MonitorDarkly).

What is implemented?
--------------------
- Serial1 protocol wrapper
- DDC2Bi3 protocol wrapper (Linux only)
- RAM read-/write-access
- Reset
- DebugOn/DebugOff
- RunCode
- GetDeviceId
- GetInformation
- Flash commands
- Listen command to dump Print-messages from the chip

TODOs
-----
- DisplayPort AUX Channel protocol wrapper

What is tested?
---------------
- building with sys/user.sh and sys/mingw32.sh on linux
- running radare2 on Linux and Windows
- communication via FTDI USB serial adaptor
- communication via DDC2Bi3
- controlling a MegaChips RD1-4320 DisplayPort 1.2a splitter reference board
- controlling a DELL U2410 connected via DVI
- flashing a STDP2600 with RC3.3 firmware on MNT RHDP board(mntre.com)

How to use for dummies?
-----------------------
radare2 -n -w gprobe:///dev/ttyUSB0
- "/dev/ttyUSB0" is the serial connection, use something like "COM3" on Windows
- "-n" is important to avoid an initial 32k read to identify the binary type
- "-w" if you want to allow writing to RAM

radare2 -n -w gprobe://i2c-4
- i2c-4 is the i2c bus where the GProbe device is connected
- find the appropriate bus with "ddcutil detect"
- make sure the i2c-dev kernel module is loaded

Setup for Turbo186 processor core:
- e asm.bits=16
- e asm.offset.segment.bits=8

Now enjoy all the great stuff that r2 offers, like:
- run grobe commands with =!?
- dump memory with px
- Visual mode with V, including cursor mode and insert hexpairs
- dumping segments to file
- disassembly and analysis

How to flash?
-------------
To flash you need three things:
- a flasher program that gets uploaded to the chip
  - since it as a hexfile with multiple sections, you can convert it to .rapatch with hex2rapatch.py
  - alternatively you can use ihex://, list the sections in json with :j and write them to gprobe:// using a script
- a binary firmware blob that gets flashed
- parameters (probably supplied in the gprobe script that comes with the firmware):
  - load and start address for flasher program (0x1800 in the example)
  - Maximum chunksize for flashing (0x200 in the example)
  - flash address for binary blob (0x40000 in the example)

- :reset 0
- wp isp.rapatch
- :runcode 0x1800
- :flasherase 0xffff
- :flashwrite 0x200 0x400000 STDP2600_HDMI2DP_STD_RC3_3.bin

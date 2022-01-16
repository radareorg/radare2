RAP protocol
============

RAP stands for the Remote Access Protocol of Radare2, it is compatible with radare1
and it simply defines a communication between a client and a server to simulate IO
operations.

There are two different implementations, one in C and another in Python.

Usage example
-------------

Start in one terminal the following command to wait for incoming connections:

	r2 rap://:9999

In another machine or terminal connect it:

	r2 rap://localhost:9999//bin/ls

As you see, the path of the remote file to load must be specified, and this handled
by the open() packet.

Known Bugs
----------

* Read/Write operations ignore the filedescriptor completely because it is supposed to be handled by the IO layer and it is redundant, but it introduces a bug that breaks support for multiple files.
* This can be fixed with a new packet type RAP_SETFD.
* Read lengths should be only 2 bytes, there's no sense in read > 64K of memory in a shot.
* Seek does not returns anything
* System vs Cmd - the first should have a return value as well as string result
* Filedescriptors are assumed to be 32bit


Operations
----------

The protocol is designed to be bidirectional, but right now, only one way is supported.
The client sends a byte specifying the operation and the server will reply the same byte
masked with the RMT_REPLY value (0x80 | op)

	RAP_OPEN   = 1
	RAP_READ   = 2
	RAP_WRITE  = 3
	RAP_SEEK   = 4
	RAP_CLOSE  = 5
	RAP_SYSTEM = 6
	RAP_CMD    = 7
	RAP_REPLY  = 0x80

This is how are constructed the packets:

	RAP_OPEN
		struct packed RapOpen {
			ut8 op = 1;
			ut8 rw = 0; // 0 = read-only, 1 = read-write
			ut8 len = 15; // length of filename
		}
		>> 01 RW LN [....]
		<< 81 FD=(.. .. .. ..)

	RAP_READ
		>> 02 LN=(.. .. .. ..)
		<< 82 LN=(.. .. .. ..) [..LN..]

	RAP_WRITE
		>> 03 LN=(.. .. .. ..) [..LN..]
		<< 83 LN=(.. .. .. ..)

	RAP_SEEK
		>> 04 FLAG=(..) OFFSET=(.. 8 bytes ..)
		<< 84

	RAP_CLOSE
		>> 05 FD=(4 bytes)
		<< 85 RET=(4 bytes)

	RAP_SYSTEM
		>> 06 LEN=(4 bytes) STR[LEN bytes]
		<< 86 LN=(.. .. .. ..) STR[ LEN bytes]

	RAP_CMD_
		>> 07 LEN=(4 bytes) STR[LEN bytes]
		<< 87 LN=(.. .. .. ..) STR[ LEN bytes]


Examples
--------

Python:

	See radare2-bindings/python/remote.py and test-rap-*.py

C:

	Server: libr/socket/rap_server.c
	Client: libr/io/p/io_rap.c

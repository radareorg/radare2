Radare2 Regression Test Suite
=============================

A set of regression tests for Radare2 (http://radare.org).

Originally based on work by and now in collaboration with pancake.

Directory Hierarchy
-------------------

 * db/:          The tests sources
 * unit/:        Unit tests (written in C, using minunit).
 * fuzz/:        Fuzzing helper scripts
 * bins/:        Sample binaries (fetched from the [external repository](https://github.com/radareorg/radare2-testbins))

Requirements
------------

 * Radare2 installed (and in `$PATH` or set the R2 environment).
 * r2pipe tests require Python and r2pipe (in CI uses python3 and r2pipe from git, but users may be good with latests releases)
 * Valgrind (optional).

Usage
-----

 * To run *all* tests, use `make -k all`.
 * To execute only the unit tests use `make -k unit_tests`.

Failure Levels
--------------

A test can have one of the following results:
* success: The test passed, and that was expected.
* fixed: The test passed, but failure was expeced.
* broken: Failure was expected, and happened.
* failed: The test failed unexpectedly. This is a regression.

Reporting Radare2 Bugs
----------------------

Please do not post Radare2 bugs on the r2-regressions github tracker. Instead
use the official r2 tracker:

https://github.com/radareorg/radare2/issues?state=open

Writing Assembly tests
----------------------

Example tests for `db/asm/*`:

	General format:
	type "assembly" opcode [offset]

		type:
			* a stands for assemble
			* d stands for disassemble
			* B stands for broken
			* E stands for cfg.bigendian=true

		offset:
			Some architectures are going to assemble an instruction differently depending
			on the offset it's written to. Optional.

	Examples:
	a "ret" c3
	d "ret" c3
	a "nop" 90 # Assembly is correct
	dB "nopppp" 90 # Disassembly test is broken

	You can merge lines:

	adB "nop" 90

	acts the same as

	aB "nop" 90
	dB "nop" 90

        The filename is very important. It is used to tell radare which architecture to use.

        Format:
        arch[[_cpu]_bits]

	Example:
	x86_32 means -a x86 -b 32
        arm_v7_64 means what it means


Writing JSON tests
----------

The JSON tests `db/json` are executed on 3 standard files (1 ELF, 1 MachO, 1 PE). The tests need to be working on the 3 files to pass.

# Commands tests
----------------

Example commands tests for the other `db/` folders:

	NAME=test_db
	FILE=bins/elf/ls
	CMDS=<<EXPECT
	pd 4
	EXPECT=<<RUN
            ;-- main:
            ;-- entry0:
            ;-- func.100001174:
            0x100001174      55             Push rbp
            0x100001175      4889e5         Mov  rbp, rsp
            0x100001178      4157           Push r15
	RUN

* **NAME** is the name of the test, it must be unique
* **FILE** is the path of the file used for the test
* **ARGS** (optional) are the command line argument passed to r2 (e.g -b 16)
* **CMDS** are the commands to be executed by the test
* **EXPECT** is the expected output of the test
* **BROKEN** (optional) is 1 if the tests is expected to be fail, 0 otherwise
* **TIMEOUT** (optional) is the number of seconds to wait before considering the test timeout

You must end the test by adding RUN keyword

Advices
-------

* For portability reasons Do not use shell pipes, use `~`
* dont use `pd` if not necessary, use `pi`

License
-------

The test files are licensed under GPL 3 (or later).

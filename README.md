```
    ____  ___  ___  ___ ____  ___    ____
   |  _ \/   \|   \/   \  _ \/ _ \  (__  \
   |    (  -  | |  ) -  |   (   _/  /  __/
   |__\__|_|__|___/__|__|_\__|___|  |____|

                https://www.radare.org

                                  --pancake
```



| | |
|----------|---------------------------------------------------------------------|
| **Jenkins**  	| [![Build Status](http://ci.rada.re/buildStatus/icon?job=radare2)](http://ci.rada.re/job/radare2)|
| **TravisCI** 	| [![Build Status](https://travis-ci.org/radare/radare2.svg?branch=master)](https://travis-ci.org/radare/radare2)|
| **AppVeyor**  | [![Build Status](https://ci.appveyor.com/api/projects/status/v9bxvsb1p6c3cmf9/branch/master?svg=true)](https://ci.appveyor.com/project/radare/radare2-shvdd)|
| **Coverity** 	| [![Build Status](https://scan.coverity.com/projects/416/badge.svg)](https://scan.coverity.com/projects/416) |
| **Infrastructure** |  [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/741/badge)](https://bestpractices.coreinfrastructure.org/projects/741) |
| **Codecov** | [![codecov](https://codecov.io/gh/radare/radare2/branch/master/graph/badge.svg)](https://codecov.io/gh/radare/radare2)
<a href="https://repology.org/metapackage/radare2">
<img src="https://repology.org/badge/vertical-allrepos/radare2.svg" alt="Packaging status" align="right" width="150px">
</a>

# Introduction

r2 is a rewrite from scratch of radare in order to provide
a set of libraries and tools to work with binary files.

Radare project started as a forensics tool, a scriptable
command-line hexadecimal editor able to open disk files,
but later added support for analyzing binaries, disassembling
code, debugging programs, attaching to remote gdb servers...

radare2 is portable.

## Architectures

i386, x86-64, ARM, MIPS, PowerPC, SPARC, RISC-V, SH, m68k, AVR, XAP,
System Z, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300, V810, V850,
CRIS, XAP, PIC, LM32, 8051, 6502, i4004, i8080, Propeller, Tricore, Chip8
LH5801, T8200, GameBoy, SNES, MSP430, Xtensa, NIOS II,
Dalvik, WebAssembly, MSIL, EBC, TMS320 (c54x, c55x, c55+, c66),
Hexagon, Brainfuck, Malbolge, DCPU16.

## File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, OMF, TE, XBE, BIOS/UEFI,
Dyldcache, DEX, ART, CGC, Java class, Android boot image, Plan9 executable,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump),
WASM (WebAssembly binary), Commodore VICE emulator, 
Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs, various filesystems.

## Operating Systems

Windows (since XP), GNU/Linux, OS X, [Net|Free|Open]BSD,
Android, iOS, OSX, QNX, Solaris, Haiku, FirefoxOS.

## Bindings

Vala/Genie, Python (2, 3), NodeJS, Lua, Go, Perl,
Guile, PHP, Newlisp, Ruby, Java, OCaml...

# Dependencies

radare2 can be built without any special dependency, just
get a working toolchain (gcc, clang, tcc...) and use make.

Optionally you can use libewf for loading EnCase disk images.

To build the bindings you need latest valabind, g++ and swig2.

# Install

The easiest way to install radare2 from git is by running
the following command:

	$ sys/install.sh

If you want to install radare2 in the home directory without
using root privileges and sudo, simply run:

	$ sys/user.sh

# Building with meson + ninja

If you don't already have meson and ninja, you can install them
with your distribution package manager or with r2pm:

	$ r2pm -i meson

If you already have them installed, you can run this line to
compile radare2:

	$ python ./sys/meson.py --prefix=/usr --shared --install

This method is mostly useful on Windows because the initial building
with Makefile is not suitable. If you are lost in any way, just type:

	$ python ./sys/meson.py --help

# Update

To update Radare2 system-wide, you don't need to uninstall or pull.
Just re-run:

	$ sys/install.sh

If you installed Radare2 in the home directory,
just re-run:

	$ sys/user.sh

# Uninstall

In case of a polluted filesystem, you can uninstall the current
version or remove all previous installations:

	$ make uninstall
	$ make purge
	
To remove all stuff including libraries, use

	$ make system-purge

# Package manager

Radare2 has its own package manager - r2pm. Its packages
repository is on [GitHub too](https://github.com/radare/radare2-pm).
To start to using it for the first time, you need to initialize packages:

	$ r2pm init

Refresh the packages database before installing any package:

	$ r2pm update

To install a package, use the following command:

	$ r2pm install [package name]

# Bindings

All language bindings are under the r2-bindings directory.
You will need to install swig and valabind in order to
build the bindings for Python, Lua, etc..

APIs are defined in vapi files which are then translated
to swig interfaces, nodejs-ffi or other and then compiled.

The easiest way to install the python bindings is to run:

	$ r2pm install lang-python2 #lang-python3 for python3 bindings
	$ r2pm install r2api-python
	$ r2pm install r2pipe-py

In addition there are `r2pipe` bindings, which is an API
interface to interact with the prompt, passing commands
and receivent the output as a string, many commands support
JSON output, so its integrated easily with many languages
in order to deserialize it into native objects.

	$ npm install r2pipe   # NodeJS
	$ gem install r2pipe   # Ruby
	$ pip install r2pipe   # Python
	$ opam install radare2 # OCaml

And also for Go, Rust, Swift, D, .NET, Java, NewLisp, Perl, Haskell,
Vala, OCaml, and many more to come!

# Regression Testsuite

Running `make tests` will fetch the radare2-regressions
repository and run all the tests in order to verify that no
changes break any functionality.

We run those tests on every commit, and they are also
executed with ASAN and valgrind on different platforms
to catch other unwanted 'features'.

# Documentation

There is no formal documentation of r2 yet. Not all commands
are compatible with radare1, so the best way to learn how to
do stuff in r2 is by reading the examples from the web and
appending '?' to every command you are interested in.

Commands are small mnemonics of few characters and there is
some extra syntax sugar that makes the shell much more pleasant
for scripting and interacting with the APIs.

You could also checkout the [radare2 book](https://radare.gitbooks.io/radare2book/content/).

# Coding Style

Look at [CONTRIBUTING.md](https://github.com/radare/radare2/blob/master/CONTRIBUTING.md).

# Webserver

radare2 comes with an embedded webserver which serves a pure
html/js interface that sends ajax queries to the core and
aims to implement an usable UI for phones, tablets and desktops.

	$ r2 -c=H /bin/ls

To use the webserver on Windows, you require a cmd instance
with administrator rights. To start the webserver, use the following command
in the project root.

	> radare2.exe -c=H rax2.exe

# Pointers

Website: https://www.radare.org/

IRC: irc.freenode.net #radare

Telegram: https://t.me/radare

Matrix: @radare2:matrix.org

Twitter: [@radareorg](https://twitter.com/radareorg)

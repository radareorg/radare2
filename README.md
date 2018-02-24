```
    ____  ___  ___  ___ ____  ___    ____
   |  _ \/   \|   \/   \  _ \/ _ \  |__  \
   |    (  V  | |  ) V  |   (   _/   / __/
   |__\__|_|__|___/__|__|_\__|___|  |____|

                www.radare.org

                                  --pancake
```

| | |
|----------|---------------------------------------------------------------------|
| **Jenkins**  	| [![Build Status](http://ci.rada.re/buildStatus/icon?job=radare2)](http://ci.rada.re/job/radare2)|
| **TravisCI** 	| [![Build Status](https://travis-ci.org/radare/radare2.svg?branch=master)](https://travis-ci.org/radare/radare2)|
| **AppVeyor**  | [![Build Status](https://ci.appveyor.com/api/projects/status/v9bxvsb1p6c3cmf9/branch/master?svg=true)](https://ci.appveyor.com/project/radare/radare2-shvdd)|
| **Coverity** 	| [![Build Status](https://scan.coverity.com/projects/416/badge.svg)](https://scan.coverity.com/projects/416) |
# Introduction

r2 is a rewrite from scratch of radare in order to provide
a set of libraries and tools to work with binary files.

Radare project started as a forensics tool, a scriptable
commandline hexadecimal editor able to open disk files,
but later support for analyzing binaries, disassembling
code, debugging programs, attaching to remote gdb servers, ..

   radare2 is portable.

   * **Architectures:**
	* 6502, 8051, CRIS, H8/300, LH5801, T8200, arc, arm, avr, bf, blackfin, xap,
   dalvik, dcpu16, gameboy, i386, i4004, i8080, m68k, malbolge, mips, msil,
   msp430, nios II, powerpc, rar, sh, snes, sparc, tms320 (c54x c55x c55+), V810,
   x86-64, zimg, risc-v.

   * **File Formats:**
	* bios, CGC, dex, elf, elf64, filesystem, java, fatmach0, mach0,
   mach0-64, MZ, PE, PE+, TE, COFF, plan9, dyldcache, Commodore VICE emulator,
   Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs.

   * **Operating Systems:**
	* Android, GNU/Linux, [Net|Free|Open]BSD, iOS, OSX, QNX, w32,
   w64, Solaris, Haiku, FirefoxOS

   * **Bindings:**
	* Vala/Genie, Python (2, 3), NodeJS, Lua, Go, Perl,
   Guile, php5, newlisp, Ruby, Java, OCaml, ...

# Dependencies

radare2 can be built without any special dependency, just
use make and get a working toolchain (gcc, clang, tcc, ..)

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

The sys/install.sh method uses acr+make to build r2 from sources, which is the default
and recommended way, but there's also a work-in-progress support for Meson.

You can install last version of meson and ninja using r2pm:

	$ r2pm -i meson
	$ r2pm -r make meson
	$ r2pm -r make meson-symstall

Or just run this line if you have them available in PATH:

        $ python ./sys/meson.py --prefix=/usr --shared --install

Alternatively you can try these lines (but it is just a wrapper around the above script):

        $ ./configure
	$ make meson
	$ sudo make meson-symstall  # symstall the meson build into PREFIX (/usr)
	$ sudo make meson-uninstall # uninstall the meson installation

But if you do it via the Makefile, note that the PREFIX is inherited from the last run
of ./configure, so it's recommended to run sys/install.sh at least once to autodetect this,
this step will end up into meson.

At the moment, the meson build system doesnt supports much configuration options and it
is not able to build all the plugins, it has been tested to work on the following hosts:

* Rpi3-arm32
* macOS-x86-64
* Termux/Android-arm64
* VoidLinux-x86-64
* Windows-x86-64

# Update

To update Radare2 system wide you don't need to uninstall or pull,
just re-run:

	$ sys/install.sh

If you installed Radare2 in the home directory,
just re-run:

	$ sys/user.sh

# Uninstall

In case of a polluted filesystem you can uninstall the current
version or remove all previous installations:

	$ make uninstall
	$ make purge

# Package manager

Radare2 has its own package manager - r2pm. It's packages
repository is on [GitHub too](https://github.com/radare/radare2-pm).
To start to use it for the first time you need to initialize packages:

	$ r2pm init

Refresh the packages database before installing any package:

	$ r2pm update

To install a package use the following command:

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

In addition there are `r2pipe` bindings, which are an API
interface to interact with the prompt, passing commands
and receivent the output as a string, many commands support
JSON output, so it's integrated easily with many languages
in order to deserialize it into native objects.

	$ npm install r2pipe   # NodeJS
	$ gem install r2pipe   # Ruby
	$ pip install r2pipe   # Python
	$ opam install radare2 # OCaml

And also for Go, Rust, Swift, D, .NET, Java, NewLisp, Perl, Haskell,
Vala, OCaml, and many more to come!

# Regression Testsuite

Running `make tests` it will fetch the radare2-regressions
repository and run all the tests in order to verify that no
changes break a functionality.

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
for scripting and interacting with the apis.

You could also checkout the [radare2 book](https://radare.gitbooks.io/radare2book/content/).

# Coding Style

Look at [CONTRIBUTING.md](https://github.com/radare/radare2/blob/master/CONTRIBUTING.md).

# Webserver

radare2 comes with an embedded webserver that serves a pure
html/js interface that sends ajax queries to the core and
aims to implement an usable UI for phones, tablets and desktops.

	$ r2 -c=H /bin/ls

To use the webserver on Windows, you require a cmd instance
with administrator rights. To start the webserver use command
in the project root.

	> radare2.exe -c=H rax2.exe

# Pointers

Website: http://www.radare.org/

IRC: irc.freenode.net #radare

Telegram: https://t.me/radare

Matrix: @radare2:matrix.org

Twitter: @radareorg

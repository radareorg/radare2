```
 ____  ___  ___  ___ ____  ___   ____
|  _ \/   \|   \/   \  _ \/ _ \ (__  \
|    (  -  | |  ) -  |   (   _/ /  __/
|__\__|_|__|___/__|__|_\__|___| |____|

             https://www.radare.org

                             --pancake
```

| **Build&Test** | [![Tests Status](https://github.com/radareorg/radare2/workflows/CI/badge.svg)](https://github.com/radareorg/radare2/actions?query=workflow%3A%22CI%22) | [![Build Status](https://travis-ci.com/radareorg/radare2.svg?branch=master)](https://travis-ci.com/radareorg/radare2)|
|----------|------|--------|
| **CodeQuality** | [![Build Status](https://scan.coverity.com/projects/416/badge.svg)](https://scan.coverity.com/projects/416) | [![Total alerts](https://img.shields.io/lgtm/alerts/g/radareorg/radare2.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/radareorg/radare2/alerts/) |
| **Coverage** | [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/741/badge)](https://bestpractices.coreinfrastructure.org/projects/741) | [![codecov](https://codecov.io/gh/radareorg/radare2/branch/master/graph/badge.svg)](https://codecov.io/gh/radareorg/radare2) |
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

## Learn More

To learn more you may read the [official radare2 book](https://book.rada.re),
the source code, or browse the web for blog posts or presentations from
[r2con](https://www.youtube.com/c/r2con).

You may also want to meet other people in r2land. use the following chats:

* irc.freenode.net `#radare` `#radare_side`
* [Telegram](https://t.me/radare)
* [Discord](https://discord.gg/MgEdxrMnqx)
* Twitter: [@radareorg](https://twitter.com/radareorg)

Website: [https://www.radare.org/](https://www.radare.org/)

## Operating Systems

Windows (since XP), GNU/Linux, GNU/Darwin, GNU/Hurd, Apple's {Mac,i,iPad,watch}OS,
[Dragonfly|Net|Free|Open]BSD, Android, QNX, Solaris, Haiku, FirefoxOS.

## Architectures

i386, x86-64, ARM, MIPS, PowerPC, SPARC, RISC-V, SH, m68k, m680x, AVR,
XAP, System Z, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300, V810,
V850, CRIS, XAP, PIC, LM32, 8051, 6502, i4004, i8080, Propeller,
Tricore, CHIP-8, LH5801, T8200, GameBoy, SNES, SPC700, MSP430, Xtensa,
NIOS II, Java, Dalvik, WebAssembly, MSIL, EBC, TMS320 (c54x, c55x,
c55+, c66), Hexagon, Brainfuck, Malbolge, whitespace, DCPU16, LANAI,
MCORE, mcs96, RSP, SuperH-4, VAX, AMD Am29000.

## File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, OMF, TE, XBE, BIOS/UEFI,
Dyldcache, DEX, ART, CGC, Java class, Android boot image, Plan9 executable,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump),
WASM (WebAssembly binary), Commodore VICE emulator, QNX,
Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs, various filesystems.

## Scripting

Native bindings are supported but the recommended way to interact with r2
from other languages is by using [r2pipe](https://github.com/radareorg/radare2-r2pipe)

Python, Ruby, JavaScript, Lua, Perl, PHP, Go, Rust, Swift, C#, Java,
Shell, OCaml, Haskell, Scheme (Guile), Common Lisp, Clojure, Erlang, D,
Vala/Genie, Prolog, Nim, Newlisp...

# Install / Update

The recommended way to install or update radare2 from git for single-user systems:

	$ sys/install.sh

If you don't have root, or just want to install it in your home use:

	$ sys/user.sh

Note that those scripts will install using configure+make using symlinks, so you
don't need to reinstall every time you change something in the builddir.

* If you don't like symlinks use `sys/install.sh --install`
* To use capstone5 use the `--with-capstone5` flag.

Alternatively you can also build with meson + ninja:

	$ sys/meson.py --prefix=/usr --shared --install

Or install in your home with meson + ninja:

	$ sys/meson.py --prefix=$HOME/r2meson --local --shared --install

## Uninstall

In case of a polluted filesystem, you can uninstall the current
version or remove all previous installations:

	$ make uninstall
	$ make purge

To remove all stuff including libraries, use

	$ make system-purge

## Package Manager

Radare2 has its own package manager - r2pm. Its packages
repository is on [GitHub too](https://github.com/radareorg/radare2-pm).
To start to using it for the first time, you need to initialize packages:

	$ r2pm init

Refresh the packages database before installing any package:

	$ r2pm update

To install a package, use the following command:

	$ r2pm install [package name]

# Development

## Coding Style

Look at [CONTRIBUTING.md](https://github.com/radareorg/radare2/blob/master/CONTRIBUTING.md).

## Tests

Running `make tests` will fetch the test binaries
repository and run all the tests in order to verify that no changes break any functionality.

We run those tests on every commit, and they are also executed with ASAN
and valgrind on different platforms to catch other unwanted 'features'.

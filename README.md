```
 ___  __  ___  __ ___  ___   ____
| _ \/  \|   \/  \ _ \/ _ \ (__  \
|   (  - | |  ) - |  (   _/ /  __/
|_\__|_|_|___/__|_|_\_|___| |____|

      https://www.radare.org

                        --pancake
```

| **Build&Test** | [![Tests Status](https://github.com/radareorg/radare2/workflows/CI/badge.svg)](https://github.com/radareorg/radare2/actions?query=workflow%3A%22CI%22) | [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/741/badge)](https://bestpractices.coreinfrastructure.org/projects/741) |
|----------|------|--------|
| **CodeQuality** | [![Build Status](https://scan.coverity.com/projects/416/badge.svg)](https://scan.coverity.com/projects/416) | [![Total alerts](https://img.shields.io/lgtm/alerts/g/radareorg/radare2.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/radareorg/radare2/alerts/) |
<a href="https://repology.org/metapackage/radare2">
<img src="https://repology.org/badge/vertical-allrepos/radare2.svg" alt="Packaging status" align="right" width="150px">
</a>

# Libre Reverse Engineering Framework

r2 is a rewrite from scratch of radare. It provies a set of
libraries, tools and plugins to ease reverse engineering tasks.

The radare project started as a forensics tool, a scriptable
command-line hexadecimal editor able to open disk files,
but later added support for analyzing binaries, disassembling
code, debugging programs, attaching to remote gdb servers...

<img src="doc/images/shot.png" alt="screenshot" align="center" width="600px">

## Installation

The [GHA CI](https://github.com/radareorg/radare2/actions) builds the packages for every commit and those are also
available in the [release](https://github.com/radareorg/radare2/releases) page. But it is always recommended to
install r2 from git.

The most used and recommend way is by running this script which will build
and install r2 from sources and install it system wide with symlinks.

```
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

If you need to install it in your user's home or switch between multiple
r2 builds you may checkout the `meson` build and [r2env]().

	* If you don't like symlinks use `sys/install.sh --install`
	* To use capstone5 use the `--with-capstone5` flag.

	Alternatively you can also build with meson + ninja:

		$ sys/meson.py --prefix=/usr --shared --install

	Or install in your home with meson + ninja:

		$ sys/meson.py --prefix=$HOME/r2meson --local --shared --install


r2env allows to build and install different versions of r2 in your home
or system and it is available via Python's PIP tool.

```
pip install r2env
r2env init
r2env add radare2
```

## Scripting

There are native API bindings available for many programming languages,
but it is recommended to use [r2pipe](https://github.com/radareorg/radare2-r2pipe) which is a simple interface to
execute r2 commands and get the output in result. Appending a `j` in the
commands the output will be in JSON, so it can be parsed with `.cmdj()`

Some of the languages supported by r2 are: Python, Ruby, JavaScript,
Lua, Perl, PHP, V, Go, Rust, Swift, C#, Java, Shell, OCaml, Haskell,
Scheme (Guile), Common Lisp, Clojure, Erlang, D, Vala/Genie, Prolog,
Nim, Newlisp...

## Supported Operating Systems

Windows (since XP), Linux, Darwin, GNU/Hurd, Apple's {Mac,i,iPad,watch}OS,
[Dragonfly|Net|Free|Open]BSD, Android, Z/OS, QNX, Solaris, Haiku, FirefoxOS.

## Architectures

i386, x86-64, ARM, MIPS, PowerPC, SPARC, RISC-V, SH, m68k, m680x, AVR,
XAP, S390, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300, V810,
V850, CRIS, XAP, PIC, LM32, 8051, 6502, i4004, i8080, Propeller,
Tricore, CHIP-8, LH5801, T8200, GameBoy, SNES, SPC700, MSP430, Xtensa,
NIOS II, Java, Dalvik, WebAssembly, MSIL, EBC, TMS320 (c54x, c55x,
c55+, c66), Hexagon, Brainfuck, Malbolge, whitespace, DCPU16, LANAI,
MCORE, mcs96, RSP, SuperH-4, VAX, AMD Am29000.

## File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, OMF, TE, XBE, BIOS/UEFI,
Dyldcache, DEX, ART, CGC, Java class, Android boot image, Plan9 executable,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump),
WASM (WebAssembly binary), Commodore VICE emulator, QNX, WAD, OFF,
Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs, various filesystems.

## Uninstall

In case of a polluted filesystem, you can uninstall the current version
or remove all previous installations with one or more of those commands:

```
make uninstall
make system-purge
make purge
git clean -xdf
rm -rf shlr/capstone
```

## Package Manager

Radare2 has its own package manager - r2pm. Its packages
repository is on [GitHub too](https://github.com/radareorg/radare2-pm).
To start to using it for the first time, you need to initialize packages:

```
r2pm update          # initialize and update the package database
r2pm install [pkg]   # installs the package
```

# Contributing

There are many ways to contribute to the project, join the c

## Coding Style

Look at [CONTRIBUTING.md](https://github.com/radareorg/radare2/blob/master/CONTRIBUTING.md).

## Testsuite

Use the `r2r` tool to run the tests that are under the `tests/` subdirectory.

## Community and Documentation

To learn more about r2 we encourage you to watch youtube talks from
[r2con](https://www.youtube.com/c/r2con). As well as reading blogposts,
slides or read the [official radare2 book](https://book.rada.re), You can reach us in the following chats:

* irc.libera.chat `#radare` `#radare_side`
* [Matrix](https://matrix.org/) `#radare:matrix.org`
* [Telegram](https://t.me/radare) and the [Side Channel](https://t.me/radare_side)
* [Discord](https://discord.gg/MgEdxrMnqx)
* Twitter: [@radareorg](https://twitter.com/radareorg)
* Website: [https://www.radare.org/](https://www.radare.org/)

## Additional resources

 * [CONTRIBUTING.md][]
 * [DEVELOPERS.md][]

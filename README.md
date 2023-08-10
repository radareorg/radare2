<a href="https://radare.org/"><img border=0 src="doc/images/r2emoji.png" alt="screenshot" align="left" width="128px"></a>

## Radare2: Libre Reversing Framework for Unix Geeks

[![Latest packaged version](https://repology.org/badge/latest-versions/radare2.svg)](https://repology.org/project/radare2/versions) [![Tests Status](https://github.com/radareorg/radare2/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/ci.yml?query=branch%3Amaster) [![build](https://github.com/radareorg/radare2/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/build.yml?query=branch%3Amaster) [![tcc](https://github.com/radareorg/radare2/actions/workflows/tcc.yml/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/tcc.yml)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/741/badge)](https://bestpractices.coreinfrastructure.org/projects/741) [![Build Status](https://scan.coverity.com/projects/416/badge.svg)](https://scan.coverity.com/projects/416) [![Discord](https://badgen.net/discord/members/YBey7CR9jf)](https://discord.gg/YBey7CR9jf)

See the [Releases](https://github.com/radareorg/radare2/releases) page for
downloads. The current git `master` branch is `5.8.9`, next will be `5.9.0`.

* Since r2-5.6.0 all the patch releases are [abi stable](doc/abi.md)
* Odd patch versions are used in git builds only, releases use even numbers
* No need to recompile the plugins, bindings or tools if the major and minor version are the same

### Description

r2 is a complete rewrite of radare. It provides a set of libraries, tools and
plugins to ease reverse engineering tasks. Distributed mostly under LGPLv3,
each plugin can have different licenses (see r2 -L, rasm2 -L, ...).

The radare project started as a simple command-line hexadecimal editor focused
on forensics. Today, r2 is a featureful low-level command-line tool with
support for scripting. r2 can edit files on local hard drives, view kernel
memory, and debug programs locally or via a remote gdb server. r2's wide
architecture support allows you to analyze, emulate, debug, modify, and
disassemble any binary.

<p align="center">
<a href="https://www.radare.org/"><img src="doc/images/shot.png" alt="screenshot" align="center" border=0 width="600px"></a>
</p>

## Installation

* r2 can be installed from `git` or via `pip` using `r2env`.
* Run `sys/install.sh` for the default acr+make+symlink installation
* meson/ninja (muon/samu also works) and make builds are supported.
* Windows builds require meson and msvc or mingw as compilers
* To uninstall the current build of r2 run `make uninstall`
* To uninstall ALL the system installations of r2 do: `sudo make purge`

```sh
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

Default Windows builds use MSVC, so run those `.bat`:

```sh
preconfigure.bat       REM setup python, meson, ninja
configure.bat          REM run meson b + vs project
make.bat               REM run ninja -C b
prefix\bin\radare2.exe
```

Alternatively you can use r2env to switch between different versions.

```sh
pip install -U r2env
r2env init
r2env add radare2@git
```

## Usage

These are the first steps to use r2, read the book or find tutorials for more details

```sh
$ r2 /bin/ls   # open file in read-only
> aaa          # analyse the program (r2 -A)
> afl          # list all functions (try aflt, aflm)
> px 32        # print 32 byte hexdump current block
> s sym.main   # seek to main (using flag name)
> f~foo        # filter flags matching 'foo' (internal |grep)
> iS;is        # list sections and symbols (rabin2 -Ss)
> pdf; agf     # disassembly and ascii-art function graph
> oo+;w hello  # reopen in read-write and write a string
> ?*~...       # interactive filter in all command help
> q            # quit
```

## Resources

* [Official Book](https://book.rada.re): Read about r2 usage
* [COMMUNITY.md](COMMUNITY.md): Community engagement and loose guidelines
* [CONTRIBUTING.md](CONTRIBUTING.md): Information about reporting issues and
  contributing. See also [Contributing](#contributing)
* [DEVELOPERS.md](DEVELOPERS.md): Development guidelines for r2
* [SECURITY.md](SECURITY.md): Instructions for reporting vulnerabilities
* [USAGE.md](USAGE.md): Some example commands
* [INSTALL.md](INSTALL.md): Installation instructions using make or meson

## Plugins

Many plugins are included in r2 by default. But you can extend its capabilities
by using the [r2pm](https://github.com/radareorg/radare2-pm) package manager.

```sh
r2pm -s <word> # search package by word
r2pm -ci <pkg> # install a package
r2pm -u <pkg>  # uninstall
r2pm -l <pkg>  # list installed packages
```

Most popular packages are:

* [esilsolve](https://github.com/radareorg/esilsolve): The symbolic execution plugin, based on esil and z3
* [r2diaphora](https://github.com/FernandoDoming/r2diaphora): [Diaphora](https://github.com/joxeankoret/diaphora)'s diffing engine working on top of radare2
* [iaito](https://github.com/radareorg/iaito): The official Qt graphical interface
* [radius2](https://github.com/nowsecure/radius2): A fast symbolic execution engine based on boolector and esil
* [r2dec](https://github.com/wargio/r2dec-js): A decompiler based on r2 written in JS, accessed with the `pdd` command
* [r2ghidra](https://github.com/radareorg/r2ghidra): The native ghidra decompiler plugin, accessed with the `pdg` command
* [r2frida](https://github.com/nowsecure/r2frida): The frida io plugin. Start r2 with `r2 frida://0` to use it
* [r2poke](https://github.com/radareorg/radare2-extras/tree/master/r2poke) Integration with GNU/Poke for extended binary parsing capabilities
* [r2pipe](https://github.com/radareorg/radare2-r2pipe) Script radare2 from any programming language
* [r2papi](https://github.com/radareorg/radare2-r2papi) High level api on top of r2pipe

# Contributing

There are many ways to contribute to the project. Contact the
[community](#community), check out the github issues, or grep for
TODO/FIXME/XXX comments in the source.

To contribute code, push your changes to a branch on your fork of the
repository. Please ensure that you follow the coding and style guidelines and
that your changes pass the testing suite, which you can run with the `r2r`
tool. If you are adding significant code, it may be necessary to modify or add
additional tests in the `test/` directory.

For more details, see [CONTRIBUTING.md](CONTRIBUTING.md) and
[DEVELOPERS.md](DEVELOPERS.md).

## Documentation

To learn more about r2 we encourage you to watch [youtube
talks](https://www.youtube.com/c/r2con) from [r2con](https://rada.re/con). In
addition to reading blogposts, slides or the [official radare2
book](https://book.rada.re), here are some methods to contact us:

## Community

* [irc.libera.chat](https://libera.chat): `#radare`, `#radare_side`
* [Matrix](https://matrix.to/#/#radare:matrix.org): `#radare:matrix.org`
* Telegram: [Main Channel](https://t.me/radare) and [Side Channel](https://t.me/radare_side)
* [Discord server](https://discord.gg/YBey7CR9jf)

* Mastodon: [@radareorg](https://infosec.exchange/@radareorg)
* Website: [https://www.radare.org/](https://www.radare.org/)

# Supported Platforms

## Operating Systems

Windows (since XP), Linux, Darwin, GNU/Hurd, Apple's {Mac,i,iPad,watch}OS, Android,
[Dragonfly, Net, Free, Open] BSD, Z/OS, QNX, SerenityOS, Solaris, Haiku, Vinix, FirefoxOS.

## Architectures

i386, x86-64, Alpha, ARM, AVR, BPF, MIPS, PowerPC, SPARC, RISC-V, SH, m68k,
S390, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300, V810, PDP11, m680x, V850,
CRIS, XAP (CSR), PIC, LM32, 8051, 6502, i4004, i8080, Propeller, EVM, OR1K
Tricore, CHIP-8, LH5801, T8200, GameBoy, SNES, SPC700, MSP430, Xtensa, xcore,
NIOS II, Java, Dalvik, Pickle, WebAssembly, MSIL, EBC, TMS320 (c54x, c55x,
c55+, c64x), Hexagon, Brainfuck, Malbolge, whitespace, DCPU16, LANAI, lm32,
MCORE, mcs96, RSP, SuperH-4, VAX, KVX, Am29000, LOONGARCH, JDH8, s390x.

## File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, XCOFF, OMF, TE, XBE, SEP64, BIOS/UEFI, 
Dyldcache, DEX, ART, CGC, Java class, Android boot image, Plan9 executables,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump), PDP11, XTAC,
WASM (WebAssembly binary), Commodore VICE emulator, QNX, WAD, OFF, TIC-80,
GB/GBA, NDS and N3DS, and mount several filesystems like NTFS, FAT, HFS+, EXT,...

## Packaging Status

* [![Snap package](https://snapcraft.io/radare2/badge.svg)](https://snapcraft.io/radare2)
* [![Termux package](https://repology.org/badge/version-for-repo/termux/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Alpine Linux Edge package](https://repology.org/badge/version-for-repo/alpine_edge/radare2.svg)](https://repology.org/project/radare2/versions) [![Alpine Linux 3.13 package](https://repology.org/badge/version-for-repo/alpine_3_13/radare2.svg)](https://repology.org/project/radare2/versions) [![Alpine Linux 3.12 package](https://repology.org/badge/version-for-repo/alpine_3_12/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Arch package](https://repology.org/badge/version-for-repo/arch/radare2.svg)](https://repology.org/project/radare2/versions) [![AUR package](https://repology.org/badge/version-for-repo/aur/radare2.svg)](https://repology.org/project/radare2/versions)
* [![EPEL 7 package](https://repology.org/badge/version-for-repo/epel_7/radare2.svg)](https://repology.org/project/radare2/versions)
* [![EPEL 8 package](https://repology.org/badge/version-for-repo/epel_8/radare2.svg)](https://repology.org/project/radare2/versions)
* [![EPEL 9 package](https://repology.org/badge/version-for-repo/epel_9/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Fedora Dev](https://repology.org/badge/version-for-repo/fedora_rawhide/radare2.svg)](https://repology.org/project/radare2/versions) [![Fedora 36](https://repology.org/badge/version-for-repo/fedora_36/radare2.svg)](https://repology.org/project/radare2/versions) [![Fedora 34](https://repology.org/badge/version-for-repo/fedora_34/radare2.svg)](https://repology.org/project/radare2/versions)
* [![FreeBSD port](https://repology.org/badge/version-for-repo/freebsd/radare2.svg)](https://repology.org/project/radare2/versions) [![OpenBSD port](https://repology.org/badge/version-for-repo/openbsd/radare2.svg)](https://repology.org/project/radare2/versions) [![pkgsrc current package](https://repology.org/badge/version-for-repo/pkgsrc_current/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Homebrew package](https://repology.org/badge/version-for-repo/homebrew/radare2.svg)](https://repology.org/project/radare2/versions) [![MacPorts package](https://repology.org/badge/version-for-repo/macports/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Haiku Ports](https://repology.org/badge/version-for-repo/haikuports_master/radare2.svg)](https://repology.org/project/radare2/versions) [![Void Linux](https://repology.org/badge/version-for-repo/void_x86_64/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Ubuntu 20.04 package](https://repology.org/badge/version-for-repo/ubuntu_20_04/radare2.svg)](https://repology.org/project/radare2/versions) [![Ubuntu 18.04 package](https://repology.org/badge/version-for-repo/ubuntu_18_04/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Debian Unstable package](https://repology.org/badge/version-for-repo/debian_unstable/radare2.svg)](https://repology.org/project/radare2/versions) [![Raspbian Stable package](https://repology.org/badge/version-for-repo/raspbian_stable/radare2.svg)](https://repology.org/project/radare2/versions) [![Kali Linux Rolling package](https://repology.org/badge/version-for-repo/kali_rolling/radare2.svg)](https://repology.org/project/radare2/versions)

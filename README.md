<a href="https://radare.org/"><img border=0 src="doc/images/r2emoji.png" alt="screenshot" align="left" width="128px"></a>

## Radare2: Libre Reversing Framework for Unix Geeks

[![Latest packaged version](https://repology.org/badge/latest-versions/radare2.svg)](https://repology.org/project/radare2/versions) [![Tests Status](https://github.com/radareorg/radare2/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/ci.yml?query=branch%3Amaster) [![build](https://github.com/radareorg/radare2/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/build.yml?query=branch%3Amaster) [![tcc](https://github.com/radareorg/radare2/actions/workflows/tcc.yml/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/tcc.yml)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/741/badge)](https://bestpractices.coreinfrastructure.org/projects/741) [![Build Status](https://scan.coverity.com/projects/416/badge.svg)](https://scan.coverity.com/projects/416) [![Discord](https://badgen.net/discord/members/YBey7CR9jf)](https://discord.gg/YBey7CR9jf)

See the [Releases](https://github.com/radareorg/radare2/releases) page for
downloads. The current git `master` branch is `5.9.9`, next will be `6.0.0`.

* Since 5.6.0, patch releases are [abi stable](doc/abi.md)
* Even patch numbers used for releases, odd ones for git.
* .9 patch versions reflect the abi breaking seasson

### Description

r2 is a complete rewrite of radare. It provides a set of libraries, tools and
plugins to ease reverse engineering tasks. Distributed mostly under LGPLv3,
each plugin can have different licenses (see r2 -L, rasm2 -L, ...).

The radare project started as a simple command-line hexadecimal editor focused
on forensics. Today, r2 is a featureful low-level command-line tool with
support for scripting with the embedded Javascript interpreter or via r2pipe.

r2 can edit files on local hard drives, view kernel memory, and debug programs
locally or via a remote gdb/windbg servers. r2's wide architecture support allows
you to analyze, emulate, debug, modify, and disassemble any binary.

<p align="center">
<a href="https://www.radare.org/"><img src="doc/images/shot.png" alt="screenshot" align="center" border=0 width="600px"></a>
</p>

## Installation

The recommended way to install radare2 is via Git using acr/make or meson:

```sh
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

On Windows you may want to use the precompiled builds or the .bat files to compile if you have msvc:

```bat
preconfigure.bat       REM setup python, meson, ninja
configure.bat          REM run meson b + vs project
make.bat               REM run ninja -C b
prefix\bin\radare2.exe
```

* r2 can be installed from `git` or via `pip` using `r2env`.
* Run `sys/install.sh` for the default acr+make+symlink installation
* meson/ninja (muon/samu also works) and make builds are supported.
* Windows builds require meson and msvc or mingw as compilers
* To uninstall the current build of r2 run `make uninstall`
* To uninstall ALL the system installations of r2 do: `sudo make purge`

## Popular Plugins:

Using the `r2pm` tool you can browse and install many plugins and tools that use radare2.

* [esilsolve](https://github.com/radareorg/esilsolve): The symbolic execution plugin, based on esil and z3
* [iaito](https://github.com/radareorg/iaito): The official Qt graphical interface
* [keystone](https://github.com/radareorg/radare2-extras/tree/master/keystone) Assembler instructions using the Keystone library
* [decai](https://github.com/radareorg/r2ai) Decompiler based on AI
* [r2ai](https://github.com/radareorg/r2ai) Run a Language Model in localhost with Llama inside r2!
* [r2dec](https://github.com/wargio/r2dec-js): A decompiler based on r2 written in JS, accessed with the `pdd` command
* [r2diaphora](https://github.com/FernandoDoming/r2diaphora): [Diaphora](https://github.com/joxeankoret/diaphora)'s binary diffing engine on top of radare2
* [r2frida](https://github.com/nowsecure/r2frida): The frida io plugin. Start r2 with `r2 frida://0` to use it
* [r2ghidra](https://github.com/radareorg/r2ghidra): The standalone native ghidra decompiler accessible with `pdg`
* [r2papi](https://github.com/radareorg/radare2-r2papi) High level api on top of r2pipe
* [r2pipe](https://github.com/radareorg/radare2-r2pipe) Script radare2 from any programming language
* [r2poke](https://github.com/radareorg/radare2-extras/tree/master/r2poke) Integration with GNU/Poke for extended binary parsing capabilities
* [goresym](https://github.com/hanemile/radare2-GoReSym): Import GoReSym symbol as flags
* [r2yara](https://github.com/radareorg/r2yara) Run Yara from r2 or use r2 primitives from Yara
* [radius2](https://github.com/nowsecure/radius2): A fast symbolic execution engine based on boolector and esil
* [r2sarif](https://github.com/radareorg/r2sarif) import/extend/export SARIF documents

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

Many plugins are included in r2 by default. But you can extend its capabilities
by using the [r2pm](https://github.com/radareorg/radare2-pm) package manager.

```sh
r2pm -s <word>  # search packages matching a word
r2pm -Uci <pkg> # update database and clean install a package
r2pm -u <pkg>   # uninstall the given package
r2pm -l <pkg>   # list installed packages
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

## Documentation

Learn more about r2 watching [youtube talks](https://www.youtube.com/c/r2con) from [r2con](https://rada.re/con). There are also many blogposts, slidedecks and the [official radare2 book](https://book.rada.re), but it's always a good idea to join any of the official chats and drop your questions or feedback there.

## Community

* [irc.libera.chat](https://libera.chat): `#radare`, `#radare_side`
* [Matrix](https://matrix.to/#/#radare:matrix.org): `#radare:matrix.org`
* Telegram: [Main](https://t.me/radare) and [Side](https://t.me/radare_side) channels
* Discord: [Server](https://discord.gg/YBey7CR9jf)
* Mastodon: [@radareorg](https://infosec.exchange/@radareorg)
* Website: [https://www.radare.org/](https://www.radare.org/)

# Supported Platforms

## Operating Systems

Windows (since XP), Linux, Darwin, GNU/Hurd, Apple's {Mac,i,iPad,watch}OS, Android, Wasmer,
[Dragonfly, Net, Free, Open] BSD, Z/OS, QNX, SerenityOS, Solaris, AIX, Haiku, Vinix, FirefoxOS.

## Architectures

i386, x86-64, Alpha, ARM, AVR, BPF, MIPS, PowerPC, SPARC, RISC-V, SH, m68k,
S390, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300, V810, PDP11, m680x, V850,
CRIS, XAP (CSR), PIC, LM32, 8051, 6502, i4004, i8080, Propeller, EVM, OR1K
Tricore, CHIP-8, LH5801, T8200, GameBoy, SNES, SPC700, MSP430, Xtensa, xcore,
NIOS II, Java, Dalvik, Pickle, WebAssembly, MSIL, EBC, TMS320 (c54x, c55x,
c55+, c64x), Hexagon, Brainfuck, Malbolge, whitespace, DCPU16, LANAI, lm32,
MCORE, mcs96, RSP, SuperH-4, VAX, KVX, Am29000, LOONGARCH, JDH8, s390x, STM8.

## File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, XCOFF, OMF, TE, XBE, SEP64, BIOS/UEFI,
Dyldcache, DEX, ART, Java class, Android boot image, Plan9 executables, Amiga HUNK,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump), PDP11, XTAC, CGC,
WASM (WebAssembly binary), Commodore VICE emulator, QNX, WAD, OFF, TIC-80,
GB/GBA, NDS and N3DS, and mount several filesystems like NTFS, FAT, HFS+, EXT,...

## Packaging Status

* [![Snap package](https://snapcraft.io/radare2/badge.svg)](https://snapcraft.io/radare2)
* [![Termux package](https://repology.org/badge/version-for-repo/termux/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Alpine Linux Edge package](https://repology.org/badge/version-for-repo/alpine_edge/radare2.svg)](https://repology.org/project/radare2/versions) [![Alpine Linux 3.20 package](https://repology.org/badge/version-for-repo/alpine_3_20/radare2.svg)](https://repology.org/project/radare2/versions) [![Alpine Linux 3.19 package](https://repology.org/badge/version-for-repo/alpine_3_19/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Arch package](https://repology.org/badge/version-for-repo/arch/radare2.svg)](https://repology.org/project/radare2/versions) [![AUR package](https://repology.org/badge/version-for-repo/aur/radare2.svg)](https://repology.org/project/radare2/versions)
* [![EPEL 10 package](https://repology.org/badge/version-for-repo/epel_10/radare2.svg)](https://repology.org/project/radare2/versions) [![EPEL 9 package](https://repology.org/badge/version-for-repo/epel_9/radare2.svg)](https://repology.org/project/radare2/versions) [![EPEL 8 package](https://repology.org/badge/version-for-repo/epel_8/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Fedora Dev](https://repology.org/badge/version-for-repo/fedora_rawhide/radare2.svg)](https://repology.org/project/radare2/versions) [![Fedora 41](https://repology.org/badge/version-for-repo/fedora_41/radare2.svg)](https://repology.org/project/radare2/versions) [![Fedora 40](https://repology.org/badge/version-for-repo/fedora_40/radare2.svg)](https://repology.org/project/radare2/versions)
* [![FreeBSD port](https://repology.org/badge/version-for-repo/freebsd/radare2.svg)](https://repology.org/project/radare2/versions) [![OpenBSD port](https://repology.org/badge/version-for-repo/openbsd/radare2.svg)](https://repology.org/project/radare2/versions) [![pkgsrc current package](https://repology.org/badge/version-for-repo/pkgsrc_current/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Homebrew package](https://repology.org/badge/version-for-repo/homebrew/radare2.svg)](https://repology.org/project/radare2/versions) [![MacPorts package](https://repology.org/badge/version-for-repo/macports/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Haiku Ports](https://repology.org/badge/version-for-repo/haikuports_master/radare2.svg)](https://repology.org/project/radare2/versions) [![Void Linux](https://repology.org/badge/version-for-repo/void_x86_64/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Ubuntu 24.10 package](https://repology.org/badge/version-for-repo/ubuntu_24_10/radare2.svg)](https://repology.org/project/radare2/versions) [![Ubuntu 24.04 package](https://repology.org/badge/version-for-repo/ubuntu_24_04/radare2.svg)](https://repology.org/project/radare2/versions) [![Ubuntu 20.04 package](https://repology.org/badge/version-for-repo/ubuntu_20_04/radare2.svg)](https://repology.org/project/radare2/versions) [![Ubuntu 18.04 package](https://repology.org/badge/version-for-repo/ubuntu_18_04/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Debian Unstable package](https://repology.org/badge/version-for-repo/debian_unstable/radare2.svg)](https://repology.org/project/radare2/versions) [![Debian 12 package](https://repology.org/badge/version-for-repo/debian_12/radare2.svg)](https://repology.org/project/radare2/versions)
[![Kali Linux Rolling package](https://repology.org/badge/version-for-repo/kali_rolling/radare2.svg)](https://repology.org/project/radare2/versions)

<img src="doc/images/r2emoji.png" alt="screenshot" align="left" width="128px">

## Radare2: Unix-Like Reverse Engineering Framework

[![Latest packaged version](https://repology.org/badge/latest-versions/radare2.svg)](https://repology.org/project/radare2/versions) [![Tests Status](https://github.com/radareorg/radare2/workflows/CI/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/ci.yml?query=branch%3Amaster) [![freebsd](https://github.com/radareorg/radare2/actions/workflows/freebsd.yml/badge.svg)](https://github.com/radareorg/radare2/actions/workflows/freebsd.yml) [![windows](https://github.com/radareorg/radare2/actions/workflows/windows.yml/badge.svg)](https://github.com/radareorg/radare2/actions/workflows/windows.yml) [![tcc](https://github.com/radareorg/radare2/actions/workflows/tcc.yml/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/tcc.yml)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/741/badge)](https://bestpractices.coreinfrastructure.org/projects/741) [![Build Status](https://scan.coverity.com/projects/416/badge.svg)](https://scan.coverity.com/projects/416) [![Total alerts](https://img.shields.io/lgtm/alerts/g/radareorg/radare2.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/radareorg/radare2/alerts/)

See the [Releases](https://github.com/radareorg/radare2/releases) page for
binary downloads. The current git `master` branch is `5.6.3`, and the next
release will be `5.6.4`.

r2 is a complete rewrite of radare. It provides a set of libraries, tools and
plugins to ease reverse engineering tasks.

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

r2 can be installed via `git` or `pip`.

```sh
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

```sh
pip install r2env
r2env init
r2env add radare2@git
```

## Usage

These are the first steps to use r2, read the book or find tutorials for more details

```sh
$ r2 /bin/ls   # open the binary in read-only mode
> aaa          # same as r2 -A, analyse the binary
> afl          # list all functions (try aflt, aflm)
> px 32        # print 32 byte hexdump current block
> s sym.main   # seek to the given offset (by flag name, number, ..)
> f~foo        # filter flags with ~grep (same as |grep)
> iS;is        # list sections and symbols (same as rabin2 -Ss)
> pdf; agf     # print function and show control-flow-graph in ascii-art
> oo+;w hello  # reopen in rw mode and write a string in the current offset
> ?*~...       # interactive filter all command help messages
> q            # quit
```

## Resources

* [Official radare2 book](https://book.rada.re): Read about r2 usage.
* [COMMUNITY.md](COMMUNITY.md): Community engagement and loose guidelines.
* [CONTRIBUTING.md](CONTRIBUTING.md): Information about reporting issues and
  contributing. See also the [Contributing](#Contributing) section below.
* [DEVELOPERS.md](DEVELOPERS.md): Development guidelines for r2.
* [SECURITY.md](SECURITY.md): Instructions for reporting vulnerabilities.
* [USAGE.md](USAGE.md): Some example commands.
* [INSTALL.md](INSTALL.md): Full instructions for different installation
  methods.

## Plugins

Many plugins are included with r2 by default. You can find more plugins using
the [r2pm](https://github.com/radareorg/radare2-pm) package manager.

```sh
r2pm -ci <pkg> # install a package
```

Some of the most installed packages are:

* [esilsolve](https://github.com/radareorg/esilsolve): The symbolic execution plugin, based on esil and z3.
* [iaito](https://github.com/radareorg/iaito): The official Qt graphical interface.
* [radius](https://github.com/aemmitt-ns/radius): A fast symbolic execution engine based on boolector and r2.
* [r2dec](https://github.com/wargio/r2dec-js): A decompiler based on r2 written in JS, accessed with the `pdd` command.
* [r2ghidra](https://github.com/radareorg/r2ghidra): The native ghidra decompiler plugin, accessed with the `pdg` command.
* [r2frida](https://github.com/nowsecure/r2frida): The frida io plugin. Start r2 with `r2 frida://0` to use it.

# Contributing

There are many ways to contribute to the project. Contact the
[community](#Community), check out the github issues, or grep for
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
* [Discord server](https://discord.gg/MgEdxrMnqx)
* Twitter: [@radareorg](https://twitter.com/radareorg)
* Website: [https://www.radare.org/](https://www.radare.org/)

# Supported Platforms

## Operating Systems

Windows (since XP), Linux, Darwin, GNU/Hurd, Apple's {Mac,i,iPad,watch}OS, Android
[Dragonfly, Net, Free, Open] BSD, Z/OS, QNX, SerenityOS, Solaris, Haiku, Vinix, FirefoxOS.

## Architectures

i386, x86-64, ARM, MIPS, PowerPC, SPARC, RISC-V, SH, m68k, m680x, AVR,
XAP, S390, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300, V810,
V850, CRIS, XAP, PIC, LM32, 8051, 6502, i4004, i8080, Propeller,
Tricore, CHIP-8, LH5801, T8200, GameBoy, SNES, SPC700, MSP430, Xtensa,
NIOS II, Java, Dalvik, WebAssembly, MSIL, EBC, TMS320 (c54x, c55x,
c55+, c66), Hexagon, Brainfuck, Malbolge, whitespace, DCPU16, LANAI,
MCORE, mcs96, RSP, SuperH-4, VAX, AMD Am29000, LOONGARCH.

## File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, OMF, TE, XBE, BIOS/UEFI,
Dyldcache, DEX, ART, CGC, Java class, Android boot image, Plan9 executable,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump),
WASM (WebAssembly binary), Commodore VICE emulator, QNX, WAD, OFF, TIC-80
Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs, various filesystems.

## Packaging Status

* [![Termux package](https://repology.org/badge/version-for-repo/termux/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Alpine Linux Edge package](https://repology.org/badge/version-for-repo/alpine_edge/radare2.svg)](https://repology.org/project/radare2/versions) [![Alpine Linux 3.13 package](https://repology.org/badge/version-for-repo/alpine_3_13/radare2.svg)](https://repology.org/project/radare2/versions) [![Alpine Linux 3.12 package](https://repology.org/badge/version-for-repo/alpine_3_12/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Arch package](https://repology.org/badge/version-for-repo/arch/radare2.svg)](https://repology.org/project/radare2/versions) [![AUR package](https://repology.org/badge/version-for-repo/aur/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Fedora 34 package](https://repology.org/badge/version-for-repo/fedora_34/radare2.svg)](https://repology.org/project/radare2/versions) [![Fedora 32 package](https://repology.org/badge/version-for-repo/fedora_32/radare2.svg)](https://repology.org/project/radare2/versions)
* [![FreeBSD port](https://repology.org/badge/version-for-repo/freebsd/radare2.svg)](https://repology.org/project/radare2/versions) [![OpenBSD port](https://repology.org/badge/version-for-repo/openbsd/radare2.svg)](https://repology.org/project/radare2/versions) [![pkgsrc current package](https://repology.org/badge/version-for-repo/pkgsrc_current/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Homebrew package](https://repology.org/badge/version-for-repo/homebrew/radare2.svg)](https://repology.org/project/radare2/versions) [![MacPorts package](https://repology.org/badge/version-for-repo/macports/radare2.svg)](https://repology.org/project/radare2/versions)
* [![HaikuPorts master package](https://repology.org/badge/version-for-repo/haikuports_master/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Ubuntu 20.04 package](https://repology.org/badge/version-for-repo/ubuntu_20_04/radare2.svg)](https://repology.org/project/radare2/versions) [![Ubuntu 18.04 package](https://repology.org/badge/version-for-repo/ubuntu_18_04/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Debian Unstable package](https://repology.org/badge/version-for-repo/debian_unstable/radare2.svg)](https://repology.org/project/radare2/versions) [![Raspbian Stable package](https://repology.org/badge/version-for-repo/raspbian_stable/radare2.svg)](https://repology.org/project/radare2/versions) [![Kali Linux Rolling package](https://repology.org/badge/version-for-repo/kali_rolling/radare2.svg)](https://repology.org/project/radare2/versions)

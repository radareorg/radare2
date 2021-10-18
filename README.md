<img src="doc/images/r2emoji.png" alt="screenshot" align="left" width="128px">

## Radare2: Unix-Like Reverse Engineering Framework

[![Tests Status](https://github.com/radareorg/radare2/workflows/CI/badge.svg?branch=master)](https://github.com/radareorg/radare2/actions/workflows/ci.yml?query=branch%3Amaster) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/741/badge)](https://bestpractices.coreinfrastructure.org/projects/741) [![Build Status](https://scan.coverity.com/projects/416/badge.svg)](https://scan.coverity.com/projects/416) [![Total alerts](https://img.shields.io/lgtm/alerts/g/radareorg/radare2.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/radareorg/radare2/alerts/) [![TODO counter](https://img.shields.io/github/search/radareorg/radare2/TODO.svg)](https://github.com/radareorg/radare2/search?q=TODO) [![XXX counter](https://img.shields.io/github/search/radareorg/radare2/XXX.svg)](https://github.com/radareorg/radare2/search?q=XXX)

Next release will be 5.5.0, current git is 5.4.3 and the [![latest packaged version(s)](https://repology.org/badge/latest-versions/radare2.svg)](https://repology.org/project/radare2/versions) See the [Release](https://github.com/radareorg/radare2/releases) downloads page.

r2 is a rewrite from scratch of radare. It provies a set of libraries, tools and
plugins to ease reverse engineering tasks.

The radare project started as a simple command-line hexadecimal editor focused on
forensics, over time more features were added to support a scriptable command-line
low level tool to edit from local hard drives, kernel memory, programs, remote gdb
servers and be able to analyze, emulate, debug, modify and disassemble any binary.

<p align="center">
<a href="https://www.radare.org/"><img src="doc/images/shot.png" alt="screenshot" align="center" border=0 width="600px"></a>
</p>

* Install r2 from **Git** (Clone the repo and run `sys/install.sh`) or use `pip install r2env`
* Read the [Official radare2 book](https://book.rada.re)
* [COMMUNITY.md](COMMUNITY.md) engagement
* [CONTRIBUTING.md](CONTRIBUTING.md) general rules
* [DEVELOPERS.md](DEVELOPERS.md) to improve r2 for your needs
* [SECURITY.md](SECURITY.md) on vulnerability report instructions
* [USAGE.md](USAGE.md) for an introductory session
* [INSTALL.md](INSTALL.md) instructions

```
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

# Plugins

Most of the plugins you need may be available in the stock r2 installation,
but you can find more in the [r2pm](https://github.com/radareorg/radare2-pm) package manager.

```
r2pm update          # initialize and update the package database
r2pm install [pkg]   # installs the package
```

Some of the most installed packages are:

* [radius](https://github.com/aemmitt-ns/radius) fast symbolic execution engine based on boolector and r2
* [r2ghidra](https://github.com/radareorg/r2ghidra) the native ghidra decompiler plugin: `pdg` command
* [esilsolve](https://github.com/radareorg/esilsolve) symbolic execution r2 plugin based on esil and z3
* [r2dec](https://github.com/wargio/r2dec-js) decompiler based on r2 written in js `pdd`
* [r2frida](https://github.com/nowsecure/r2frida) the frida io plugin `r2 frida://0`
* [iaito](https://github.com/radareorg/iaito) - official graphical interface (Qt)

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
MCORE, mcs96, RSP, SuperH-4, VAX, AMD Am29000.

## File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, OMF, TE, XBE, BIOS/UEFI,
Dyldcache, DEX, ART, CGC, Java class, Android boot image, Plan9 executable,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump),
WASM (WebAssembly binary), Commodore VICE emulator, QNX, WAD, OFF, TIC-80
Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs, various filesystems.

# Contributing

There are many ways to contribute to the project, join the IRC/Matrix/Telegram
channels, check out the github issues or grep for the TODO comments in the source.
To contribute with code, create a branch in your forked repository and push
a pull request, follow the coding style and ensure it passes the tests with
the `r2r` tool to run the tests that are under the `tests/` subdirectory.

For more details read the [CONTRIBUTING.md](CONTRIBUTING.md) file.

## Community and Documentation

To learn more about r2 we encourage you to watch youtube talks from
[r2con](https://www.youtube.com/c/r2con) [conference](https://rada.re/con). As well as reading blogposts,
slides or read the [Official radare2 book](https://book.rada.re), You can reach us in the following chats:

* irc.libera.chat `#radare` `#radare_side`
* [Matrix](https://matrix.org/) `#radare:matrix.org`
* [Telegram](https://t.me/radare) and the [Side Channel](https://t.me/radare_side)
* [Discord](https://discord.gg/MgEdxrMnqx) server
* Twitter: [@radareorg](https://twitter.com/radareorg)
* Website: [https://www.radare.org/](https://www.radare.org/)

## Packaging Status

* [![Termux package](https://repology.org/badge/version-for-repo/termux/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Alpine Linux Edge package](https://repology.org/badge/version-for-repo/alpine_edge/radare2.svg)](https://repology.org/project/radare2/versions) [![Alpine Linux 3.13 package](https://repology.org/badge/version-for-repo/alpine_3_13/radare2.svg)](https://repology.org/project/radare2/versions) [![Alpine Linux 3.12 package](https://repology.org/badge/version-for-repo/alpine_3_12/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Arch package](https://repology.org/badge/version-for-repo/arch/radare2.svg)](https://repology.org/project/radare2/versions) [![AUR package](https://repology.org/badge/version-for-repo/aur/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Fedora 34 package](https://repology.org/badge/version-for-repo/fedora_34/radare2.svg)](https://repology.org/project/radare2/versions) [![Fedora 32 package](https://repology.org/badge/version-for-repo/fedora_32/radare2.svg)](https://repology.org/project/radare2/versions)
* [![FreeBSD port](https://repology.org/badge/version-for-repo/freebsd/radare2.svg)](https://repology.org/project/radare2/versions) [![OpenBSD port](https://repology.org/badge/version-for-repo/openbsd/radare2.svg)](https://repology.org/project/radare2/versions) [![pkgsrc current package](https://repology.org/badge/version-for-repo/pkgsrc_current/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Homebrew package](https://repology.org/badge/version-for-repo/homebrew/radare2.svg)](https://repology.org/project/radare2/versions) [![MacPorts package](https://repology.org/badge/version-for-repo/macports/radare2.svg)](https://repology.org/project/radare2/versions)
* [![HaikuPorts master package](https://repology.org/badge/version-for-repo/haikuports_master/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Ubuntu 20.10 package](https://repology.org/badge/version-for-repo/ubuntu_20_10/radare2.svg)](https://repology.org/project/radare2/versions) [![Ubuntu 20.04 package](https://repology.org/badge/version-for-repo/ubuntu_20_04/radare2.svg)](https://repology.org/project/radare2/versions) [![Ubuntu 18.04 package](https://repology.org/badge/version-for-repo/ubuntu_18_04/radare2.svg)](https://repology.org/project/radare2/versions)
* [![Debian Unstable package](https://repology.org/badge/version-for-repo/debian_unstable/radare2.svg)](https://repology.org/project/radare2/versions) [![Raspbian Stable package](https://repology.org/badge/version-for-repo/raspbian_stable/radare2.svg)](https://repology.org/project/radare2/versions) [![Kali Linux Rolling package](https://repology.org/badge/version-for-repo/kali_rolling/radare2.svg)](https://repology.org/project/radare2/versions)

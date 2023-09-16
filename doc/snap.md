Installing the snap package of radare2
======================================
radare2 is also available as a snap package and can be installed on a system that supports snap packages. See [Installing snapd](https://snapcraft.io/docs/installing-snapd) to setup your system to support snap packages.

Status of snap package support
------------------------------
Currently, radare2 is available as a snap package that works in _classic_ security confinement.

Currently, you need to prepend `radare2.` to each command you want to run. For example, use `radare2.rabin2` to run `rabin2`.

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/radare2)

To find information about this snap package, run `snap info radare2`. See the section below on this.

To review the snap build reciepe this can be found in [this separate repository](https://github.com/radareorg/radare2-snap).

Installing radare2
-----------------
This command installs the `radare2` snap package using the _classic_ security confinement type. The _classic_ security confinement disables some restrictions that are applied to typical snap packages. _classic_ makes a package to work similar to APT and RPM packages.

    $ sudo snap install radare2 --classic

Running commands
----------------

Currently, the radare2 commands can be invoked with the following names:

- `radare2` or `radare2.r2` or `radare2.radare2`: The `r2`/`radare2` command.
- `radare2.r2p` : The `r2p` command.
- `radare2.r2pm` : The `r2pm` command.
- `radare2.r2r` : The `r2r` command.
- `radare2.r2agent` : The `r2agent` command.
- `radare2.rafind2` : The `rafind2` command.
- `radare2.rahash2` : The `rahash2` command.
- `radare2.rasm2` : The `rasm2` command.
- `radare2.rabin2` : The `rabin2` command.
- `radare2.radiff2` : The `radiff2` command.
- `radare2.ragg2` : The `ragg2` command.
- `radare2.rarun2` : The `rarun2` command.
- `radare2.ravc2` : The `ravc2` command.
- `radare2.rax2` : The `rax2` command.
- `radare2.rasign2` : The `rasign2` command.

Getting info about the radare2 snap package
-------------------------------------------

Run the following command to get info about the radare2 snap package. You can see the list of available commands and how to invoke them. There will always be packages in the `stable` channel and sometimes in the `edge` channel. As an example, the following capture exposes that we have installed radare 4.5.0 (from build 5), using the _devmode_ security confinement and _tracking_ from the `edge` channel.

```
$ snap info radare2
...
description: |
  Radare2 (also known as r2) is a complete framework for reverse-engineering
  and analyzing binaries; composed of a set of small utilities
  that can be used together or independently from the command line.
  Built around a disassembler for computer software which generates
  assembly language source code from machine-executable code,
  it supports a variety of executable formats for different processors
  and operating systems.

commands:
  - radare2.r2
  - radare2.r2agent
  - radare2.r2p
  - radare2.r2pm
  - radare2.r2r
  - radare2.rabin2
  - radare2
  - radare2.radiff2
  - radare2.rafind2
  - radare2.ragg2
  - radare2.rahash2
  - radare2.rarun2
  - radare2.rasign2
  - radare2.rasm2
  - radare2.ravc2
  - radare2.rax2
snap-id:      ceuTRkmV5T8oTHt2psXxLRma25xfBrfS
tracking:     latest/edge
refresh-date: today at 12:51 EEST
channels:
  latest/stable:    5.8.2 2023-03-14 (2367) 145MB classic
  latest/candidate: ↑
  latest/beta:      ↑
  latest/edge:      ↑
installed:          4.5.0            (5) 15MB devmode
```

Updating radare2
----------------

The snap packages are updated automatically when the installed version is not in _devmode_.
If you installed radare2 snap in the past when it was only available as _devmode_ and you wish to update, you can switch to the new stable channel and get the updates by running this command:

    $ sudo snap refresh radare2 --stable --classic

See the section above on how to get info about the radare2 snap package and how to determine whether you have installed from `edge` or `beta` channels as _devmode_ or the latest from the `stable` channel as _classic_ confinement (only this last one has automatic updates).

Uninstalling radare2
--------------------
Run the following command to uninstall the snap package of radare2:

    $ sudo snap remove --purge radare2

Supported architectures
=======================
The radare2 snap package is currently available for the following architectures:

1. `amd64`
1. `arm64`
1. `armhf`

Troubleshooting
---------------

- _error: This revision of snap "radare2" was published using classic confinement..._: When installing the snap package of radare2, you need to specify the _classic_ confinement. Append `--classic` on the installation command line.
- _How can I download the snap package for offline use?_: Use the command `snap download radare2`. You can then run `sudo snap install` to install the `.snap` package that was just downloaded.
- _Do I need to use "sudo" with snap commands?_: You need to prepend `sudo` when you run most snap commands that perform privileged actions. However, if you log in into the Snap Store using `sudo snap login`, then you do not need anymore to prepend `sudo`.


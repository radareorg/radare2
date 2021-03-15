Installing the snap package of radare2
======================================
radare2 is also available as a snap package and can be installed on a system that supports snap packages. See [Installing snapd](https://snapcraft.io/docs/installing-snapd) to setup your system to support snap packages. 

Status of snap package support
------------------------------
Currently, radare2 is available as a _beta_ snap package that works in _devmode_ security confinement (developer mode). Refer back to this section for updated instructions when radare2 is out of _beta/devmode_. 

Currently, you need to prepend `radare2.` to each command you want to run. For example, use `radare2.rabin2` to run `rabin2`. 

Snap packages that work in _devmode_ security confinement do not appear in search results, when you search for them in the Snap Store. To find information about this snap package, run `snap info radare2`. See the section below on this.

Installing radare2
-----------------
This command installs the `radare2` snap package from the _beta_ channel, using the _devmode_ (developer mode) security confinement type. The _devmode_ security confinement disables any restrictions that are applied to typical snap packages. _devmode_ makes a package to work similar to APT and RPM packages. 

    $ sudo snap install radare2 --channel=beta --devmode
    
Running commands
----------------

Currently, the radare2 commands can be invoked with the following names: 

- `radare2` or `radare2.radare2`: The `r2`/`radare2` command.
- `radare2.r2pm` : The `r2pm` command.
- `radare2.r2agent` : The `r2agent` command.
- `radare2.rafind2` : The `rafind2` command.
- `radare2.rahash2` : The `rahash2` command.
- `radare2.rasm2` : The `rasm2` command.
- `radare2.rabin2` : The `rabin2` command.
- `radare2.radiff2` : The `radiff2` command.
- `radare2.ragg2` : The `ragg2` command.
- `radare2.rarun2` : The `rarun2` command.
- `radare2.rax2` : The `rax2` command.
- `radare2.rasign2` : The `rasign2` command.

Getting info about the radare2 snap package
-------------------------------------------

Run the following command to get info about the radare2 snap package. You can see the list of available commands and how to invoke them. There are packages in the `beta` and `edge` channels, currently with radare2 4.5.0. The build number in this example is 5, and is an ascending number that characterises each new build. We have installed radare 4.5.0 from build 5, using the _devmode_ security confinement. We are _tracking_ the `beta` channel. Since the installed build number is the same as the build number in the channel that we are tracking, we are already running the latest available version.

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
  - radare2.r2agent
  - radare2.r2pm
  - radare2.rabin2
  - radare2.radare2
  - radare2.radiff2
  - radare2.rafind2
  - radare2.ragg2
  - radare2.rahash2
  - radare2.rarun2
  - radare2.rasign2
  - radare2.rasm2
  - radare2.rax2
snap-id:      ceuTRkmV5T8oTHt2psXxLRma25xfBrfS
tracking:     latest/beta
refresh-date: today at 12:51 EEST
channels:
  latest/stable:    –
  latest/candidate: –
  latest/beta:      4.5.0 2020-07-23 (5) 15MB devmode
  latest/edge:      4.5.0 2020-07-23 (5) 15MB devmode
installed:          4.5.0            (5) 15MB devmode
```

Updating radare2
----------------

The snap packages that are installed in _devmode_ are not updated automatically.
You can update manually: 

    $ sudo snap refresh radare2

See the section above on how to get info about the radare2 snap package and how to determine whether there is an updated version available. 

Uninstalling radare2
--------------------
Run the following command to uninstall the snap package of radare2:

    $ sudo snap remove radare2

Supported architectures
=======================
The radare2 snap package is currently available for the following architectures:

1. `amd64`
1. `i386`
1. `arm64`
1. `armhf`
1. `ppc64el`
1. `s390x`

Troubleshooting
---------------

- _error: snap "radare2" is not available on stable_: When installing the snap package of radare2, you currently need to specify the _beta_ channel. Append `--channel=beta` on the installation command line.
- _error: The publisher of snap "radare2" has indicated that they do not consider this revision to be of production quality_: When installing the snap package of radare2, you currently need to specify the _devmode_ confinement. Append `--devmode` on the installation command line. 
- _How can I download the snap package for offline use?_: Use the command `snap download radare2 --channel=beta`. You can then run `sudo snap install` to install the `.snap` package that was just downloaded. 
- _Do I need to use "sudo" with snap commands?_: You need to prepend `sudo` when you run most snap commands that perform privileged actions. However, if you log in into the Snap Store using `sudo snap login`, then you do not need anymore to prepend `sudo`.


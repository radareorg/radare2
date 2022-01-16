# Installation

You can find the most recent packaged versions on the
[Releases](https://github.com/radareorg/radare2/releases) page. However,
installing from git is recommended whenever possible.

The most used and recommended way is by running `sys/install.sh` which will
build and install r2 from sources and install it **system-wide** using
**symlinks**.

```sh
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

To install in your user's home directory, use `sys/user.sh`. To manage multiple
installations on the same system, use
[r2env](https://github.com/radareorg/r2env).

The focus on portability enables r2 to be built in many different ways for
multiple operating systems easily by using the `./configure && make` or `meson`
build systems.

r2env allows you to build and install different versions of r2 in your home or
system and it is available via Python's `pip` tool.

```sh
pip install r2env
r2env init
r2env add radare2@git
```

## Uninstallation

In case of a polluted filesystem, you can uninstall the current version
or remove all previous installations with one or more of those commands:

```sh
make uninstall       # Remove the current installation
make purge           # Remove all files from all installations
make system-purge    # Remove all installed packages
git clean -xdf       # Remove any files not tracked by git
rm -rf shlr/capstone # Remove the current version of capstone
```

# Packaging status

<a href="https://repology.org/metapackage/radare2">
<img src="https://repology.org/badge/vertical-allrepos/radare2.svg" alt="Packaging status" align="right" width="150px">
</a>


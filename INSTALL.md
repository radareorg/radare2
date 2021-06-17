# Installation

The [GHA CI](https://github.com/radareorg/radare2/actions) builds the packages for every commit and those are also
available in the [release](https://github.com/radareorg/radare2/releases) page. But it is always recommended to
install r2 from git.

The most used and recommended way is by running this script which will build
and install r2 from sources and install it **system wide** with **symlinks**.

```
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

If you need to install it in your user's home or switch between multiple r2
builds you may checkout the `meson` build and the [r2env](https://github.com/radareorg/r2env) Python tool.

The focus on portability enables r2 to be built in many different ways for multiple
operating systems easily by using the `./configure;make` or `meson` build systems.

r2env allows to build and install different versions of r2 in your home
or system and it is available via Python's PIP tool.

```
pip install r2env
r2env init
r2env install radare2@latest
```

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

# Packaging status

<a href="https://repology.org/metapackage/radare2">
<img src="https://repology.org/badge/vertical-allrepos/radare2.svg" alt="Packaging status" align="right" width="150px">
</a>


# Installation Guide

To get the latest packaged versions of Radare2, visit the [Releases page](https://github.com/radareorg/radare2/releases). For most users, installing directly from the Git repository is recommended to ensure you have the most recent features and updates.

## Recommended Installation Method

For a system-wide installation using source code, execute the `sys/install.sh` script. This will compile Radare2 and set up symlinks for global usage.

1. **Clone the Repository**

```sh
git clone https://github.com/radareorg/radare2
```
2. **Run the Installation Script**

```sh
radare2/sys/install.sh
```

## Alternative Installation Options

- **User Directory Installation**: If you prefer to install Radare2 in your home directory, use the `sys/user.sh` script.
- **Manage Multiple Installations**: Utilize [r2env](https://github.com/radareorg/r2env) to handle multiple Radare2 versions on the same machine. It can be installed via Python's `pip` tool.

```sh
pip install r2env
r2env init
r2env add radare2@git
```

## Building Flexibility

Radare2's design prioritizes portability, making it straightforward to compile on various operating systems. You can build the software using either the `./configure && make` or `meson` build systems.

## Uninstallation Guide

If you need to clean up your system or remove Radare2 installations, use the following commands as needed:

- **Remove the Current Installation**

```sh
make uninstall
```

- **Completely Remove All Previous Installations**

```sh
make purge
make system-purge
```

## Troubleshooting

- **Clean Untracked Files**

```sh
git clean -xdf
```
- **Address Permission Issues**

```sh
sudo chown -R $USER
```

## Packaging Status

For information on Radare2’s availability across various Linux distributions:

<a href="https://repology.org/metapackage/radare2">
  <img src="https://repology.org/badge/vertical-allrepos/radare2.svg" alt="Packaging status" align="right" width="150px">
</a>

This badge provides an overview of packaging status across different repositories.

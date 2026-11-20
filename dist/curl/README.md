# Install radare2 via curl

This directory contains the installation and uninstallation scripts available at [radare.org/install](https://radare.org/install) and [radare.org/uninstall](https://radare.org/uninstall).

## Quick Install

You can install radare2 on your system by running:

```bash
curl https://radare.org/install | sh
```

## Quick Uninstall

You can uninstall radare2 by running:

```bash
curl https://radare.org/uninstall | sh
```

## Platform Support

- **Linux**: Fully supported.
- **macOS**: Fully supported.
- **Android (Termux)**: Fully supported.
- **Windows**: These scripts are designed for POSIX shells. Windows users should use [WSL](https://learn.microsoft.com/en-us/windows/wsl/) or [Git Bash](https://git-scm.com/downloads) to run the commands above.

## Details

- The script clones the radare2 repository into `~/.local/src/radare2`.
- It builds and installs radare2 into `~/.local`.
- After installation, you may need to add `~/.local/bin` to your `PATH` environment variable:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

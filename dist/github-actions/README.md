# Install Radare2 GitHub Action

Composite GitHub Action to install radare2 in CI workflows. Supports Linux, macOS and Windows runners, with options to install from release packages or build from git source.

## Usage

Reference the action from your workflow:

```yaml
- uses: radareorg/radare2/dist/github-actions@master
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `version` | Radare2 version to install (e.g., `6.1.2`). Empty for latest. | `""` (latest) |
| `from-git` | Build from git source instead of release packages. | `false` |
| `prefix` | Installation prefix (Unix git builds only). | `/usr` |

## Examples

### Install latest release

```yaml
steps:
  - uses: radareorg/radare2/dist/github-actions@master
```

### Install a specific version

```yaml
steps:
  - uses: radareorg/radare2/dist/github-actions@master
    with:
      version: '6.1.2'
```

### Build latest git from source

```yaml
steps:
  - uses: radareorg/radare2/dist/github-actions@master
    with:
      from-git: true
```

### Build a specific version from source

```yaml
steps:
  - uses: radareorg/radare2/dist/github-actions@master
    with:
      version: '6.1.2'
      from-git: true
```

### Custom install prefix

```yaml
steps:
  - uses: radareorg/radare2/dist/github-actions@master
    with:
      from-git: true
      prefix: '/opt/radare2'
```

### Multi-platform matrix

```yaml
jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: radareorg/radare2/dist/github-actions@master
      - run: radare2 -v
```

## How it works

The operating system is auto-detected from the runner:

- **Linux** - Downloads and installs `.deb` packages (`radare2` + `radare2-dev`). Architecture is detected via `dpkg --print-architecture`.
- **macOS** - Downloads and installs `.pkg` package. Detects `arm64` vs `x86_64` automatically.
- **Windows** - Downloads and extracts the `.zip` release, then adds the `bin/` directory to `PATH`.

When `from-git` is `true`, the action clones the radare2 repository and builds from source using `sys/install.sh` on Unix or `meson`/`ninja` on Windows.

## Notes

- Windows git builds use meson/ninja and require a Visual C++ environment. Add `ilammy/msvc-dev-cmd@v1` before this action if building from source on Windows.
- Both `radare2` and `radare2-dev` packages are installed on Linux so headers and pkg-config files are available for building plugins.
- The action verifies the installation by running `radare2 -v` at the end.

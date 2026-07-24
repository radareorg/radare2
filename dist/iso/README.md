# R2ISO

Minimal Debian live ISO builder for radare2.

## Usage

```sh
make
```

Optional overrides:

```sh
make R2_GIT_REF=master R2PM_PLUGINS="r2dec"
```

Output file:

```text
output/<ISO_NAME>-<DEBIAN_RELEASE>-<ARCH>.iso
```

## Run in QEMU (amd64)

```sh
make run
```

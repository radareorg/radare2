# radare2 on RISC-V JSLinux

Boots a riscv64 Linux in the browser using Fabrice Bellard's
[JSLinux](https://bellard.org/jslinux/) (the MIT-licensed
[TinyEMU](https://bellard.org/tinyemu/) compiled to WebAssembly) with a
static, size-optimized radare2 and a compact TinyCC toolchain injected
into the busybox rootfs.

radare2 is cross-compiled from this source tree as **one static binary**
(`r2blob`, all the r2 tools multiplexed busybox-style through argv[0])
with a musl riscv64 toolchain from
[toolchains.bootlin.com](https://toolchains.bootlin.com). The plugin set
comes from `dist/plugins-cfg/plugins.jslinux.cfg` and is the smallest
useful one: **ELF only, riscv arch only, no debugger, no QuickJS, no
capstone**. Deploying it into the guest is literally copying that one
file plus a dozen symlinks.

## Usage

```sh
make check-tools   # verify Docker on macOS, native tools on Linux
make               # toolchain + r2blob + rootfs + website in www/
make serve         # http://localhost:8080
```

On macOS, `make` automatically builds in a `linux/amd64` Docker
container because Bootlin's prebuilt cross compiler is an x86-64 Linux
executable. The source tree is bind-mounted into the container, so build
artifacts still appear in `work/` and `www/` and remain incremental.
Linux builds are native by default; use `make USE_DOCKER=1` or `make
docker` to use the same container there. Set `USE_DOCKER=0` to force a
native build.

Other targets and knobs:

```sh
make r2                        # only build work/r2blob
make tcc                       # only build and stage TinyCC
make run                       # boot the image in a natively-built temu
make ROOT_MB=96                # bigger guest disk (default 32MB)
make SHIP_TCC=0                # omit TinyCC from the guest image
make R2BLOB=/path/to/r2blob    # reuse a prebuilt riscv64 static blob
make TC_VER=2024.05-1          # pick another bootlin toolchain release
make docker DOCKER_TARGET=r2   # build only r2blob in Docker
```

Note: `make` reconfigures the radare2 source tree for the riscv64 cross
build (like the other `dist/` cross pipelines); rebuild your native r2
afterwards.

## How it works

1. The bootlin `riscv64-lp64d--musl` toolchain is downloaded; musl makes
   `-static` produce a fully self-contained binary that runs on the 4.15
   guest kernel.
2. radare2 is configured with `plugins.jslinux.cfg` and
   `--disable-debugger --without-qjs --without-capstone --without-zydis
   --without-gpl --without-dylink --disable-loadlibs`, compiled with
   `-Oz -ffunction-sections -fdata-sections`, and `binr/blob/r2blob` is
   linked with `-static -Wl,--gc-sections` and stripped.
3. TinyCC is downloaded at the exact commit pinned by `TCC_COMMIT`, built
   as a stripped static riscv64 compiler with `-Oz`, then staged with its
   runtime, a compact musl userspace header set and the shared musl loader.
   Its compile-and-run smoke test executes under QEMU before packaging.
   Set `SHIP_TCC=0` to skip this download, build and rootfs overlay.
4. The pristine 4MB `root-riscv64.bin` ext2 image from the jslinux demo
   tarball is grown with `resize2fs` and `r2blob` is injected with
   `debugfs` (no root privileges needed anywhere).
5. The image is split into 256KB blocks (TinyEMU `splitimg` format). A
   generated service worker precaches only the bootable app shell when offline
   storage is requested. Without it, disk blocks simply stream on demand. The
   Cache popup's `Cache all` action downloads every block sequentially,
   skipping blocks from an interrupted earlier pass. This keeps normal startup
   fast and does not starve TinyEMU's interactive disk reads.
6. `www/` ends up fully self-contained: the JSLinux runtime
   (riscvemu64-wasm), bbl + kernel, the split disk and a small
   installable web app; host it on any static web server. Once the first
   cache pass finishes, a Home Screen installation works completely offline.
   On iOS, launch the Home Screen copy once while online, open `Cache`, choose
   `Cache all`, and keep it open until all files are reported local before
   disconnecting. Its explicit `index.html` launch URL avoids relying on a
   directory redirect while offline.

## Guest integration

- `guest/` is a rootfs overlay: every file in it is injected at the
  same path inside the image (0755 when executable on the host, 0644
  otherwise).
- `guest/sbin/init` replaces `/sbin/init` so the console shell is a
  login shell, and `guest/etc/profile` prints `/etc/motd` (no login(1)
  runs, so nothing else would), sets `TERM=xterm-256color`,
  `COLORTERM=truecolor` and `LANG=C.UTF-8` (the stock term.js only
  renders 16 colors, but `web/term-colors.patch` teaches it the
  256-color and truecolor SGR sequences and brightens the base ANSI
  palette, so r2 defaults to `scr.color=3` and `scr.utf8=true`),
  defines a busybox-compatible `resize` helper
  (cursor-position-report trick) for initial sync and as a fallback, selects
  `/etc/radare2rc` through r2's `R2_RCFILE`
  override, and mounts the upload filesystem. That image-wide rc selects the
  `bluy` theme, responsive layouts and horizontal wheel navigation.
- The color themes are compiled into the r2 binary
  (`--with-static-themes`) since no r2 share directory is installed in
  the guest image, so `eco` and friends work as usual.
- Uploads: the page ships an empty in-memory 9p filesystem
  (`www/netfs`, generated with TinyEMU's `build_filelist`); files
  uploaded from the browser appear in **/mnt/tmp** inside the guest.
- The page is phone-friendly: dark, a single title bar with Upload /
  Keyboard / Cache / About buttons, and the terminal geometry is
  computed from the viewport (`?cols=`, `?rows=`, `?font_size=` URL
  params still override it). It also includes iOS Home Screen metadata and a
  radare2 touch icon. Page rubber-banding is disabled on touch devices; a
  two-finger terminal pinch changes only its font size and refits its character
  grid, while a one-finger drag becomes vertical or horizontal terminal
  mouse-wheel input for r2 visual modes. Real grid changes notify TinyEMU's
  virtio console, keeping the guest tty and responsive applications in sync.
  The Keyboard button is the only page control that focuses the hidden text
  input; focus loss and visual-viewport changes hide the extra keys and refit
  the terminal when iOS dismisses its keyboard.

## Licensing

TinyEMU is MIT-licensed; the JSLinux demo files (`jslinux.js`,
`term.js`, precompiled emulator, kernel and rootfs) are downloaded from
bellard.org at build time and are not stored in this repository.
TinyCC is LGPL-licensed, downloaded from its upstream GitHub repository
at the pinned commit, and its `COPYING` file is installed in the guest.

# radare2 on ReactOS, in the browser

Builds a small ReactOS disk image with the radare2 w32 (mingw32) build
preinstalled in `C:\radare2`, plus a static website that boots that image
inside the browser so people can test w32 builds of radare2 without
installing anything — phones included.

The browser side uses [v86](https://github.com/copy/v86), a wasm x86 PC
emulator with full VGA output, mouse/keyboard and low memory requirements.
(qemu's wasm port was considered but it only provides a serial console —
no graphics — and needs ~2.3GB of browser memory, which excludes phones.)
The disk image is streamed on demand with HTTP Range requests: visitors
only download the sectors ReactOS actually reads (a few tens of MB for a
boot), not the whole disk.

## Dependencies

    sudo apt install curl unzip xorriso qemu-system-x86 qemu-utils mtools
    # plus mingw to build radare2 for w32: gcc-mingw-w64-i686

Run `make check-tools` to verify.

## Build

    make            # everything: reactos.qcow2 + www/
    make image      # only the qcow2
    make www        # only the website
    make serve      # test locally on http://localhost:8080
    make run        # boot reactos.qcow2 in native qemu

What happens under the hood:

1. Downloads the ReactOS BootCD, enables `UnattendSetupEnabled` in its
   `unattend.inf` (reinjected with xorriso, keeping the iso bootable).
2. Runs the unattended install headless in qemu: two `-no-reboot` runs,
   one per setup stage (text mode, then gui). With KVM this takes minutes.
3. Unzips a `radare2-*-mingw32.zip` (built with `make w32` in the repo root
   if none exists — pass `R2_W32_ZIP=/path/to.zip` to use your own) and
   copies it into `C:\radare2` on the FAT partition with mtools, plus an
   `r2.cmd` wrapper in `system32` so `r2` works from any cmd prompt.
4. Produces `reactos.qcow2` (compressed) and `www/images/reactos.img`
   (raw, sparse) plus the v86 emulator files and the html page.

Useful knobs: `DISK_MB=2048` (disk size), `WEB_MEM_MB=256` (guest RAM in
the browser), `QEMU_DISPLAY=` (watch the unattended install instead of
running it headless), `REACTOS_VER`/`REACTOS_ZIP_URL` (other releases).

## Hosting www/

Copy the `www/` directory to any static host. Requirements:

- **Range requests**: the host must honor `Range:` headers on
  `images/reactos.img` (nginx, apache, caddy, most CDNs do; python's
  builtin http.server does not — use the bundled `serve.py`).
- **Sparse transfer**: `reactos.img` is mostly holes; upload with
  `rsync -S` or pack with `tar -Szcf` to avoid transferring zeros.
- `config.js` and `sw.js` should be served with `Cache-Control: no-cache`
  (everything else can be cached aggressively; asset urls carry a
  `?v=<image-hash>` so new builds invalidate naturally).

## Caching

A service worker caches the emulator, bios and page after the first visit,
and the browser's http cache keeps the disk chunks. The page has a
**Clear cache** button that deletes the CacheStorage, unregisters the
service worker, bumps the cache-busting query and reloads — use it when a
new image is uploaded but the browser insists on the old one (stale cache
entries from previous builds are also pruned automatically at boot).

## Using it

The page boots straight to the ReactOS desktop (no password). Open `cmd`
from the Start menu and run e.g.:

    r2 C:\ReactOS\system32\cmd.exe

On phones: drag on the screen to move the mouse pointer, tap to click,
long-press to right-click, and use the **Keyboard** button to open the
soft keyboard.

Use **Upload files**, or drag files onto the page, to create and mount a
temporary transfer CD in ReactOS (normally `D:`). The image is generated
entirely in the browser; files are not sent to the web server. Uploading again
replaces the CD, and **Eject files** removes it. For browser-memory safety a
single transfer is limited to 128 MB. ISO-compatible filenames are used, so
unsupported characters and long names may be shortened in the guest.

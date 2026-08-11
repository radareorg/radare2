# radare2 on NetBSD, in the browser

Builds a minimal NetBSD/i386 disk image with radare2 cross-compiled from
this tree into `/usr/local`, plus a static website that boots that image
inside the browser with [v86](https://github.com/copy/v86) — the same
runtime used by `../reactos`, whose page, service worker, upload-ISO
builder and range-request server are reused verbatim (they are copied,
not duplicated; branding comes from `config.js`).

Unlike ReactOS this boots to a real unix text console: the VGA text mode
is rendered by v86 as crisp text, the guest auto-logs-in as root, and
radare2 is already in the `PATH`. It works on phones too: the Keyboard
button opens the soft keyboard and the image only needs 256MB of guest
RAM, with disk sectors streamed on demand over HTTP Range requests.

## Why a custom kernel

The stock `GENERIC` kernel does **not** boot under v86, and the two reasons
are worth knowing (both are in `guest/V86.conf`):

1. **Fatal page fault at `eip 0` in the idle thread.** SeaBIOS (the bios v86
   runs) publishes an MP floating pointer, so `mainbus` takes the MPBIOS
   enumeration path — and under v86 that yields no CPU flagged as the
   bootstrap processor. `mainbus.c` only falls back to `CPU_ROLE_SP` when
   `mpbios_probe()` fails, so `cpu_attach()` never calls
   `x86_cpu_idle_init()`, `x86_cpu_idle` stays NULL, and the first
   `cpu_idle()` calls through it. Fixed with `no options MPBIOS`, which is
   free here: v86 is uniprocessor and routes interrupts through the 8259.
2. **Panic in `cnopen` when init starts.** v86 exposes *no* PCI devices
   (its VGA, disk, keyboard and serial are all legacy ISA), but `GENERIC`
   only probes `vga at pci` — `vga0 at isa?` is commented out upstream, see
   NetBSD PR#49290. Nothing attaches a `wsdisplay`, so `/dev/console`
   cannot be opened. Fixed by re-enabling `vga0 at isa?`.

Neither is v86-specific in a fixable-in-v86 way, and NetBSD is arguably too
trusting in both places (the first dies with an unattributable jump to
address 0 rather than a diagnostic), but two config lines avoid both. The
same config also drops the emulated SoundBlaster and VMware-tools probes,
which otherwise fail and produce "2 errors while detecting hardware", and
one patch is applied to the kernel sources so that v86's ATAPI CD-ROM (which
does not set the removable bit) attaches as `cd0` and uploaded files can be
mounted.
`make webtest` boots the finished image in v86 headlessly under node and
dumps the text console, which is how these were tracked down; set
`WEBTEST_TYPE='r2 /bin/ls'` to run a command once the shell appears.

[FIXES.md](FIXES.md) has the full story: the ddb evidence behind both
diagnoses, what was ruled out, two more NetBSD bugs found on the way, and
the cross-toolchain, image and radare2 portability fixes this needed.

## How it works

1. **Cross toolchain**: no NetBSD cross-gcc is built for userland; `clang`
   targets `i386-unknown-netbsd` out of the box, linking with `lld` against
   a sysroot extracted from the official `base.tgz`+`comp.tgz` sets.
2. **radare2**: `./configure --host=i386-unknown-netbsd --with-ostype=bsd`
   with `CC` pointing at a small wrapper script; `make install` into a
   DESTDIR is packed as `work/r2.tgz` (`make r2` builds just this).
   Note this reconfigures the source tree, like `sys/mingw32.sh` does.
3. **Kernel**: the NetBSD source sets are fetched and NetBSD's own
   `build.sh` builds its cross toolchain and the `V86` kernel described
   above (`make kernel`). The toolchain build is the slow one-time step;
   kernel iterations take a couple of minutes.
4. **Image**: [anita](http://www.gson.org/netbsd/anita/) (NetBSD's
   official install-automation tool, auto-installed into `work/venv`)
   drives sysinst in qemu over the serial console with a minimal set
   list (`kern-GENERIC,modules,base,etc,rescue`), producing a raw disk.
5. **Inject**: `work/r2.tgz`, the `V86` kernel and `guest/install.sh` are
   packed into an ISO; anita boots the image once more (`--persist`) and
   runs the script, which extracts r2, installs the kernel as `/netbsd`
   (keeping the stock one as `/netbsd.generic`), switches the boot console
   to VGA (`consdev=pc`), enables root autologin on `ttyE0` and disables
   network daemons so the boot is fast and quiet.
6. **Website**: `www/` gets the v86 assets (reused from `../reactos/www`
   when present, downloaded otherwise), the shared page files from
   `../reactos/web`, the sparse raw image and a generated `config.js`
   with the NetBSD title/hints and `acpi: false` (v86's ACPI is
   incomplete; NetBSD happily boots the legacy path).

## Dependencies

    sudo apt install curl xorriso qemu-system-x86 qemu-utils \
        clang lld llvm python3-venv build-essential nodejs

Run `make check-tools` to verify. KVM (`/dev/kvm`) makes the unattended
install take minutes instead of hours.

## Build

    make            # everything: netbsd.qcow2 + www/
    make r2         # only the NetBSD radare2 build (work/r2.tgz)
    make kernel     # only the v86 kernel (work/netbsd.v86)
    make image      # only the qcow2
    make www        # only the website
    make serve      # test locally on http://localhost:8080
    make run        # boot netbsd.qcow2 in native qemu
    make webtest    # boot www/ headlessly in v86 and dump the console

Useful knobs: `NETBSD_VER=10.1` (release; `make clean` when changing it),
`GUEST_TIMECOUNTER=i8254` (finer time, at the price of v86's clock jitter
tripping "timecounter went backwards"), `DISK_MB=2048` (disk size),
`WEB_MEM_MB=256` (browser guest RAM), `R2_NETBSD_TGZ=/path.tgz` (reuse a
prebuilt r2 tarball), `ANITA_ACCEL=` (no kvm), `WEB_ACPI=true`.

## Hosting www/

Same rules as `../reactos/README.md`: the host must honor HTTP `Range`
requests on `images/netbsd.img` (use the bundled `serve.py` for local
testing, python's builtin server does not), upload the sparse image with
`rsync -S`, and serve `config.js`/`sw.js` with `Cache-Control: no-cache`.

## Using it

The page boots to an auto-logged-in root shell on the VGA console:

    r2 /bin/ls

Uploading files (button or drag&drop) builds an ISO in the browser and
inserts it as a CD; run `mount /mnt` in the guest to read the files and
`umount /mnt` before uploading the next batch. On phones use the
Keyboard button to type; arrows/enter/etc are forwarded, so even `r2 -w`
visual mode works from a soft keyboard.

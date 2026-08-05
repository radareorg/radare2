# Fixes needed to boot NetBSD (with radare2) under v86

Notes from making `dist/netbsd` work, kept because most of these are
non-obvious and none of them are documented anywhere else. Three of them are
NetBSD bugs, several are traps that cost real time, and a few are radare2
portability bugs that only a NetBSD cross build exposes.

Section 1 is what stopped it booting at all; section 2 is what was still
wrong once it did boot (colors, fsck, timekeeping, file uploads, boot
noise); the rest is the supporting machinery.

Target: NetBSD 11.0/i386 in [v86](https://github.com/copy/v86) (the wasm PC
emulator the browser page runs), with SeaBIOS, no ACPI, 256MB of RAM.

Everything below is reproducible headlessly with `make webtest`, which boots
the built image in v86 under node and dumps the VGA text console.

---

## 1. The two showstoppers: GENERIC cannot boot under v86

Both are fixed by `guest/V86.conf`, a small delta over `GENERIC`, built with
NetBSD's own `build.sh` (`make kernel`).

### 1.1 Fatal page fault at `eip 0` in the idle thread

**Symptom**, about one second into boot, right after the ISA devices attach:

    uvm_fault(0xc15e55e0, 0, 1) -> 0xe
    fatal page fault in supervisor mode
    trap type 6 code 0 eip 0xc012fb3c cs 0x8 eflags 0x246 cr2 0
    curlwp 0xc1dd3040 pid 0 lid 2
    Stopped in pid 0.2 (system) at netbsd:trap+0x865: movzbl 0(%edx),%eax

The reported `eip` is a red herring: it is a *nested* fault. `trap+0x865`
is the kernel reading the opcode byte at `tf_eip` (the segment-load/`iret`
fixup path in `trap()`), and it faults because `tf_eip` is 0. Dumping the
original trapframe in ddb (`%edi` points at it at that instruction) gives:

    tf_trapno = 6 (T_PAGEFLT)   tf_eip = 0   tf_cs = 8   tf_eflags = 0x246

so the CPU really did execute at address 0, in kernel mode, in `pid 0 lid 2`
— the `idle/0` lwp — with `idle_loop` and `lwp_trampoline+0x11` on the stack.
`cpu_idle()` on x86 is `(*x86_cpu_idle)()`, and ddb confirms it directly:

    db{0}> x/x x86_cpu_idle
    netbsd:x86_cpu_idle:    0

**Cause.** `x86_cpu_idle_init()` is only called from `cpu_attach()` for
`CPU_ROLE_BP` and `CPU_ROLE_SP` (`sys/arch/x86/x86/cpu.c`). In
`sys/arch/x86/x86/mainbus.c` the `CPU_ROLE_SP` fallback lives in an
`else if (numcpus == 0)` that is skipped entirely whenever `mpbios_probe()`
succeeds:

    #ifdef MPBIOS
            if (mpbios_probe(self))
                    mpbios_scan(self, &numcpus);
            else
    #endif
            if (numcpus == 0) {
                    ... caa.cpu_role = CPU_ROLE_SP; config_found(...)
            }

SeaBIOS publishes an MP floating pointer, so `mpbios_probe()` succeeds, but
under v86 the enumeration produces no usable bootstrap CPU (`mpbios_cpu()`
requires `PROCENTRY_FLAG_EN`, and sets `CPU_ROLE_BP` only for
`PROCENTRY_FLAG_BP`). Nothing initialises the idle handler, and the first
switch into the idle thread calls through a NULL pointer.

**Fix**: `no options MPBIOS`. mainbus then takes the no-MP-tables path and
attaches `cpu0` as `CPU_ROLE_SP`. Nothing is lost — v86 is uniprocessor and
its interrupt routing is the plain 8259 PIC.

This is arguably a NetBSD robustness bug: an MP enumeration that yields no BP
leaves the kernel guaranteed to die, with a jump to address 0 that gives no
hint about what went wrong, instead of a diagnostic.

### 1.2 Panic in `cnopen` as soon as init starts

With 1.1 fixed the kernel boots all the way to userland and then panics in
`cnopen`, reached from `init` doing `open()` (visible as a breakpoint trap
in `pid 120 (init)` with `cnopen -> cdev_open -> spec_open -> ... -> sys_open`
on the stack).

**Cause.** v86 exposes **no PCI devices at all** — the serial dmesg shows
`pci0 at mainbus0 bus 0: configuration mode 2` with nothing under it; its
VGA, IDE, keyboard and serial are all legacy ISA. But `GENERIC` only probes
VGA on PCI; the ISA line is commented out upstream:

    # vga@isa and pcdisplay@isa are disabled; see PR#49290
    #vga0		at isa?
    vga*		at pci? dev ? function ?

So no `wsdisplay` ever attaches, `/dev/ttyE*` do not exist (`wsconscfg:
/dev/ttyEcfg: Device not configured`), and `/dev/console` cannot be opened.

**Fix**: re-enable `vga0 at isa?`. `wsdisplay* at vga? console ?` is already
in GENERIC, so the rest follows.

### What was ruled out (so nobody repeats it)

Each of these was tested and made no difference:

- **NetBSD version** — 10.1 and 11.0 fail identically.
- **`MULTIPROCESSOR`** — a uniprocessor kernel crashes the same way. The old
  advice in [v86#350](https://github.com/copy/v86/issues/350) ("NetBSD works
  only with a custom kernel", NOSMP) treats a symptom, not the cause.
- **`kern-LEGACY`** (new in 11.0) — same crash.
- **ACPI** — with `acpi: true` in v86 it crashes *earlier*, inside
  `acpi_attach`. The page keeps `acpi: false`.
- **Disabling individual devices** (`fdc`, `sb`, ...) via userconf.
- **v86 version** — 0.5.379, 0.5.409, 0.5.419 and 0.5.424 all fail.

### Two more NetBSD bugs found while bisecting

Not needed by the final config (it keeps `MULTIPROCESSOR`), but real:

- **NetBSD 11.0 cannot link a uniprocessor i386 kernel that has acpi or
  mpbios.** `mpacpi.c` and `mpbios.c` reference `mp_cpu_funcs`
  unconditionally, but `cpu.c` defines it (and `mp_cpu_start*`) only under
  `#ifdef MULTIPROCESSOR`:

      ld: mpbios.c:(.text+0x7bb): undefined reference to `mp_cpu_funcs'

- **UP x86 needs `options NO_PREEMPTION`**, otherwise `kern_stub.c` fails with
  `#error __HAVE_PREEMPTION requires MULTIPROCESSOR` (x86 `intr.h` defines
  `__HAVE_PREEMPTION` unless `NO_PREEMPTION` is set). Only the amd64
  `XEN3_DOM0` config mentions this, in a commented-out line.

---

## 2. Five things that were still broken once it booted

Reported after actually using the browser image. None of them is a boot
failure, and each has a different culprit.

### 2.1 radare2 has no colors, and `scr.color=2` changes nothing

Not a `TERM` problem — setting `TERM=xterm` does not help and is in fact a
lie. The console is wscons, which announces itself as

    wsdisplay0 at vga0 kbdmux 1: console (80x25, vt100 emulation)

`wsemul_vt100` implements the **8/16 basic ANSI colors** (SGR 30-37/40-47)
and nothing more. `scr.color=2` emits 256-colour escapes
(`ESC[38;5;Nm`) and `scr.color=3` emits truecolor (`ESC[38;2;R;G;Bm`);
wscons does not understand either and drops the attribute, so the text comes
out plain. The tell is that `WARN:` *is* magenta — `R_LOG` uses the basic
codes unconditionally, so some color always survives.

**Fix**: `/root/.radare2rc` with `e scr.color=1`, written by `install.sh`.
Use `scr.color=1` for any 16-color terminal; 2 and 3 need a terminal
emulator that implements them (xterm, and v86's own text renderer, do — the
NetBSD console in between does not).

### 2.2 fsck runs on every single boot

Symptom, once per boot, forever:

    /dev/rwd0a: ALTERNATE SUPERBLK(S) ARE INCORRECT (SALVAGED)
    /dev/rwd0a: MARKING FILE SYSTEM CLEAN

The repair itself is normal and succeeds — the problem is that it never
sticks. **In the browser the disk is read-only from the guest's point of
view**: v86 keeps writes in memory and throws them away when the tab
closes, and every visitor starts from the same published image. So a
filesystem that needs *any* repair needs it again on every boot, for
everyone, forever.

**Fix**: settle the image once, natively, before publishing it. `make`
now boots the freshly injected image in qemu (`work/.settle`), where the
repair lands on disk for good and the fs is marked clean. To make that
unattended, `install.sh` drops a one-shot into `/etc/rc.local` that powers
the machine off on the next boot and deletes itself:

    if [ -f /.settle ]; then rm -f /.settle; sync; /sbin/shutdown -p now; fi

so no interactive driving of the guest is needed, and normal boots are
unaffected. The general rule for any browser image: **anything the guest
would otherwise fix on first boot must be fixed before publishing**.

### 2.3 `timecounter went backwards` warnings all over the boot

    WARNING: lwp 287 (sh) flags 0x20000020: timecounter went backwards
    from (20 + 0x51841fee4bcd1998/2^64) sec to (20 + 0x50f3e40017f921f0/2^64)
    sec in netbsd:mi_switch+0x5c

v86 derives its timers from the browser's clock, which is not monotonic (and
is deliberately jittered and throttled by browsers), so a timecounter read
can come out lower than the previous one. Under v86 the TSC is not even
registered (NetBSD demotes it in `x86/x86/tsc.c` when it is not invariant)
and the kernel already picks `i8254`, so this is the PIT read jittering.

Two things make it much less alarming than it looks:

- the check latches — `updatertime()` in `kern_synch.c` has a
  `static bool backwards` — so it is **at most one line per boot**, not a
  flood;
- it is purely a diagnostic, and it is unrelated to 2.2 despite appearing
  right next to the fsck output.

**Fix**: `install.sh` pins the timecounter in `/etc/sysctl.conf` to
**`clockinterrupt`**, which counts timer ticks instead of sampling a device
and therefore cannot go backwards at all. Its 10ms resolution costs nothing
noticeable here — in the guest, `sleep 5` still takes exactly five seconds
and `time sleep 1` reports `1.02 real`. Build with
`make GUEST_TIMECOUNTER=i8254` for the finer-grained (but jitter-exposed)
PIT instead. Pinning also guarantees a jittery TSC is never selected if a
future v86 advertises an invariant one.

Note that no sysctl can prevent a warning during *early* boot:
`/etc/sysctl.conf` is applied by rc, and `rcorder` — which is usually what
trips it — runs before that. Because the check latches, that is at most one
line, once.

### 2.4 Uploaded files: "inserted" but nothing to mount

The upload button builds an ISO in the browser and hands it to v86, but the
guest had no `cd0`. The drive *was* there, under a different name:

    uk0 at atapibus0 drive 0: <v86 ATAPI CD-ROM, 8086-8610, 1.00> cdrom fixed

Note **`cdrom fixed`**: v86 leaves `ATAPI_CFG_REMOV` clear in its IDENTIFY
PACKET DEVICE data, and `cd(4)` only matches *removable* devices
(`{T_CDROM, T_REMOV, ...}` in `atapiconf.c`), so `atapi_wdc.c` hands the
drive to `uk(4)` — "unknown", no block device, nothing to mount.

**Fix**: `guest/atapi-cdrom-removable.patch` (applied to the kernel sources
by `make kernel`) trusts the device type over the missing bit: an ATAPI
CD-ROM is removable by definition. The drive then attaches as `cd0` and
`mount /mnt` works, using the `/dev/cd0a` entry `install.sh` adds to
`/etc/fstab`.

The page also used to claim the files were "mounted"; it now says
"inserted ... in the CD drive - run `mount /mnt` in the guest", via the
optional `VM_CONFIG.cd_note`.

### 2.5 "N errors while detecting hardware"

    WARNING: 2 errors while detecting hardware; check system log.

Both come from hardware v86 pretends to have and then does not implement:
`opl at sb0 not configured` (the FM synth child of the emulated
SoundBlaster) and `vmt0: failed to open backdoor RPC channel`, from the
VMware-tools driver probing the backdoor port that v86 answers just enough
to look present. `no sb0` and `no vmt0` in the kernel config drop both;
there is no audio in the browser page anyway.

The `ACPI Error:` lines during boot are a separate, harmless case: the page
runs v86 with `acpi: false`, so there are no ACPI tables to find
(`A valid RSDP was not found`). ACPI is deliberately kept in the kernel
regardless, because the native settle boot in 2.2 needs it to power the
machine off.

---

## 3. radare2 portability fixes (found by cross-compiling for NetBSD)

- **`libr/include/r_io.h`** — NetBSD's `ptrace(2)` takes an `int` data
  argument like Free/OpenBSD, but the typedef fell through to the generic
  `void *` branch, so `io_ptrace.c` failed to build (`incompatible integer to
  pointer conversion`). `__NetBSD__` added to the int branch.
  *(committed as `3bba8e129b`)*

- **`libr/util/deps.mk`** — `-lexecinfo` (which NetBSD needs for
  `backtrace(3)`) was selected by `BUILD_OS` plus a `uname -r` check, i.e. by
  the *build machine*, so cross builds never linked it and `libr_util.so`
  ended with undefined `backtrace`/`backtrace_symbols_fd`. Now keyed on
  `HOST_OS`, with the `uname` check kept only for native builds.
  *(committed as `0046f45ffd`)*

- **root `Makefile`** — `make clean` swept
  `` rm -f `find . -type f -name '*.o'` `` across the whole tree, which
  reached into `dist/netbsd/work/sysroot/usr/lib` and **deleted NetBSD's
  `crt0.o`/`crti.o`**, after which every later configure failed with
  "cannot create executables". The sweeps now prune `./dist`.

---

## 4. Cross-toolchain traps

No NetBSD cross-gcc is needed for userland: clang targets
`i386-unknown-netbsd` directly against a sysroot made from the official
`base.tgz`+`comp.tgz` sets. Three things bite:

- **`usr/include/machine` does not exist in the sets.** It is a symlink to
  the arch directory that `postinstall` creates on a real system; without it
  every compile dies at `#include <machine/cdefs.h>`. The Makefile creates
  `machine -> i386` after extracting.

- **lld's default layout is rejected by `ld.elf_so`.** Binaries link fine but
  the guest refuses them:

      r2: Shared object "libr_cons.so" not found
      ldd: /usr/local/bin/r2: wrong number of segments (4 != 2)

  NetBSD's dynamic loader wants the classic two-`PT_LOAD` layout, so the cc
  wrapper passes `-Wl,--no-rosegment -Wl,-z,norelro`.

- **The sysroot must be extracted atomically** (temp dir + `mv`), or an
  interrupted/clobbered extraction leaves a half-populated sysroot that fails
  in confusing ways much later.

---

## 5. Image and guest-configuration fixes

- **Partitioning**: anita lets sysinst pick GPT by default; the browser boot
  path is better tested with MBR + disklabel, hence
  `--partitioning-scheme MBR`.

- **The injected tarball must be root-owned and not group-writable.** NetBSD
  `tar` as root restores ownership and modes, so a tarball built by a normal
  user leaves `/usr` owned by uid 1000 — and then **openpam refuses every
  login**:

      login: in openpam_check_path_owner_perms(): /usr/: insecure ownership
      login: pam_start failed

  which also silently disables the autologin getty. Fixed with
  `chmod -R go-w` plus `tar --owner=0 --group=0 --numeric-owner`.

- **`/etc/ttys` fields are tab-separated**, so the obvious
  `sed 's, on , off ,'` silently does nothing. And sysinst (driven over the
  serial console) enables gettys on **both** `console` and `constty`, which
  keep the VGA console busy. `install.sh` rewrites all three entries whole.

- **`consdev=pc` must be the last thing anita does.** anita drives the guest
  over the serial console; once the image is switched to the VGA console it
  can no longer be automated. Any further change means reinstalling — the
  Makefile notes this on the inject rule.

- **Set a hostname** in `rc.conf`, otherwise postfix fails loudly on every
  boot (`postconf: fatal: unable to use my own hostname`). Network daemons
  are disabled anyway to keep the boot fast and quiet.

- **Settle the image before publishing it** (see 2.2): the guest cannot keep
  any fix it makes on first boot, so `make` boots the injected image once
  natively and lets it power itself off.

---

## 6. Shared browser runtime (`../reactos`)

The page, service worker, upload-ISO builder and range-request server are
reused verbatim from `dist/reactos`; the changes needed there are all
backwards compatible:

- `web/index.html` now honours optional `VM_CONFIG.title`, `VM_CONFIG.hint`,
  `VM_CONFIG.acpi` and `VM_CONFIG.cd_note`, so a second guest needs no forked
  copy of the page. ReactOS still gets `acpi: true` (it hangs without it);
  NetBSD sets `acpi: false`.
- The cache-busting token in `localStorage` is now keyed by `location.pathname`,
  so two builds hosted on the same origin do not clobber each other.
- **Text-mode guests are now scaled.** The fit-to-window code only ever
  resized the canvas, which is what v86 draws into in *graphics* mode. A unix
  console runs in VGA **text** mode, where v86 instead writes styled spans
  into a `<div>` — a DOM element with no intrinsic pixel size to stretch, so
  it kept its small fixed size, fullscreen included. The page now tracks
  which mode the guest is in (`screen-set-size` sends `[cols, rows, 0]` for
  text and `[w, h, bpp]` for graphics) and scales the div with a css
  transform. It re-measures a few times after a mode change, because the div
  is announced before the guest paints anything and an empty one measures
  0x0.

---

## 7. Test harness

`webtest.js` (`make webtest`) boots `www/` in v86 under node and dumps the
VGA text screen; `WEBTEST_TYPE='r2 /bin/ls'` runs a command once the shell
prompt appears. Two things worth remembering:

- **Type one character at a time**, ~150-250ms apart. `keyboard_send_text()`
  with a whole line overruns the guest's keyboard polling and characters are
  silently dropped — very visible in ddb, where `bt` arrives as `b`.

- **For full scrollback, use the serial console.** The VGA text grid loses
  everything that scrolls off, which hides panic messages. Typing
  `consdev com0` at the bootloader prompt and then capturing v86's
  `serial0-output-byte` events gives the complete transcript (and
  `serial0_send()` can drive the guest from there). The kernel `-h` flag is
  not enough — `consdev=pc` in `/boot.cfg` wins over it.

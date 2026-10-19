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
comes from `dist/plugins-cfg/plugins.jslinux.cfg`, with QuickJS included
and Capstone omitted. Deploying it into the guest is literally copying
that one file plus a dozen symlinks.

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
   `--without-capstone --without-zydis --without-gpl --with-static-themes`,
   compiled with `-Oz -ffunction-sections -fdata-sections`, and `binr/blob/r2blob` is
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
- QuickJS is enabled by default. Scripts can use the same synchronous
  `r2.http(method, url, headers, data?)` API as native r2 and WASI builds.
  It returns `{status, body}` through `r_socket_http_*`; enabling the binding
  does not itself provide browser networking to the Linux guest.
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

## Optional PHP HTTP relay

`web/http.php` supplies the server side of an HTTP bridge for AI clients.
Place it beside the page on a PHP-enabled host such as the radare.org
deployment. `make relay` copies just this file to `www/http.php`; `make www`
also includes it. PHP 7.4 or later with the cURL extension is required.
The ordinary `make serve` server only serves static files and cannot execute PHP.

Configure these environment variables in the PHP server or PHP-FPM pool:

- `R2_HTTP_UPSTREAM`: the fixed upstream base URL, for example
  `https://llm.example/v1` or `http://127.0.0.1:11434` for Ollama running
  on the web server.
- `R2_HTTP_TOKEN`: a private access token supplied by each relay client.
  Keep it out of the static page and offline bundle.

Both are required; an unconfigured relay returns HTTP 503. Upstream API keys
are supplied separately in the request headers. `localhost` here refers to
the PHP server, not the browser user's machine. With the relay on the same
origin as the page, upstream providers do not need to enable browser CORS.
All requests and supplied API keys pass through the PHP server.

The bridge protocol is a POST to `http.php` with a JSON body. It also accepts
JSON sent as `application/octet-stream`, as used by TinyEMU's filesystem XHR:

```json
{
  "token": "your-relay-access-token",
  "method": "POST",
  "path": "/chat/completions",
  "headers": "Content-Type: application/json\nAuthorization: Bearer your-api-key",
  "data": "{\"model\":\"your-model\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"stream\":false}"
}
```

`path` is appended to `R2_HTTP_UPSTREAM`; clients cannot select another host.
`method` defaults to `GET`, `path` to `/`, and `headers` and `data` to empty
strings. Headers are newline-separated; accepted names are listed in the PHP
file. GET requests cannot carry data. Request envelopes are limited to 2 MiB,
responses to 16 MiB, and requests to 120 seconds with a 10-second connection
timeout. The web server's own timeouts must accommodate the chosen model.
Redirects are returned without following them. TLS certificate verification
remains enabled. This endpoint buffers complete responses; use non-streaming
AI requests.

A completed upstream request returns HTTP 200 with the upstream status and
a base64-encoded body, including upstream errors such as 401 and 429:

```json
{"status":200,"body":"aGVsbG8=","encoding":"base64"}
```

Relay errors use HTTP 4xx/5xx with `{"error":"..."}`. The endpoint is excluded
from the offline cache and sends `Cache-Control: no-store`.

The guest's `r_socket_http_get/post` APIs can use TinyEMU's existing filesystem
XHR command through `/mnt/.fscmd`. This transport is available in normal Unix
builds and is selected at runtime, without another build flag or an emulator
patch. Configure it in the guest shell before starting r2, for example:

```sh
export R2_HTTP_RELAY=https://radare.org/your-jslinux-directory/http.php
export R2_HTTP_UPSTREAM=https://llm.example/v1
export R2_HTTP_TOKEN=your-relay-access-token
r2
```

`R2_HTTP_UPSTREAM` must match the upstream base configured in PHP. Only requests
under this exact base are accepted; the guest strips it to obtain the relay's
`path`. For example, `https://llm.example/v1/chat/completions` becomes
`/chat/completions`. Set the AI client's base URL accordingly. Requests to other
origins or base paths fail, and relay errors do not fall back to sockets or
curl. Unset `R2_HTTP_RELAY` to restore ordinary HTTP transport selection.

`R2_HTTP_FS` optionally selects another shared filesystem mount (default
`/mnt`); it must contain `.fscmd` and a writable `tmp` directory.
`R2_HTTP_TIMEOUT` sets the guest wait in seconds (default 130; nonpositive
values also use the default). Request and response files use a private
directory and are removed on completion or failure. A timeout stops the
guest's wait; the existing TinyEMU interface does not cancel a browser XHR
already in progress. The transport requires socket, network and filesystem
access, and refuses operation under `cfg.sandbox=true`, which prohibits the
temporary-file writes.

Scripts can now call `r2.http()` through this transport. With decai installed,
use its default `http=auto` or `decai -e http=r2`; forcing `http=curl` bypasses
it. With the C r2ai plugin installed, select `e r2ai.http.backend=socket` and
keep `e r2ai.stream=false`. These AI plugins still need to be packaged into
the guest image. The PHP endpoint and a rebuilt guest r2 are both required.

Run the relay regression locally, without contacting an AI provider:

```sh
python3 test/scripts/test-jslinux-http.py  # from the repository root
python3 test/scripts/test-jslinux-guest-http.py
```

The second test runs the rebuilt r2 against a filesystem mock of TinyEMU's
XHR command, covering request envelopes, URL mapping, errors, limits, sandbox
denial and cleanup. It does not boot the browser emulator.

## Licensing

TinyEMU is MIT-licensed; the JSLinux demo files (`jslinux.js`,
`term.js`, precompiled emulator, kernel and rootfs) are downloaded from
bellard.org at build time and are not stored in this repository.
TinyCC is LGPL-licensed, downloaded from its upstream GitHub repository
at the pinned commit, and its `COPYING` file is installed in the guest.

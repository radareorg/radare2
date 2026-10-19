# WebAssembly (WASI) support

Build with WASI SDK 29 using `sys/wasi.sh` (CLI), `sys/wasi-api.sh`
(reactor exporting the C APIs), or `sys/wasi-browser.sh` (browser console
and HTTP imports). Set `WASI_SDK` and `WASI_SYSROOT` to use an installed SDK.
These builds disable native debugging, process execution and raw sockets.
Only explicitly preopened directories are shared with the guest.

## Build without networking

`./configure --disable-network` or `meson setup build -Dnetwork=false` disables
libr_socket networking on native and WASI targets. Socket operations use failure
stubs (`false`, `NULL` or `-1`, according to the return type). HTTP GET/POST and
download also fail, including with `R2_CURL=1`; the built-in `curl` command cannot
launch external curl. Disabled builds contain no host HTTP imports, even when
WASM HTTP was requested. This is a build capability limit, independent of the
runtime sandbox. It does not restrict programs explicitly launched with `!` or
third-party plugins implementing their own networking.

## Optional HTTP GET and POST

The HTTP API and browser variants use one `r2.http_request` import. There is no low-level socket ABI or WebSocket proxy.

```sh
# Use a clean checkout when changing build flags.
WASI_HTTP=1 sys/wasi-api.sh
# Produces radare2-<version>-wasi-api-http.zip
```

Release CI builds both ordinary and HTTP API variants. The ordinary API
build retains its import set and has no HTTP access. Browser builds already
include these HTTP imports; no extra browser variant is needed.

`r_socket_http_get()`, `r_socket_http_post()` and `r_socket_http_download()`
keep their C signatures and ownership rules. WASM routes GET/POST directly
to the host, including HTTPS, before the native curl/socket code. The
`R2_CURL` environment variable cannot make these APIs spawn a process in WASM.
The built-in `curl` command and HTTP file IO use the same C APIs.

Two gates apply independently: the host adapter defaults to `enabled: false`,
and each C request checks the radare2 sandbox. When sandboxing is enabled,
**both `socket` and `network` grains are required**, even for localhost:
host clients can follow redirects to other hosts. No execution permission is
required. Tightening the sandbox prevents subsequent requests. It does not
cancel a synchronous request already in progress. Browser CORS, restricted
headers and credential policies still apply.

## Host ABI

| Import in `r2` | wasm32 arguments | Result |
| --- | --- | --- |
| `http_request` | post, url, headers, data, status pointer, length pointer | response pointer or 0 |

`post` is 0 for GET and 1 for POST. This replaces the earlier two-import ABI;
update host adapters together with the module. Imports are required at
instantiation: an omitted callback causes a WebAssembly link error. The supplied
adapter installs a denial callback when disabled, allowing radare2 to start
and returning an HTTP failure without a host request.

Strings are UTF-8 and NUL-terminated; headers are newline-separated
`Name: value` lines (or NULL). POST data is a string, matching the existing
C API. Status/length output pointers may be NULL. On failure return NULL
with status/length zero; HTTP error responses can still return a body and
status such as 404. Allocate the response with the **guest's** `malloc`,
append NUL, and report the body length in **bytes**, excluding NUL. The C
caller owns and frees that buffer. Binary responses may contain NUL bytes.

`sys/wasm-http.mjs` handles encoding, bounds checks and response ownership:

```js
import { createHttpImports } from './sys/wasm-http.mjs';
let instance;
const r2 = createHttpImports(() => instance.exports, {
  enabled: true,
  // Optional synchronous application callback:
  // request(method, url, headers, body) => ({ status, body: Uint8Array })
});
// Instantiate with { ...wasiImports, r2 }, then initialize the reactor.
```

The ABI is synchronous. A plain async function or Promise-returning `fetch`
callback cannot be passed directly as an import. For custom callbacks,
`headers` is a newline-separated string of `Name: value` lines and `body` is the POST string
(or undefined for GET). Accept only HTTP(S) and enforce application-specific
host restrictions inside your callback if needed.

## Browser

Use the helper's default request implementation in a **dedicated Web Worker**.
It performs synchronous XMLHttpRequest and returns byte-exact response data.
The host UI stays responsive. With the browser CLI build, merge the returned
HTTP functions into your existing `r2` console imports (`is_tty`,
`set_raw_mode`, `key_next`, etc.); with the HTTP reactor only the HTTP
function are needed in that namespace. Both still require a WASI provider.

```js
// Inside the Worker; wasiImports comes from your browser WASI provider.
const { instance: loaded } = await WebAssembly.instantiate(wasmBytes, {
  ...wasiImports,
  r2: createHttpImports(() => instance.exports, { enabled: true }),
});
instance = loaded;
instance.exports._initialize();
const core = instance.exports.r_core_new();
// Use the C API; send command results back to the UI with postMessage.
instance.exports.r_core_free(core);
```

## Node.js

Node's fetch is asynchronous, so the small adapter runs it on another worker
while the C call waits. It exposes only whole HTTP requests, no socket handles.
It defaults to a 30-second deadline and a 16 MiB response limit, configurable
as `timeout` (milliseconds) and `maxResponse` (bytes). TLS uses normal
certificate verification. Close the worker when finished.

```js
import { readFileSync } from 'node:fs';
import { WASI } from 'node:wasi';
import { createHttpImports } from './sys/wasm-http.mjs';
import { createNodeHttp } from './sys/wasm-http-node.mjs';

let instance;
const http = createNodeHttp({ enabled: true });
const wasi = new WASI({ version: 'preview1', args: ['radare2'],
  env: {}, preopens: {}, returnOnExit: true });
try {
  ({ instance } = await WebAssembly.instantiate(readFileSync('radare2.wasm'), {
    ...wasi.getImportObject(),
    r2: createHttpImports(() => instance.exports, { enabled: true, request: http.request }),
  }));
  wasi.initialize(instance);
  const core = instance.exports.r_core_new();
  // Call r_core_cmd_str / r_socket_http_get / r_socket_http_post, then free results.
  instance.exports.r_core_free(core);
} finally {
  await http.close();
}
```

## Python and AI clients

The Python Wasmer wrapper in `radareorg/radare2-r2pipe/python-wasm` accepts
`open(wasm='radare2.wasm', network=True)` and provides HTTP(S) GET/POST through
Python's standard library. Networking defaults off there too.

For r2ai compiled into the guest, `e r2ai.http.backend=socket` selects the
existing `r_socket_http_*` path; `e r2ai.stream=false` requests a complete
response. Native plugins cannot be dynamically loaded into a WASM build.
All QuickJS-enabled builds expose `r2.http(method, url, headers, data?)`,
returning `{status, body}` synchronously. `method` is `GET` or `POST`,
`headers` is a newline-separated string (use `""` for no headers), and
`data` is the optional POST string. `body` is a JavaScript string, including
embedded NULs; this is a text API, not a binary buffer API. HTTP error
responses retain their status and body. Transport failures, disabled
networking and sandbox denials throw an exception.

The binding delegates to `r_socket_http_get/post` on every platform. Native
builds use their existing socket/curl transport; WASI HTTP builds use the host
import described above. Scripts need no platform-specific HTTP implementation.
WASI builds still provide no arbitrary shell command emulation.

Run the real C API regression with:

```sh
node test/scripts/wasm-http.mjs binr/radare2/radare2.wasm
```

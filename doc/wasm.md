# WebAssembly (WASI) Support in radare2

## Introduction

radare2 can be compiled to WebAssembly (WASM) using the WASI (WebAssembly System Interface) standard, allowing it to run in web browsers or other WASM-compatible environments. This enables radare2 to be used in client-side applications without server-side execution.

## Building radare2 for WASI

To build radare2 for WASI, you need the WASI SDK installed. The build process is automated in `sys/wasi.sh`.

### Prerequisites

- Install the WASI SDK from https://github.com/WebAssembly/wasi-sdk/releases
- Set the `WASI_SDK` environment variable to the installation path

### Building

Run the WASI build script:

```bash
./sys/wasi.sh
```

This script configures radare2 with the following options:

```bash
./configure \
  --with-static-themes \
  --without-gperf \
  --with-compiler=wasi \
  --disable-debugger \
  --without-fork \
  --with-ostype=wasi \
  --with-checks-level=0 \
  --disable-threads \
  --without-dylink \
  --with-libr \
  --without-gpl
```

Then compiles and packages the WASM binaries for tools like `radare2`, `rabin2`, etc., into a `radare2-<version>-wasi.zip` file.

## Instantiating the WASM Module

To use the generated `.wasm` files in a web application, instantiate them using the WebAssembly API.

### Basic Instantiation

```javascript
const response = await fetch('radare2.wasm');
const buffer = await response.arrayBuffer();
const module = await WebAssembly.compile(buffer);

// Define imports
const imports = {
  r2: {
    is_tty: () => 1,  // Assume TTY available
    set_raw_mode: (raw) => { /* set terminal mode */ },
    key_next: () => { /* return next key code */ },
    http_get: (url, headers_str, code_ptr, rlen_ptr) => {
      // Implement HTTP GET using fetch
      // Allocate memory for response, set code and rlen
      return response_ptr;
    },
    http_post: (url, headers_str, data, code_ptr, rlen_ptr) => {
      // Implement HTTP POST using fetch
      return response_ptr;
    }
  }
};

const instance = await WebAssembly.instantiate(module, imports);
```

### Import Functions

The WASM module requires the following imports in the `r2` module:

- `is_tty()`: Returns 1 if running in a TTY environment, 0 otherwise
- `set_raw_mode(raw)`: Set terminal to raw mode (raw=1) or cooked mode (raw=0)
- `key_next()`: Return the next key code from input
- `http_get(url, headers_str, code_ptr, rlen_ptr)`: Perform HTTP GET request
- `http_post(url, headers_str, data, code_ptr, rlen_ptr)`: Perform HTTP POST request

For HTTP functions:
- `url`: Null-terminated string
- `headers_str`: Headers as "Header: value\nHeader2: value\n"
- `data`: POST data (for POST only)
- `code_ptr`: Pointer to int for HTTP status code
- `rlen_ptr`: Pointer to int for response length
- Return: Pointer to allocated response string in WASM memory

## Using with xterm.js

xterm.js is a terminal emulator for the web. To integrate radare2 WASM with xterm.js:

1. Set up xterm.js in your HTML:

```html
<div id="terminal"></div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5/lib/xterm.min.js"></script>
```

2. Initialize xterm.js and connect to WASM I/O:

```javascript
const term = new Terminal();
term.open(document.getElementById('terminal'));

// WASM memory buffer
let wasmMemory;

// Instantiate WASM with imports
const imports = {
  r2: {
    is_tty: () => 1,
    set_raw_mode: (raw) => {
      // Configure xterm.js for raw/cooked mode
      term.setOption('cursorBlink', !raw);
    },
    key_next: () => {
      // This is tricky - xterm.js input is event-driven
      // You might need to buffer input or use a promise-based approach
      return term.buffer.active.getLine(term.buffer.active.cursorY).translateToString(
        term.buffer.active.cursorX
      ).charCodeAt(0) || 0;
    },
    http_get: async (urlPtr, headersPtr, codePtr, rlenPtr) => {
      const url = getStringFromWasm(urlPtr);
      const headers = getStringFromWasm(headersPtr);
      
      try {
        const response = await fetch(url, {
          headers: parseHeaders(headers)
        });
        
        const data = await response.text();
        const dataPtr = allocateStringInWasm(data);
        
        setInt32(codePtr, response.status);
        setInt32(rlenPtr, data.length);
        
        return dataPtr;
      } catch (error) {
        setInt32(codePtr, 500);
        setInt32(rlenPtr, 0);
        return 0;
      }
    },
    http_post: async (urlPtr, headersPtr, dataPtr, codePtr, rlenPtr) => {
      const url = getStringFromWasm(urlPtr);
      const headers = getStringFromWasm(headersPtr);
      const data = getStringFromWasm(dataPtr);
      
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: parseHeaders(headers),
          body: data
        });
        
        const responseData = await response.text();
        const responsePtr = allocateStringInWasm(responseData);
        
        setInt32(codePtr, response.status);
        setInt32(rlenPtr, responseData.length);
        
        return responsePtr;
      } catch (error) {
        setInt32(codePtr, 500);
        setInt32(rlenPtr, 0);
        return 0;
      }
    }
  }
};

WebAssembly.instantiateStreaming(fetch('radare2.wasm'), imports)
  .then(({ instance }) => {
    wasmMemory = instance.exports.memory;
    
    // Connect WASM stdout to xterm.js
    // This requires hooking the WASM write functions or using WASI stdout
    
    // For input, you may need to handle xterm.js 'data' events
    term.onData(data => {
      // Send data to WASM input buffer
    });
  });
```

### Helper Functions

```javascript
function getStringFromWasm(ptr) {
  const view = new Uint8Array(wasmMemory.buffer);
  let str = '';
  let i = ptr;
  while (view[i]) {
    str += String.fromCharCode(view[i]);
    i++;
  }
  return str;
}

function allocateStringInWasm(str) {
  const bytes = new TextEncoder().encode(str + '\0');
  const ptr = instance.exports.malloc(bytes.length);
  const view = new Uint8Array(wasmMemory.buffer);
  view.set(bytes, ptr);
  return ptr;
}

function setInt32(ptr, value) {
  const view = new DataView(wasmMemory.buffer);
  view.setInt32(ptr, value, true);
}

function parseHeaders(headersStr) {
  const headers = {};
  headersStr.split('\n').forEach(line => {
    const [key, ...valueParts] = line.split(':');
    if (key && valueParts.length) {
      headers[key.trim()] = valueParts.join(':').trim();
    }
  });
  return headers;
}
```

## Limitations

- WASI build disables some features like debugger and threading
- Network access is limited to HTTP via imports
- File system access is restricted to WASI APIs
- Performance may be lower than native builds

## Examples

See the radare2 web interface at `shlr/www/` for examples of WASM integration.
## Optional host networking

A normal WASI build still has no socket creation/connect implementation.
WASI Preview1's receive/send imports alone cannot enable radare2 networking.
To build the host-socket variant from a **clean checkout**:

```sh
WASI_NETWORK=1 sys/wasi-api.sh
# radare2-<version>-wasi-api-net.zip
```

`WASI_NETWORK=1 sys/wasi-browser.sh` also builds a `-wasi-browser-net.zip`
variant. Clean the build before switching between these variants; compiler
flags are not dependency-tracked. The regular API/browser artifacts retain
their existing import sets. Release CI builds both API variants.

The host must supply the synchronous `r2net` imports below. Returning `-1`
from all imports disables the transport. Hosts must use their own per-instance
handle table, not expose arbitrary OS descriptors, and close all remaining
handles when destroying an instance. No process-spawning imports are added.

| Import | Arguments | Result |
| --- | --- | --- |
| `connect` | host string, port string, protocol (6 TCP / 17 UDP), TLS boolean, timeout seconds | handle or -1 |
| `listen` | port string, loopback-only boolean, protocol | handle or -1 |
| `accept` | listener handle | connected handle or -1 |
| `read` / `write` | handle, buffer pointer, byte count | transferred bytes, EOF 0, or -1 |
| `close` | handle | 0 or -1 |
| `ready` | handle, seconds, microseconds | readable 1, timeout 0, error -1 |
| `block_time` | handle, blocking boolean, seconds, microseconds | 0 or -1 |
| `peer` | handle, output buffer, capacity including NUL | string length or -1 |

All arguments/results are wasm32 `i32`; strings are UTF-8 and NUL-terminated.
Buffers belong to the guest and must be bounds-checked by the host. A returned
handle is opaque and is not a WASI file descriptor. Unsupported operations
must fail, rather than use a shell or another transport implicitly.

### Sandbox policy

There are two independent gates: the embedding application's network opt-in,
and radare2's sandbox policy. Denying either prevents network access.

- Socket operations require the `socket` grain. Non-loopback connections and
  listeners additionally require `network`. `localhost` is canonicalized to
  `127.0.0.1`; the localhost exception does not accept hostname prefixes.
- Reads, writes, accept, readiness and socket configuration recheck policy,
  including on sockets opened before the sandbox was enabled/tightened.
- Closing sockets remains possible after revocation, to release resources.
- Browser HTTP callbacks require **both** `socket` and `network`, because the
  browser may follow redirects beyond the initial URL. Browser CORS and origin
  restrictions still apply; this does not grant raw TCP access to browsers.

### Node.js

`sys/wasm-network-node.mjs` provides a TCP/TLS transport, with optional TCP
listeners. UDP, TLS listeners and Unix sockets are not implemented by this
adapter. TLS uses Node's default certificate verification. Socket IO runs on
another worker thread so synchronous WASM calls do not block its event loop.
A host call has a 30-second deadline by default; on expiry the adapter destroys
its worker and all handles. Supply `timeout` in milliseconds to change it.

```js
import { readFileSync } from 'node:fs';
import { WASI } from 'node:wasi';
import { createNetworkImports } from './sys/wasm-network.mjs';
import { createNodeTransport } from './sys/wasm-network-node.mjs';

const network = true; // Both helpers default to false.
let instance;
const transport = await createNodeTransport({ enabled: network });
const wasi = new WASI({ version: 'preview1', args: ['radare2'],
  env: {}, preopens: {}, returnOnExit: true });
try {
  ({ instance } = await WebAssembly.instantiate(readFileSync('radare2.wasm'), {
    ...wasi.getImportObject(),
    ...createNetworkImports(() => instance.exports, { enabled: network, transport }),
  }));
  wasi.initialize(instance);
  const core = instance.exports.r_core_new();
  // Use r_core_cmd_str / r_core_file_open as usual, then release the core.
  instance.exports.r_core_free(core);
} finally {
  await transport.close();
}
```

Do not run a test server on the same Node event loop that makes synchronous
WASM calls: run it in another worker/process. The regression test demonstrates
this arrangement: `node test/scripts/wasm-network.mjs path/to/radare2.wasm`.

### Browser JavaScript

For HTTP with the existing browser build, use the explicit opt-in helper in a
**dedicated Worker**. Merge these functions into the other `r2` console imports:

```js
import { createBrowserHttpImports, createNetworkImports } from './sys/wasm-network.mjs';
let instance;
const imports = {
  // Include your WASI imports here.
  r2: {
    // Include is_tty, set_raw_mode, key_next, etc. here.
    ...createBrowserHttpImports(() => instance.exports, { enabled: true }),
  },
  ...createNetworkImports(() => instance.exports), // Raw sockets remain disabled.
};
// Instantiate your browser module with imports, then run its entry point.
```

This helper uses synchronous XMLHttpRequest in the Worker, because these C
imports return synchronously. Returning a Promise from an import is incorrect.
A browser cannot supply raw TCP/UDP. To use `r2net` there, provide an application
transport backed by a WebSocket proxy and a separate worker/message bridge,
subject to the same explicit opt-in and sandbox checks. No proxy is configured
or started automatically.

The Python counterpart is `r2pipe_wasm.open(wasm=..., network=True)` in
`radareorg/radare2-r2pipe/python-wasm`; it supports TCP, connected UDP, TLS clients
and TCP listeners through Python's socket/SSL modules.

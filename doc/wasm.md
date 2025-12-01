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
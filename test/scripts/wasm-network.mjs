// Run: node test/scripts/wasm-network.mjs path/to/radare2.wasm
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { WASI } from 'node:wasi';
import { Worker } from 'node:worker_threads';
import { createNetworkImports, createBrowserHttpImports } from '../../sys/wasm-network.mjs';
import { createNodeTransport } from '../../sys/wasm-network-node.mjs';

// Exercise the browser HTTP adapter's opt-in and guest-owned result buffer.
const fakeMemory = new WebAssembly.Memory({ initial: 1 });
let nextPointer = 1024;
const fakeExports = { memory: fakeMemory, malloc: size => { const p = nextPointer; nextPointer += size; return p; }, free() {} };
new Uint8Array(fakeMemory.buffer).set(new TextEncoder().encode('https://example.test/\0'), 128);
let requests = 0;
class TestXHR {
  open(method, url, async) { assert.equal(method, 'GET'); assert.equal(url, 'https://example.test/'); assert.equal(async, false); }
  setRequestHeader() {}
  send() { requests++; this.status = 200; this.response = new Uint8Array([1, 2, 3]).buffer; }
}
globalThis.XMLHttpRequest = TestXHR;
try {
  assert.equal(createBrowserHttpImports(() => fakeExports).http_get(128, 0, 64, 68), 0);
  assert.equal(requests, 0);
  const pointer = createBrowserHttpImports(() => fakeExports, { enabled: true }).http_get(128, 0, 64, 68);
  assert.equal(requests, 1);
  assert.deepEqual([...new Uint8Array(fakeMemory.buffer, pointer, 4)], [1, 2, 3, 0]);
  assert.equal(new DataView(fakeMemory.buffer).getInt32(64, true), 200);
  assert.equal(new DataView(fakeMemory.buffer).getInt32(68, true), 3);
} finally { delete globalThis.XMLHttpRequest; }

const server = new Worker(`
  const {parentPort}=require('node:worker_threads');
  require('node:http').createServer((req,res)=>{
    res.writeHead(200, {'Content-Length': 3}); res.end(Buffer.from([144,144,195]));
  }).listen(0,'127.0.0.1',function(){parentPort.postMessage(this.address().port)});
`, { eval: true });
const port = await new Promise((resolve, reject) => { server.once('message', resolve); server.once('error', reject); });
const transport = await createNodeTransport({ enabled: true });
try {
  const bytes = readFileSync(process.argv[2]);
  for (const enabled of [false, true]) {
    let exports;
    const wasi = new WASI({ version: 'preview1', args: ['radare2'], env: {}, preopens: {}, returnOnExit: true });
    const imports = createNetworkImports(() => exports, { enabled, transport });
    const { instance } = await WebAssembly.instantiate(bytes, { ...wasi.getImportObject(), ...imports });
    exports = instance.exports;
    wasi.initialize(instance);
    const alloc = text => {
      const data = new TextEncoder().encode(text + '\0');
      const p = exports.malloc(data.length) >>> 0;
      new Uint8Array(exports.memory.buffer).set(data, p);
      return p;
    };
    const host = alloc('localhost'), remote = alloc('127.example.invalid'), service = alloc(String(port));
    const request = alloc('GET / HTTP/1.0\r\n\r\n');
    const socket = exports.r_socket_new(0);
    exports.r_sandbox_grain(1); // localhost sockets only
    exports.r_sandbox_enable(1);
    assert.equal(exports.r_socket_connect(socket, remote, service, 6, 2), 0);
    assert.equal(exports.r_socket_connect(socket, host, service, 6, 2), Number(enabled));
    if (enabled) {
      assert.equal(exports.r_socket_write(socket, request, 18), 18);
      assert.equal(exports.r_socket_ready(socket, 2, 0), 1);
      const buffer = exports.malloc(4096);
      const count = exports.r_socket_read(socket, buffer, 4096);
      assert.ok(count > 0);
      assert.match(new TextDecoder().decode(new Uint8Array(exports.memory.buffer, buffer, count)), /HTTP\/1.1 200/);
      exports.r_sandbox_grain(0);
      assert.equal(exports.r_socket_write(socket, request, 1), -1);
      assert.equal(exports.r_socket_read(socket, buffer, 1), -1);
      assert.equal(exports.r_socket_ready(socket, 0, 0), -1);
      assert.equal(exports.r_socket_accept(socket), 0);
      assert.equal(exports.r_socket_listen(socket, service, 0), 0);
      exports.free(buffer);
    }
    exports.r_socket_free(socket);
    for (const p of [host, remote, service, request]) exports.free(p);
    const http = createBrowserHttpImports(() => exports);
    assert.equal(http.http_get(host, 0, 0, 0), 0); // Disabled must not perform XHR.
  }
  console.log('WASM network opt-in, TCP/HTTP, and sandbox revocation passed');
} finally {
  await transport.close();
  await server.terminate();
}

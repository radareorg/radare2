// Run: node test/scripts/wasm-http.mjs path/to/radare2.wasm
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { WASI } from 'node:wasi';
import { Worker } from 'node:worker_threads';
import { createHttpImports } from '../../sys/wasm-http.mjs';
import { createNodeHttp } from '../../sys/wasm-http-node.mjs';

// Check the browser adapter contract with XHR; real browser execution needs CORS.
const memory = new WebAssembly.Memory({ initial: 1 });
const fake = { memory, malloc() { memory.grow(1); return 1024; }, free() {} };
const encode = s => new TextEncoder().encode(s);
new Uint8Array(memory.buffer).set(encode('https://example.test/\0'), 128);
let calls = 0;
globalThis.XMLHttpRequest = class {
  open(method, url, async) { assert.equal(method, 'GET'); assert.equal(url, 'https://example.test/'); assert.equal(async, false); }
  setRequestHeader() {}
  send() { calls++; this.status = 200; this.response = new Uint8Array([1, 0, 3]).buffer; }
};
try {
  assert.equal(createHttpImports(() => fake).http_request(0, 128, 0, 0, 64, 68), 0);
  assert.equal(calls, 0);
  const pointer = createHttpImports(() => fake, { enabled: true }).http_request(0, 128, 0, 0, 64, 68);
  assert.deepEqual([...new Uint8Array(memory.buffer, pointer, 4)], [1, 0, 3, 0]);
  assert.equal(new DataView(memory.buffer).getInt32(64, true), 200);
  assert.equal(new DataView(memory.buffer).getInt32(68, true), 3);
} finally { delete globalThis.XMLHttpRequest; }

// The server must run independently of the thread making blocking WASM calls.
const server = new Worker(`
  const {parentPort}=require('node:worker_threads');
  require('node:http').createServer(async (req,res)=>{
    const chunks=[]; for await (const chunk of req) chunks.push(chunk);
    if (req.url === '/redirect') { res.writeHead(302, {Location:'/sample'}); res.end(); return; }
    if (req.url === '/post') {
      if (req.headers.authorization !== 'Bearer test' || req.headers['content-type'] !== 'application/json') {
        res.writeHead(400); res.end('bad headers'); return;
      }
      res.writeHead(201); res.end(Buffer.concat(chunks)); return;
    }
    if (req.url === '/curl') { res.end(Buffer.concat(chunks).toString() || 'curl-get'); return; }
    res.writeHead(req.url === '/missing' ? 404 : 200);
    res.end(Buffer.from([144,0,195]));
  }).listen(0,'127.0.0.1',function(){parentPort.postMessage(this.address().port)});
`, { eval: true });
const port = await new Promise((resolve, reject) => { server.once('message', resolve); server.once('error', reject); });
const http = createNodeHttp({ enabled: true });
try {
  const bytes = readFileSync(process.argv[2]);
  assert.ok(!WebAssembly.Module.imports(new WebAssembly.Module(bytes)).some(i => i.module === 'r2net'));
  for (const enabled of [false, true]) {
    let e, requests = 0;
    const wasi = new WASI({ version: 'preview1', args: ['radare2'], env: { R2_CURL: '1' }, preopens: {}, returnOnExit: true });
    const r2 = createHttpImports(() => e, { enabled, request: (...args) => { assert.equal(typeof args[2], "string"); requests++; return http.request(...args); } });
    const { instance } = await WebAssembly.instantiate(bytes, { ...wasi.getImportObject(), r2 });
    e = instance.exports;
    wasi.initialize(instance);
    const alloc = text => {
      const data = encode(text + '\0'), p = e.malloc(data.length) >>> 0;
      new Uint8Array(e.memory.buffer).set(data, p);
      return p;
    };
    function call(method, path = '/sample') {
      const url = alloc(`http://127.0.0.1:${port}${path}`), code = e.malloc(4), length = e.malloc(4);
      const h1 = alloc('Authorization: Bearer test'), h2 = alloc('Content-Type: application/json');
      const headers = e.malloc(12), data = alloc('{"prompt":"hello món"}');
      new Uint32Array(e.memory.buffer, headers, 3).set([h1, h2, 0]);
      const result = method === 'POST' ? e.r_socket_http_post(url, headers, data, code, length) : e.r_socket_http_get(url, headers, code, length);
      try {
        const view = new DataView(e.memory.buffer);
        if (!result) { assert.equal(view.getInt32(code, true), 0); assert.equal(view.getInt32(length, true), 0); return null; }
        const size = view.getInt32(length, true);
        assert.equal(new Uint8Array(e.memory.buffer)[(result >>> 0) + size], 0);
        return { status: view.getInt32(code, true), body: new Uint8Array(e.memory.buffer, result >>> 0, size).slice() };
      } finally { for (const p of [url, code, length, h1, h2, headers, data, result]) if (p) e.free(p); }
    }
    const core = e.r_core_new();
    assert.ok(core);
    function command(text) {
      const p = alloc(text), out = e.r_core_cmd_str(core, p);
      try {
        const memory = new Uint8Array(e.memory.buffer), start = out >>> 0;
        return new TextDecoder().decode(memory.subarray(start, memory.indexOf(0, start))).trim();
      } finally { e.free(p); if (out) e.free(out); }
    }
    command('e scr.color=0');
    assert.equal(command(`curl http://127.0.0.1:${port}/curl`), enabled ? 'curl-get' : '');
    assert.equal(command(`curl -D hello http://127.0.0.1:${port}/curl`), enabled ? 'hello' : '');
    e.r_core_free(core);
    if (!enabled) {
      assert.equal(call('GET'), null); assert.equal(call('POST', '/post'), null);
      assert.equal(requests, 0); continue;
    }
    assert.deepEqual(call('GET'), { status: 200, body: new Uint8Array([144, 0, 195]) });
    assert.deepEqual(call('POST', '/post'), { status: 201, body: encode('{"prompt":"hello món"}') });
    assert.equal(call('GET', '/missing').status, 404);
    assert.equal(call('GET', '/redirect').status, 200);
    e.r_sandbox_grain(33); e.r_sandbox_enable(1);
    assert.equal(call('POST', '/post').status, 201);
    const before = requests;
    for (const grain of [1, 32, 0]) {
      e.r_sandbox_grain(grain);
      assert.equal(call('GET'), null); assert.equal(call('POST', '/post'), null);
      assert.equal(requests, before);
    }
  }
  console.log('WASM C HTTP GET/POST, headers, binary bodies, status, redirects, opt-in and sandbox passed');
} finally { await http.close(); await server.terminate(); }

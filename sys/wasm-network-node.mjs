// Keep Node's asynchronous sockets on another thread while the WASM ABI blocks.
import { Worker, isMainThread, parentPort } from 'node:worker_threads';
import net from 'node:net';
import tls from 'node:tls';

export async function createNodeTransport({ enabled = false, timeout = 30000 } = {}) {
  if (!enabled) return { call: () => -1, close() {} };
  const worker = new Worker(new URL(import.meta.url));
  await new Promise((resolve, reject) => { worker.once('online', resolve); worker.once('error', reject); });
  let closed = false;
  worker.on('error', () => { closed = true; });
  const close = () => { closed = true; return worker.terminate(); };
  return {
    close,
    call(op, args) {
      if (closed) return -1;
      const shared = new SharedArrayBuffer(16 + 65536);
      const control = new Int32Array(shared, 0, 4);
      worker.postMessage({ op, args, shared });
      if (Atomics.wait(control, 0, 0, timeout) === 'timed-out') {
        close(); // Abandon all handles if the worker can no longer respond.
        return -1;
      }
      const result = control[1];
      if (control[2] === 1) return new Uint8Array(shared, 16, result).slice();
      if (control[2] === 2) return new TextDecoder().decode(new Uint8Array(shared, 16, result));
      return result;
    },
  };
}

if (!isMainThread) {
  const handles = new Map();
  let nextHandle = 1;
  function add(socket, server = false) {
    const state = { socket, server, queue: [], timeout: 30000, error: false };
    socket.on('error', () => { state.error = true; });
    if (server) socket.on('connection', client => { state.queue.push(client); client.on('error', () => {}); });
    const handle = nextHandle++;
    handles.set(handle, state);
    return handle;
  }
  function wait(state, event, timeout) {
    return new Promise(resolve => {
      let timer;
      const done = () => { clearTimeout(timer); state.socket.off(event, done); state.socket.off('error', done); state.socket.off('end', done); resolve(); };
      state.socket.once(event, done);
      state.socket.once('error', done);
      state.socket.once('end', done);
      timer = setTimeout(done, timeout);
    });
  }
  const operations = {
    async connect(host, port, proto, secure, timeout) {
      if (proto !== 6) return -1; // Node adapter currently provides TCP/TLS.
      const socket = secure ? tls.connect({ host, port: Number(port), servername: host }) : net.connect({ host, port: Number(port) });
      const handle = add(socket);
      const state = handles.get(handle);
      let connected = false;
      const event = secure ? 'secureConnect' : 'connect';
      socket.once(event, () => { connected = true; });
      await wait(state, event, timeout > 0 ? timeout * 1000 : 30000);
      if (!connected || state.error) { operations.close(handle); return -1; }
      return handle;
    },
    async listen(port, local, proto) {
      if (proto !== 0 && proto !== 6) return -1;
      const socket = net.createServer();
      const handle = add(socket, true);
      const state = handles.get(handle);
      const pending = wait(state, 'listening', 30000);
      socket.listen(Number(port), local ? '127.0.0.1' : '0.0.0.0');
      await pending;
      if (!socket.listening || state.error) { operations.close(handle); return -1; }
      return handle;
    },
    async accept(handle) {
      const state = handles.get(handle);
      if (!state.server) return -1;
      if (!state.queue.length) await wait(state, 'connection', state.timeout);
      return state.queue.length ? add(state.queue.shift()) : -1;
    },
    async read(handle, length) {
      const state = handles.get(handle);
      if (!length) return new Uint8Array();
      if (!state.socket.readableLength && !state.socket.readableEnded && !state.error) await wait(state, 'readable', state.timeout);
      if (state.error) return -1;
      if (state.socket.readableLength) return state.socket.read(Math.min(length, state.socket.readableLength));
      return state.socket.readableEnded ? new Uint8Array() : -1;
    },
    async write(handle, data) {
      const state = handles.get(handle);
      if (state.error || !state.socket.writable) return -1;
      return new Promise(resolve => state.socket.write(data, error => resolve(error ? -1 : data.length)));
    },
    close(handle) {
      const state = handles.get(handle);
      if (!state) return -1;
      for (const client of state.queue) client.destroy();
      if (state.server) state.socket.close(); else state.socket.destroy();
      handles.delete(handle);
      return 0;
    },
    async ready(handle, sec, usec) {
      const state = handles.get(handle);
      const ready = () => state.server ? state.queue.length > 0 : state.socket.readableLength > 0 || state.socket.readableEnded;
      if (!ready() && !state.error && (sec > 0 || usec > 0)) await wait(state, state.server ? 'connection' : 'readable', Math.max(0, sec * 1000 + usec / 1000));
      return state.error ? -1 : Number(ready());
    },
    block_time(handle, block, sec, usec) {
      handles.get(handle).timeout = block ? (Math.max(0, sec * 1000 + usec / 1000) || 30000) : 0;
      return 0;
    },
    peer(handle) {
      const socket = handles.get(handle).socket;
      return socket.remoteAddress ? `${socket.remoteAddress}:${socket.remotePort}` : -1;
    },
  };
  parentPort.on('message', async ({ op, args, shared }) => {
    const control = new Int32Array(shared, 0, 4);
    try {
      const result = await operations[op](...args);
      if (result instanceof Uint8Array || typeof result === 'string') {
        const bytes = typeof result === 'string' ? new TextEncoder().encode(result) : result;
        new Uint8Array(shared, 16, bytes.length).set(bytes);
        control[1] = bytes.length;
        control[2] = typeof result === 'string' ? 2 : 1;
      } else control[1] = result;
    } catch { control[1] = -1; }
    Atomics.store(control, 0, 1);
    Atomics.notify(control, 0);
  });
}

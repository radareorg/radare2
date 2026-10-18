// Run fetch on another thread while the synchronous WASM import waits.
import { Worker, workerData, parentPort } from 'node:worker_threads';

export function createNodeHttp({ enabled = false, timeout = 30000, maxResponse = 16 * 1024 * 1024 } = {}) {
  if (!enabled) return { request() { throw new Error('HTTP disabled'); }, close() {} };
  if (!Number.isSafeInteger(maxResponse) || maxResponse < 0 || maxResponse > 0x7ffffffe || !Number.isFinite(timeout) || timeout <= 0) throw new RangeError('HTTP limits');
  const worker = new Worker(new URL(import.meta.url), { workerData: { r2http: true } });
  let closed = false;
  worker.on('error', () => { closed = true; });
  worker.on('exit', () => { closed = true; });
  const close = () => { closed = true; return worker.terminate(); };
  return {
    close,
    request(method, url, headers, body) {
      if (closed) throw new Error('HTTP adapter closed');
      const shared = new SharedArrayBuffer(12 + maxResponse);
      const control = new Int32Array(shared, 0, 3);
      worker.postMessage({ method, url, headers, body, shared, timeout });
      if (Atomics.wait(control, 0, 0, timeout) === 'timed-out') {
        close();
        throw new Error('HTTP timeout');
      }
      if (!control[1]) throw new Error('HTTP request failed');
      return { status: control[1], body: new Uint8Array(shared, 12, control[2]) };
    },
  };
}

if (workerData?.r2http) {
  parentPort.on('message', async ({ method, url, headers, body, shared, timeout }) => {
    const control = new Int32Array(shared, 0, 3);
    const output = new Uint8Array(shared, 12);
    try {
      const response = await fetch(url, { method, headers, body, signal: AbortSignal.timeout(timeout) });
      let length = 0;
      if (response.body) {
        for await (const chunk of response.body) {
          if (length + chunk.length > output.length) throw new RangeError('HTTP response too large');
          output.set(chunk, length);
          length += chunk.length;
        }
      }
      control[1] = response.status;
      control[2] = length;
    } catch { control[1] = 0; }
    Atomics.store(control, 0, 1);
    Atomics.notify(control, 0);
  });
}

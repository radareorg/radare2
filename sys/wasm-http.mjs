// The C ABI is synchronous: request must return { status, body: Uint8Array }.
export function createHttpImports(getExports, { enabled = false, request = browserRequest } = {}) {
  function call(post, url, headers, data, code, length) {
    const method = post ? 'POST' : 'GET';
    const exports = getExports();
    const setInt = (p, value) => { if (p) new DataView(exports.memory.buffer).setInt32(p >>> 0, value, true); };
    function string(p) {
      if (!p) return '';
      p >>>= 0;
      const bytes = new Uint8Array(exports.memory.buffer);
      const end = bytes.indexOf(0, p);
      if (end < 0) throw new RangeError('WASM string');
      return new TextDecoder().decode(bytes.subarray(p, end));
    }
    let pointer = 0;
    try {
      setInt(code, 0);
      setInt(length, 0);
      if (!enabled) return 0;
      const address = new URL(string(url));
      if (!['http:', 'https:'].includes(address.protocol)) return 0;
      const { status, body } = request(method, address.href, string(headers), method === 'POST' ? string(data) : undefined);
      if (!(body instanceof Uint8Array) || body.length > 0x7ffffffe || !Number.isInteger(status) || status < 100 || status > 599) return 0;
      pointer = exports.malloc(body.length + 1) >>> 0;
      if (!pointer) return 0;
      // malloc may grow memory: always obtain a new view.
      const memory = new Uint8Array(exports.memory.buffer);
      memory.set(body, pointer);
      memory[pointer + body.length] = 0;
      setInt(code, status);
      setInt(length, body.length);
      return pointer;
    } catch {
      if (pointer) exports.free(pointer);
      return 0;
    }
  }
  return { http_request: call };
}

// Dedicated browser Worker only; CORS and browser credential policies still apply.
function browserRequest(method, url, headers, body) {
  const xhr = new XMLHttpRequest();
  xhr.open(method, url, false);
  xhr.responseType = 'arraybuffer';
  for (const [name, value] of parseHeaders(headers)) xhr.setRequestHeader(name, value);
  xhr.send(body);
  return { status: xhr.status, body: new Uint8Array(xhr.response || new ArrayBuffer(0)) };
}

// Convert only at the transport boundary; application callbacks receive a string.
export function parseHeaders(headers) {
  return headers.split('\n').filter(Boolean).map(line => {
    const colon = line.indexOf(':');
    if (colon < 1) throw new TypeError('HTTP header');
    return [line.slice(0, colon).trim(), line.slice(colon + 1).trim()];
  });
}

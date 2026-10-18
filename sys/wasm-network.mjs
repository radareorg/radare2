// Synchronous r2net imports. A transport owns its handles and returns -1 on errors.
export function createNetworkImports(getExports, { enabled = false, transport } = {}) {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  function memory(pointer, length) {
    pointer >>>= 0;
    const bytes = new Uint8Array(getExports().memory.buffer);
    if (length < 0 || pointer + length > bytes.length) throw new RangeError('WASM buffer');
    return bytes.subarray(pointer, pointer + length);
  }
  function string(pointer) {
    pointer >>>= 0;
    const bytes = new Uint8Array(getExports().memory.buffer);
    const end = bytes.indexOf(0, pointer);
    if (end < 0) throw new RangeError('WASM string');
    return decoder.decode(bytes.subarray(pointer, end));
  }
  function call(name, ...args) {
    if (!enabled || !transport) return -1;
    return transport.call(name, args);
  }
  const methods = {
    connect: (host, port, proto, tls, timeout) => call('connect', string(host), string(port), proto, tls, timeout),
    listen: (port, local, proto) => call('listen', string(port), local, proto),
    accept: fd => call('accept', fd),
    close: fd => call('close', fd),
    ready: (fd, sec, usec) => call('ready', fd, sec, usec),
    block_time: (fd, block, sec, usec) => call('block_time', fd, block, sec, usec),
    read(fd, pointer, length) {
      memory(pointer, length);
      const data = call('read', fd, Math.min(length, 65536));
      if (!(data instanceof Uint8Array) || data.length > length) return -1;
      memory(pointer, data.length).set(data);
      return data.length;
    },
    write: (fd, pointer, length) => call('write', fd, memory(pointer, Math.min(length, 65536)).slice()),
    peer(fd, pointer, length) {
      memory(pointer, length);
      const peer = call('peer', fd);
      if (typeof peer !== 'string') return -1;
      const data = encoder.encode(peer + '\0');
      if (data.length > length) return -1;
      memory(pointer, data.length).set(data);
      return data.length - 1;
    },
  };
  return { r2net: Object.fromEntries(Object.entries(methods).map(([name, fn]) => [name, (...args) => {
    if (!enabled) return -1;
    try { return fn(...args); } catch { return -1; }
  }])) };
}

// Use in a dedicated browser Worker. XHR is synchronous to match the C ABI.
// The C browser HTTP path requires both sandbox socket and network permissions.
export function createBrowserHttpImports(getExports, { enabled = false } = {}) {
  function request(method, url, headers, data, code, length) {
    const exports = getExports();
    const setInt = (ptr, value) => { if (ptr) new DataView(exports.memory.buffer).setInt32(ptr >>> 0, value, true); };
    setInt(code, 0);
    setInt(length, 0);
    if (!enabled) return 0;
    function string(ptr) {
      if (!ptr) return '';
      const memory = new Uint8Array(exports.memory.buffer);
      const end = memory.indexOf(0, ptr >>> 0);
      if (end < 0) throw new RangeError('WASM string');
      return new TextDecoder().decode(memory.subarray(ptr >>> 0, end));
    }
    let pointer = 0;
    try {
      const address = new URL(string(url));
      if (!['http:', 'https:'].includes(address.protocol)) return 0;
      const xhr = new XMLHttpRequest();
      xhr.open(method, address.href, false);
      xhr.responseType = 'arraybuffer';
      for (const header of string(headers).split('\n')) {
        const colon = header.indexOf(':');
        if (colon > 0) xhr.setRequestHeader(header.slice(0, colon), header.slice(colon + 1).trim());
      }
      xhr.send(method === 'POST' ? string(data) : null);
      const bytes = new Uint8Array(xhr.response || new ArrayBuffer(0));
      pointer = exports.malloc(bytes.length + 1) >>> 0;
      if (!pointer) return 0;
      const memory = new Uint8Array(exports.memory.buffer);
      memory.set(bytes, pointer);
      memory[pointer + bytes.length] = 0;
      setInt(code, xhr.status);
      setInt(length, bytes.length);
      return pointer;
    } catch {
      if (pointer) exports.free(pointer);
      return 0;
    }
  }
  return { http_get: (u, h, c, l) => request('GET', u, h, 0, c, l),
    http_post: (u, h, d, c, l) => request('POST', u, h, d, c, l) };
}

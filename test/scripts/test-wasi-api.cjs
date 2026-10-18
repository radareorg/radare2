const assert = require('node:assert/strict');
const fs = require('node:fs');
const { WASI } = require('node:wasi');

async function main() {
	const [path, version] = process.argv.slice(2);
	assert.ok(path && version, 'Usage: node test-wasi-api.cjs module.wasm version');
	const module = await WebAssembly.compile(fs.readFileSync(path));
	const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {}, returnOnExit: true });
	const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi.wasiImport });
	wasi.initialize(instance);
	const api = instance.exports;
	const core = api.r_core_new();
	assert.ok(core, 'r_core_new failed');
	function command(text) {
		const bytes = Buffer.from(text + '\0');
		const input = api.malloc(bytes.length);
		assert.ok(input, 'malloc failed');
		let output = 0;
		try {
			new Uint8Array(api.memory.buffer, input, bytes.length).set(bytes);
			output = api.r_core_cmd_str(core, input);
			assert.ok(output, 'r_core_cmd_str failed');
			const memory = new Uint8Array(api.memory.buffer);
			const end = memory.indexOf(0, output);
			assert.ok(end >= output, 'Unterminated command output');
			return Buffer.from(memory.subarray(output, end)).toString().trim();
		} finally {
			api.free(output);
			api.free(input);
		}
	}
	try {
		assert.equal(command('?V').split(/\s+/)[1], version);
		assert.equal(command('?v 1+2'), '0x3');
		command('o malloc://16');
		command('wx 01020304');
		assert.equal(command('p8 4'), '01020304');
	} finally {
		api.r_core_free(core);
	}
	console.log('WASI API smoke test passed');
}

main().catch(error => {
	console.error(error);
	process.exitCode = 1;
});

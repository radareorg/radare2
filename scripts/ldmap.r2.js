/* ldmap.r2.js: parser for GNU ld map files -- by pancake@nopcode.org */

const mapFileName = "/tmp/pebble-app.map";

function isZeroAddress(addr) {
	return addr.replace(/^0x0*/i, '') === '';
}

function parseMapLine(line) {
	let match = line.match(/^\s*\S+\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+|\d+)\s+(.+)$/);
	if (!match) {
		match = line.match(/^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+|\d+)\s+(.+)$/);
	}
	if (!match) {
		return null;
	}
	return {
		addr: match[1],
		file: match[3].trim(),
	};
}

function loadLinesFromLdMap(fileName) {
	const script = [];
	const lines = r2.cmd("cat " + fileName).split("\n");
	let inMap = false;
	for (const line of lines) {
		const trimmed = line.trim();
		if (!inMap) {
			if (trimmed === "Linker script and memory map") {
				inMap = true;
			}
			continue;
		}
		if (trimmed === "DISCARD") {
			break;
		}
		const item = parseMapLine(line);
		if (item && item.file && !isZeroAddress(item.addr)) {
			script.push("'CL " + item.addr + " " + item.file + ":0");
		}
	}
	return script;
}

loadLinesFromLdMap(mapFileName).map(r2.cmd);

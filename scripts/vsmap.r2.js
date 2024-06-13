/* parser for the msvc map files */

const mapFileName = "Sqlite3Console.map";

function filterFlag(symName) {
	return "sym." + symName.replace(/[^a-zA-Z0-9]/g, '_');
}

function loadFlagsFromVsMap(fileName) {
	const script = [];
	const lines = r2.cmd("cat " + fileName).split("\n");
	let publics = false;
	for (const line of lines) {
		if (!publics) {
			if (line.indexOf("Publics") !== -1) {
				publics = true;
			}
			continue;
		}
		const [paddr, symName, symAddr, objName] = line.trim().split(/\s+/);
		if (symName && symAddr) {
			const flagName = filterFlag(symName);
			script.push("'f " + flagName + " = 0x" + symAddr.replace(/^0+/g, ''));
		}
	}
	return script;
}

loadFlagsFromVsMap(mapFileName).map(r2.cmd);

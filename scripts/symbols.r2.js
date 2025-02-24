/* parser symbols files from xcode */
const mapFileName = "r2.map";

function filterFlag(symName) {
	return "sym." + symName.replace(/[^a-zA-Z0-9]/g, '_');
}

function loadFlagsFromSymbols(fileName) {
	const script = [];
	const lines = r2.syscmds("xcrun symbols " + fileName).split("\n");
	for (const line of lines) {
		if (line.indexOf("0x") !== -1) {
			if (line.indexOf("FUNC") !== -1) {
				const adr = line.indexOf ("(");
				const beg = line.indexOf (")");
				const end = line.indexOf ("[");
				if (beg !== -1 && end !== -1 && adr !== -1) {
					const addr = line.substr (0, adr).trim();
					const name = line.substr (beg, end - beg).trim();
					script.push("'f " + name + " = " + addr);
				}
			} else {
				const adr = line.indexOf ("(");
				const beg = line.indexOf (")");
				if (beg !== -1 && adr !== -1) {
					const addr = line.substr (0, adr).trim();
					const file= line.substr (adr).trim();
					script.push("'CL " + addr + " = " + file);
				}
			}
		}
	}
	return script;
}

loadFlagsFromSymbols(mapFileName).map(r2.cmd);


#!/usr/bin/env -S r2 -j
(function() {
	// TODO: get rid of theses aliases
	const compat = {
		"LGPLv3": "LGPL-3.0-only",
		"LGPL3": "LGPL-3.0-only",
		"LGPL2": "LGPL-2.0-only",
		"LGPL": "LGPL-2.0-only",
		"GPL3": "GPL-3.0-only",
		"GPL2": "GPL-2.0-only",
		"GPL": "GPL-2.0-only",
		"BSD": "BSD-3-Clause", // maybe 2?
		"BSD-3": "BSD-3-Clause",
		"Apache": "Apache-2.0",
	}
	const cache = {};
	function getLicense(name) {
		if (!name) {
			return name;
		}
		const aliasedName = compat[name]? compat[name]: name;
		if (cache[aliasedName]) {
			return cache[aliasedName];
		}
		if (aliasedName != name) {
			console.log("\x1b[33mALIASED\x1b[0m " + name);
		}
		const found = r2.cmd("test -f doc/licenses/" + aliasedName + ".txt;?v $?").trim() == 0;
		if (found) {
			return r2.cmd("cat doc/licenses/" + aliasedName + ".txt");
		}
		const response = r2.syscmds("curl -s https://spdx.org/licenses/"+aliasedName+".json");
		try {
			const res = JSON.parse(response).licenseText;
			cache[aliasedName] = res;
			r2.call("mkdir -p doc/licenses");
			r2.cmd("p6ds " + b64(res) + " > doc/licenses/"+ aliasedName + ".txt");
			return res;
		} catch (e) {
			return undefined;
		}
	}
	const data = r2.cmdj("!!r2 -Vj");
	console.log(data.radare2.license);
	for (let module of Object.keys(data.thirdparty)) {
		const moduleLicense = data.thirdparty[module].license;
		const hasLicense = getLicense(moduleLicense)? "OK": "\x1b[31mERROR\x1b[0m";
		console.log(module + " " + moduleLicense + " " + hasLicense);
	}
	for (let library of Object.keys(data.plugins)) {
		console.log("- " + library);
		for (let plugin of data.plugins[library]) {
			const hasLicense = getLicense(plugin.license)? "OK": "\x1b[31mERROR\x1b[0m";
			console.log("  - " + plugin.name + " : " + plugin.license + "    " + hasLicense);
		}
	}
})();

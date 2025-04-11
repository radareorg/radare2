var tagsRegisterPlugin = (function () {
	var tags = {};
	function loadTagsFile(tagsFile) {
		const lines = r2.cmd("cat " + tagsFile).split(/\n/g);;
		for (let line of lines) {
			const cols = line.split(/\t/g);
			tags[cols[0]] = {
				file: cols[1],
				expr: cols[2],
			}
		}
	}
	function catFunction(name) {
		const found = tags[name];
		if (found) {
			console.log(JSON.stringify(tags[name], null, 2));
			const par = found.expr.indexOf("(");
			if (par != -1) {
				found.expr = found.expr.substr(0, par- 1);
			}
			const res = r2.cmd("cat " + found.file);
			const beg = new RegExp (found.expr.substr(2));
			const end = new RegExp (/\n}/);
			const fileData = r2.cmd("cat " + found.file);
			if (fileData && fileData.length > 0) {
				const index = fileData.search(beg);
				if (index >= 0) {
					const functionData = fileData.substr(index);
					const elfin = functionData.search(end);
					if (elfin != -1) {
						r2.log(functionData.substr(0, elfin + 2));
						return true;
					}
				} else {
					console.log("Cannot find pattern: "+ beg);
				}
			} else {
				console.log("Cannot open " + found.file);
			}
		}
		return false;
	}
function tagsCommand(cmd) {
	const args = cmd.substr(4).trim();
	if (args.startsWith("-f")) {
		loadTagsFile(args.substr(2).trim());
	} else if (args.startsWith("-h")) {
		console.log("Usage: tags [args]");
		console.log("  tags -f ./tags    - load tags in memory");
		console.log("  tags main         - show function contents from file");
		console.log("  tags              - show function in current offset");
	} else if (args === "") {
		let functionName = r2.cmd("isqq.").trim();
		if (functionName === "") {
			functionName = r2.cmd("fd").trim();
			if (functionName) {
				const space = functionName.indexOf(" ");
				if (space != -1) {
					functionName = functionName.substr(0, space);
				}
			}
		}
		if (functionName.startsWith("_")) {
			if (!catFunction(functionName)) {
				catFunction(functionName.substr(1));
			}
		} else {
			catFunction(functionName);
		}
	} else if (args.startsWith("-d")) {
		const dir = args.substr(2).trim();
		r2.cmd("cd " + dir);
	} else {
		catFunction(args);
	}
}
function main() {
	r2.unload('core', 'tags');
	r2.plugin('core', function () {
		function coreCall (cmd) {
			if (cmd.startsWith('tags')) {
				try {
					tagsCommand(cmd);
				} catch (e) {
					console.error(e);
				}
				return true;
			}
			return false;
		}
		return {
			name: 'tags',
			license: 'MIT',
			desc: 'read function from ctags',
			call: coreCall
		};
	});
}
return main;
})();
tagsRegisterPlugin();


(function() {
	let { log } = console;

	function examplePlugin() {
		function coreCall(input) {
			if (input.startsWith("t1")) {
				log("This is a QJS test");
				return true;
			}
			return false;
		}
		return {
			name: "qjs-example",
			desc: "Example QJS plugin (type 't1') in the r2 shell",
			call: coreCall,
		};
	}

	function examplePlugin2() {
		function coreCall(input) {
			if (input.startsWith("t2")) {
				log("This is another QJS test");
				return true;
			}
			return false;
		}
		return {
			name: "qjs-example2",
			desc: "Example QJS plugin (type 't2') in the r2 shell",
			call: coreCall,
		};
	}

	log("Installing the `qjs-example` core plugin");
	log("Type 'test' to confirm it works");
	console.log("load true", r2.plugin("core", examplePlugin));
	console.log("load true", r2.plugin("core", examplePlugin2));
	if (false) {
		console.log("load true", r2.plugin("core", examplePlugin));
		console.log("load true", r2.plugin("core", examplePlugin2));
		console.log("load false", r2.plugin("core", examplePlugin));
		console.log("unload false", r2.unload("false"));
		console.log("unload true", r2.unload("qjs-example"));
		console.log("unload false", r2.unload("qjs-example"));
		log("Plugins:");
		log(r2cmd("Lc"));
	}
})();

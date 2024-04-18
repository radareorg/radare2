(function() {
	let { log } = console;

	function parseExample() {
		function parseCall(input) {
			return input.replace("sp, -0x60", "LOCALVAR");
		}
		return {
			name: "qjs",
			desc: "Example QJS RParse plugin (qjs://)",
			parse: parseCall,
		};
	}

	r2.plugin("parse", parseExample);
	r2.cmd("-e asm.parser=qjs");
	r2.cmd("-e asm.pseudo=true");
	r2.cmd("pd 10");
})();


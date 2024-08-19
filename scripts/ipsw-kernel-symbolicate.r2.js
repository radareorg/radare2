// script to symbolicate iOS kernels with IPSW by pancake
// ref: https://blacktop.github.io/ipsw/blog/kernel-symbolication/

function loadFlagsFromIpswKsym(jsonFiles) {
	function filterFlag(symName) {
		return "sym." + symName.replace(/[^a-zA-Z0-9]/g, '_');
	}
	const script = [];
	for (const jf of jsonFiles) {
		const data = JSON.parse(r2.cmd("cat " + jf));
		for (const item of data) {
			script.push("'f ksym." + filterFlag(item.sym) + " = " + item.addr);
		}
	}
	script.map(r2.cmd0);
}

const jsonFiles = r2.cmdj("ls -j *.js").map((x) => x.name);
loadFlagsFromIpswKsym(jsonFiles);

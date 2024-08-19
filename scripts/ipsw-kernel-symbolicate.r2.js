// script to symbolicate iOS kernels with IPSW by pancake
// ref: https://blacktop.github.io/ipsw/blog/kernel-symbolication/

const jsonFiles = r2.cmdj("ls -j *.js").map((x) => x.name);

function filterFlag(symName) {
	return "sym." + symName.replace(/[^a-zA-Z0-9]/g, '_');
}

function loadFlagsFromIpswKsym(jsonFiles) {
	const script = [];
	for (const jf of jsonFiles) {
		const data = JSON.parse(r2.cmd("cat " + jf));
		const flagName = filterFlag(jf.sym);
		script.push("'f ksym." + flagName + " = " + jf.addr);
	}
	script.map(r2.cmd0);
}

loadFlagsFromIpswKsym(jsonFiles);


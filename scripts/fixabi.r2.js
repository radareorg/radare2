(function() {
	function yesno(msg) {
		return +r2.cmd("?iy " + msg + "@e:scr.interactive=true;?vi $?") === 1;
	}
	let pava = r2.cmd("iE,name/eq/radare_plugin,1/head/1,:noheader,paddr/cols/vaddr").trim();
	if (pava) {
		const [pa, va] = pava.split(/ /);
		console.log(va);
		console.log(pa);
		const abi = r2.cmdj("-Vj").abiversion;
		const v = +r2.callAt("pv4d", va + "+0x28");
		if (v < 1 || v > 256) {
			console.log("Invalid abiversion extracted from bin, better to ignore");
		} else if (v == abi) {
			console.log("Abiversion seems correct. Nothing to do here");
		} else {
			console.log("expected abi:", abi);
			console.log("found abi:", v);
			const filename = r2.cmd("o.").trim();
			if (filename && yesno (`Fix abiversion for ${filename}?`)) {
				r2.cmd2(`!!r2 -nwc 'wv4 ${abi} @ ${pa}+0x28' ${filename}`);
				console.log("Done");
			} else {
				console.log("Ok, not doing anything");
			}
		}
	} else {
		console.log("This is not a radare plugin");
	}
}());

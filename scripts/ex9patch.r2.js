// find and patch all ex9.it instructions for NDS32 binaries
// run it like this: `r2 -q -i ex9patch.r2.js at.elf`
// run the script within r2 with the `.` command (`. ex9patch.r2.js`)
(() => {
	console.log("### NDS32 ex9it patcher");
	r2.call("e cfg.json.num = hex");
	const ex9base = r2.cmd('f~_EX9_BASE_[0]').trim();
	if (!ex9base) {
		console.error("ERROR: Cannot find the EX9_BASE");
		console.error("If you know where it is, run this command:");
		console.error("   f _EX9_BASE_ = 0x123456");
		return;
	}
	console.log(`## Using EX9_BASE at ${ex9base}`);
	r2.call("-e search.in=io.map");
	const ops = r2.cmdj ("/adj ex9.it");
	for (const op of ops) {
		const ex9arg = op.code.split(/ /)[1];
		const at = r2.cmd(`'?v ${ex9base} + (4 * ${ex9arg})`).trim();
		const ex9op = r2.cmdj(`aoj @ ${at}`)[0];
		if (op.len != 2 || ex9op.size != 4) {
			console.error ("Weird ex9it expansion here (2 !=> 4)");
		}
		console.log(JSON.stringify(ex9op, 2));
		console.log(`[${op.addr}] ${op.code} => [${at}] ${ex9op.disasm}`);
		r2.callAt("CC was:ex9it", op.addr);
		r2.callAt(`ahd ${ex9op.disasm}`, op.addr);
		r2.callAt(`aho ${ex9op.type}`, op.addr);
		if (ex9op.jump) {
			r2.callAt(`ahc ${ex9op.jump}`, op.addr);
		}
		if (ex9op.esil) {
			r2.callAt(`ahe ${ex9op.esil}`, op.addr);
		}
	}
})();

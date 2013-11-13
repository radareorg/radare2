/* gadget_search.vala - LGPL - Copyright 2010 nibble <develsec.org>
 * LaCon'10 */

using Radare;

static RCore c;

static void dosearch(string pattern, int ctx) {
	/* Get baddr */
	var baddr = c.bin.get_baddr ();
	/* Iterate over executable sections */
	foreach (var scn in c.bin.get_sections ()) {
		if ((scn.srwx & 0x1) == 0)
			continue;
		var from= baddr + scn.rva;
		var to = from + scn.size;
		print ("Looking for '%s' from 0x%08"+uint64.FORMAT_MODIFIER+
			   "x to 0x%08"+uint64.FORMAT_MODIFIER+"x\n\n", pattern, from, to);
		/* Look for the given pattern in the section */
		foreach (var hit in c.asm_strsearch (pattern, from, to)) {
			print ("-----[GADGET]-----\n");
			/* Disassemble context */
			var mid = c.disassemble_bytes (hit.addr, hit.len);
			var post = c.disassemble_instr (hit.addr+hit.len, ctx);
			var bwdhits = c.asm_bwdisassemble (hit.addr, ctx, 64);
			if (bwdhits.length () == 0)
				print ("%s-\n%s", mid, post);
			else foreach (var bwd in bwdhits) {
					var pre = c.disassemble_instr (bwd.addr, ctx);
					print ("%s-\n%s-\n%s--\n", pre, mid, post);
				}
		}
	}
}

public static void main(string[] args) {
	/* Parse args */
	if (args.length != 4)
		error ("Usage: %s <file> <pattern> <ctx>\n", args[0]);
	var file = args[1];
	var pattern = args[2];
	var ctx = args[3].to_int ();
	/* Init r_core */
	c = new RCore ();
	if (c.file_open (file, 0) == null)
		error ("Error: r_core cannot open the file");
	c.bin_load (file, 0);
	/* Enable va */
	c.config.set ("io.va", "true");
	/* Set minimal disasm */
	c.config.set ("asm.profile", "simple");
	c.config.set ("asm.comments", "false");
	c.config.set ("asm.functions", "false");
	/* Do search */
	dosearch (pattern, ctx);
}

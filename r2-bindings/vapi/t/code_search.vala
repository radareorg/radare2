/* code_search.vala - LGPL - Copyright 2010 nibble <develsec.org>
 * LaCon'10 */

using Radare;

static RCore c;

static void dosearch(string pattern) {
	/* Get baddr */
	var baddr = c.bin.get_baddr ();
	/* Iterate over sections and search in the executable ones */
	foreach (var scn in c.bin.get_sections ()) {
		if ((scn.srwx & 0x1) == 0)
			continue;
		var from= baddr + scn.rva;
		var to = from + scn.size;
		foreach (var hit in c.asm_strsearch (pattern, from, to))
			print ("0x%08"+uint64.FORMAT_MODIFIER+"x - %s (%i)\n",
					hit.addr, hit.code, hit.len);
	}
}

public static void main(string[] args) {
	/* Parse args */
	if (args.length != 3)
		error ("Usage: %s <file> <pattern>\n", args[0]);
	var file = args[1];
	var pattern = args[2];
	/* Init r_core */
	c = new RCore ();
	if (c.file_open (file, 0) == null)
		error ("Error: r_core cannot open the file");
	c.bin_load (null);
	/* Enable va */
	c.config.set ("io.va", "true");
	/* Do search */
	dosearch (pattern);
}

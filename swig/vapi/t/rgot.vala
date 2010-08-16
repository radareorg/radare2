/* Extract GOT addresses for each import symbol on 32 bit ELF binaries */
/* author: pancake // nopcode.org */

using Radare;

struct Rel {
	uint32 r_offset;
	uint16 r_info;
}

void main(string[] args) {
	if (args.length != 2)
		error ("Usage: %s <file>\n", args[0]);

	string file = args[1];
	var bin = new RBin ();
	if (bin.load (file, null) != 1)
		error ("Cannot open binary file\n");

	uint64 baddr = bin.get_baddr();
	int gotsize = 0, relpltsz = 0;
	uint64 gotaddr = 0, relplt = 0;
	
	foreach (var sec in bin.get_sections ()) {
		if (sec.name == ".got.plt") {
			gotaddr = sec.rva+baddr; // in memory offset
			gotsize = sec.size;
		} else
		if (sec.name == ".rel.plt") {
			relplt = sec.offset; // disk offset
			relpltsz = sec.size;
		}
	}
	if (relpltsz==0 || gotaddr==0)
		error ("Cannot find .rel.plt\n");

	var relpltp = RFile.slurp_range (file, relplt, relpltsz, out relpltsz);
	// only for 32 bit ELFs
	Rel *ptr = relpltp;

	foreach (var sym in bin.get_imports ()) {
		Rel gotrel = (Rel) ptr [(sym.ordinal-1)];
		uint64 got = gotrel.r_offset;
		//int nfo = gotrel.r_info >> 8;
		//stderr.print ("nfo %d\n", nfo);
		if (got >= gotaddr && got <= gotaddr+gotsize)
			print ("f got.%s @ 0x%08"+uint64.FORMAT_MODIFIER+"x\n", sym.name, got);
		else stderr.printf ("Cannot resolve GOT address for import '%s'\n", sym.name);
	}
}

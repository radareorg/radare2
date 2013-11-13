/* Extract GOT addresses for each import symbol on 32 bit ELF binaries */
/* author: pancake // nopcode.org */

using Radare;

// only for 32 bit ELFs
struct Rel {
	uint32 r_offset;
	uint16 r_info;
}

#if 0
// not used
struct Rel64 {
	uint64 r_offset;
	uint16 r_info;
}
#endif

void main(string[] args) {
	if (args.length != 2)
		error ("Usage: %s <file>\n", args[0]);

	string file = args[1];
	var bin = new RBin ();
	if (bin.load (file, false) != 1)
		error ("Cannot open binary file\n");

	uint64 baddr = bin.get_baddr();
	uint64 gotsize = 0, relpltsz = 0;
	uint64 gotaddr = 0, relplt = 0;
	
	foreach (var sec in bin.get_sections ()) {
		string name = (string)sec.name;
		if (name == ".got.plt") {
			gotaddr = sec.rva+baddr; // in memory offset
			gotsize = sec.size;
		} else
		if (name == ".rel.plt") {
			relplt = sec.offset; // disk offset
			relpltsz = sec.size;
		}
	}
	if (relpltsz==0 || gotaddr==0)
		error ("Cannot find .rel.plt\n");

	var relpltp = RFile.slurp_range (file, relplt, (int)relpltsz, out relpltsz);

	Rel *ptr = relpltp;
	Rel *ptrend = (Rel*)(((uint8*)relpltp) + relpltsz);

	foreach (var sym in bin.get_imports ()) {
		int n;
		uint64 got = 0;
		for (n=0, ptr = relpltp; ptr < ptrend; ptr++) {
			if ((ptr->r_info>>8) == sym.ordinal) {
				got = ptr->r_offset;
				break;
			}
			n++;
		}
		if (got >= gotaddr && got <= gotaddr+gotsize)
			print ("f got.%s @ 0x%08"+uint64.FORMAT_MODIFIER+"x\n", sym.name, got);
		else stderr.printf ("Cannot resolve GOT address for import '%s'\n", (string)sym.name);
	}
}

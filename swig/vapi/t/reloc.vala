/* Print address for each relocation entry */
/* Currently only ELF32 & ELF64 binaries are supported */
/* author: nibble <.ds@gmail.com> */

using Radare;

void main(string[] args) {
	if (args.length != 2)
		error ("Usage: %s <file>\n", args[0]);

	string file = args[1];
	var bin = new RBin ();
	if (bin.load (file, null) != 1)
		error ("Cannot open binary file\n");

	uint64 baddr = bin.get_baddr();
	
	foreach (var reloc in bin.get_relocs ())
		print ("f reloc.%s @ 0x%08"+uint64.FORMAT_MODIFIER+"x\n", reloc.name, baddr+reloc.rva);
}

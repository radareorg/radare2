/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */
// gcc array.c `pkg-config --libs --cflags r_util r_bin gobject-2.0` -I ../../include/

using Radare;

void main(string[] args) {
	var bin = new RBin();

	if (args.length==1)
		error("No file given");
	if (bin.load(args[1], false)<0)
		error("Cannot open file");

	foreach (var f in bin.get_entries())
		print("Entrypoint: 0x%08"+uint64.FORMAT_MODIFIER+"\n", f.offset);
	foreach (var f in bin.get_symbols())
		print(" - 0x%08"+uint64.FORMAT_MODIFIER+"x  %s\n", f.offset, f.name);

	foreach (var f in bin.get_sections())
		print(" - 0x%08"+uint64.FORMAT_MODIFIER+"x  %s\n", f.offset, f.name);
}

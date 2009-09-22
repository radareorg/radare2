/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */
// gcc array.c `pkg-config --libs --cflags r_util r_bin gobject-2.0` -I ../../include/

using Radare;

void main(string[] args) {
	var bin = new Bin();

	if (args.length==1)
		error("No file given");
	if (bin.open(args[1], false)<0)
		error("Cannot open file");

	print("Entrypoint: 0x%08llx\n", bin.get_entry()->offset);
	foreach (Bin.Symbol* f in bin.get_symbols())
		print(" - 0x%08llx  %s\n", f->offset, f->name);

	foreach (Bin.Section * f in bin.get_sections())
		print(" - 0x%08llx  %s\n", f->offset, f->name);

	bin.close();
}

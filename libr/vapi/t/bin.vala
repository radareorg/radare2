/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

using Radare;

public class BinExample
{
	public static int main(string[] args)
	{ 
		uint64 baddr;
		Bin.Entrypoint *e;
		Bin.Section *s;
		int i;

		if (args.length != 2) {
			stdout.printf("Usage: %s <file>\n", args[0]);
			return 1;
		}

		Bin bin = new Bin();
		if (!bin.open(args[1], false)) {
			stderr.printf("Cannot open binary file\n");
			return 1;
		}

		baddr = bin.get_baddr();
		stdout.printf("Base addr: 0x%08llx\n", baddr);

		e = bin.get_entry();
		stdout.printf("Entry point: 0x%08llx\n", baddr+e->rva);

		stdout.printf("SECTIONS\n");
		s = bin.get_sections();
		if (s != null)
		for (i=0; !s[i].last; i++) {
			stdout.printf("idx=%02i address=0x%08llx offset=0x%08llx"+
				" size=%08lli name=%s\n",
				i, baddr + s[i].rva, s[i].offset, s[i].size, s[i].name);
		}

		stdout.printf("IMPORTS\n");
		var imp = bin.get_imports();
		for (i=0; !imp[i].last; i++) {
			stdout.printf("idx=%02i name=%s\n", i, imp[i].name);
		}

		/* TODO: make it possible */ /*
		stdout.printf("SYMBOLS\n");
		foreach (unowned Bin.Symbol* sym in bin.symbols) {
			stdout.printf("  => name=%s\n", sym->name);
		}
		*/

		var sym = bin.get_symbols();
		for (i=0; !sym[i].last; i++) {
			stdout.printf("idx=%02i name=%s\n", i, sym[i].name);
		}

		bin.close();
		
		return 0;
	}
}

/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

using Radare;

public class rBinExample
{
	public static int main(string[] args)
	{ 
		uint64 baddr;
		int i;

		if (args.length != 2)
			error("Usage: %s <file>\n", args[0]);

		rBin bin = new rBin();
		if (bin.open(args[1], false)<2)
			error("Cannot open binary file\n");

		baddr = bin.get_baddr();
		print("Base addr: 0x%08llx\n", baddr);

		rBin.Entrypoint e = bin.get_entry();
		print("Entry point: 0x%08llx\n", baddr+e.rva);

		i=0;
		print("Sections:\n");
		foreach (rBin.Section s in bin.get_sections())
			print("idx=%02i address=0x%08llx offset=0x%08llx"+
				" size=%08lli name=%s\n", i++, baddr + s.rva,
				s.offset, s.size, s.name);

		i = 0;
		print("Imports\n");
		foreach(rBin.Import imp in bin.get_imports())
			print("idx=%02i name=%s\n", i++, imp.name);

		foreach(rBin.Symbol sym in bin.get_symbols())
			print("idx=%02i name=%s\n", i, sym.name);

		bin.close();
		
		return 0;
	}
}

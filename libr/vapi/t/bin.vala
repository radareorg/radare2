/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

using Radare;

public class RBinExample
{
	public static int main(string[] args)
	{ 
		uint64 baddr;

		if (args.length != 2)
			error("Usage: %s <file>\n", args[0]);

		RBin bin = new RBin();
		if (bin.load(args[1], null) != 1)
			error("Cannot open binary file\n");

		baddr = bin.get_baddr();
		print("Base addr: 0x%08llx\n", baddr);
		foreach (RBin.Symbol sym in bin.get_symbols())
			print("0x%08llx - %s\n", baddr+sym.rva, sym.name);
		
		return 0;
	}
}

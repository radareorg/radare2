/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

using Radare;

public class BinExample
{
	public static int main(string[] args)
	{ 
		uint64 baddr;
		Entry *e;
		Section *s;
		int i;

		if (args.length != 2) {
			stdout.printf("Usage: %s <file>\n", args[0]);
			return 1;
		}

		Bin bin = new Bin(args[1], 0);

		baddr = bin.get_baddr();
		stdout.printf("Base addr: 0x%08llx\n", baddr);

		e = bin.get_entry();
		stdout.printf("Entry point: 0x%08llx\n", baddr+e->rva);

		s = bin.get_sections();
		if (s != null)
		for (i=0;!s[i].last;i++) {
			stdout.printf("idx=%02i address=0x%08llx offset=0x%08llx"+
				" size=%08li name=%s\n",
				i, baddr + s[i].rva, s[i].offset, s[i].size, s[i].name);
		}

		bin.close();
		
		return 0;
	}
}

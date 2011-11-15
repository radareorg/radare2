/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

[CCode (cheader_filename="r_egg.h", cprefix="r_egg_", lower_case_cprefix="r_egg_")]
namespace Radare {
	[Compact]
	[CCode (cname="REgg", free_function="r_egg_free", cprefix="r_egg_")]
	public class REgg {
		public REgg ();
		public bool setup (string arch, int bits, bool bigendian, string os);
		public void load (string code, int fmt);
		public void include (string file, int fmt);
		public bool raw(uint8 *buf, int len);
		public bool encode(string name);
		public bool shellcode(string name);
		public void option_set(string k, string v);
		public string option_get (string k);
		public bool padding(string pad);
		public bool compile();
		public bool assemble();
		public RBuffer get_bin();
		public string get_assembly();
		public void append(string src);
		public int run();
	}
}

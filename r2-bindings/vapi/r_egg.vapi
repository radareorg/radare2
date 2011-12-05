/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

[CCode (cheader_filename="r_egg.h", cprefix="r_egg_", lower_case_cprefix="r_egg_")]
namespace Radare {
	[Compact]
	[CCode (cname="REggPlugin", free_function="r_egg_free", cprefix="r_egg_")]
	public class REggPlugin {
		string name;
		string desc;
		int type;
		//RBuffer build (void *egg);
	}

	[Compact]
	[CCode (cname="REgg", free_function="r_egg_free", cprefix="r_egg_")]
	public class REgg {
		public int arch;
		public int endian;
		public int bits;
		public uint32 os;
		public REgg ();
		public string to_string ();
		public void reset ();
		public bool setup (string arch, int bits, bool bigendian, string os);
		public void load (string code, int fmt);
		public void syscall(string arg, ...);
		public void alloc(int n);
		public void label (string name);
		public void include (string file, int fmt);
		public bool raw(uint8 *buf, int len);
		public bool encode(string name);
		public bool shellcode(string name);
		public void option_set(string k, string v);
		public string option_get (string k);
		public bool padding(string pad);
		public bool compile();
		public bool assemble();
		//public int patch (int off, const uint8 *b, int l);
		public string get_source ();
		public RBuffer get_bin();
		public string get_assembly();
		public void append(string src);
		public int run();
	}
}

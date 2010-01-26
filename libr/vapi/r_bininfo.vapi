/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

[CCode (cheader_filename="r_bininfo.h", cprefix="r_bininfo_", lower_case_cprefix="r_bininfo_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_bininfo_t", free_function="r_bininfo_free", cprefix="r_bininfo_")]
	public class RBininfo {
		public RBininfo ();
		// XXX bad signature?
		public int get_line (uint64 addr, out string file, int len, int *line);
		public bool set_source_path (string path);
		public string get_source_path ();
	}
}

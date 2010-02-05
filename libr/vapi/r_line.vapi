/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_lib.h", cprefix="r_lib_", cname="struct r_lib_t", free_function="r_lib_free")]
	public class RLine {
		public RLine(string symname);
		public bool init ();
		public bool readline (int argc, char **argv);

		public bool hist_load (string file);
		public bool hist_add (string line);
		public bool hist_save (string file);
		//public bool hist_label (string file);
	}
}

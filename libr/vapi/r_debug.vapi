/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_debug.h", cprefix="r_debug", lower_case_cprefix="r_debug_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_debug_t", free_function="r_debug_free", cprefix="r_debug_")]
	public class Debug {
		public Debug();
	}
}

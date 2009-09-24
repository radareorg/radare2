/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

[CCode (cheader_filename="r_parse.h", cprefix="r_parse_", lower_case_cprefix="r_parse_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_parse_t", free_function="r_parse_free", cprefix="r_parse_")]
	public class Parse {
		public Parse();

		public int init();
		public int list();
		public bool use(string name);
		public bool assemble(ref string dst, string src);
		public bool parse(ref string dst, string src);
		public void set_user_ptr(void *user);
		//TODO public bool @add();
		// This is the destructor
		public void free();
	}
}

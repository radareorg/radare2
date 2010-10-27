/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

[CCode (cheader_filename="r_parse.h,r_flags.h", cprefix="r_parse_", lower_case_cprefix="r_parse_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_parse_t", free_function="r_parse_free", cprefix="r_parse_")]
	public class RParse {
		public RParse();

		public int list();
		public bool use(string name);
		public bool assemble(ref string dst, string src);
		public bool parse(ref string dst, string src);
		public bool assemble(string data, string str);
		public bool filter(RFlag flag, string data, string str, int len);
		public void set_user_ptr(void *user);
		//TODO public bool @add();
		// This is the destructor
		public void free();
	}
}

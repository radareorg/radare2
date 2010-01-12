/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_lib.h", cprefix="r_", lower_case_cprefix="r_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_lib_t", free_function="r_lib_free")]
	public class rLibrary {
		public rLibrary(string symname);
		public rLibrary init(string symname);
		public bool close(void *ptr);
		public void* opendir(string path);
		public string types_get(int idx);

		/* lowlevel api */
		public void* dl_open(string libname);
		public void* dl_sym(string symname);
		public bool dl_close(void *lh);
		public bool dl_check_filename(string file);
		/* handlers */
	// we need delegates here (function pointerz)
	//	public bool add_handler(int type, string desc, /* */, void* user);
		public bool del_handler(int type);
		public Handler get_handler(int type);
		//public struct Struct { }
		[Compact]
		public struct Handler {
			int type;
			string desc;
			void* user;
			// constructor
			// destructor
		}
	}
}

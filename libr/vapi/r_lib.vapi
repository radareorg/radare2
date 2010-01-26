/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_lib.h", cprefix="r_lib_", cname="struct r_lib_t", free_function="r_lib_free")]
	public class RLibrary {
		public RLibrary(string symname);
		public RLibrary init(string symname);
		public bool close(void *ptr);
		public void* opendir(string path);
		public string types_get(int idx);

		/* lowlevel api */
		public static void* dl_open(string libname);
		public void* dl_sym(string symname);
		public static bool dl_close(void *lh);
		public static bool dl_check_filename(string file);
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

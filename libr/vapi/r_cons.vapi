/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_cons.h", cprefix="r_cons", lower_case_cprefix="r_cons_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_cons_t", free_function="r_cons_free", cprefix="r_cons_")]
	public class rCons {
		public static void printf(string fmt, ...);
		public static void strcat(string str);
		public static void memcat(string str, int len);
		public static void newline();
		public static void flush();
		//public static int fgets(out string buf, int len, int argc, string argv[]);
		public static int readchar();
		public static void any_key();
		public static int eof();
		public static int get_columns();
		public static int get_real_columns();
	}
}

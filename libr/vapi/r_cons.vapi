/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_cons.h", cprefix="r_cons", lower_case_cprefix="r_cons_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_cons_t", free_function="r_cons_free", cprefix="r_cons_")]
	public class RCons {
		public static bool init (); /* you have to call this before using it */

		public static bool is_interactive;
		public static bool is_html;
		public static bool eof();

		/* size of terminal */
		public static int rows;
		public static int columns;

		public static void printf(string fmt, ...);
		public static void strcat(string str);
		public static void memcat(string str, int len);
		public static void newline();
		public static void flush();
		//public static int fgets(out string buf, int len, int argc, string argv[]);
		public static int readchar();
		public static void any_key();
		public static int get_size(out int rows);
		//public static int get_columns();
		//public static int get_real_columns();
	}
}

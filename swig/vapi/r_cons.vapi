/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

[CCode (cheader_filename="r_cons.h", cprefix="r_cons", lower_case_cprefix="r_cons_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_cons_t", free_function="r_cons_free", cprefix="r_cons_")]
	public class RCons {
		public RCons ();
		[CCode (cname="Color_RED")]
		public static const string RED;
#if 0
			BLACK,
			BGRED,
			WHITE,
			RESET,
			MAGENTA,
			YELLOW,
			TURQOISE,
			BLUE,
			GRAY,
			/* TODO: bold colors */
		}
#endif
		public static bool init (); /* you have to call this before using it */

		public static bool is_interactive;
		public static bool is_html;
		public static bool eof();

		/* size of terminal */
		public static int rows;
		public static int columns;

		public static void clear();
		public static void clear00();
		public static void reset();
		public static void gotoxy(int x, int y);
		public static void set_raw(bool b);

		/* output */
		public static void printf(string fmt, ...);
		public static void strcat(string str);
		public static void memcat(string str, int len);
		public static void newline();
		public static void flush();

		//public static int fgets(out string buf, int len, int argc, string argv[]);
		/* input */
		public static int readchar();
		public static void any_key();
		public static int get_size(out int rows);
		public static bool yesno(bool def, string fmt, ...);
	}
}

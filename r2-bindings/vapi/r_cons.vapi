/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

[CCode (cheader_filename="r_cons.h", cprefix="r_cons", lower_case_cprefix="r_cons_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_cons_t", free_function="", cprefix="r_cons_")]
	/* XXX: LEAK */
	public class RCons {
//		public RCons ();
		public static RCons singleton ();

		static void free();
		[CCode (cname="Color_RED")]
		public static const string RED;
		[CCode (cname="Color_BLACK")]
		public static const string BLACK;
		[CCode (cname="Color_WHITE")]
		public static const string WHITE;
		[CCode (cname="Color_RESET")]
		public static const string RESET;
		[CCode (cname="Color_MAGENTA")]
		public static const string MAGENTA;
		[CCode (cname="Color_YELLOW")]
		public static const string YELLOW;
		[CCode (cname="Color_TURQOISE")]
		public static const string TURQOISE;
		[CCode (cname="Color_BLUE")]
		public static const string BLUE;
		[CCode (cname="Color_GRAY")]
		public static const string GRAY;
		/* TODO : add bold colors */

		public static bool is_interactive;
		public static bool is_html;
		public static bool eof();

		public static int pipe_open (string file, bool append);
		public static void pipe_close (int fd);

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
		public static void filter();
		public static void visual_flush();
		//public static void visual_write(weak string buf);

		//public static int fgets(out string buf, int len, int argc, string argv[]);
		/* input */
		public static int readchar();
		public static void any_key();
		public static int get_size(out int rows);
		public static bool yesno(bool def, string fmt, ...);

		public static int html_print (string ptr);
		public static int arrow_to_hjkl (int ch);
		public static unowned string get_buffer ();
		public static void grep (string str);
		//public static int grep_line (string str, int len);
		//public static int grepbuf (string str, int len);
		public static void invert (bool set, int color);
	}
}

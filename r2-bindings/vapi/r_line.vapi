/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cname="RLine", cheader_filename="r_line.h", cprefix="r_line_")]
	public class RLine {
		//public RLine();
		public static RLine singleton();
		public static bool readline (); //int argc, char **argv);
		public static void set_prompt (string promp);

		public static bool hist_load (string file);
		public static bool hist_add (string line);
		public static bool hist_save (string file);
		//public static bool hist_label (string file);
	}
}

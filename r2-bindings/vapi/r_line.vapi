/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_line.h", cprefix="r_line_")]
	public class RLine {
		public RLine(string symname);
		public static bool readline (int argc, char **argv);

		public static bool hist_load (string file);
		public static bool hist_add (string line);
		public static bool hist_save (string file);
		//public static bool hist_label (string file);
	}
}

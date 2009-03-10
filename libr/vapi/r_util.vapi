/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

[CCode (cheader_filename="r_util.h", cprefix="r_util_", lower_case_cprefix="r_util_")]
namespace Radare {
	[Compact]
	[CCode (cprefix="r_")]
	public static class Util {
		public static int hex_str2bin(string in, uint8 *buf);
	}
}


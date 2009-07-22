/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

[CCode (cheader_filename="r_util.h", cprefix="r_util_", lower_case_cprefix="r_util_")]
namespace Radare {
	[Compact]
	[CCode (cprefix="r_")]
	public static class Util {
		public static int hex_str2bin (string input, out uint8 *buf);
		public static int hex_bin2str (uint8 *buf, int len, out string str);
		/* mem */
		public static uint8 *mem_mem (uint8 *a, int al, uint8 *b, int bl);
		public static void mem_copyendian (uint8 *dest, uint8 *orig, int size, int endian);
		public static void mem_copyloop (uint8 *dest, uint8 *orig, int dsize, int osize);
		public static void mem_cmp_mask (uint8 *dest, uint8 *orig, uint8 *mask, int len);
		/* num */
		public static uint64 num_get(void *num, string str); // XXX void *
		//public static int offsetof(void *type, void *member);
	}
}


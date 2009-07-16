/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

[CCode (cheader_filename="r_util.h", cprefix="r_util_", lower_case_cprefix="r_util_")]
namespace Radare {
	[Compact]
	[CCode (cprefix="r_")]
	public static class Util {
		public static int hex_str2bin (string in, uint8 *buf);
		/* mem */
		public uint8 *mem_mem (uint8 *a, int al, uint8 *b, int bl);
		public void mem_copyendian (uint8 *dest, uint8 *orig, int size, int endian);
		public void mem_copyloop (uint8 *dest, uint8 *orig, int dsize, int osize);
		public void mem_cmp_mask (uint8 *dest, uint8 *orig, uint8 *mask, int len);
	}
}


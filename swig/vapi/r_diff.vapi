/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com>, pancake <nopcode.org>*/

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_diff.h", cname="struct r_diff_t", free_function="r_diff_free", cprefix="r_diff_")]
	public class RDiff {
		public RDiff (uint64 off_a = 0LL, uint64 off_b = 0LL);
		public int buffers (uint8* a, int la, uint8* b, int lb);
		public int buffers_static (uint8[] a, uint8[] b);
		public int buffers_delta (uint8[] a, uint8[] b);
		//public int set_callback(...);
		public int buffers_distance (uint8 *a, int la, uint8 *b, int lb, out uint32 distance, out double similarity);
		//public static int lines (string file, string sa, int la, string file2, string sb, int lb);

		public int lines(string a, int len, string b, int len);
		public static int gdiff(string file1, string file2, bool rad, bool va);
		public bool set_delta(int delta);

		[Compact]
		[CCode (cname="struct r_diff_plugin_t", destroy_function="", free_function="" )]
		public struct Plugin {
			public uint64 a_off;
			public uint8* a_buf;
			public int a_len;

			public uint64 b_off;
			public uint8* b_buf;
			public int b_len;
		}
	}
}

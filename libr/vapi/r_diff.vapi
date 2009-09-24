/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

[CCode (cheader_filename="r_diff.h", cprefix="r_diff_", lower_case_cprefix="r_diff_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_diff_t", free_function="r_diff_free", cprefix="r_diff_")]
	public class Diff {
		public Diff();
		public int buffers(uint8* a, int la, uint8* b, int lb);
		//public int set_callback(...);
		public int distance(uint8 *a, int la, uint8 *b, int lb, out int distance, out double similarity);
		public int lines(string file, string sa, string file2, string sb, int lb);

		[Compact]
		[CCode (cname="struct r_diff_handle_t", destroy_function="", free_function="" )]
		public class Operation {
			public uint64 a_off;
			public uint8* a_buf;
			public int a_len;

			public uint64 b_off;
			public uint8* b_buf;
			public int b_len;
		}
	}
}



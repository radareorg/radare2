/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_range.h", cprefix="r_range", lower_case_cprefix="r_range_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_range_t", free_function="r_range_free", cprefix="r_range_")]
	public class Range {
		/* lifecycle */
		public Range();
		public Range.from_string(string str);

		public Range.Item *item_get(uint64 addr);
		public uint64 size();
		public uint64 add_from_string(string str);
		public uint64 add_string(string str);
		public uint64 add(uint64 from, uint64 to, int rw);
		public bool sub(uint64 from, uint64 to);
		public bool merge(Range r);
		public bool contains(uint64 addr);
		public bool sort();
		public bool percent(); // XXX
		public bool list(bool rad); // XXX
		public bool get_n(int n, out uint64 from, out uint64 to);
		public Range *inverse(uint64 from, uint64 to, int flags);

		[Compact]
		[CCode (cname="struct r_core_file_t", cprefix="r_core_")]
		public static struct Item {
			public uint64 from;
			public uint64 to;
			public uint8 *data
			public int datalen;
		}
	}
}

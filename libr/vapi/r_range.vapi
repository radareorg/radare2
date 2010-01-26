/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

[Compact]
[CCode (cheader_filename="r_range.h", cname="struct r_range_t", free_function="r_range_free", cprefix="r_range_")]
public class Radare.RRange {
	/* lifecycle */
	public RRange();
	public RRange.from_string(string str);

	public Item *item_get(uint64 addr);
	public uint64 size();
	public uint64 add_from_string(string str);
	public uint64 add_string(string str);
	//public uint64 add(uint64 fr, uint64 to, int rw);
//		public bool sub(uint64 fr, uint64 to);
	//public bool merge(Range r);
	public bool contains(uint64 addr);
	public bool sort();
	//public bool percent(); // XXX
	public bool list(bool rad); // XXX
	public bool get_n(int n, out uint64 fr, out uint64 to);
	public Range *inverse(uint64 fr, uint64 to, int flags);

	[Compact]
	[CCode (cname="struct r_range_item_t", cprefix="r_range_item_")]
	public static struct Item {
		public uint64 fr;
		public uint64 to;
		public uint8 *data;
		public int datalen;
	}
}

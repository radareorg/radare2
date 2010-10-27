/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

[CCode (cheader_filename="r_flags.h", cprefix="r_flag_", lower_case_cprefix="r_flag_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_flag_item_t", free_function="free")]
	public class RFlagItem {
		string name;
		uint64 namehash;
		int space;
		uint64 size;
		uint64 offset;
		string cmd;
		//public void rename(string name);
	}
	[Compact]
	[CCode (cname="struct r_flag_t", free_function="r_flag_free", cprefix="r_flag_")]
	public class RFlag {
		public RFlag();
		public void list(bool rad);
		public RFlagItem get(string name);
		public RFlagItem get_i(uint64 addr);
		public bool unset(string name);
		public bool sort(int namesort);
		public static bool name_check(string name);
		public static bool name_filter(string name);
		public bool unset_i(uint64 addr);
		public void set(string name, uint64 addr, int size=1, bool dup=false);

		public void space_list();
		public string? space_get(int idx);
		public void space_set(string name);
	}
}

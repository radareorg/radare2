/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_search.h", cprefix="r_search", lower_case_cprefix="r_search_")]
namespace Radare.Search {
	[CCode (cname="R_SEARCH_", cprefix="R_SEARCH_")]
	public enum Mode {
		KEYWORD,
		REGEXP,
		PATTERN,
		STRING,
		AES
	}

	[Compact]
	[CCode (cname="struct r_search_t", free_function="r_search_free", cprefix="r_search_")]
	public class Searcher {
		public Searcher (Mode mode);
		public bool set_mode (Mode mode);
		public bool set_string_limits (uint32 min, uint32 max);
		public bool begin();
		//public bool set_callback(delegate callback, pointer user);
		public bool update(out uint64 from, uint8 *buf, long len);
		public bool update_i(uint64 from, uint8 *buf, long len);
		public bool kw_add(string kw, string binmask);
		public bool kw_add_hex(string kw, string binmask);
		public bool kw_add_bin(string kw, uint32 kw_len, string binmask, long bm_len);
		public bool kw_list();
		public int set_callback(Radare.Search.Callback cb, void *user);
	}

	[Compact]
	[CCode (cname="struct r_search_kw_t")]
	public struct Keyword {
		public unowned string keyword;
		public unowned string binmask;
		public uint8 *bin_keyword;
		public uint8 *bin_binmask;
		public int keyword_length;
		public int binmask_length;
		public int idx;
		public int count;
	}

	public static delegate int Callback(Radare.Search.Keyword s, void *user, uint64 addr);
}

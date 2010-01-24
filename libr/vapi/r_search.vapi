/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_search.h")]
namespace Radare {

	[Compact]
	[CCode (cname="struct r_search_t", free_function="r_search_free", cprefix="r_search_")]
	public class rSearch {
		public rSearch (Mode mode);
		public bool set_mode (Mode mode);
		public bool set_string_limits (uint32 min, uint32 max);
		public bool begin();
		public void kw_reset();
		public void reset();
		public bool update(out uint64 from, uint8 *buf, long len);
		public bool update_i(uint64 from, uint8 *buf, long len);
		public bool kw_add(string kw, string binmask);
		public bool kw_add_hex(string kw, string binmask);
		public bool kw_add_bin(string kw, uint32 kw_len, string binmask, long bm_len);
		public Keyword kw_list();
		public int set_callback(Callback cb, void *user);
		public int pattern_update(int size); // this is uint? long?
		public int set_pattern_size(int size); // this is uint? long?
		public int strings_update(uint64 addr, char *buf, int len, int enc);

		[CCode (cprefix="R_SEARCH_", cname="int")]
		public enum Mode {
			KEYWORD,
			REGEXP,
			PATTERN,
			STRING,
			XREFS,
			AES
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
	}

	[CCode (cname="rSearchCallback")]
	public static delegate int Callback(rSearch.Keyword s, void *user, uint64 addr);
}

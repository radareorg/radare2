/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

[CCode (cheader_filename="r_types_base.h,r_list.h,r_search.h", cname="struct r_search_t", free_function="r_search_free", unref_function="r_search_free", cprefix="r_search_")]
public class Radare.RSearch {
	[CCode (cname="RSearchCallback", has_target="false")]
	public delegate int Callback(Keyword s, void *user, uint64 addr);

	public RSearch (Mode mode);
	public bool set_mode (Mode mode);
//	public bool set_string_limits (uint32 min, uint32 max);
	public bool begin();
	public void reset(int mode);
// XXX must return bool?? or not? 3 state? or two?
	public int update(ref uint64 from, uint8 *buf, long len);
	public int update_i(uint64 from, uint8 *buf, long len);
	public RList<RSearch.Hit> find(uint64 addr, uint8 *buf, int len);

	public bool kw_add(Keyword kw);
	public void kw_reset();

	public void set_callback(Callback cb, void *user);
	//public int pattern_update(int size); // this is uint? long?
	//public int set_pattern_size(int size); // this is uint? long?
	public int strings_update(uint64 addr, uint8 *buf, int len);

	[CCode (cprefix="R_SEARCH_", cname="int")]
	public enum Mode {
		KEYWORD,
		REGEXP,
		PATTERN,
		STRING,
		XREFS,
		AES
	}
	public RList<Keyword> kws;

	[Compact]
	[CCode (cname="struct r_search_keyword_t", free_function="free", cprefix="r_search_keyword_")]
	public class Keyword {
		public string keyword;
		public string binmask;
		public uint8 *bin_keyword;
		public uint8 *bin_binmask;
		public int keyword_length;
		public int binmask_length;
		//public int idx;
		public int count;

		public Keyword.str (string str, string bmask, string data);
		//public Keyword.hex (string str, string bmask, string data);
		public Keyword (uint8 *s, int sl, uint8 *b, int bl, string data);
	}

	[Compact]
	[CCode (cname="struct r_search_hit_t", free_function="free", cprefix="r_search_hit_")]
	public class Hit {
		public /*unowned*/ Keyword kw;
		uint64 addr;
	}
}

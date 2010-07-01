/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

[Compact]
[CCode (cheader_filename="r_search.h", cname="struct r_search_t", free_function="r_search_free", cprefix="r_search_")]
public class Radare.RSearch {
	[CCode (cname="RSearchCallback", has_target="false")]
	public delegate int Callback(Keyword s, void *user, uint64 addr);

	public RSearch (Mode mode);
	public bool set_mode (Mode mode);
//	public bool set_string_limits (uint32 min, uint32 max);
	public bool begin();
	public void reset(int mode);
	public bool update(out uint64 from, uint8 *buf, long len);
	public bool update_i(uint64 from, uint8 *buf, long len);

	public bool kw_add(Keyword kw);
	public void kw_reset();
	public void kw_list();

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

	[Compact]
	[CCode (cname="struct r_search_keyword_t", free_function="free", cprefix="r_search_keyword_")]
	public class Keyword {
		public unowned string keyword;
		public unowned string binmask;
		public uint8 *bin_keyword;
		public uint8 *bin_binmask;
		public int keyword_length;
		public int binmask_length;
		public int idx;
		public int count;

		public Keyword.str (string str, string bmask, string data);
		//public Keyword.hex (string str, string bmask, string data);
		public Keyword (uint8 *s, int sl, uint8 *b, int bl, string data);
	}
}

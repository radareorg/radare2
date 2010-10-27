/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_meta.h,r_list.h,r_types_base.h", cname="RMeta", free_function="r_meta_free", cprefix="r_meta_")]
	public class RMeta {
		[Compact]
		[CCode (cname="RMetaItem")]
		public class Item {
			public uint64 from;
			public uint64 to;
			public uint64 size;
			public int type;
			public string str;
		}
		
	}
	public RList<RMeta.Item> data;

	[CCode (cprefix="R_META_WHERE_")]
	public enum Where {
		PREV,
		HERE,
		NEXT
	}
	[CCode (cprefix="R_META_")]
	public enum Type {
		ANY,
		DATA,
		CODE,
		STRING,
		STRUCT,
		COMMENT,
		FOLDER
	}

	//public int count (RMeta.Type type, uint64 from, uint64 to, 
	public string get_string(RMeta.Type, uint64 addr);
	public bool @add(RMeta.Type type, uint64 from, uint64 size, string str);
	public bool del(RMeta.Type type, uint64 from, uint64 size, string str);
	public RMeta.Item find(uint64 off, RMeta.Type type, RMeta.Where where);
	public bool cleanup (uint64 from, uint64 to);
	public static string tytpe_to_string(RMeta.Type type);
	public int list (RMeta.Type type);
}

/* radare - LGPL - Copyright 2009-2010 pancake<@nopcode.org> */

[Compact]
[CCode (cheader_filename="r_reg.h", cname="struct r_reg_t", free_function="r_reg_free", cprefix="r_reg_")]
public class Radare.RRegister {
	[CCode (cprefix="R_REG_TYPE_", cname="int")]
	public enum Type {
		GPR,
		DRX,
		FPU,
		MMX,
		XMM,
		FLG,
		SEG,
		LAST,
		ALL
	}

	[Compact]
	[CCode (cname="struct r_reg_item_t", destroy_function="", free_function="" )]
	public class Item {
		public string name;
		public int size;
		public int offset;
		public int packed_size;
		public Type type;
	}

	[Compact]
	[CCode (cname="struct r_reg_arena_t", destroy_function="", free_function="" )]
	public class Arena {
		public uint8* bytes;
		public int size;
	}
	
	[Compact]
	[CCode (cname="struct r_reg_set_t", destroy_function="", free_function="" )]
	public class Set {
		public RRegister.Arena arena;
		public RList<Arena*> arenas;
		public RList<Item*> regs;
	}

	public RRegister();
	public bool set_profile(string file);
	public bool set_profile_string(string profile);
	public Item get(string name, int type = -1);
	/* TODO: use r_flist or r_list here */
	//public KernelList<RRegister.Item*> get_list(RRegister.Type type);

	public static string? get_type(int idx);

	public uint64 get_value(Item item);
	public bool set_value(Item item, uint64 val);

	public float get_fvalue(Item item);
	public bool set_fvalue(Item item, float val);

	public uint64 get_pvalue(Item item, int pidx);
	public bool set_pvalue(Item item, uint64 val, int pidx);

	public uint8* get_bytes(Type type, out int size = null);
	public int set_bytes(Type type, uint8* buf, int len);

	public void fit_arena();
}

/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

[CCode (cheader_filename="r_reg.h", cprefix="r_reg_", lower_case_cprefix="r_reg_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_reg_t", free_function="r_reg_free", cprefix="r_reg_")]
	public class Register {
		[CCode (cprefix="R_REG_TYPE_")]
		public enum Type {
			GPR,
			DRX,
			FPU,
			MMX,
			XMM,
			FLG,
			SEG,
			LAST
			ALL,
		}

		[Compact]
		[CCode (cname="struct r_reg_item_t", destroy_function="", free_function="" )]
		public class Item {
			public string name;
			public int size;
			public int offset;
			public int packed_size;
			public Register.Type type;
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
			public Register.Arena arena;
			public Radare.List<Register.Arena*> arenas;
			public Radare.List<Register.Item*> regs;
		}

		public Register();
		public bool set_profile(string file);
		public bool set_profile_string(string profile);
		public Register.Item get(string name);
		public Radare.List<Register.Item*> get_list(Register.Type type);

		public uint64 get_value(Register.Item item);
		public bool set_value(Register.Item item, uint64 val);

		public float get_fvalue(Register.Item item);
		public bool set_fvalue(Register.Item item, float val);

		public uint64 get_pvalue(Register.Item item, int pidx);
		public bool set_pvalue(Register.Item item, uint64 val, int pidx);

		public uint8* get_bytes(Register.Type type, out int size = null);
		public int set_bytes(Register.Type type, uint8* buf, int len);

		public void fit_arena();
	}
}

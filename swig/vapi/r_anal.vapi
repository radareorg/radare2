/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

[Compact]
[CCode (cheader_filename="r_anal.h", cprefix="r_anal_", lowercase_c_prefix="r_anal_", free_function="r_anal_free")]
public class Radare.RAnal {
	public int bits;
	public bool big_endian;
	public void *user;
	RList <BasicBlock> bbs;
	RList <Function> fcns;
	RList <VariableType> vartypes;

	public RAnal ();
	//public weak RAnal init ();
	public bool set_bits (int bits);
	public bool set_big_endian (bool big);
	//public bool set_pc (uint64 addr);

	[Compact]
	[CCode (cname="RAnalBB")]
	public class BasicBlock {
		public uint64 addr;
		public uint64 size;
		public uint64 jump;
		public uint64 fail;
		public RList<Opcode> aops;
	}
	public bool bb_split(BasicBlock bb, RList<BasicBlock> bbs, uint64 addr);
	public bool bb_overlap(BasicBlock bb, RList<BasicBlock> bbs);

	[Compact]
	[CCode (cprefix="r_anal_aop_t")]
	public class Opcode {
		public uint64 addr;
		public int type;
		public int stackop;
		public int cond;
		public int length;
		public int family;
		public bool eob;
		public uint64 jump;
		public uint64 fail;
		//public uint64 value;
		//TODO public uint64 ref;
	}

	[Compact]
	[CCode (cprefix="r_anal_fcn_t")]
	public class Function {
		public string name;
		public uint64 addr;
		public uint64 size;
		public RList<Variable> vars;
		public RList<uint64> refs;
		public RList<uint64> xrefs;
	}

	[Compact]
	[CCode (cprefix="r_anal_var_t")]
	public class Variable {
		public string name;
		public int delta;
		public int type;
		public RList<VariableAccess> accesses;
	}

	[Compact]
	[CCode (cprefix="r_anal_var_access_t")]
	public class VariableAccess {
		public string name;
		public int delta;
		public int type;
		public RList<VariableAccess> accessess;
	}

	[Compact]
	[CCode (cprefix="r_anal_var_type_t")]
	public class VariableType {
		public string name;
		public string fmt;
		public uint size;
	}

	[Compact]
	public class Refline {
		uint64 from;
		uint64 to;
		int index;
	}
}

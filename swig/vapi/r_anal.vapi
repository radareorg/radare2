/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

namespace Radare {
[Compact]
[CCode (cheader_filename="r_anal.h", cprefix="r_anal_", lowercase_c_prefix="r_anal_", free_function="r_anal_free", cname="RAnal")]
public class RAnal {
	public int bits;
	public bool big_endian;
	public void *user;
	public RList <BasicBlock> bbs;
	public RList <Function> fcns;
	public RList <VariableType> vartypes;

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
	[CCode (cprefix="r_anal_aop_t", cname="RAnalAop")]
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
	[CCode (lower_case_cprefix="r_anal_fcn_", cprefix="r_anal_fcn_t", cname="RAnalFcn")]
	public class Function {
		public string name;
		public uint64 addr;
		public uint64 size;
		public RList<Variable> vars;
		public RList<uint64> refs;
		public RList<uint64> xrefs;
		public RList<BasicBlock> bb_list ();
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
	[CCode (free_function="")]
	public class Refline {
		uint64 from;
		uint64 to;
		int index;
	}
}
}

/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

/* this vapi is broken as shit... we need to rename some stuff here ..
   if we can just avoid to use cname CCode attribute... */

namespace Radare {
[Compact]
[CCode (cheader_filename="r_anal.h", cprefix="r_anal_", lowercase_c_prefix="r_anal_", free_function="r_anal_free", cname="RAnal")]
public class RAnal {
	public int bits;
	public bool big_endian;
	public void *user;
	public RList <Block> bbs;
	public RList <Fcn> fcns;
	public RList <VarType> vartypes;

	public RAnal ();
	public bool set_bits (int bits);
	public bool set_big_endian (bool big);
	//public bool set_pc (uint64 addr);
	public RList<Block> fcn_bb_list(Fcn fun);

	[Compact]
	[CCode (cname="RAnalBlock")]
	public class Block {
		public uint64 addr;
		public uint64 size;
		public uint64 jump;
		public uint64 fail;
		public RList<Op> aops;
	}
	public bool bb_split(Block bb, RList<Block> bbs, uint64 addr);
	public bool bb_overlap(Block bb, RList<Block> bbs);

	[Compact]
	[CCode (cname="RAnalOp")]
	public class Op {
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
	[CCode (cprefix="r_anal_fcn_", cname="RAnalFcn")]
	public class Fcn {
		public string name;
		public uint64 addr;
		public uint64 size;
		public RList<Var> vars;
		public RList<uint64> refs;
		public RList<uint64> xrefs;
	}

	[Compact]
	[CCode (cname="RAnalVar")]
	public class Var {
		public string name;
		public int delta;
		public int type;
		public RList<VarAccess> accesses;
	}

	[Compact]
	[CCode (cname="RAnalVarAccess")]
	public class VarAccess {
		public string name;
		public int delta;
		public int type;
		public RList<VarAccess> accessess;
	}

	[Compact]
	[CCode (cname="RAnalVarType")]
	public class VarType {
		public string name;
		public string fmt;
		public uint size;
	}

	[Compact]
	[CCode (cname="RAnalRefline", free_function="")]
	public class Refline {
		uint64 from;
		uint64 to;
		int index;
	}
}
}

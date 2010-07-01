/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

/* this vapi is broken as shit... we need to rename some stuff here ..
   if we can just avoid to use cname CCode attribute... */

namespace Radare {
[Compact]
[CCode (cheader_filename="r_anal.h,r_list.h,r_types_base.h", cprefix="r_anal_", lowercase_c_prefix="r_anal_", free_function="r_anal_free", cname="RAnal")]
public class RAnal {
	public int bits;
	public bool big_endian;
	public void *user;
	public RList<RAnal.Block> bbs;
	public RList<RAnal.Fcn> fcns;
	public RList<RAnal.VarType> vartypes;

	public RAnal ();
	public bool set_bits (int bits);
	public bool set_big_endian (bool big);
	//public bool set_pc (uint64 addr);
	public RList<RAnal.Block> fcn_bb_list(Fcn fun);

/*
	[CCode (cprefix="R_ANAL_OP_COND_")]
	public enum OpCond {
		EQ,
		NE,
		GE,
		GT,
		LE,
		LT
	}
*/

	[CCode (cprefix="R_ANAL_VAR_TYPE_")]
	public enum VarType {
		NULL,
		GLOBAL,
		LOCAL,
		ARG,
		ARGREG
	}

	[CCode (cprefix="R_ANAL_BB_TYPE_")]
	public enum BlockType {
		NULL,
		HEAD,
		BODY,
		LAST,
		FOOT
	}

	[CCode (cprefix="R_ANAL_DIFF_")]
	public enum BlockDiff {
		NULL,
		MATCH,
		UNMATCH
	}

/* XXX JAM!
	[CCode (cprefix="R_ANAL_REFLINE_")]
	public enum Refline {
		STYLE,
		WIDE
	}
*/

	[CCode (cprefix="R_ANAL_RET_")]
	public enum Ret {
		ERROR,
		DUP,
		NEW,
		END
	}

	[CCode (cprefix="R_ANAL_STACK_")]
	public enum Stack {
		NULL,
		INCSTACK,
		GET,
		SET
	}

	[CCode (cprefix="R_ANAL_DATA")]
	public enum Data {
		NULL,
		HEX,
		STR,
		CODE,
		FUN,
		STRUCT,
		LAST
	}

	[CCode (cprefix="R_ANAL_OP_FAMILY_")]
	public enum OpFamily {
		UNKNOWN,
		CPU,
		FPU,
		MMX,
		PRIV,
		LAST
	}

	[CCode (cprefix="R_ANAL_OP_TYPE_")]
	public enum OpType {
		NULL,
		JMP,
		UJMP,
		CJMP,
		CALL,
		RCALL,
		REP,
		RET,
		ILL,
		UNK,
		NOP,
		MOV,
		TRAP, 
		SWI,  
		UPUSH,
		PUSH, 
		POP,  
		CMP,  
		ADD,
		SUB,
		MUL,
		DIV,
		SHR,
		SHL,
		OR,
		AND,
		XOR,
		NOT,
		STORE,
		LOAD, 
		//LAST
	}

	[Compact]
	[CCode (cprefix="r_anal_bb_", cname="RAnalBlock")]
	public class Block {
		public uint64 addr;
		public uint64 size;
		public uint64 jump;
		public uint64 fail;
		public BlockType type;
		public BlockDiff diff;
		public RList<RAnal.Op> aops;
	}
	public bool bb_split(Block bb, RList<RAnal.Block> bbs, uint64 addr);
	public bool bb_overlap(Block bb, RList<RAnal.Block> bbs);

	[Compact]
	[CCode (cprefix="r_anal_aop_", cname="RAnalOp")]
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
		public RList<RAnal.Var> vars;
		public RList<uint64> refs;
		public RList<uint64> xrefs;
	}

	[Compact]
	[CCode (cname="RAnalVar")]
	public class Var {
		public string name;
		public int delta;
		public int type;
		public RList<RAnal.VarAccess> accesses;
	}

	[Compact]
	[CCode (cname="RAnalVarAccess")]
	public class VarAccess {
		public string name;
		public int delta;
		public int type;
		public RList<RAnal.VarAccess> accessess;
	}

/*
	[Compact]
	[CCode (cname="RAnalVarType")]
	public class VarType {
		public string name;
		public string fmt;
		public uint size;
	}
*/

	[Compact]
	[CCode (cname="RAnalRefline", free_function="")]
	public class Refline {
		uint64 from;
		uint64 to;
		int index;
	}
}
}

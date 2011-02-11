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
	public RList<RAnal.Fcn> fcns;
	public RList<RAnal.VarType> vartypes;

	public RAnal ();
	public bool set_bits (int bits);
	public bool set_big_endian (bool big);
	//public bool set_pc (uint64 addr);
	public RList<RAnal.Fcn> get_fcns();

	[Compact]
	[CCode (cname="RAnalValue")]
	public class Value {
		public bool absolute;
		public bool memref;
		public uint64 @base;
		public int64 delta;
		public int64 imm;
		public int mul;
		//public uint16 sel;
		public RReg.Item reg;
		public RReg.Item regdelta;
	}

	[Compact]
	[CCode (cname="RAnalCond")]
	public class Cond {
		public int type;
		public RAnal.Value arg[2];
	}

	[CCode (cname="int", cprefix="R_ANAL_COND_")]
	public enum Cnd {
		EQ,
		NE,
		GE,
		GT,
		LE,
		LT
	}

	[CCode (cname="int", cprefix="R_ANAL_VAR_TYPE_")]
	public enum VarClass {
		NULL,
		GLOBAL,
		LOCAL,
		ARG,
		ARGREG
	}

	[CCode (cname="int", cprefix="R_ANAL_FCN_TYPE_")]
	public enum FcnType {
		NULL,
		FCN,
		LOC,
		SYM,
		IMP
	}

	[CCode (cname="int", cprefix="R_ANAL_BB_TYPE_")]
	public enum BlockType {
		NULL,
		HEAD,
		BODY,
		LAST,
		FOOT
	}

	[CCode (cname="int", cprefix="R_ANAL_DIFF_TYPE_")]
	public enum BlockDiff {
		NULL,
		MATCH,
		UNMATCH
	}

	[CCode (cname="int", cprefix="R_ANAL_REFLINE_TYPE_")]
	public enum ReflineType {
		STYLE,
		WIDE
	}

	[CCode (cname="int", cprefix="R_ANAL_RET_")]
	public enum Ret {
		ERROR,
		DUP,
		NEW,
		END
	}

	[CCode (cname="int", cprefix="R_ANAL_STACK_")]
	public enum Stack {
		NULL,
		NOP,
		INCSTACK,
		GET,
		SET
	}

	[CCode (cname="int", cprefix="R_ANAL_DATA_")]
	public enum Data {
		NULL,
		HEX,
		STR,
		CODE,
		FUN,
		STRUCT,
		LAST
	}

	[CCode (cname="int", cprefix="R_ANAL_OP_FAMILY_")]
	public enum OpFamily {
		UNKNOWN,
		CPU,
		FPU,
		MMX,
		PRIV,
		LAST
	}

	[CCode (cname="int", cprefix="R_ANAL_VAR_DIR_")]
	public enum VarDir {
		NONE,
		IN,
		OUT
	}

	[CCode (cname="int", cprefix="R_ANAL_OP_TYPE_")]
	public enum OpType {
		NULL,
		JMP,
		UJMP,
		CJMP,
		CALL,
		UCALL,
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
	[CCode (cprefix="r_anal_diff_", cname="RAnalDiff")]
	public class Diff {
		public BlockDiff type;
		public string name;
		public uint64 addr;
	}

	[CCode (cname="RAnalFcn", free_function="", ref_function="", unref_function="")]
	public class Fcn {
		public string name;
		public uint64 addr;
		public uint64 size;
		public Diff diff;
		public FcnType type;
		public RList<RAnal.Block> bbs;
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
		public uint64 from;
		public uint64 to;
		public int index;
	}
}


/* meta */
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
		
		public RList<RMeta.Item> data;

		[CCode (cname="int", cprefix="R_META_WHERE_")]
		public enum Where {
			PREV,
			HERE,
			NEXT
		}

		[CCode (cname="int", cprefix="R_META_")]
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
		//public string get_string(RMeta.Type, uint64 addr);
		public bool @add(RMeta.Type type, uint64 from, uint64 size, string str);
		public bool del(RMeta.Type type, uint64 from, uint64 size, string str);
		public RMeta.Item find(uint64 off, RMeta.Type type, RMeta.Where where);
		public bool cleanup (uint64 from, uint64 to);
		public static unowned string type_to_string(RMeta.Type type);
		public int list (RMeta.Type type);
	}
}

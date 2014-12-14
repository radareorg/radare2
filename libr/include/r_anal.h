/* radare - LGPL - Copyright 2009-2014 - nibble, pancake, xvilka */

#ifndef R2_ANAL_H
#define R2_ANAL_H

#define NEW_ESIL 1
/* use sdb function storage */
#define FCN_SDB 1
/* use old refs and function storage */
// still required by core in lot of places
#define FCN_OLD 1
#define USE_VARSUBS 0

#include <r_types.h>
#include <r_db.h>
#include <r_io.h>
#include <r_reg.h>
#include <r_list.h>
#include <r_util.h>
#include <r_syscall.h>
#include <r_flags.h>
#include <r_bin.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_anal);

// TODO: save memory2 : fingerprints must be pointers to a buffer
// containing a dupped file in memory

/* save memory:
   bb_has_ops=1 -> 600M
   bb_has_ops=0 -> 350MB
*/
#define R_ANAL_BB_HAS_OPS 0

/* TODO: work in progress */
#define USE_NEW_FCN_STORE 0

// TODO: Remove this define? /cc @nibble_ds
#define VERBOSE_ANAL if(0)

/* meta */
typedef struct r_anal_meta_item_t {
	ut64 from;
	ut64 to;
	ut64 size;
	int type;
	char *str;
} RAnalMetaItem;

typedef struct r_anal_range_t {
	ut64 from;
	ut64 to;
} RAnalRange;
/* CPARSE stuff */

#define R_ANAL_UNMASK_TYPE(x) (x&R_ANAL_VAR_TYPE_SIZE_MASK)
#define R_ANAL_UNMASK_SIGN(x) (((x& R_ANAL_VAR_TYPE_SIGN_MASK)>> R_ANAL_VAR_TYPE_SIGN_SHIFT)==R_ANAL_VAR_TYPE_UNSIGNED)?0:1

enum {
	R_ANAL_DATA_TYPE_NULL = 0,
	R_ANAL_DATA_TYPE_UNKNOWN = 1,
	R_ANAL_DATA_TYPE_STRING = 2,
	R_ANAL_DATA_TYPE_WIDE_STRING = 3,
	R_ANAL_DATA_TYPE_POINTER = 4,
	R_ANAL_DATA_TYPE_NUMBER = 5,
	R_ANAL_DATA_TYPE_INVALID = 6,
	R_ANAL_DATA_TYPE_HEADER = 7,
	R_ANAL_DATA_TYPE_SEQUENCE = 8,
	R_ANAL_DATA_TYPE_PATTERN = 9,
};

// used from core/anal.c
#define R_ANAL_ADDR_TYPE_EXEC      1
#define R_ANAL_ADDR_TYPE_READ      1<<1
#define R_ANAL_ADDR_TYPE_WRITE     1<<2
#define R_ANAL_ADDR_TYPE_FLAG      1<<3
#define R_ANAL_ADDR_TYPE_FUNC      1<<4
#define R_ANAL_ADDR_TYPE_HEAP      1<<5
#define R_ANAL_ADDR_TYPE_STACK     1<<6
#define R_ANAL_ADDR_TYPE_REG       1<<7
#define R_ANAL_ADDR_TYPE_PROGRAM   1<<8
#define R_ANAL_ADDR_TYPE_LIBRARY   1<<9
#define R_ANAL_ADDR_TYPE_ASCII     1<<10
#define R_ANAL_ADDR_TYPE_SEQUENCE  1<<11

/* type = (R_ANAL_VAR_TYPE_BYTE & R_ANAL_VAR_TYPE_SIZE_MASK) |
 *			( RANAL_VAR_TYPE_SIGNED & RANAL_VAR_TYPE_SIGN_MASK) |
 *			( RANAL_VAR_TYPE_CONST & RANAL_VAR_TYPE_MODIFIER_MASK)
 */
typedef struct r_anal_type_var_t {
	char *name;
	int index;
	int scope;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	union {
		ut8	 v8;
		ut16 v16;
		ut32 v32;
		ut64 v64;
	} value;
} RAnalTypeVar;

typedef struct r_anal_type_ptr_t {
	char *name;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	union {
		ut8 v8;
		ut16 v16;
		ut32 v32;
		ut64 v64;
	} value;
} RAnalTypePtr;

typedef struct r_anal_type_array_t {
	char *name;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	ut64 count;
	union {
		ut8 *v8;
		ut16 *v16;
		ut32 *v32;
		ut64 *v64;
	} value;
} RAnalTypeArray;

typedef struct r_anal_type_struct_t RAnalTypeStruct;
typedef struct r_anal_type_t RAnalType;

struct r_anal_type_struct_t {
	char *name;
	ut8 type;
	ut32 size;
	void *parent;
	RAnalType *items;
};

typedef struct r_anal_type_union_t {
	char *name;
	ut8 type;
	ut32 size;
	void *parent;
	RAnalType *items;
} RAnalTypeUnion;

typedef struct r_anal_type_alloca_t {
	long address;
	long size;
	void *parent;
	RAnalType *items;
} RAnalTypeAlloca;

enum {
	R_ANAL_FQUALIFIER_NONE = 0,
	R_ANAL_FQUALIFIER_STATIC = 1,
	R_ANAL_FQUALIFIER_VOLATILE = 2,
	R_ANAL_FQUALIFIER_INLINE = 3,
	R_ANAL_FQUALIFIER_NAKED	= 4,
	R_ANAL_FQUALIFIER_VIRTUAL = 5,
};

enum {
	R_ANAL_CC_TYPE_NONE,
	R_ANAL_CC_TYPE_CDECL,
	R_ANAL_CC_TYPE_STDCALL,
	R_ANAL_CC_TYPE_FASTCALL,
	R_ANAL_CC_TYPE_PASCAL,
	R_ANAL_CC_TYPE_WINAPI, // Microsoft's pascal call clone
	R_ANAL_CC_TYPE_MSFASTCALL, // microsoft fastcall
	R_ANAL_CC_TYPE_BOFASTCALL, // borland fastcall
	R_ANAL_CC_TYPE_WAFASTCALL, // wacom fastcall
	R_ANAL_CC_TYPE_CLARION, // TopSpeed/Clarion/JPI
	/* Clation:
	 *	first four integer parameters are passed in registers:
	 *	eax, ebx, ecx, edx. Floating point parameters are passed
	 *	on the floating point stack - registers
	 *	st0, st1, st2, st3, st4, st5, st6. Structure parameters
	 *	are always passed on the stack. Additional parameters
	 *	are passed on the stack after registers are exhausted.
	 *	Integer values are returned in eax, pointers in edx
	 *	and floating point types in st0.
	 */
	R_ANAL_CC_TYPE_SAFECALL, // Delphi and Free Pascal on Windows
	R_ANAL_CC_TYPE_SYSV,
	R_ANAL_CC_TYPE_THISCALL,
};

#define R_ANAL_CC_ARGS 16

typedef struct r_anal_cc_t {
	int type;
	int bits; // 8, 16, 32, ...
	int rel; // relative or absolute?
	ut64 off; // offset of the call instruction (caller)
	ut64 jump; // offset of the call instruction (caller)
	int nargs;
	ut64 args[R_ANAL_CC_ARGS];
	// TODO: Store arguments someway
} RAnalCC;

typedef struct r_anal_cc_type_t {
	int rtl; // right-to-left? if false use left-to-right
	int alignstack;
	//
	//const char **reglist; //
} RAnalCCType;

enum {
	R_ANAL_FCN_TYPE_NULL = 0,
	R_ANAL_FCN_TYPE_FCN = 1,
	R_ANAL_FCN_TYPE_LOC = 2,
	R_ANAL_FCN_TYPE_SYM = 4,
	R_ANAL_FCN_TYPE_IMP = 8,
	R_ANAL_FCN_TYPE_ROOT = 16  /* matching flag */
};

#define R_ANAL_VARSUBS 32

typedef struct r_anal_varsub_t {
	char pat[128];
	char sub[128];
} RAnalVarSub;

enum {
	R_ANAL_DIFF_TYPE_NULL = 0,
	R_ANAL_DIFF_TYPE_MATCH = 'm',
	R_ANAL_DIFF_TYPE_UNMATCH = 'u'
};

typedef struct r_anal_diff_t {
	int type;
	ut64 addr;
	double dist;
	char *name;
} RAnalDiff;

typedef struct r_anal_locals_t {
	RAnalType *items;
} RAnalLocals;

typedef struct r_anal_fcn_local_t {
	ut64 index;
	char* name;
	char* type;
} RAnalFcnLocal;

typedef struct r_anal_attr_t RAnalAttr;
struct r_anal_attr_t {
	char *key;
	long value;
	RAnalAttr *next;
};

typedef struct r_anal_fcn_store_t {
	RHashTable64 *h;
	RList *l;
} RAnalFcnStore;

/* Store various function information,
 * variables, arguments, refs and even
 * description */
typedef struct r_anal_type_function_t {
	char* name;
	char* dsc; // For producing nice listings
	ut32 size;
	int bits; // ((> bits 0) (set-bits bits))
	short type;
	/*item_list *rets; // Type of return value */
	short rets;
	short fmod; //  static, inline or volatile?
	/* TODO: Change to RAnalCC ??? */
	short call; // calling convention
	char* attr; // __attribute__(()) list
	ut64 addr;
	int stack;
	int ninstr;
	int nargs; // Function arguments counter
	int depth;
	RAnalType *args; // list of arguments
#if USE_VARSUBS
	RAnalVarSub varsubs[R_ANAL_VARSUBS];
#endif
	ut8 *fingerprint; // TODO: make is fuzzy and smarter
	RAnalDiff *diff;
	RList *locs; // list of local variables
	//RList *locals; // list of local labels -> moved to anal->sdb_fcns
	RList *bbs;
	RList *vars;
#if FCN_OLD
	RList *refs;
	RList *xrefs;
#endif
} RAnalFunction;

struct r_anal_type_t {
	char *name;
	ut32 size;
	ut32 type;
	union {
		RAnalTypeVar *v;
		RAnalTypePtr *p;
		RAnalTypeArray *a;
		RAnalTypeStruct *s;
		RAnalTypeUnion *u;
		RAnalTypeAlloca *al;
		RAnalFunction *f;
	} custom;
	RAnalType *next;
	RAnalType *prev;
	RAnalType *head;
	// Parent filename
	char* filename;
};

enum {
	R_META_WHERE_PREV = -1,
	R_META_WHERE_HERE = 0,
	R_META_WHERE_NEXT = 1,
};

enum {
	R_META_TYPE_ANY = -1,
	R_META_TYPE_DATA = 'd',
	R_META_TYPE_CODE = 'c',
	R_META_TYPE_STRING = 's',
	R_META_TYPE_FORMAT = 'f',
	R_META_TYPE_MAGIC = 'm',
	R_META_TYPE_HIDE = 'h',
	R_META_TYPE_COMMENT = 'C',
};

// anal
enum {
	R_ANAL_OP_FAMILY_UNKNOWN = 0,
	R_ANAL_OP_FAMILY_CPU,  /* normal cpu instruction */
	R_ANAL_OP_FAMILY_FPU,  /* fpu (floating point) */
	R_ANAL_OP_FAMILY_MMX,  /* multimedia instruction (packed data) */
	R_ANAL_OP_FAMILY_PRIV, /* priviledged instruction */
	R_ANAL_OP_FAMILY_LAST
};

#if 0
On x86 acording to Wikipedia

     Prefix group 1
        0xF0: LOCK prefix
        0xF2: REPNE/REPNZ prefix
        0xF3: REP or REPE/REPZ prefix
    Prefix group 2
        0x2E: CS segment override
        0x36: SS segment override
        0x3E: DS segment override
        0x26: ES segment override
        0x64: FS segment override
        0x65: GS segment override
        0x2E: Branch not taken    (hinting)
        0x3E: Branch taken
    Prefix group 3
        0x66: Operand-size override prefix
    Prefix group 4
        0x67: Address-size override prefix
#endif

typedef enum {
	R_ANAL_OP_PREFIX_COND     = 1,
	R_ANAL_OP_PREFIX_REP      = 1<<1,
	R_ANAL_OP_PREFIX_REPNE    = 1<<2,
	R_ANAL_OP_PREFIX_LOCK     = 1<<3,
	R_ANAL_OP_PREFIX_LIKELY   = 1<<4,
	R_ANAL_OP_PREFIX_UNLIKELY = 1<<5
	/* TODO: add segment override typemods? */
} RAnalOpPrefix;

// XXX: this definition is plain wrong. use enum or empower bits
typedef enum {
	R_ANAL_OP_TYPE_COND  = 0x80000000, // TODO must be moved to prefix?
	//TODO: MOVE TO PREFIX .. it is used by anal_ex.. must be updated
	R_ANAL_OP_TYPE_REP   = 0x40000000, /* repeats next instruction N times */
	R_ANAL_OP_TYPE_NULL  = 0,
	R_ANAL_OP_TYPE_JMP   = 1,  /* mandatory jump */
	R_ANAL_OP_TYPE_UJMP  = 2,  /* unknown jump (register or so) */
	R_ANAL_OP_TYPE_CJMP  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_JMP,  /* conditional jump */
	R_ANAL_OP_TYPE_UCJMP = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UJMP, /* conditional unknown jump */
	R_ANAL_OP_TYPE_CALL  = 3,  /* call to subroutine (branch+link) */
	R_ANAL_OP_TYPE_UCALL = 4, /* unknown call (register or so) */
	R_ANAL_OP_TYPE_CCALL = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL, /* conditional call to subroutine */
	R_ANAL_OP_TYPE_UCCALL= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UCALL, /* conditional unknown call */
	R_ANAL_OP_TYPE_RET   = 5, /* returns from subroutine */
	R_ANAL_OP_TYPE_CRET  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET, /* conditional return from subroutine */
	R_ANAL_OP_TYPE_ILL   = 6,  /* illegal instruction // trap */
	R_ANAL_OP_TYPE_UNK   = 7, /* unknown opcode type */
	R_ANAL_OP_TYPE_NOP   = 8, /* does nothing */
	R_ANAL_OP_TYPE_MOV   = 9, /* register move */
	R_ANAL_OP_TYPE_TRAP  = 10, /* it's a trap! */
	R_ANAL_OP_TYPE_SWI   = 11,  /* syscall, software interrupt */
	R_ANAL_OP_TYPE_UPUSH = 12, /* unknown push of data into stack */
	R_ANAL_OP_TYPE_PUSH  = 13,  /* push value into stack */
	R_ANAL_OP_TYPE_POP   = 14,   /* pop value from stack to register */
	R_ANAL_OP_TYPE_CMP   = 15,  /* compare something */
	R_ANAL_OP_TYPE_ACMP  = 16,  /* compare via and */
	R_ANAL_OP_TYPE_ADD   = 17,
	R_ANAL_OP_TYPE_SUB   = 18,
	R_ANAL_OP_TYPE_IO    = 19,
	R_ANAL_OP_TYPE_MUL   = 20,
	R_ANAL_OP_TYPE_DIV   = 21,
	R_ANAL_OP_TYPE_SHR   = 22,
	R_ANAL_OP_TYPE_SHL   = 23,
	R_ANAL_OP_TYPE_SAL   = 24,
	R_ANAL_OP_TYPE_SAR   = 25,
	R_ANAL_OP_TYPE_OR    = 26,
	R_ANAL_OP_TYPE_AND   = 27,
	R_ANAL_OP_TYPE_XOR   = 28,
	R_ANAL_OP_TYPE_NOT   = 29,
	R_ANAL_OP_TYPE_STORE = 30,  /* store from register to memory */
	R_ANAL_OP_TYPE_LOAD  = 31,  /* load from memory to register */
	R_ANAL_OP_TYPE_LEA   = 32,
	R_ANAL_OP_TYPE_LEAVE = 33,
	R_ANAL_OP_TYPE_ROR   = 34,
	R_ANAL_OP_TYPE_ROL   = 35,
	R_ANAL_OP_TYPE_XCHG  = 36,
	R_ANAL_OP_TYPE_MOD   = 37,
	R_ANAL_OP_TYPE_SWITCH = 38,
	R_ANAL_OP_TYPE_CASE = 39,
} _RAnalOpType;

/* TODO: what to do with signed/unsigned conditionals? */
typedef enum {
	R_ANAL_COND_EQ = 0,
	R_ANAL_COND_NE,
	R_ANAL_COND_GE,
	R_ANAL_COND_GT,
	R_ANAL_COND_LE,
	R_ANAL_COND_LT,
	R_ANAL_COND_AL,
	R_ANAL_COND_NV,
} _RAnalCond;

typedef enum {
	R_ANAL_VAR_SCOPE_NULL   = 0,
	R_ANAL_VAR_SCOPE_GLOBAL = 0x00,
	R_ANAL_VAR_SCOPE_LOCAL  = 0x01,
	R_ANAL_VAR_SCOPE_ARG    = 0x04,
	R_ANAL_VAR_SCOPE_ARGREG = 0x08,
	R_ANAL_VAR_SCOPE_RET    = 0x10,
} _RAnalVarScope;

typedef enum {
	R_ANAL_VAR_DIR_NONE = 0,
	R_ANAL_VAR_DIR_IN   = 0x100,
	R_ANAL_VAR_DIR_OUT  = 0x200
} _RAnalVarDir;

typedef enum {
	R_ANAL_DATA_NULL = 0,
	R_ANAL_DATA_HEX,      /* hex byte pairs */
	R_ANAL_DATA_STR,      /* ascii string */
	R_ANAL_DATA_CODE,     /* plain assembly code */
	R_ANAL_DATA_FUN,      /* plain assembly code */
	R_ANAL_DATA_STRUCT,   /* memory */
	R_ANAL_DATA_LAST
} _RAnalData;

typedef enum {
	R_ANAL_BB_TYPE_NULL = 0,
	R_ANAL_BB_TYPE_HEAD = 0x1,     /* first block */
	R_ANAL_BB_TYPE_BODY = 0x2,     /* conditional jump */
	R_ANAL_BB_TYPE_LAST = 0x4,     /* ret */
	R_ANAL_BB_TYPE_FOOT = 0x8,     /* unknown jump */
	R_ANAL_BB_TYPE_SWITCH = 0x10,   /* TODO: switch */

	R_ANAL_BB_TYPE_RET  = 0x0020,   /* return bb */
	R_ANAL_BB_TYPE_JMP  = 0x0040,   /* jmp bb */
	R_ANAL_BB_TYPE_COND = 0x0100,   /* conditional bb */
	R_ANAL_BB_TYPE_CJMP = R_ANAL_BB_TYPE_COND | R_ANAL_BB_TYPE_JMP,
	R_ANAL_BB_TYPE_CALL = 0x0200,
	R_ANAL_BB_TYPE_CMP  = 0x0400,
	R_ANAL_BB_TYPE_LD   = 0x0800,
	R_ANAL_BB_TYPE_ST   = 0x1000,
	R_ANAL_BB_TYPE_BINOP= 0x2000,
	R_ANAL_BB_TYPE_TAIL = 0x8000,
} _RAnalBlockType;

enum {
	R_ANAL_STACK_NULL = 0,
	R_ANAL_STACK_NOP,
	R_ANAL_STACK_INC,
	R_ANAL_STACK_GET,
	R_ANAL_STACK_SET,
};

enum {
	R_ANAL_REFLINE_TYPE_STYLE = 1,
	R_ANAL_REFLINE_TYPE_WIDE = 2,
};

enum {
	R_ANAL_RET_ERROR = -1,
	R_ANAL_RET_DUP = -2,
	R_ANAL_RET_NEW = -3,
	R_ANAL_RET_END = -4
};

typedef struct r_anal_case_obj_t {
	ut64 addr;
	ut64 jump;
	ut64 value;
	ut32 cond; // TODO: treat like a regular condition
	ut64 bb_ref_to;
	ut64 bb_ref_from;
	struct r_anal_bb_t *jumpbb;
} RAnalCaseOp;


typedef struct r_anal_switch_obj_t {
	ut64 addr;
	ut64 min_val;
	ut64 def_val;
	ut64 max_val;
	RList *cases;
} RAnalSwitchOp;

typedef struct r_anal_t {
	char *cpu;
	int bits;
	int lineswidth; // wtf
	int big_endian;
	int split; // used only from core
	int sleep; // sleep some usecs before analyzing more (avoid 100% cpu usages)
	int nopskip; // skip nops at the beginning of functions
	void *user;
	ut64 gp; // global pointer. used for mips. but can be used by other arches too in the future
	RList *fcns;
	RListRange *fcnstore;
	RList *refs;
	RList *vartypes;
	RReg *reg;
	RSyscall *syscall;
	struct r_anal_op_t *queued;
	int diff_ops;
	double diff_thbb;
	double diff_thfcn;
	RIOBind iob;
	RFlagBind flb;
	RBinBind binb; // Set only from core when an analysis plugin is called.
	int decode;
	int eobjmp; // option
	int afterjmp; // continue analysis after jmp eax or forward jmp // option
	int maxreflines;
	RList *types;
	//struct r_anal_ctx_t *ctx;
	struct r_anal_esil_t *esil;
	struct r_anal_plugin_t *cur;
	RAnalRange *limit;
	//struct list_head anals; // TODO: Reimplement with RList
	RList *plugins;
	Sdb *sdb_xrefs;
	Sdb *sdb_types;
	Sdb *sdb_meta; // TODO: Future r_meta api
	PrintfCallback printf;
//moved from RAnalFcn
	Sdb *sdb; // root
	Sdb *sdb_refs;
	Sdb *sdb_fcns;
#define DEPRECATE 1
#if DEPRECATE
	Sdb *sdb_args;  //
	Sdb *sdb_vars; // globals?
	//Sdb *sdb_locals;
	// Sdb *sdb_ret;   // UNUSED
#endif
	Sdb *sdb_hints; // OK
	//RList *hints; // XXX use better data structure here (slist?)
} RAnal;

typedef struct r_anal_hint_t {
	ut64 addr;
	ut64 ptr;
	ut64 jump;
	ut64 fail;
	char *arch;
	char *opcode;
	char *esil;
	int size;
	int bits;
} RAnalHint;

// mul*value+regbase+regidx+delta
typedef struct r_anal_value_t {
	int absolute; // if true, unsigned cast is used
	int memref; // is memory reference? which size? 1, 2 ,4, 8
	ut64 base ; // numeric address
	st64 delta; // numeric delta
	st64 imm; // immediate value
	int mul; // multiplier (reg*4+base)
	ut16 sel; // segment selector
	RRegItem *reg; // register index used (-1 if no reg)
	RRegItem *regdelta; // register index used (-1 if no reg)
} RAnalValue;

typedef struct r_anal_op_t {
	char *mnemonic; /* mnemonic */
	ut64 addr;      /* address */
	ut64 type;      /* type of opcode */
	ut64 prefix;    /* type of opcode prefix (rep,lock,..) */
	ut64 type2; // used by java
	int stackop;    /* operation on stack? */
	int cond;       /* condition type */
	int size;       /* size in bytes of opcode */
	int nopcode;    /* number of bytes representing the opcode (not the arguments) */
	int cycles;	/* cpu-cycles taken by instruction */
	int failcycles;	/* conditional cpu-cycles */
	int family;     /* family of opcode */
	int eob;        /* end of block (boolean) */
	/* Run N instructions before executing the current one */
	int delay;      /* delay N slots (mips, ..)*/
	ut64 jump;      /* true jmp */
	ut64 fail;      /* false jmp */
	ut32 selector;  /* segment selector */
	st64 ptr;       /* reference to memory */ /* XXX signed? */
	ut64 val;       /* reference to value */ /* XXX signed? */
	st64 stackptr;  /* stack pointer */
	int refptr;     /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
	RAnalValue *src[3];
	RAnalValue *dst;
	struct r_anal_op_t *next; // XXX deprecate
	RStrBuf esil;
	RAnalSwitchOp *switch_op;
} RAnalOp;

#define R_ANAL_COND_SINGLE(x) (!x->arg[1] || x->arg[0]==x->arg[1])

typedef struct r_anal_cond_t {
	int type; // filled by CJMP opcode
	RAnalValue *arg[2]; // filled by CMP opcode
} RAnalCond;

typedef struct r_anal_bb_t {
	char *name;
	ut64 addr;
	ut64 jump;
	ut64 type2;
	ut64 fail;
	int size;
	int type;
	int type_ex;
	int ninstr;
	int returnbb;
	int conditional;
	int traced;
	char *label;
	ut8 *fingerprint;
	RAnalDiff *diff;
#if R_ANAL_BB_HAS_OPS
	RList *ops;
#endif
	RAnalCond *cond;
	RAnalSwitchOp *switch_op;
	ut8 *op_bytes;
	ut8 op_sz;
	ut64 eflags;
	struct r_anal_bb_t *head;
	struct r_anal_bb_t *tail;
	struct r_anal_bb_t *next;
	struct r_anal_bb_t *prev;
	struct r_anal_bb_t *failbb;
	struct r_anal_bb_t *jumpbb;
	RList /*struct r_anal_bb_t*/ *cases;
} RAnalBlock;

typedef struct r_anal_var_access_t {
	ut64 addr;
	int set;
} RAnalVarAccess;

// generic for args and locals
typedef struct r_anal_var_t {
	char *name;		/* name of the variable */
	char *type; // cparse type of the variable
	char kind; // 'a'rg, 'v'ar ..
	ut64 addr;		// not used correctly?
	ut64 eaddr;		// not used correctly?
	int size;
	int delta;		/* delta offset inside stack frame */
	int scope;		/* global, local... | in, out... */
	/* probably dupped or so */
	RList/*RAnalVarAccess*/ *accesses; /* list of accesses for this var */
	RList/*RAnalValue*/ *stores;   /* where this */
} RAnalVar;

/*
typedef struct r_anal_var_type_t {
	char *name;
	char *fmt;
	ut32 size;
} RAnalVarType;
*/

typedef enum {
	R_ANAL_REF_TYPE_NULL = 0,
	R_ANAL_REF_TYPE_CODE = 'c', // code ref
	R_ANAL_REF_TYPE_CALL = 'C', // code ref (call)
	R_ANAL_REF_TYPE_DATA = 'd', // mem ref
	R_ANAL_REF_TYPE_STRING='s'  // string ref
} RAnalRefType;

typedef struct r_anal_ref_t {
	int type;
	ut64 addr;
	ut64 at;
} RAnalRef;

typedef struct r_anal_refline_t {
	ut64 from;
	ut64 to;
	int index;
	struct list_head list;
} RAnalRefline;

typedef struct r_anal_state_type_t {
	ut64 start;
	ut64 end;
	const ut8* buffer;
	ut64 len;

	ut64 bytes_consumed;
	ut64 last_addr;
	ut64 current_addr;
	ut64 next_addr;

	RList *bbs;
	RHashTable64 *ht;
	ut64 ht_sz;

	RAnalFunction *current_fcn;
	RAnalOp *current_op;
	RAnalBlock *current_bb;
	RAnalBlock *current_bb_head;

	ut8 done;
	int anal_ret_val;
	ut32 current_depth;
	ut32 max_depth;

	void *user_state;
} RAnalState;

typedef struct r_anal_cycle_frame_t {
	ut64 naddr;			//next addr
	RList *hooks;
	struct r_anal_cycle_frame_t *prev;
} RAnalCycleFrame;

typedef struct r_anal_cycle_hook_t {	//rename ?
	ut64 addr;
	int cycles;
} RAnalCycleHook;

typedef struct r_anal_esil_word_t {
	int type;
	const char *str;
} RAnalEsilWord;

// only flags that affect control flow
enum {
	R_ANAL_ESIL_FLAG_ZERO = 1,
	R_ANAL_ESIL_FLAG_CARRY = 2,
	R_ANAL_ESIL_FLAG_OVERFLOW = 4,
	R_ANAL_ESIL_FLAG_PARITY = 8,
	R_ANAL_ESIL_FLAG_SIGN = 16,
	// ...
};

enum {
	R_ANAL_TRAP_NONE = 0,
	R_ANAL_TRAP_UNHANDLED = 1,
	R_ANAL_TRAP_BREAKPOINT = 2,
	R_ANAL_TRAP_DIVBYZERO = 3,
	R_ANAL_TRAP_TODO = 4,
	R_ANAL_TRAP_HALT = 5,
};

enum {
	R_ANAL_ESIL_PARM_INVALID = 0,
	R_ANAL_ESIL_PARM_INTERNAL,
	R_ANAL_ESIL_PARM_REG,
	R_ANAL_ESIL_PARM_NUM,
};

#define ESIL_INTERNAL_PREFIX	'%'		//must be a char
#define ESIL struct r_anal_esil_t

typedef struct r_anal_esil_t {
	void *user;
	RAnal *anal;
	char *stack[32];
	int stackptr;
	int skip;
	int nowrite;
	int repeat;
	int parse_stop;
	int parse_goto;
	int parse_goto_limit;
	int parse_goto_count;
	int debug;
	ut64 flags;
	ut64 offset;
	int delay;
	ut64 delay_addr;
	int trap;
	ut32 trap_code; // extend into a struct to store more exception info?
// parity flag?
	ut64 old;	//used for carry-flagging and borrow-flagging
	ut64 cur;	//used for carry-flagging and borrow-flagging
	/* native ops and custom ops */
	Sdb *ops;
	/* deep esil parsing fills this */
	Sdb *stats;
	/* callbacks */
	int (*hook_flag_read)(ESIL *esil, const char *flag, ut64 *num);
	int (*hook_command)(ESIL *esil, const char *op);
	int (*hook_mem_read)(ESIL *esil, ut64 addr, ut8 *buf, int len);
	int (*mem_read)(ESIL *esil, ut64 addr, ut8 *buf, int len);
	int (*hook_mem_write)(ESIL *esil, ut64 addr, const ut8 *buf, int len);
	int (*mem_write)(ESIL *esil, ut64 addr, const ut8 *buf, int len);
	int (*hook_reg_read)(ESIL *esil, const char *name, ut64 *res);
	int (*reg_read)(ESIL *esil, const char *name, ut64 *res);
	int (*hook_reg_write)(ESIL *esil, const char *name, ut64 val);
	int (*reg_write)(ESIL *esil, const char *name, ut64 val);
} RAnalEsil;

#undef ESIL

typedef int (*RAnalEsilOp)(RAnalEsil *esil);

typedef int (*RAnalCmdExt)(/* Rcore */RAnal *anal, const char* input);
typedef int (*RAnalAnalyzeFunctions)(RAnal *a, ut64 at, ut64 from, int reftype, int depth);
typedef int (*RAnalExCallback)(RAnal *a, struct r_anal_state_type_t *state, ut64 addr);
typedef RList *(*RAnalExAnalysisAlgorithm)(RAnal *a, struct r_anal_state_type_t *state, ut64 addr);

typedef RAnalOp * (*RAnalOpFromBuffer)      (RAnal *a, ut64 addr, const ut8* buf, ut64 len);
typedef RAnalBlock * (*RAnalBbFromBuffer)   (RAnal *a, ut64 addr, const ut8* buf, ut64 len);
typedef RAnalFunction * (*RAnalFnFromBuffer)(RAnal *a, ut64 addr, const ut8* buf, ut64 len);

typedef int (*RAnalOpCallback)(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len);
typedef int (*RAnalBbCallback)(RAnal *a, RAnalBlock *bb, ut64 addr, const ut8 *data, int len);
typedef int (*RAnalFnCallback)(RAnal *a, RAnalFunction *fcn, ut64 addr, const ut8 *data, int len, int reftype);

typedef int (*RAnalRegProfCallback)(RAnal *a);
typedef int (*RAnalFPBBCallback)(RAnal *a, RAnalBlock *bb);
typedef int (*RAnalFPFcnCallback)(RAnal *a, RAnalFunction *fcn);
typedef int (*RAnalDiffBBCallback)(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2);
typedef int (*RAnalDiffFcnCallback)(RAnal *anal, RList *fcns, RList *fcns2);
typedef int (*RAnalDiffEvalCallback)(RAnal *anal);

typedef int (*RAnalEsilCB)(RAnalEsil *esil);
typedef int (*RAnalEsilLoopCB)(RAnalEsil *esil, RAnalOp *op);

typedef struct r_anal_plugin_t {
	char *name;
	char *desc;
	char *license;
	int arch;
	int bits;
	int esil; // can do esil or not
	int fileformat_type;
	int custom_fn_anal;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*reset_counter) (RAnal *anal, ut64 start_addr);

	// legacy r_anal_functions
	RAnalOpCallback op;
	RAnalBbCallback bb;
	RAnalFnCallback fcn;

	// overide the default analysis function in r_core_anal_fcn
	RAnalAnalyzeFunctions analyze_fns;

	// parse elements from a buffer
	RAnalOpFromBuffer op_from_buffer;
	RAnalBbFromBuffer bb_from_buffer;
	RAnalFnFromBuffer fn_from_buffer;

	// analysis algorithm to use instead of the default
	// r_anal_ex_recursive_decent when using perform_analysis from
	// RAnalEx stuffs
	RAnalExAnalysisAlgorithm analysis_algorithm;
	// order in which these call backs are
	// used with the recursive descent disassembler
	// analysis
	// 0) Before performing any analysis is start, opportunity to do any pre analysis.
	// in the current function
	RAnalExCallback pre_anal;
	// 1) Before any ops are bbs are created
	RAnalExCallback pre_anal_fn_cb;
	// 2) Just Before an op is created.
	// if current_op is set in state, then an op in the main alg wont be processed
	RAnalExCallback pre_anal_op_cb;
	// 3) After a op is created.
	// the current_op in state is used to fix-up the state of op before creating a bb
	RAnalExCallback post_anal_op_cb;
	// 4) Before a bb is created.
	// if current_op is set in state, then an op in the main alg wont be processed
	RAnalExCallback pre_anal_bb_cb;
	// 5) After a bb is created.
	// the current_bb in state is used to fix-up the state of before performing analysis
	// with the current bb
	RAnalExCallback post_anal_bb_cb;
	// 6) After processing is bb and cb is completed, opportunity to do any post analysis.
	// in the current function
	RAnalExCallback post_anal_fn_cb;

	// 6) After bb in a node is completed, opportunity to do any post analysis.
	// in the current function
	RAnalExCallback post_anal;

	RAnalExCallback revisit_bb_anal;

	// command extension to directly call any analysis functions
	RAnalCmdExt cmd_ext;

	RAnalRegProfCallback set_reg_profile;
	RAnalFPBBCallback fingerprint_bb;
	RAnalFPFcnCallback fingerprint_fcn;
	RAnalDiffBBCallback diff_bb;
	RAnalDiffFcnCallback diff_fcn;
	RAnalDiffEvalCallback diff_eval;
	struct list_head list;

	RAnalEsilCB esil_init;
	RAnalEsilLoopCB esil_post_loop;		//cycle-counting, firing interrupts, ...
	RAnalEsilCB esil_trap;
	RAnalEsilCB esil_fini;
} RAnalPlugin;



#ifdef R_API
/* --------- */ /* REFACTOR */ /* ---------- */
R_API RListRange* r_listrange_new ();
R_API void r_listrange_free(RListRange *s);
R_API void r_listrange_add(RListRange *s, RAnalFunction *f);
R_API void r_listrange_del(RListRange *s, RAnalFunction *f);
R_API void r_listrange_resize(RListRange *s, RAnalFunction *f, int newsize);
R_API RAnalFunction *r_listrange_find_in_range(RListRange* s, ut64 addr);
R_API RAnalFunction *r_listrange_find_root(RListRange* s, ut64 addr);
/* --------- */ /* REFACTOR */ /* ---------- */
/* type.c */
R_API RAnalType *r_anal_type_new();
R_API void r_anal_type_add(RAnal *l, RAnalType *t);
R_API void r_anal_type_del(RAnal *l, const char *name);
R_API RList *r_anal_type_list_new();
R_API RAnalType *r_anal_type_find(RAnal *a, const char* name);
R_API void r_anal_type_list(RAnal *a, short category, short enabled);
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* s);
R_API char *r_anal_type_to_str(RAnal *a, const char *name);
R_API char *r_anal_optype_to_string(int t);
R_API const char *r_anal_op_family_to_string (int n);
R_API RAnalType *r_anal_type_free(RAnalType *t);
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path);
R_API void r_anal_type_define (RAnal *anal, const char *key, const char *value);
R_API void r_anal_type_header (RAnal *anal, const char *hdr);

R_API int r_anal_type_link (RAnal *anal, const char *val, ut64 addr);
R_API char *r_anal_type_format (RAnal *anal, const char *t);
R_API int r_anal_type_set(RAnal *anal, ut64 at, const char *field, ut64 val);

/* anal.c */
R_API RAnal *r_anal_new();
R_API RAnal *r_anal_free(RAnal *r);
R_API void r_anal_set_user_ptr(RAnal *anal, void *user);
R_API void r_anal_plugin_free (RAnalPlugin *p);
R_API int r_anal_add(RAnal *anal, RAnalPlugin *foo);
R_API int r_anal_list(RAnal *anal);
R_API int r_anal_use(RAnal *anal, const char *name);
R_API int r_anal_set_reg_profile(RAnal *anal);
R_API int r_anal_set_bits(RAnal *anal, int bits);
R_API void r_anal_set_cpu(RAnal *anal, const char *cpu);
R_API int r_anal_set_big_endian(RAnal *anal, int boolean);
R_API char *r_anal_strmask (RAnal *anal, const char *data);
R_API void r_anal_trace_bb(RAnal *anal, ut64 addr);
R_API const char *r_anal_fcn_type_tostring(int type);

/* bb.c */
R_API RAnalBlock *r_anal_bb_new();
R_API RList *r_anal_bb_list_new();
R_API void r_anal_bb_free(RAnalBlock *bb);
R_API int r_anal_bb(RAnal *anal, RAnalBlock *bb,
		ut64 addr, ut8 *buf, ut64 len, int head);
R_API RAnalBlock *r_anal_bb_from_offset(RAnal *anal, ut64 off);
R_API int r_anal_bb_is_in_offset (RAnalBlock *bb, ut64 addr);

/* op.c */
R_API const char *r_anal_stackop_tostring (int s);
R_API RAnalOp *r_anal_op_new();
R_API void r_anal_op_free(void *op);
R_API void r_anal_op_fini(RAnalOp *op);
R_API int r_anal_op_is_eob (RAnalOp *op);
R_API RList *r_anal_op_list_new();
R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr,
		const ut8 *data, int len);
R_API RAnalOp *r_anal_op_hexstr(RAnal *anal, ut64 addr,
		const char *hexstr);
R_API char *r_anal_op_to_string(RAnal *anal, RAnalOp *op);


R_API RAnalEsil *r_anal_esil_new();
R_API int r_anal_esil_set_offset(RAnalEsil *esil, ut64 addr);
R_API int r_anal_esil_setup (RAnalEsil *esil, RAnal *anal, int romem, int stats);
R_API void r_anal_esil_free (RAnalEsil *esil);
R_API int r_anal_esil_parse(RAnalEsil *esil, const char *str);
R_API int r_anal_esil_dumpstack (RAnalEsil *esil);
R_API int r_anal_esil_pushnum(RAnalEsil *esil, ut64 num);
R_API int r_anal_esil_push(RAnalEsil *esil, const char *str);
R_API char *r_anal_esil_pop(RAnalEsil *esil);
R_API int r_anal_esil_set_op (RAnalEsil *esil, const char *op, RAnalEsilOp code);
R_API void r_anal_esil_stack_free (RAnalEsil *esil);
R_API int r_anal_esil_get_parm_type (RAnalEsil *esil, const char *str);
R_API int r_anal_esil_get_parm (RAnalEsil *esil, const char *str, ut64 *num);
R_API int r_anal_esil_condition(RAnalEsil *esil, const char *str);

R_API void r_anal_esil_mem_ro(RAnalEsil *esil, int mem_readonly);
R_API void r_anal_esil_stats(RAnalEsil *esil, int enable);
/* fcn.c */
R_API RAnalFunction *r_anal_fcn_new();
R_API int r_anal_fcn_is_in_offset (RAnalFunction *fcn, ut64 addr);
R_API RAnalFunction *r_anal_get_fcn_at(RAnal *anal, ut64 addr, int type);
R_API RAnalFunction *r_anal_get_fcn_in(RAnal *anal, ut64 addr, int type);
R_API RAnalFunction *r_anal_fcn_find_name(RAnal *anal, const char *name);
R_API RList *r_anal_fcn_list_new();
R_API int r_anal_fcn_insert(RAnal *anal, RAnalFunction *fcn);
R_API void r_anal_fcn_free(void *fcn);
R_API int r_anal_fcn(RAnal *anal, RAnalFunction *fcn, ut64 addr,
		ut8 *buf, ut64 len, int reftype);
R_API int r_anal_fcn_add(RAnal *anal, ut64 addr, ut64 size,
		const char *name, int type, RAnalDiff *diff);
R_API int r_anal_fcn_del(RAnal *anal, ut64 addr);
R_API int r_anal_fcn_del_locs(RAnal *anal, ut64 addr);
R_API int r_anal_fcn_add_bb(RAnalFunction *fcn, ut64 addr, ut64 size,
		ut64 jump, ut64 fail, int type, RAnalDiff *diff);

/* locals */
#if 0
R_API int r_anal_fcn_local_add(RAnal *anal, RAnalFunction *fcn, int index, const char *name, const char *type);
R_API int r_anal_fcn_local_del_name(RAnal *anal, RAnalFunction *fcn, const char *name);
R_API int r_anal_fcn_local_del_index(RAnal *anal, RAnalFunction *fcn, ut32 index);
#endif

#define R_ANAL_FCN_VARKIND_LOCAL 'v'
#define R_ANAL_FCN_VARKIND_ARG 'a'
#define R_ANAL_FCN_VARKIND_FASTARG 'A'

#define r_anal_fcn_local_add(x,y,z,n,t) r_anal_fcn_var_add(x, y->addr, z,\
	R_ANAL_FCN_VARKIND_LOCAL, n, t)
#define r_anal_fcn_local_del_index(x,y,z) r_anal_fcn_var_del_byindex(x, y,\
	R_ANAL_FCN_VARKIND_LOCAL, z)
#define r_anal_fcn_local_del_name(x,y,z) error

R_API int r_anal_fcn_arg_add (RAnal *a, ut64 fna, int scope, int delta, const char *type, const char *name);

R_API int r_anal_fcn_var_del_bydelta (RAnal *a, ut64 fna, const char kind, int scope, ut32 delta);
R_API int r_anal_fcn_var_add (RAnal *a, ut64 fna, int scope, int delta, const char *type, const char *name);
R_API int r_anal_fcn_var_del_byindex (RAnal *a, ut64 fna, const char kind,
	int scope, ut32 idx);
/* args */

/* vars // globals. not here  */


R_API int r_anal_fcn_cc(RAnalFunction *fcn);
R_API int r_anal_fcn_split_bb(RAnalFunction *fcn, RAnalBlock *bb, ut64 addr);
R_API int r_anal_fcn_bb_overlaps(RAnalFunction *fcn, RAnalBlock *bb);
R_API RAnalVar *r_anal_fcn_get_var(RAnalFunction *fs, int num, int dir);
R_API void r_anal_fcn_fit_overlaps (RAnal *anal, RAnalFunction *fcn);
R_API RAnalFunction *r_anal_fcn_next(RAnal *anal, ut64 addr);
R_API char *r_anal_fcn_to_string(RAnal *a, RAnalFunction* fs);
R_API int r_anal_str_to_fcn(RAnal *a, RAnalFunction *f, const char *_str);
R_API int r_anal_fcn_count (RAnal *a, ut64 from, ut64 to);
R_API RAnalBlock *r_anal_fcn_bbget(RAnalFunction *fcn, ut64 addr); // default 20
R_API int r_anal_fcn_resize (RAnalFunction *fcn, int newsize);

#if 0
#define r_anal_fcn_get_refs(x) x->refs
#define r_anal_fcn_get_xrefs(x) x->xrefs
#define r_anal_fcn_get_vars(x) x->vars
#define r_anal_fcn_get_bbs(x) x->bbs
#else
R_API const char *r_anal_xrefs_type_tostring (char type);
R_API RList *r_anal_xrefs_get (RAnal *anal, ut64 to);
R_API RList *r_anal_xrefs_get_from (RAnal *anal, ut64 from);
R_API void r_anal_xrefs_list(RAnal *anal, int rad);
R_API RList* r_anal_fcn_get_refs (RAnalFunction *anal);
R_API RList* r_anal_fcn_get_xrefs (RAnalFunction *anal);
R_API int r_anal_xrefs_from (RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr);
R_API int r_anal_xrefs_set (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to);
R_API int r_anal_xrefs_deln (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to);
R_API void r_anal_xrefs_save(RAnal *anal, const char *prjfile);
R_API RList* r_anal_fcn_get_vars (RAnalFunction *anal);
R_API RList* r_anal_fcn_get_bbs (RAnalFunction *anal);
R_API RList* r_anal_get_fcns (RAnal *anal);
#endif

/* ref.c */
R_API RAnalRef *r_anal_ref_new();
R_API RList *r_anal_ref_list_new();
R_API void r_anal_ref_free(void *ref);
R_API int r_anal_ref_add(RAnal *anal, ut64 addr, ut64 at, int type);
R_API int r_anal_ref_del(RAnal *anal, ut64 at, ut64 addr);
R_API RList *r_anal_xref_get(RAnal *anal, ut64 addr);
R_API RList *r_anal_ref_get(RAnal *anal, ut64 addr);

/* var.c */
R_API void r_anal_var_access_clear (RAnal *a, ut64 var_addr, int scope, int index);
R_API int r_anal_var_access (RAnal *a, ut64 var_addr, char kind, int scope, int index, int xs_type, ut64 xs_addr);

R_API RAnalVar *r_anal_var_new();
R_API int r_anal_var_rename (RAnal *a, ut64 var_addr, int scope, char kind, const char *old_name, const char *new_name);
R_API RAnalVarAccess *r_anal_var_access_new();
R_API RList *r_anal_var_list_new();
R_API RList *r_anal_var_access_list_new();
R_API void r_anal_var_free(RAnalVar *var);
R_API void r_anal_var_access_free(void *access);
//R_API int r_anal_var_add(RAnal *anal, RAnalFunction *fcn, ut64 from, int delta, int scope,
//		RAnalType *type, const char *name, int set);
R_API int r_anal_var_delete (RAnal *a, ut64 var_addr, const char kind, int scope, int delta);
R_API int r_anal_var_add (RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, const char *name);
R_API int r_anal_var_del(RAnal *anal, RAnalFunction *fcn, int delta, int scope);
R_API RAnalVar *r_anal_var_get (RAnal *a, ut64 addr, char kind, int scope, int index);
R_API const char *r_anal_var_scope_to_str(RAnal *anal, int scope);
R_API int r_anal_var_access_add(RAnal *anal, RAnalVar *var, ut64 from, int set);
R_API int r_anal_var_access_del(RAnal *anal, RAnalVar *var, ut64 from);
R_API RAnalVarAccess *r_anal_var_access_get(RAnal *anal, RAnalVar *var, ut64 from);

/* project */
R_API int r_anal_project_load(RAnal *anal, const char *prjfile);
R_API int r_anal_project_save(RAnal *anal, const char *prjfile);
R_API int r_anal_xrefs_load(RAnal *anal, const char *prjfile);
R_API int r_anal_xrefs_init (RAnal *anal);

#define R_ANAL_THRESHOLDFCN 0.7F
#define R_ANAL_THRESHOLDBB 0.7F

/* diff.c */
R_API RAnalDiff *r_anal_diff_new();
R_API void r_anal_diff_setup(RAnal *anal, int doops, double thbb, double thfcn);
R_API void r_anal_diff_setup_i(RAnal *anal, int doops, int thbb, int thfcn);
R_API void* r_anal_diff_free(RAnalDiff *diff);
R_API int r_anal_diff_fingerprint_bb(RAnal *anal, RAnalBlock *bb);
R_API int r_anal_diff_fingerprint_fcn(RAnal *anal, RAnalFunction *fcn);
R_API int r_anal_diff_bb(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2);
R_API int r_anal_diff_fcn(RAnal *anal, RList *fcns, RList *fcns2);
R_API int r_anal_diff_eval(RAnal *anal);

/* value.c */
R_API RAnalValue *r_anal_value_new();
R_API RAnalValue *r_anal_value_copy (RAnalValue *ov);
R_API RAnalValue *r_anal_value_new_from_string(const char *str);
R_API st64 r_anal_value_eval(RAnalValue *value);
R_API char *r_anal_value_to_string (RAnalValue *value);
R_API ut64 r_anal_value_to_ut64(RAnal *anal, RAnalValue *val);
R_API int r_anal_value_set_ut64(RAnal *anal, RAnalValue *val, ut64 num);
R_API void r_anal_value_free(RAnalValue *value);

R_API RAnalCond *r_anal_cond_new();
R_API RAnalCond *r_anal_cond_new_from_op(RAnalOp *op);
R_API void r_anal_cond_fini (RAnalCond *c);
R_API void r_anal_cond_free (RAnalCond *c);
R_API char *r_anal_cond_to_string(RAnalCond *cond);
R_API int r_anal_cond_eval (RAnal *anal, RAnalCond *cond);
R_API RAnalCond *r_anal_cond_new_from_string(const char *str);

/* reflines.c */
R_API RAnalRefline *r_anal_reflines_get(RAnal *anal,
	ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall);
R_API int r_anal_reflines_middle(RAnal *anal, RAnalRefline *list, ut64 addr, int len);
R_API char* r_anal_reflines_str(void *core, ut64 addr, int opts);
R_API RAnalRefline *r_anal_reflines_fcn_get( struct r_anal_t *anal, RAnalFunction *fcn,
    int nlines, int linesout, int linescall);
/* TODO move to r_core */
R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, int kind);
R_API RList *r_anal_var_list(RAnal *anal, RAnalFunction *fcn, int kind);

// calling conventions API
R_API RAnalCC* r_anal_cc_new ();
R_API void r_anal_cc_init (RAnalCC *cc);
R_API RAnalCC* r_anal_cc_new_from_string (const char *str, int type);
R_API void r_anal_cc_free (RAnalCC* cc);
R_API void r_anal_cc_reset (RAnalCC *cc);
R_API char *r_anal_cc_to_string (RAnal *anal, RAnalCC* cc);
R_API boolt r_anal_cc_update (RAnal *anal, RAnalCC *cc, RAnalOp *op);
R_API const char *r_anal_cc_type2str(int type);
R_API int r_anal_cc_str2type (const char *str);
//R_API int r_anal_cc_register (RAnal *anal, RAnalCC *cc);
//R_API int r_anal_cc_unregister (RAnal *anal, RAnalCC *cc);

typedef struct r_anal_data_t {
	ut64 addr;
	int type;
	ut64 ptr;
	char *str;
	int len;
	ut8 *buf;
	ut8 sbuf[8];
} RAnalData;

R_API RAnalData *r_anal_data (RAnal *anal, ut64 addr, const ut8 *buf, int size);
R_API const char *r_anal_data_kind (RAnal *anal, ut64 addr, const ut8 *buf, int len);
R_API RAnalData *r_anal_data_new_string (ut64 addr, const char *p, int size, int wide);
R_API RAnalData *r_anal_data_new (ut64 addr, int type, ut64 n, const ut8 *buf, int len);
R_API void r_anal_data_free (RAnalData *d);
R_API char *r_anal_data_to_string (RAnalData *d);

R_API void r_meta_free(RAnal *m);
R_API int r_meta_count(RAnal *m, int type, ut64 from, ut64 to);
R_API char *r_meta_get_string(RAnal *m, int type, ut64 addr);
R_API int r_meta_set_string(RAnal *m, int type, ut64 addr, const char *s);
R_API int r_meta_del(RAnal *m, int type, ut64 from, ut64 size, const char *str);
R_API int r_meta_add(RAnal *m, int type, ut64 from, ut64 size, const char *str);
R_API RAnalMetaItem *r_meta_find(RAnal *m, ut64 off, int type, int where);
R_API int r_meta_cleanup(RAnal *m, ut64 from, ut64 to);
R_API const char *r_meta_type_to_string(int type);
R_API int r_meta_list(RAnal *m, int type, int rad);
R_API void r_meta_item_free(void *_item);
R_API RAnalMetaItem *r_meta_item_new(int type);

R_API int r_anal_fcn_xref_add (RAnal *anal, RAnalFunction *fcn, ut64 at, ut64 addr, int type);
R_API int r_anal_fcn_xref_del (RAnal *anal, RAnalFunction *fcn, ut64 at, ut64 addr, int type);

/* hints */
//R_API void r_anal_hint_list (RAnal *anal, int mode);
R_API RAnalHint *r_anal_hint_from_string(RAnal *a, ut64 addr, const char *str);
R_API void r_anal_hint_del (RAnal *anal, ut64 addr, int size);
R_API void r_anal_hint_clear (RAnal *a);
R_API RAnalHint *r_anal_hint_at (RAnal *a, ut64 from);
R_API RAnalHint *r_anal_hint_add (RAnal *a, ut64 from, int size);
R_API void r_anal_hint_free (RAnalHint *h);
R_API RAnalHint *r_anal_hint_get(RAnal *anal, ut64 addr);
R_API void r_anal_hint_set_jump (RAnal *a, ut64 addr, ut64 ptr);
R_API void r_anal_hint_set_fail (RAnal *a, ut64 addr, ut64 ptr);
R_API void r_anal_hint_set_length (RAnal *a, ut64 addr, int length);
R_API void r_anal_hint_set_bits (RAnal *a, ut64 addr, int bits);
R_API void r_anal_hint_set_arch (RAnal *a, ut64 addr, const char *arch);
R_API void r_anal_hint_set_size (RAnal *a, ut64 addr, int length);
R_API void r_anal_hint_set_opcode (RAnal *a, ut64 addr, const char *str);
R_API void r_anal_hint_set_esil (RAnal *a, ut64 addr, const char *str);
R_API void r_anal_hint_set_pointer (RAnal *a, ut64 addr, ut64 jump);
R_API int r_anal_esil_eval(RAnal *anal, const char *str);

/* switch.c APIs */
R_API RAnalSwitchOp * r_anal_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val);
R_API void r_anal_switch_op_free(RAnalSwitchOp * swop);
R_API RAnalCaseOp* r_anal_switch_op_add_case(RAnalSwitchOp * swop, ut64 addr, ut64 value, ut64 jump);

/* cycles.c */
R_API RAnalCycleFrame* r_anal_cycle_frame_new ();
R_API void r_anal_cycle_frame_free (RAnalCycleFrame *cf);

/*
 * RAnalState maintains state during analysis.
 * there are standard values current_fcn, current_op, current_bb, addr,
 * data buffer, etc. but there is also a void * for user defined structures
 * that can be updated during the callbacks.
 */
R_API RAnalState * r_anal_state_new (ut64 start, ut8* buffer, ut64 len);
R_API void r_anal_state_insert_bb (RAnalState* state, RAnalBlock *bb);
R_API int r_anal_state_need_rehash (RAnalState* state, RAnalBlock *bb);
R_API RAnalBlock * r_anal_state_search_bb (RAnalState* state, ut64 addr);
R_API void r_anal_state_free (RAnalState * state);
R_API ut64 r_anal_state_get_len (RAnalState *state, ut64 addr);
R_API const ut8 * r_anal_state_get_buf_by_addr (RAnalState *state, ut64 addr);
R_API int r_anal_state_addr_is_valid (RAnalState *state, ut64 addr);
R_API void r_anal_state_merge_bb_list (RAnalState *state, RList* bbs);
R_API void r_anal_state_set_depth(RAnalState *state, ut32 depth);

/* labels */
R_API ut64 r_anal_fcn_label_get (RAnal *anal, RAnalFunction *fcn, const char *name);
R_API const char *r_anal_fcn_label_at (RAnal *anal, RAnalFunction *fcn, ut64 addr);
R_API int r_anal_fcn_label_set (RAnal *anal, RAnalFunction *fcn, const char *name, ut64 addr);
R_API int r_anal_fcn_label_del (RAnal *anal, RAnalFunction *fcn, const char *name, ut64 addr);
R_API int r_anal_fcn_labels (RAnal *anal, RAnalFunction *fcn, int rad);

/* limits */
R_API void r_anal_set_limits(RAnal *anal, ut64 from, ut64 to);
R_API void r_anal_unset_limits(RAnal *anal);

/* plugin pointers */
extern RAnalPlugin r_anal_plugin_null;
extern RAnalPlugin r_anal_plugin_csr;
extern RAnalPlugin r_anal_plugin_tms320;
extern RAnalPlugin r_anal_plugin_avr;
extern RAnalPlugin r_anal_plugin_arm_gnu;
extern RAnalPlugin r_anal_plugin_arm_cs;
extern RAnalPlugin r_anal_plugin_x86;
extern RAnalPlugin r_anal_plugin_x86_cs;
extern RAnalPlugin r_anal_plugin_x86_im;
extern RAnalPlugin r_anal_plugin_x86_udis;
extern RAnalPlugin r_anal_plugin_x86_simple;
extern RAnalPlugin r_anal_plugin_ppc_gnu;
extern RAnalPlugin r_anal_plugin_ppc_cs;
extern RAnalPlugin r_anal_plugin_java;
extern RAnalPlugin r_anal_plugin_mips_gnu;
extern RAnalPlugin r_anal_plugin_mips_cs;
extern RAnalPlugin r_anal_plugin_dalvik;
extern RAnalPlugin r_anal_plugin_sh;
extern RAnalPlugin r_anal_plugin_sparc_gnu;
extern RAnalPlugin r_anal_plugin_bf;
extern RAnalPlugin r_anal_plugin_m68k;
extern RAnalPlugin r_anal_plugin_z80;
extern RAnalPlugin r_anal_plugin_i8080;
extern RAnalPlugin r_anal_plugin_8051;
extern RAnalPlugin r_anal_plugin_arc;
extern RAnalPlugin r_anal_plugin_ebc;
extern RAnalPlugin r_anal_plugin_gb;
extern RAnalPlugin r_anal_plugin_nios2;
extern RAnalPlugin r_anal_plugin_malbolge;
extern RAnalPlugin r_anal_plugin_ws;
extern RAnalPlugin r_anal_plugin_h8300;
extern RAnalPlugin r_anal_plugin_cr16;
extern RAnalPlugin r_anal_plugin_v850;
extern RAnalPlugin r_anal_plugin_sysz;
extern RAnalPlugin r_anal_plugin_sparc_cs;
extern RAnalPlugin r_anal_plugin_xcore_cs;
extern RAnalPlugin r_anal_plugin_propeller;
extern RAnalPlugin r_anal_plugin_msp430;
extern RAnalPlugin r_anal_plugin_cris;
#ifdef __cplusplus
}
#endif

#endif
#endif

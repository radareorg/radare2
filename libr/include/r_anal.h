/* radare2 - LGPL - Copyright 2009-2018 - nibble, pancake, xvilka */

#ifndef R2_ANAL_H
#define R2_ANAL_H

#define USE_DICT 1

/* use sdb function storage */
#define FCN_SDB 1
/* use old refs and function storage */
// still required by core in lot of places
#define FCN_OLD 1
#define USE_VARSUBS 0

#include <r_types.h>
#include <r_io.h>
#include <r_reg.h>
#include <r_list.h>
#include <r_util.h>
#include <r_bind.h>
#include <r_syscall.h>
#include <r_flag.h>
#include <r_bin.h>

#define esilprintf(op, fmt, ...) r_strbuf_setf (&op->esil, fmt, ##__VA_ARGS__)

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

// TODO: Remove this define? /cc @nibble_ds
#define VERBOSE_ANAL if(0)

/* meta */
typedef struct r_anal_meta_item_t {
	ut64 from;
	ut64 to;
	ut64 size;
	int type;
	int subtype;
	char *str;
	int space;
} RAnalMetaItem;

typedef struct {
	struct r_anal_t *anal;
	int type;
	int rad;
	SdbForeachCallback cb;
	void *user;
	int count;
	struct r_anal_type_function_t *fcn;
} RAnalMetaUserItem;

typedef struct r_anal_range_t {
	ut64 from;
	ut64 to;
	int bits;
} RAnalRange;

#define R_ANAL_UNMASK_TYPE(x) (x&R_ANAL_VAR_TYPE_SIZE_MASK)
#define R_ANAL_UNMASK_SIGN(x) (((x& R_ANAL_VAR_TYPE_SIGN_MASK)>> R_ANAL_VAR_TYPE_SIGN_SHIFT)==R_ANAL_VAR_TYPE_UNSIGNED)?0:1

#define R_ANAL_GET_OFFSET(x,y,z) \
	(x && x->binb.bin && x->binb.get_offset)? \
		x->binb.get_offset (x->binb.bin, y, z): -1
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
#define R_ANAL_ADDR_TYPE_READ      1 << 1
#define R_ANAL_ADDR_TYPE_WRITE     1 << 2
#define R_ANAL_ADDR_TYPE_FLAG      1 << 3
#define R_ANAL_ADDR_TYPE_FUNC      1 << 4
#define R_ANAL_ADDR_TYPE_HEAP      1 << 5
#define R_ANAL_ADDR_TYPE_STACK     1 << 6
#define R_ANAL_ADDR_TYPE_REG       1 << 7
#define R_ANAL_ADDR_TYPE_PROGRAM   1 << 8
#define R_ANAL_ADDR_TYPE_LIBRARY   1 << 9
#define R_ANAL_ADDR_TYPE_ASCII     1 << 10
#define R_ANAL_ADDR_TYPE_SEQUENCE  1 << 11

#define R_ANAL_ARCHINFO_MIN_OP_SIZE 0
#define R_ANAL_ARCHINFO_MAX_OP_SIZE 1
#define R_ANAL_ARCHINFO_ALIGN 2
#define R_ANAL_ARCHINFO_DATA_ALIGN 4

/* copypaste from r_asm.h */

#define R_ANAL_GET_OFFSET(x,y,z) \
        (x && x->binb.bin && x->binb.get_offset)? \
                x->binb.get_offset (x->binb.bin, y, z): -1

#define R_ANAL_GET_NAME(x,y,z) \
        (x && x->binb.bin && x->binb.get_name)? \
                x->binb.get_name (x->binb.bin, y, z): NULL

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
		ut8  v8;
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
		ut8  v8;
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

/*--------------------Function Convnetions-----------*/
//XXX dont use then in the future
#define R_ANAL_CC_TYPE_STDCALL 0
#define R_ANAL_CC_TYPE_PASCAL 1
#define R_ANAL_CC_TYPE_FASTCALL 'A' // syscall
#define R_ANAL_CC_TYPE_SYSV 8

enum {
	R_ANAL_FCN_TYPE_NULL = 0,
	R_ANAL_FCN_TYPE_FCN = 1 << 0,
	R_ANAL_FCN_TYPE_LOC = 1 << 1,
	R_ANAL_FCN_TYPE_SYM = 1 << 2,
	R_ANAL_FCN_TYPE_IMP = 1 << 3,
	R_ANAL_FCN_TYPE_INT = 1 << 4, /* priviledged function - ends with iret/reti/.. */
	R_ANAL_FCN_TYPE_ROOT = 1 << 5  /* matching flag */
};

#define R_ANAL_VARSUBS 32

#define RAnalBlock struct r_anal_bb_t

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
	ut32 size;
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
	SdbHash *h;
	RList *l;
} RAnalFcnStore;

/* Stores useful function metadata */
/* TODO: Think about moving more stuff to this structure? */
typedef struct r_anal_fcn_meta_t {
	ut64 min;           // min address
	ut64 max;           // max address
	int numrefs;        // number of cross references
	int numcallrefs;    // number of calls
	int sgnc;           // node cardinality of the functions callgraph
	int sgec;           // edge cardinality of the functions callgraph
} RAnalFcnMeta;

/* Store various function information,
 * variables, arguments, refs and even
 * description */
typedef struct r_anal_type_function_t {
	char* name;
	char* dsc; // For producing nice listings
	ut32 _size;
	int bits; // ((> bits 0) (set-bits bits))
	int type;
	/*item_list *rets; // Type of return value */
	char *rets;
	short fmod; //  static, inline or volatile?
	const char *cc; // calling convention
	char* attr; // __attribute__(()) list
	ut64 addr;
	ut64 rb_max_addr; // maximum of addr + _size - 1 in the subtree, for interval tree
	int stack; //stack frame size
	int maxstack;
	int ninstr;
	int nargs; // Function arguments counter
	int depth;
	bool folded;
	RAnalType *args; // list of arguments
	ut8 *fingerprint; // TODO: make is fuzzy and smarter
	RAnalDiff *diff;
	RList *locs; // list of local variables
	RList *fcn_locs; //sorted list of a function *.loc refs
	//RList *locals; // list of local labels -> moved to anal->sdb_fcns
	RList *bbs;
	RAnalFcnMeta meta;
	RRangeTiny bbr;
	RBNode rb;
} RAnalFunction;

typedef struct r_anal_func_arg_t {
	const char *name;
	const char *fmt;
	const char *cc_source;
	char *orig_c_type;
	char *c_type;
	ut64 size;
	ut64 src; //Function-call argument value or pointer to it
} RAnalFuncArg;

struct r_anal_type_t {
	char *name;
	ut32 type;
	ut32 size;
	RList *content;
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
	R_META_TYPE_RUN = 'r',
	R_META_TYPE_HIGHLIGHT = 'H',
};

// anal
enum {
	R_ANAL_OP_FAMILY_UNKNOWN = -1,
	R_ANAL_OP_FAMILY_CPU = 0,/* normal cpu instruction */
	R_ANAL_OP_FAMILY_FPU,    /* fpu (floating point) */
	R_ANAL_OP_FAMILY_MMX,    /* multimedia instruction (packed data) */
	R_ANAL_OP_FAMILY_SSE,    /* extended multimedia instruction (packed data) */
	R_ANAL_OP_FAMILY_PRIV,   /* priviledged instruction */
	R_ANAL_OP_FAMILY_CRYPTO, /* cryptographic instructions */
	R_ANAL_OP_FAMILY_VIRT,   /* virtualization instructions */
	R_ANAL_OP_FAMILY_IO,     /* IO instructions (i.e. IN/OUT) */
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
#define R_ANAL_OP_TYPE_MASK 0x8000ffff
typedef enum {
	R_ANAL_OP_TYPE_COND  = 0x80000000, // TODO must be moved to prefix?
	//TODO: MOVE TO PREFIX .. it is used by anal_ex.. must be updated
	R_ANAL_OP_TYPE_REP   = 0x40000000, /* repeats next instruction N times */
	R_ANAL_OP_TYPE_MEM   = 0x20000000, // TODO must be moved to prefix?
	R_ANAL_OP_TYPE_REG   = 0x10000000, // operand is a register
	R_ANAL_OP_TYPE_IND   = 0x08000000, // operand is indirect
	R_ANAL_OP_TYPE_NULL  = 0,
	R_ANAL_OP_TYPE_JMP   = 1,  /* mandatory jump */
	R_ANAL_OP_TYPE_UJMP  = 2,  /* unknown jump (register or so) */
	R_ANAL_OP_TYPE_RJMP  = R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UJMP,
	R_ANAL_OP_TYPE_IJMP  = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_UJMP,
	R_ANAL_OP_TYPE_IRJMP = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UJMP,
	R_ANAL_OP_TYPE_CJMP  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_JMP,  /* conditional jump */
	R_ANAL_OP_TYPE_MJMP  = R_ANAL_OP_TYPE_MEM | R_ANAL_OP_TYPE_JMP,  /* conditional jump */
	R_ANAL_OP_TYPE_UCJMP = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UJMP, /* conditional unknown jump */
	R_ANAL_OP_TYPE_CALL  = 3,  /* call to subroutine (branch+link) */
	R_ANAL_OP_TYPE_UCALL = 4, /* unknown call (register or so) */
	R_ANAL_OP_TYPE_RCALL = R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UCALL,
	R_ANAL_OP_TYPE_ICALL = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_UCALL,
	R_ANAL_OP_TYPE_IRCALL= R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UCALL,
	R_ANAL_OP_TYPE_CCALL = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL, /* conditional call to subroutine */
	R_ANAL_OP_TYPE_UCCALL= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UCALL, /* conditional unknown call */
	R_ANAL_OP_TYPE_RET   = 5, /* returns from subroutine */
	R_ANAL_OP_TYPE_CRET  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET, /* conditional return from subroutine */
	R_ANAL_OP_TYPE_ILL   = 6,  /* illegal instruction // trap */
	R_ANAL_OP_TYPE_UNK   = 7, /* unknown opcode type */
	R_ANAL_OP_TYPE_NOP   = 8, /* does nothing */
	R_ANAL_OP_TYPE_MOV   = 9, /* register move */
	R_ANAL_OP_TYPE_CMOV  = 9 | R_ANAL_OP_TYPE_COND, /* conditional move */
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
	R_ANAL_OP_TYPE_NOR   = 29,
	R_ANAL_OP_TYPE_NOT   = 30,
	R_ANAL_OP_TYPE_STORE = 31,  /* store from register to memory */
	R_ANAL_OP_TYPE_LOAD  = 32,  /* load from memory to register */
	R_ANAL_OP_TYPE_LEA   = 33, /* TODO add ulea */
	R_ANAL_OP_TYPE_LEAVE = 34,
	R_ANAL_OP_TYPE_ROR   = 35,
	R_ANAL_OP_TYPE_ROL   = 36,
	R_ANAL_OP_TYPE_XCHG  = 37,
	R_ANAL_OP_TYPE_MOD   = 38,
	R_ANAL_OP_TYPE_SWITCH = 39,
	R_ANAL_OP_TYPE_CASE = 40,
	R_ANAL_OP_TYPE_LENGTH = 41,
	R_ANAL_OP_TYPE_CAST = 42,
	R_ANAL_OP_TYPE_NEW = 43,
	R_ANAL_OP_TYPE_ABS = 44,
	R_ANAL_OP_TYPE_CPL = 45,	/* complement */
	R_ANAL_OP_TYPE_CRYPTO = 46,
	R_ANAL_OP_TYPE_SYNC = 47,
	//R_ANAL_OP_TYPE_DEBUG = 43, // monitor/trace/breakpoint
#if 0
	R_ANAL_OP_TYPE_PRIV = 40, /* priviledged instruction */
	R_ANAL_OP_TYPE_FPU = 41, /* floating point stuff */
#endif
} _RAnalOpType;

typedef enum {
	R_ANAL_OP_MASK_ESIL       = 1,
	R_ANAL_OP_MASK_ALL        = R_ANAL_OP_MASK_ESIL
} RAnalOpMask;

/* TODO: what to do with signed/unsigned conditionals? */
typedef enum {
	R_ANAL_COND_AL = 0,        // Always executed (no condition)
	R_ANAL_COND_EQ,            // Equal
	R_ANAL_COND_NE,            // Not equal
	R_ANAL_COND_GE,            // Greater or equal
	R_ANAL_COND_GT,            // Greater than
	R_ANAL_COND_LE,            // Less or equal
	R_ANAL_COND_LT,            // Less than
	R_ANAL_COND_NV,            // Never executed             must be a nop? :D
	R_ANAL_COND_HS,            // Carry set                  >, ==, or unordered
	R_ANAL_COND_LO,            // Carry clear                Less than
	R_ANAL_COND_MI,            // Minus, negative            Less than
	R_ANAL_COND_PL,            // Plus, positive or zero     >, ==, or unordered
	R_ANAL_COND_VS,            // Overflow                   Unordered
	R_ANAL_COND_VC,            // No overflow                Not unordered
	R_ANAL_COND_HI,            // Unsigned higher            Greater than, or unordered
	R_ANAL_COND_LS             // Unsigned lower or same     Less than or equal
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
	R_ANAL_STACK_RESET,
	R_ANAL_STACK_ALIGN,
};

enum {
	R_ANAL_REFLINE_TYPE_UTF8 = 1,
	R_ANAL_REFLINE_TYPE_WIDE = 2,  /* reflines have a space between them */
	R_ANAL_REFLINE_TYPE_MIDDLE = 4 /* do not consider starts/ends of reflines (used for comments lines) */
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
	RAnalBlock *jumpbb;
} RAnalCaseOp;

typedef struct r_anal_switch_obj_t {
	ut64 addr;
	ut64 min_val;
	ut64 def_val;
	ut64 max_val;
	RList *cases;
} RAnalSwitchOp;

#define RANAL void*
//struct r_anal_t*
#define RANAL_BLOCK void*
//struct r_anal_bb_t*
typedef struct r_anal_callbacks_t {
	int (*on_fcn_new) (RANAL, void *user, RAnalFunction *fcn);
	int (*on_fcn_delete) (RANAL , void *user, RAnalFunction *fcn);
	int (*on_fcn_rename) (RANAL, void *user, RAnalFunction *fcn, const char *oldname);
	int (*on_fcn_bb_new) (RANAL, void *user, RAnalFunction *fcn, RANAL_BLOCK bb);
} RAnalCallbacks;

#define R_ANAL_ESIL_GOTO_LIMIT 4096

typedef struct r_anal_options_t {
	int depth;
	int cjmpref;
	int jmpref;
	int jmpabove;
	bool ijmp;
	int followdatarefs;
	int searchstringrefs;
	int followbrokenfcnsrefs;
	int bbs_alignment;
	int bb_max_size;
	int afterjmp; // continue analysis after jmp eax or forward jmp // option
	int recont; // continue on recurse analysis mode
	int eobjmp; // option
	int bbsplit;
	int noncode;
	int nopskip; // skip nops at the beginning of functions
	int hpskip; // skip `mov reg,reg` and `lea reg,[reg]`
	int jmptbl; // analyze jump tables
	bool pushret; // analyze push+ret as jmp
	bool armthumb; //
} RAnalOptions;

typedef enum {
	R_ANAL_CPP_ABI_ITANIUM = 0,
	R_ANAL_CPP_ABI_MSVC
} RAnalCPPABI;

typedef struct r_anal_t {
	char *cpu;
	char *os;
	int bits;
	int lineswidth; // wtf
	int big_endian;
	int split; // used only from core
	int sleep; // sleep some usecs before analyzing more (avoid 100% cpu usages)
	RAnalCPPABI cpp_abi;
	void *user;
	ut64 gp; // global pointer. used for mips. but can be used by other arches too in the future
	RList *fcns;
	RBNode *fcn_tree;
	RListRange *fcnstore;
	RList *refs;
	RList *vartypes;
	RReg *reg;
	ut8 *last_disasm_reg;
	RSyscall *syscall;
	struct r_anal_op_t *queued;
	int diff_ops;
	double diff_thbb;
	double diff_thfcn;
	RIOBind iob;
	RFlagBind flb;
	RBinBind binb; // Set only from core when an analysis plugin is called.
	RCoreBind coreb;
	int decode;
	int maxreflines;
	int trace;
	int esil_goto_limit;
	int pcalign;
	int bitshift;
	RList *types;
	//struct r_anal_ctx_t *ctx;
	struct r_anal_esil_t *esil;
	struct r_anal_plugin_t *cur;
	RAnalRange *limit;
	RList *plugins;
	Sdb *sdb_types;
	Sdb *sdb_meta; // TODO: Future r_meta api
	Sdb *sdb_zigns;

#if USE_DICT
	SdbHash *dict_refs;
	SdbHash *dict_xrefs;
#endif
	bool recursive_noreturn;
	RSpaces meta_spaces;
	RSpaces zign_spaces;
	char *zign_path;
	PrintfCallback cb_printf;
	//moved from RAnalFcn
	Sdb *sdb; // root
	Sdb *sdb_refs;
	Sdb *sdb_fcns;
	Sdb *sdb_pins;
#define DEPRECATE 1
#if DEPRECATE
	Sdb *sdb_args;  //
	Sdb *sdb_vars; // globals?
#endif
	Sdb *sdb_hints; // OK
	bool bits_hints_changed;
	Sdb *sdb_fcnsign; // OK
	Sdb *sdb_cc; // calling conventions
	//RList *hints; // XXX use better data structure here (slist?)
	RAnalCallbacks cb;
	RAnalOptions opt;
	RList *reflines;
	RList *reflines2;
	//RList *noreturn;
	RList /*RAnalRange*/ *bits_ranges;
	RListComparator columnSort;
	int stackptr;
	bool (*log)(struct r_anal_t *anal, const char *msg);
	bool (*read_at)(struct r_anal_t *anal, ut64 addr, ut8 *buf, int len);
	char *cmdtail;
	int seggrn;
} RAnal;

typedef RAnalFunction *(* RAnalGetFcnIn)(RAnal *anal, ut64 addr, int type);

typedef struct r_anal_bind_t {
	RAnal *anal;
	RAnalGetFcnIn get_fcn_in;
} RAnalBind;

typedef struct r_anal_hint_t {
	ut64 addr;
	ut64 ptr;
	ut64 jump;
	ut64 fail;
	char *arch;
	char *opcode;
	char *syntax;
	char *esil;
	char *offset;
	int size;
	int bits;
	int new_bits; // change asm.bits after evaluating this instruction
#if 0
	int new_endian; // change the endianness
	int new_bank; // select bank switch
#endif
	int immbase;
	bool high; // highlight hint
} RAnalHint;

typedef struct r_anal_var_access_t {
	ut64 addr;
	int set;
} RAnalVarAccess;

#define R_ANAL_VAR_KIND_ANY 0
#define R_ANAL_VAR_KIND_ARG 'a'
#define R_ANAL_VAR_KIND_REG 'r'
#define R_ANAL_VAR_KIND_BPV 'b'
#define R_ANAL_VAR_KIND_SPV 's'

// generic for args and locals
typedef struct r_anal_var_t {
	char *name;  /* name of the variable */
	char *type;  // cparse type of the variable
	char kind;   // 'a'rg, 'v'ar ..
	ut64 addr;   // not used correctly?
	ut64 eaddr;  // not used correctly?
	int size;
	int delta;   /* delta offset inside stack frame */
	int scope;   /* global, local... | in, out... */
	/* probably dupped or so */
	RList/*RAnalVarAccess*/ *accesses; /* list of accesses for this var */
	RList/*RAnalValue*/ *stores;   /* where this */
} RAnalVar;

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

enum RAnalOpDirection {
	R_ANAL_OP_DIR_READ = 1,
	R_ANAL_OP_DIR_WRITE = 2,
	R_ANAL_OP_DIR_EXEC = 4,
	R_ANAL_OP_DIR_REF = 8,
};

typedef struct r_anal_op_t {
	char *mnemonic; /* mnemonic */
	ut64 addr;      /* address */
	ut32 type;      /* type of opcode */
	ut64 prefix;    /* type of opcode prefix (rep,lock,..) */
	ut32 type2;	/* used by java */
	int group;      /* is fpu, is privileged, mmx, etc */
	int stackop;    /* operation on stack? */
	int cond;       /* condition type */
	int size;       /* size in bytes of opcode */
	int nopcode;    /* number of bytes representing the opcode (not the arguments) TODO: find better name */
	int cycles;	/* cpu-cycles taken by instruction */
	int failcycles;	/* conditional cpu-cycles */
	int family;     /* family of opcode */
	int id;         /* instruction id */
	bool eob;       /* end of block (boolean) */
	/* Run N instructions before executing the current one */
	int delay;      /* delay N slots (mips, ..)*/
	ut64 jump;      /* true jmp */
	ut64 fail;      /* false jmp */
	int direction;  /* 1 = read, 2 = write, 4 = exec, 8 = reference,  */
	st64 ptr;       /* reference to memory */ /* XXX signed? */
	ut64 val;       /* reference to value */ /* XXX signed? */
	int ptrsize;    /* f.ex: zero extends for 8, 16 or 32 bits only */
	st64 stackptr;  /* stack pointer */
	int refptr;     /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
	RAnalVar *var;  /* local var/arg used by this instruction */
	RAnalValue *src[3];
	RAnalValue *dst;
	struct r_anal_op_t *next; // TODO deprecate
	RStrBuf esil;
	RStrBuf opex;
	const char *reg; /* destination register */
	const char *ireg; /* register used for indirect memory computation*/
	int scale;
	ut64 disp;
	RAnalSwitchOp *switch_op;
	RAnalHint hint;
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
	RAnalCond *cond;
	RAnalSwitchOp *switch_op;
	// offsets of instructions in this block
	ut16 *op_pos;
	// size of the op_pos array
	int op_pos_size;
	ut8 *op_bytes;
	ut8 op_sz;
	/* deprecate ??? where is this used? */
	/* iirc only java. we must use r_anal_bb_from_offset(); instead */
	RAnalBlock *head;
	RAnalBlock *tail;
	RAnalBlock *next;
	/* these are used also in pdr: */
	RAnalBlock *prev;
	RAnalBlock *failbb;
	RAnalBlock *jumpbb;
	RList /*struct r_anal_bb_t*/ *cases;
	ut8 *parent_reg_arena;
	int stackptr;
	int parent_stackptr;
#undef RAnalBlock
} RAnalBlock;

typedef enum {
	R_ANAL_REF_TYPE_NULL = 0,
	R_ANAL_REF_TYPE_CODE = 'c', // code ref
	R_ANAL_REF_TYPE_CALL = 'C', // code ref (call)
	R_ANAL_REF_TYPE_DATA = 'd', // mem ref
	R_ANAL_REF_TYPE_STRING='s'  // string ref
} RAnalRefType;

typedef struct r_anal_ref_t {
	RAnalRefType type;
	ut64 addr;
	ut64 at;
} RAnalRef;

/* represents a reference line from one address (from) to another (to) */
typedef struct r_anal_refline_t {
	ut64 from;
	ut64 to;
	int index;
	int level;
	int type;
	int direction;
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
	SdbHash *ht;
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
	R_ANAL_TRAP_WRITE_ERR = 4,
	R_ANAL_TRAP_READ_ERR = 5,
	R_ANAL_TRAP_EXEC_ERR = 6,
	R_ANAL_TRAP_TODO = 7,
	R_ANAL_TRAP_HALT = 8,
};

enum {
	R_ANAL_ESIL_PARM_INVALID = 0,
	R_ANAL_ESIL_PARM_INTERNAL,
	R_ANAL_ESIL_PARM_REG,
	R_ANAL_ESIL_PARM_NUM,
};

/* Constructs to convert from ESIL to REIL */
#define FOREACHOP(GENERATE)                     \
/* No Operation */               GENERATE(NOP)  \
/* Unknown/Undefined */          GENERATE(UNK)  \
/* Conditional Jump */           GENERATE(JCC)  \
/* Store Value to register */    GENERATE(STR)  \
/* Store value to memory */      GENERATE(STM)  \
/* Load value from memory */     GENERATE(LDM)  \
/* Addition */                   GENERATE(ADD)  \
/* Subtraction */                GENERATE(SUB)  \
/* Negation */                   GENERATE(NEG)  \
/* Multiplication */             GENERATE(MUL)  \
/* Division */                   GENERATE(DIV)  \
/* Modulo */                     GENERATE(MOD)  \
/* Signed Multiplication */      GENERATE(SMUL) \
/* Sugned Division */            GENERATE(SDIV) \
/* Signed Modulus */             GENERATE(SMOD) \
/* Shift Left */                 GENERATE(SHL)  \
/* Shift Right */                GENERATE(SHR)  \
/* Binary and */                 GENERATE(AND)  \
/* Binary or */                  GENERATE(OR)   \
/* Binary xor */                 GENERATE(XOR)  \
/* Binary not */                 GENERATE(NOT)  \
/* Equation */                   GENERATE(EQ)   \
/* Less Than */                  GENERATE(LT)

#define MAKE_ENUM(OP) REIL_##OP,
#define REIL_OP_STRING(STRING) #STRING,

typedef enum {
	FOREACHOP(MAKE_ENUM)
} RAnalReilOpcode;

typedef enum {
	ARG_REG,           // CPU Register
	ARG_TEMP,          // Temporary register used by REIL
	ARG_CONST,         // Constant value
	ARG_ESIL_INTERNAL, // Used to resolve ESIL internal flags
	ARG_NONE           // Operand not used by the instruction
} RAnalReilArgType;

// Arguments to a REIL instruction.
typedef struct r_anal_reil_arg {
	RAnalReilArgType type; // Type of the argument
	ut8 size;              // Size of the argument in bytes
	char name[32];         // Name of the argument
} RAnalReilArg;

// Instruction arg1, arg2, arg3
typedef struct r_anal_reil_inst {
	RAnalReilOpcode opcode;
	RAnalReilArg *arg[3];
} RAnalReilInst;

typedef struct r_anal_reil {
	char old[32]; // Used to compute flags.
	char cur[32];
	ut8 lastsz;
	ut64 reilNextTemp;   // Used to store the index of the next REIL temp register to be used.
	ut64 addr;           // Used for instruction sequencing. Check esil2reil.c for details.
	ut8 seq_num;         // Incremented and used when noInc is set to 1.
	int skip;
	int cmd_count;
	char if_buf[64];
	char pc[8];
} RAnalReil;

// must be a char
#define ESIL_INTERNAL_PREFIX '$'
#define ESIL_STACK_NAME "esil.ram"
#define ESIL struct r_anal_esil_t

typedef struct r_anal_esil_session_t {
	ut64 key;
	ut64 addr;
	ut64 size;
	ut8 *data;
	RListIter *reg[R_REG_TYPE_LAST];
} RAnalEsilSession;

typedef int (*RAnalEsilHookRegWriteCB)(ESIL *esil, const char *name, ut64 *val);

typedef struct r_anal_esil_callbacks_t {
	void *user;
	/* callbacks */
	int (*hook_flag_read)(ESIL *esil, const char *flag, ut64 *num);
	int (*hook_command)(ESIL *esil, const char *op);
	int (*hook_mem_read)(ESIL *esil, ut64 addr, ut8 *buf, int len);
	int (*mem_read)(ESIL *esil, ut64 addr, ut8 *buf, int len);
	int (*hook_mem_write)(ESIL *esil, ut64 addr, const ut8 *buf, int len);
	int (*mem_write)(ESIL *esil, ut64 addr, const ut8 *buf, int len);
	int (*hook_reg_read)(ESIL *esil, const char *name, ut64 *res, int *size);
	int (*reg_read)(ESIL *esil, const char *name, ut64 *res, int *size);
	RAnalEsilHookRegWriteCB hook_reg_write;
	int (*reg_write)(ESIL *esil, const char *name, ut64 val);
} RAnalEsilCallbacks;

typedef struct r_anal_esil_t {
	RAnal *anal;
	char **stack;
	ut64 addrmask;
	int stacksize;
	int stackptr;
	int skip;
	int nowrite;
	int iotrap;
	int exectrap;
	int repeat;
	int parse_stop;
	int parse_goto;
	int parse_goto_count;
	int verbose;
	ut64 flags;
	ut64 address;
	ut64 stack_addr;
	ut32 stack_size;
	int delay; 		// mapped to $ds in ESIL
	ut64 jump_target; 	// mapped to $jt in ESIL
	int jump_target_set; 	// mapped to $js in ESIL
	int trap;
	ut32 trap_code; // extend into a struct to store more exception info?
	// parity flag? done with cur
	ut64 old;	//used for carry-flagging and borrow-flagging
	ut64 cur;	//used for carry-flagging and borrow-flagging
	ut8 lastsz;	//in bits //used for signature-flag
	/* native ops and custom ops */
	Sdb *ops;
	Sdb *interrupts;
	/* deep esil parsing fills this */
	Sdb *stats;
	Sdb *db_trace;
	int trace_idx;
	RAnalEsilCallbacks cb;
	RAnalReil *Reil;
	char *cmd_intr; // r2 (external) command to run when an interrupt occurs
	char *cmd_trap; // r2 (external) command to run when a trap occurs
	char *cmd_mdev; // r2 (external) command to run when an memory mapped device address is used
	char *cmd_todo; // r2 (external) command to run when esil expr contains TODO
	char *cmd_ioer; // r2 (external) command to run when esil fails to IO
	char *mdev_range; // string containing the r_str_range to match for read/write accesses
	bool (*cmd)(ESIL *esil, const char *name, ut64 a0, ut64 a1);
	void *user;
	int stack_fd;
	RList *sessions; // <RAnalEsilSession*>
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
typedef char*(*RAnalRegProfGetCallback)(RAnal *a);
typedef int (*RAnalFPBBCallback)(RAnal *a, RAnalBlock *bb);
typedef int (*RAnalFPFcnCallback)(RAnal *a, RAnalFunction *fcn);
typedef int (*RAnalDiffBBCallback)(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2);
typedef int (*RAnalDiffFcnCallback)(RAnal *anal, RList *fcns, RList *fcns2);
typedef int (*RAnalDiffEvalCallback)(RAnal *anal);

typedef bool (*RAnalIsValidOffsetCB)(RAnal *anal, ut64 offset, int hasperm);

typedef int (*RAnalEsilCB)(RAnalEsil *esil);
typedef int (*RAnalEsilLoopCB)(RAnalEsil *esil, RAnalOp *op);
typedef int (*RAnalEsilInterruptCB)(RAnalEsil *esil, int interrupt);
typedef int (*RAnalEsilTrapCB)(RAnalEsil *esil, int trap_type, int trap_code);

typedef struct r_anal_plugin_t {
	char *name;
	char *desc;
	char *license;
	char *arch;
	char *author;
	char *version;
	int bits;
	int esil; // can do esil or not
	int fileformat_type;
	int custom_fn_anal;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*reset_counter) (RAnal *anal, ut64 start_addr);
	int (*archinfo)(RAnal *anal, int query);
	ut8* (*anal_mask)(RAnal *anal, int size, const ut8 *data, ut64 at);

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
	// r_anal_ex_recursive_descent when using perform_analysis from
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
	RAnalRegProfGetCallback get_reg_profile;
	RAnalFPBBCallback fingerprint_bb;
	RAnalFPFcnCallback fingerprint_fcn;
	RAnalDiffBBCallback diff_bb;
	RAnalDiffFcnCallback diff_fcn;
	RAnalDiffEvalCallback diff_eval;

	RAnalIsValidOffsetCB is_valid_offset;

	RAnalEsilCB esil_init; // initialize esil-related stuff
	RAnalEsilLoopCB esil_post_loop;	//cycle-counting, firing interrupts, ...
	RAnalEsilInterruptCB esil_intr; // interrupts
	RAnalEsilTrapCB esil_trap; // traps / exceptions
	RAnalEsilCB esil_fini; // deinitialize
} RAnalPlugin;

/*----------------------------------------------------------------------------------------------*/
int * (r_anal_compare) (RAnalFunction , RAnalFunction );
/*----------------------------------------------------------------------------------------------*/

#ifdef R_API
/* --------- */ /* REFACTOR */ /* ---------- */
R_API RListRange* r_listrange_new (void);
R_API void r_listrange_free(RListRange *s);
R_API void r_listrange_add(RListRange *s, RAnalFunction *f);
R_API void r_listrange_del(RListRange *s, RAnalFunction *f);
R_API void r_listrange_resize(RListRange *s, RAnalFunction *f, int newsize);
R_API RAnalFunction *r_listrange_find_in_range(RListRange* s, ut64 addr);
R_API RAnalFunction *r_listrange_find_root(RListRange* s, ut64 addr);
/* --------- */ /* REFACTOR */ /* ---------- */
/* type.c */
R_API int r_anal_type_get_bitsize (RAnal *anal, const char *type);
R_API RList* r_anal_type_get_by_offset(RAnal *anal, ut64 offset);
R_API RAnalType *r_anal_type_new(void);
R_API void r_anal_type_add(RAnal *l, RAnalType *t);
R_API void r_anal_type_del(RAnal *l, const char *name);
R_API RList *r_anal_type_list_new(void);
R_API RAnalType *r_anal_type_find(RAnal *a, const char* name);
R_API void r_anal_type_list(RAnal *a, short category, short enabled);
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* s);
R_API char *r_anal_type_to_str(RAnal *a, const char *name);
R_API const char *r_anal_optype_to_string(int t);
R_API const char *r_anal_op_family_to_string (int n);
R_API int r_anal_op_family_from_string(const char *f);
R_API int r_anal_op_hint(RAnalOp *op, RAnalHint *hint);
R_API RAnalType *r_anal_type_free(RAnalType *t);
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path);
R_API void r_anal_type_define (RAnal *anal, const char *key, const char *value);
R_API void r_anal_type_header (RAnal *anal, const char *hdr);

R_API int r_anal_type_link (RAnal *anal, const char *val, ut64 addr);
R_API int r_anal_type_unlink(RAnal *anal, ut64 addr);
R_API int r_anal_type_link_offset (RAnal *anal, const char *val, ut64 addr);
R_API char *r_anal_type_format (RAnal *anal, const char *t);
R_API int r_anal_type_set(RAnal *anal, ut64 at, const char *field, ut64 val);
R_API int r_anal_type_func_exist(RAnal *anal, const char *func_name);
R_API const char *r_anal_type_func_cc(RAnal *anal, const char *func_name);
 R_API const char *r_anal_type_func_ret(RAnal *anal, const char *func_name);
R_API int r_anal_type_func_args_count(RAnal *anal, const char *func_name);
R_API char *r_anal_type_func_args_type(RAnal *anal, const char *func_name, int i);
R_API char *r_anal_type_func_args_name(RAnal *anal, const char *func_name, int i);
R_API char *r_anal_type_func_guess(RAnal *anal, char *func_name);
/* anal.c */
R_API RAnal *r_anal_new(void);
R_API int r_anal_purge (RAnal *anal);
R_API RAnal *r_anal_free(RAnal *r);
R_API void r_anal_set_user_ptr(RAnal *anal, void *user);
R_API void r_anal_plugin_free (RAnalPlugin *p);
R_API int r_anal_add(RAnal *anal, RAnalPlugin *foo);
R_API void r_anal_list(RAnal *anal);
R_API int r_anal_archinfo(RAnal *anal, int query);
R_API bool r_anal_use(RAnal *anal, const char *name);
R_API bool r_anal_set_reg_profile(RAnal *anal);
R_API char *r_anal_get_reg_profile(RAnal *anal);
R_API bool r_anal_set_bits(RAnal *anal, int bits);
R_API bool r_anal_set_os(RAnal *anal, const char *os);
R_API void r_anal_set_cpu(RAnal *anal, const char *cpu);
R_API int r_anal_set_big_endian(RAnal *anal, int boolean);
R_API ut8 *r_anal_mask(RAnal *anal, int size, const ut8 *data, ut64 at);
R_API void r_anal_trace_bb(RAnal *anal, ut64 addr);
R_API const char *r_anal_fcn_type_tostring(int type);
R_API void r_anal_bind(RAnal *b, RAnalBind *bnd);

/* fcnsign */
R_API int r_anal_set_triplet(RAnal *anal, const char *os, const char *arch, int bits);
R_API bool r_anal_set_fcnsign(RAnal *anal, const char *name);
R_API const char *r_anal_get_fcnsign(RAnal *anal, const char *sym);

/* bb.c */
R_API RAnalBlock *r_anal_bb_new(void);
R_API RList *r_anal_bb_list_new(void);
R_API void r_anal_bb_free(RAnalBlock *bb);
R_API int r_anal_bb(RAnal *anal, RAnalBlock *bb, ut64 addr, ut8 *buf, ut64 len, int head);
R_API RAnalBlock *r_anal_bb_from_offset(RAnal *anal, ut64 off);
R_API int r_anal_bb_is_in_offset(RAnalBlock *bb, ut64 addr);
R_API bool r_anal_bb_set_offset(RAnalBlock *bb, int i, ut16 v);
R_API ut16 r_anal_bb_offset_inst(RAnalBlock *bb, int i);
R_API ut64 r_anal_bb_opaddr_at(RAnalBlock *bb, ut64 addr);
R_API RAnalBlock *r_anal_bb_get_failbb(RAnalFunction *fcn, RAnalBlock *bb);
R_API RAnalBlock *r_anal_bb_get_jumpbb(RAnalFunction *fcn, RAnalBlock *bb);

/* op.c */
R_API const char *r_anal_stackop_tostring (int s);
R_API RAnalOp *r_anal_op_new(void);
R_API void r_anal_op_free(void *op);
R_API bool r_anal_op_fini(RAnalOp *op);
R_API bool r_anal_op_is_eob (RAnalOp *op);
R_API RList *r_anal_op_list_new(void);
R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr,
		const ut8 *data, int len, int mask);
R_API RAnalOp *r_anal_op_hexstr(RAnal *anal, ut64 addr,
		const char *hexstr);
R_API char *r_anal_op_to_string(RAnal *anal, RAnalOp *op);

R_API RAnalEsil *r_anal_esil_new (int stacksize, int iotrap, unsigned int addrsize);
R_API void r_anal_esil_trace (RAnalEsil *esil, RAnalOp *op);
R_API void r_anal_esil_trace_list (RAnalEsil *esil);
R_API void r_anal_esil_trace_show (RAnalEsil *esil, int idx);
R_API bool r_anal_esil_set_pc (RAnalEsil *esil, ut64 addr);
R_API int r_anal_esil_setup (RAnalEsil *esil, RAnal *anal, int romem, int stats, int nonull);
R_API void r_anal_esil_free (RAnalEsil *esil);
R_API int r_anal_esil_runword (RAnalEsil *esil, const char *word);
R_API int r_anal_esil_parse (RAnalEsil *esil, const char *str);
R_API int r_anal_esil_dumpstack (RAnalEsil *esil);
R_API int r_anal_esil_mem_read (RAnalEsil *esil, ut64 addr, ut8 *buf, int len);
R_API int r_anal_esil_mem_write (RAnalEsil *esil, ut64 addr, const ut8 *buf, int len);
R_API int r_anal_esil_reg_read (RAnalEsil *esil, const char *regname, ut64 *num, int *size);
R_API int r_anal_esil_reg_write (RAnalEsil *esil, const char *dst, ut64 num);
R_API int r_anal_esil_pushnum (RAnalEsil *esil, ut64 num);
R_API bool r_anal_esil_push (RAnalEsil *esil, const char *str);
R_API char *r_anal_esil_pop (RAnalEsil *esil);
R_API int r_anal_esil_set_op (RAnalEsil *esil, const char *op, RAnalEsilOp code);
R_API void r_anal_esil_stack_free (RAnalEsil *esil);
R_API int r_anal_esil_get_parm_type (RAnalEsil *esil, const char *str);
R_API int r_anal_esil_get_parm (RAnalEsil *esil, const char *str, ut64 *num);
R_API int r_anal_esil_condition (RAnalEsil *esil, const char *str);
R_API int r_anal_esil_set_interrupt (RAnalEsil *esil, int interrupt, RAnalEsilInterruptCB interruptcb);
R_API int r_anal_esil_fire_interrupt (RAnalEsil *esil, int interrupt);

R_API void r_anal_esil_mem_ro(RAnalEsil *esil, int mem_readonly);
R_API void r_anal_esil_stats(RAnalEsil *esil, int enable);

/* session */
R_API void r_anal_esil_session_list(RAnalEsil *esil);
R_API RAnalEsilSession *r_anal_esil_session_add(RAnalEsil *esil);
R_API void r_anal_esil_session_set(RAnalEsil *esil, RAnalEsilSession *session);
R_API void r_anal_esil_session_free(void *p);

/* pin */
R_API void r_anal_pin_init(RAnal *a);
R_API void r_anal_pin_fini(RAnal *a);
R_API void r_anal_pin (RAnal *a, ut64 addr, const char *name);
R_API void r_anal_pin_unset (RAnal *a, ut64 addr);
R_API const char *r_anal_pin_call(RAnal *a, ut64 addr);
R_API void r_anal_pin_list(RAnal *a);

/* fcn.c */
R_API ut32 r_anal_fcn_cost(RAnal *anal, RAnalFunction *fcn);
R_API bool r_anal_fcn_tree_delete(RBNode **root, RAnalFunction *data);
R_API void r_anal_fcn_tree_insert(RBNode **root, RAnalFunction *fcn);
R_API int r_anal_fcn_count_edges(RAnalFunction *fcn, int *ebbs);
R_API RAnalFunction *r_anal_fcn_new(void);
R_API int r_anal_fcn_is_in_offset (RAnalFunction *fcn, ut64 addr);
R_API bool r_anal_fcn_in(RAnalFunction *fcn, ut64 addr);
R_API RAnalFunction *r_anal_get_fcn_at(RAnal *anal, ut64 addr, int type);
R_API RAnalFunction *r_anal_get_fcn_in(RAnal *anal, ut64 addr, int type);
R_API RAnalFunction *r_anal_get_fcn_in_bounds(RAnal *anal, ut64 addr, int type);
R_API RAnalFunction *r_anal_fcn_find_name(RAnal *anal, const char *name);
R_API RList *r_anal_fcn_list_new(void);
R_API int r_anal_fcn_insert(RAnal *anal, RAnalFunction *fcn);
R_API void r_anal_fcn_free(void *fcn);
R_API void r_anal_fcn_fill_args (RAnal *anal, RAnalFunction *fcn, RAnalOp *op);
R_API int r_anal_fcn(RAnal *anal, RAnalFunction *fcn, ut64 addr,
		ut8 *buf, ut64 len, int reftype);
R_API int r_anal_fcn_add(RAnal *anal, ut64 addr, ut64 size,
		const char *name, int type, RAnalDiff *diff);
R_API int r_anal_fcn_del(RAnal *anal, ut64 addr);
R_API int r_anal_fcn_del_locs(RAnal *anal, ut64 addr);
R_API int r_anal_fcn_add_bb(RAnal *anal, RAnalFunction *fcn,
		ut64 addr, ut64 size,
		ut64 jump, ut64 fail, int type, RAnalDiff *diff);
R_API bool r_anal_check_fcn(RAnal *anal, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high);
R_API void r_anal_fcn_update_tinyrange_bbs(RAnalFunction *fcn);


/* locals */
#if 0
R_API int r_anal_fcn_local_add(RAnal *anal, RAnalFunction *fcn, int index, const char *name, const char *type);
R_API int r_anal_fcn_local_del_name(RAnal *anal, RAnalFunction *fcn, const char *name);
R_API int r_anal_fcn_local_del_index(RAnal *anal, RAnalFunction *fcn, ut32 index);
#endif

#define R_ANAL_FCN_VARKIND_LOCAL 'v'
#define R_ANAL_FCN_VARKIND_ARG 'a'
#define R_ANAL_FCN_VARKIND_FASTARG 'A'

#define r_anal_fcn_local_del_index(x,y,z) r_anal_fcn_var_del_byindex(x, y,\
R_ANAL_FCN_VARKIND_LOCAL, z)
#define r_anal_fcn_local_del_name(x,y,z) error


R_API int r_anal_fcn_var_del_bydelta (RAnal *a, ut64 fna, const char kind, int scope, ut32 delta);
R_API int r_anal_fcn_var_del_byindex (RAnal *a, ut64 fna, const char kind, int scope, ut32 idx);
/* args */
R_API int r_anal_var_count(RAnal *a, RAnalFunction *fcn, int kind, int type);

/* vars // globals. not here  */
R_API bool r_anal_var_display(RAnal *anal, int delta, char kind, const char *type);
R_API ut32 r_anal_fcn_size(const RAnalFunction *fcn);
R_API void r_anal_fcn_set_size(const RAnal *anal, RAnalFunction *fcn, ut32 size);
R_API ut32 r_anal_fcn_contsize(const RAnalFunction *fcn);
R_API ut32 r_anal_fcn_realsize(const RAnalFunction *fcn);
R_API int r_anal_fcn_cc(RAnalFunction *fcn);
R_API int r_anal_fcn_loops(RAnalFunction *fcn);
R_API int r_anal_fcn_split_bb(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb, ut64 addr);
R_API int r_anal_fcn_bb_overlaps(RAnalFunction *fcn, RAnalBlock *bb);
R_API RAnalVar *r_anal_fcn_get_var(RAnalFunction *fs, int num, int dir);
R_API void r_anal_fcn_fit_overlaps (RAnal *anal, RAnalFunction *fcn);
R_API void r_anal_trim_jmprefs(RAnal *anal, RAnalFunction *fcn);
R_API RAnalFunction *r_anal_fcn_next(RAnal *anal, ut64 addr);
R_API char *r_anal_fcn_to_string(RAnal *a, RAnalFunction* fs);
R_API int r_anal_str_to_fcn(RAnal *a, RAnalFunction *f, const char *_str);
R_API int r_anal_fcn_count (RAnal *a, ut64 from, ut64 to);
R_API RAnalBlock *r_anal_fcn_bbget(RAnalFunction *fcn, ut64 addr);
R_API bool r_anal_fcn_contains(RAnalFunction *fcn, ut64 addr);
R_API bool r_anal_fcn_bbadd(RAnalFunction *fcn, RAnalBlock *bb);
R_API int r_anal_fcn_resize (const RAnal *anal, RAnalFunction *fcn, int newsize);

typedef bool (* RAnalRefCmp)(RAnalRef *ref, void *data);
R_API RAnalRef *r_anal_ref_new(void);
R_API RList *r_anal_ref_list_new(void);
R_API void r_anal_ref_free(void *ref);
R_API int r_anal_xrefs_count(RAnal *anal);
R_API const char *r_anal_xrefs_type_tostring(RAnalRefType type);
R_API RAnalRefType r_anal_xrefs_type(char ch);
R_API RList *r_anal_xrefs_get(RAnal *anal, ut64 to);
R_API RList *r_anal_refs_get(RAnal *anal, ut64 to);
R_API RList *r_anal_xrefs_get_from(RAnal *anal, ut64 from);
R_API void r_anal_xrefs_list(RAnal *anal, int rad);
R_API RList *r_anal_fcn_get_refs(RAnal *anal, RAnalFunction *fcn);
R_API RList *r_anal_fcn_get_xrefs(RAnal *anal, RAnalFunction *fcn);
R_API RList *r_anal_fcn_get_refs_sorted(RAnal *anal, RAnalFunction *fcn);
R_API RList *r_anal_fcn_get_xrefs_sorted(RAnal *anal, RAnalFunction *fcn);
R_API int r_anal_xrefs_from(RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr);
R_API int r_anal_xrefs_set(RAnal *anal, ut64 from, ut64 to, const RAnalRefType type);
R_API int r_anal_xrefs_deln(RAnal *anal, ut64 from, ut64 to, const RAnalRefType type);
R_API int r_anal_xref_del(RAnal *anal, ut64 at, ut64 addr);

R_API RList* r_anal_fcn_get_vars (RAnalFunction *anal);
R_API RList* r_anal_fcn_get_bbs (RAnalFunction *anal);
R_API RList* r_anal_get_fcns (RAnal *anal);

/* var.c */
R_API void r_anal_var_access_clear (RAnal *a, ut64 var_addr, int scope, int index);
R_API int r_anal_var_access (RAnal *a, ut64 var_addr, char kind, int scope, int index, int xs_type, ut64 xs_addr);

R_API RAnalVar *r_anal_var_new(void);
R_API int r_anal_var_rename (RAnal *a, ut64 var_addr, int scope, char kind, const char *old_name, const char *new_name);
R_API int r_anal_var_retype (RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, const char *name);
R_API RAnalVarAccess *r_anal_var_access_new(void);
R_API RList *r_anal_var_list_new(void);
R_API RList *r_anal_var_access_list_new(void);
R_API void r_anal_var_free(RAnalVar *var);
R_API void r_anal_var_access_free(void *access);
//R_API int r_anal_var_add(RAnal *anal, RAnalFunction *fcn, ut64 from, int delta, int scope,
//		RAnalType *type, const char *name, int set);
R_API int r_anal_var_delete_all (RAnal *a, ut64 addr, const char kind);
R_API int r_anal_var_delete (RAnal *a, ut64 var_addr, const char kind, int scope, int delta);
R_API bool r_anal_var_delete_byname (RAnal *a, RAnalFunction *fcn, int type, const char *name);
R_API bool r_anal_var_add (RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, const char *name);
R_API int r_anal_var_del(RAnal *anal, RAnalFunction *fcn, int delta, int scope);
R_API RAnalVar *r_anal_var_get (RAnal *a, ut64 addr, char kind, int scope, int index);
R_API const char *r_anal_var_scope_to_str(RAnal *anal, int scope);
R_API int r_anal_var_access_add(RAnal *anal, RAnalVar *var, ut64 from, int set);
R_API int r_anal_var_access_del(RAnal *anal, RAnalVar *var, ut64 from);
R_API RAnalVarAccess *r_anal_var_access_get(RAnal *anal, RAnalVar *var, ut64 from);
R_API RAnalVar *r_anal_var_get_byname (RAnal *anal, RAnalFunction *fcn, const char* name);

/* project */
R_API bool r_anal_xrefs_init (RAnal *anal);

#define R_ANAL_THRESHOLDFCN 0.7F
#define R_ANAL_THRESHOLDBB 0.7F

/* diff.c */
R_API RAnalDiff *r_anal_diff_new(void);
R_API void r_anal_diff_setup(RAnal *anal, int doops, double thbb, double thfcn);
R_API void r_anal_diff_setup_i(RAnal *anal, int doops, int thbb, int thfcn);
R_API void* r_anal_diff_free(RAnalDiff *diff);
R_API int r_anal_diff_fingerprint_bb(RAnal *anal, RAnalBlock *bb);
R_API int r_anal_diff_fingerprint_fcn(RAnal *anal, RAnalFunction *fcn);
R_API bool r_anal_diff_bb(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2);
R_API int r_anal_diff_fcn(RAnal *anal, RList *fcns, RList *fcns2);
R_API int r_anal_diff_eval(RAnal *anal);

/* value.c */
R_API RAnalValue *r_anal_value_new(void);
R_API RAnalValue *r_anal_value_copy (RAnalValue *ov);
R_API RAnalValue *r_anal_value_new_from_string(const char *str);
R_API st64 r_anal_value_eval(RAnalValue *value);
R_API char *r_anal_value_to_string (RAnalValue *value);
R_API ut64 r_anal_value_to_ut64(RAnal *anal, RAnalValue *val);
R_API int r_anal_value_set_ut64(RAnal *anal, RAnalValue *val, ut64 num);
R_API void r_anal_value_free(RAnalValue *value);

R_API RAnalCond *r_anal_cond_new(void);
R_API RAnalCond *r_anal_cond_new_from_op(RAnalOp *op);
R_API void r_anal_cond_fini (RAnalCond *c);
R_API void r_anal_cond_free (RAnalCond *c);
R_API char *r_anal_cond_to_string(RAnalCond *cond);
R_API int r_anal_cond_eval (RAnal *anal, RAnalCond *cond);
R_API RAnalCond *r_anal_cond_new_from_string(const char *str);
R_API const char *r_anal_cond_tostring(int cc);

/* reflines.c */
R_API RList* /*<RAnalRefline>*/ r_anal_reflines_get(RAnal *anal,
		ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall);
R_API int r_anal_reflines_middle(RAnal *anal, RList *list, ut64 addr, int len);
R_API char* r_anal_reflines_str(void *core, ut64 addr, int opts);
R_API RList *r_anal_reflines_fcn_get(struct r_anal_t *anal, RAnalFunction *fcn, int nlines, int linesout, int linescall);
/* TODO move to r_core */
R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, int kind, int mode);
R_API RList *r_anal_var_list(RAnal *anal, RAnalFunction *fcn, int kind);
R_API RList *r_anal_var_all_list(RAnal *anal, RAnalFunction *fcn);
R_API RList *r_anal_var_list_dynamic(RAnal *anal, RAnalFunction *fcn, int kind);

// calling conventions API
R_API int r_anal_cc_exist (RAnal *anal, const char *convention);
R_API const char *r_anal_cc_arg(RAnal *anal, const char *convention, int n);
R_API const char *r_anal_cc_ret(RAnal *anal, const char *convention);
R_API const char *r_anal_cc_default(RAnal *anal);
R_API const char *r_anal_cc_to_constant(RAnal *anal, char *convention);
R_API bool r_anal_noreturn_at(RAnal *anal, ut64 addr);

typedef struct r_anal_data_t {
	ut64 addr;
	int type;
	ut64 ptr;
	char *str;
	int len;
	ut8 *buf;
	ut8 sbuf[8];
} RAnalData;

R_API RAnalData *r_anal_data (RAnal *anal, ut64 addr, const ut8 *buf, int size, int wordsize);
R_API const char *r_anal_data_kind (RAnal *anal, ut64 addr, const ut8 *buf, int len);
R_API RAnalData *r_anal_data_new_string (ut64 addr, const char *p, int size, int wide);
R_API RAnalData *r_anal_data_new (ut64 addr, int type, ut64 n, const ut8 *buf, int len);
R_API void r_anal_data_free (RAnalData *d);
#include <r_cons.h>
R_API char *r_anal_data_to_string(RAnalData *d, RConsPrintablePalette *pal);

R_API void r_meta_free(RAnal *m);
R_API void r_meta_space_unset_for(RAnal *a, int type);
R_API int r_meta_space_count_for(RAnal *a, int space_idx);
R_API RList *r_meta_enumerate(RAnal *a, int type);
R_API int r_meta_count(RAnal *m, int type, ut64 from, ut64 to);
R_API char *r_meta_get_string(RAnal *m, int type, ut64 addr);
R_API char *r_meta_get_var_comment (RAnal *a, int type, ut64 idx, ut64 addr);
R_API int r_meta_set_string(RAnal *m, int type, ut64 addr, const char *s);
R_API int r_meta_set_var_comment (RAnal *a, int type, ut64 idx, ut64 addr, const char *s);
R_API int r_meta_del(RAnal *m, int type, ut64 from, ut64 size);
R_API int r_meta_var_comment_del(RAnal *a, int type, ut64 idx, ut64 addr);
R_API int r_meta_add(RAnal *m, int type, ut64 from, ut64 size, const char *str);
R_API int r_meta_add_with_subtype(RAnal *m, int type, int subtype, ut64 from, ut64 size, const char *str);
R_API RAnalMetaItem *r_meta_find(RAnal *m, ut64 off, int type, int where);
R_API RAnalMetaItem *r_meta_find_in(RAnal *m, ut64 off, int type, int where);
R_API int r_meta_cleanup(RAnal *m, ut64 from, ut64 to);
R_API const char *r_meta_type_to_string(int type);
R_API RList *r_meta_enumerate(RAnal *a, int type);
R_API int r_meta_list(RAnal *m, int type, int rad);
R_API int r_meta_list_at(RAnal *m, int type, int rad, ut64 addr);
R_API int r_meta_list_cb(RAnal *m, int type, int rad, SdbForeachCallback cb, void *user, ut64 addr);
R_API void r_meta_item_free(void *_item);
R_API RAnalMetaItem *r_meta_item_new(int type);
R_API bool r_meta_deserialize_val(RAnalMetaItem *it, int type, ut64 from, const char *v);
R_API void r_meta_print(RAnal *a, RAnalMetaItem *d, int rad, bool show_full);

/* hints */

R_API void r_anal_build_range_on_hints (RAnal *a);
//R_API void r_anal_hint_list (RAnal *anal, int mode);
R_API RAnalHint *r_anal_hint_from_string(RAnal *a, ut64 addr, const char *str);
R_API void r_anal_hint_del (RAnal *anal, ut64 addr, int size);
R_API void r_anal_hint_clear (RAnal *a);
R_API RAnalHint *r_anal_hint_at (RAnal *a, ut64 from);
R_API RAnalHint *r_anal_hint_add (RAnal *a, ut64 from, int size);
R_API void r_anal_hint_free (RAnalHint *h);
R_API RAnalHint *r_anal_hint_get(RAnal *anal, ut64 addr);
R_API void r_anal_hint_set_syntax (RAnal *a, ut64 addr, const char *syn);
R_API void r_anal_hint_set_jump (RAnal *a, ut64 addr, ut64 ptr);
R_API void r_anal_hint_set_offset (RAnal *a, ut64 addr, const char *typeoff);
R_API void r_anal_hint_set_immbase (RAnal *a, ut64 addr, int base);
R_API void r_anal_hint_set_fail (RAnal *a, ut64 addr, ut64 ptr);
R_API void r_anal_hint_set_length (RAnal *a, ut64 addr, int length);
R_API void r_anal_hint_set_bits (RAnal *a, ut64 addr, int bits);
R_API void r_anal_hint_set_arch (RAnal *a, ut64 addr, const char *arch);
R_API void r_anal_hint_set_size (RAnal *a, ut64 addr, int length);
R_API void r_anal_hint_set_opcode (RAnal *a, ut64 addr, const char *str);
R_API void r_anal_hint_set_esil (RAnal *a, ut64 addr, const char *str);
R_API void r_anal_hint_set_pointer (RAnal *a, ut64 addr, ut64 jump);
R_API void r_anal_hint_set_high(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_high(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_size(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_bits(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_esil(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_opcode(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_arch(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_syntax(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_pointer(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_offset(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_jump(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_fail(RAnal *a, ut64 addr);
R_API int r_anal_esil_eval(RAnal *anal, const char *str);

/* switch.c APIs */
R_API RAnalSwitchOp * r_anal_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val);
R_API void r_anal_switch_op_free(RAnalSwitchOp * swop);
R_API RAnalCaseOp* r_anal_switch_op_add_case(RAnalSwitchOp * swop, ut64 addr, ut64 value, ut64 jump);

/* cycles.c */
R_API RAnalCycleFrame* r_anal_cycle_frame_new (void);
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
R_API bool r_anal_state_addr_is_valid (RAnalState *state, ut64 addr);
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

/* ESIL to REIL */
R_API int r_anal_esil_to_reil_setup (RAnalEsil *esil, RAnal *anal, int romem, int stats);

/* no-return stuff */
R_API void r_anal_noreturn_list(RAnal *anal, int mode);
R_API bool r_anal_noreturn_add(RAnal *anal, const char *name, ut64 addr);
R_API int r_anal_noreturn_drop(RAnal *anal, const char *expr);
R_API bool r_anal_noreturn_at_addr(RAnal *anal, ut64 addr);

/* zign spaces */
R_API int r_sign_space_count_for(RAnal *a, int idx);
R_API void r_sign_space_unset_for(RAnal *a, int idx);
R_API void r_sign_space_rename_for(RAnal *a, int idx, const char *oname, const char *nname);

/* vtables */
typedef struct {
	RAnal *anal;
	RAnalCPPABI abi;
	ut8 word_size;
	bool (*read_addr) (RAnal *anal, ut64 addr, ut64 *buf);
} RVTableContext;

typedef struct vtable_info_t {
	ut64 saddr; //starting address
	int method_count;
	RList* methods;
} RVTableInfo;

typedef struct vtable_method_info_t {
	ut64 addr;           // addr of the function
	ut64 vtable_offset;  // offset inside the vtable
} RVTableMethodInfo;

R_API void r_anal_vtable_info_fini(RVTableInfo *vtable);
R_API ut64 r_anal_vtable_info_get_size(RVTableContext *context, RVTableInfo *vtable);
R_API bool r_anal_vtable_begin(RAnal *anal, RVTableContext *context);
R_API RList *r_anal_vtable_search(RVTableContext *context);
R_API RList *r_anal_vtable_get_methods(RVTableContext *context, RVTableInfo *table);
R_API void r_anal_list_vtables(RAnal *anal, int rad);

/* rtti */
R_API void r_anal_rtti_msvc_print_complete_object_locator(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_msvc_print_type_descriptor(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_msvc_print_class_hierarchy_descriptor(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_msvc_print_base_class_descriptor(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_msvc_print_at_vtable(RVTableContext *context, ut64 addr, int mode);

R_API void r_anal_rtti_itanium_print_class_type_info(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_itanium_print_si_class_type_info(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_itanium_print_vmi_class_type_info(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_itanium_print_at_vtable(RVTableContext *context, ut64 addr, int mode);

R_API void r_anal_rtti_print_at_vtable(RAnal *anal, ut64 addr, int mode);
R_API void r_anal_rtti_print_all(RAnal *anal, int mode);

/* plugin pointers */
extern RAnalPlugin r_anal_plugin_null;
extern RAnalPlugin r_anal_plugin_xap;
extern RAnalPlugin r_anal_plugin_tms320;
extern RAnalPlugin r_anal_plugin_tms320c64x;
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
extern RAnalPlugin r_anal_plugin_m68k_cs;
extern RAnalPlugin r_anal_plugin_z80;
extern RAnalPlugin r_anal_plugin_i8080;
extern RAnalPlugin r_anal_plugin_8051;
extern RAnalPlugin r_anal_plugin_arc;
extern RAnalPlugin r_anal_plugin_ebc;
extern RAnalPlugin r_anal_plugin_gb;
extern RAnalPlugin r_anal_plugin_nios2;
extern RAnalPlugin r_anal_plugin_malbolge;
extern RAnalPlugin r_anal_plugin_hexagon;
extern RAnalPlugin r_anal_plugin_wasm;
extern RAnalPlugin r_anal_plugin_ws;
extern RAnalPlugin r_anal_plugin_h8300;
extern RAnalPlugin r_anal_plugin_cr16;
extern RAnalPlugin r_anal_plugin_v850;
extern RAnalPlugin r_anal_plugin_sysz;
extern RAnalPlugin r_anal_plugin_sparc_cs;
extern RAnalPlugin r_anal_plugin_xcore_cs;
extern RAnalPlugin r_anal_plugin_propeller;
extern RAnalPlugin r_anal_plugin_msp430;
extern RAnalPlugin r_anal_plugin_chip8;
extern RAnalPlugin r_anal_plugin_cris;
extern RAnalPlugin r_anal_plugin_v810;
extern RAnalPlugin r_anal_plugin_6502;
extern RAnalPlugin r_anal_plugin_snes;
extern RAnalPlugin r_anal_plugin_riscv;
extern RAnalPlugin r_anal_plugin_vax;
extern RAnalPlugin r_anal_plugin_i4004;
extern RAnalPlugin r_anal_plugin_xtensa;
extern RAnalPlugin r_anal_plugin_pic;
extern RAnalPlugin r_anal_plugin_rsp;
#ifdef __cplusplus
}
#endif

#endif
#endif

/* radare - LGPL - Copyright 2009-2013 - nibble, pancake, xvilka */

#ifndef _INCLUDE_R_ANAL_H_
#define _INCLUDE_R_ANAL_H_

#include <r_types.h>
#include <list.h>
#include <r_db.h>
#include <r_io.h>
#include <r_reg.h>
#include <r_list.h>
#include <r_util.h>
#include <r_syscall.h>

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
typedef struct r_meta_item_t {
	ut64 from;
	ut64 to;
	ut64 size;
	int type;
	char *str;
} RMetaItem;

typedef struct r_meta_t {
	RList *data; // TODO: rename to 'list'
	PrintfCallback printf;
} RMeta;

/* CPARSE stuff */

#define R_ANAL_UNMASK_TYPE(x) (x&R_ANAL_VAR_TYPE_SIZE_MASK)
#define R_ANAL_UNMASK_SIGN(x) (((x& R_ANAL_VAR_TYPE_SIGN_MASK)>> R_ANAL_VAR_TYPE_SIGN_SHIFT)==R_ANAL_VAR_TYPE_UNSIGNED)?0:1

enum {
	R_ANAL_TYPE_VARIABLE = 1,
	R_ANAL_TYPE_POINTER = 2,
	R_ANAL_TYPE_ARRAY = 3,
	R_ANAL_TYPE_STRUCT = 4,
	R_ANAL_TYPE_UNION = 5,
	R_ANAL_TYPE_ALLOCA = 6,
	R_ANAL_TYPE_FUNCTION = 7,
	R_ANAL_TYPE_ANY = 8,
};

// [0:3] bits - place to store variable size
#define R_ANAL_VAR_TYPE_SIZE_MASK 0xF

enum {
	R_ANAL_VAR_TYPE_CHAR = 1,
	R_ANAL_VAR_TYPE_BYTE = 2,
	R_ANAL_VAR_TYPE_WORD = 3,
	R_ANAL_VAR_TYPE_DWORD = 4,
	R_ANAL_VAR_TYPE_QWORD = 5,
	R_ANAL_VAR_TYPE_SHORT = 6,
	R_ANAL_VAR_TYPE_INT = 7,
	R_ANAL_VAR_TYPE_LONG = 8,
	R_ANAL_VAR_TYPE_LONGLONG = 9,
	R_ANAL_VAR_TYPE_FLOAT = 10,
	R_ANAL_VAR_TYPE_DOUBLE = 11,
	R_ANAL_VAR_TYPE_VOID = 12,
};

enum {
	R_ANAL_DATA_TYPE_NULL = 0,
	R_ANAL_DATA_TYPE_STRING = 1,
	R_ANAL_DATA_TYPE_WIDE_STRING = 2,
	R_ANAL_DATA_TYPE_POINTER = 3,
	R_ANAL_DATA_TYPE_NUMBER = 4,
	R_ANAL_DATA_TYPE_INVALID = 5,
	R_ANAL_DATA_TYPE_HEADER = 6,
	R_ANAL_DATA_TYPE_UNKNOWN = 7,
};

// [4:7] bits - place to store sign of variable
#define R_ANAL_VAR_TYPE_SIGN_MASK 0xF0
#define R_ANAL_VAR_TYPE_SIGN_SHIFT 4

enum {
	R_ANAL_VAR_TYPE_SIGNED = 1,
	R_ANAL_VAR_TYPE_UNSIGNED = 2,
};

// [8:11] bits - place to store variable modifiers/parameters
#define R_ANAL_VAR_TYPE_MODIFIER_MASK 0xF00
#define R_ANAL_VAR_TYPE_MODIFIER_SHIFT 8

enum {
	R_ANAL_VAR_TYPE_REGISTER = 1,
	R_ANAL_VAR_TYPE_CONST = 2,
	R_ANAL_VAR_TYPE_STATIC = 3,
	R_ANAL_VAR_TYPE_VOLATILE = 4,
};

/* type = (R_ANAL_VAR_TYPE_BYTE & R_ANAL_VAR_TYPE_SIZE_MASK) |
 *			( RANAL_VAR_TYPE_SIGNED & RANAL_VAR_TYPE_SIGN_MASK) |
 *			( RANAL_VAR_TYPE_CONST & RANAL_VAR_TYPE_MODIFIER_MASK)
 */
typedef struct r_anal_type_var_t {
	char *name;
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
	int bits;
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

/*
typedef struct r_anal_fcn_t {
	char *name;
	ut64 addr;
	ut64 size;
	int type;
	int calltype; // See R_ANAL_CC_TYPE_
	int stack;
	int ninstr;
	int nargs;
	int depth;
	RAnalVarSub varsubs[R_ANAL_VARSUBS];
	ut8 *fingerprint;
	RAnalDiff *diff;
	RList *bbs;
	RList *vars;
	RList *refs;
	RList *xrefs;
} RAnalFcn;
*/

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
	ut64 addr;
	char* name;
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
	int size; // Size of function XXX. use int, or ut32. no need for ut64
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
	RAnalVarSub varsubs[R_ANAL_VARSUBS];
	ut8 *fingerprint; // TODO: make is fuzzy and smarter
	RAnalDiff *diff;
	RList *locs; // list of local variables
	RList *locals; // list of local labels
	RList *bbs;
	RList *vars;
	RList *refs;
	RList *xrefs;
} RAnalFunction;

struct r_anal_type_t {
	char *name;
	ut32 size;
	int type;
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
	R_ANAL_OP_FAMILY_CPU,  /* normal cpu insturction */
	R_ANAL_OP_FAMILY_FPU,  /* fpu (floating point) */
	R_ANAL_OP_FAMILY_MMX,  /* multimedia instruction (packed data) */
	R_ANAL_OP_FAMILY_PRIV, /* priviledged instruction */
	R_ANAL_OP_FAMILY_LAST
};

// XXX: this definition is plain wrong. use enum or empower bits
enum {
	R_ANAL_OP_TYPE_COND  = 0x80000000,
	R_ANAL_OP_TYPE_REP   = 0x40000000, /* repeats next instruction N times */
	R_ANAL_OP_TYPE_NULL  = 0,
	R_ANAL_OP_TYPE_JMP   = 1,  /* mandatory jump */
	R_ANAL_OP_TYPE_UJMP  = 2,  /* unknown jump (register or so) */
	R_ANAL_OP_TYPE_CJMP  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_JMP,  /* conditional jump */
	R_ANAL_OP_TYPE_CALL  = 3,  /* call to subroutine (branch+link) */
	R_ANAL_OP_TYPE_UCALL = 4, /* unknown call (register or so) */
	R_ANAL_OP_TYPE_RET   = 5, /* returns from subrutine */
	R_ANAL_OP_TYPE_CRET  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET, /* returns from subrutine */
	R_ANAL_OP_TYPE_ILL   = 6,  /* illegal instruction // trap */
	R_ANAL_OP_TYPE_UNK   = 7, /* unknown opcode type */
	R_ANAL_OP_TYPE_NOP   = 8, /* does nothing */
	R_ANAL_OP_TYPE_MOV   = 9, /* register move */
	R_ANAL_OP_TYPE_TRAP  = 10, /* it's a trap! */
	R_ANAL_OP_TYPE_SWI   = 11,  /* syscall, software interrupt */
	R_ANAL_OP_TYPE_UPUSH = 12, /* unknown push of data into stack */
	R_ANAL_OP_TYPE_PUSH  = 13,  /* push value into stack */
	R_ANAL_OP_TYPE_POP   = 14,   /* pop value from stack to register */
	R_ANAL_OP_TYPE_CMP   = 15,  /* copmpare something */
	R_ANAL_OP_TYPE_ADD   = 16,
	R_ANAL_OP_TYPE_SUB   = 17,
	R_ANAL_OP_TYPE_IO    = 18,
	R_ANAL_OP_TYPE_MUL   = 19,
	R_ANAL_OP_TYPE_DIV   = 20,
	R_ANAL_OP_TYPE_SHR   = 21,
	R_ANAL_OP_TYPE_SHL   = 22,
	R_ANAL_OP_TYPE_OR    = 23,
	R_ANAL_OP_TYPE_AND   = 24,
	R_ANAL_OP_TYPE_XOR   = 25,
	R_ANAL_OP_TYPE_NOT   = 26,
	R_ANAL_OP_TYPE_STORE = 27,  /* store from register to memory */
	R_ANAL_OP_TYPE_LOAD  = 28,  /* load from memory to register */
	R_ANAL_OP_TYPE_LEA   = 29,
	R_ANAL_OP_TYPE_LEAVE = 30,
	R_ANAL_OP_TYPE_ROR   = 31,
	R_ANAL_OP_TYPE_ROL   = 32,
};

/* TODO: what to do with signed/unsigned conditionals? */
enum {
	R_ANAL_COND_EQ = 0,
	R_ANAL_COND_NE,
	R_ANAL_COND_GE,
	R_ANAL_COND_GT,
	R_ANAL_COND_LE,
	R_ANAL_COND_LT,
	R_ANAL_COND_AL,
	R_ANAL_COND_NV,
};

enum {
	R_ANAL_VAR_SCOPE_NULL   = 0,
	R_ANAL_VAR_SCOPE_GLOBAL = 0x01,
	R_ANAL_VAR_SCOPE_LOCAL  = 0x02,
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
	R_ANAL_BB_TYPE_SWITCH = 0x10   /* TODO: switch */
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

typedef struct r_anal_t {
	int bits;
	int lineswidth; // wtf
	int big_endian;
	int split; // used only from core
	void *user;
	RList *fcns;
	RListRange *fcnstore;
	RList *refs;
	RList *vartypes;
	RMeta *meta;
	RReg *reg;
	RSyscall *syscall;
	struct r_anal_op_t *queued;
	int diff_ops;
	double diff_thbb;
	double diff_thfcn;
	RIOBind iob;
	int decode;
	RList *types;
	//struct r_anal_ctx_t *ctx;
	struct r_anal_plugin_t *cur;
	struct list_head anals; // TODO: Reimplement with RList
	RList *hints; // XXX use better data structure here (slist?)
	Sdb *sdb_xrefs;
	Sdb *sdb_types;
	PrintfCallback printf;
} RAnal;

typedef struct r_anal_hint_t {
	ut64 from;
	ut64 to;
	ut64 ptr;
	char *arch;
	char *opcode;
	char *analstr;
	ut64 jump;
	ut64 fail;
	int length;
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
	int stackop;    /* operation on stack? */
	int cond;       /* condition type */
	int length;     /* length in bytes of opcode */
	int nopcode;    /* number of bytes representing the opcode (not the arguments) */
	int family;     /* family of opcode */
	int eob;        /* end of block (boolean) */
	/* Run N instructions before executing the current one */
	int delay;      /* delay N slots (mips, ..)*/
	ut64 jump;      /* true jmp */
	ut64 fail;      /* false jmp */
	ut32 selector;  /* segment selector */
#if 0
ref->ptr
value->val
#endif
	st64 ptr;       /* reference to memory */ /* XXX signed? */
	ut64 val;     /* reference to value */ /* XXX signed? */
	st64 stackptr;  /* stack pointer */
	int refptr;
	char esil[64];
	RAnalValue *src[3];
	RAnalValue *dst;
	struct r_anal_op_t *next; // XXX deprecate
} RAnalOp;

#define R_ANAL_COND_SINGLE(x) (!x->arg[1] || x->arg[0]==x->arg[1])

typedef struct r_anal_cond_t {
	int type; // filled by CJMP opcode
	RAnalValue *arg[2]; // filled by CMP opcode
} RAnalCond;

typedef struct r_anal_bb_t {
	ut64 addr;
	ut64 size;
	ut64 jump;
	ut64 fail;
	int type;
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
} RAnalBlock;

typedef struct r_anal_var_access_t {
	ut64 addr;
	int set;
} RAnalVarAccess;

typedef struct r_anal_var_t {
	char *name;		/* name of the variable */
	char *type;
	ut64 addr;		// not used correctly?
	ut64 eaddr;		// not used correctly?
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
	R_ANAL_REF_TYPE_DATA = 'd'  // mem ref
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

typedef int (*RAnalOpCallback)(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len);
typedef int (*RAnalRegProfCallback)(RAnal *a);
typedef int (*RAnalFPBBCallback)(RAnal *a, RAnalBlock *bb);
typedef int (*RAnalFPFcnCallback)(RAnal *a, RAnalFunction *fcn);
typedef int (*RAnalDiffBBCallback)(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2);
typedef int (*RAnalDiffFcnCallback)(RAnal *anal, RList *fcns, RList *fcns2);
typedef int (*RAnalDiffEvalCallback)(RAnal *anal);

typedef struct r_anal_plugin_t {
	char *name;
	char *desc;
	int arch;
	int bits;
	int (*init)(void *user);
	int (*fini)(void *user);
	RAnalOpCallback op;
	RAnalRegProfCallback set_reg_profile;
	RAnalFPBBCallback fingerprint_bb;
	RAnalFPFcnCallback fingerprint_fcn;
	RAnalDiffBBCallback diff_bb;
	RAnalDiffFcnCallback diff_fcn;
	RAnalDiffEvalCallback diff_eval;
	struct list_head list;
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
R_API RAnalType *r_anal_type_free(RAnalType *t);
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path);
R_API void r_anal_type_define (RAnal *anal, const char *key, const char *value);
R_API void r_anal_type_header (RAnal *anal, const char *hdr);

R_API int r_anal_type_link (RAnal *anal, const char *val, ut64 addr);
R_API char *r_anal_type_format (RAnal *anal, const char *t);
R_API int r_anal_type_set(RAnal *anal, ut64 at, const char *field, ut64 val);

/* anal.c */
R_API RAnal *r_anal_new();
R_API void r_anal_free(RAnal *r);
R_API void r_anal_set_user_ptr(RAnal *anal, void *user);
R_API int r_anal_add(RAnal *anal, struct r_anal_plugin_t *foo);
R_API int r_anal_list(RAnal *anal);
R_API int r_anal_use(RAnal *anal, const char *name);
R_API int r_anal_set_reg_profile(RAnal *anal);
R_API int r_anal_set_bits(RAnal *anal, int bits);
R_API int r_anal_set_big_endian(RAnal *anal, int boolean);
R_API char *r_anal_strmask (RAnal *anal, const char *data);
R_API void r_anal_trace_bb(RAnal *anal, ut64 addr);
R_API RAnalFunction *r_anal_get_fcn_at(RAnal *anal, ut64 addr);

/* bb.c */
R_API RAnalBlock *r_anal_bb_new();
R_API RList *r_anal_bb_list_new();
R_API void r_anal_bb_free(RAnalBlock *bb);
R_API int r_anal_bb(RAnal *anal, RAnalBlock *bb,
		ut64 addr, ut8 *buf, ut64 len, int head);
R_API RAnalBlock *r_anal_bb_from_offset(RAnal *anal, ut64 off);
R_API int r_anal_bb_is_in_offset (RAnalBlock *bb, ut64 addr);

/* op.c */
R_API RAnalOp *r_anal_op_new();
R_API void r_anal_op_free(void *op);
R_API void r_anal_op_fini(RAnalOp *op);
R_API RList *r_anal_op_list_new();
R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr,
		const ut8 *data, int len);
R_API RAnalOp *r_anal_op_hexstr(RAnal *anal, ut64 addr,
		const char *hexstr);
R_API char *r_anal_op_to_string(RAnal *anal, RAnalOp *op);
R_API const char *r_anal_op_to_esil_string(RAnal *anal, RAnalOp *op);

/* fcn.c */
R_API RAnalFunction *r_anal_fcn_new();
R_API int r_anal_fcn_is_in_offset (RAnalFunction *fcn, ut64 addr);
R_API RAnalFunction *r_anal_fcn_find(RAnal *anal, ut64 addr, int type);
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
R_API int r_anal_fcn_local_add(RAnal *anal, RAnalFunction *fcn, ut64 addr, const char *name);
R_API int r_anal_fcn_local_del_name(RAnal *anal, RAnalFunction *fcn, const char *name);
R_API int r_anal_fcn_local_del_addr(RAnal *anal, RAnalFunction *fcn, ut64 addr);
R_API int r_anal_fcn_cc(RAnalFunction *fcn);
R_API int r_anal_fcn_split_bb(RAnalFunction *fcn, RAnalBlock *bb, ut64 addr);
R_API int r_anal_fcn_overlap_bb(RAnalFunction *fcn, RAnalBlock *bb);
R_API RAnalVar *r_anal_fcn_get_var(RAnalFunction *fs, int num, int dir);
R_API char *r_anal_fcn_to_string(RAnal *a, RAnalFunction* fs);
R_API int r_anal_str_to_fcn(RAnal *a, RAnalFunction *f, const char *_str);
R_API int r_anal_fcn_count (RAnal *a, ut64 from, ut64 to);

#if 0
#define r_anal_fcn_get_refs(x) x->refs
#define r_anal_fcn_get_xrefs(x) x->xrefs
#define r_anal_fcn_get_vars(x) x->vars
#define r_anal_fcn_get_bbs(x) x->bbs
#else
R_API void r_anal_xrefs_list(RAnal *anal, int rad);
R_API RList* r_anal_fcn_get_refs (RAnalFunction *anal);
R_API RList* r_anal_fcn_get_xrefs (RAnalFunction *anal);
R_API RList *r_anal_xrefs_set (RAnal *anal, const char *type, ut64 from, ut64 to);
R_API RList *r_anal_xrefs_deln (RAnal *anal, const char *type, ut64 from, ut64 to);
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
R_API RAnalVar *r_anal_var_new();
R_API RAnalVarAccess *r_anal_var_access_new();
R_API RList *r_anal_var_list_new();
R_API RList *r_anal_var_access_list_new();
R_API void r_anal_var_free(void *var);
R_API void r_anal_var_access_free(void *access);
R_API int r_anal_var_add(RAnal *anal, RAnalFunction *fcn, ut64 from, int delta, int scope,
		RAnalType *type, const char *name, int set);
R_API int r_anal_var_del(RAnal *anal, RAnalFunction *fcn, int delta, int scope);
R_API RAnalVar *r_anal_var_get(RAnal *anal, RAnalFunction *fcn, int delta, int type);
R_API const char *r_anal_var_scope_to_str(RAnal *anal, int scope);
R_API int r_anal_var_access_add(RAnal *anal, RAnalVar *var, ut64 from, int set);
R_API int r_anal_var_access_del(RAnal *anal, RAnalVar *var, ut64 from);
R_API RAnalVarAccess *r_anal_var_access_get(RAnal *anal, RAnalVar *var, ut64 from);

/* project */
R_API int r_anal_project_load(RAnal *anal, const char *prjfile);
R_API int r_anal_project_save(RAnal *anal, const char *prjfile);
R_API void r_anal_xrefs_load(RAnal *anal, const char *prjfile);
R_API void r_anal_xrefs_init (RAnal *anal);

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
	ut64 addr, ut8 *buf, ut64 len, int nlines, int linesout, int linescall);
R_API int r_anal_reflines_middle(RAnal *anal, RAnalRefline *list, ut64 addr, int len);
R_API char* r_anal_reflines_str(void *core, ut64 addr, int opts);

/* TODO move to r_core */
R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, ut64 addr);
R_API void r_anal_var_list(RAnal *anal, RAnalFunction *fcn, ut64 addr, int delta);

// calling conventions API
R_API RAnalCC* r_anal_cc_new ();
R_API void r_anal_cc_init (RAnalCC *cc);
R_API RAnalCC* r_anal_cc_new_from_string (const char *str, int type);
R_API void r_anal_cc_free (RAnalCC* cc);
R_API void r_anal_cc_reset (RAnalCC *cc);
R_API char *r_anal_cc_to_string (RAnal *anal, RAnalCC* cc);
R_API boolt r_anal_cc_update (RAnal *anal, RAnalCC *cc, RAnalOp *op);
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

R_API RMeta *r_meta_new();
R_API void r_meta_free(RMeta *m);
R_API int r_meta_count(RMeta *m, int type, ut64 from, ut64 to);
R_API char *r_meta_get_string(RMeta *m, int type, ut64 addr);
R_API int r_meta_set_string(RMeta *m, int type, ut64 addr, const char *s);
R_API int r_meta_del(RMeta *m, int type, ut64 from, ut64 size, const char *str);
R_API int r_meta_add(RMeta *m, int type, ut64 from, ut64 size, const char *str);
R_API RMetaItem *r_meta_find(RMeta *m, ut64 off, int type, int where);
R_API int r_meta_cleanup(RMeta *m, ut64 from, ut64 to);
R_API const char *r_meta_type_to_string(int type);
R_API int r_meta_list(RMeta *m, int type, int rad);
R_API void r_meta_item_free(void *_item);
R_API RMetaItem *r_meta_item_new(int type);

R_API int r_anal_fcn_xref_add (RAnal *anal, RAnalFunction *fcn, ut64 at, ut64 addr, int type);
R_API int r_anal_fcn_xref_del (RAnal *anal, RAnalFunction *fcn, ut64 at, ut64 addr, int type);

/* hints */
//R_API void r_anal_hint_list (RAnal *anal, int mode);
R_API void r_anal_hint_del (RAnal *anal, ut64 addr, int size);
R_API void r_anal_hint_clear (RAnal *a);
R_API RAnalHint *r_anal_hint_at (RAnal *a, ut64 from, int size);
R_API RAnalHint *r_anal_hint_add (RAnal *a, ut64 from, int size);
R_API void r_anal_hint_free (RAnalHint *h);
R_API RAnalHint *r_anal_hint_get(RAnal *anal, ut64 addr);
R_API void r_anal_hint_set_jump (RAnal *a, ut64 addr, ut64 ptr);
R_API void r_anal_hint_set_fail (RAnal *a, ut64 addr, ut64 ptr);
R_API void r_anal_hint_set_bits (RAnal *a, ut64 addr, int size, int bits);
R_API void r_anal_hint_set_arch (RAnal *a, ut64 addr, int size, const char *arch);
R_API void r_anal_hint_set_length (RAnal *a, ut64 addr, int size, int length);
R_API void r_anal_hint_set_opcode (RAnal *a, ut64 addr, int size, const char *str);
R_API void r_anal_hint_set_analstr (RAnal *a, ut64 addr, int size, const char *str);
R_API void r_anal_hint_set_pointer (RAnal *a, ut64 addr, ut64 jump);

R_API int r_anal_esil_eval(RAnal *anal, const char *str);

/* plugin pointers */
extern RAnalPlugin r_anal_plugin_csr;
extern RAnalPlugin r_anal_plugin_c55plus;
extern RAnalPlugin r_anal_plugin_avr;
extern RAnalPlugin r_anal_plugin_arm;
extern RAnalPlugin r_anal_plugin_x86;
extern RAnalPlugin r_anal_plugin_x86_im;
extern RAnalPlugin r_anal_plugin_x86_udis;
extern RAnalPlugin r_anal_plugin_x86_simple;
extern RAnalPlugin r_anal_plugin_ppc;
extern RAnalPlugin r_anal_plugin_java;
extern RAnalPlugin r_anal_plugin_mips;
extern RAnalPlugin r_anal_plugin_dalvik;
extern RAnalPlugin r_anal_plugin_sh;
extern RAnalPlugin r_anal_plugin_sparc;
extern RAnalPlugin r_anal_plugin_bf;
extern RAnalPlugin r_anal_plugin_m68k;
extern RAnalPlugin r_anal_plugin_z80;
extern RAnalPlugin r_anal_plugin_i8080;
extern RAnalPlugin r_anal_plugin_8051;
extern RAnalPlugin r_anal_plugin_arc;

#ifdef __cplusplus
}
#endif

#endif
#endif

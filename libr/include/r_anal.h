/* radare - LGPL - Copyright 2009-2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#ifndef _INCLUDE_R_ANAL_H_
#define _INCLUDE_R_ANAL_H_

#include <r_types.h>
#include <list.h>
#include <r_list.h>
#include <r_util.h>

// deprecate this macro?
#define R_ANAL_MAXREG 16

enum {
	R_ANAL_OP_FAMILY_UNKNOWN = 0,
	R_ANAL_OP_FAMILY_CPU,  /* normal cpu insturction */
	R_ANAL_OP_FAMILY_FPU,  /* fpu (floating point) */
	R_ANAL_OP_FAMILY_MMX,  /* multimedia instruction (packed data) */
	R_ANAL_OP_FAMILY_PRIV, /* priviledged instruction */
	R_ANAL_OP_FAMILY_LAST
};

enum {
	R_ANAL_OP_TYPE_NULL = 0,
	R_ANAL_OP_TYPE_JMP  = 1,  /* mandatory jump */
	R_ANAL_OP_TYPE_UJMP = 2,  /* unknown jump (register or so) */
	R_ANAL_OP_TYPE_CJMP = 4,  /* conditional jump */
	R_ANAL_OP_TYPE_CALL = 8,  /* call to subroutine (branch+link) */
	R_ANAL_OP_TYPE_RCALL= 16, /* call to register */
	R_ANAL_OP_TYPE_REP  = 32, /* repeats next instruction N times */
	R_ANAL_OP_TYPE_RET  = 64, /* returns from subrutine */
	R_ANAL_OP_TYPE_ILL  = 0x80,  /* illegal instruction // trap */
	R_ANAL_OP_TYPE_UNK  = 0x100, /* unknown opcode type */
	R_ANAL_OP_TYPE_NOP  = 0x200, /* does nothing */
	R_ANAL_OP_TYPE_MOV  = 0x400, /* register move */
	R_ANAL_OP_TYPE_TRAP = 0x800, /* it's a trap! */
	R_ANAL_OP_TYPE_SWI  = 0x1000,  /* syscall, software interrupt */
	R_ANAL_OP_TYPE_UPUSH = 0x2000, /* unknown push of data into stack */
	R_ANAL_OP_TYPE_PUSH = 0x4000,  /* push value into stack */
	R_ANAL_OP_TYPE_POP = 0x8000,   /* pop value from stack to register */
	R_ANAL_OP_TYPE_CMP = 0x10000,  /* copmpare something */
	R_ANAL_OP_TYPE_ADD = 0x20000,
	R_ANAL_OP_TYPE_SUB = 0x40000,
	R_ANAL_OP_TYPE_MUL = 0x100000,
	R_ANAL_OP_TYPE_DIV = 0x200000,
	R_ANAL_OP_TYPE_SHR = 0x400000,
	R_ANAL_OP_TYPE_SHL = 0x800000,
	R_ANAL_OP_TYPE_OR  = 0x1000000,
	R_ANAL_OP_TYPE_AND = 0x2000000,
	R_ANAL_OP_TYPE_XOR = 0x4000000,
	R_ANAL_OP_TYPE_NOT =   0x8000000,
	R_ANAL_OP_TYPE_STORE = 0x10000000, /* store from register to memory */
	R_ANAL_OP_TYPE_LOAD  = 0x20000000,  /* load from memory to register */
	//R_ANAL_OP_TYPE_LAST
};

/* TODO: what to do with signed/unsigned conditionals? */
enum {
	R_ANAL_OP_COND_EQ = 0,
	R_ANAL_OP_COND_NE,
	R_ANAL_OP_COND_GE,
	R_ANAL_OP_COND_GT,
	R_ANAL_OP_COND_LE,
	R_ANAL_OP_COND_LT,
};

enum {
	R_ANAL_DIFF_NULL = 0,
	R_ANAL_DIFF_MATCH = 'm',
	R_ANAL_DIFF_UNMATCH = 'u'
};

enum {
	R_ANAL_VAR_TYPE_NULL = 0,
	R_ANAL_VAR_TYPE_GLOBAL,
	R_ANAL_VAR_TYPE_LOCAL,
	R_ANAL_VAR_TYPE_ARG,
	R_ANAL_VAR_TYPE_ARGREG,
};

typedef enum {
	R_ANAL_DATA_NULL = 0,
	R_ANAL_DATA_HEX,      /* hex byte pairs */
	R_ANAL_DATA_STR,      /* ascii string */
	R_ANAL_DATA_CODE,     /* plain assembly code */
	R_ANAL_DATA_FUN,      /* plain assembly code */
	R_ANAL_DATA_STRUCT,   /* memory */
	R_ANAL_DATA_LAST
} RAnalData;

typedef enum {
	R_ANAL_BB_TYPE_NULL = 0,
	R_ANAL_BB_TYPE_HEAD = 0x1,     /* first block */
	R_ANAL_BB_TYPE_BODY = 0x2,     /* conditional jump */
	R_ANAL_BB_TYPE_LAST = 0x4,     /* ret */
	R_ANAL_BB_TYPE_FOOT = 0x8      /* unknown jump */
} RAnalBlockType;

enum {
	R_ANAL_STACK_NULL = 0,
	R_ANAL_STACK_NOP,
	R_ANAL_STACK_INCSTACK,
	R_ANAL_STACK_GET,
	R_ANAL_STACK_SET,
};

enum {
	R_ANAL_REFLINE_STYLE = 1,
	R_ANAL_REFLINE_WIDE = 2,
};

enum {
	R_ANAL_RET_ERROR = -1,
	R_ANAL_RET_DUP = -2,
	R_ANAL_RET_NEW = -3,
	R_ANAL_RET_END = -4
};

typedef struct r_anal_t {
	int bits;
	int big_endian;
	void *user;
	RList *bbs;
	RList *fcns;
	RList *vartypes;
	struct r_anal_ctx_t *ctx;
	struct r_anal_plugin_t *cur;
	struct list_head anals;
} RAnal;

typedef struct r_anal_aop_t {
	char *mnemonic;            /* mnemonic */
	ut64 addr;                 /* address */
	int type;                  /* type of opcode */
	int stackop;               /* operation on stack? */
	int cond;                  /* condition type */
	int length;                /* length in bytes of opcode */
	int nopcode;               /* number of opcodes */
	int family;                /* family of opcode */
	int eob;                   /* end of block (boolean) */
	ut64 jump;                 /* true jmp */
	ut64 fail;                 /* false jmp */
	st64 ref;                  /* reference to memory */ /* XXX signed? */
	ut64 value;                /* reference to value */ /* XXX signed? */
	st64 stackptr;             /* stack pointer */
	int r_dst[R_ANAL_MAXREG];  /* register arguments */
	ut64 i_dst[R_ANAL_MAXREG]; /* inmediate arguments */
	int refptr;
} RAnalOp;

// value+regbase+regidx+delta
typedef struct r_anal_value_t {
	int memref; // is memory reference? or value?
	ut64 base ; // numeric address
	int delta; // numeric delta
	int regbase; // register index used (-1 if no reg)
	int regdelta; // register index used (-1 if no reg)
} RAnalValue;

enum {
	R_ANAL_COND_TYPE_Z = 0, //'z', // only 'src' used
	R_ANAL_COND_TYPE_E = 1,
	R_ANAL_COND_TYPE_G = 2,
	R_ANAL_COND_TYPE_GE = 1|2,
};

// 80f92f  cmp cl, 0x2f
//   7543  jnz 0xb78b2dc0 
//         cmp byte [ecx+eax-0x1], 0x2f
// RAnalCond = {
//   .type = R_ANAL_COND_TYPE_Z,
//   .negate = 1,
//   .src = { 

typedef struct r_anal_cond_t {
	// filled by CJMP opcode
	int type;
	int negate;
	// filled by 'cmp' opcode
	RAnalValue src;
	RAnalValue dst;
} RAnalCond;

typedef struct r_anal_bb_t {
	ut64 addr;
	ut64 size;
	ut64 jump;
	ut64 fail;
	int type;
	int diff;
	int ninstr;
	RNumBig *fingerprint;
	RList *aops;
} RAnalBlock;

typedef struct r_anal_fcn_t {
	char *name;
	ut64 addr;
	ut64 size;
	int stack;
	int diff;
	int ninstr;
	RNumBig *fingerprint;
	RList *vars;
	RList *refs;
	RList *xrefs;
} RAnalFcn;

typedef struct r_anal_var_t {
	char *name;
	int delta;
	int type;        /* global, local... */
	char *vartype;   /* float, int... */
	RList *accesses; /* list of accesses for this var */
} RAnalVar;

typedef struct r_anal_var_type_t {
	char *name;
	char *fmt;
	unsigned int size;
} RAnalVarType;

typedef struct r_anal_var_access_t {
	ut64 addr;
	int set;
} RAnalVarAccess;

enum {
	R_ANAL_REF_TYPE_CODE='c', // call
	R_ANAL_REF_TYPE_DATA='d'  // mem ref
} RAnalRefType;

typedef struct r_anal_ref_t {
	int type;
	ut64 addr;
} RAnalRef;

typedef struct r_anal_refline_t {
	ut64 from;
	ut64 to;
	int index;
	struct list_head list;
} RAnalRefline;

//TODO: typedef RAnalOpCallback
typedef struct r_anal_plugin_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	// TODO: typedef
	int (*aop)(RAnal *a, struct r_anal_aop_t *aop, ut64 addr,
			const ut8 *data, int len);
	struct list_head list;
} RAnalPlugin;

#ifdef R_API
/* anal.c */
R_API RAnal *r_anal_new();
R_API RAnal *r_anal_free(RAnal *r);
R_API void r_anal_set_user_ptr(RAnal *anal, void *user);
R_API int r_anal_add(RAnal *anal, struct r_anal_plugin_t *foo);
R_API int r_anal_list(RAnal *anal);
R_API int r_anal_use(RAnal *anal, const char *name);
R_API int r_anal_set_bits(RAnal *anal, int bits);
R_API int r_anal_set_big_endian(RAnal *anal, int boolean);
R_API char *r_anal_strmask (RAnal *anal, const char *data);

/* bb.c */
R_API RAnalBlock *r_anal_bb_new();
R_API RList *r_anal_bb_list_new();
R_API void r_anal_bb_free(void *bb);
R_API int r_anal_bb(RAnal *anal, RAnalBlock *bb,
		ut64 addr, ut8 *buf, ut64 len, int head);
R_API int r_anal_bb_split(RAnal *anal, RAnalBlock *bb,
		RList *bbs, ut64 addr);
R_API int r_anal_bb_overlap(RAnal *anal, RAnalBlock *bb, RList *bbs);
R_API int r_anal_bb_add(RAnal *anal, ut64 addr,
		ut64 size, ut64 jump, ut64 fail, int type, int diff);
R_API int r_anal_bb_del(RAnal *anal, ut64 addr);

/* aop.c */
R_API RAnalOp *r_anal_aop_new();
R_API void r_anal_aop_free(void *aop);
R_API RList *r_anal_aop_list_new();
R_API int r_anal_aop(RAnal *anal, RAnalOp *aop, ut64 addr,
		const ut8 *data, int len);

/* fcn.c */
R_API RAnalFcn *r_anal_fcn_new();
R_API RList *r_anal_fcn_list_new();
R_API void r_anal_fcn_free(void *fcn);
R_API int r_anal_fcn(RAnal *anal, RAnalFcn *fcn, ut64 addr, ut8 *buf, ut64 len);
R_API int r_anal_fcn_add(RAnal *anal, ut64 addr, ut64 size,
		const char *name, int diff);
R_API int r_anal_fcn_del(RAnal *anal, ut64 addr);
R_API RList *r_anal_fcn_bb_list(RAnal *anal, RAnalFcn *fcn);

/* ref.c */
R_API RAnalRef *r_anal_ref_new();
R_API RList *r_anal_ref_list_new();
R_API void r_anal_ref_free(void *ref);

/* var.c */
R_API RAnalVar *r_anal_var_new();
R_API RAnalVarType *r_anal_var_type_new();
R_API RAnalVarAccess *r_anal_var_access_new();
R_API RList *r_anal_var_list_new();
R_API RList *r_anal_var_type_list_new();
R_API RList *r_anal_var_access_list_new();
R_API void r_anal_var_free(void *var);
R_API void r_anal_var_type_free(void *vartype);
R_API void r_anal_var_access_free(void *access);
R_API int r_anal_var_type_add(RAnal *anal, const char *name, int size, const char *fmt);
R_API int r_anal_var_type_del(RAnal *anal, const char *name);
R_API RAnalVarType *r_anal_var_type_get(RAnal *anal, const char *name);
R_API int r_anal_var_add(RAnal *anal, RAnalFcn *fcn, ut64 from, int delta, int type,
		const char *vartype, const char *name, int set);
R_API int r_anal_var_del(RAnal *anal, RAnalFcn *fcn, int delta, int type);
R_API RAnalVar *r_anal_var_get(RAnal *anal, RAnalFcn *fcn, int delta, int type);
R_API const char *r_anal_var_type_to_str (RAnal *anal, int type);
R_API int r_anal_var_access_add(RAnal *anal, RAnalVar *var, ut64 from, int set);
R_API int r_anal_var_access_del(RAnal *anal, RAnalVar *var, ut64 from);
R_API RAnalVarAccess *r_anal_var_access_get(RAnal *anal, RAnalVar *var, ut64 from);

/* reflines.c */
R_API struct r_anal_refline_t *r_anal_reflines_get(RAnal *anal, 
	ut64 addr, ut8 *buf, ut64 len, int nlines, int linesout);
R_API char* r_anal_reflines_str(struct r_anal_t *anal, struct r_anal_refline_t *list,
	ut64 addr, int opts);
R_API int r_anal_reflines_middle(RAnal *anal, RAnalRefline *list, ut64 addr, int len);

/* plugin pointers */
extern RAnalPlugin r_anal_plugin_csr;
extern RAnalPlugin r_anal_plugin_arm;
extern RAnalPlugin r_anal_plugin_x86;
extern RAnalPlugin r_anal_plugin_x86_x86im;
extern RAnalPlugin r_anal_plugin_ppc;
extern RAnalPlugin r_anal_plugin_java;

#endif
#endif

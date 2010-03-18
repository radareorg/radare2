/* radare - LGPL - Copyright 2009-2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#ifndef _INCLUDE_R_ANAL_H_
#define _INCLUDE_R_ANAL_H_

#include <r_types.h>
#include <list.h>
#include <r_list.h>

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
	R_ANAL_OP_TYPE_JMP,   /* mandatory jump */
	R_ANAL_OP_TYPE_UJMP,  /* unknown jump (register or so) */
	R_ANAL_OP_TYPE_CJMP,  /* conditional jump */
	R_ANAL_OP_TYPE_CALL,  /* call to subroutine (branch+link) */
	R_ANAL_OP_TYPE_RCALL, /* call to register */
	R_ANAL_OP_TYPE_REP,   /* repeats next instruction N times */
	R_ANAL_OP_TYPE_RET,   /* returns from subrutine */
	R_ANAL_OP_TYPE_ILL,   /* illegal instruction // trap */
	R_ANAL_OP_TYPE_UNK,   /* unknown opcode type */
	R_ANAL_OP_TYPE_NOP,   /* does nothing */
	R_ANAL_OP_TYPE_MOV,   /* register move */
	R_ANAL_OP_TYPE_TRAP,  /* it's a trap! */
	R_ANAL_OP_TYPE_SWI,   /* syscall, software interrupt */
	R_ANAL_OP_TYPE_UPUSH, /* unknown push of data into stack */
	R_ANAL_OP_TYPE_PUSH,  /* push value into stack */
	R_ANAL_OP_TYPE_POP,   /* pop value from stack to register */
	R_ANAL_OP_TYPE_CMP,   /* copmpare something */
	R_ANAL_OP_TYPE_ADD,
	R_ANAL_OP_TYPE_SUB,
	R_ANAL_OP_TYPE_MUL,
	R_ANAL_OP_TYPE_DIV,
	R_ANAL_OP_TYPE_SHR,
	R_ANAL_OP_TYPE_SHL,
	R_ANAL_OP_TYPE_OR,
	R_ANAL_OP_TYPE_AND,
	R_ANAL_OP_TYPE_XOR,
	R_ANAL_OP_TYPE_NOT,
	R_ANAL_OP_TYPE_STORE, /* store from register to memory */
	R_ANAL_OP_TYPE_LOAD,  /* load from memory to register */
	R_ANAL_OP_TYPE_LAST
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
	R_ANAL_VAR_TYPE_NULL = 0,
	R_ANAL_VAR_TYPE_GLOBAL,
	R_ANAL_VAR_TYPE_LOCAL,
	R_ANAL_VAR_TYPE_ARG,
	R_ANAL_VAR_TYPE_ARGREG,
};

enum {
	R_ANAL_DATA_NULL = 0,
	R_ANAL_DATA_HEX,      /* hex byte pairs */
	R_ANAL_DATA_STR,      /* ascii string */
	R_ANAL_DATA_CODE,     /* plain assembly code */
	R_ANAL_DATA_FUN,      /* plain assembly code */
	R_ANAL_DATA_STRUCT,   /* memory */
	R_ANAL_DATA_LAST
};

enum {
	R_ANAL_BB_TYPE_NULL = 0,
	R_ANAL_BB_TYPE_HEAD,     /* first block */
	R_ANAL_BB_TYPE_BODY,     /* conditional jump */
	R_ANAL_BB_TYPE_LAST,     /* ret */
	R_ANAL_BB_TYPE_FOOT      /* unknown jump */
};

enum {
	R_ANAL_STACK_NULL = 0,
	R_ANAL_STACK_NOP,
	R_ANAL_STACK_INCSTACK,
	R_ANAL_STACK_LOCAL_GET,
	R_ANAL_STACK_LOCAL_SET,
	R_ANAL_STACK_ARG_GET,
	R_ANAL_STACK_ARG_SET
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
	struct r_anal_handle_t *cur;
	struct list_head anals;
} RAnalysis;

typedef struct r_anal_aop_t {
	ut64 addr;
	int type;                  /* type of opcode */
	int stackop;               /* operation on stack? */
	int cond;                  /* condition type */
	int length;                /* length in bytes of opcode */
	int family;                /* family of opcode */
	int eob;                   /* end of block (boolean) */
	ut64 jump;                 /* true jmp */
	ut64 fail;                 /* false jmp */
	st64 ref;                  /*reference to memory */ /* XXX signed? */
	ut64 value;                /* reference to value */ /* XXX signed? */
	int r_dst[R_ANAL_MAXREG];  /* register arguments */
	ut64 i_dst[R_ANAL_MAXREG]; /* inmediate arguments */
} RAnalysisAop;

typedef struct r_anal_bb_t {
	ut64 addr;
	ut64 size;
	ut64 jump;
	ut64 fail;
	RList *aops;
} RAnalysisBB;

typedef struct r_anal_fcn_t {
	char *name;
	ut64 addr;
	ut64 size;
	RList *vars;
	RList *refs;
	RList *xrefs;
} RAnalysisFcn;

typedef struct r_anal_var_t {
	char *name;
	int delta;
	int type;        /* global, local... */
	char *vartype;   /* float, int... */
	RList *accesses; /* list of accesses for this var */
} RAnalysisVar;

typedef struct r_anal_var_type_t {
	char *name;
	char *fmt;
	unsigned int size;
} RAnalysisVarType;

typedef struct r_anal_var_access_t {
	ut64 addr;
	int set;
} RAnalysisVarAccess;

typedef ut64 RAnalysisRef;

typedef struct r_anal_refline_t {
	ut64 from;
	ut64 to;
	int index;
	struct list_head list;
} RAnalysisRefline;

//TODO: typedef RAnalysisAopCallback
typedef struct r_anal_handle_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	// TODO: typedef
	int (*aop)(struct r_anal_t *a, struct r_anal_aop_t *aop, ut64 addr,
			const ut8 *data, int len);
	struct list_head list;
} RAnalysisHandle;

#ifdef R_API
/* anal.c */
R_API RAnalysis *r_anal_new();
R_API RAnalysis *r_anal_free(struct r_anal_t *r);
R_API RAnalysis *r_anal_init(struct r_anal_t *anal);
R_API void r_anal_set_user_ptr(struct r_anal_t *anal, void *user);
R_API int r_anal_add(struct r_anal_t *anal, struct r_anal_handle_t *foo);
R_API int r_anal_list(struct r_anal_t *anal);
R_API int r_anal_use(struct r_anal_t *anal, const char *name);
R_API int r_anal_set_bits(struct r_anal_t *anal, int bits);
R_API int r_anal_set_big_endian(struct r_anal_t *anal, int boolean);
R_API int r_anal_set_pc(struct r_anal_t *a, ut64 pc);

/* bb.c */
R_API RAnalysisBB *r_anal_bb_new();
R_API RList *r_anal_bb_list_new();
R_API void r_anal_bb_free(void *bb);
R_API RAnalysisBB *r_anal_bb_init(struct r_anal_bb_t *bb);
R_API int r_anal_bb(struct r_anal_t *anal, struct r_anal_bb_t *bb,
		ut64 addr, ut8 *buf, ut64 len);
R_API int r_anal_bb_split(RAnalysis *anal, RAnalysisBB *bb, RList *bbs, ut64 addr);
R_API int r_anal_bb_overlap(RAnalysis *anal, RAnalysisBB *bb, RList *bbs);

/* aop.c */
R_API RAnalysisAop *r_anal_aop_new();
R_API RList *r_anal_aop_list_new();
R_API void r_anal_aop_free(void *aop);
R_API RAnalysisAop *r_anal_aop_init(struct r_anal_aop_t *aop);
R_API int r_anal_aop(RAnalysis *anal, RAnalysisAop *aop, ut64 addr,
		const ut8 *data, int len);

/* fcn.c */
R_API RAnalysisFcn *r_anal_fcn_new();
R_API RList *r_anal_fcn_list_new();
R_API void r_anal_fcn_free(void *fcn);
R_API RAnalysisFcn *r_anal_fcn_init(RAnalysisFcn *fcn);
R_API int r_anal_fcn(RAnalysis *anal, RAnalysisFcn *fcn, ut64 addr, ut8 *buf, ut64 len);

/* ref.c */
R_API RAnalysisRef *r_anal_ref_new();
R_API RList *r_anal_ref_list_new();
R_API void r_anal_ref_free(void *ref);
R_API RAnalysisRef *r_anal_ref_init(RAnalysisRef *ref);

/* var.c */
R_API RAnalysisVar *r_anal_var_new();
R_API RAnalysisVarType *r_anal_var_type_new();
R_API RAnalysisVarAccess *r_anal_var_access_new();
R_API RList *r_anal_var_list_new();
R_API RList *r_anal_var_type_list_new();
R_API RList *r_anal_var_access_list_new();
R_API void r_anal_var_free(void *var);
R_API void r_anal_var_type_free(void *vartype);
R_API void r_anal_var_access_free(void *access);
R_API RAnalysisVar *r_anal_var_init(RAnalysisVar *var);
R_API RAnalysisVarType *r_anal_var_type_init(RAnalysisVarType *vartype);
R_API RAnalysisVarAccess *r_anal_var_access_init(RAnalysisVarAccess *access);
R_API int r_anal_var_type_add(RAnalysis *anal, const char *name, int size, const char *fmt);
R_API int r_anal_var_type_del(RAnalysis *anal, const char *name);
R_API RAnalysisVarType *r_anal_var_type_get(RAnalysis *anal, const char *name);
R_API int r_anal_var_add(RAnalysis *anal, RAnalysisFcn *fcn, ut64 from, int delta, int type,
		const char *vartype, const char *name, int set);
R_API int r_anal_var_del(RAnalysis *anal, RAnalysisFcn *fcn, int delta, int type);
R_API RAnalysisVar *r_anal_var_get(RAnalysis *anal, RAnalysisFcn *fcn, int delta, int type);
R_API const char *r_anal_var_type_to_str (RAnalysis *anal, int type);
R_API int r_anal_var_access_add(RAnalysis *anal, RAnalysisVar *var, ut64 from, int set);
R_API int r_anal_var_access_del(RAnalysis *anal, RAnalysisVar *var, ut64 from);
R_API RAnalysisVarAccess *r_anal_var_access_get(RAnalysis *anal, RAnalysisVar *var, ut64 from);

/* reflines.c */
R_API struct r_anal_refline_t *r_anal_reflines_get(struct r_anal_t *anal, 
		ut64 addr, ut8 *buf, ut64 len, int nlines, int linesout);
R_API int r_anal_reflines_str(struct r_anal_t *anal, struct r_anal_refline_t *list,
		ut64 addr, char *str, int opts);

/* plugin pointers */
extern RAnalysisHandle r_anal_plugin_arm;
extern RAnalysisHandle r_anal_plugin_x86;
extern RAnalysisHandle r_anal_plugin_ppc;

#endif
#endif

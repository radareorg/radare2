/* radare - LGPL - Copyright 2009 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#ifndef _INCLUDE_R_ANAL_H_
#define _INCLUDE_R_ANAL_H_

#include "r_types.h"
#include "list.h"

enum {
	R_ANAL_AOP_TYPE_NULL = 0,
	R_ANAL_AOP_TYPE_JMP,   /* mandatory jump */
	R_ANAL_AOP_TYPE_UJMP,  /* unknown jump (register or so) */
	R_ANAL_AOP_TYPE_CJMP,  /* conditional jump */
	R_ANAL_AOP_TYPE_CALL,  /* call to subroutine (branch+link) */
	R_ANAL_AOP_TYPE_RCALL, /* call to register */
	R_ANAL_AOP_TYPE_REP,   /* repeats next instruction N times */
	R_ANAL_AOP_TYPE_RET,   /* returns from subrutine */
	R_ANAL_AOP_TYPE_ILL,   /* illegal instruction // trap */
	R_ANAL_AOP_TYPE_UNK,   /* unknown opcode type */
	R_ANAL_AOP_TYPE_NOP,   /* does nothing */
	R_ANAL_AOP_TYPE_MOV,   /* register move */
	R_ANAL_AOP_TYPE_TRAP,  /* it's a trap! */
	R_ANAL_AOP_TYPE_SWI,   /* syscall, software interrupt */
	R_ANAL_AOP_TYPE_UPUSH, /* unknown push of data into stack */
	R_ANAL_AOP_TYPE_PUSH,  /* push value into stack */
	R_ANAL_AOP_TYPE_POP,   /* pop value from stack to register */
	R_ANAL_AOP_TYPE_CMP,   /* copmpare something */
	R_ANAL_AOP_TYPE_ADD,
	R_ANAL_AOP_TYPE_SUB,
	R_ANAL_AOP_TYPE_MUL,
	R_ANAL_AOP_TYPE_DIV,
	R_ANAL_AOP_TYPE_SHR,
	R_ANAL_AOP_TYPE_SHL,
	R_ANAL_AOP_TYPE_OR,
	R_ANAL_AOP_TYPE_AND,
	R_ANAL_AOP_TYPE_XOR,
	R_ANAL_AOP_TYPE_NOT,
	R_ANAL_AOP_TYPE_STORE, /* store from register to memory */
	R_ANAL_AOP_TYPE_LOAD   /* load from memory to register */
};

enum {
	R_ANAL_DATA_NULL = 0,
	R_ANAL_DATA_HEX,      /* hex byte pairs */
	R_ANAL_DATA_STR,      /* ascii string */
	R_ANAL_DATA_CODE,     /* plain assembly code */
	R_ANAL_DATA_FUN,      /* plain assembly code */
	R_ANAL_DATA_STRUCT    /* memory */
};

enum {
	R_ANAL_BLK_TYPE_NULL = 0,
	R_ANAL_BLK_TYPE_HEAD,     /* first block */
	R_ANAL_BLK_TYPE_BODY,     /* conditional jump */
	R_ANAL_BLK_TYPE_LAST,     /* ret */
	R_ANAL_BLK_TYPE_FOOT      /* unknown jump */
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
	R_ANAL_REFLINE_LINESTYLE = 0x01,
	R_ANAL_REFLINE_NLINES = 0x02,
	R_ANAL_REFLINE_LINESWIDE = 0x04,
	R_ANAL_REFLINE_EXPAND = 0x08
};

struct r_anal_refline_t {
	u64 from;
	u64 to;
	int index;
	struct list_head list;
};

struct r_anal_aop_t {
	int type;                /* type of opcode */
	int stackop;             /* operation on stack? */
	int length;              /* length in bytes of opcode */
	int eob;                 /* end of block (boolean) */
	u64 jump;                /* true jmp */
	u64 fail;                /* false jmp */
	u64 ref;                 /* referente to memory */
	u64 value;               /* referente to value */
	int r_dst,r_src1,r_src2; /* register arguments */
	u64 i_dst,i_src1,i_src2; /* inmediate arguments */
};

struct r_anal_t {
	int bits;
	int big_endian;
	u64 pc;
	void *user;
	struct r_anal_handle_t *cur;
	struct list_head anals;
};

struct r_anal_handle_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*aop)(struct r_anal_t *a, struct r_anal_aop_t *aop, void *data);
	struct list_head list;
};

/* anal.c */
int r_anal_init(struct r_anal_t *anal);
struct r_anal_t *r_anal_free(struct r_anal_t *r);
struct r_anal_t *r_anal_new();
void r_anal_set_user_ptr(struct r_anal_t *anal, void *user);
int r_anal_add(struct r_anal_t *anal, struct r_anal_handle_t *foo);
int r_anal_list(struct r_anal_t *anal);
int r_anal_set(struct r_anal_t *anal, const char *name);
int r_anal_set_bits(struct r_anal_t *anal, int bits);
int r_anal_set_big_endian(struct r_anal_t *anal, int boolean);
int r_anal_set_pc(struct r_anal_t *a, u64 pc);
int r_anal_aop(struct r_anal_t *anal, struct r_anal_aop_t *aop, void *data);
struct r_anal_refline_t *r_anal_reflines_get(struct r_anal_t *anal, u8 *buf, u64 len, int nlines, int linesout);
int r_anal_reflines_str(struct r_anal_t *anal, struct r_anal_refline_t *list, u64 addr, char *str, int opts);
#endif

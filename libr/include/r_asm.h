/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_ASM_H_
#define _INCLUDE_R_ASM_H_

#include <r_types.h>
#include <list.h>

enum {
	R_ASM_ARCH_NULL = 0,
	R_ASM_ARCH_X86,
	R_ASM_ARCH_ARM,
	R_ASM_ARCH_PPC,
	R_ASM_ARCH_M68K,
	R_ASM_ARCH_JAVA,
	R_ASM_ARCH_MIPS,
	R_ASM_ARCH_SPARC,
	R_ASM_ARCH_CSR,
	R_ASM_ARCH_MSIL,
	R_ASM_ARCH_OBJD,
	R_ASM_ARCH_BF
};


enum {
	R_ASM_SYN_NULL = 0,
	R_ASM_SYN_INTEL,
	R_ASM_SYN_ATT,
	R_ASM_SYN_OLLY
};

struct r_asm_aop_t {
	int  inst_len;
	u8   buf[256];
	char buf_asm[256];
	char buf_hex[256];
	char buf_err[256];
};

struct r_asm_t {
	int  bits;
	int  big_endian;
	int  syntax;
	u64  pc;
	void *user;
	struct r_asm_handle_t *cur;
	struct list_head asms;
};

struct r_asm_handle_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*disassemble)(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len);
	int (*assemble)(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf);
	struct list_head list;
};

/* asm.c */
struct r_asm_t *r_asm_new();
void r_asm_free(struct r_asm_t *a);
int r_asm_init(struct r_asm_t *a);
void r_asm_set_user_ptr(struct r_asm_t *a, void *user);
int r_asm_add(struct r_asm_t *a, struct r_asm_handle_t *foo);
int r_asm_list(struct r_asm_t *a);
int r_asm_set(struct r_asm_t *a, const char *name);
int r_asm_set_bits(struct r_asm_t *a, int bits);
int r_asm_set_big_endian(struct r_asm_t *a, int boolean);
int r_asm_set_syntax(struct r_asm_t *a, int syntax);
int r_asm_set_pc(struct r_asm_t *a, u64 pc);
int r_asm_disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len);
int r_asm_assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf);
#endif

/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_ASM_H_
#define _INCLUDE_R_ASM_H_

#include <r_types.h>
#include <list.h>

#define R_ASM_BUFSIZE 1024
#define R_ASM_FASTCALL_ARGS 6

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
	R_ASM_SYN_ATT
};

typedef struct r_asm_aop_t {
	int  inst_len;
	ut8  buf[R_ASM_BUFSIZE];
	char buf_asm[R_ASM_BUFSIZE];
	char buf_hex[R_ASM_BUFSIZE];
	char buf_err[R_ASM_BUFSIZE];
} rAsmAop;

typedef struct r_asm_code_t {
	int  len;
	ut8  *buf;
	char *buf_hex;
	char *buf_asm;
} rAsmCode;

typedef struct r_asm_t {
	int  bits;
	int  big_endian;
	int  syntax;
	ut64 pc;
	void *user;
	struct r_asm_handle_t *cur;
	struct r_asm_fastcall_t *fastcall;
	struct list_head asms;
} rAsm;

typedef struct r_asm_fastcall_t {
	const char *arg[16];
} rAsmFastcall;

// TODO: rename to handler?
typedef struct r_asm_handle_t {
	char *name;
	char *arch;
	char *desc;
	int *bits;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*disassemble)(struct r_asm_t *a, struct r_asm_aop_t *aop, ut8 *buf, ut64 len);
	int (*assemble)(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf);
	int (*set_subarch)(struct r_asm_t *a, const char *buf);
	struct r_asm_fastcall_t *fastcall[R_ASM_FASTCALL_ARGS];
	struct list_head list;
} rAsmHandle;

#ifdef R_API
/* asm.c */
R_API struct r_asm_t *r_asm_new();
R_API const char *r_asm_fastcall(struct r_asm_t *a, int idx, int num);

R_API void r_asm_free(struct r_asm_t *a);
R_API void* r_asm_code_free(struct r_asm_code_t *acode);
R_API struct r_asm_t *r_asm_init(struct r_asm_t *a);
R_API void r_asm_set_user_ptr(struct r_asm_t *a, void *user);
R_API int r_asm_add(struct r_asm_t *a, struct r_asm_handle_t *foo);
R_API int r_asm_list(struct r_asm_t *a);
R_API int r_asm_use(struct r_asm_t *a, const char *name);
R_API int r_asm_set_bits(struct r_asm_t *a, int bits);
R_API int r_asm_set_big_endian(struct r_asm_t *a, int boolean);
R_API int r_asm_set_syntax(struct r_asm_t *a, int syntax);
R_API int r_asm_set_pc(struct r_asm_t *a, ut64 pc);
R_API int r_asm_disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, ut8 *buf, ut64 len);
R_API int r_asm_assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf);
R_API struct r_asm_code_t* r_asm_mdisassemble(struct r_asm_t *a, ut8 *buf, ut64 len);
R_API struct r_asm_code_t* r_asm_massemble(struct r_asm_t *a, const char *buf);

/* plugin pointers */
extern struct r_asm_handle_t r_asm_plugin_dummy;
extern struct r_asm_handle_t r_asm_plugin_bf;
extern struct r_asm_handle_t r_asm_plugin_java;
extern struct r_asm_handle_t r_asm_plugin_mips;
extern struct r_asm_handle_t r_asm_plugin_x86;
extern struct r_asm_handle_t r_asm_plugin_x86_bea;
extern struct r_asm_handle_t r_asm_plugin_x86_olly;
extern struct r_asm_handle_t r_asm_plugin_x86_nasm;
extern struct r_asm_handle_t r_asm_plugin_arm;
extern struct r_asm_handle_t r_asm_plugin_csr;
extern struct r_asm_handle_t r_asm_plugin_m68k;
extern struct r_asm_handle_t r_asm_plugin_ppc;
extern struct r_asm_handle_t r_asm_plugin_sparc;
extern struct r_asm_handle_t r_asm_plugin_psosvm;
#endif

#endif

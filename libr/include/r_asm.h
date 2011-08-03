/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_ASM_H_
#define _INCLUDE_R_ASM_H_

#include <r_types.h>
#include <r_bin.h> // only for binding, no hard dep required 
#include <list.h>
#include <r_util.h>

#define R_ASM_BUFSIZE 1024

/* backward compatibility */
#define R_ASM_ARCH_NONE R_SYS_ARCH_NONE
#define R_ASM_ARCH_X86 R_SYS_ARCH_X86
#define R_ASM_ARCH_ARM R_SYS_ARCH_ARM
#define R_ASM_ARCH_PPC R_SYS_ARCH_PPC
#define R_ASM_ARCH_M68K R_SYS_ARCH_M68K
#define R_ASM_ARCH_JAVA R_SYS_ARCH_JAVA
#define R_ASM_ARCH_MIPS R_SYS_ARCH_MIPS
#define R_ASM_ARCH_SPARC R_SYS_ARCH_SPARC
#define R_ASM_ARCH_CSR R_SYS_ARCH_CSR
#define R_ASM_ARCH_MSIL R_SYS_ARCH_MSIL
#define R_ASM_ARCH_OBJD R_SYS_ARCH_OBJD
#define R_ASM_ARCH_BF R_SYS_ARCH_BF
#define R_ASM_ARCH_SH R_SYS_ARCH_SH

#define R_ASM_GET_OFFSET(x,y,z) \
	(x && x->binb.bin && x->binb.get_offset)? \
		x->binb.get_offset (x->binb.bin, y, z): -1

enum {
	R_ASM_SYNTAX_NONE = 0,
	R_ASM_SYNTAX_INTEL,
	R_ASM_SYNTAX_ATT
};

enum {
	R_ASM_MOD_RAWVALUE = 'r',
	R_ASM_MOD_VALUE = 'v',
	R_ASM_MOD_DSTREG = 'd',
	R_ASM_MOD_SRCREG0 = '0',
	R_ASM_MOD_SRCREG1 = '1',
	R_ASM_MOD_SRCREG2 = '2'
};

typedef struct r_asm_op_t {
	int  inst_len;
	// But this is pretty slow..so maybe we should add some accessors
	ut8  buf[R_ASM_BUFSIZE];
	char buf_asm[R_ASM_BUFSIZE];
	char buf_hex[R_ASM_BUFSIZE];
	char buf_err[R_ASM_BUFSIZE];
} RAsmOp;

typedef struct r_asm_code_t {
	int  len;
	ut8  *buf;
	char *buf_hex;
	char *buf_asm;
	RList *equs; // TODO: must be a hash
} RAsmCode;

// TODO: Must use Hashtable instead of this hack
typedef struct {
	char *key;
	char *value;
} RAsmEqu;

typedef struct r_asm_t {
	int  bits;
	int  big_endian;
	int  syntax;
	ut64 pc;
	void *user;
	struct r_asm_plugin_t *cur;
	RList *plugins;
	RBinBind binb;
} RAsm;

typedef int (*RAsmModifyCallback)(RAsm *a, ut8 *buf, int field, ut64 val);

typedef struct r_asm_plugin_t {
	char *name;
	char *arch;
	char *desc;
// TODO: bits -> renamed to bitmask
// use each bit to identify 4,8,16,32,64 bitsize it can be a mask, no need for pointers here
	int *bits;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*disassemble)(RAsm *a, struct r_asm_op_t *op, const ut8 *buf, ut64 len);
	int (*assemble)(RAsm *a, struct r_asm_op_t *op, const char *buf);
	RAsmModifyCallback modify;
	int (*set_subarch)(RAsm *a, const char *buf);
} RAsmPlugin;

#ifdef R_API
/* asm.c */
R_API RAsm *r_asm_new();
#define r_asm_op_free free
R_API void r_asm_free(RAsm *a);
R_API int r_asm_modify(RAsm *a, ut8 *buf, int field, ut64 val);
R_API void r_asm_set_user_ptr(RAsm *a, void *user);
R_API int r_asm_add(RAsm *a, RAsmPlugin *foo);
R_API int r_asm_use(RAsm *a, const char *name);
R_API int r_asm_set_bits(RAsm *a, int bits);
R_API int r_asm_set_big_endian(RAsm *a, int boolean);
R_API int r_asm_set_syntax(RAsm *a, int syntax);
R_API int r_asm_set_pc(RAsm *a, ut64 pc);
R_API int r_asm_disassemble(RAsm *a, struct r_asm_op_t *op, const ut8 *buf, ut64 len);
R_API int r_asm_assemble(RAsm *a, struct r_asm_op_t *op, const char *buf);
R_API struct r_asm_code_t* r_asm_mdisassemble(RAsm *a, ut8 *buf, ut64 len);
R_API RAsmCode* r_asm_mdisassemble_hexstr(RAsm *a, const char *hexstr);
R_API struct r_asm_code_t* r_asm_massemble(RAsm *a, const char *buf);
R_API struct r_asm_code_t* r_asm_assemble_file(RAsm *a, const char *file);

/* code.c */
R_API RAsmCode *r_asm_code_new();
R_API void* r_asm_code_free(struct r_asm_code_t *acode);
R_API int r_asm_code_set_equ (RAsmCode *code, const char *key, const char *value);
R_API char *r_asm_code_equ_replace (RAsmCode *code, char *str);

// accessors, to make bindings happy
R_API char *r_asm_op_get_hex(RAsmOp *op);
R_API char *r_asm_op_get_asm(RAsmOp *op);

/* plugin pointers */
extern RAsmPlugin r_asm_plugin_bf;
extern RAsmPlugin r_asm_plugin_java;
extern RAsmPlugin r_asm_plugin_mips;
extern RAsmPlugin r_asm_plugin_x86;
extern RAsmPlugin r_asm_plugin_x86_as;
extern RAsmPlugin r_asm_plugin_x86_olly;
extern RAsmPlugin r_asm_plugin_x86_nasm;
extern RAsmPlugin r_asm_plugin_arm;
extern RAsmPlugin r_asm_plugin_armthumb;
extern RAsmPlugin r_asm_plugin_csr;
extern RAsmPlugin r_asm_plugin_m68k;
extern RAsmPlugin r_asm_plugin_ppc;
extern RAsmPlugin r_asm_plugin_sparc;
extern RAsmPlugin r_asm_plugin_psosvm;
extern RAsmPlugin r_asm_plugin_avr;
extern RAsmPlugin r_asm_plugin_dalvik;
extern RAsmPlugin r_asm_plugin_msil;
extern RAsmPlugin r_asm_plugin_sh;
#endif

#endif

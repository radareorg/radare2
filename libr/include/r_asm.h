/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#ifndef R2_ASM_H
#define R2_ASM_H

#include <r_types.h>
#include <r_bin.h> // only for binding, no hard dep required
#include <list.h>
#include <r_util.h>
#include <r_parse.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_asm);

#define R_ASM_OPCODES_PATH R2_LIBDIR "/radare2/" R2_VERSION "/opcodes"
// XXX too big!
#define R_ASM_BUFSIZE 512

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
#define R_ASM_ARCH_Z80 R_SYS_ARCH_Z80
#define R_ASM_ARCH_I8080 R_SYS_ARCH_I8080
#define R_ASM_ARCH_ARC R_SYS_ARCH_ARC

#define R_ASM_GET_OFFSET(x,y,z) \
	(x && x->binb.bin && x->binb.get_offset)? \
		x->binb.get_offset (x->binb.bin, y, z): -1

enum {
	R_ASM_SYNTAX_NONE = 0,
	R_ASM_SYNTAX_INTEL,
	R_ASM_SYNTAX_ATT,
	R_ASM_SYNTAX_REGNUM, // alias for capstone's NOREGNAME
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
	int size; // instruction size
	int payload; // size of payload (opsize = (size-payload))
	// But this is pretty slow..so maybe we should add some accessors
	ut8  buf[R_ASM_BUFSIZE];
	char buf_asm[R_ASM_BUFSIZE];
	char buf_hex[R_ASM_BUFSIZE];
} RAsmOp;

typedef struct r_asm_code_t {
	int len;
	ut8 *buf;
	char *buf_hex;
	char *buf_asm;
	RList *equs; // TODO: must be a hash
	ut64 code_offset;
	ut64 data_offset;
} RAsmCode;

// TODO: Must use Hashtable instead of this hack
typedef struct {
	char *key;
	char *value;
} RAsmEqu;

#define _RAsmPlugin struct r_asm_plugin_t
typedef struct r_asm_t {
	char *cpu;
	int bits;
	int big_endian;
	int syntax;
	ut64 pc;
	void *user;
	_RAsmPlugin *cur;
	RList *plugins;
	RBinBind binb;
	RParse *ifilter;
	RParse *ofilter;
	Sdb *pair;
	RSyscall *syscall;
	RNum *num;
} RAsm;

typedef int (*RAsmModifyCallback)(RAsm *a, ut8 *buf, int field, ut64 val);

typedef struct r_asm_plugin_t {
	char *name;
	char *arch;
	char *cpus;
	char *desc;
	char *license;
	void *user; // user data pointer
	int bits;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*disassemble)(RAsm *a, RAsmOp *op, const ut8 *buf, int len);
	int (*assemble)(RAsm *a, RAsmOp *op, const char *buf);
	RAsmModifyCallback modify;
	int (*set_subarch)(RAsm *a, const char *buf);
} RAsmPlugin;

#ifdef R_API
/* asm.c */
R_API RAsm *r_asm_new();
#define r_asm_op_free free
R_API RAsm *r_asm_free(RAsm *a);
R_API int r_asm_modify(RAsm *a, ut8 *buf, int field, ut64 val);
R_API void r_asm_set_user_ptr(RAsm *a, void *user);
R_API int r_asm_add(RAsm *a, RAsmPlugin *foo);
R_API int r_asm_setup(RAsm *a, const char *arch, int bits, int big_endian);
R_API int r_asm_is_valid(RAsm *a, const char *name);
R_API int r_asm_use(RAsm *a, const char *name);
R_API int r_asm_set_bits(RAsm *a, int bits);
R_API void r_asm_set_cpu(RAsm *a, const char *cpu);
R_API int r_asm_set_big_endian(RAsm *a, int boolean);
R_API int r_asm_set_syntax(RAsm *a, int syntax);
R_API int r_asm_set_pc(RAsm *a, ut64 pc);
R_API int r_asm_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len);
R_API int r_asm_assemble(RAsm *a, RAsmOp *op, const char *buf);
R_API RAsmCode* r_asm_mdisassemble(RAsm *a, const ut8 *buf, int len);
R_API RAsmCode* r_asm_mdisassemble_hexstr(RAsm *a, const char *hexstr);
R_API RAsmCode* r_asm_massemble(RAsm *a, const char *buf);
R_API RAsmCode* r_asm_assemble_file(RAsm *a, const char *file);
R_API int r_asm_filter_input(RAsm *a, const char *f);
R_API int r_asm_filter_output(RAsm *a, const char *f);
R_API char *r_asm_describe(RAsm *a, const char* str);
R_API RList* r_asm_get_plugins(RAsm *a);

/* code.c */
R_API RAsmCode *r_asm_code_new();
R_API void* r_asm_code_free(RAsmCode *acode);
R_API int r_asm_code_set_equ (RAsmCode *code, const char *key, const char *value);
R_API char *r_asm_code_equ_replace (RAsmCode *code, char *str);

// accessors, to make bindings happy
R_API char *r_asm_op_get_hex(RAsmOp *op);
R_API char *r_asm_op_get_asm(RAsmOp *op);
R_API int r_asm_op_get_size(RAsmOp *op);

/* plugin pointers */
extern RAsmPlugin r_asm_plugin_bf;
extern RAsmPlugin r_asm_plugin_java;
extern RAsmPlugin r_asm_plugin_mips_gnu;
extern RAsmPlugin r_asm_plugin_mips_cs;
extern RAsmPlugin r_asm_plugin_x86_udis;
extern RAsmPlugin r_asm_plugin_x86_as;
extern RAsmPlugin r_asm_plugin_x86_nz;
extern RAsmPlugin r_asm_plugin_x86_olly;
extern RAsmPlugin r_asm_plugin_x86_nasm;
extern RAsmPlugin r_asm_plugin_x86_cs;
extern RAsmPlugin r_asm_plugin_arm_gnu;
extern RAsmPlugin r_asm_plugin_arm_cs;
extern RAsmPlugin r_asm_plugin_armthumb;
extern RAsmPlugin r_asm_plugin_arm_winedbg;
extern RAsmPlugin r_asm_plugin_csr;
extern RAsmPlugin r_asm_plugin_m68k;
extern RAsmPlugin r_asm_plugin_ppc_gnu;
extern RAsmPlugin r_asm_plugin_ppc_cs;
extern RAsmPlugin r_asm_plugin_sparc_gnu;
extern RAsmPlugin r_asm_plugin_psosvm;
extern RAsmPlugin r_asm_plugin_avr;
extern RAsmPlugin r_asm_plugin_dalvik;
extern RAsmPlugin r_asm_plugin_msil;
extern RAsmPlugin r_asm_plugin_sh;
extern RAsmPlugin r_asm_plugin_z80;
extern RAsmPlugin r_asm_plugin_i8080;
extern RAsmPlugin r_asm_plugin_m68k;
extern RAsmPlugin r_asm_plugin_arc;
extern RAsmPlugin r_asm_plugin_rar;
extern RAsmPlugin r_asm_plugin_dcpu16;
extern RAsmPlugin r_asm_plugin_8051;
extern RAsmPlugin r_asm_plugin_tms320;
extern RAsmPlugin r_asm_plugin_gb;
extern RAsmPlugin r_asm_plugin_snes;
extern RAsmPlugin r_asm_plugin_ebc;
extern RAsmPlugin r_asm_plugin_nios2;
extern RAsmPlugin r_asm_plugin_malbolge;
extern RAsmPlugin r_asm_plugin_ws;
extern RAsmPlugin r_asm_plugin_6502;
extern RAsmPlugin r_asm_plugin_h8300;
extern RAsmPlugin r_asm_plugin_cr16;
extern RAsmPlugin r_asm_plugin_v850;
extern RAsmPlugin r_asm_plugin_sysz;
extern RAsmPlugin r_asm_plugin_sparc_cs;
extern RAsmPlugin r_asm_plugin_xcore_cs;
extern RAsmPlugin r_asm_plugin_spc700;
extern RAsmPlugin r_asm_plugin_propeller;
extern RAsmPlugin r_asm_plugin_msp430;
extern RAsmPlugin r_asm_plugin_i4004;
extern RAsmPlugin r_asm_plugin_cris_gnu;
#endif

#ifdef __cplusplus
}
#endif

#endif

/* radare - LGPL - Copyright 2009-2025 - nibble, pancake */

#ifndef R2_ASM_H
#define R2_ASM_H

#include <r_arch.h>
#include <r_anal.h>
#include <r_bin.h> // only for binding, no hard dep required
#include <r_bind.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_asm);

#define R_PARSE_FILTER_IMMTRIM 1
#define R_PARSE_FILTER_SUBVAR 2
#define R_PARSE_FILTER_FILTER 4
#define R_PARSE_FILTER_PSEUDO 8
#define R_PARSE_FILTER_COLOR 16

typedef struct r_asm_code_t {
#if 1
	int len;
	ut8 *bytes;
	char *assembly;
#else
	// imho this asmcode should contain multiple archops
	RAnalOp op; // we have those fields already inside RAnalOp
#endif
	HtPP *equs;
	ut64 code_offset;
	ut64 data_offset;
	int code_align;
} RAsmCode;

typedef RList* (*RAnalVarList)(RAnalFunction *fcn, int kind);

typedef struct r_parse_t {
	void *user;
	RSpace *flagspace;
	RSpace *notin_flagspace;
	bool pseudo;
	bool subreg; // replace registers with their respective alias/role name (rdi=A0, ...)
	bool subrel; // replace rip relative expressions in instruction
	bool subtail; // replace any immediate relative to current address with .. prefix syntax
	bool localvar_only; // if true use only the local variable name (e.g. [local_10h] instead of [ebp + local10h])
	ut64 subrel_addr;
	int maxflagnamelen;
	int minval;
	char *retleave_asm;
	RAnalVarList varlist;
	st64 (*get_ptr_at)(RAnalFunction *fcn, st64 delta, ut64 addr);
	const char *(*get_reg_at)(RAnalFunction *fcn, st64 delta, ut64 addr);
	char* (*get_op_ireg)(void *user, ut64 addr);
	RFlagGetAtAddr flag_get; // XXX
	RAnalLabelAt label_get;
	// -- struct r_asm_plugin_t *cur; // XXX move into session
} RParse;

typedef struct r_asm_t {
	RArch *arch;
	RArchConfig *config;
	ut64 pc;
	void *user;
	RArchSession *ecur; // encode current
	RArchSession *dcur; // decode current
	struct r_asm_plugin_session_t *cur;
	RList *sessions; // NOTE: one session per plugin! both lists must have the same length
	RAnalBind analb; // Should be RArchBind instead, but first we need to move all the anal plugins.. well not really we can kill it imho
	Sdb *pair;
	RSyscall *syscall;
	RNum *num;
	int dataalign;
	int codealign;
	HtPP *flags;
	bool pseudo; // should be implicit by RParse
	RParse *parse;
} RAsm;

typedef struct r_asm_plugin_session_t {
	struct r_asm_t *rasm;
	struct r_asm_plugin_t *plugin;
	void *data;
} RAsmPluginSession;

typedef void (*RAsmParseInit)(RAsmPluginSession *s);
typedef void (*RAsmParseFini)(RAsmPluginSession *s);
typedef char *(*RAsmParsePseudo)(RAsmPluginSession *s, const char *data);
typedef char *(*RAsmParseFilter)(RAsmPluginSession *s, ut64 addr, RFlag *f, const char *data);
typedef char *(*RAsmParseSubvar)(RAsmPluginSession *s, RAnalFunction *f, ut64 addr, int oplen, const char *data);
typedef char *(*RAsmParsePatch)(RAsmPluginSession *s, RAnalOp *aop, const char *newop);

typedef struct r_asm_plugin_t {
	RPluginMeta meta;
	RAsmParseInit init;
	RAsmParseFini fini;
	RAsmParsePseudo parse; // TODO. rename to pseudo
	RAsmParseFilter filter;
	RAsmParseSubvar subvar;
	RAsmParsePatch patch;
} RAsmPlugin;

#ifdef R_API

/* rparse */
R_API RParse *r_parse_new(void);
R_API void r_parse_free(RParse *p);

R_API char *r_asm_parse_pseudo(RAsm *a, const char *data);
R_API char *r_asm_parse_filter(RAsm *a, ut64 addr, RFlag *f, RAnalHint *hint, const char *data);
R_API char *r_asm_parse_subvar(RAsm *a, RAnalFunction *f, ut64 addr, int oplen, const char *data);
R_API char *r_asm_parse_immtrim(RAsm *a, const char *opstr);
R_API char *r_asm_parse_patch(RAsm *a, RAnalOp *aop, const char *newop);


/* asm.c */
R_API RAsm *r_asm_new(void);
R_API void r_asm_free(RAsm *a);
R_API bool r_asm_modify(RAsm *a, ut8 *buf, int field, ut64 val);
R_API char *r_asm_mnemonics(RAsm *a, int id, bool json);
R_API int r_asm_mnemonics_byname(RAsm *a, const char *name);
R_API void r_asm_set_user_ptr(RAsm *a, void *user); // TODO: rename to set_user or set_userdata or set_userptr

R_API bool r_asm_use(RAsm *a, const char *name);
R_API bool r_asm_use_assembler(RAsm *a, const char *name);
R_API bool r_asm_use_parser(RAsm *a, const char *name);

// this is in archconfig
R_API int r_asm_set_bits(RAsm *a, int bits);
R_API bool r_asm_set_big_endian(RAsm *a, bool big_endian);

R_API bool r_asm_set_syntax(RAsm *a, int syntax); // This is in RArchConfig
R_API int r_asm_syntax_from_string(const char *name);
R_API int r_asm_set_pc(RAsm *a, ut64 pc);
R_API int r_asm_disassemble(RAsm *a, RAnalOp *op, const ut8 *buf, int len);
R_API RAsmCode* r_asm_mdisassemble(RAsm *a, const ut8 *buf, int len);
R_API RAsmCode* r_asm_mdisassemble_hexstr(RAsm *a, RParse *p, const char *hexstr);
R_API RAsmCode* r_asm_massemble(RAsm *a, const char *buf);
R_API RAsmCode* r_asm_rasm_assemble(RAsm *a, const char *buf, bool use_spp);
R_API char *r_asm_tostring(RAsm *a, ut64 addr, const ut8 *b, int l);
/* to ease the use of the native bindings (not used in r2) */
R_API ut8 *r_asm_from_string(RAsm *a, ut64 addr, const char *b, int *l);
R_API char *r_asm_describe(RAsm *a, const char* str);
R_API void r_asm_list_directives(void);
R_API SdbGperf *r_asm_get_gperf(const char *k);
R_API RList *r_asm_cpus(RAsm *a);

/* code.c */
R_API RAsmCode *r_asm_code_new(void);
R_API void r_asm_code_free(RAsmCode *acode);
R_API void r_asm_code_set_equ(RAsmCode *code, const char *key, const char *value);
R_API R_MUSTUSE char *r_asm_code_equ_replace(RAsmCode *code, const char *str);
R_API char* r_asm_code_get_hex(RAsmCode *acode);
R_API char *r_asm_code_equ_get(RAsmCode *code, const char *key);

/* op.c XXX Deprecate the use of all those apis and just use RArchOp */
R_API RAnalOp *r_asm_op_new(void);
R_API void r_asm_op_init(RAnalOp *op);
R_API void r_asm_op_free(RAnalOp *op);
R_API void r_asm_op_fini(RAnalOp *op);
R_API char *r_asm_op_get_hex(RAnalOp *op);
R_API int r_asm_op_get_size(RAnalOp *op);
R_API void r_asm_op_set_asm(RAnalOp *op, const char *str);
R_API int r_asm_op_set_hex(RAnalOp *op, const char *str);
R_API int r_asm_op_set_hexbuf(RAnalOp *op, const ut8 *buf, int len);
R_API void r_asm_op_set_buf(RAnalOp *op, const ut8 *str, int len);

/* plugins */
R_API bool r_asm_plugin_add(RAsm *a, RAsmPlugin *plugin);
R_API bool r_asm_plugin_remove(RAsm *a, RAsmPlugin *plugin);

extern RAsmPlugin r_asm_plugin_6502;
extern RAsmPlugin r_asm_plugin_8051;
extern RAsmPlugin r_asm_plugin_arm;
extern RAsmPlugin r_asm_plugin_att2intel;
extern RAsmPlugin r_asm_plugin_avr;
extern RAsmPlugin r_asm_plugin_bpf;
extern RAsmPlugin r_asm_plugin_chip8;
extern RAsmPlugin r_asm_plugin_cosmac;
extern RAsmPlugin r_asm_plugin_dalvik;
extern RAsmPlugin r_asm_plugin_dummy;
extern RAsmPlugin r_asm_plugin_evm;
extern RAsmPlugin r_asm_plugin_gb;
extern RAsmPlugin r_asm_plugin_java;
extern RAsmPlugin r_asm_plugin_m68k;
extern RAsmPlugin r_asm_plugin_mips;
extern RAsmPlugin r_asm_plugin_msp430;
extern RAsmPlugin r_asm_plugin_null;
extern RAsmPlugin r_asm_plugin_pickle;
extern RAsmPlugin r_asm_plugin_ppc;
extern RAsmPlugin r_asm_plugin_riscv;
extern RAsmPlugin r_asm_plugin_sbpf;
extern RAsmPlugin r_asm_plugin_sh;
extern RAsmPlugin r_asm_plugin_sparc;
extern RAsmPlugin r_asm_plugin_stm8;
extern RAsmPlugin r_asm_plugin_tms320;
extern RAsmPlugin r_asm_plugin_tricore;
extern RAsmPlugin r_asm_plugin_v850;
extern RAsmPlugin r_asm_plugin_wasm;
extern RAsmPlugin r_asm_plugin_x86;
extern RAsmPlugin r_asm_plugin_z80;

#endif

#ifdef __cplusplus
}
#endif

#endif

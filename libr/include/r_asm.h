/* radare - LGPL - Copyright 2009-2024 - nibble, pancake */

#ifndef R2_ASM_H
#define R2_ASM_H

#include <r_types.h>
#include <r_arch.h>
#include <r_bin.h> // only for binding, no hard dep required
#include <r_util.h>
#include <r_parse.h>
#include <r_bind.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_asm);

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

typedef struct r_asm_t {
	RArch *arch;
	RArchConfig *config;
	ut64 pc;
	void *user;
	RArchSession *ecur; // encode current
	RArchSession *dcur; // decode current
	RList *plugins;
	RAnalBind analb; // Should be RArchBind instead, but first we need to move all the anal plugins.. well not really we can kill it imho
	RParse *ifilter;
	RParse *ofilter;
	Sdb *pair;
	RSyscall *syscall;
	RNum *num;
	int dataalign;
	int codealign;
	HtPP *flags;
	bool pseudo; // should be implicit by RParse
	RParse *parse;
} RAsm;

#ifdef R_API

/* asm.c */
R_API RAsm *r_asm_new(void);
R_API void r_asm_free(RAsm *a);
R_API bool r_asm_modify(RAsm *a, ut8 *buf, int field, ut64 val);
R_API char *r_asm_mnemonics(RAsm *a, int id, bool json);
R_API int r_asm_mnemonics_byname(RAsm *a, const char *name);
R_API void r_asm_set_user_ptr(RAsm *a, void *user);
R_API bool r_asm_is_valid(RAsm *a, const char *name);

R_API bool r_asm_use(RAsm *a, const char *name);
R_API bool r_asm_use_assembler(RAsm *a, const char *name);

// this is in archconfig
R_API int r_asm_set_bits(RAsm *a, int bits);
R_API void r_asm_set_cpu(RAsm *a, const char *cpu);
// TODO: must be set_endian (BIG; MIDDLE; LITTLE, ..)
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
R_API bool r_asm_sub_names_input(RAsm *a, const char *f);
R_API bool r_asm_sub_names_output(RAsm *a, const char *f);
R_API char *r_asm_describe(RAsm *a, const char* str);
R_API const RList* r_asm_get_plugins(RAsm *a);
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
R_API char *r_asm_op_get_asm(RAnalOp *op);
R_API int r_asm_op_get_size(RAnalOp *op);
R_API void r_asm_op_set_asm(RAnalOp *op, const char *str);
R_API int r_asm_op_set_hex(RAnalOp *op, const char *str);
R_API int r_asm_op_set_hexbuf(RAnalOp *op, const ut8 *buf, int len);
R_API void r_asm_op_set_buf(RAnalOp *op, const ut8 *str, int len);
// R_DEPRECATE R_API ut8 *r_asm_op_get_buf(RAnalOp *op);

#endif

#ifdef __cplusplus
}
#endif

#endif

/* radare - LGPL - Copyright 2009-2024 - pancake, nibble */

#ifndef R2_PARSE_H
#define R2_PARSE_H

#include <r_types.h>
#include <r_flag.h>
#include <r_anal.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_parse);

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
	struct r_parse_plugin_t *cur;
	// RAnal *anal; // weak anal ref XXX do not use. use analb.anal
	RList *parsers;
	RAnalVarList varlist;
	st64 (*get_ptr_at)(RAnalFunction *fcn, st64 delta, ut64 addr);
	const char *(*get_reg_at)(RAnalFunction *fcn, st64 delta, ut64 addr);
	char* (*get_op_ireg)(void *user, ut64 addr);
	RAnalBind analb;
	RFlagGetAtAddr flag_get; // XXX
	RAnalLabelAt label_get;
} RParse; // TODO rename to RAsmParseState

typedef struct r_parse_plugin_t {
	// TODO R2_600 Use RPluginMeta instead
	char *name;
	char *desc;
	bool (*init)(RParse *p, void *user); // returns an RAsmParseState*
	int (*fini)(RParse *p, void *user); // receives the asmparsestate

	int (*parse)(RParse *p, const char *data, char *str);
	// UNUSED bool (*assemble)(RParse *p, char *data, char *str);
	int (*filter)(RParse *p, ut64 addr, RFlag *f, char *data, char *str, int len, bool big_endian);
	bool (*subvar)(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
	// int (*replace)(int argc, const char *argv[], char *newstr); // rename to pseudo!
	// int (*pseudo)(int argc, const char *argv[], char *newstr); // rename to pseudo!
} RParsePlugin;

#ifdef R_API

/* lifecycle */
R_API RParse *r_parse_new(void);
R_API void r_parse_free(RParse *p);

/* plugins */
R_API void r_parse_set_user_ptr(RParse *p, void *user);
R_API bool r_parse_plugin_add(RParse *p, RParsePlugin *plugin);
R_API bool r_parse_plugin_remove(RParse *p, RParsePlugin *plugin);
R_API bool r_parse_use(RParse *p, const char *name);

/* action */
R_API bool r_parse_parse(RParse *p, const char *data, char *str);
R_API char *r_parse_instruction(RParse *p, const char *data);
R_API bool r_parse_assemble(RParse *p, char *data, char *str); // XXX deprecate, unused and probably useless, related to write-hack
R_API bool r_parse_filter(RParse *p, ut64 addr, RFlag *f, RAnalHint *hint, char *data, char *str, int len, bool big_endian);
R_API bool r_parse_subvar(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
R_API char *r_parse_immtrim(char *opstr);

/* plugin pointers */
extern RParsePlugin r_parse_plugin_6502_pseudo;
extern RParsePlugin r_parse_plugin_arm_pseudo;
extern RParsePlugin r_parse_plugin_att2intel;
extern RParsePlugin r_parse_plugin_avr_pseudo;
extern RParsePlugin r_parse_plugin_chip8_pseudo;
extern RParsePlugin r_parse_plugin_dalvik_pseudo;
extern RParsePlugin r_parse_plugin_dummy;
extern RParsePlugin r_parse_plugin_m68k_pseudo;
extern RParsePlugin r_parse_plugin_mips_pseudo;
extern RParsePlugin r_parse_plugin_ppc_pseudo;
extern RParsePlugin r_parse_plugin_sh_pseudo;
extern RParsePlugin r_parse_plugin_wasm_pseudo;
extern RParsePlugin r_parse_plugin_riscv_pseudo;
extern RParsePlugin r_parse_plugin_x86_pseudo;
extern RParsePlugin r_parse_plugin_z80_pseudo;
extern RParsePlugin r_parse_plugin_tms320_pseudo;
extern RParsePlugin r_parse_plugin_v850_pseudo;
extern RParsePlugin r_parse_plugin_bpf_pseudo;
extern RParsePlugin r_parse_plugin_stm8_pseudo;
extern RParsePlugin r_parse_plugin_evm_pseudo;
extern RParsePlugin r_parse_plugin_null_pseudo;
extern RParsePlugin r_parse_plugin_gb_pseudo;
extern RParsePlugin r_parse_plugin_pickle_pseudo;
extern RParsePlugin r_parse_plugin_tricore_pseudo;
#endif

#ifdef __cplusplus
}
#endif

#endif

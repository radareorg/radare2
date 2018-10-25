/* radare - LGPL - Copyright 2009-2018 - pancake, nibble */

#ifndef R2_PARSE_H
#define R2_PARSE_H

#include <r_types.h>
#include <r_flag.h>
#include <r_anal.h>

#ifdef __cplusplus
extern "C" {
#endif

// XXX : remove this define???
#define R_PARSE_STRLEN 256

R_LIB_VERSION_HEADER(r_parse);

typedef RList* (*RAnalVarList)(RAnal *anal, RAnalFunction *fcn, int kind);

typedef struct r_parse_t {
	void *user;
	int flagspace;
	int notin_flagspace;
	bool pseudo;
	bool relsub; // replace rip relative expressions in instruction
	bool tailsub; // replace any immediate relative to current address with .. prefix syntax
	bool localvar_only; // if true use only the local variable name (e.g. [local_10h] instead of [ebp + local10h])
	ut64 relsub_addr;
	int minval;
	char *retleave_asm;
	struct r_parse_plugin_t *cur;
	RAnal *anal; // weak anal ref
	RAnalHint *hint; // weak anal ref
	RList *parsers;
	RAnalVarList varlist;
	RAnalBind analb;
} RParse;

typedef struct r_parse_plugin_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*parse)(RParse *p, const char *data, char *str);
	int (*assemble)(RParse *p, char *data, char *str);
	int (*filter)(RParse *p, ut64 addr, RFlag *f, char *data, char *str, int len, bool big_endian);
	bool (*varsub)(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
	int (*replace)(int argc, const char *argv[], char *newstr);
} RParsePlugin;

#ifdef R_API
R_API struct r_parse_t *r_parse_new(void);
R_API void r_parse_free(RParse *p);
R_API void r_parse_set_user_ptr(RParse *p, void *user);
R_API int r_parse_add(RParse *p, RParsePlugin *foo);
R_API int r_parse_list(RParse *p);
R_API int r_parse_use(RParse *p, const char *name);
R_API int r_parse_parse(RParse *p, const char *data, char *str);
R_API int r_parse_assemble(RParse *p, char *data, char *str);
R_API int r_parse_filter(RParse *p, ut64 addr, RFlag *f, char *data, char *str, int len, bool big_endian);
R_API bool r_parse_varsub(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
R_API char *r_parse_c_string(RAnal *anal, const char *code);
R_API char *r_parse_c_file(RAnal *anal, const char *path);
R_API int r_parse_is_c_file (const char *file);
R_API char *r_parse_immtrim (char *opstr);

/* plugin pointers */
extern RParsePlugin r_parse_plugin_dummy;
extern RParsePlugin r_parse_plugin_att2intel;
extern RParsePlugin r_parse_plugin_x86_pseudo;
extern RParsePlugin r_parse_plugin_arm_pseudo;
extern RParsePlugin r_parse_plugin_mips_pseudo;
extern RParsePlugin r_parse_plugin_dalvik_pseudo;
extern RParsePlugin r_parse_plugin_mreplace;
extern RParsePlugin r_parse_plugin_ppc_pseudo;
extern RParsePlugin r_parse_plugin_sh_pseudo;
extern RParsePlugin r_parse_plugin_avr_pseudo;
extern RParsePlugin r_parse_plugin_6502_pseudo;
extern RParsePlugin r_parse_plugin_m68k_pseudo;
extern RParsePlugin r_parse_plugin_z80_pseudo;
#endif

#ifdef __cplusplus
}
#endif

#endif

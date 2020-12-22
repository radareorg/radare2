/* radare - LGPL - Copyright 2009-2018 - pancake, nibble */

#ifndef R2_PARSE_H
#define R2_PARSE_H

#include <r_types.h>
#include <r_flag.h>
#include <r_anal.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_parse);

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
} RParse;

typedef struct r_parse_plugin_t {
	char *name;
	char *desc;
	bool (*init)(RParse *p, void *user);
	int (*fini)(RParse *p, void *user);
	int (*parse)(RParse *p, const char *data, char *str);
	bool (*assemble)(RParse *p, char *data, char *str);
	int (*filter)(RParse *p, ut64 addr, RFlag *f, char *data, char *str, int len, bool big_endian);
	bool (*subvar)(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
	int (*replace)(int argc, const char *argv[], char *newstr);
} RParsePlugin;

#ifdef R_API

/* lifecycle */
R_API struct r_parse_t *r_parse_new(void);
R_API void r_parse_free(RParse *p);

/* plugins */
R_API void r_parse_set_user_ptr(RParse *p, void *user);
R_API bool r_parse_add(RParse *p, RParsePlugin *foo);
R_API bool r_parse_use(RParse *p, const char *name);

/* action */
R_API bool r_parse_parse(RParse *p, const char *data, char *str);
R_API bool r_parse_assemble(RParse *p, char *data, char *str); // XXX deprecate, unused and probably useless, related to write-hack
R_API bool r_parse_filter(RParse *p, ut64 addr, RFlag *f, RAnalHint *hint, char *data, char *str, int len, bool big_endian);
R_API bool r_parse_subvar(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
R_API char *r_parse_immtrim(char *opstr);

/* c */
// why we have anal scoped things in rparse
R_API char *r_parse_c_string(RAnal *anal, const char *code, char **error_msg);
R_API char *r_parse_c_file(RAnal *anal, const char *path, const char *dir, char **error_msg);
R_API void r_parse_c_reset(RParse *p);

/* ctype */
// Parses strings like "const char * [0x42] const * [23]" to RParseCTypeType

typedef struct r_parse_ctype_t RParseCType;

typedef enum {
	R_PARSE_CTYPE_TYPE_KIND_IDENTIFIER,
	R_PARSE_CTYPE_TYPE_KIND_POINTER,
	R_PARSE_CTYPE_TYPE_KIND_ARRAY
} RParseCTypeTypeKind;

typedef enum {
	R_PARSE_CTYPE_IDENTIFIER_KIND_UNSPECIFIED,
	R_PARSE_CTYPE_IDENTIFIER_KIND_STRUCT,
	R_PARSE_CTYPE_IDENTIFIER_KIND_UNION,
	R_PARSE_CTYPE_IDENTIFIER_KIND_ENUM
} RParseCTypeTypeIdentifierKind;

typedef struct r_parse_ctype_type_t RParseCTypeType;
struct r_parse_ctype_type_t {
	RParseCTypeTypeKind kind;
	union {
		struct {
			RParseCTypeTypeIdentifierKind kind;
			char *name;
			bool is_const;
		} identifier;
		struct {
			RParseCTypeType *type;
			bool is_const;
		} pointer;
		struct {
			RParseCTypeType *type;
			ut64 count;
		} array;
	};
};

R_API RParseCType *r_parse_ctype_new(void);
R_API void r_parse_ctype_free(RParseCType *ctype);
R_API RParseCTypeType *r_parse_ctype_parse(RParseCType *ctype, const char *str, char **error);
R_API void r_parse_ctype_type_free(RParseCTypeType *type);

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
#endif

#ifdef __cplusplus
}
#endif

#endif

/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#ifndef R2_PARSE_H
#define R2_PARSE_H

#include <r_types.h>
#include <r_flags.h>
#include <r_anal.h>
#include <list.h>

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
	struct r_parse_plugin_t *cur;
	RAnal *anal; // weak anal ref
	RList *parsers;
	RAnalVarList varlist;
} RParse;

typedef struct r_parse_plugin_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*parse)(RParse *p, const char *data, char *str);
	int (*assemble)(RParse *p, char *data, char *str);
	int (*filter)(RParse *p, RFlag *f, char *data, char *str, int len);
	int (*varsub)(RParse *p, RAnalFunction *f, char *data, char *str, int len);
	struct list_head list;
} RParsePlugin;

#ifdef R_API
R_API struct r_parse_t *r_parse_new();
R_API void r_parse_free(RParse *p);
R_API void r_parse_set_user_ptr(RParse *p, void *user);
R_API int r_parse_add(RParse *p, struct r_parse_plugin_t *foo);
R_API int r_parse_list(RParse *p);
R_API int r_parse_use(RParse *p, const char *name);
R_API int r_parse_parse(RParse *p, const char *data, char *str);
R_API int r_parse_assemble(RParse *p, char *data, char *str);
R_API int r_parse_filter(RParse *p, RFlag *f, char *data, char *str, int len);
R_API int r_parse_varsub(RParse *p, RAnalFunction *f, char *data, char *str, int len);
R_API char *r_parse_c_string(const char *code);
R_API char *r_parse_c_file(const char *path);
R_API int r_parse_is_c_file (const char *file);

/* plugin pointers */
extern struct r_parse_plugin_t r_parse_plugin_dummy;
extern struct r_parse_plugin_t r_parse_plugin_att2intel;
extern struct r_parse_plugin_t r_parse_plugin_x86_pseudo;
extern struct r_parse_plugin_t r_parse_plugin_mips_pseudo;
extern struct r_parse_plugin_t r_parse_plugin_dalvik_pseudo;
extern struct r_parse_plugin_t r_parse_plugin_mreplace;
#endif

#ifdef __cplusplus
}
#endif

#endif

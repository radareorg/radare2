/* radare - LGPL - Copyright 2009-2012 - pancake, nibble */

#ifndef _INCLUDE_R_PARSE_H_
#define _INCLUDE_R_PARSE_H_

#include <r_types.h>
#include <r_flags.h>
#include <r_anal.h>
#include <list.h>

// XXX : remove this define???
#define R_PARSE_STRLEN 256

typedef struct r_parse_t {
	void *user;
	struct r_parse_plugin_t *cur;
	struct list_head parsers;
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

/* plugin pointers */
extern struct r_parse_plugin_t r_parse_plugin_dummy;
extern struct r_parse_plugin_t r_parse_plugin_att2intel;
extern struct r_parse_plugin_t r_parse_plugin_x86_pseudo;
extern struct r_parse_plugin_t r_parse_plugin_mips_pseudo;
extern struct r_parse_plugin_t r_parse_plugin_mreplace;
#endif

#endif

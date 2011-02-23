/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

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
	int (*parse)(struct r_parse_t *p, void *data, char *str);
	int (*assemble)(struct r_parse_t *p, char *data, char *str);
	int (*filter)(RParse *p, struct r_flag_t *f, char *data, char *str, int len);
	int (*varsub)(RParse *p, struct r_anal_fcn_t *f, char *data, char *str, int len);
	struct list_head list;
} RParsePlugin;

#ifdef R_API
R_API struct r_parse_t *r_parse_new();
R_API void r_parse_free(RParse *p);
R_API void r_parse_set_user_ptr(RParse *p, void *user);
R_API int r_parse_add(RParse *p, struct r_parse_plugin_t *foo);
R_API int r_parse_list(RParse *p);
R_API int r_parse_use(RParse *p, const char *name);
R_API int r_parse_parse(RParse *p, void *data, char *str);
R_API int r_parse_assemble(RParse *p, char *data, char *str);
R_API int r_parse_filter(RParse *p, RFlag *f, char *data, char *str, int len);
R_API int r_parse_varsub(RParse *p, RAnalFcn *f, char *data, char *str, int len);

/* plugin pointers */
extern struct r_parse_plugin_t r_parse_plugin_dummy;
extern struct r_parse_plugin_t r_parse_plugin_x86_pseudo;
extern struct r_parse_plugin_t r_parse_plugin_mreplace;
#endif

#endif

#ifndef _INCLUDE_R_LANG_H_
#define _INCLUDE_R_LANG_H_

#include <r_types.h>
#include <r_list.h>

typedef struct r_lang_t {
	struct r_lang_plugin_t *cur;
	void *user;
	RList *defs;
	RList *langs;
} RLang;

typedef struct r_lang_plugin_t {
	const char *name;
	const char *desc;
	const char **help;
	int (*init)(struct r_lang_t* user);
	int (*setup)(struct r_lang_t* user);
	int (*fini)(struct r_lang_t *user);
	int (*prompt)(struct r_lang_t *user);
	int (*run)(struct r_lang_t *user, const char *code, int len);
	int (*run_file)(struct r_lang_t *user, const char *file);
	int (*set_argv)(struct r_lang_t *user, int argc, char **argv);
} RLangPlugin;

typedef struct r_lang_def_t {
	char *name;
	char *type;
	void *value;
} RLangDef;

#ifdef R_API
R_API struct r_lang_t *r_lang_new();
R_API void *r_lang_free(RLang *lang);
R_API int r_lang_setup(RLang *lang);
R_API int r_lang_add(RLang *lang, struct r_lang_plugin_t *foo);
R_API int r_lang_list(RLang *lang);
R_API int r_lang_use(RLang *lang, const char *name);
R_API int r_lang_run(RLang *lang, const char *code, int len);
R_API int r_lang_run_string(RLang *lang, const char *code);
/* TODO: user_ptr must be deprecated */
R_API void r_lang_set_user_ptr(RLang *lang, void *user);
R_API int r_lang_set_argv(RLang *lang, int argc, char **argv);
R_API int r_lang_run(RLang *lang, const char *code, int len);
R_API int r_lang_run_file(RLang *lang, const char *file);
R_API int r_lang_prompt(RLang *lang);
R_API void r_lang_plugin_free (RLang *lang, RLangPlugin *p);
// TODO: rename r_Lang_add for r_lang_plugin_add

R_API int r_lang_define(RLang *lang, const char *type, const char *name, void *value);
R_API void r_lang_undef(RLang *lang, const char *name);
R_API void r_lang_def_free (RLangDef *def);
#endif
#endif

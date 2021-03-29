#ifndef R2_LANG_H
#define R2_LANG_H

#include <r_types.h>
#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_lang);

typedef char* (*RCoreCmdStrCallback)(void* core, const char *s);
typedef int (*RCoreCmdfCallback)(void* core, const char *s, ...);

typedef struct r_lang_t {
	struct r_lang_plugin_t *cur;
	void *user;
	RList *defs;
	RList *langs;
	PrintfCallback cb_printf;
	RCoreCmdStrCallback cmd_str;
	RCoreCmdfCallback cmdf;
} RLang;

typedef struct r_lang_plugin_t {
	const char *name;
	const char *alias;
	const char *desc;
	const char *example;
	const char *license;
	const char **help;
	const char *ext;
	bool (*init)(RLang *user);
	bool (*setup)(RLang *user);
	bool (*fini)(RLang *user);
	bool (*prompt)(RLang *user);
	bool (*run)(RLang *user, const char *code, int len);
	bool (*run_file)(RLang *user, const char *file);
	int (*set_argv)(RLang *user, int argc, char **argv);
} RLangPlugin;

typedef struct r_lang_def_t {
	char *name;
	char *type;
	void *value;
} RLangDef;

#ifdef R_API
R_API RLang *r_lang_new(void);
R_API void r_lang_free(RLang *lang);
R_API bool r_lang_setup(RLang *lang);
R_API bool r_lang_add(RLang *lang, RLangPlugin *foo);
R_API bool r_lang_list(RLang *lang);
R_API bool r_lang_use(RLang *lang, const char *name);
R_API bool r_lang_run(RLang *lang, const char *code, int len);
R_API bool r_lang_run_string(RLang *lang, const char *code);
/* TODO: user_ptr must be deprecated */
R_API void r_lang_set_user_ptr(RLang *lang, void *user);
R_API bool r_lang_set_argv(RLang *lang, int argc, char **argv);
R_API bool r_lang_run_file(RLang *lang, const char *file);
R_API bool r_lang_prompt(RLang *lang);
R_API void r_lang_plugin_free(RLangPlugin *p); // XXX
R_API RLangPlugin *r_lang_get_by_name(RLang *lang, const char *name);
R_API RLangPlugin *r_lang_get_by_extension(RLang *lang, const char *ext);
// TODO: rename r_Lang_add for r_lang_plugin_add

R_API bool r_lang_define(RLang *lang, const char *type, const char *name, void *value);
R_API void r_lang_undef(RLang *lang, const char *name);
R_API void r_lang_def_free(RLangDef *def);

#endif

#ifdef __cplusplus
}
#endif

#endif

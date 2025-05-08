#ifndef R2_LANG_H
#define R2_LANG_H

#include <r_types.h>
#include <r_list.h>
#include <r_util/r_table.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_lang);

typedef char* (*RCoreCmdStrCallback)(void* core, const char *s);
typedef int (*RCoreCmdfCallback)(void* core, const char *s, ...);
typedef char *(*RCoreCallAtCallback)(void* core, ut64 addr, const char *s);

typedef struct r_lang_t {
	void *user;
	RCons *cons;
	RList *defs;
	RList *langs;
	PrintfCallback cb_printf;
	RCoreCmdStrCallback cmd_str;
	RCoreCmdfCallback cmdf;
	RCoreCallAtCallback call_at;
	RList *sessions;
	struct r_lang_session_t *session;
} RLang;

typedef struct r_lang_session_t _RLangSession;

typedef bool (*RLangPluginInit)(_RLangSession *s);
typedef bool (*RLangPluginSetup)(_RLangSession *s);
typedef bool (*RLangPluginFini)(_RLangSession *s);
typedef bool (*RLangPluginPrompt)(_RLangSession *s);
typedef bool (*RLangPluginRun)(_RLangSession *s, const char *code, int len);
typedef bool (*RLangPluginRunFile)(_RLangSession *s, const char *file);
typedef int (*RLangPluginSetArgv)(_RLangSession *s, int argc, char **argv);

#include <r_lib.h>

typedef struct r_lang_plugin_t {
	RPluginMeta meta;
	// TODO add those into meta too?
	const char *alias;
	const char *example;
	const char **help;
	const char *ext;
	RLangPluginInit init;
	RLangPluginSetup setup;
	RLangPluginFini fini;
	RLangPluginPrompt prompt;
	RLangPluginRun run;
	RLangPluginRunFile run_file;
	RLangPluginSetArgv set_argv;
} RLangPlugin;

typedef struct r_lang_def_t {
	char *name;
	char *type;
	void *value;
} RLangDef;

typedef struct r_lang_session_t {
	RLang *lang;
	RLangPlugin *plugin;
	void *plugin_data;
	void *user_data; // there's also lang->user_data :think:
} RLangSession;

#ifdef R_API
R_API RLang *r_lang_new(void);
R_API void r_lang_free(RLang *lang);
R_API bool r_lang_setup(RLang *lang);
R_API bool r_lang_plugin_add(RLang *lang, RLangPlugin *plugin);
R_API bool r_lang_plugin_remove(RLang *lang, RLangPlugin *plugin);
R_API bool r_lang_use(RLang *lang, const char *name);
R_API bool r_lang_use_plugin(RLang *lang, RLangPlugin *h);
R_API bool r_lang_run(RLang *lang, const char *code, int len);
R_API bool r_lang_run_string(RLang *lang, const char *code);
/* TODO: user_ptr must be deprecated */
R_API void r_lang_set_user_ptr(RLang *lang, void *user);
R_API bool r_lang_set_argv(RLang *lang, int argc, char **argv);
R_API bool r_lang_run_file(RLang *lang, const char *file);
R_API bool r_lang_prompt(RLang *lang);
R_API RLangPlugin *r_lang_get_by_name(RLang *lang, const char *name);
R_API RLangPlugin *r_lang_get_by_extension(RLang *lang, const char *ext);

R_API bool r_lang_define(RLang *lang, const char *type, const char *name, void *value);
R_API void r_lang_undef(RLang *lang, const char *name);
R_API void r_lang_def_free(RLangDef *def);

#endif

#ifdef __cplusplus
}
#endif

#endif

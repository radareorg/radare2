#ifndef _INCLUDE_R_LANG_H_
#define _INCLUDE_R_LANG_H_

#include <r_types.h>
#include <list.h>

typedef struct r_lang_t {
	struct r_lang_handle_t *cur;
	void *user;
	struct list_head defs;
	struct list_head langs;
} RLang;

typedef struct r_lang_handle_t {
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
	struct list_head list;
} RLangHandle;

typedef struct r_lang_def_t {
	char *name;
	char *type;
	void *value;
	struct list_head list;
} RLangDef;

#ifdef R_API
R_API struct r_lang_t *r_lang_new();
R_API void *r_lang_free(struct r_lang_t *lang);
R_API int r_lang_setup(RLang *lang);
R_API struct r_lang_t *r_lang_init(struct r_lang_t *lang);
R_API int r_lang_add(struct r_lang_t *lang, struct r_lang_handle_t *foo);
R_API int r_lang_list(struct r_lang_t *lang);
R_API int r_lang_use(struct r_lang_t *lang, const char *name);
R_API int r_lang_run(struct r_lang_t *lang, const char *code, int len);
R_API int r_lang_run_string(RLang *lang, const char *code);
/* TODO: user_ptr must be deprecated */
R_API void r_lang_set_user_ptr(struct r_lang_t *lang, void *user);
R_API int r_lang_set_argv(struct r_lang_t *lang, int argc, char **argv);
R_API int r_lang_run(struct r_lang_t *lang, const char *code, int len);
R_API int r_lang_run_file(struct r_lang_t *lang, const char *file);
R_API int r_lang_prompt(struct r_lang_t *lang);

R_API int r_lang_define(struct r_lang_t *lang, const char *type, const char *name, void *value);
R_API void r_lang_undef(struct r_lang_t *lang);
#endif
#endif

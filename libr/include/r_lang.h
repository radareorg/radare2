#ifndef _INCLUDE_R_LANG_H_
#define _INCLUDE_R_LANG_H_

#include <r_types.h>
#include <list.h>

struct r_lang_handle_t {
	const char *name;
	const char *desc;
	const char **help;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*prompt)(void *user);
	int (*run)(void *user, const char *code, int len);
	int (*run_file)(void *user, const char *file);
	int (*set_argv)(void *user, int argc, char **argv);
	struct list_head list;
};

struct r_lang_t {
	struct r_lang_handle_t *cur;
	void *user;
	struct list_head langs;
};

int r_lang_init(struct r_lang_t *lang);
int r_lang_add(struct r_lang_t *lang, struct r_lang_handle_t *foo);
int r_lang_list(struct r_lang_t *lang);
int r_lang_set(struct r_lang_t *lang, const char *name);
int r_lang_run(struct r_lang_t *lang, const char *code, int len);
void r_lang_set_user_ptr(struct r_lang_t *lang, void *user);
int r_lang_set_argv(struct r_lang_t *lang, int argc, char **argv);
int r_lang_run(struct r_lang_t *lang, const char *code, int len);
int r_lang_run_file(struct r_lang_t *lang, const char *file);

#endif

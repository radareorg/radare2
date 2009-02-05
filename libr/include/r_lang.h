#ifndef _INCLUDE_R_LANG_H_
#define _INCLUDE_R_LANG_H_

#include <r_types.h>
#include <list.h>

struct r_lang_handle_t {
	char *name;
	char *desc;
	struct list_head list;
};

struct r_lang_t {
	struct r_lang_handle_t *cur;
	struct list_head langs;
};

int r_lang_init(struct r_lang_t *lang);
int r_lang_add(struct r_lang_t *lang, struct r_lang_handle_t *foo);
int r_lang_list(struct r_lang_t *lang);
int r_lang_set(struct r_lang_t *lang, const char *name);
int r_lang_run(struct r_lang_t *lang, const char *code, int len);

#endif

/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_PARSE_H_
#define _INCLUDE_R_PARSE_H_

#include <r_types.h>
#include <list.h>


#define R_PARSE_STRLEN 256

struct r_parse_t {
	void *user;
	struct r_parse_handle_t *cur;
	struct list_head parsers;
};

struct r_parse_handle_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*parse)(struct r_parse_t *p, void *data, char *str);
	struct list_head list;
};

/* parse.c */
struct r_parse_t *r_parse_new();
void r_parse_free(struct r_parse_t *p);
int r_parse_init(struct r_parse_t *p);
void r_parse_set_user_ptr(struct r_parse_t *p, void *user);
int r_parse_add(struct r_parse_t *p, struct r_parse_handle_t *foo);
int r_parse_list(struct r_parse_t *p);
int r_parse_set(struct r_parse_t *p, const char *name);
int r_parse_parse(struct r_parse_t *p, void *data, char *str);

#endif

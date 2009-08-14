/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_parse.h>
#include <list.h>
#include "../config.h"

static struct r_parse_handle_t *parse_static_plugins[] = 
	{ R_PARSE_STATIC_PLUGINS };

struct r_parse_t *r_parse_new()
{
	struct r_parse_t *p = MALLOC_STRUCT(struct r_parse_t);
	r_parse_init(p);
	return p;
}

void r_parse_free(struct r_parse_t *p)
{
	free(p);
}

int r_parse_init(struct r_parse_t *p)
{
	int i;
	p->user = NULL;
	INIT_LIST_HEAD(&p->parsers);
	for(i=0;parse_static_plugins[i];i++)
		r_parse_add(p, parse_static_plugins[i]);
	return R_TRUE;
}

void r_parse_set_user_ptr(struct r_parse_t *p, void *user)
{
	p->user = user;
}

int r_parse_add(struct r_parse_t *p, struct r_parse_handle_t *foo)
{
	if (foo->init)
		foo->init(p->user);
	list_add_tail(&(foo->list), &(p->parsers));
	return R_TRUE;
}

int r_parse_list(struct r_parse_t *p)
{
	struct list_head *pos;
	list_for_each_prev(pos, &p->parsers) {
		struct r_parse_handle_t *h = list_entry(pos, struct r_parse_handle_t, list);
		printf(" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

int r_parse_set(struct r_parse_t *p, const char *name)
{
	struct list_head *pos;
	list_for_each_prev(pos, &p->parsers) {
		struct r_parse_handle_t *h = list_entry(pos, struct r_parse_handle_t, list);
		if (!strcmp(h->name, name)) {
			p->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

int r_parse_parse(struct r_parse_t *p, void *data, char *str)
{
	if (p->cur && p->cur->parse)
		return p->cur->parse(p, data, str);
	
	return R_FALSE;
}

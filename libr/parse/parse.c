/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_parse.h>
#include <list.h>
#include "../config.h"

static struct r_parse_handle_t *parse_static_plugins[] = 
	{ R_PARSE_STATIC_PLUGINS };

R_API struct r_parse_t *r_parse_new() {
	struct r_parse_t *p = R_NEW(struct r_parse_t);
	return r_parse_init(p);
}

R_API void r_parse_free(struct r_parse_t *p) {
	free(p);
}

R_API struct r_parse_t *r_parse_init(struct r_parse_t *p) {
	if (p) {
		int i;
		p->user = NULL;
		INIT_LIST_HEAD(&p->parsers);
		for(i=0;parse_static_plugins[i];i++)
			r_parse_add(p, parse_static_plugins[i]);
	}
	return p;
}

R_API void r_parse_set_user_ptr(struct r_parse_t *p, void *user) {
	p->user = user;
}

R_API int r_parse_add(struct r_parse_t *p, struct r_parse_handle_t *foo) {
	if (foo->init)
		foo->init(p->user);
	list_add_tail(&(foo->list), &(p->parsers));
	return R_TRUE;
}

R_API int r_parse_list(struct r_parse_t *p) {
	struct list_head *pos;
	list_for_each_prev(pos, &p->parsers) {
		struct r_parse_handle_t *h = list_entry(pos, struct r_parse_handle_t, list);
		printf("parse %10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_parse_use(struct r_parse_t *p, const char *name) {
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

R_API int r_parse_assemble(struct r_parse_t *p, char *data, char *str) {
	int ret = R_FALSE;
	char *in = strdup(str);
	char *s, *o;

	data[0]='\0';
	if (p->cur && p->cur->assemble) {
		o = data+strlen(data);
		do {
			s = strchr(str, ';');
			if (s) *s='\0';
			ret = p->cur->assemble(p, o, str);
			if (!ret) break;
			if (s) {
				str = s + 1;
				o = o+strlen(data);
				o[0]='\n';
				o[1]='\0';
				o = o + 1;
			}
		} while(s);
	}
	free(in);
	return ret;
}

R_API int r_parse_symreplace(struct r_parse_t *p, struct r_flag_t *f, char *data, char *str) {
	if (p->cur && p->cur->symreplace)
		return p->cur->symreplace(p, f, data, str);
	return R_FALSE;
}

R_API int r_parse_parse(struct r_parse_t *p, void *data, char *str) {
	if (p->cur && p->cur->parse)
		return p->cur->parse(p, data, str);
	return R_FALSE;
}

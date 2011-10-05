/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com>, pancake<@nopcode.org> */

#include <stdio.h>

#include <r_types.h>
#include <r_parse.h>
#include <list.h>
#include "../config.h"

static RParsePlugin *parse_static_plugins[] = 
	{ R_PARSE_STATIC_PLUGINS };

R_API RParse *r_parse_new() {
	int i;
	RParsePlugin *static_plugin;
	RParse *p = R_NEW (RParse);
	if (!p) return NULL;
	p->user = NULL;
	INIT_LIST_HEAD (&p->parsers);
	for (i=0; parse_static_plugins[i];i++) {
		static_plugin = R_NEW (RParsePlugin);
		memcpy (static_plugin, parse_static_plugins[i], sizeof (RParsePlugin));
		r_parse_add (p, static_plugin);
	}
	return p;
}

R_API void r_parse_free(RParse *p) {
	free (p);
}

R_API void r_parse_set_user_ptr(RParse *p, void *user) {
	p->user = user;
}

R_API int r_parse_add(RParse *p, RParsePlugin *foo) {
	if (foo->init)
		foo->init (p->user);
	list_add_tail (&(foo->list), &(p->parsers));
	return R_TRUE;
}

// DEPRECATE. only for debug
R_API int r_parse_list(RParse *p) {
	struct list_head *pos;
	list_for_each_prev (pos, &p->parsers) {
		RParsePlugin *h = list_entry (pos, RParsePlugin, list);
		printf ("parse %10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_parse_use(RParse *p, const char *name) {
	struct list_head *pos;
	list_for_each_prev (pos, &p->parsers) {
		RParsePlugin *h = list_entry (pos, RParsePlugin, list);
		if (!strcmp (h->name, name)) {
			p->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_parse_assemble(RParse *p, char *data, char *str) {
	int ret = R_FALSE;
	char *in = strdup (str);
	char *s, *o;

	data[0]='\0';
	if (p->cur && p->cur->assemble) {
		o = data+strlen (data);
		do {
			s = strchr (str, ';');
			if (s) *s='\0';
			ret = p->cur->assemble (p, o, str);
			if (!ret) break;
			if (s) {
				str = s + 1;
				o = o+strlen (data);
				o[0]='\n';
				o[1]='\0';
				o++;
			}
		} while (s);
	}
	free (in);
	return ret;
}

R_API int r_parse_parse(RParse *p, void *data, char *str) {
	if (p->cur && p->cur->parse)
		return p->cur->parse (p, data, str);
	return R_FALSE;
}

R_API int r_parse_filter(RParse *p, struct r_flag_t *f, char *data, char *str, int len) {
	if (p->cur && p->cur->filter)
		return p->cur->filter (p, f, data, str, len);
	return R_FALSE;
}

R_API int r_parse_varsub(RParse *p, struct r_anal_fcn_t *f, char *data, char *str, int len) {
	if (p->cur && p->cur->varsub)
		return p->cur->varsub (p, f, data, str, len);
	return R_FALSE;
}

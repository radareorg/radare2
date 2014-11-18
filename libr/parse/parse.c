/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <stdio.h>

#include <r_types.h>
#include <r_parse.h>
#include <list.h>
#include "../config.h"

R_LIB_VERSION (r_parse);

static RParsePlugin *parse_static_plugins[] =
	{ R_PARSE_STATIC_PLUGINS };

R_API RParse *r_parse_new() {
	int i;
	RParsePlugin *static_plugin;
	RParse *p = R_NEW (RParse);
	if (!p) return NULL;
	p->user = NULL;
	p->parsers = r_list_new ();
	p->parsers->free = NULL; // memleak
	p->notin_flagspace = -1;
	p->flagspace = -1;
	for (i=0; parse_static_plugins[i]; i++) {
		static_plugin = R_NEW (RParsePlugin);
		memcpy (static_plugin, parse_static_plugins[i],
			sizeof (RParsePlugin));
		r_parse_add (p, static_plugin);
	}
	return p;
}

R_API void r_parse_free(RParse *p) {
	r_list_free (p->parsers);
	free (p);
}

R_API int r_parse_add(RParse *p, RParsePlugin *foo) {
	if (foo->init)
		foo->init (p->user);
	r_list_append (p->parsers, foo);
	return R_TRUE;
}

R_API int r_parse_use(RParse *p, const char *name) {
	RListIter *iter;
	RParsePlugin *h;
	r_list_foreach (p->parsers, iter, h) {
		if (!strcmp (h->name, name)) {
			p->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_parse_assemble(RParse *p, char *data, char *str) {
	char *in = strdup (str);
	int ret = R_FALSE;
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

R_API int r_parse_parse(RParse *p, const char *data, char *str) {
	if (p->cur && p->cur->parse)
		return p->cur->parse (p, data, str);
	return R_FALSE;
}

#define isx86separator(x) ( \
	(x)==' '||(x)=='\t'||(x)=='\n'|| (x)=='\r'||(x)==' '|| \
	(x)==','||(x)==';'||(x)=='['||(x)==']'|| \
	(x)=='('||(x)==')'||(x)=='{'||(x)=='}'||(x)=='\x1b')

static int isvalidflag(RFlagItem *flag) {
	if (flag && strchr (flag->name, '.')) {
		return 1; //strlen (flag->name)>3) {
	}
	return 0;
}

static int filter(RParse *p, RFlag *f, char *data, char *str, int len) {
	char *ptr = data, *ptr2;
	RAnalFunction *fcn;
	RFlagItem *flag;
	ut64 off;
	int x86 = (p&&p->cur&&p->cur->name)?
		(strstr (p->cur->name, "x86")? 1: 0): 0;
	if (!data || !p) return 0;
#if FILTER_DWORD
	ptr2 = strstr (ptr, "dword ");
	if (ptr2)
		memmove (ptr2, ptr2+6, strlen (ptr2+6)+1);
#endif
	ptr2 = NULL;
// remove "dword" ?
	while ((ptr = strstr (ptr, "0x"))) {
		if (x86) for (ptr2 = ptr; *ptr2 && !isx86separator (*ptr2); ptr2++);
		else for (ptr2 = ptr; *ptr2 && ((*ptr2=='\x1b')||!isseparator (*ptr2)); ptr2++);
		off = r_num_math (NULL, ptr);
		// small numbers should not be replaced by flags
		if (off <0xff) {
			ptr = ptr2;
			continue;
		}
#if 0
		// old behaviour: only hide flags at 0
		if (!off) {
			ptr = ptr2;
			continue;
		}
#endif
		fcn = r_anal_get_fcn_in (p->anal, off, 0);
		if (fcn) {
			if (fcn->addr == off) {
				*ptr = 0;
				// hack to realign pointer for colours
				ptr2--;
				if (*ptr2!=0x1b)
					ptr2++;
				snprintf (str, len, "%s%s%s", data, fcn->name,
						(ptr!=ptr2)? ptr2: "");
				return R_TRUE;
			}
		}
		if (f) {
			flag = r_flag_get_i2 (f, off);
			if (!flag)
				flag = r_flag_get_i (f, off);
			if (isvalidflag (flag)) {
				if (p->notin_flagspace != -1) {
					if (p->flagspace == flag->space)
						continue;
				} else
				if (p->flagspace != -1 && \
						(p->flagspace != flag->space)) {
					ptr = ptr2;
					continue;
				}
				*ptr = 0;
				// hack to realign pointer for colours
				ptr2--;
				if (*ptr2!=0x1b)
					ptr2++;
				snprintf (str, len, "%s%s%s", data, flag->name,
					(ptr!=ptr2)? ptr2: "");
				return R_TRUE;
			}
		}
		ptr = ptr2;
	}
	strncpy (str, data, len);
	return R_FALSE;
}

R_API int r_parse_filter(RParse *p, RFlag *f, char *data, char *str, int len) {
	filter (p, f, data, str, len);
	if (p->cur && p->cur->filter)
		return p->cur->filter (p, f, data, str, len);
	return R_FALSE;
}

R_API int r_parse_varsub(RParse *p, RAnalFunction *f, char *data, char *str, int len) {
	if (p->cur && p->cur->varsub)
		return p->cur->varsub (p, f, data, str, len);
	return R_FALSE;
}

/* setters */
R_API void r_parse_set_user_ptr(RParse *p, void *user) {
	p->user = user;
}

R_API void r_parse_set_flagspace(RParse *p, int fs) {
	p->flagspace = fs;
}

/* TODO: DEPRECATE */
R_API int r_parse_list(RParse *p) {
	RListIter *iter;
	RParsePlugin *h;
	r_list_foreach (p->parsers, iter, h) {
		printf ("parse %10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

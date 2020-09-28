/* radare2 - LGPL - Copyright 2009-2020 - nibble, pancake, maijin */

#include <stdio.h>

#include <r_types.h>
#include <r_parse.h>
#include <config.h>

R_LIB_VERSION (r_parse);

static RParsePlugin *parse_static_plugins[] =
	{ R_PARSE_STATIC_PLUGINS };

R_API RParse *r_parse_new(void) {
	int i;
	RParse *p = R_NEW0 (RParse);
	if (!p) {
		return NULL;
	}
	p->parsers = r_list_newf (NULL); // memleak
	if (!p->parsers) {
		r_parse_free (p);
		return NULL;
	}
	p->notin_flagspace = NULL;
	p->flagspace = NULL;
	p->pseudo = false;
	p->subrel = false;
	p->subtail = false;
	p->minval = 0x100;
	p->localvar_only = false;
	for (i = 0; parse_static_plugins[i]; i++) {
		r_parse_add (p, parse_static_plugins[i]);
	}
	return p;
}

R_API void r_parse_free(RParse *p) {
	r_list_free (p->parsers);
	free (p);
}

R_API bool r_parse_add(RParse *p, RParsePlugin *foo) {
	bool itsFine = true;
	if (foo->init) {
		itsFine = foo->init (p, p->user);
	}
	if (itsFine) {
		r_list_append (p->parsers, foo);
	}
	return true;
}

R_API bool r_parse_use(RParse *p, const char *name) {
	RListIter *iter;
	RParsePlugin *h;
	r_return_val_if_fail (p && name, false);
	r_list_foreach (p->parsers, iter, h) {
		if (!strcmp (h->name, name)) {
			p->cur = h;
			return true;
		}
	}
	return false;
}

// this function is a bit confussing, assembles C code into wat?, whehres theh input and wheres the output
// and its unused. so imho it sshould be DEPRECATED this conflicts with rasm.assemble imhoh
R_API bool r_parse_assemble(RParse *p, char *data, char *str) {
	char *in = strdup (str);
	bool ret = false;
	char *s, *o;

	data[0]='\0';
	if (p->cur && p->cur->assemble) {
		o = data + strlen (data);
		do {
			s = strchr (str, ';');
			if (s) {
				*s = '\0';
			}
			ret = p->cur->assemble (p, o, str);
			if (!ret) {
				break;
			}
			if (s) {
				str = s + 1;
				o += strlen (data);
				o[0] = '\n';
				o[1] = '\0';
				o++;
			}
		} while (s);
	}
	free (in);
	return ret;
}

// data is input disasm, str is output pseudo
// TODO: refactooring, this should return char * instead
R_API bool r_parse_parse(RParse *p, const char *data, char *str) {
	r_return_val_if_fail (p && data && str, false);
	return (p && data && *data && p->cur && p->cur->parse)
		? p->cur->parse (p, data, str) : false;
}

R_API char *r_parse_immtrim(char *opstr) {
	if (!opstr || !*opstr) {
		return NULL;
	}
	char *n = strstr (opstr, "0x");
	if (n) {
		char *p = n + 2;
		while (IS_HEXCHAR (*p)) {
			p++;
		}
		memmove (n, p, strlen (p) + 1);
	}
	if (strstr (opstr, " - ]")) {
		opstr = r_str_replace (opstr, " - ]", "]", 1);
	}
	if (strstr (opstr, " + ]")) {
		opstr = r_str_replace (opstr, " + ]", "]", 1);
	}
	if (strstr (opstr, ", ]")) {
		opstr = r_str_replace (opstr, ", ]", "]", 1);
	}
	if (strstr (opstr, " - ")) {
		opstr = r_str_replace (opstr, " - ", "-", 1);
	}
	if (strstr (opstr, " + ")) {
		opstr = r_str_replace (opstr, " + ", "+", 1);
	}
	return opstr;
}

R_API bool r_parse_subvar(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	if (p->cur && p->cur->subvar) {
		return p->cur->subvar (p, f, addr, oplen, data, str, len);
	}
	return false;
}

/* setters */
R_API void r_parse_set_user_ptr(RParse *p, void *user) {
	p->user = user;
}

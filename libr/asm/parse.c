/* radare2 - LGPL - Copyright 2009-2022 - nibble, pancake, maijin */

#include <r_parse.h>
#include <config.h>

R_LIB_VERSION (r_parse);

static RParsePlugin *parse_static_plugins[] =
	{ R_PARSE_STATIC_PLUGINS };

#if 0
typedef struct r_parse_session_t {
	RParse *p;
	RParsePlugin *cur;
	void *user;
	// all the settings
	RSpace *flagspace;
	RSpace *notin_flagspace;
	bool pseudo;
	bool subreg; // replace registers with their respective alias/role name (rdi=A0, ...)
	bool subrel; // replace rip relative expressions in instruction
	bool subtail; // replace any immediate relative to current address with .. prefix syntax
	bool localvar_only; // if true use only the local variable name (e.g. [local_10h] instead of [ebp + local10h])
	ut64 subrel_addr;
	int maxflagnamelen;
	int minval;
	char *retleave_asm;
} RParseSession;

R_API RParseSession *r_parse_new_session(RParse *p, const char *name) {
	if (r_parse_use (p, name)) {
		RParseSession *ps = R_NEW0 (RParseSession);
		ps->p = p;
		ps->cur = p->cur;
		return ps;
	}
	return NULL;
}

R_API char *r_parse_
#endif

R_API RParse *r_parse_new(void) {
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
	size_t i;
	for (i = 0; parse_static_plugins[i]; i++) {
		r_parse_plugin_add (p, parse_static_plugins[i]);
	}
	return p;
}

R_API void r_parse_free(RParse *p) {
	if (p) {
		r_list_free (p->parsers);
		free (p);
	}
}

R_API bool r_parse_plugin_add(RParse *p, RParsePlugin *foo) {
	r_return_val_if_fail (p && foo, false);
	bool itsFine = foo->init? foo->init (p, p->user): true;
	if (itsFine) {
		r_list_append (p->parsers, foo);
	}
	return true;
}

R_API bool r_parse_plugin_remove(RParse *p, RParsePlugin *plugin) {
	return true;
}

static char *predotname(const char *name) {
	char *sname = strdup (name);
	char *dot = strchr (sname, '.');
	if (dot) {
		*dot = 0;
	}
	return sname;
}

R_API bool r_parse_use(RParse *p, const char *name) {
	r_return_val_if_fail (p && name, false);

	// TODO: remove the alias workarounds because of missing pseudo plugins
	// TODO: maybe we want to have a generic pseudo parser?
	if (r_str_startswith (name, "s390.")) {
		name = "x86.pseudo";
	}

	RListIter *iter;
	RParsePlugin *h;
	r_list_foreach (p->parsers, iter, h) {
		if (!strcmp (h->name, name)) {
			p->cur = h;
			return true;
		}
	}
	char *sname = predotname (name);
	bool found = false;
	r_list_foreach (p->parsers, iter, h) {
		char *shname = predotname (h->name);
		found = !strcmp (shname, sname);
		free (shname);
		if (found) {
			p->cur = h;
			break;
		}
	}
	free (sname);
	return false;
}

#if 0
// this function is a bit confussing, assembles C code into wat?, whehres theh input and wheres the output
// and its unused. so imho it sshould be DEPRECATED this conflicts with rasm.assemble imhoh
R_API bool r_parse_assemble(RParse *p, char *data, char *str) {
	r_return_val_if_fail (p && data && str, false);
	char *in = strdup (str);
	bool ret = false;
	char *s, *o;

	data[0] = '\0';
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
#endif

// data is input disasm, str is output pseudo
// TODO: refactoring, this should return char * instead
// like parseHeap()
R_API char *r_parse_instruction(RParse *p, const char *data) {
	r_return_val_if_fail (p && data, false);
	char *str = malloc (32 + strlen (data) * 2);
	strcpy (str, data);
	bool bres = (p && p->cur && p->cur->parse)
		? p->cur->parse (p, data, str) : false;
	if (bres) {
		return str;
	}
	free (str);
	return NULL;
}

R_API bool r_parse_parse(RParse *p, const char *data, char *str) { // TODO deprecate. in R2_590 because r_parse_instruction is better
	r_return_val_if_fail (p && data && str, false);
	return (p && data && *data && p->cur && p->cur->parse)
		? p->cur->parse (p, data, str) : false;
}

R_API char *r_parse_immtrim(char *_opstr) {
// R_API char *r_parse_immtrim(const char *_opstr) {
	if (R_STR_ISEMPTY (_opstr)) {
		return NULL;
	}
	char *opstr = _opstr;
	// TODO: make this inmutable strdup
	// char *opstr = strdup (_opstr);
	char *n = strstr (_opstr, "0x");
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

R_API bool r_parse_subvar(RParse *p, R_NULLABLE RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	r_return_val_if_fail (p, false);
	if (p->cur && p->cur->subvar) {
		return p->cur->subvar (p, f, addr, oplen, data, str, len);
	}
	return false;
}

/* setters */
R_API void r_parse_set_user_ptr(RParse *p, void *user) {
	r_return_if_fail (p && user);
	p->user = user;
}

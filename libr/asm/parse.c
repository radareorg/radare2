/* radare2 - LGPL - Copyright 2009-2024 - nibble, pancake, maijin */

#include <r_asm.h>
#include <config.h>

R_LIB_VERSION (r_parse);


#if 0

R_API RParseSession *r_parse_new_session(RParse *p, const char *name) {
	if (r_parse_use (p, name)) {
		RParseSession *ps = R_NEW0 (RParseSession);
		ps->p = p;
		ps->cur = p->cur;
		return ps;
	}
	return NULL;
}
#endif

// R_API bool r_parse_session_

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
	return p;
}

R_API void r_parse_free(RParse *p) {
	if (p) {
		r_list_free (p->parsers);
		free (p);
	}
}

// TODO .make it internal
R_API char *r_asm_parse_pseudo(RAsm *a, const char *data) {
	R_RETURN_VAL_IF_FAIL (a && data, false);
	RParse *p = a->parse;
	char *str = malloc (32 + strlen (data) * 2);
	strcpy (str, data);
	RAsmParsePseudo parse = R_UNWRAP3 (p, cur, parse);
	bool bres = parse? parse (p, data, str) : false;
	if (bres) {
		return str;
	}
	free (str);
	return NULL;
}

// TODO: make it internal
R_API char *r_asm_parse_immtrim(RAsm *a, const char *_opstr) {
	RParse *p = a->parse;
	if (R_STR_ISEMPTY (_opstr)) {
		return NULL;
	}
	char *opstr = strdup (_opstr);
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
	r_str_trim (opstr);
	char *last = opstr + strlen (opstr) - 1;
	if (*last == ',') {
		*last = 0;
		r_str_trim (opstr);
	}
	return opstr;
}

// TODO : make it internal
R_API bool r_asm_parse_subvar(RAsm *a, R_NULLABLE RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	R_RETURN_VAL_IF_FAIL (a, false);
	RParse *p = a->parse;
	if (p->cur && p->cur->subvar) {
		return p->cur->subvar (a, f, addr, oplen, data, str, len);
	}
	return false;
}

/* radare2 - LGPL - Copyright 2009-2024 - nibble, pancake, maijin */

#include <r_asm.h>
#include <config.h>

R_LIB_VERSION (r_parse);

R_API RParse *r_parse_new(void) {
	RParse *p = R_NEW0 (RParse);
	if (R_LIKELY (p)) {
		p->minval = 0x100;
	}
	return p;
}

R_API void r_parse_free(RParse *p) {
	if (p) {
		free (p);
	}
}

// TODO .make it internal
R_API char *r_asm_parse_pseudo(RAsm *a, const char *data) {
	R_RETURN_VAL_IF_FAIL (a && data, false);
	char *str = malloc (32 + (strlen (data) * 2));
	if (str) {
		strcpy (str, data);
		RAsmParsePseudo parse = R_UNWRAP4 (a, cur, plugin, parse);
		bool bres = parse? parse (a->cur, data, str) : false;
		if (bres) {
			return str;
		}
		free (str);
	}
	return NULL;
}

// TODO: make it internal
R_API char *r_asm_parse_immtrim(RAsm *a, const char *_opstr) {
	R_RETURN_VAL_IF_FAIL (a && _opstr, NULL);
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
	RAsmPlugin *pcur = R_UNWRAP3 (a, cur, plugin);
	if (pcur && pcur->subvar) {
		return pcur->subvar (a->cur, f, addr, oplen, data, str, len);
	}
	return false;
}

/* radare2 - LGPL - Copyright 2009-2024 - nibble, pancake, maijin */

#include <r_asm.h>
#include <config.h>

R_LIB_VERSION (r_parse);

R_API RParse *r_parse_new(void) {
	RParse *p = R_NEW0 (RParse);
	p->minval = 0x100;
	return p;
}

R_API void r_parse_free(RParse *p) {
	free (p);
}

// TODO .make it internal?
R_API char *r_asm_parse_pseudo(RAsm *a, const char *data) {
	R_RETURN_VAL_IF_FAIL (a && data, false);
	RAsmParsePseudo parse = R_UNWRAP4 (a, cur, plugin, parse);
	return parse? parse (a->cur, data) : NULL;
}

// TODO: make it internal?
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

R_API char *r_asm_parse_immbase(RAsm *a, const char *_opstr, int base) {
	R_RETURN_VAL_IF_FAIL (a && _opstr && base > 1, NULL);
	if (R_STR_ISEMPTY (_opstr)) {
		return NULL;
	}
	char *opstr = strdup (_opstr);
	if (!opstr) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	char *p = opstr;
	char *last = opstr;
	while ((p = strstr (p, "$"))) {
		r_strbuf_append_n (sb, last, p - last);
		p++; // skip $
		char *end = p;
		ut64 num = strtoull (p, &end, 0);
		if (end != p) {
			char buf[64];
			if (base == 16) {
				snprintf (buf, sizeof (buf), "0x%"PFMT64x, num);
			} else if (base == 10) {
				snprintf (buf, sizeof (buf), "%"PFMT64u, num);
			} else if (base == 8) {
				snprintf (buf, sizeof (buf), "0%"PFMT64o, num);
			} else {
				r_strbuf_append_n (sb, p - 1, end - (p - 1));
				last = end;
				p = end;
				continue;
			}
			r_strbuf_append (sb, "$");
			r_strbuf_append (sb, buf);
			last = end;
			p = end;
		} else {
			p = end;
		}
	}
	r_strbuf_append (sb, last);
	return r_strbuf_drain (sb);
}

// TODO : make them internal?
R_API char *r_asm_parse_subvar(RAsm *a, RAnalFunction * R_NULLABLE f, ut64 addr, int oplen, const char *data) {
	R_RETURN_VAL_IF_FAIL (a, false);
	RAsmPlugin *pcur = R_UNWRAP3 (a, cur, plugin);
	if (pcur && pcur->subvar && data) {
		return pcur->subvar (a->cur, f, addr, oplen, data);
	}
	return NULL;
}

R_API char *r_asm_parse_patch(RAsm *a, RAnalOp *aop, const char *op) {
	R_RETURN_VAL_IF_FAIL (a, false);
	RAsmPlugin *pcur = R_UNWRAP3 (a, cur, plugin);
	if (pcur && pcur->patch) {
		return pcur->patch (a->cur, aop, op);
	}
	return NULL;
}

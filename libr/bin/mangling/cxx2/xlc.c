// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// IBM XL C++ legacy ABI demangler.
//
// This covers the classic XL-based AIX frontend (`xlC`, `xlc++`) symbols such
// as foo__Fv, f__1XFi and getAverage__7AverageFv.  The grammar is related to
// old cfront/ARM-style C++ mangling, but XL adds its own template and
// compressed-parameter forms.

#include <r_util.h>
#include "cxx2.h"
#include "cxx2_internal.h"

#define IBMXL_MAX_DEPTH 128
#define IBMXL_MAX_PARAMS 4096

typedef struct {
	const char *cur;
	const char *end;
	bool fail;
	int depth;
	char **params;
	int nparams;
	int cparams;
} IBMXLParser;

typedef enum {
	IBMXL_SYM_NORMAL,
	IBMXL_SYM_CTOR,
	IBMXL_SYM_DTOR,
	IBMXL_SYM_OPERATOR,
	IBMXL_SYM_CONV
} IBMXLSymKind;

static const CXX2Op ibmxl_ops[] = {
	{ "aa", "&&" }, { "aad", "&=" }, { "ad", "&" }, { "adv", "/=" },
	{ "aer", "^=" }, { "als", "<<=" }, { "amd", "%=" }, { "ami", "-=" },
	{ "aml", "*=" }, { "aor", "|=" }, { "apl", "+=" }, { "ars", ">>=" },
	{ "as", "=" }, { "cl", "()" }, { "cm", ", " }, { "co", "~" },
	{ "dl", " delete" }, { "dv", "/" }, { "eq", "==" }, { "er", "^" },
	{ "ge", ">=" }, { "gt", ">" }, { "le", "<=" }, { "ls", "<<" },
	{ "lt", "<" }, { "md", "%" }, { "mi", "-" }, { "ml", "*" },
	{ "mm", "--" }, { "ne", "!=" }, { "nt", "!" }, { "nw", " new" },
	{ "oo", "||" }, { "or", "|" }, { "pl", "+" }, { "pp", "++" },
	{ "pt", "->" }, { "rf", "->" }, { "rm", "->*" }, { "rs", ">>" },
	{ "sz", "sizeof " }, { "vc", "[]" }, { "vd", " delete[]" },
	{ "vn", " new[]" }, { NULL, NULL }
};

static void ibmxl_type(IBMXLParser *p, RStrBuf *out, const char *inner);
static char *ibmxl_type_string(IBMXLParser *p);
static char *ibmxl_name(IBMXLParser *p);

static inline char ibmxl_peek(IBMXLParser *p) {
	return p->cur < p->end ? *p->cur : 0;
}

static inline char ibmxl_peek2(IBMXLParser *p) {
	return p->cur + 1 < p->end ? p->cur[1] : 0;
}

static inline char ibmxl_take(IBMXLParser *p) {
	return p->cur < p->end ? *p->cur++ : 0;
}

static inline bool ibmxl_eat(IBMXLParser *p, char ch) {
	if (ibmxl_peek (p) == ch) {
		p->cur++;
		return true;
	}
	return false;
}

static bool ibmxl_startswith(IBMXLParser *p, const char *s) {
	size_t n = strlen (s);
	return (size_t)(p->end - p->cur) >= n && r_str_startswith (p->cur, s);
}

static bool ibmxl_name_start(char ch) {
	return isdigit ((unsigned char)ch) || ch == 'Q';
}

static bool ibmxl_declarator_type(char ch) {
	return ch == 'P' || ch == 'R' || ch == 'O' || ch == 'M' || ch == 'A' || ch == 'F';
}

static const char *ibmxl_builtin(char ch) {
	switch (ch) {
	case 'v': return "void";
	case 'i': return "int";
	case 'c': return "char";
	case 's': return "short";
	case 'l': return "long";
	case 'x': return "long long";
	case 'b': return "bool";
	case 'w': return "wchar_t";
	case 'f': return "float";
	case 'd': return "double";
	case 'r': return "long double";
	case 'e': return "...";
	}
	return NULL;
}

static int ibmxl_number(IBMXLParser *p) {
	if (!isdigit ((unsigned char)ibmxl_peek (p))) {
		return -1;
	}
	int n = 0;
	while (isdigit ((unsigned char)ibmxl_peek (p))) {
		if (n > (INT_MAX - 9) / 10) {
			p->fail = true;
			return -1;
		}
		n = n * 10 + (ibmxl_take (p) - '0');
	}
	return n;
}

static int ibmxl_source_len(IBMXLParser *p) {
	const char *start = p->cur;
	const char *bestp = NULL;
	int best = -1;
	int n = 0;
	if (!isdigit ((unsigned char)ibmxl_peek (p))) {
		return -1;
	}
	while (isdigit ((unsigned char)ibmxl_peek (p))) {
		if (n > (INT_MAX - 9) / 10) {
			p->fail = true;
			return -1;
		}
		n = n * 10 + (ibmxl_take (p) - '0');
		if (n > 0 && n <= p->end - p->cur) {
			best = n;
			bestp = p->cur;
		}
	}
	if (n > 0 && n <= p->end - p->cur) {
		return n;
	}
	if (best > 0) {
		p->cur = bestp;
		return best;
	}
	p->cur = start;
	return -1;
}

static int ibmxl_param_number(IBMXLParser *p) {
	int n = ibmxl_number (p);
	if (n < 0) {
		p->fail = true;
		return -1;
	}
	if (ibmxl_peek (p) == '_') {
		p->cur++;
	}
	return n;
}

static char *ibmxl_join_inner(const char *left, const char *right) {
	if (R_STR_ISEMPTY (right)) {
		return strdup (left);
	}
	return r_str_newf ("%s%s", left, right);
}

static char *ibmxl_inner_qual(const char *inner, const char *qual) {
	if (R_STR_ISEMPTY (inner)) {
		return r_str_newf (" %s", qual);
	}
	return r_str_newf (" %s %s", qual, inner);
}

static void ibmxl_terminal(RStrBuf *out, const char *base, const char *inner) {
	r_strbuf_append (out, base);
	if (R_STR_ISNOTEMPTY (inner)) {
		r_strbuf_append (out, " ");
		r_strbuf_append (out, inner);
	}
}

static void ibmxl_append_template_close(RStrBuf *out) {
	char *s = r_strbuf_get (out);
	size_t n = s ? strlen (s) : 0;
	r_strbuf_append (out, n > 0 && s[n - 1] == '>' ? " >" : ">");
}

static bool ibmxl_push_param(IBMXLParser *p, const char *s) {
	if (p->fail || !s) {
		return false;
	}
	if (!cxx2_strvec_push (&p->params, &p->nparams, &p->cparams, s, IBMXL_MAX_PARAMS)) {
		p->fail = true;
		return false;
	}
	return true;
}

static char *ibmxl_param_ref(IBMXLParser *p) {
	int idx = ibmxl_param_number (p);
	if (idx <= 0 || idx > p->nparams) {
		p->fail = true;
		return NULL;
	}
	return strdup (p->params[idx - 1]);
}

static char *ibmxl_template_value(IBMXLParser *p) {
	if (ibmxl_startswith (p, "SP") || ibmxl_startswith (p, "SN")) {
		bool neg = p->cur[1] == 'N';
		p->cur += 2;
		int n = ibmxl_number (p);
		if (n < 0) {
			p->fail = true;
			return NULL;
		}
		return r_str_newf ("%s%d", neg ? "-" : "", n);
	}
	if (ibmxl_startswith (p, "SM")) {
		p->cur += 2;
		return strdup ("<repeated>");
	}
	const char *start = p->cur;
	while (p->cur < p->end && ibmxl_peek (p) != '_') {
		p->cur++;
	}
	if (start == p->cur) {
		p->fail = true;
		return NULL;
	}
	return r_str_ndup (start, p->cur - start);
}

static char *ibmxl_template_arg(IBMXLParser *p, bool explicit_type_marker) {
	if (explicit_type_marker && ibmxl_peek (p) == 'T') {
		p->cur++;
		return ibmxl_type_string (p);
	}
	if (!explicit_type_marker) {
		if (ibmxl_startswith (p, "SP") || ibmxl_startswith (p, "SN") || ibmxl_startswith (p, "SM")) {
			return ibmxl_template_value (p);
		}
		return ibmxl_type_string (p);
	}
	if (ibmxl_startswith (p, "SP") || ibmxl_startswith (p, "SN") || ibmxl_startswith (p, "SM") || ibmxl_peek (p) == 'A') {
		if (ibmxl_peek (p) == 'A') {
			p->cur++;
			char *v = ibmxl_template_value (p);
			if (!v) {
				return NULL;
			}
			char *r = r_str_newf ("&%s", v);
			free (v);
			return r;
		}
		return ibmxl_template_value (p);
	}
	return ibmxl_template_value (p);
}

static char *ibmxl_template_args(IBMXLParser *p, bool explicit_type_marker) {
	RStrBuf *out = r_strbuf_new ("");
	r_strbuf_append (out, "<");
	int narg = 0;
	while (!p->fail && p->cur < p->end && ibmxl_peek (p) != '_') {
		char *arg = ibmxl_template_arg (p, explicit_type_marker);
		if (!arg) {
			p->fail = true;
			break;
		}
		if (narg++) {
			r_strbuf_append (out, ", ");
		}
		r_strbuf_append (out, arg);
		free (arg);
	}
	if (!ibmxl_eat (p, '_')) {
		p->fail = true;
	}
	ibmxl_append_template_close (out);
	return r_strbuf_drain (out);
}

static char *ibmxl_qualified(IBMXLParser *p) {
	if (!ibmxl_eat (p, 'Q')) {
		p->fail = true;
		return NULL;
	}
	int count = -1;
	if (ibmxl_eat (p, '_')) {
		count = ibmxl_number (p);
		if (!ibmxl_eat (p, '_')) {
			p->fail = true;
			return NULL;
		}
	} else if (isdigit ((unsigned char)ibmxl_peek (p))) {
		count = ibmxl_take (p) - '0';
		(void)ibmxl_eat (p, '_');
	}
	if (count <= 0 || count > 128) {
		p->fail = true;
		return NULL;
	}
	RStrBuf *out = r_strbuf_new ("");
	int i;
	for (i = 0; i < count && !p->fail; i++) {
		char *part = ibmxl_name (p);
		if (!part) {
			p->fail = true;
			break;
		}
		if (i) {
			r_strbuf_append (out, "::");
		}
		r_strbuf_append (out, part);
		free (part);
	}
	if (p->fail) {
		r_strbuf_free (out);
		return NULL;
	}
	return r_strbuf_drain (out);
}

static char *ibmxl_name(IBMXLParser *p) {
	if (p->fail || p->depth > IBMXL_MAX_DEPTH) {
		p->fail = true;
		return NULL;
	}
	p->depth++;
	char *res = NULL;
	if (ibmxl_peek (p) == 'Q') {
		res = ibmxl_qualified (p);
	} else {
		int n = ibmxl_source_len (p);
		if (n <= 0 || p->cur + n > p->end) {
			p->fail = true;
			goto out;
		}
		res = r_str_ndup (p->cur, n);
		p->cur += n;
		if (!res) {
			p->fail = true;
			goto out;
		}
		if (ibmxl_eat (p, 'X')) {
			char *args = ibmxl_template_args (p, true);
			if (args) {
				char *tmp = r_str_newf ("%s%s", res, args);
				free (res);
				free (args);
				res = tmp;
			}
		}
	}
out:
	p->depth--;
	return res;
}

static void ibmxl_type_qualified(IBMXLParser *p, RStrBuf *out, const char *inner) {
	RStrBuf *qb = r_strbuf_new ("");
	int nquals = 0;
	while (ibmxl_peek (p) == 'C' || ibmxl_peek (p) == 'V' || ibmxl_peek (p) == 'u') {
		char ch = ibmxl_take (p);
		if (nquals++) {
			r_strbuf_append (qb, " ");
		}
		r_strbuf_append (qb, ch == 'C' ? "const" : ch == 'V' ? "volatile" : "__restrict");
	}
	char *quals = r_strbuf_drain (qb);
	if (ibmxl_declarator_type (ibmxl_peek (p))) {
		char *ni = ibmxl_inner_qual (inner, quals);
		ibmxl_type (p, out, ni);
		free (ni);
	} else {
		RStrBuf *tb = r_strbuf_new ("");
		ibmxl_type (p, tb, inner);
		char *t = r_strbuf_drain (tb);
		if (t && *t) {
			r_strbuf_append (out, quals);
			r_strbuf_append (out, " ");
			r_strbuf_append (out, t);
		} else {
			p->fail = true;
		}
		free (t);
	}
	free (quals);
}

static char *ibmxl_args(IBMXLParser *p, bool stop_at_underscore) {
	RStrBuf *out = r_strbuf_new ("");
	int printed = 0;
	if (ibmxl_peek (p) == 'v' && (p->cur + 1 == p->end || (stop_at_underscore && p->cur[1] == '_'))) {
		p->cur++;
		return r_strbuf_drain (out);
	}
	while (!p->fail && p->cur < p->end) {
		if (stop_at_underscore && ibmxl_peek (p) == '_') {
			break;
		}
		char *arg = NULL;
		if (ibmxl_peek (p) == 'T') {
			p->cur++;
			arg = ibmxl_param_ref (p);
		} else if (ibmxl_peek (p) == 'N') {
			p->cur++;
			int count = isdigit ((unsigned char)ibmxl_peek (p)) ? ibmxl_take (p) - '0' : -1;
			char *ref = ibmxl_param_ref (p);
			if (count < 2 || count > 9 || !ref) {
				free (ref);
				p->fail = true;
				break;
			}
			int i;
			for (i = 0; i < count; i++) {
				if (printed++) {
					r_strbuf_append (out, ", ");
				}
				r_strbuf_append (out, ref);
				ibmxl_push_param (p, ref);
			}
			free (ref);
			continue;
		} else {
			arg = ibmxl_type_string (p);
		}
		if (!arg) {
			p->fail = true;
			break;
		}
		if (!strcmp (arg, "void") && !printed && (p->cur == p->end || (stop_at_underscore && ibmxl_peek (p) == '_'))) {
			free (arg);
			break;
		}
		if (printed++) {
			r_strbuf_append (out, ", ");
		}
		r_strbuf_append (out, arg);
		ibmxl_push_param (p, arg);
		free (arg);
	}
	if (p->fail) {
		r_strbuf_free (out);
		return NULL;
	}
	return r_strbuf_drain (out);
}

static void ibmxl_type(IBMXLParser *p, RStrBuf *out, const char *inner) {
	if (p->fail || p->depth > IBMXL_MAX_DEPTH) {
		p->fail = true;
		return;
	}
	p->depth++;
	char ch = ibmxl_peek (p);
	switch (ch) {
	case 'P':
	case 'R':
	case 'O': {
		p->cur++;
		const char *sign = ch == 'P' ? "*" : ch == 'R' ? "&" : "&&";
		char la = ibmxl_peek (p);
		bool wrap = la == 'F' || la == 'A' || la == 'M';
		char *ni = wrap
			? r_str_newf ("(%s%s)", sign, R_STR_ISNOTEMPTY (inner) ? inner : "")
			: ibmxl_join_inner (sign, R_STR_ISNOTEMPTY (inner) ? inner : "");
		ibmxl_type (p, out, ni);
		free (ni);
		break;
	}
	case 'C':
	case 'V':
	case 'u':
		ibmxl_type_qualified (p, out, inner);
		break;
	case 'U':
	case 'S':
	case 'J': {
		const char *prefix = ch == 'U' ? "unsigned" : ch == 'S' ? "signed" : "__complex";
		p->cur++;
		RStrBuf *tb = r_strbuf_new ("");
		ibmxl_type (p, tb, inner);
		char *t = r_strbuf_drain (tb);
		if (t && *t) {
			r_strbuf_append (out, prefix);
			r_strbuf_append (out, " ");
			r_strbuf_append (out, t);
		} else {
			p->fail = true;
		}
		free (t);
		break;
	}
	case 'A': {
		p->cur++;
		int n = ibmxl_number (p);
		(void)ibmxl_eat (p, '_');
		if (n < 0) {
			p->fail = true;
			break;
		}
		char *ni = r_str_newf ("%s[%d]", R_STR_ISNOTEMPTY (inner) ? inner : "", n);
		ibmxl_type (p, out, ni);
		free (ni);
		break;
	}
	case 'F': {
		p->cur++;
		char *args = ibmxl_args (p, true);
		if (!args || !ibmxl_eat (p, '_')) {
			free (args);
			p->fail = true;
			break;
		}
		char *ni = r_str_newf ("%s(%s)", R_STR_ISNOTEMPTY (inner) ? inner : "", args);
		free (args);
		ibmxl_type (p, out, ni);
		free (ni);
		break;
	}
	case 'M': {
		p->cur++;
		char *cls = ibmxl_name (p);
		if (!cls) {
			p->fail = true;
			break;
		}
		char *ni = r_str_newf ("%s::*%s", cls, R_STR_ISNOTEMPTY (inner) ? inner : "");
		free (cls);
		ibmxl_type (p, out, ni);
		free (ni);
		break;
	}
	case 'G':
	case 'Z':
		p->cur++;
		ibmxl_type (p, out, inner);
		break;
	default: {
		const char *bt = ibmxl_builtin (ch);
		if (bt) {
			p->cur++;
			ibmxl_terminal (out, bt, inner);
		} else if (ibmxl_name_start (ch)) {
			char *n = ibmxl_name (p);
			if (n) {
				ibmxl_terminal (out, n, inner);
				free (n);
			} else {
				p->fail = true;
			}
		} else {
			p->fail = true;
		}
		break;
	}
	}
	p->depth--;
}

static char *ibmxl_type_string(IBMXLParser *p) {
	RStrBuf *out = r_strbuf_new ("");
	ibmxl_type (p, out, "");
	if (p->fail) {
		r_strbuf_free (out);
		return NULL;
	}
	return r_strbuf_drain (out);
}

static char *ibmxl_basename(const char *name, bool strip_template) {
	if (!name) {
		return NULL;
	}
	const char *base = name;
	const char *p = name;
	const char *sep;
	while ((sep = strstr (p, "::"))) {
		base = sep + 2;
		p = sep + 2;
	}
	char *res = strdup (base);
	if (res && strip_template) {
		char *lt = strchr (res, '<');
		if (lt) {
			*lt = 0;
		}
	}
	return res;
}

static bool ibmxl_this_qual(IBMXLParser *p, bool *is_const, bool *is_volatile) {
	bool any = false;
	for (;;) {
		if ((ibmxl_peek (p) == 'C' || ibmxl_peek (p) == 'V') && ibmxl_name_start (ibmxl_peek2 (p))) {
			if (ibmxl_take (p) == 'C') {
				*is_const = true;
			} else {
				*is_volatile = true;
			}
			any = true;
			continue;
		}
		break;
	}
	return any;
}

static char *ibmxl_parse_signature(const char *root, IBMXLSymKind kind, const char *opspell, IBMXLParser *p) {
	bool is_method = false;
	bool cv_const = false;
	bool cv_volatile = false;
	bool function_template = false;
	char *tpl = NULL;
	char *cls = NULL;
	char *args = NULL;
	RStrBuf *out = r_strbuf_new ("");

	if (ibmxl_eat (p, 'H')) {
		function_template = true;
		tpl = ibmxl_template_args (p, false);
		if (p->fail) {
			goto fail;
		}
	}

	(void)ibmxl_this_qual (p, &cv_const, &cv_volatile);
	if (!function_template && ibmxl_eat (p, 'F')) {
		/* global function */
	} else if (!function_template && ibmxl_name_start (ibmxl_peek (p))) {
		is_method = true;
		cls = ibmxl_name (p);
		if (!cls) {
			goto fail;
		}
		while (ibmxl_peek (p) == 'C' || ibmxl_peek (p) == 'V') {
			if (ibmxl_take (p) == 'C') {
				cv_const = true;
			} else {
				cv_volatile = true;
			}
		}
		(void)ibmxl_eat (p, 'F');
	} else if (!function_template) {
		goto fail;
	}

	if (is_method) {
		r_strbuf_append (out, cls);
		r_strbuf_append (out, "::");
	}
	if (kind == IBMXL_SYM_CTOR) {
		if (!cls) {
			goto fail;
		}
		char *base = ibmxl_basename (cls, true);
		if (!base) {
			goto fail;
		}
		r_strbuf_append (out, base);
		free (base);
	} else if (kind == IBMXL_SYM_DTOR) {
		if (!cls) {
			goto fail;
		}
		char *base = ibmxl_basename (cls, true);
		if (!base) {
			goto fail;
		}
		r_strbuf_append (out, "~");
		r_strbuf_append (out, base);
		free (base);
	} else if (kind == IBMXL_SYM_OPERATOR) {
		r_strbuf_append (out, "operator");
		r_strbuf_append (out, opspell);
	} else if (kind == IBMXL_SYM_CONV) {
		r_strbuf_append (out, "operator ");
		r_strbuf_append (out, opspell);
	} else {
		r_strbuf_append (out, root);
		if (tpl) {
			r_strbuf_append (out, tpl);
		}
	}

	args = ibmxl_args (p, function_template);
	if (!args) {
		goto fail;
	}
	if (function_template && ibmxl_eat (p, '_')) {
		char *ret = ibmxl_type_string (p);
		free (ret);
	}
	if (p->fail || p->cur != p->end) {
		goto fail;
	}
	r_strbuf_append (out, "(");
	r_strbuf_append (out, args);
	r_strbuf_append (out, ")");
	if (cv_const) {
		r_strbuf_append (out, " const");
	}
	if (cv_volatile) {
		r_strbuf_append (out, " volatile");
	}

	free (tpl);
	free (cls);
	free (args);
	return r_strbuf_drain (out);

fail:
	free (tpl);
	free (cls);
	free (args);
	r_strbuf_free (out);
	return NULL;
}

static const char *ibmxl_find_sep(const char *s) {
	const char *p = s;
	while ((p = strstr (p, "__"))) {
		char ch = p[2];
		if (ch == 'F' || ch == 'H' || ch == 'C' || ch == 'V' || ch == 'Q' || isdigit ((unsigned char)ch)) {
			return p;
		}
		p += 2;
	}
	return NULL;
}

static char *ibmxl_special_vft(const char *s) {
	if (!r_str_startswith (s, "__vft")) {
		return NULL;
	}
	IBMXLParser p = {0};
	p.cur = s + 5;
	p.end = s + strlen (s);
	char *cls = ibmxl_name (&p);
	if (!cls || p.fail || p.cur != p.end) {
		free (cls);
		return NULL;
	}
	char *res = r_str_newf ("%s virtual function table", cls);
	free (cls);
	return res;
}

static char *ibmxl_parse(const char *s) {
	if (R_STR_ISEMPTY (s) || s[0] == '?' || r_str_startswith (s, "_Z") || r_str_startswith (s, "__Z")) {
		return NULL;
	}
	if (s[0] == '.') {
		s++;
	}

	char *vft = ibmxl_special_vft (s);
	if (vft) {
		return vft;
	}

	IBMXLParser p = {0};
	p.end = s + strlen (s);
	char *res = NULL;
	char *root = NULL;
	const char *sig = NULL;
	IBMXLSymKind kind = IBMXL_SYM_NORMAL;
	const char *opspell = NULL;

	if (s[0] == 'Q') {
		p.cur = s;
		res = ibmxl_name (&p);
		if (p.fail || p.cur != p.end) {
			R_FREE (res);
		}
		return res;
	}

	if (r_str_startswith (s, "__ct__")) {
		kind = IBMXL_SYM_CTOR;
		sig = s + 6;
	} else if (r_str_startswith (s, "__dt__")) {
		kind = IBMXL_SYM_DTOR;
		sig = s + 6;
	} else if (s[0] == '_' && s[1] == '_') {
		const char *sep = strstr (s + 2, "__");
		if (!sep || sep == s + 2) {
			return NULL;
		}
		const char *op = s + 2;
		size_t oplen = sep - op;
		if (oplen >= 2 && op[0] == 'o' && op[1] == 'p') {
			IBMXLParser tp = {0};
			tp.cur = op + 2;
			tp.end = sep;
			char *conv = ibmxl_type_string (&tp);
			if (!conv || tp.fail || tp.cur != tp.end) {
				free (conv);
				return NULL;
			}
			kind = IBMXL_SYM_CONV;
			opspell = conv;
			sig = sep + 2;
		} else {
				const CXX2Op *opinfo = cxx2_op_lookup (ibmxl_ops, op, oplen);
			if (!opinfo) {
				return NULL;
			}
			kind = IBMXL_SYM_OPERATOR;
			opspell = opinfo->spelling;
			sig = sep + 2;
		}
	} else {
		const char *sep = ibmxl_find_sep (s);
		if (!sep || sep == s) {
			return NULL;
		}
		root = r_str_ndup (s, sep - s);
		if (!root) {
			return NULL;
		}
		sig = sep + 2;
	}

	p.cur = sig;
	p.end = s + strlen (s);
	res = ibmxl_parse_signature (root, kind, opspell, &p);
	if (kind == IBMXL_SYM_CONV) {
		free ((char *)opspell);
	}
	free (root);
	cxx2_strvec_fini (&p.params, &p.nparams);
	if (res && !*res) {
		R_FREE (res);
	}
	return res;
}

char *r_demangle_ibmxl(const char *mangled) {
	return ibmxl_parse (mangled);
}

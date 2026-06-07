// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// ARM C++ ABI demangler: the pre-Itanium cfront/"Annotated C++ Reference
// Manual" mangling used by the ARM toolchains (ARM SDT, ADS, ARMCC, RVCT<4,
// Keil MDK) before they adopted the Itanium/Generic C++ ABI (_Z...). It is the
// "arm" style of the old libiberty cplus_demangle and is close to, but distinct
// from, the g++ 2.x "gnu" style:
//
//   - explicit "__ct__"/"__dt__" constructor/destructor markers
//   - an always-present 'F' before the argument list (even for members)
//   - 'S'/'C'/'V' member qualifiers printed as " static"/" const"/" volatile"
//   - "Q<count>_<names>" qualified (nested) names
//   - "<name>__pt__<len>_<args>" parameterized (template) types
//   - "__sti__"/"__std__" global constructor/destructor keys
//   - T<n> / N<count><index> back references, 1-based over the argument list
//
// No global state; types render with a C-declarator model so function pointers
// nest correctly. Recursion is bounded.

#include <r_util.h>
#include "cxx2.h"
#include "cxx2_internal.h"

#define ARM_MAX_DEPTH 200

typedef struct {
	const char *p;
	const char *end;
	bool fail;
	int depth;
	char **types; // typevec of argument type strings (1-based for T/N)
	int ntypes, captypes;
} ARM;

static void arm_type(ARM *c, RStrBuf *o, const char *inner);
static void arm_class(ARM *c, RStrBuf *o);

static inline char arm_peek(ARM *c) {
	return (c->p < c->end) ? *c->p : 0;
}

static inline char arm_take(ARM *c) {
	return (c->p < c->end) ? *c->p++ : 0;
}

static inline bool arm_eat(ARM *c, char ch) {
	if (arm_peek (c) == ch) {
		c->p++;
		return true;
	}
	return false;
}

static int arm_number(ARM *c) {
	if (!isdigit ((unsigned char)arm_peek (c))) {
		return -1;
	}
	int n = 0;
	while (isdigit ((unsigned char)arm_peek (c))) {
		if (n > (INT_MAX - 9) / 10) {
			c->fail = true;
			return -1;
		}
		n = n * 10 + (arm_take (c) - '0');
	}
	return n;
}

static void arm_push_type(ARM *c, const char *s) {
	if (c->fail || !s) {
		return;
	}
	if (!cxx2_strvec_push (&c->types, &c->ntypes, &c->captypes, s, 0)) {
		c->fail = true;
	}
}

static void arm_truncate_types(ARM *c, int n) {
	cxx2_strvec_truncate (c->types, &c->ntypes, n);
}

// ---------------------------------------------------------------------------
// operators
// ---------------------------------------------------------------------------

static const CXX2Op arm_ops[] = {
	{ "aa", "&&" }, { "aad", "&=" }, { "ad", "&" }, { "adv", "/=" },
	{ "aer", "^=" }, { "als", "<<=" }, { "amd", "%=" }, { "ami", "-=" },
	{ "aml", "*=" }, { "amu", "*=" }, { "aor", "|=" }, { "apl", "+=" },
	{ "ars", ">>=" }, { "as", "=" }, { "cl", "()" }, { "cm", ", " },
	{ "co", "~" }, { "dl", " delete" }, { "dv", "/" }, { "eq", "==" },
	{ "er", "^" }, { "ge", ">=" }, { "gt", ">" }, { "le", "<=" },
	{ "ls", "<<" }, { "lt", "<" }, { "md", "%" }, { "mi", "-" },
	{ "ml", "*" }, { "mm", "--" }, { "ne", "!=" }, { "nt", "!" },
	{ "nw", " new" }, { "oo", "||" }, { "or", "|" }, { "pl", "+" },
	{ "pp", "++" }, { "rf", "->" }, { "rm", "->*" }, { "rs", ">>" },
	{ "vc", "[]" }, { "vd", " delete[]" }, { "vn", " new[]" },
	{ NULL, NULL }
};

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

static const char *arm_builtin(char ch) {
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

// parse the "<name>__pt__<len>_<args>" template tail of a class whose name
// region is [name, name+namelen). `base` is the part before "__pt__".
static void arm_template(ARM *c, RStrBuf *o, const char *base, int baselen,
		const char *pt, const char *name_end) {
	r_strbuf_append_n (o, base, baselen);
	// pt points at "__pt__"; advance the cursor there to parse from the region
	const char *saved_p = c->p;
	const char *saved_end = c->end;
	c->p = pt + 6; // skip "__pt__"
	c->end = name_end;
	int len = arm_number (c); // length of the "_<args>" block
	(void)len;
	(void)arm_eat (c, '_'); // leading underscore of the block
	r_strbuf_append (o, "<");
	int saved_types = c->ntypes; // template args do not leak into the arg list
	int i = 0;
	while (!c->fail && c->p < name_end) {
		if (i++) {
			r_strbuf_append (o, ", ");
		}
		arm_type (c, o, "");
	}
	arm_truncate_types (c, saved_types);
	// avoid ">>"
	char *cur = r_strbuf_get (o);
	int cl = cur ? (int)strlen (cur) : 0;
	r_strbuf_append (o, (cl > 0 && cur[cl - 1] == '>') ? " >" : ">");
	c->p = saved_p;
	c->end = saved_end;
}

// emit a length-prefixed name, handling an embedded "__pt__" template
static void arm_simple_name(ARM *c, RStrBuf *o) {
	if (arm_peek (c) == '0') {
		c->fail = true; // a length never has a leading zero
		return;
	}
	int n = arm_number (c);
	if (n <= 0 || c->p + n > c->end) {
		c->fail = true;
		return;
	}
	const char *name = c->p;
	const char *name_end = name + n;
	// search for "__pt__" inside the name region
	const char *pt = NULL;
	const char *q;
	for (q = name; q + 6 <= name_end; q++) {
		if (!strncmp (q, "__pt__", 6)) {
			pt = q;
			break;
		}
	}
	if (pt) {
		arm_template (c, o, name, (int)(pt - name), pt, name_end);
	} else {
		r_strbuf_append_n (o, name, n);
	}
	c->p = name_end;
}

// <class> ::= <simple-name> | Q <count> _ <simple-name>+
static void arm_class(ARM *c, RStrBuf *o) {
	if (c->fail || c->depth > ARM_MAX_DEPTH) {
		c->fail = true;
		return;
	}
	c->depth++;
	if (arm_peek (c) == 'Q') {
		c->p++;
		int count = isdigit ((unsigned char)arm_peek (c)) ? (arm_take (c) - '0') : -1;
		(void)arm_eat (c, '_');
		int i;
		for (i = 0; i < count && !c->fail; i++) {
			if (i) {
				r_strbuf_append (o, "::");
			}
			arm_simple_name (c, o);
		}
	} else {
		arm_simple_name (c, o);
	}
	c->depth--;
}

static void arm_terminal(RStrBuf *o, const char *base, const char *inner) {
	r_strbuf_append (o, base);
	if (R_STR_ISNOTEMPTY (inner)) {
		r_strbuf_append (o, " ");
		r_strbuf_append (o, inner);
	}
}

// <type> rendered with the declarator string `inner`
static void arm_type(ARM *c, RStrBuf *o, const char *inner) {
	if (c->fail || c->depth > ARM_MAX_DEPTH) {
		c->fail = true;
		return;
	}
	c->depth++;
	char ch = arm_peek (c);
	switch (ch) {
	case 'P': case 'R': case 'O': {
		c->p++;
		if (ch == 'P' && arm_peek (c) == 'M') {
			arm_type (c, o, inner); // pointer-to-member: M supplies "class::*"
			break;
		}
		const char *sign = (ch == 'P') ? "*" : (ch == 'R') ? "&" : "&&";
		char la = arm_peek (c);
		bool wrap = (la == 'F' || la == 'A');
		char *ni = wrap
			? r_str_newf ("(%s%s)", sign, inner ? inner : "")
			: r_str_newf ("%s%s", sign, inner ? inner : "");
		arm_type (c, o, ni);
		free (ni);
		break;
	}
	case 'U':
		c->p++;
		r_strbuf_append (o, "unsigned ");
		arm_type (c, o, inner);
		break;
	case 'S':
		c->p++;
		r_strbuf_append (o, "signed ");
		arm_type (c, o, inner);
		break;
	case 'C': case 'V': {
		const char *q = (ch == 'C') ? "const" : "volatile";
		c->p++;
		char *ni = (inner && *inner) ? r_str_newf ("%s %s", q, inner) : strdup (q);
		arm_type (c, o, ni);
		free (ni);
		break;
	}
	case 'F': { // function type: F <args> _ <return>
		c->p++;
		RStrBuf *ab = r_strbuf_new ("");
		int i = 0;
		bool any = false;
		while (!c->fail && arm_peek (c) && arm_peek (c) != '_') {
			if (i++) {
				r_strbuf_append (ab, ", ");
			}
			arm_type (c, ab, "");
			any = true;
		}
		(void)arm_eat (c, '_');
		char *args = r_strbuf_drain (ab);
		char *ni = r_str_newf ("%s(%s)", inner ? inner : "", any ? args : "void");
		arm_type (c, o, ni);
		free (ni);
		free (args);
		break;
	}
	case 'A': { // array: A <number> _ <type>
		c->p++;
		int n = arm_number (c);
		(void)arm_eat (c, '_');
		char *ni = r_str_newf ("%s[%d]", inner ? inner : "", n);
		arm_type (c, o, ni);
		free (ni);
		break;
	}
	case 'M': { // pointer to member: M <class> <type>
		c->p++;
		RStrBuf *cb = r_strbuf_new ("");
		arm_class (c, cb);
		char *cls = r_strbuf_drain (cb);
		bool fn = (arm_peek (c) == 'F');
		char *ni = fn
			? r_str_newf ("(%s::*%s)", cls, inner ? inner : "")
			: r_str_newf ("%s::*%s", cls, inner ? inner : "");
		arm_type (c, o, ni);
		free (ni);
		free (cls);
		break;
	}
	case 'T': { // back reference: T<index>  (single digit, 1-based)
		c->p++;
		int idx = isdigit ((unsigned char)arm_peek (c)) ? (arm_take (c) - '0') : -1;
		if (idx >= 1 && idx <= c->ntypes) {
			arm_terminal (o, c->types[idx - 1], inner);
		} else {
			c->fail = true;
		}
		break;
	}
	default: {
		const char *bt = arm_builtin (ch);
		if (bt) {
			c->p++;
			arm_terminal (o, bt, inner);
		} else if (isdigit ((unsigned char)ch) || ch == 'Q') {
			RStrBuf *cb = r_strbuf_new ("");
			arm_class (c, cb);
			char *cls = r_strbuf_drain (cb);
			arm_terminal (o, r_str_get (cls), inner);
			free (cls);
		} else {
			c->fail = true;
		}
		break;
	}
	}
	c->depth--;
}

// the argument list, remembering each top-level type for T/N (1-based)
static void arm_args(ARM *c, RStrBuf *o) {
	int printed = 0;
	while (!c->fail && arm_peek (c) && arm_peek (c) != '_') {
		char ch = arm_peek (c);
		if (ch == 'T') {
			c->p++;
			int idx = isdigit ((unsigned char)arm_peek (c)) ? (arm_take (c) - '0') : -1;
			if (idx < 1 || idx > c->ntypes) {
				c->fail = true;
				break;
			}
			if (printed++) {
				r_strbuf_append (o, ", ");
			}
			r_strbuf_append (o, c->types[idx - 1]);
			arm_push_type (c, c->types[idx - 1]);
			continue;
		}
		if (ch == 'N') { // N <count> <index> : count is 1 digit, index multi-digit
			c->p++;
			int count = isdigit ((unsigned char)arm_peek (c)) ? (arm_take (c) - '0') : -1;
			int idx = arm_number (c);
			if (count < 0 || idx < 1 || idx > c->ntypes) {
				c->fail = true;
				break;
			}
			int k;
			for (k = 0; k < count; k++) {
				if (printed++) {
					r_strbuf_append (o, ", ");
				}
				r_strbuf_append (o, c->types[idx - 1]);
				arm_push_type (c, c->types[idx - 1]);
			}
			continue;
		}
		RStrBuf *tb = r_strbuf_new ("");
		arm_type (c, tb, "");
		char *t = r_strbuf_drain (tb);
		if (c->fail) {
			free (t);
			break;
		}
		arm_push_type (c, t);
		if (printed++) {
			r_strbuf_append (o, ", ");
		}
		r_strbuf_append (o, t);
		free (t);
	}
	if (!printed) {
		r_strbuf_append (o, "void");
	}
}

// ---------------------------------------------------------------------------
// entry
// ---------------------------------------------------------------------------

char *r_demangle_arm(const char *mangled) {
	if (R_STR_ISEMPTY (mangled)) {
		return NULL;
	}
	const char *s = mangled;
	// global constructors/destructors
	if (r_str_startswith (s, "__sti__")) {
		return r_str_newf ("global constructors keyed to %s", s + 7);
	}
	if (r_str_startswith (s, "__std__")) {
		return r_str_newf ("global destructors keyed to %s", s + 7);
	}
	// virtual table: __vtbl__<class>
	if (r_str_startswith (s, "__vtbl__")) {
		ARM t = {0};
		t.p = s + 8;
		t.end = s + strlen (s);
		RStrBuf *o = r_strbuf_new ("");
		arm_class (&t, o);
		char *res = NULL;
		if (!t.fail && t.p == t.end) {
			r_strbuf_append (o, " virtual table");
			res = r_strbuf_drain (o);
		} else {
			r_strbuf_free (o);
		}
			cxx2_strvec_fini (&t.types, &t.ntypes);
			return res;
	}

	ARM c = {0};
	c.end = s + strlen (s);
	RStrBuf *o = r_strbuf_new ("");
	RStrBuf *cls = NULL;
	const char *name = NULL;
	int namelen = 0;
	bool is_ctor = false, is_dtor = false, is_op = false;
	const char *opspell = NULL;

	if (s[0] == '_' && s[1] == '_' && islower ((unsigned char)s[2])) {
		// __<opcode>__<signature>
		const char *op = s + 2;
		const char *sep = strstr (op, "__");
		if (!sep) {
			r_strbuf_free (o);
			return NULL;
		}
		size_t oplen = sep - op;
		if (oplen == 2 && !strncmp (op, "ct", 2)) {
			is_ctor = true;
		} else if (oplen == 2 && !strncmp (op, "dt", 2)) {
			is_dtor = true;
		} else {
			const CXX2Op *opinfo = cxx2_op_lookup (arm_ops, op, oplen);
			if (opinfo) {
				opspell = opinfo->spelling;
			}
			if (!opspell) {
				r_strbuf_free (o);
				return NULL;
			}
			is_op = true;
		}
		c.p = sep + 2;
	} else {
		// <name>__<signature>
		const char *sep = NULL;
		const char *q = s;
		while ((q = strstr (q, "__"))) {
			char a = q[2];
			if (q > s && (a == 'F' || a == 'Q' || isdigit ((unsigned char)a))) {
				sep = q;
				break;
			}
			q += 1;
		}
		if (!sep) {
			r_strbuf_free (o);
			return NULL;
		}
		name = s;
		namelen = (int)(sep - s);
		c.p = sep + 2;
	}

	// optional class (member), else 'F' marks a free function
	bool member = (arm_peek (&c) != 'F');
	if (member) {
		cls = r_strbuf_new ("");
		arm_class (&c, cls);
	}
	// member qualifiers: C const, V volatile, S static (any order)
	bool q_const = false, q_vol = false, q_static = false;
	for (;;) {
		char ch = arm_peek (&c);
		if (ch == 'C') { q_const = true; c.p++; }
		else if (ch == 'V') { q_vol = true; c.p++; }
		else if (ch == 'S') { q_static = true; c.p++; }
		else break;
	}
	bool has_args = arm_eat (&c, 'F');

	if (c.fail) {
		goto fail;
	}

	// emit the qualified name
	if (member && cls) {
		char *cs = r_strbuf_drain (cls);
		cls = NULL;
			r_strbuf_append (o, cs);
			r_strbuf_append (o, "::");
			if (is_ctor || is_dtor) {
				char *bn = cxx2_basename (cs);
				if (!bn) {
					free (cs);
					goto fail;
				}
				if (is_dtor) {
					r_strbuf_append (o, "~");
				}
				r_strbuf_append (o, bn);
				free (bn);
			} else if (is_op) {
			r_strbuf_appendf (o, "operator%s", opspell);
		} else {
			r_strbuf_append_n (o, name, namelen);
		}
		free (cs);
	} else {
		if (is_op) {
			r_strbuf_appendf (o, "operator%s", opspell);
		} else if (name) {
			r_strbuf_append_n (o, name, namelen);
		} else {
			goto fail; // ctor/dtor without a class
		}
	}

	if (has_args) {
		r_strbuf_append (o, "(");
		arm_args (&c, o);
		r_strbuf_append (o, ")");
	}
	// member qualifier suffixes
	if (q_const) {
		r_strbuf_append (o, " const");
	}
	if (q_vol) {
		r_strbuf_append (o, " volatile");
	}
	if (q_static) {
		r_strbuf_append (o, " static");
	}

	// a valid ARM symbol is fully consumed; a leftover tail means we mis-read a
	// differently-mangled (e.g. g++ v2) name, so reject it.
	if (c.fail || c.p != c.end) {
		goto fail;
	}
	char *res = r_strbuf_drain (o);
	o = NULL;
		cxx2_strvec_fini (&c.types, &c.ntypes);
		if (res && !*res) {
			free (res);
			res = NULL;
	}
	return res;
fail:
	r_strbuf_free (o);
	r_strbuf_free (cls);
	cxx2_strvec_fini (&c.types, &c.ntypes);
	return NULL;
}

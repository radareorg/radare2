// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// GNU v2 C++ demangler: the pre-Itanium g++ 2.x ABI (a.k.a. the "gnu" style of
// the old libiberty cplus_demangle). Names look like `foo__1Ai`, `__ls__3fooi`,
// `_$_3foo`, `printf__FPCce`. There is no global state; types are rendered with
// a C-declarator model so that function pointers nest correctly. The type
// vector (typevec) backs the T<n> / N<count><index> back references.

#include <r_util.h>
#include "cxx2.h"

#define GV2_MAX_DEPTH 200

typedef struct {
	const char *p;
	const char *end;
	bool fail;
	int depth;
	char **types; // typevec of rendered type strings (slot 0 = class for methods)
	int ntypes, captypes;
} GV2;

static void gv2_type(GV2 *c, RStrBuf *o, const char *inner);
static void gv2_class(GV2 *c, RStrBuf *o);

static inline char gv2_peek(GV2 *c) {
	return (c->p < c->end) ? *c->p : 0;
}

static inline char gv2_take(GV2 *c) {
	return (c->p < c->end) ? *c->p++ : 0;
}

static inline bool gv2_eat(GV2 *c, char ch) {
	if (gv2_peek (c) == ch) {
		c->p++;
		return true;
	}
	return false;
}

static int gv2_number(GV2 *c) {
	if (!isdigit ((unsigned char)gv2_peek (c))) {
		return -1;
	}
	int n = 0;
	while (isdigit ((unsigned char)gv2_peek (c))) {
		if (n > (INT_MAX - 9) / 10) {
			c->fail = true;
			return -1;
		}
		n = n * 10 + (gv2_take (c) - '0');
	}
	return n;
}

static void gv2_push_type(GV2 *c, const char *s) {
	if (c->fail || !s) {
		return;
	}
	if (c->ntypes == c->captypes) {
		int ncap = c->captypes ? c->captypes * 2 : 8;
		char **nt = realloc (c->types, ncap * sizeof (char *));
		if (!nt) {
			c->fail = true;
			return;
		}
		c->types = nt;
		c->captypes = ncap;
	}
	c->types[c->ntypes++] = strdup (s);
}

// ---------------------------------------------------------------------------
// operators
// ---------------------------------------------------------------------------

typedef struct {
	const char *code;
	const char *spelling; // appended after "operator"
} Gv2Op;

static const Gv2Op gv2_ops[] = {
	{ "aa", "&&" }, { "aad", "&=" }, { "ad", "&" }, { "adv", "/=" },
	{ "aer", "^=" }, { "als", "<<=" }, { "amd", "%=" }, { "ami", "-=" },
	{ "aml", "*=" }, { "aor", "|=" }, { "apl", "+=" }, { "ars", ">>=" },
	{ "as", "=" }, { "cl", "()" }, { "cm", ", " }, { "co", "~" },
	{ "dl", " delete" }, { "dv", "/" }, { "eq", "==" }, { "er", "^" },
	{ "ge", ">=" }, { "gt", ">" }, { "le", "<=" }, { "ls", "<<" },
	{ "lt", "<" }, { "md", "%" }, { "mi", "-" }, { "ml", "*" },
	{ "mm", "--" }, { "ne", "!=" }, { "nt", "!" }, { "nw", " new" },
	{ "oo", "||" }, { "or", "|" }, { "pl", "+" }, { "pp", "++" },
	{ "rf", "->" }, { "rm", "->*" }, { "rs", ">>" }, { "vc", "[]" },
	{ "vd", " delete[]" }, { "vn", " new[]" }, { "pt", "->*" },
	{ "mn", "<?" }, { "mx", ">?" }, { "md", "%" }, { "sz", "sizeof" },
	{ NULL, NULL }
};

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

static const char *gv2_builtin(char ch) {
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

// a template integral value: [_] [m] <digits> [_]   (m = minus, _ wraps)
static void gv2_value(GV2 *c, RStrBuf *o) {
	(void)gv2_eat (c, '_'); // optional wrapper open
	bool neg = gv2_eat (c, 'm');
	int v = gv2_number (c);
	(void)gv2_eat (c, '_'); // optional wrapper close / terminator
	r_strbuf_appendf (o, "%s%d", neg ? "-" : "", v < 0 ? 0 : v);
}

// <class> ::= <number> <name> | Q <count> <name>+ | t <template>
static void gv2_class(GV2 *c, RStrBuf *o) {
	if (c->fail || c->depth > GV2_MAX_DEPTH) {
		c->fail = true;
		return;
	}
	c->depth++;
	char ch = gv2_peek (c);
	if (ch == 'Q') {
		c->p++;
		int count;
		if (gv2_eat (c, '_')) { // Q_<count>_ for >= 10 components
			count = gv2_number (c);
			(void)gv2_eat (c, '_');
		} else {
			count = isdigit ((unsigned char)gv2_peek (c)) ? (gv2_take (c) - '0') : -1;
		}
		int i;
		for (i = 0; i < count && !c->fail; i++) {
			if (i) {
				r_strbuf_append (o, "::");
			}
			gv2_class (c, o);
		}
	} else if (ch == 't') {
		// t <name-len> <name> <argcount> <args>
		c->p++;
		int nl = gv2_number (c);
		if (nl > 0 && c->p + nl <= c->end) {
			r_strbuf_append_n (o, c->p, nl);
			c->p += nl;
		} else {
			c->fail = true;
		}
		int argc = isdigit ((unsigned char)gv2_peek (c)) ? (gv2_take (c) - '0') : -1;
		r_strbuf_append (o, "<");
		int i;
		for (i = 0; i < argc && !c->fail; i++) {
			if (i) {
				r_strbuf_append (o, ", ");
			}
			if (gv2_eat (c, 'Z')) {
				gv2_type (c, o, "");
			} else {
				// value parameter: <type> <value>
				RStrBuf *tb = r_strbuf_new ("");
				gv2_type (c, tb, "");
				r_strbuf_free (tb);
				gv2_value (c, o);
			}
		}
		// avoid ">>"
		char *cur = r_strbuf_get (o);
		int cl = cur ? (int)strlen (cur) : 0;
		r_strbuf_append (o, (cl > 0 && cur[cl - 1] == '>') ? " >" : ">");
	} else if (gv2_peek (c) == '0') {
		c->fail = true; // a length never has a leading zero (rejects C/JNI names)
	} else {
		int n = gv2_number (c);
		if (n > 0 && c->p + n <= c->end) {
			r_strbuf_append_n (o, c->p, n);
			c->p += n;
		} else {
			c->fail = true;
		}
	}
	c->depth--;
}

// emit `base` followed by the declarator `inner` (with a separating space)
static void gv2_terminal(RStrBuf *o, const char *base, const char *inner) {
	r_strbuf_append (o, base);
	if (R_STR_ISNOTEMPTY (inner)) {
		r_strbuf_append (o, " ");
		r_strbuf_append (o, inner);
	}
}

// <type> rendered with the declarator string `inner`
static void gv2_type(GV2 *c, RStrBuf *o, const char *inner) {
	if (c->fail || c->depth > GV2_MAX_DEPTH) {
		c->fail = true;
		return;
	}
	c->depth++;
	char ch = gv2_peek (c);
	switch (ch) {
	case 'P': case 'R': case 'O': { // pointer / lvalue ref / rvalue ref
		c->p++;
		// a pointer-to-member is encoded "PM...": let M supply the "class::*"
		if (ch == 'P' && gv2_peek (c) == 'M') {
			gv2_type (c, o, inner);
			break;
		}
		const char *sign = (ch == 'P') ? "*" : (ch == 'R') ? "&" : "&&";
		char la = gv2_peek (c);
		bool wrap = (la == 'F' || la == 'A');
		char *ni = wrap
			? r_str_newf ("(%s%s)", sign, inner ? inner : "")
			: r_str_newf ("%s%s", sign, inner ? inner : "");
		gv2_type (c, o, ni);
		free (ni);
		break;
	}
	case 'U': // unsigned
		c->p++;
		r_strbuf_append (o, "unsigned ");
		gv2_type (c, o, inner);
		break;
	case 'S': // signed
		c->p++;
		r_strbuf_append (o, "signed ");
		gv2_type (c, o, inner);
		break;
	case 'C': case 'V': { // east-const/volatile qualifier on the following type
		const char *q = (ch == 'C') ? "const" : "volatile";
		c->p++;
		// "const" sits right after the base; any outer declarator follows it
		char *ni = (inner && *inner) ? r_str_newf ("%s %s", q, inner) : strdup (q);
		gv2_type (c, o, ni);
		free (ni);
		break;
	}
	case 'F': { // function type: F <args> _ <return>
		c->p++;
		RStrBuf *ab = r_strbuf_new ("");
		// parameter list
		int i = 0;
		bool any = false;
		while (!c->fail && gv2_peek (c) && gv2_peek (c) != '_') {
			if (i++) {
				r_strbuf_append (ab, ", ");
			}
			gv2_type (c, ab, "");
			any = true;
		}
		(void)gv2_eat (c, '_');
		char *args = r_strbuf_drain (ab);
		char *ni = r_str_newf ("%s(%s)", inner ? inner : "", any ? args : "void");
		gv2_type (c, o, ni); // return type
		free (ni);
		free (args);
		break;
	}
	case 'A': { // array: A <number> _ <type>
		c->p++;
		int n = gv2_number (c);
		(void)gv2_eat (c, '_');
		char *ni = r_str_newf ("%s[%d]", inner ? inner : "", n);
		gv2_type (c, o, ni);
		free (ni);
		break;
	}
	case 'M': { // pointer to member: M <class> <type>  ->  T (class::*) ...
		c->p++;
		RStrBuf *cb = r_strbuf_new ("");
		gv2_class (c, cb);
		char *cls = r_strbuf_drain (cb);
		bool fn = (gv2_peek (c) == 'F');
		char *ni = fn
			? r_str_newf ("(%s::*%s)", cls, inner ? inner : "")
			: r_str_newf ("%s::*%s", cls, inner ? inner : "");
		gv2_type (c, o, ni);
		free (ni);
		free (cls);
		break;
	}
	case 'G': // explicit struct/class type marker
		c->p++;
		gv2_type (c, o, inner);
		break;
	case 'T': { // back reference: T<index>  (0-based into typevec)
		c->p++;
		int idx = isdigit ((unsigned char)gv2_peek (c)) ? (gv2_take (c) - '0') : -1;
		if (idx >= 0 && idx < c->ntypes) {
			gv2_terminal (o, c->types[idx], inner);
		} else {
			c->fail = true;
		}
		break;
	}
	default: {
		const char *bt = gv2_builtin (ch);
		if (bt) {
			c->p++;
			gv2_terminal (o, bt, inner);
		} else if (isdigit ((unsigned char)ch) || ch == 'Q' || ch == 't') {
			RStrBuf *cb = r_strbuf_new ("");
			gv2_class (c, cb);
			char *cls = r_strbuf_drain (cb);
			gv2_terminal (o, r_str_get (cls), inner);
			free (cls);
		} else {
			c->fail = true;
		}
		break;
	}
	}
	c->depth--;
}

// Render the argument list into `o`. Each top-level argument is remembered in
// the typevec so that T<n> and N<count><index> can reference it.
static void gv2_args(GV2 *c, RStrBuf *o) {
	int printed = 0;
	while (!c->fail && gv2_peek (c) && gv2_peek (c) != '_') {
		char ch = gv2_peek (c);
		if (ch == 'T') { // single back reference
			c->p++;
			int idx = isdigit ((unsigned char)gv2_peek (c)) ? (gv2_take (c) - '0') : -1;
			if (idx < 0 || idx >= c->ntypes) {
				c->fail = true;
				break;
			}
			if (printed++) {
				r_strbuf_append (o, ", ");
			}
			r_strbuf_append (o, c->types[idx]);
			gv2_push_type (c, c->types[idx]);
			continue;
		}
		if (ch == 'N') { // N <count> <index> : repeat a type count times
			c->p++;
			int count = isdigit ((unsigned char)gv2_peek (c)) ? (gv2_take (c) - '0') : -1;
			int idx = isdigit ((unsigned char)gv2_peek (c)) ? (gv2_take (c) - '0') : -1;
			if (count < 0 || idx < 0 || idx >= c->ntypes) {
				c->fail = true;
				break;
			}
			int k;
			for (k = 0; k < count; k++) {
				if (printed++) {
					r_strbuf_append (o, ", ");
				}
				r_strbuf_append (o, c->types[idx]);
				gv2_push_type (c, c->types[idx]);
			}
			continue;
		}
		// a regular argument: render to a string, remember it, emit it
		RStrBuf *tb = r_strbuf_new ("");
		gv2_type (c, tb, "");
		char *t = r_strbuf_drain (tb);
		if (c->fail) {
			free (t);
			break;
		}
		gv2_push_type (c, t);
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
// entry / top-level structure
// ---------------------------------------------------------------------------

// the last top-level "::"-separated component of an already-rendered qualified
// name, with any template-argument list stripped (for ctor/dtor names): e.g.
// "List<X>::Pix" -> "Pix", "vector<int>" -> "vector". Writes into `out`.
static void gv2_basename(const char *qual, char *out, size_t outsz) {
	const char *base = qual, *p;
	int d = 0;
	for (p = qual; *p; p++) {
		if (*p == '<') {
			d++;
		} else if (*p == '>') {
			d--;
		} else if (d == 0 && p[0] == ':' && p[1] == ':') {
			base = p + 2;
			p++;
		}
	}
	size_t n = 0;
	d = 0;
	for (p = base; *p && n + 1 < outsz; p++) {
		if (*p == '<' && d == 0) {
			break;
		}
		out[n++] = *p;
	}
	out[n] = 0;
}

// Demangle the special "_vt$foo$bar" / "_vt.foo.bar" virtual-table symbols.
static char *gv2_vtable(const char *s) {
	const char *p = s;
	if (r_str_startswith (p, "_vt$") || r_str_startswith (p, "_vt.")) {
		p += 4;
	} else if (r_str_startswith (p, "__vt_")) {
		p += 5;
	} else {
		return NULL;
	}
	RStrBuf *o = r_strbuf_new ("");
	bool first = true;
	while (*p) {
		const char *e = p;
		while (*e && *e != '$' && *e != '.') {
			e++;
		}
		if (!first) {
			r_strbuf_append (o, "::");
		}
		first = false;
		// a component may be a mangled (template) class or a raw identifier
		if (*p == 't' && isdigit ((unsigned char)p[1])) {
			GV2 t = {0};
			t.p = p;
			t.end = e;
			gv2_class (&t, o);
			free (t.types);
			if (t.fail) {
				r_strbuf_free (o);
				return NULL;
			}
		} else {
			r_strbuf_append_n (o, p, e - p);
		}
		p = (*e) ? e + 1 : e;
	}
	r_strbuf_append (o, " virtual table");
	return r_strbuf_drain (o);
}

// _GLOBAL_$<I|D>$<name> : global constructors/destructors keyed to a name
static char *gv2_global(const char *s) {
	if (!r_str_startswith (s, "_GLOBAL_")) {
		return NULL;
	}
	const char *p = s + 8;
	char kind = 0;
	if (p[0] == '$' && p[2] == '$') {
		kind = p[1];
		p += 3;
	} else if (p[0] == '.' && p[2] == '.') {
		kind = p[1];
		p += 3;
	} else if (p[0] == '_' && p[2] == '_') {
		kind = p[1];
		p += 3;
	} else {
		return NULL;
	}
	const char *what = (kind == 'I') ? "constructors" : (kind == 'D') ? "destructors" : NULL;
	if (!what) {
		return NULL;
	}
	return r_str_newf ("global %s keyed to %s", what, p);
}

char *r_demangle_gnu_v2(const char *mangled) {
	if (R_STR_ISEMPTY (mangled)) {
		return NULL;
	}
	const char *s = mangled;
	// strip a single leading underscore on platforms that add one
	if (s[0] == '_' && s[1] == '_' && (isalpha ((unsigned char)s[2]) || isdigit ((unsigned char)s[2]) || s[2] == 'Q')) {
		// keep: leading __ is meaningful (ctor/operator)
	}

	// virtual tables
	if (r_str_startswith (s, "_vt")) {
		return gv2_vtable (s);
	}
	// global constructors/destructors
	if (r_str_startswith (s, "_GLOBAL_")) {
		return gv2_global (s);
	}
	// type_info function (__tf<type>) / type_info node (__ti<type>)
	if ((r_str_startswith (s, "__tf") || r_str_startswith (s, "__ti")) && s[4]) {
		GV2 t = {0};
		t.p = s + 4;
		t.end = s + strlen (s);
		RStrBuf *tb = r_strbuf_new ("");
		gv2_type (&t, tb, "");
		char *ty = r_strbuf_drain (tb);
		char *res = NULL;
		if (!t.fail && t.p == t.end) {
			res = r_str_newf ("%s type_info %s", ty, (s[3] == 'f') ? "function" : "node");
		}
		free (ty);
		int i;
		for (i = 0; i < t.ntypes; i++) {
			free (t.types[i]);
		}
		free (t.types);
		if (res) {
			return res;
		}
	}
	// static data member: _<class>$<member>  ->  class::member
	if (s[0] == '_' && (isdigit ((unsigned char)s[1]) || s[1] == 'Q')) {
		const char *dollar = strchr (s, '$');
		if (dollar && dollar[1]) {
			GV2 t = {0};
			t.p = s + 1;
			t.end = dollar;
			RStrBuf *cb = r_strbuf_new ("");
			gv2_class (&t, cb);
			if (!t.fail && t.p == dollar) {
				r_strbuf_appendf (cb, "::%s", dollar + 1);
				free (t.types);
				return r_strbuf_drain (cb);
			}
			r_strbuf_free (cb);
			free (t.types);
		}
	}

	GV2 c = {0};
	RStrBuf *o = r_strbuf_new ("");
	bool is_method = false, is_ctor = false, is_dtor = false, is_op = false;
	bool cv_const = false, cv_vol = false;
	const char *opspell = NULL;
	char *convtype = NULL;
	RStrBuf *cls = NULL;
	const char *name = NULL;
	int namelen = 0;

	// destructor: _$_<class> or _._<class>
	if (r_str_startswith (s, "_$_") || r_str_startswith (s, "_._")) {
		is_dtor = is_method = true;
		c.p = s + 3;
		c.end = s + strlen (s);
		cls = r_strbuf_new ("");
		gv2_class (&c, cls);
	} else if (s[0] == '_' && s[1] == '_' && (isdigit ((unsigned char)s[2]) || s[2] == 'Q' || s[2] == 't')) {
		// constructor: __<class>[args]
		is_ctor = is_method = true;
		c.p = s + 2;
		c.end = s + strlen (s);
		cls = r_strbuf_new ("");
		gv2_class (&c, cls);
	} else if (s[0] == '_' && s[1] == '_' && (islower ((unsigned char)s[2]) || s[2] == 'o')) {
		// operator: __<opcode>__<signature>
		is_op = true;
		const char *op = s + 2;
		const char *sep = strstr (op, "__");
		if (!sep) {
			r_strbuf_free (o);
			return NULL;
		}
		size_t oplen = sep - op;
		// conversion operator: op<type>
		if (oplen >= 2 && op[0] == 'o' && op[1] == 'p') {
			GV2 t = {0};
			t.p = op + 2;
			t.end = sep;
			RStrBuf *tb = r_strbuf_new ("");
			gv2_type (&t, tb, "");
			convtype = r_strbuf_drain (tb);
			} else {
				int i;
				for (i = 0; gv2_ops[i].code; i++) {
					if (strlen (gv2_ops[i].code) == oplen && r_str_startswith (op, gv2_ops[i].code)) {
						opspell = gv2_ops[i].spelling;
						break;
					}
			}
			if (!opspell) {
				r_strbuf_free (o);
				return NULL;
			}
		}
		c.p = sep + 2;
		c.end = s + strlen (s);
		// optional this-qualifiers then class (member) or F (global)
		while (gv2_peek (&c) == 'C' || gv2_peek (&c) == 'V') {
			if (gv2_take (&c) == 'C') { cv_const = true; } else { cv_vol = true; }
		}
		if (gv2_peek (&c) == 'F') {
			c.p++; // global operator
		} else if (isdigit ((unsigned char)gv2_peek (&c)) || gv2_peek (&c) == 'Q' || gv2_peek (&c) == 't') {
			is_method = true;
			cls = r_strbuf_new ("");
			gv2_class (&c, cls);
		}
	} else {
		// ordinary: <name>__<signature>
		const char *sep = NULL;
		const char *q = s;
		while ((q = strstr (q, "__"))) {
			char after = q[2];
			if (q > s && (after == 'F' || after == 'C' || after == 'V' || after == 'Q'
					|| after == 't' || isdigit ((unsigned char)after))) {
				sep = q;
				break;
			}
			q += 1; // allow overlapping "__" (names may end in '_')
		}
		if (!sep) {
			r_strbuf_free (o);
			return NULL;
		}
		name = s;
		namelen = (int)(sep - s);
		c.p = sep + 2;
		c.end = s + strlen (s);
		while (gv2_peek (&c) == 'C' || gv2_peek (&c) == 'V') {
			if (gv2_take (&c) == 'C') { cv_const = true; } else { cv_vol = true; }
		}
		if (gv2_peek (&c) == 'F') {
			c.p++; // global function
		} else {
			is_method = true;
			cls = r_strbuf_new ("");
			gv2_class (&c, cls);
		}
	}

	if (c.fail) {
		goto fail;
	}

	// seed the typevec with the class type (slot 0) for member functions
	if (is_method && cls) {
		char *cs = r_strbuf_get (cls);
		gv2_push_type (&c, cs ? cs : "");
	}

	// emit the qualified name
	if (is_method && cls) {
		char *cs = r_strbuf_drain (cls);
		cls = NULL;
		r_strbuf_append (o, cs);
		r_strbuf_append (o, "::");
		if (is_ctor || is_dtor) {
			char bn[256];
			gv2_basename (cs, bn, sizeof (bn));
			if (is_dtor) {
				r_strbuf_append (o, "~");
			}
			r_strbuf_append (o, bn);
		} else if (is_op) {
			if (convtype) {
				r_strbuf_appendf (o, "operator %s", convtype);
			} else {
				r_strbuf_appendf (o, "operator%s", opspell);
			}
		} else {
			r_strbuf_append_n (o, name, namelen);
		}
		free (cs);
	} else {
		// global function / operator
		if (is_op) {
			if (convtype) {
				r_strbuf_appendf (o, "operator %s", convtype);
			} else {
				r_strbuf_appendf (o, "operator%s", opspell);
			}
		} else {
			r_strbuf_append_n (o, name, namelen);
		}
	}

	// arguments
	r_strbuf_append (o, "(");
	gv2_args (&c, o);
	r_strbuf_append (o, ")");
	if (cv_const) {
		r_strbuf_append (o, " const");
	}
	if (cv_vol) {
		r_strbuf_append (o, " volatile");
	}

	char *res = NULL;
	if (!c.fail) {
		res = r_strbuf_drain (o);
		o = NULL;
	}
	goto done;
fail:
	res = NULL;
done:
	r_strbuf_free (o);
	r_strbuf_free (cls);
	free (convtype);
	int i;
	for (i = 0; i < c.ntypes; i++) {
		free (c.types[i]);
	}
	free (c.types);
	if (res && !*res) {
		free (res);
		res = NULL;
	}
	return res;
}

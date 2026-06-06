// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// D (dlang) symbol demangler, following the D ABI name mangling. Single pass
// into an RStrBuf, no global state, bounded recursion. Matches the default
// (non-verbose) output of the libiberty d-demangle (c++filt -s dlang):
// function return types and attributes are omitted, type modifiers shown.

#include <r_util.h>
#include "cxx2.h"

#define D_MAX_DEPTH 200

typedef struct {
	const char *buf; // mangled bytes after the "_D" prefix
	const char *p;
	const char *end;
	int depth;
	bool fail;
} DCTX;

static bool d_type(DCTX *c, RStrBuf *o);
static void d_qualified(DCTX *c, RStrBuf *o);

static inline char d_peek(DCTX *c) {
	return (c->p < c->end) ? *c->p : 0;
}

static inline char d_take(DCTX *c) {
	return (c->p < c->end) ? *c->p++ : 0;
}

// <number> decimal identifier length
static int d_number(DCTX *c) {
	if (!isdigit ((unsigned char)d_peek (c))) {
		return -1;
	}
	int n = 0;
	while (isdigit ((unsigned char)d_peek (c))) {
		if (n > (INT_MAX - 9) / 10) {
			c->fail = true;
			return -1;
		}
		n = n * 10 + (d_take (c) - '0');
	}
	return n;
}

static const char *d_basic_type(char c) {
	switch (c) {
	case 'v': return "void";
	case 'b': return "bool";
	case 'g': return "byte";
	case 'h': return "ubyte";
	case 's': return "short";
	case 't': return "ushort";
	case 'i': return "int";
	case 'k': return "uint";
	case 'l': return "long";
	case 'm': return "ulong";
	case 'f': return "float";
	case 'd': return "double";
	case 'e': return "real";
	case 'o': return "ifloat";
	case 'p': return "idouble";
	case 'j': return "ireal";
	case 'q': return "cfloat";
	case 'r': return "cdouble";
	case 'c': return "creal";
	case 'a': return "char";
	case 'u': return "wchar";
	case 'w': return "dchar";
	case 'n': return "typeof(null)";
	}
	return NULL;
}

// is the next char the start of a (length-prefixed) symbol name?
static bool d_is_symbol(DCTX *c) {
	char ch = d_peek (c);
	return isdigit ((unsigned char)ch) || ch == 'Q' || ch == '_';
}

// <NumberBackRef> = [A-Z]* [a-z] (base 26, a-z terminates). Returns the target
// pointer (Q position minus the decoded value), or NULL on error.
static const char *d_backref_target(DCTX *c) {
	const char *qpos = c->p; // at 'Q'
	c->p++; // consume 'Q'
	ut64 val = 0;
	bool got = false;
	while (isalpha ((unsigned char)d_peek (c))) {
		if (val > (UT64_MAX - 25) / 26) {
			break;
		}
		val *= 26;
		char ch = d_take (c);
		if (ch >= 'a' && ch <= 'z') {
			val += ch - 'a';
			got = (val > 0);
			break;
		}
		val += ch - 'A';
	}
	if (!got || val == 0 || val > (ut64)(qpos - c->buf)) {
		c->fail = true;
		return NULL;
	}
	return qpos - (size_t)val;
}

// <identifier> = <number> <name> | template instance | Q backref
static void d_identifier(DCTX *c, RStrBuf *o) {
	// back reference to an earlier identifier
	if (d_peek (c) == 'Q') {
		const char *target = d_backref_target (c);
		if (c->fail) {
			return;
		}
		const char *saved = c->p;
		c->p = target;
		d_identifier (c, o);
		c->p = saved;
		return;
	}
	// length-less template instance: __T <name> ... Z
	if (c->p + 2 < c->end && c->p[0] == '_' && c->p[1] == '_' && c->p[2] == 'T') {
		c->p += 3;
		// the template name
		int n = d_number (c);
		if (n > 0 && c->p + n <= c->end) {
			r_strbuf_append_n (o, c->p, n);
			c->p += n;
		}
		r_strbuf_append (o, "!(");
		int i = 0;
		while (!c->fail && d_peek (c) && d_peek (c) != 'Z') {
			char k = d_take (c); // template-arg kind: T type, V value, S symbol
			if (i++) {
				r_strbuf_append (o, ", ");
			}
			if (k == 'T') {
				d_type (c, o);
			} else if (k == 'S') {
				d_qualified (c, o);
			} else {
				// value or unhandled arg: stop to stay safe
				c->fail = true;
				break;
			}
		}
		(void)(d_peek (c) == 'Z' && d_take (c));
		r_strbuf_append (o, ")");
		return;
	}
	int n = d_number (c);
	if (n <= 0 || c->p + n > c->end) {
		c->fail = true;
		return;
	}
	r_strbuf_append_n (o, c->p, n);
	c->p += n;
}

// is N<x> a function attribute (pure/nothrow/.../@live) rather than a type
// modifier? Ng (inout) and Nh (vector) are type constructors, not attributes.
static bool d_is_attr(char x) {
	return (x >= 'a' && x <= 'f') || (x >= 'i' && x <= 'n');
}

// function attributes: a run of N<x> markers - dropped from the output
static void d_skip_attrs(DCTX *c) {
	while (d_peek (c) == 'N' && c->p + 1 < c->end && d_is_attr (c->p[1])) {
		c->p += 2;
	}
}

// parse a function type's parameter list and (dropped) return type, emitting
// "(params)". For function pointers/delegates the caller prepends the return.
static void d_params(DCTX *c, RStrBuf *o) {
	r_strbuf_append (o, "(");
	int i = 0;
	while (!c->fail && d_peek (c) && d_peek (c) != 'Z' && d_peek (c) != 'X' && d_peek (c) != 'Y') {
		if (i++) {
			r_strbuf_append (o, ", ");
		}
		// parameter storage classes
		char sc = d_peek (c);
		if (sc == 'K') { c->p++; r_strbuf_append (o, "ref "); }
		else if (sc == 'J') { c->p++; r_strbuf_append (o, "out "); }
		else if (sc == 'L') { c->p++; r_strbuf_append (o, "lazy "); }
		else if (sc == 'M') { c->p++; r_strbuf_append (o, "scope "); }
		if (!d_type (c, o)) {
			break;
		}
	}
	char term = d_take (c); // Z (none) / X (typesafe variadic) / Y (C variadic)
	if (term == 'X') {
		r_strbuf_append (o, "..."); // typesafe variadic abuts the last param
	} else if (term == 'Y') {
		r_strbuf_append (o, i ? ", ..." : "...");
	}
	r_strbuf_append (o, ")");
	// the return type follows but is not shown for plain functions; callers
	// that need it (function pointers/delegates) handle it themselves.
}

// is the cursor at a function type (optionally member-qualified)?
static bool d_at_function(DCTX *c) {
	const char *p = c->p;
	if (p < c->end && *p == 'M') {
		p++;
	}
	while (p + 1 < c->end && *p == 'N' && d_is_attr (p[1])) {
		p += 2;
	}
	return p < c->end && (*p == 'F' || *p == 'U' || *p == 'W' || *p == 'V' || *p == 'R');
}

// consume the M/attrs/callconv prefix of a function type
static void d_func_prefix(DCTX *c) {
	(void)(d_peek (c) == 'M' && d_take (c)); // member 'this'
	d_skip_attrs (c);
	char cc = d_peek (c);
	if (cc == 'F' || cc == 'U' || cc == 'W' || cc == 'V' || cc == 'R') {
		c->p++;
	}
	d_skip_attrs (c); // attributes can also follow the calling convention
}

// <type>
static bool d_type(DCTX *c, RStrBuf *o) {
	if (c->fail || c->depth > D_MAX_DEPTH) {
		c->fail = true;
		return false;
	}
	c->depth++;
	bool ok = true;
	char ch = d_peek (c);
	switch (ch) {
	case 'x': // const(T)
		c->p++;
		r_strbuf_append (o, "const(");
		d_type (c, o);
		r_strbuf_append (o, ")");
		break;
	case 'y': // immutable(T)
		c->p++;
		r_strbuf_append (o, "immutable(");
		d_type (c, o);
		r_strbuf_append (o, ")");
		break;
	case 'O': // shared(T)
		c->p++;
		r_strbuf_append (o, "shared(");
		d_type (c, o);
		r_strbuf_append (o, ")");
		break;
	case 'N':
		if (c->p[1] == 'g') { // inout(T)
			c->p += 2;
			r_strbuf_append (o, "inout(");
			d_type (c, o);
			r_strbuf_append (o, ")");
		} else {
			ok = false;
		}
		break;
	case 'A': // dynamic array T[]
		c->p++;
		d_type (c, o);
		r_strbuf_append (o, "[]");
		break;
	case 'G': { // static array T[N]
		c->p++;
		int n = d_number (c);
		RStrBuf *el = r_strbuf_new ("");
		d_type (c, el);
		char *e = r_strbuf_drain (el);
		r_strbuf_appendf (o, "%s[%d]", r_str_get (e), n);
		free (e);
		break;
	}
	case 'H': { // associative array V[K]
		c->p++;
		RStrBuf *kb = r_strbuf_new ("");
		d_type (c, kb); // key
		char *k = r_strbuf_drain (kb);
		d_type (c, o); // value
		r_strbuf_appendf (o, "[%s]", r_str_get (k));
		free (k);
		break;
	}
	case 'P': // pointer / function pointer
		c->p++;
		if (d_at_function (c)) {
			// ret(params) function
			d_func_prefix (c);
			RStrBuf *pb = r_strbuf_new ("");
			d_params (c, pb);
			char *params = r_strbuf_drain (pb);
			d_type (c, o); // return type
			r_strbuf_appendf (o, "%s function", params);
			free (params);
		} else {
			d_type (c, o);
			r_strbuf_append (o, "*");
		}
		break;
	case 'D': // delegate: ret(params) delegate
		c->p++;
		d_func_prefix (c);
		{
			RStrBuf *pb = r_strbuf_new ("");
			d_params (c, pb);
			char *params = r_strbuf_drain (pb);
			d_type (c, o);
			r_strbuf_appendf (o, "%s delegate", params);
			free (params);
		}
		break;
	case 'C': // class
	case 'S': // struct
	case 'E': // enum
	case 'T': // typedef
		c->p++;
		d_qualified (c, o);
		break;
	case 'F': case 'U': case 'W': case 'V': case 'R': { // bare function type
		d_func_prefix (c);
		RStrBuf *pb = r_strbuf_new ("");
		d_params (c, pb);
		char *params = r_strbuf_drain (pb);
		d_type (c, o);
		r_strbuf_appendf (o, "%s function", params);
		free (params);
		break;
	}
	default: {
		const char *bt = d_basic_type (ch);
		if (bt) {
			c->p++;
			r_strbuf_append (o, bt);
		} else {
			ok = false;
		}
		break;
	}
	}
	if (!ok) {
		c->fail = true;
	}
	c->depth--;
	return ok && !c->fail;
}

// <QualifiedName> = dotted identifiers; a trailing function type on the last
// symbol becomes "(params)". A trailing non-function type is the variable's
// type and is omitted.
static void d_qualified(DCTX *c, RStrBuf *o) {
	if (c->fail || c->depth > D_MAX_DEPTH) {
		c->fail = true;
		return;
	}
	c->depth++;
	bool first = true;
	do {
		// skip anonymous symbols (runs of '0')
		while (d_peek (c) == '0') {
			c->p++;
		}
		if (!d_is_symbol (c)) {
			break;
		}
		if (!first) {
			r_strbuf_append (o, ".");
		}
		first = false;
		d_identifier (c, o);
		// a function type attached to this symbol -> "(params)"
		if (d_at_function (c)) {
			d_func_prefix (c);
			d_params (c, o);
			// the (dropped) return type follows
			if (!c->fail && d_peek (c) && d_peek (c) != 'Z' && !d_is_symbol (c)) {
				RStrBuf *scratch = r_strbuf_new ("");
				d_type (c, scratch);
				r_strbuf_free (scratch);
			}
		}
	} while (!c->fail && d_is_symbol (c));
	c->depth--;
}

char *r_demangle_dlang(const char *mangled) {
	if (!mangled) {
		return NULL;
	}
	const char *p = mangled;
	if (p[0] == '_' && p[1] == '_' && p[2] == 'D') {
		p++;
	}
	if (!(p[0] == '_' && p[1] == 'D')) {
		return NULL;
	}
	// special case: the C main wrapper
	if (!strcmp (p, "_Dmain")) {
		return strdup ("D main");
	}
	// back references count bytes from the start of the "_D..." symbol, so the
	// context spans the whole string while parsing begins after the prefix.
	DCTX c = {0};
	c.buf = p;
	c.p = p + 2;
	c.end = p + strlen (p);
	RStrBuf *o = r_strbuf_new ("");
	d_qualified (&c, o);
	// A trailing variable type (or artificial 'Z') is consumed but not shown.
	// The whole symbol must be consumed for it to be a valid D mangling.
	if (!c.fail && c.p < c.end) {
		if (d_peek (&c) == 'Z') {
			c.p++;
		} else {
			RStrBuf *scratch = r_strbuf_new ("");
			d_type (&c, scratch);
			r_strbuf_free (scratch);
		}
	}
	if (!c.fail && c.p != c.end) {
		c.fail = true; // leftover bytes => not a valid D symbol
	}
	char *res = NULL;
	if (!c.fail) {
		res = r_strbuf_drain (o);
	} else {
		r_strbuf_free (o);
	}
	if (res && !*res) {
		free (res);
		res = NULL;
	}
	return res;
}

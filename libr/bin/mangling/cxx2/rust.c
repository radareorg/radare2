// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// Rust v0 (RFC 2603) demangler. Single pass, emits into an RStrBuf, supports
// back-references (B<base62>_) by re-parsing from an earlier byte offset. No
// global state; everything lives in the RV0 context. Recursion is bounded.

#include <r_util.h>
#include "cxx2.h"

#define V0_MAX_DEPTH 256

typedef struct {
	const char *s; // mangled bytes after the "_R" prefix
	int len;
	int pos;
	int depth;
	bool fail;
	RStrBuf *out;
} RV0;

static void v0_type(RV0 *v);
static void v0_path(RV0 *v, bool in_value);
static void v0_const(RV0 *v);

static inline char v0_peek(RV0 *v) {
	return (v->pos < v->len) ? v->s[v->pos] : 0;
}

static inline char v0_next(RV0 *v) {
	return (v->pos < v->len) ? v->s[v->pos++] : 0;
}

static inline bool v0_eat(RV0 *v, char c) {
	if (v0_peek (v) == c) {
		v->pos++;
		return true;
	}
	return false;
}

static inline void v0_emit(RV0 *v, const char *s) {
	r_strbuf_append (v->out, s);
}

// <base-62-number> = { 0-9 a-z A-Z } "_"  ; empty => 0, else value+1
static ut64 v0_base62(RV0 *v) {
	ut64 n = 0;
	bool any = false;
	for (;;) {
		char c = v0_peek (v);
		int d;
		if (c >= '0' && c <= '9') {
			d = c - '0';
		} else if (c >= 'a' && c <= 'z') {
			d = c - 'a' + 10;
		} else if (c >= 'A' && c <= 'Z') {
			d = c - 'A' + 36;
		} else {
			break;
		}
		any = true;
		if (n > (UT64_MAX - 62) / 62) {
			v->fail = true;
			return 0;
		}
		n = n * 62 + d;
		v->pos++;
	}
	if (!v0_eat (v, '_')) {
		v->fail = true;
		return 0;
	}
	return any ? n + 1 : 0;
}

static int v0_decimal(RV0 *v) {
	if (!isdigit ((unsigned char)v0_peek (v))) {
		return -1;
	}
	int n = 0;
	while (isdigit ((unsigned char)v0_peek (v))) {
		if (n > (INT_MAX - 9) / 10) {
			v->fail = true;
			return -1;
		}
		n = n * 10 + (v0_next (v) - '0');
	}
	return n;
}

// an optional "s<base62>" disambiguator; absent => 0, else base62 value + 1
static ut64 v0_disambiguator(RV0 *v) {
	if (v0_eat (v, 's')) {
		return v0_base62 (v) + 1;
	}
	return 0;
}

// <undisambiguated-identifier> = ["u"] <decimal> ["_"] <bytes>
// Prints the identifier (punycode is shown raw with a marker rather than decoded).
static void v0_ident(RV0 *v, bool *is_punycode) {
	bool puny = v0_eat (v, 'u');
	if (is_punycode) {
		*is_punycode = puny;
	}
	int n = v0_decimal (v);
	if (n < 0) {
		v->fail = true;
		return;
	}
	(void)v0_eat (v, '_'); // separator
	if (v->pos + n > v->len) {
		v->fail = true;
		return;
	}
	if (puny) {
		// punycode identifiers are uncommon; emit the raw payload verbatim
		r_strbuf_append_n (v->out, v->s + v->pos, n);
	} else {
		r_strbuf_append_n (v->out, v->s + v->pos, n);
	}
	v->pos += n;
}

// <lifetime> = "L" <base62> ; printed as 'a, 'b ... (or '_ for 0)
static void v0_lifetime(RV0 *v) {
	ut64 idx = v0_base62 (v);
	if (idx == 0) {
		v0_emit (v, "'_");
	} else {
		// map 1->a, 2->b, ...
		char buf[24];
		ut64 i = idx - 1;
		if (i < 26) {
			snprintf (buf, sizeof (buf), "'%c", (char)('a' + i));
		} else {
			snprintf (buf, sizeof (buf), "'_%" PFMT64u, i);
		}
		v0_emit (v, buf);
	}
}

static void v0_basic_type(char c, RV0 *v) {
	const char *t = NULL;
	switch (c) {
	case 'b': t = "bool"; break;
	case 'c': t = "char"; break;
	case 'e': t = "str"; break;
	case 'u': t = "()"; break;
	case 'a': t = "i8"; break;
	case 's': t = "i16"; break;
	case 'l': t = "i32"; break;
	case 'x': t = "i64"; break;
	case 'n': t = "i128"; break;
	case 'i': t = "isize"; break;
	case 'h': t = "u8"; break;
	case 't': t = "u16"; break;
	case 'm': t = "u32"; break;
	case 'y': t = "u64"; break;
	case 'o': t = "u128"; break;
	case 'j': t = "usize"; break;
	case 'f': t = "f32"; break;
	case 'd': t = "f64"; break;
	case 'z': t = "!"; break;
	case 'p': t = "_"; break;
	case 'v': t = "..."; break;
	}
	if (t) {
		v0_emit (v, t);
	} else {
		v->fail = true;
	}
}

// run `fn` with the cursor temporarily relocated to a back-reference target
static void v0_backref(RV0 *v, void (*fn)(RV0 *, bool), bool arg) {
	ut64 target = v0_base62 (v);
	if (v->fail || (int)target >= v->pos || (int)target < 0) {
		v->fail = true;
		return;
	}
	int saved = v->pos;
	v->pos = (int)target;
	fn (v, arg);
	v->pos = saved;
}

static void v0_skip_path(RV0 *v) {
	RStrBuf *scratch = r_strbuf_new ("");
	RStrBuf *saved = v->out;
	v->out = scratch;
	v0_path (v, false);
	v->out = saved;
	r_strbuf_free (scratch);
}

static bool v0_suffix(const char *s) {
	if (*s != '.') {
		return false;
	}
	for (; *s; s++) {
		if (*s == '.') {
			if (!isalnum ((unsigned char)s[1]) && s[1] != '_' && s[1] != '$') {
				return false;
			}
		} else if (!isalnum ((unsigned char)*s) && *s != '_' && *s != '$') {
			return false;
		}
	}
	return true;
}

// <generic-arg> = <lifetime> | <type> | "K" <const>
static void v0_generic_arg(RV0 *v) {
	char c = v0_peek (v);
	if (c == 'L') {
		v->pos++;
		v0_lifetime (v);
	} else if (c == 'K') {
		v->pos++;
		v0_const (v);
	} else {
		v0_type (v);
	}
}

// <fn-sig> = [<binder>] ["U"] ["K" <abi>] <type>* "E" <type>
static void v0_fn_sig(RV0 *v) {
	if (v0_eat (v, 'G')) { // binder (for<...>): skipped in output
		(void)v0_base62 (v);
	}
	if (v0_eat (v, 'U')) {
		v0_emit (v, "unsafe ");
	}
	if (v0_eat (v, 'K')) {
		// abi: "C" or a custom identifier
		v0_emit (v, "extern \"");
		if (v0_eat (v, 'C')) {
			v0_emit (v, "C");
		} else {
			bool p = false;
			v0_ident (v, &p);
		}
		v0_emit (v, "\" ");
	}
	v0_emit (v, "fn(");
	int i = 0;
	while (!v->fail && v0_peek (v) && v0_peek (v) != 'E') {
		if (i++) {
			v0_emit (v, ", ");
		}
		v0_type (v);
	}
	(void)v0_eat (v, 'E');
	v0_emit (v, ")");
	// return type (omit when it is unit)
	if (v0_peek (v) == 'u') {
		v->pos++;
	} else {
		v0_emit (v, " -> ");
		v0_type (v);
	}
}

// dyn bounds: "D" <dyn-bounds> <lifetime>
static void v0_dyn(RV0 *v) {
	v0_emit (v, "dyn ");
	if (v0_eat (v, 'G')) { // binder
		(void)v0_base62 (v);
	}
	int i = 0;
	while (!v->fail && v0_peek (v) && v0_peek (v) != 'E') {
		if (i++) {
			v0_emit (v, " + ");
		}
		// <dyn-trait> = <path> { "p" <ident> <type> }
		v0_path (v, false);
		while (v0_eat (v, 'p')) {
			v0_emit (v, "<");
			bool pun = false;
			v0_ident (v, &pun);
			v0_emit (v, " = ");
			v0_type (v);
			v0_emit (v, ">");
		}
	}
	(void)v0_eat (v, 'E');
	// trailing lifetime bound
	if (v0_eat (v, 'L')) {
		ut64 idx = v0_base62 (v);
		if (idx != 0) {
			char buf[24];
			ut64 i2 = idx - 1;
			v0_emit (v, " + ");
			if (i2 < 26) {
				snprintf (buf, sizeof (buf), "'%c", (char)('a' + i2));
			} else {
				snprintf (buf, sizeof (buf), "'_%" PFMT64u, i2);
			}
			v0_emit (v, buf);
		}
	}
}

// <type>
static void v0_type(RV0 *v) {
	if (v->fail || v->depth > V0_MAX_DEPTH) {
		v->fail = true;
		return;
	}
	v->depth++;
	char c = v0_peek (v);
	switch (c) {
	case 'A': { // [T; N]
		v->pos++;
		v0_emit (v, "[");
		v0_type (v);
		v0_emit (v, "; ");
		v0_const (v);
		v0_emit (v, "]");
		break;
	}
	case 'S': // [T]
		v->pos++;
		v0_emit (v, "[");
		v0_type (v);
		v0_emit (v, "]");
		break;
	case 'T': { // tuple (T, U, ...)
		v->pos++;
		v0_emit (v, "(");
		int i = 0;
		while (!v->fail && v0_peek (v) && v0_peek (v) != 'E') {
			if (i++) {
				v0_emit (v, ", ");
			}
			v0_type (v);
		}
		(void)v0_eat (v, 'E');
		if (i == 1) {
			v0_emit (v, ","); // 1-tuple
		}
		v0_emit (v, ")");
		break;
	}
	case 'R': // &T or &'a T
		v->pos++;
		v0_emit (v, "&");
		if (v0_eat (v, 'L')) {
			ut64 li = v0_base62 (v);
			if (li) {
				char b[24];
				ut64 k = li - 1;
				if (k < 26) {
					snprintf (b, sizeof (b), "'%c ", (char)('a' + k));
					v0_emit (v, b);
				}
			}
		}
		v0_type (v);
		break;
	case 'Q': // &mut T
		v->pos++;
		v0_emit (v, "&mut ");
		if (v0_eat (v, 'L')) {
			(void)v0_base62 (v);
		}
		v0_type (v);
		break;
	case 'P': // *const T
		v->pos++;
		v0_emit (v, "*const ");
		v0_type (v);
		break;
	case 'O': // *mut T
		v->pos++;
		v0_emit (v, "*mut ");
		v0_type (v);
		break;
	case 'F': // fn pointer
		v->pos++;
		v0_fn_sig (v);
		break;
	case 'D': // dyn Trait
		v->pos++;
		v0_dyn (v);
		break;
	case 'B': { // backref
		v->pos++;
		ut64 target = v0_base62 (v);
		if (!v->fail && (int)target < v->pos && (int)target >= 0) {
			int saved = v->pos;
			v->pos = (int)target;
			v0_type (v);
			v->pos = saved;
		} else {
			v->fail = true;
		}
		break;
	}
	default:
		if (c == 'C' || c == 'M' || c == 'X' || c == 'Y' || c == 'I' || c == 'N') {
			v0_path (v, false);
		} else {
			v->pos++;
			v0_basic_type (c, v);
		}
		break;
	}
	v->depth--;
}

// <const> = <type> <const-data> | "p" | <backref>
// Only the value is printed (true/false, the integer, the char), not the type.
static void v0_const(RV0 *v) {
	if (v->fail || v->depth > V0_MAX_DEPTH) {
		v->fail = true;
		return;
	}
	v->depth++;
	char c = v0_peek (v);
	if (c == 'B') {
		v->pos++;
		ut64 target = v0_base62 (v);
		if (!v->fail && (int)target < v->pos && (int)target >= 0) {
			int saved = v->pos;
			v->pos = (int)target;
			v0_const (v);
			v->pos = saved;
		} else {
			v->fail = true;
		}
		v->depth--;
		return;
	}
	if (c == 'p') { // placeholder
		v->pos++;
		v0_emit (v, "_");
		v->depth--;
		return;
	}
	char ty = v0_next (v); // the type char is consumed but not printed
	if (ty == 'b') { // bool: 0_ / 1_
		char d = v0_next (v);
		(void)v0_eat (v, '_');
		v0_emit (v, (d == '1') ? "true" : "false");
	} else if (ty == 'c') { // char: <hex>_
		while (isxdigit ((unsigned char)v0_peek (v))) {
			v->pos++;
		}
		(void)v0_eat (v, '_');
		v0_emit (v, "'?'");
	} else { // integer: [n] <hex>* _
		bool neg = v0_eat (v, 'n');
		ut64 val = 0;
		bool any = false;
		while (isxdigit ((unsigned char)v0_peek (v))) {
			char h = v0_next (v);
			int d = (h <= '9') ? h - '0' : (tolower (h) - 'a' + 10);
			val = val * 16 + d;
			any = true;
		}
		(void)v0_eat (v, '_');
		if (any || !v->fail) {
			char b[32];
			snprintf (b, sizeof (b), "%s%" PFMT64u, neg ? "-" : "", val);
			v0_emit (v, b);
		}
	}
	v->depth--;
}

// special (uppercase) namespace label for nested names
static const char *v0_ns_label(char ns) {
	switch (ns) {
	case 'C': return "closure";
	case 'S': return "shim";
	}
	return NULL;
}

// <path>
static void v0_path(RV0 *v, bool in_value) {
	if (v->fail || v->depth > V0_MAX_DEPTH) {
		v->fail = true;
		return;
	}
	v->depth++;
	char c = v0_next (v);
	switch (c) {
	case 'C': { // crate root: <identifier>  (disambiguator + hash dropped)
		(void)v0_disambiguator (v);
		bool pun = false;
		v0_ident (v, &pun);
		break;
	}
	case 'N': { // nested: <namespace> <path> <identifier>
		char ns = v0_next (v);
		v0_path (v, in_value);
		ut64 dis = v0_disambiguator (v);
		// peek the identifier
		RStrBuf *name = r_strbuf_new ("");
		RStrBuf *saved = v->out;
		v->out = name;
		bool pun = false;
		v0_ident (v, &pun);
		v->out = saved;
		char *nm = r_strbuf_drain (name);
		const char *label = (ns >= 'A' && ns <= 'Z') ? v0_ns_label (ns) : NULL;
		if (ns >= 'A' && ns <= 'Z') {
			// special namespace -> {label[:name]#disambiguator}
			v0_emit (v, "::{");
			if (label) {
				v0_emit (v, label);
			} else {
				char one[2] = { ns, 0 };
				v0_emit (v, one); // unknown special namespace prints its letter
			}
			if (nm && *nm) {
				v0_emit (v, ":");
				v0_emit (v, nm);
			}
			char b[24];
			snprintf (b, sizeof (b), "#%" PFMT64u "}", dis);
			v0_emit (v, b);
		} else {
			v0_emit (v, "::");
			v0_emit (v, r_str_get (nm));
		}
		free (nm);
		break;
	}
		case 'M': { // inherent impl: <impl-path> <type>   -> <Type>
			(void)v0_disambiguator (v);
			// impl-path: parsed for back-reference correctness, not printed
			v0_skip_path (v);
			v0_emit (v, "<");
			v0_type (v);
			v0_emit (v, ">");
		break;
	}
		case 'X': { // trait impl: <impl-path> <type> <path> -> <Type as Trait>
			(void)v0_disambiguator (v);
			v0_skip_path (v);
			v0_emit (v, "<");
			v0_type (v);
			v0_emit (v, " as ");
		v0_path (v, false);
		v0_emit (v, ">");
		break;
	}
	case 'Y': // <type> <path> -> <Type as Trait>
		v0_emit (v, "<");
		v0_type (v);
		v0_emit (v, " as ");
		v0_path (v, false);
		v0_emit (v, ">");
		break;
	case 'I': { // generic: <path> <generic-arg>* E -> path::<args>
		v0_path (v, in_value);
		v0_emit (v, in_value ? "::<" : "<");
		int i = 0;
		while (!v->fail && v0_peek (v) && v0_peek (v) != 'E') {
			if (i++) {
				v0_emit (v, ", ");
			}
			v0_generic_arg (v);
		}
		(void)v0_eat (v, 'E');
		v0_emit (v, ">"); // Rust syntax allows ">>"
		break;
	}
	case 'B': // backref
		v0_backref (v, v0_path, in_value);
		break;
	default:
		v->fail = true;
		break;
	}
	v->depth--;
}

char *r_demangle_rust_v0(const char *mangled) {
	if (!mangled) {
		return NULL;
	}
	const char *p = mangled;
	if (p[0] == '_' && p[1] == '_' && p[2] == 'R') {
		p++;
	}
	if (!(p[0] == '_' && p[1] == 'R')) {
		return NULL;
	}
	p += 2;
	// an optional leading decimal (encoding version) precedes the path
	while (isdigit ((unsigned char)*p)) {
		p++;
	}
	RV0 v = {0};
	v.s = p;
	v.len = (int)strlen (p);
	v.out = r_strbuf_new ("");
	v0_path (&v, true);
	// allow a trailing instantiating-crate path and a vendor suffix
	if (!v.fail && v.pos < v.len && v.s[v.pos] != '.') {
		v0_skip_path (&v);
	}
	if (!v.fail && v.pos < v.len && !v0_suffix (v.s + v.pos)) {
		v.fail = true;
	}
	char *res = NULL;
	if (!v.fail) {
		res = r_strbuf_drain (v.out);
	} else {
		r_strbuf_free (v.out);
	}
	if (res && !*res) {
		free (res);
		res = NULL;
	}
	return res;
}

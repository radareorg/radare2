// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// Rust v0 (RFC 2603) demangler. Single pass, emits into an RStrBuf, supports
// back-references (B<base62>_) by re-parsing from an earlier byte offset. No
// global state; everything lives in the RV0 context. Recursion is bounded and
// the printed output is capped to defuse exponential back-reference expansion.
// Output matches rustc-demangle's alternate ("{:#}") form: no symbol hash, no
// integer-const type suffixes.

#include <r_util.h>
#include "cxx2.h"

#define V0_MAX_DEPTH 256
// nested back-references can expand exponentially; cap the printed size like
// the reference demangler (rustc-demangle uses MAX_SIZE = 1_000_000).
#define V0_MAX_OUTPUT 1000000

typedef struct {
	const char *s; // mangled bytes after the "_R" prefix (and version digits)
	int len;
	int pos;
	int depth;
	int binders; // lifetimes bound by the enclosing for<> binders
	bool fail;
	bool skipping; // parsing a path only to advance past it (not printed)
	RStrBuf *out;
} RV0;

static void v0_type(RV0 *v);
static void v0_path(RV0 *v, bool in_value);
static void v0_const(RV0 *v, bool in_value);
static void v0_generic_arg(RV0 *v);
static void v0_ident(RV0 *v);
static void v0_pat(RV0 *v);

static void v0_const_value(RV0 *v) {
	v0_const (v, true);
}

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

static inline bool v0_overflow(RV0 *v) {
	if (r_strbuf_length (v->out) > V0_MAX_OUTPUT) {
		v->fail = true;
		return true;
	}
	return false;
}

static inline void v0_emit(RV0 *v, const char *s) {
	if (!v0_overflow (v)) {
		r_strbuf_append (v->out, s);
	}
}

static inline void v0_emit_n(RV0 *v, const char *s, int n) {
	if (!v0_overflow (v)) {
		r_strbuf_append_n (v->out, s, n);
	}
}

static void v0_emitf(RV0 *v, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
static void v0_emitf(RV0 *v, const char *fmt, ...) {
	if (v0_overflow (v)) {
		return;
	}
	va_list ap;
	va_start (ap, fmt);
	r_strbuf_vappendf (v->out, fmt, ap);
	va_end (ap);
}

// parse "<item> { <item> } E" emitting sep between the items; returns the count
static int v0_list(RV0 *v, const char *sep, void (*item)(RV0 *)) {
	int i = 0;
	while (!v->fail && v0_peek (v) && v0_peek (v) != 'E') {
		if (i++) {
			v0_emit (v, sep);
		}
		item (v);
	}
	if (!v0_eat (v, 'E')) {
		v->fail = true;
	}
	return i;
}

// run fn with the output redirected to a scratch buffer and return its text
static char *v0_capture(RV0 *v, void (*fn)(RV0 *)) {
	RStrBuf *saved = v->out;
	v->out = r_strbuf_new ("");
	fn (v);
	char *s = r_strbuf_drain (v->out);
	v->out = saved;
	return s;
}

static inline bool v0_is_hex(char c) {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
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

// <decimal-number> = "0" | [1-9] [0-9]*  ; a leading zero is the whole number
static int v0_decimal(RV0 *v) {
	if (!isdigit ((unsigned char)v0_peek (v))) {
		return -1;
	}
	if (v0_peek (v) == '0') {
		v->pos++;
		return 0;
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

// jump the cursor to a back-reference target; the "B" byte was already consumed.
// A valid target points strictly before the "B" and never forward.
static bool v0_backref_to(RV0 *v, int *saved) {
	int bpos = v->pos - 1;
	ut64 target = v0_base62 (v);
	if (v->fail || target >= (ut64)bpos) {
		v->fail = true;
		return false;
	}
	*saved = v->pos;
	v->pos = (int)target;
	return true;
}

// append a Unicode scalar as UTF-8
static void v0_emit_utf8(RV0 *v, ut32 cp) {
	ut8 b[8] = {0};
	r_utf8_encode (b, cp);
	v0_emit (v, (const char *)b);
}

// escape one char the way Rust's Debug does (approximated: printable Unicode is
// kept verbatim, C0/C1 controls and DEL are shown as \u{..})
static void v0_emit_escaped(RV0 *v, ut32 cp, char quote) {
	switch (cp) {
	case '\t': v0_emit (v, "\\t"); return;
	case '\r': v0_emit (v, "\\r"); return;
	case '\n': v0_emit (v, "\\n"); return;
	case '\\': v0_emit (v, "\\\\"); return;
	case 0: v0_emit (v, "\\0"); return;
	}
	if (cp == (ut32)(unsigned char)quote) {
		v0_emitf (v, "\\%c", quote);
	} else if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) {
		v0_emitf (v, "\\u{%x}", (unsigned int)cp);
	} else {
		v0_emit_utf8 (v, cp);
	}
}

static void v0_basic_type(RV0 *v, char c) {
	static const char keys[] = "bceuaslxnihtmyojfdzpv";
	static const char *names[] = {
		"bool", "char", "str", "()", "i8", "i16", "i32", "i64", "i128", "isize",
		"u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64", "!", "_", "..."
	};
	const char *k = c? strchr (keys, c): NULL;
	if (k) {
		v0_emit (v, names[k - keys]);
	} else {
		v->fail = true;
	}
}

static void v0_path_ref(RV0 *v) {
	v0_path (v, false);
}

// parse a path to advance the cursor past it without printing; back-references
// are validated but not followed (matching the reference's skipping mode)
static void v0_skip_path(RV0 *v) {
	bool was_skipping = v->skipping;
	v->skipping = true;
	free (v0_capture (v, v0_path_ref));
	v->skipping = was_skipping;
}

static bool v0_suffix(const char *s, int len) {
	if (len < 1 || *s != '.') {
		return false;
	}
	int i;
	for (i = 0; i < len; i++) {
		const char c = s[i];
		if (c != '.' && !isalnum ((unsigned char)c) && c != '_' && c != '$') {
			return false;
		}
	}
	return true;
}

// <lifetime> printed from a de Bruijn index relative to the bound-lifetime depth.
// 0 => '_ (erased); otherwise 'a .. 'z, then '_<n> once the letters run out.
static void v0_lifetime_from_index(RV0 *v, ut64 lt) {
	if (lt == 0) {
		v0_emit (v, "'_");
		return;
	}
	if (lt > (ut64)v->binders) {
		v->fail = true;
		return;
	}
	const ut64 depth = (ut64)v->binders - lt;
	if (depth < 26) {
		v0_emitf (v, "'%c", (char)('a' + depth));
	} else {
		v0_emitf (v, "'_%" PFMT64u, depth);
	}
}

// run `body` inside an optional "G<base62>" binder, printing "for<'a, ...> "
static void v0_in_binder(RV0 *v, void (*body)(RV0 *)) {
	ut64 count = 0;
	if (v0_eat (v, 'G')) {
		count = v0_base62 (v) + 1;
	}
	if (count > 0) {
		v0_emit (v, "for<");
		ut64 i;
		for (i = 0; i < count && !v->fail; i++) {
			if (i) {
				v0_emit (v, ", ");
			}
			v->binders++;
			v0_lifetime_from_index (v, 1);
		}
		v0_emit (v, "> ");
	}
	body (v);
	v->binders -= (int)count;
}

// <fn-sig> body (inside a binder): ["U"] ["K" <abi>] <type>* "E" <type>
static void v0_fn_sig_body(RV0 *v) {
	if (v0_eat (v, 'U')) {
		v0_emit (v, "unsafe ");
	}
	if (v0_eat (v, 'K')) {
		v0_emit (v, "extern \"");
		if (v0_eat (v, 'C')) {
			v0_emit (v, "C");
		} else {
			// abi identifier: underscores were substituted for dashes
			char *abi = v0_capture (v, v0_ident);
			if (abi) {
				r_str_replace_ch (abi, '_', '-', true);
				v0_emit (v, abi);
				free (abi);
			}
		}
		v0_emit (v, "\" ");
	}
	v0_emit (v, "fn(");
	v0_list (v, ", ", v0_type);
	v0_emit (v, ")");
	if (!v0_eat (v, 'u')) { // a unit ("u") return type is omitted
		v0_emit (v, " -> ");
		v0_type (v);
	}
}

// <path> that may leave its generic-argument angle bracket open (for dyn bounds);
// returns true if a "<" was emitted and not yet closed.
static bool v0_path_open_generics(RV0 *v) {
	if (v0_eat (v, 'B')) {
		int saved;
		bool open = false;
		if (v0_backref_to (v, &saved)) {
			if (!v->skipping) {
				open = v0_path_open_generics (v);
			}
			v->pos = saved;
		}
		return open;
	}
	if (v0_eat (v, 'I')) {
		v0_path (v, false);
		v0_emit (v, "<");
		v0_list (v, ", ", v0_generic_arg);
		return true;
	}
	v0_path (v, false);
	return false;
}

// <dyn-trait> = <path-maybe-open-generics> { "p" <ident> <type|K const> }
static void v0_dyn_trait(RV0 *v) {
	bool open = v0_path_open_generics (v);
	while (!v->fail && v0_eat (v, 'p')) {
		if (!open) {
			v0_emit (v, "<");
			open = true;
		} else {
			v0_emit (v, ", ");
		}
		v0_ident (v);
		v0_emit (v, " = ");
		if (v0_eat (v, 'K')) {
			v0_const (v, false);
		} else {
			v0_type (v);
		}
	}
	if (open) {
		v0_emit (v, ">");
	}
}

// dyn bounds body (inside a binder): <dyn-trait> { "+" <dyn-trait> } "E"
static void v0_dyn_bounds_body(RV0 *v) {
	v0_list (v, " + ", v0_dyn_trait);
}

// <generic-arg> = <lifetime> | <type> | "K" <const>
static void v0_generic_arg(RV0 *v) {
	char c = v0_peek (v);
	if (c == 'L') {
		v->pos++;
		v0_lifetime_from_index (v, v0_base62 (v));
	} else if (c == 'K') {
		v->pos++;
		v0_const (v, false);
	} else {
		v0_type (v);
	}
}

// <pattern> = "R" <const> <const>  (range)
//           | "O" <pattern>+ "E"   (or-pattern)
//           | "N"                  (non-null)
static void v0_pat(RV0 *v) {
	if (v->fail || v->depth > V0_MAX_DEPTH) {
		v->fail = true;
		return;
	}
	char tag = v0_next (v);
	switch (tag) {
	case 'R': // range: lo..=hi
		v0_const (v, false);
		v0_emit (v, "..=");
		v0_const (v, false);
		break;
	case 'O': // or-pattern: a | b | ...
		v->depth++;
		v0_pat (v);
		while (!v->fail && !v0_eat (v, 'E')) {
			if (!v0_peek (v)) {
				v->fail = true;
				break;
			}
			v0_emit (v, " | ");
			v0_pat (v);
		}
		v->depth--;
		break;
	case 'N': // non-null
		v0_emit (v, "!null");
		break;
	default:
		v->fail = true;
		break;
	}
}

// <type>
static void v0_type(RV0 *v) {
	if (v->fail || v->depth > V0_MAX_DEPTH) {
		v->fail = true;
		return;
	}
	v->depth++;
	// unstable splat marker: a "#[splat]" attribute prefixing the type
	if (v0_eat (v, 'w')) {
		v0_emit (v, "#[splat] ");
	}
	char c = v0_peek (v);
	switch (c) {
	case 'W': // pattern type: <type> is <pattern>
		v->pos++;
		v0_type (v);
		v0_emit (v, " is ");
		v0_pat (v);
		break;
	case 'A': // [T; N]
		v->pos++;
		v0_emit (v, "[");
		v0_type (v);
		v0_emit (v, "; ");
		v0_const (v, true);
		v0_emit (v, "]");
		break;
	case 'S': // [T]
		v->pos++;
		v0_emit (v, "[");
		v0_type (v);
		v0_emit (v, "]");
		break;
	case 'T': // tuple (T, U, ...)
		v->pos++;
		v0_emit (v, "(");
		if (v0_list (v, ", ", v0_type) == 1) {
			v0_emit (v, ","); // 1-tuple
		}
		v0_emit (v, ")");
		break;
	case 'R': // &T or &'a T
	case 'Q': // &mut T or &'a mut T
		v->pos++;
		v0_emit (v, "&");
		if (v0_eat (v, 'L')) {
			ut64 lt = v0_base62 (v);
			if (lt != 0) {
				v0_lifetime_from_index (v, lt);
				v0_emit (v, " ");
			}
		}
		if (c == 'Q') {
			v0_emit (v, "mut ");
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
		v0_in_binder (v, v0_fn_sig_body);
		break;
	case 'D': // dyn Trait
		v->pos++;
		v0_emit (v, "dyn ");
		v0_in_binder (v, v0_dyn_bounds_body);
		if (!v0_eat (v, 'L')) {
			v->fail = true;
		} else {
			ut64 lt = v0_base62 (v);
			if (lt != 0) {
				v0_emit (v, " + ");
				v0_lifetime_from_index (v, lt);
			}
		}
		break;
	case 'B': { // backref
		v->pos++;
		int saved;
		if (v0_backref_to (v, &saved)) {
			if (!v->skipping) {
				v0_type (v);
			}
			v->pos = saved;
		}
		break;
	}
	default:
		if (c && strchr ("CMXYNI", c)) {
			v0_path (v, false);
		} else {
			v->pos++;
			v0_basic_type (v, c);
		}
		break;
	}
	v->depth--;
}

// read a run of lowercase hex nibbles followed by the terminating "_"
static bool v0_read_nibbles(RV0 *v, const char **nib, int *nnib) {
	int start = v->pos;
	while (v0_is_hex (v0_peek (v))) {
		v->pos++;
	}
	*nib = v->s + start;
	*nnib = v->pos - start;
	return v0_eat (v, '_');
}

// fold up to 16 significant nibbles into a u64; returns false if it won't fit
static bool v0_fold_u64(const char *nib, int nnib, ut64 *out) {
	int lead = 0;
	while (lead < nnib && nib[lead] == '0') {
		lead++;
	}
	if (nnib - lead > 16) {
		return false;
	}
	ut64 val = 0;
	int k;
	for (k = lead; k < nnib; k++) {
		char h = nib[k];
		val = (val << 4) | (ut64)((h <= '9') ? h - '0' : h - 'a' + 10);
	}
	*out = val;
	return true;
}

static void v0_const_uint(RV0 *v, bool neg) {
	const char *nib;
	int nnib;
	if (!v0_read_nibbles (v, &nib, &nnib)) {
		v->fail = true;
		return;
	}
	if (neg) {
		v0_emit (v, "-");
	}
	ut64 val;
	if (v0_fold_u64 (nib, nnib, &val)) {
		v0_emitf (v, "%" PFMT64u, val);
	} else {
		v0_emit (v, "0x");
		v0_emit_n (v, nib, nnib);
	}
}

// <const-str-data> = <hex-byte-pairs> "_" ; printed as a quoted string literal
static void v0_const_str(RV0 *v) {
	const char *nib;
	int nnib;
	if (!v0_read_nibbles (v, &nib, &nnib) || (nnib & 1)) {
		v->fail = true;
		return;
	}
	int nbytes = nnib / 2, i;
	ut8 *bytes = malloc (nbytes ? nbytes : 1);
	if (!bytes) {
		v->fail = true;
		return;
	}
	for (i = 0; i < nbytes; i++) {
		ut8 b = 0;
		r_hex_to_byte (&b, nib[i * 2]);
		r_hex_to_byte (&b, nib[i * 2 + 1]);
		bytes[i] = b;
	}
	v0_emit (v, "\"");
	i = 0;
	while (i < nbytes && !v->fail) {
		RRune cp;
		const int n = r_utf8_decode (bytes + i, nbytes - i, &cp);
		if (n < 1) {
			v->fail = true;
			break;
		}
		v0_emit_escaped (v, cp, '"');
		i += n;
	}
	v0_emit (v, "\"");
	free (bytes);
}

// a struct-variant field: ["s<b62>"] <ident> ": " <const>
static void v0_field(RV0 *v) {
	(void)v0_disambiguator (v);
	v0_ident (v);
	v0_emit (v, ": ");
	v0_const (v, true);
}

// <const> = <backref> | "p" | <type-tag> <const-data>
static void v0_const(RV0 *v, bool in_value) {
	if (v->fail || v->depth > V0_MAX_DEPTH) {
		v->fail = true;
		return;
	}
	v->depth++;
	if (v0_eat (v, 'B')) {
		int saved;
		if (v0_backref_to (v, &saved)) {
			if (!v->skipping) {
				v0_const (v, in_value);
			}
			v->pos = saved;
		}
		v->depth--;
		return;
	}
	char ty = v0_next (v);
	switch (ty) {
	case 'p': // placeholder
		v0_emit (v, "_");
		break;
	case 'h': case 't': case 'm': case 'y': case 'o': case 'j': // unsigned
		v0_const_uint (v, false);
		break;
	case 'a': case 's': case 'l': case 'x': case 'n': case 'i': { // signed
		bool neg = v0_eat (v, 'n');
		v0_const_uint (v, neg);
		break;
	}
	case 'b': { // bool
		const char *nib;
		int nnib;
		ut64 val;
		if (!v0_read_nibbles (v, &nib, &nnib) || !v0_fold_u64 (nib, nnib, &val) || val > 1) {
			v->fail = true;
		} else {
			v0_emit (v, val ? "true" : "false");
		}
		break;
	}
	case 'c': { // char
		const char *nib;
		int nnib;
		ut64 val;
		if (!v0_read_nibbles (v, &nib, &nnib) || !v0_fold_u64 (nib, nnib, &val)
				|| val > 0x10FFFF || (val >= 0xD800 && val <= 0xDFFF)) {
			v->fail = true;
		} else {
			v0_emit (v, "'");
			v0_emit_escaped (v, (ut32)val, '\'');
			v0_emit (v, "'");
		}
		break;
	}
	case 'e': { // str
		bool brace = !in_value;
		if (brace) {
			v0_emit (v, "{");
		}
		v0_emit (v, "*");
		v0_const_str (v);
		if (brace) {
			v0_emit (v, "}");
		}
		break;
	}
	case 'R': // &
	case 'Q': // &mut
		if (v0_peek (v) == 'e') {
			v->pos++;
			v0_const_str (v);
		} else {
			bool brace = !in_value;
			if (brace) {
				v0_emit (v, "{");
			}
			v0_emit (v, "&");
			if (ty == 'Q') {
				v0_emit (v, "mut ");
			}
			v0_const (v, true);
			if (brace) {
				v0_emit (v, "}");
			}
		}
		break;
	case 'A': { // array [a, b, ...]
		bool brace = !in_value;
		if (brace) {
			v0_emit (v, "{");
		}
		v0_emit (v, "[");
		v0_list (v, ", ", v0_const_value);
		v0_emit (v, "]");
		if (brace) {
			v0_emit (v, "}");
		}
		break;
	}
	case 'T': { // tuple (a, b, ...)
		bool brace = !in_value;
		if (brace) {
			v0_emit (v, "{");
		}
		v0_emit (v, "(");
		if (v0_list (v, ", ", v0_const_value) == 1) {
			v0_emit (v, ",");
		}
		v0_emit (v, ")");
		if (brace) {
			v0_emit (v, "}");
		}
		break;
	}
	case 'V': { // ADT variant: unit, tuple or struct body after the path
		bool brace = !in_value;
		if (brace) {
			v0_emit (v, "{");
		}
		v0_path (v, true);
		char k = v0_next (v);
		if (k == 'T') {
			v0_emit (v, "(");
			v0_list (v, ", ", v0_const_value);
			v0_emit (v, ")");
		} else if (k == 'S') {
			v0_emit (v, " { ");
			v0_list (v, ", ", v0_field);
			v0_emit (v, " }");
		} else if (k != 'U') { // "U" is a unit variant: just the path
			v->fail = true;
		}
		if (brace) {
			v0_emit (v, "}");
		}
		break;
	}
	default:
		v->fail = true;
		break;
	}
	v->depth--;
}

// <undisambiguated-identifier> = ["u"] <decimal> ["_"] <bytes>
// Punycode-encoded identifiers are decoded to UTF-8; on failure the raw payload
// is shown as punycode{...}.
static void v0_ident(RV0 *v) {
	bool puny = v0_eat (v, 'u');
	int n = v0_decimal (v);
	if (n < 0) {
		v->fail = true;
		return;
	}
	(void)v0_eat (v, '_'); // separator
	if (n > v->len - v->pos) { // v->pos <= v->len holds, cannot overflow
		v->fail = true;
		return;
	}
	const char *payload = v->s + v->pos;
	v->pos += n;
	if (!puny) {
		v0_emit_n (v, payload, n);
		return;
	}
	// punycode: split the payload at the LAST '_' into ascii prefix and delta
	// digits, rejoin them with the standard "-" delimiter and let the shared
	// RFC 3492 decoder (same digit map as v0) do the work
	int sep = -1, k;
	for (k = n - 1; k >= 0; k--) {
		if (payload[k] == '_') {
			sep = k;
			break;
		}
	}
	const int alen = (sep > 0)? sep: 0;
	const char *deltas = (sep >= 0)? payload + sep + 1: payload;
	const int dlen = (sep >= 0)? n - sep - 1: n;
	if (dlen < 1) {
		v->fail = true;
		return;
	}
	char *joined = (alen > 0)
		? r_str_newf ("%.*s-%.*s", alen, payload, dlen, deltas)
		: r_str_ndup (deltas, dlen);
	int declen = 0;
	char *dec = joined? r_punycode_decode (joined, (int)strlen (joined), &declen): NULL;
	free (joined);
	if (dec) {
		v0_emit (v, dec);
		free (dec);
		return;
	}
	v0_emit (v, "punycode{");
	if (alen > 0) {
		v0_emit_n (v, payload, alen);
		v0_emit (v, "-");
	}
	v0_emit_n (v, deltas, dlen);
	v0_emit (v, "}");
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
	case 'C': // crate root: <identifier>  (disambiguator + hash dropped)
		(void)v0_disambiguator (v);
		v0_ident (v);
		break;
	case 'N': { // nested: <namespace> <path> <identifier>
		char ns = v0_next (v);
		// namespace must be a letter: A-Z special, a-z unspecified
		if (!((ns >= 'A' && ns <= 'Z') || (ns >= 'a' && ns <= 'z'))) {
			v->fail = true;
			break;
		}
		v0_path (v, in_value);
		ut64 dis = v0_disambiguator (v);
		// capture the identifier so we can decide whether to print "::"
		char *nm = v0_capture (v, v0_ident);
		if (ns >= 'A' && ns <= 'Z') {
			// special namespace -> ::{label[:name]#disambiguator}
			const char *label = v0_ns_label (ns);
			if (label) {
				v0_emitf (v, "::{%s", label);
			} else {
				v0_emitf (v, "::{%c", ns); // unknown ones print their letter
			}
			if (R_STR_ISNOTEMPTY (nm)) {
				v0_emitf (v, ":%s", nm);
			}
			v0_emitf (v, "#%" PFMT64u "}", dis);
		} else if (R_STR_ISNOTEMPTY (nm)) {
			v0_emitf (v, "::%s", nm);
		}
		free (nm);
		break;
	}
	case 'M': // inherent impl: <impl-path> <type>   -> <Type>
	case 'X': // trait impl: <impl-path> <type> <path> -> <Type as Trait>
	case 'Y': // <type> <path> -> <Type as Trait>
		if (c != 'Y') {
			(void)v0_disambiguator (v);
			v0_skip_path (v); // impl-path parsed for backref correctness, not printed
		}
		v0_emit (v, "<");
		v0_type (v);
		if (c != 'M') {
			v0_emit (v, " as ");
			v0_path (v, false);
		}
		v0_emit (v, ">");
		break;
	case 'I': // generic: <path> <generic-arg>* E -> path::<args>
		v0_path (v, in_value);
		v0_emit (v, in_value? "::<": "<");
		v0_list (v, ", ", v0_generic_arg);
		v0_emit (v, ">");
		break;
	case 'B': { // backref ('B' already consumed by v0_next above)
		int saved;
		if (v0_backref_to (v, &saved)) {
			if (!v->skipping) {
				v0_path (v, in_value);
			}
			v->pos = saved;
		}
		break;
	}
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
	if (r_str_startswith (p, "__R")) {
		p++;
	}
	if (!r_str_startswith (p, "_R")) {
		return NULL;
	}
	// an optional leading decimal (encoding version) precedes the path
	p = r_str_trim_head_digits (p + 2);
	RV0 v = {0};
	v.s = p;
	v.len = (int)strlen (p);
	// LLVM-added suffixes (".llvm." + uppercase hex or '@') are dropped
	const char *llvm = strstr (p, ".llvm.");
	if (llvm) {
		const char *q = llvm + strlen (".llvm.");
		while (*q && (isdigit ((unsigned char)*q) || (*q >= 'A' && *q <= 'F') || *q == '@')) {
			q++;
		}
		if (!*q) {
			v.len = (int)(llvm - p);
		}
	}
	v.out = r_strbuf_new ("");
	v0_path (&v, true);
	// allow a trailing instantiating-crate path and a vendor suffix
	if (!v.fail && v.pos < v.len && v.s[v.pos] != '.') {
		v0_skip_path (&v);
	}
	if (!v.fail && v.pos < v.len) {
		// keep any trailing "."-separated vendor suffix (".cold", ".0", ...)
		if (v0_suffix (v.s + v.pos, v.len - v.pos)) {
			r_strbuf_append_n (v.out, v.s + v.pos, v.len - v.pos);
		} else {
			v.fail = true;
		}
	}
	if (v.fail) {
		r_strbuf_free (v.out);
		return NULL;
	}
	char *res = r_strbuf_drain (v.out);
	if (R_STR_ISEMPTY (res)) {
		R_FREE (res);
	}
	return res;
}

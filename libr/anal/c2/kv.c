/* radare - LGPL - Copyright 2024-2026 - pancake */

#include <r_util.h>

typedef struct {
	const char *a;
	const char *b;
} KVCToken;

typedef struct {
	KVCToken keys[10];
	KVCToken values[10];
	size_t count;
} AttrList;

typedef struct {
	char *name;
	char *type;
} TypedefEntry;

typedef struct {
	RStrBuf *sb;
	int line;
	AttrList attrs;
	KVCToken s;
	const char *error;
	TypedefEntry tdefs[64];
	size_t tdef_count;
	int struct_pack;
} KVCParser;

typedef bool(*KVCParserCallback)(KVCParser *, const char *);

static size_t kvctoken_len(KVCToken t) {
	R_RETURN_VAL_IF_FAIL (t.a <= t.b, 0);
	return t.b - t.a;
}

static char *kvctoken_tostring(KVCToken t) {
	if (t.a && t.b) {
		size_t len = kvctoken_len (t);
		return r_str_ndup (t.a, len);
	}
	return NULL;
}

static bool kvctoken_equals(KVCToken a, KVCToken b) {
	const int alen = kvctoken_len (a);
	const int blen = kvctoken_len (b);
	if (alen != blen) {
		return false;
	}
	return !memcmp (a.a, b.a, alen);
}

static void kvctoken_trim(KVCToken *t) {
	// Skip leading whitespace and semicolons
	while (t->a < t->b && (isspace (*t->a) || *t->a == ';')) {
		t->a++;
	}
	// Skip trailing whitespace and semicolons
	while (t->b > t->a && (isspace (t->b[-1]) || t->b[-1] == ';')) {
		t->b--;
	}
}

#include "pp.inc.c"

static inline bool kvctoken_eof(KVCToken t) {
	return t.a >= t.b;
}

static const char kvc_getch(KVCParser *kvc) {
	if (!kvctoken_eof (kvc->s)) {
		const char ch = *(kvc->s.a);
		if (ch == '\n') {
			kvc->line++;
		}
		kvc->s.a++;
		return ch;
	}
	return 0; // EOF
}

static const char kvc_peek(KVCParser *kvc, int delta) { // rename to peek_at
	if (delta >= 0 && kvc->s.a + delta < kvc->s.b) {
		return kvc->s.a[delta];
	}
	return 0;
}

static void kvc_error(KVCParser *kvc, const char *msg) {
	R_LOG_WARN ("Parsing problem at line %d: %s", kvc->line, msg);
	kvc->error = msg;
	kvc->s.a = kvc->s.b;
}

static void massage_type(char **s) {
	// Skip leading semicolons
	char *str = *s;
	if (!str) {
		return;
	}
	while (*str == ';') {
		str++;
	}
	// Skip whitespace after semicolons
	while (isspace (*str)) {
		str++;
	}

	if (str != *s) {
		char *new_str = strdup (str);
		free (*s);
		*s = new_str;
	}

	// Handle asterisks in type
	char *star = strchr (*s, '*');
	if (star) {
		char *ostar = star;
		while (star > *s) {
			if (!isspace (*star)) {
				break;
			}
			star--;
		}
		char *type = r_str_ndup (*s, star - *s);
		r_str_trim (type);
		char *res = r_str_newf ("%s %s", type, ostar);
		free (*s);
		free (type);
		*s = res;
	}
}

static const char *kvc_peekn(KVCParser *kvc, size_t amount) {
	return (kvctoken_len (kvc->s) >= amount)? kvc->s.a: NULL;
}

static const char *kvctoken_find(KVCToken t, const char *needle) {
	size_t len = kvctoken_len (t);
	return (const char *)r_mem_mem ((const ut8 *)t.a, len, (const ut8 *)needle, strlen (needle));
}

static const char *kvc_find(KVCParser *kvc, const char *needle) {
	size_t len = kvctoken_len (kvc->s);
	return (const char *)r_mem_mem ((const ut8 *)kvc->s.a, len, (const ut8 *)needle, strlen (needle));
}

static inline void kvc_skipn(KVCParser *kvc, size_t amount) {
	if (amount <= kvctoken_len (kvc->s)) {
		kvc->s.a += amount;
	} else {
		// should not reach this, implies a bug somewhere else
		kvc->s.a = kvc->s.b;
	}
}

static const char *scan_to_semicolon(KVCParser *kvc, bool allow_parens) {
	while (!kvctoken_eof (kvc->s)) {
		const char c = kvc_peek (kvc, 0);
		if (c == ';') {
			return kvc->s.a;
		}
		if (!isalnum (c) && !isspace (c) && c != '_' && c != '[' && c != ']' && c != '*') {
			if (!allow_parens || (c != ',' && c != '(' && c != ')')) {
				return NULL;
			}
		}
		kvc_getch (kvc);
	}
	return NULL;
}

static bool skip_until(KVCParser *kvc, char ch) {
	while (!kvctoken_eof (kvc->s)) {
		const char c = kvc_peek (kvc, 0);
		if (c == ch) {
			return true;
		}
		kvc_getch (kvc);
	}
	return false;
}

static inline void skip_only_spaces(KVCParser *kvc) {
	while (true) {
		char ch = kvc_peek (kvc, 0);
		if (!isspace (ch)) {
			break;
		}
		kvc_getch (kvc);
	}
}

static void skip_spaces(KVCParser *kvc) {
	bool again;
	do {
		again = false;
		skip_only_spaces (kvc);
		const char *p = kvc_peekn (kvc, 2);
		if (p && p[0] == '/' && p[1] == '*') {
			kvc_skipn (kvc, 2);
			const char *closing = kvc_find (kvc, "*/");
			if (!closing) {
				kvc_error (kvc, "Unclosed comment");
				return;
			}
			kvc_skipn (kvc, 1 + closing - p);
			again = true;
		}
		p = kvc_peekn (kvc, 3);
		if (p && p[0] == '/' && p[1] == '/' && p[2] != '/') {
			skip_until (kvc, '\n');
			again = true;
		}
	} while (again);
}

static void skip_semicolons(KVCParser *kvc) {
	while (true) {
		char ch = kvc_peek (kvc, 0);
		if (!ch || ch == '\n') {
			break;
		}
		if (ch != ';' && !isspace (ch)) {
			break;
		}
		kvc_getch (kvc);
	}
}

static void skip_ws(KVCParser *kvc) {
	skip_spaces (kvc);
	skip_semicolons (kvc);
	skip_spaces (kvc);
}

static const char *consume_word(KVCParser *kvc) {
	skip_only_spaces (kvc);
	const char *word = kvc->s.a;
	while (true) {
		const char ch = kvc_peek (kvc, 0);
		if (!ch) {
			return false;
		}
		if (!isalnum (ch) && ch != '_' && ch != '-') {
			break;
		}
		if (isspace (ch)) {
			break;
		}
		kvc_getch (kvc);
	}
	return word;
}

static const char *kvc_attr(KVCParser *kvc, const char *k) {
	KVCToken s = { .a = k, .b = k + strlen (k) };
	int i;
	for (i = 0; i < kvc->attrs.count; i++) {
		if (kvctoken_equals (kvc->attrs.keys[i], s)) {
			return kvctoken_tostring (kvc->attrs.values[i]);
		}
	}
	return NULL;
}

static bool parse_attributes(KVCParser *kvc) {
	skip_spaces (kvc);
	const char *begin = kvc_peekn (kvc, 3);
	if (!begin || !r_str_startswith (begin, "///")) {
		return false;
	}
	kvc_skipn (kvc, 3);

	// kvc->attrs.count = 0;
	while (true) {
		int line = kvc->line;
		skip_spaces (kvc);
		if (line != kvc->line) {
			// newline found
			return true;
		}
		char ch = kvc_peek (kvc, 0);
		if (ch != '@') {
			R_LOG_ERROR ("unexpected attribute name must start with @ its '%c'", ch);
			break;
		}
		kvc_getch (kvc);
		KVCToken attr_name = { .a = consume_word (kvc) };
		if (!attr_name.a) {
			R_LOG_ERROR ("Cannot consume word");
			return false;
		}
		attr_name.b = kvc->s.a;
		ch = kvc_peek (kvc, 0);
		KVCToken attr_value = { 0 };
		if (ch == '(') {
			// parse value
			kvc_getch (kvc);
			attr_value.a = consume_word (kvc);
			if (!attr_value.a) {
				R_LOG_ERROR ("Cannot consume word in value");
				return false;
			}
			// kvc->s.a = attr
			ch = kvc_peek (kvc, 0);
			if (ch != ')') {
				R_LOG_ERROR ("Expected )");
				return false;
			}
			attr_value.b = kvc->s.a;
			kvc_getch (kvc);
		} else {
			attr_value.a = "true";
			attr_value.b = attr_value.a + 4;
		}
		int atidx = kvc->attrs.count;
		bool duppedkey = false;
		{
			int i;
			for (i = 0; i < kvc->attrs.count; i++) {
				if (kvctoken_equals (kvc->attrs.keys[i], attr_name)) {
					duppedkey = true;
					atidx = i;
					break;
				}
			}
		}
		if (!duppedkey) {
			kvc->attrs.count++;
			kvc->attrs.keys[atidx] = attr_name;
		}
		if (attr_value.a) {
			kvc->attrs.values[atidx] = attr_value;
		} else {
			kvc->attrs.values[atidx].a = "true";
			kvc->attrs.values[atidx].b = kvc->attrs.values[atidx].a + 4;
		}
	}
	skip_until (kvc, '\n');
	return true;
}

static bool parse_trailing_attributes(KVCParser *kvc) {
	char ch;
	while ((ch = kvc_peek (kvc, 0)) == ' ' || ch == '\t') {
		kvc_getch (kvc);
	}
	const char *begin = kvc_peekn (kvc, 3);
	if (!begin || !r_str_startswith (begin, "///")) {
		return false;
	}
	return parse_attributes (kvc);
}

static void apply_attributes(KVCParser *kvc, const char *type, const char *scope) {
	int i;
	for (i = 0; i < kvc->attrs.count; i++) {
		KVCToken key = kvc->attrs.keys[i];
		KVCToken val = kvc->attrs.values[i];
		r_strbuf_appendf (kvc->sb, "%s.%s.@.", type, scope);
		r_strbuf_append_n (kvc->sb, key.a, kvctoken_len (key));
		r_strbuf_append (kvc->sb, "=");
		r_strbuf_append_n (kvc->sb, val.a, kvctoken_len (val));
		r_strbuf_append (kvc->sb, "\n");
	}
	kvc->attrs.count = 0; // Reset after applying
}

static void kvctoken_typename(KVCToken *fun_rtyp, KVCToken *fun_name) {
	fun_rtyp->b = fun_name->b;
	kvctoken_trim (fun_rtyp);
	kvctoken_trim (fun_name);
	const bool accept_dots_in_function_names = true;
	const char *p = fun_rtyp->b - 1;
	while (p >= fun_rtyp->a) {
		bool pass = false;
		if (accept_dots_in_function_names) {
			pass = (!isalnum (*p) && *p != '.' && *p != '_') || isspace (*p);
		} else {
			pass = (!isalnum (*p) && *p != '_') || isspace (*p);
		}
		if (pass && *p != '[' && *p != ']') {
			p++;
			break;
		}
		if (p <= fun_rtyp->a) {
			break;
		}
		p--;
	}
	fun_name->a = p;
	fun_rtyp->b = p;
	kvctoken_trim (fun_rtyp);
	kvctoken_trim (fun_name);
	if (fun_name->a > fun_name->b) {
		fun_name->b = fun_name->a;
	}
	if (fun_rtyp->a > fun_rtyp->b) {
		fun_rtyp->a = fun_rtyp->b;
	}
}

static int kvc_typesize(KVCParser *kvc, const char *name, int dimension) {
	if (!strcmp (name, "char") || r_str_endswith (name, "8")) {
		return 1 * dimension;
	}
	if (!strcmp (name, "short") || r_str_endswith (name, "16")) {
		return 2 * dimension;
	}
	if (!strcmp (name, "long long") || !strcmp (name, "double") || r_str_endswith (name, "64")) {
		return 8 * dimension;
	}
	if (r_str_startswith (name, "int") || !strcmp (name, "float") || !strcmp (name, "long")) {
		return 4 * dimension;
	}
	if (dimension > 1) {
		return dimension;
	}
	return 4;
}

static int kvc_typealign(KVCParser *kvc, const char *name) {
	if (!strcmp (name, "char") || r_str_endswith (name, "8")) {
		return 1;
	}
	if (!strcmp (name, "short") || r_str_endswith (name, "16")) {
		return 2;
	}
	if (!strcmp (name, "long long") || !strcmp (name, "double") || r_str_endswith (name, "64")) {
		return 8;
	}
	return 4;
}

static void trim_underscores(KVCToken *t) {
	while (t->a[0] == '_') {
		t->a++;
	}
	while (t->b > t->a) {
		t->b--;
		if (t->b[0] != '_') {
			t->b++;
			break;
		}
	}
}

static bool parse_c_attributes(KVCParser *kvc) {
	const char *p = kvc_peekn (kvc, strlen ("__attribute__"));
	if (!p || !r_str_startswith (p, "__attribute__")) {
		return false;
	}
	kvc_skipn (kvc, strlen ("__attribute__"));
	skip_spaces (kvc);
	// Expect double parentheses
	if (kvc_getch (kvc) != '(' || kvc_getch (kvc) != '(') {
		kvc_error (kvc, "Expected __attribute__ ( (...))");
		return false;
	}
	// Parse attribute name
	KVCToken attr_name = { .a = kvc->s.a };
	while (isalnum (*kvc->s.a) || *kvc->s.a == '_') {
		kvc_getch (kvc);
	}
	attr_name.b = kvc->s.a;
	skip_spaces (kvc);
	trim_underscores (&attr_name);
	// Parse optional value
	KVCToken attr_value = { 0 };
	if (kvc_peek (kvc, 0) == '(') {
		kvc_getch (kvc);
		attr_value.a = kvc->s.a;
		const char *close = kvc_find (kvc, ")");
		if (!close) {
			kvc_error (kvc, "Missing ')' in __attribute__");
			return false;
		}
		attr_value.b = close;
		kvc_skipn (kvc, close - kvc->s.a + 1);
	} else {
		attr_value.a = "true";
		attr_value.b = attr_value.a + strlen ("true");
	}
	skip_spaces (kvc);
	if (kvc_getch (kvc) != ')') {
		kvc_error (kvc, "Expected ')' after __attribute__");
		return false;
	}
	skip_spaces (kvc);
	// Store attribute
	int idx = kvc->attrs.count++;
	kvc->attrs.keys[idx] = attr_name;
	kvc->attrs.values[idx] = attr_value;
	kvc_getch (kvc);
	return true;
}

static void kvc_register_typedef(KVCParser *kvc, const char *name, const char *type) {
	if (kvc->tdef_count < (sizeof (kvc->tdefs) / sizeof (kvc->tdefs[0]))) {
		kvc->tdefs[kvc->tdef_count].name = strdup (name);
		kvc->tdefs[kvc->tdef_count].type = strdup (type);
		kvc->tdef_count++;
	}
}

static const char *kvc_lookup_typedef(KVCParser *kvc, const char *name) {
	int i;
	for (i = 0; i < (int)kvc->tdef_count; i++) {
		if (!strcmp (kvc->tdefs[i].name, name)) {
			return kvc->tdefs[i].type;
		}
	}
	return NULL;
}

static int emit_func_args(KVCParser *kvc, const char *fname, const char *args) {
	int arg_idx = 0;
	RStrBuf *fnames = r_strbuf_new ("");
	if (R_STR_ISNOTEMPTY (args)) {
		char *args_copy = strdup (args);
		char *p = args_copy;
		while (p) {
			char *comma = strchr (p, ',');
			char *tok = comma? r_str_ndup (p, comma - p): strdup (p);
			p = comma? comma + 1: NULL;
			r_str_trim (tok);
			char *last_space = strrchr (tok, ' ');
			char *arg_type, *arg_name;
			if (last_space) {
				arg_type = r_str_ndup (tok, last_space - tok);
				r_str_trim (arg_type);
				arg_name = strdup (last_space + 1);
				r_str_trim (arg_name);
			} else {
				arg_type = strdup (tok);
				r_str_trim (arg_type);
				arg_name = strdup ("");
			}
			r_strbuf_appendf (fnames, "%s%s", arg_idx? ",": "", arg_name);
			r_strbuf_appendf (kvc->sb, "func.%s.arg.%d=%s,%s\n", fname, arg_idx, arg_type, arg_name);
			free (arg_type);
			free (arg_name);
			free (tok);
			arg_idx++;
		}
		free (args_copy);
	}
	char *fnames_s = r_strbuf_drain (fnames);
	r_strbuf_appendf (kvc->sb, "func.%s=%s\n", fname, fnames_s);
	r_strbuf_appendf (kvc->sb, "func.%s.cc=cdecl\n", fname);
	r_strbuf_appendf (kvc->sb, "func.%s.args=%d\n", fname, arg_idx);
	free (fnames_s);
	return arg_idx;
}

static void emit_func_typedef(KVCParser *kvc, const char *name, const char *rtype, const char *args) {
	if (R_STR_ISEMPTY (name)) {
		return;
	}
	emit_func_args (kvc, name, args);
	r_strbuf_appendf (kvc->sb, "func.%s.ret=%s\n", name, rtype? rtype: "void");
}

static int parse_ptr_depth(KVCParser *kvc) {
	int depth = 0;
	while (kvc_peek (kvc, 0) == '*') {
		kvc_getch (kvc);
		depth++;
		skip_spaces (kvc);
	}
	return depth;
}

static char *make_ptr_suffix(int depth) {
	if (depth <= 0) {
		return strdup ("");
	}
	RStrBuf *sb = r_strbuf_new ("");
	int i;
	for (i = 0; i < depth; i++) {
		r_strbuf_append (sb, " *");
	}
	return r_strbuf_drain (sb);
}

static bool emit_typedef_forward(KVCParser *kvc, const char *kind, const char *tag_str, int ptr_depth) {
	KVCToken alias = { .a = consume_word (kvc) };
	if (!alias.a) {
		kvc_error (kvc, "Expected alias in typedef forward declaration");
		return false;
	}
	alias.b = kvc->s.a;
	char *alias_str = kvctoken_tostring (alias);
	if (ptr_depth > 0) {
		char *ptrs = make_ptr_suffix (ptr_depth);
		char *target = r_str_newf ("%s %s%s", kind, tag_str, ptrs);
		r_strbuf_appendf (kvc->sb, "typedef.%s=%s\n", alias_str, target);
		r_strbuf_appendf (kvc->sb, "%s=typedef\n", alias_str);
		kvc_register_typedef (kvc, alias_str, target);
		free (target);
		free (ptrs);
	} else {
		r_strbuf_appendf (kvc->sb, "typedef.%s=%s %s\n", alias_str, kind, tag_str);
	}
	free (alias_str);
	skip_ws (kvc);
	return true;
}

static char *lookahead_alias_after_brace(KVCParser *kvc, const char *anon_prefix) {
	const char *closing = kvc_find (kvc, "}");
	if (closing) {
		const char *p = closing + 1;
		while (p < kvc->s.b && (isspace ((unsigned char)*p) || *p == ';')) {
			p++;
		}
		const char *start = p;
		while (p < kvc->s.b && (isalnum ((unsigned char)*p) || *p == '_')) {
			p++;
		}
		if (p > start) {
			return r_str_ndup (start, p - start);
		}
	}
	return r_str_newf ("%s_%d", anon_prefix, kvc->line);
}

static bool parse_typedef(KVCParser *kvc, const char *unused) {
	skip_spaces (kvc);
	const char *next = kvc_peekn (kvc, 6);
	if (next && r_str_startswith (next, "struct")) {
		/* typedef struct [Tag]? { ... } Alias; */
		kvc_skipn (kvc, strlen ("struct"));
		skip_spaces (kvc);
		KVCToken tag = { 0 };
		bool has_tag = false;
		if (*kvc->s.a != '{') {
			// There is a tag (or tag name) present.
			tag.a = consume_word (kvc);
			if (!tag.a) {
				kvc_error (kvc, "Expected struct tag in typedef");
				return false;
			}
			tag.b = kvc->s.a;
			has_tag = true;
			skip_spaces (kvc);
		}
		if (kvc_peek (kvc, 0) != '{') {
			skip_spaces (kvc);
			int ptr_depth = parse_ptr_depth (kvc);
			char *tag_str = has_tag? kvctoken_tostring (tag): strdup ("");
			bool res = emit_typedef_forward (kvc, "struct", tag_str, ptr_depth);
			free (tag_str);
			return res;
		}
		kvc_getch (kvc);
		char *struct_tag = has_tag? kvctoken_tostring (tag): lookahead_alias_after_brace (kvc, "anon_struct");
		r_strbuf_appendf (kvc->sb, "%s=struct\n", struct_tag);
		apply_attributes (kvc, "struct", struct_tag);
		RStrBuf *args_sb = r_strbuf_new ("");
		int member_idx = 0;
		int off = 0;
		while (true) {
			skip_spaces (kvc);
			if (kvc_peek (kvc, 0) == '}') {
				kvc_getch (kvc); // Consume '}'
				break;
			}
			parse_attributes (kvc);
			skip_spaces (kvc);
			KVCToken member_type = { 0 };
			KVCToken member_name = { 0 };
			KVCToken member_dimm = { 0 };
			// parse member type token up to semicolon
			member_type.a = kvc->s.a;
			member_type.b = scan_to_semicolon (kvc, false);
			if (!member_type.b) {
				kvc_error (kvc, "Missing semicolon in struct member");
				r_strbuf_free (args_sb);
				free (struct_tag);
				return false;
			}
			if (member_type.a == member_type.b) {
				kvc_getch (kvc);
				break;
			}
			memcpy (&member_name, &member_type, sizeof (member_name));
			kvctoken_typename (&member_type, &member_name);
#if 1
			kvc_getch (kvc); // Skip the semicolon
			parse_trailing_attributes (kvc); // Handle trailing /// comments on same line
#else
			// Handle trailing C-style __attribute__ before semicolon
			skip_spaces (kvc);
			while (parse_c_attributes (kvc)) {
				skip_spaces (kvc);
			}
			if (kvc_peek (kvc, 0) == ';') {
				kvc_getch (kvc);
			} else {
				kvc_error (kvc, "Expected ';' after struct field");
				return false;
			}
#endif
			kvctoken_trim (&member_type);
			// Handle possible array dimensions (e.g. "[10]"):
			// Handle possible array dimensions (e.g. "[10]"):
			const char *bracket = kvctoken_find (member_name, "[");
			if (bracket) {
				// Extract dimension and adjust member name to exclude brackets
				member_dimm.a = bracket + 1;
				member_dimm.b = member_name.b;
				// Set name end to bracket start (exclusive) to include full name
				member_name.b = bracket;
				const char *close = kvctoken_find (member_dimm, "]");
				if (close) {
					member_dimm.b = close;
				} else {
					r_strbuf_free (args_sb);
					free (struct_tag);
					kvc_error (kvc, "Missing ] in struct member dimension");
					return false;
				}
			}
			char *mt = kvctoken_tostring (member_type);
			char *mn = kvctoken_tostring (member_name);
			char *md = kvctoken_tostring (member_dimm);
			if (!*mn) {
				free (mt);
				free (mn);
				free (md);
				R_LOG_ERROR ("struct field parse failed");
				break;
			}
			r_strf_var (full_scope, 512, "%s.%s", struct_tag, mn);
			// Detect if this field is a function-pointer (direct or via typedef). If so,
			// skip the generic append here and let the specialized handling emit the
			// canonical named type and func.<struct>.<member> entries.
			bool _is_fp_field = kvctoken_find (member_type, " (*");
			if (!_is_fp_field) {
				// check typedefs (mt is a heap string)
				const char *tdef_local = kvc_lookup_typedef (kvc, mt);
				if (tdef_local && (strstr (tdef_local, "* (") || strstr (tdef_local, " * ("))) {
					_is_fp_field = true;
				}
			}
			if (!_is_fp_field) {
				r_strbuf_appendf (kvc->sb, "struct.%s.%s=%s,%d,%s\n", struct_tag, mn, mt, off, R_STR_ISNOTEMPTY (md)? md: "0");
				r_strbuf_appendf (kvc->sb, "struct.%s.%s.meta=0\n", struct_tag, mn);
				off += kvc_typesize (kvc, mt, 1);
				apply_attributes (kvc, "struct", full_scope);
				r_strbuf_appendf (args_sb, "%s%s", member_idx? ",": "", mn);
				member_idx++;
				free (mt);
				free (mn);
				free (md);
				// continue with next field
				continue;
			}
			// function-pointer field: release temporary strings to avoid leaks
			free (mt);
			free (mn);
			free (md);
			continue;
		}
		// After the closing '}', we expect the typedef alias:
		skip_spaces (kvc);
		KVCToken alias = { .a = consume_word (kvc) };
		if (!alias.a) {
			kvc_error (kvc, "Missing alias in typedef struct");
			r_strbuf_free (args_sb);
			free (struct_tag);
			return false;
		}
		alias.b = kvc->s.a;
		char *alias_str = kvctoken_tostring (alias);
		r_strbuf_appendf (kvc->sb, "typedef.%s=struct %s\n", alias_str, struct_tag);
		skip_ws (kvc);
		char *argstr = r_strbuf_drain (args_sb);
		r_strbuf_appendf (kvc->sb, "struct.%s=%s\n", struct_tag, argstr);
		r_strbuf_appendf (kvc->sb, "%s=struct\n", alias_str);
		free (argstr);
		free (struct_tag);
		free (alias_str);
		return true;
	} else if (next && r_str_startswith (next, "union")) {
		/* typedef union [Tag]? { ... } Alias; */
		kvc_skipn (kvc, strlen ("union"));
		skip_spaces (kvc);
		KVCToken tag = { 0 };
		bool has_tag = false;
		if (*kvc->s.a != '{') {
			// There is a tag (or tag name) present.
			tag.a = consume_word (kvc);
			if (!tag.a) {
				kvc_error (kvc, "Expected union tag in typedef");
				return false;
			}
			tag.b = kvc->s.a;
			has_tag = true;
			skip_spaces (kvc);
		}
		if (kvc_peek (kvc, 0) != '{') {
			skip_spaces (kvc);
			int ptr_depth = parse_ptr_depth (kvc);
			char *tag_str = has_tag? kvctoken_tostring (tag): strdup ("");
			bool res = emit_typedef_forward (kvc, "union", tag_str, ptr_depth);
			free (tag_str);
			return res;
		}
		kvc_getch (kvc);
		char *union_tag = has_tag? kvctoken_tostring (tag): lookahead_alias_after_brace (kvc, "anon_union");
		/* Begin output for the union definition */
		r_strbuf_appendf (kvc->sb, "%s=union\n", union_tag);
		apply_attributes (kvc, "union", union_tag);
		RStrBuf *args_sb = r_strbuf_new ("");
		int member_idx = 0;
		int off = 0;
		while (true) {
			skip_spaces (kvc);
			if (kvc_peek (kvc, 0) == '}') {
				kvc_getch (kvc); // Consume '}'
				break;
			}
			parse_attributes (kvc);
			skip_spaces (kvc);
			KVCToken member_type = { 0 };
			KVCToken member_name = { 0 };
			KVCToken member_dimm = { 0 };
			// parse member type token up to semicolon
			member_type.a = kvc->s.a;
			member_type.b = scan_to_semicolon (kvc, false);
			if (!member_type.b) {
				kvc_error (kvc, "Missing semicolon in union member");
				r_strbuf_free (args_sb);
				free (union_tag);
				return false;
			}
			if (member_type.a == member_type.b) {
				kvc_getch (kvc);
				break;
			}
			memcpy (&member_name, &member_type, sizeof (member_name));
			kvctoken_typename (&member_type, &member_name);
			kvc_getch (kvc); // Skip the semicolon
			parse_trailing_attributes (kvc); // Handle trailing /// comments on same line
			kvctoken_trim (&member_type);
			// Handle possible array dimensions (e.g. "[10]"):
			const char *bracket = kvctoken_find (member_name, "[");
			if (bracket) {
				// Extract dimension and adjust member name to exclude brackets
				member_dimm.a = bracket + 1;
				member_dimm.b = member_name.b;
				// Set name end to bracket start (exclusive) to include full name
				member_name.b = bracket;
				const char *close = kvctoken_find (member_dimm, "]");
				if (close) {
					member_dimm.b = close;
				} else {
					r_strbuf_free (args_sb);
					free (union_tag);
					kvc_error (kvc, "Missing ] in union member dimension");
					return false;
				}
			}
			char *mt = kvctoken_tostring (member_type);
			char *mn = kvctoken_tostring (member_name);
			char *md = kvctoken_tostring (member_dimm);
			if (!*mn) {
				free (mt);
				free (mn);
				free (md);
				R_LOG_ERROR ("union field parse failed");
				break;
			}
			r_strf_var (full_scope, 512, "%s.%s", union_tag, mn);
			// Detect if this field is a function-pointer (direct or via typedef). If so,
			// skip the generic append here and let the specialized handling emit the
			// canonical named type and func.<union>.<member> entries.
			bool _is_fp_field = kvctoken_find (member_type, " (*");
			if (!_is_fp_field) {
				// check typedefs (mt is a heap string)
				const char *tdef_local = kvc_lookup_typedef (kvc, mt);
				if (tdef_local && (strstr (tdef_local, "* (") || strstr (tdef_local, " * ("))) {
					_is_fp_field = true;
				}
			}
			if (!_is_fp_field) {
				r_strbuf_appendf (kvc->sb, "union.%s.%s=%s,%d,%s\n", union_tag, mn, mt, off, R_STR_ISNOTEMPTY (md)? md: "0");
				apply_attributes (kvc, "union", full_scope);
				r_strbuf_appendf (args_sb, "%s%s", member_idx? ",": "", mn);
				member_idx++;
				free (mt);
				free (mn);
				free (md);
				// continue with next field
				continue;
			}
			// function-pointer field: release temporary strings to avoid leaks
			free (mt);
			free (mn);
			free (md);
			continue;
		}
		// After the closing '}', we expect the typedef alias:
		skip_spaces (kvc);
		KVCToken alias = { .a = consume_word (kvc) };
		if (!alias.a) {
			kvc_error (kvc, "Missing alias in typedef union");
			r_strbuf_free (args_sb);
			free (union_tag);
			return false;
		}
		alias.b = kvc->s.a;
		char *alias_str = kvctoken_tostring (alias);
		r_strbuf_appendf (kvc->sb, "typedef.%s=union %s\n", alias_str, union_tag);
		skip_ws (kvc);
		char *argstr = r_strbuf_drain (args_sb);
		r_strbuf_appendf (kvc->sb, "union.%s=%s\n", union_tag, argstr);
		r_strbuf_appendf (kvc->sb, "%s=union\n", alias_str);
		free (argstr);
		free (union_tag);
		free (alias_str);
		return true;
	} else if (next && r_str_startswith (next, "enum")) {
		/* typedef enum [Tag]? { ... } Alias; */
		kvc_skipn (kvc, strlen ("enum"));
		skip_spaces (kvc);
		KVCToken tag = { 0 };
		bool has_tag = false;
		if (*kvc->s.a != '{') {
			// There is a tag (or tag name) present.
			tag.a = consume_word (kvc);
			if (!tag.a) {
				kvc_error (kvc, "Expected enum tag in typedef");
				return false;
			}
			tag.b = kvc->s.a;
			has_tag = true;
			skip_spaces (kvc);
		}
		if (kvc_peek (kvc, 0) != '{') {
			skip_spaces (kvc);
			int ptr_depth = parse_ptr_depth (kvc);
			char *tag_str = has_tag? kvctoken_tostring (tag): strdup ("");
			bool res = emit_typedef_forward (kvc, "enum", tag_str, ptr_depth);
			free (tag_str);
			return res;
		}
		kvc_getch (kvc);
		char *enum_tag = has_tag? kvctoken_tostring (tag): lookahead_alias_after_brace (kvc, "anon_enum");
		r_strbuf_appendf (kvc->sb, "%s=enum\n", enum_tag);
		RStrBuf *enumstr = NULL;
		apply_attributes (kvc, "enum", enum_tag);
		ut64 value = 0;
		bool closing = false;
		while (!closing) {
			parse_attributes (kvc);
			skip_spaces (kvc);
			KVCToken member_name = { 0 };
			KVCToken member_value = { 0 };
			member_name.a = consume_word (kvc);
			if (!member_name.a) {
				R_LOG_ERROR ("a");
				free (enum_tag);
				return false;
			}
			member_name.b = kvc->s.a;
			skip_spaces (kvc);
			char ch = kvc_getch (kvc);
			if (ch == '=') {
				skip_spaces (kvc);
				member_value.a = consume_word (kvc);
				if (!member_value.a) {
					R_LOG_ERROR ("a");
					free (enum_tag);
					return false;
				}
				member_value.b = kvc->s.a;
				skip_spaces (kvc);
				ch = kvc_getch (kvc);
				// equal
			}
			if (ch == '}') {
				closing = true;
			} else if (ch == ',') {
				// next
			} else {
				kvc_error (kvc, "Expected , or } inside enum");
				free (enum_tag);
				return false;
			}

			char *mn = kvctoken_tostring (member_name);
			apply_attributes (kvc, "enum", enum_tag);
			r_strf_var (full_scope, 512, "%s.%s", enum_tag, mn);
			if (member_value.a) {
				st64 nv = r_num_get (NULL, member_value.a);
				r_strbuf_appendf (kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, nv);
				r_strbuf_appendf (kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", enum_tag, nv, mn);
				value = nv;
			} else {
				r_strbuf_appendf (kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, (ut64)value);
				r_strbuf_appendf (kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", enum_tag, (ut64)value, mn);
			}
			if (enumstr) {
				r_strbuf_appendf (enumstr, ",%s", mn);
			} else {
				enumstr = r_strbuf_new (mn);
			}
			free (mn);
			value++;
		}
		if (enumstr) {
			char *es = r_strbuf_drain (enumstr);
			r_strbuf_appendf (kvc->sb, "enum.%s=%s\n", enum_tag, es);
			free (es);
		}
		// After the closing '}', we expect the typedef alias:
		skip_spaces (kvc);
		KVCToken alias = { .a = consume_word (kvc) };
		if (!alias.a) {
			kvc_error (kvc, "Missing alias in typedef enum");
			free (enum_tag);
			return false;
		}
		alias.b = kvc->s.a;
		char *alias_str = kvctoken_tostring (alias);
		r_strbuf_appendf (kvc->sb, "typedef.%s=enum %s\n", alias_str, enum_tag);
		r_strbuf_appendf (kvc->sb, "%s=enum\n", alias_str);
		skip_ws (kvc);
		free (enum_tag);
		free (alias_str);
		return true;
	} else {
		/* Handle a “simple” typedef such as:
		typedef int myint;
		In this case we assume that everything from the current pointer until
		the semicolon is the declaration, and the last word is the alias. */
		const char *start = kvc->s.a;
		/* First check if this is a function-pointer typedef of the form:
		typedef RETTYPE (*alias) (ARGS); */
		KVCToken decl = { .a = start };
		/* find semicolon for decl end */
		const char *semicolon = scan_to_semicolon (kvc, true);
		if (!semicolon) {
			semicolon = scan_to_semicolon (kvc, false);
		}
		decl.b = semicolon;
		if (!semicolon) {
			kvc_error (kvc, "Missing semicolon in typedef");
			return false;
		}
		/* Detect function-pointer typedefs like: typedef RET (*alias) (args); */
		const char *fp_marker = kvctoken_find (decl, " (*");
		if (fp_marker) {
			const char *name_start = fp_marker + 3;
			const char *name_end = name_start;
			while (name_end < semicolon && *name_end != ')') {
				name_end++;
			}
			if (name_end < semicolon) {
				KVCToken alias = { .a = name_start, .b = name_end };
				kvctoken_trim (&alias);
				char *alias_str = kvctoken_tostring (alias);
				KVCToken rtype_tok = { .a = start, .b = fp_marker };
				kvctoken_trim (&rtype_tok);
				char *rtype = kvctoken_tostring (rtype_tok);
				/* find args */
				const char *args_open = name_end;
				while (args_open < semicolon && *args_open != '(') {
					args_open++;
				}
				char *args_str = NULL;
				if (args_open < semicolon) {
					const char *args_end = semicolon - 1;
					while (args_end >= args_open && *args_end != ')') {
						args_end--;
					}
					if (args_end > args_open) {
						KVCToken args_tok = { .a = args_open + 1, .b = args_end };
						args_str = kvctoken_tostring (args_tok);
						r_str_trim (args_str);
					}
				}
				char *fulltype = r_str_newf ("%s * (%s)", rtype, args_str? args_str: "");
				// Map typedef alias to a canonical func.<alias> handle and emit func entries so the typedef
				// can be resolved even if it is never referenced by a struct field.
				r_strbuf_appendf (kvc->sb, "typedef.%s=func.%s\n", alias_str, alias_str);
				r_strbuf_appendf (kvc->sb, "%s=typedef\n", alias_str);
				emit_func_typedef (kvc, alias_str, rtype, args_str);
				// Keep the original fulltype registered so other code can detect function-pointer typedefs
				kvc_register_typedef (kvc, alias_str, fulltype);
				kvc_skipn (kvc, semicolon - kvc->s.a);
				if (kvc_peek (kvc, 0) == ';') {
					kvc_getch (kvc);
				}
				free (alias_str);
				free (rtype);
				if (args_str) {
					free (args_str);
				}
				free (fulltype);
				return true;
			}
		}
		const char *p = semicolon - 1;
		// Skip trailing spaces before alias
		while (p >= start && isspace (*p)) {
			p--;
		}
		// Mark end of alias
		const char *alias_end = p + 1;
		// Scan backwards over alias characters (alphanumeric and underscore)
		while (p >= start && (isalnum (*p) || *p == '_')) {
			p--;
		}
		// If stopped on non-identifier, advance to start of alias
		if (p < start || (!isalnum (*p) && *p != '_')) {
			p++;
		}
		// Alias token
		KVCToken alias = { .a = p, .b = alias_end };
		// Original type spans from start up to alias start
		KVCToken orig_type = { .a = start, .b = p };
		kvctoken_trim (&alias);
		kvctoken_trim (&orig_type);
		char *alias_str = kvctoken_tostring (alias);
		char *type_str = kvctoken_tostring (orig_type);
		r_strbuf_appendf (kvc->sb, "typedef.%s=%s\n", alias_str, type_str);
		r_strbuf_appendf (kvc->sb, "%s=typedef\n", alias_str);
		/* Register simple typedef for later lookup */
		kvc_register_typedef (kvc, alias_str, type_str);
		free (alias_str);
		free (type_str);
		kvc_skipn (kvc, semicolon - kvc->s.a);
		if (kvc_peek (kvc, 0) == ';') {
			kvc_getch (kvc);
		}
		return true;
	}
}

// works for unions and structs
static bool parse_struct(KVCParser *kvc, const char *type) {
	KVCToken struct_name = { .a = consume_word (kvc) };
	if (!struct_name.a) {
		R_LOG_ERROR ("Cannot consume word");
		return false;
	}
	struct_name.b = kvc->s.a;
	skip_spaces (kvc);
	parse_c_attributes (kvc);
	skip_spaces (kvc);
	const char p0 = kvc_peek (kvc, 0);
	if (p0 != '{') {
		R_LOG_ERROR ("Expected { after name in struct");
		return false;
	}
	RStrBuf *args_sb = r_strbuf_new ("");
	kvc_getch (kvc);
	char *sn = kvctoken_tostring (struct_name);
	r_strbuf_appendf (kvc->sb, "%s=%s\n", sn, type);
	const char *pack_attr = kvc_attr (kvc, "pack");
	const char *packed_attr = kvc_attr (kvc, "packed");
	if (pack_attr) {
		kvc->struct_pack = atoi (pack_attr);
	} else if (packed_attr) {
		kvc->struct_pack = 1;
	} else {
		kvc->struct_pack = 0;
	}
	free ((void *)pack_attr);
	free ((void *)packed_attr);
	apply_attributes (kvc, type, sn);
	// Lookahead: scan struct body for direct function-pointer members so we can
	// emit a typedef-like func handle for them (e.g. foo.fp=func)
	{
		const char *closing = kvc_find (kvc, "}");
		if (closing) {
			const char *p = kvc->s.a;
			while (p < closing) {
				const char *st = (const char *)r_mem_mem ((const ut8 *)p, closing - p, (const ut8 *)"(*", 2);
				if (!st) {
					break;
				}
				// find member name between '(*' and ')'
				const char *name_start = st + 2;
				const char *name_end = name_start;
				while (name_end < closing && *name_end != ')') {
					name_end++;
				}
				if (name_end >= closing) {
					p = name_end;
					continue;
				}
				KVCToken mtok = { .a = name_start, .b = name_end };
				kvctoken_trim (&mtok);
				char *mname_look = kvctoken_tostring (mtok);
				if (mname_look) {
					const char *tdef = kvc_lookup_typedef (kvc, mname_look);
					if (tdef) {
						r_strbuf_appendf (kvc->sb, "%s.%s=func\n", sn, mname_look);
					}
					free (mname_look);
				}
				p = name_end + 1;
			}
		}
	}
	int member_idx = 0;
	int off = 0;
	while (true) {
		parse_attributes (kvc);
		skip_spaces (kvc);
		KVCToken member_type = { 0 };
		KVCToken member_name = { 0 };
		KVCToken member_dimm = { 0 };
		member_type.a = kvc->s.a;
		// Support function pointer fields: allow parentheses when scanning semicolon
		if (kvctoken_find ((KVCToken){ member_type.a, kvc->s.b }, " (*")) {
			member_type.b = scan_to_semicolon (kvc, true);
		} else {
			member_type.b = scan_to_semicolon (kvc, false);
		}
		if (!member_type.b) {
			// attempt extended scan allowing parentheses (attributes or function pointers)
			const char *semi2 = scan_to_semicolon (kvc, true);
			if (!semi2) {
				const char ch0 = kvc_peek (kvc, 0);
				if (ch0 == '}') {
					// end of struct definition
					kvc_getch (kvc);
					kvc_getch (kvc);
					break;
				}
				kvc_error (kvc, "Missing semicolon in struct member");
				r_strbuf_free (args_sb);
				free (sn);
				return false;
			}
			// check for C-style attribute inside this span
			const char *attrp = kvctoken_find ((KVCToken){ member_type.a, semi2 }, "__attribute");
			if (attrp) {
				member_type.b = attrp - 1;
				kvc->s.a = attrp;
				if (!parse_c_attributes (kvc)) {
					r_strbuf_free (args_sb);
					return false;
				}
				skip_spaces (kvc);
			} else {
				// function pointer: include full type span
				member_type.b = semi2;
				kvc->s.a = semi2;
			}
		}
		if (member_type.a == member_type.b) {
			kvc_getch (kvc);
			break;
		}
		memcpy (&member_name, &member_type, sizeof (member_name));
		kvctoken_typename (&member_type, &member_name);
		skip_semicolons (kvc);
		parse_trailing_attributes (kvc); // Handle trailing /// comments on same line
		kvctoken_trim (&member_type);
		// Special-case function pointer fields
		if (kvctoken_find (member_type, " (*")) {
			// member_type spans entire function pointer declaration including args
			const char *start = member_type.a;
			const char *starp = strstr (start, " (*");
			if (starp) {
				// return type
				char *rtype = r_str_ndup (start, starp - start);
				r_str_trim (rtype);
				// member name
				const char *name_start = starp + 3;
				const char *name_end = strchr (name_start, ')');
				char *mname = NULL;
				if (name_end && name_end > name_start) {
					mname = r_str_ndup (name_start, name_end - name_start);
					r_str_trim (mname);
				}
				// argument types
				const char *args_start = NULL;
				if (name_end) {
					args_start = strchr (name_end + 1, '(');
				}
				char *args = NULL;
				if (args_start && args_start < member_type.b) {
					const char *args_end = member_type.b;
					// skip trailing ')'
					if (args_end > args_start && args_end[-1] == ')') {
						args_end--;
					}
					args = r_str_ndup (args_start + 1, args_end - args_start - 1);
					r_str_trim (args);
				}
				// build full type string
				char *fulltype = r_str_newf ("%s * (%s)", rtype, args? args: "");
				// We'll reference the function-pointer's type by a struct-prefixed name: <struct>.<member>
				char *type_name = r_str_newf ("%s.%s", sn, mname);
				// Emit the struct member referring to that type name (no commas in the type)
				r_strbuf_appendf (kvc->sb, "struct.%s.%s=%s,%d,0\n", sn, mname, type_name, off);
				char *fname = r_str_newf ("%s.%s", sn, mname);
				emit_func_args (kvc, fname, args);
				free (fname);
				// return type
				r_strbuf_appendf (kvc->sb, "type.%s.%s=func\n", sn, mname);
				r_strbuf_appendf (kvc->sb, "%s.%s=func\n", sn, mname);
				r_strbuf_appendf (kvc->sb, "func.%s.%s.ret=%s\n", sn, mname, rtype? rtype: "void");
				// store the canonical signature too
				r_strbuf_appendf (kvc->sb, "func.%s.%s=%s\n", sn, mname, args? args: "");
				off += kvc_typesize (kvc, fulltype, 1);
				// add member name to struct's args list and advance index
				r_strbuf_appendf (args_sb, "%s%s", member_idx? ",": "", mname);
				member_idx++;
				{
					r_strf_var (full_scope, 512, "%s.%s", sn, mname);
					apply_attributes (kvc, "struct", full_scope);
				}
				free (type_name);
				free (fulltype);
				free (rtype);
				if (args) {
					free (args);
				}
				free (mname);
				/* mt_check is not defined in this scope */
				continue;
			}
		}
		// Check for typedef aliases that represent function pointers
		{
			char *mt_check = kvctoken_tostring (member_type);
			const char *tdef = kvc_lookup_typedef (kvc, mt_check);
			if (tdef) {
				/* If typedef stored a function-pointer like "int * (...)" treat it as function pointer */
				if (strstr (tdef, "* (") || strstr (tdef, " * (")) {
					char *mname = kvctoken_tostring (member_name);
					// split tdef into rtype and args
					const char *p = strstr (tdef, "* (");
					if (!p) {
						p = strstr (tdef, " * (");
					}
					if (p) {
						int rlen = p - tdef;
						char *rtype = r_str_ndup (tdef, rlen);
						r_str_trim (rtype);
						// find args
						const char *args_open = strchr (p, '(');
						char *args_str = NULL;
						if (args_open) {
							const char *args_close = strrchr (tdef, ')');
							if (args_close && args_close > args_open) {
								args_str = r_str_ndup (args_open + 1, args_close - args_open - 1);
								r_str_trim (args_str);
							}
						}
						// For typedef function-pointer types, reference the typedef alias as the field's type
						r_strbuf_appendf (kvc->sb, "struct.%s.%s=%s,%d,0\n", sn, mname, mt_check, off);
						off += kvc_typesize (kvc, tdef, 1);
						r_strbuf_appendf (args_sb, "%s%s", member_idx? ",": "", mname);
						member_idx++;
						{
							r_strf_var (full_scope, 512, "%s.%s", sn, mname);
							apply_attributes (kvc, "struct", full_scope);
						}
						emit_func_args (kvc, mt_check, args_str);
						r_strbuf_appendf (kvc->sb, "func.%s.ret=%s\n", mt_check, rtype);
						free (mname);
						free (rtype);
						if (args_str) {
							free (args_str);
						}
						free (mt_check);
						continue;
					}
				}
			}
			free (mt_check);
		}
		if (member_name.a) {
			const char *bracket = kvctoken_find (member_name, "[");
			if (bracket) {
				// parse dimensions
				member_dimm.a = bracket + 1;
				member_dimm.b = member_name.b;
				member_name.b = member_dimm.a - 1;
				member_dimm.b = kvctoken_find (member_dimm, "]");
				if (member_dimm.b) {
					// Dimensions already consumed by kvc_find_semicolon; no need to skip
				} else {
					R_LOG_ERROR ("Missing ] in struct field dimension");
				}
			}
		}

		char *mt = kvctoken_tostring (member_type);
		char *mn = kvctoken_tostring (member_name);
		char *md = kvctoken_tostring (member_dimm);
		if (!*mn) {
			kvc_error (kvc, "Missing type, name or dimension in struct field");
			free (mt);
			free (mn);
			free (md);
			break;
		}
		massage_type (&mt);
		r_strf_var (full_scope, 512, "%s.%s", sn, mn);
		int dimension = 1;
		const char *align_attribute = kvc_attr (kvc, "aligned");
		int av = kvc_typealign (kvc, mt);
		if (align_attribute) {
			int explicit_align = atoi (align_attribute);
			if (explicit_align > 0) {
				av = explicit_align;
			}
			free ((void *)align_attribute);
		}
		if (kvc->struct_pack > 0 && av > kvc->struct_pack) {
			av = kvc->struct_pack;
		}
		if (av > 1 && (off % av)) {
			const int rest = av - (off % av);
			off += rest;
		}
		if (md) {
			dimension = atoi (md);
			r_strbuf_appendf (kvc->sb, "%s.%s=%s,%d,%s\n", type, full_scope, mt, off, md);
		} else {
			r_strbuf_appendf (kvc->sb, "%s.%s=%s,%d,0\n", type, full_scope, mt, off);
		}
		if (!strcmp (type, "struct")) {
			off += kvc_typesize (kvc, mt, dimension);
		}
		// r_strbuf_appendf (kvc->sb, "%s.%s.meta=0\n", type, mn);
		apply_attributes (kvc, type, full_scope);
		r_strbuf_appendf (args_sb, "%s%s", member_idx? ",": "", mn);
		member_idx++;
		free (mt);
		free (mn);
		free (md);
	}
	skip_ws (kvc);
	char *argstr = r_strbuf_drain (args_sb);
	r_strbuf_appendf (kvc->sb, "%s.%s=%s\n", type, sn, argstr);
	free (argstr);
	free (sn);
	return true;
}

static bool parse_enum(KVCParser *kvc, const char *name) {
	parse_attributes (kvc);
	KVCToken enum_name = { .a = consume_word (kvc) };
	if (!enum_name.a) {
		R_LOG_ERROR ("Cannot consume a word");
		return false;
	}
	enum_name.b = kvc->s.a;
	char *en = kvctoken_tostring (enum_name);
	r_strbuf_appendf (kvc->sb, "%s=enum\n", en);
	RStrBuf *enumstr = NULL;
	apply_attributes (kvc, "enum", en);
	skip_spaces (kvc);
	const char p0 = kvc_peek (kvc, 0);
	if (p0 != '{') {
		R_LOG_ERROR ("Expected { after name in enum");
		free (en);
		return false;
	}
	kvc_getch (kvc);
	ut64 value = 0;
	bool closing = false;
	while (!closing) {
		parse_attributes (kvc);
		skip_spaces (kvc);
		KVCToken member_name = { 0 };
		KVCToken member_value = { 0 };
		member_name.a = consume_word (kvc);
		if (!member_name.a) {
			R_LOG_ERROR ("a");
			return false;
		}
		member_name.b = kvc->s.a;
		skip_spaces (kvc);
		char ch = kvc_getch (kvc);
		if (ch == '=') {
			skip_spaces (kvc);
			member_value.a = consume_word (kvc);
			if (!member_value.a) {
				R_LOG_ERROR ("a");
				return false;
			}
			member_value.b = kvc->s.a;
			skip_spaces (kvc);
			ch = kvc_getch (kvc);
			// equal
		}
		if (ch == '}') {
			closing = true;
		} else if (ch == ',') {
			// next
		} else {
			kvc_error (kvc, "Expected , or } inside enum");
			free (en);
			return false;
		}

		char *mn = kvctoken_tostring (member_name);
		apply_attributes (kvc, "enum", en);
		r_strf_var (full_scope, 512, "%s.%s", en, mn);
		if (member_value.a) {
			st64 nv = r_num_get (NULL, member_value.a);
			r_strbuf_appendf (kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, nv);
			r_strbuf_appendf (kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", en, nv, mn);
			value = nv;
		} else {
			r_strbuf_appendf (kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, (ut64)value);
			r_strbuf_appendf (kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", en, (ut64)value, mn);
		}
		if (enumstr) {
			r_strbuf_appendf (enumstr, ",%s", mn);
		} else {
			enumstr = r_strbuf_new (mn);
		}
		free (mn);
		value++;
	}
	if (enumstr) {
		char *es = r_strbuf_drain (enumstr);
		r_strbuf_appendf (kvc->sb, "enum.%s=%s\n", en, es);
		free (es);
	}
	skip_ws (kvc);
	free (en);
	return true;
}

static bool parse_function(KVCParser *kvc) {
	parse_attributes (kvc);
	bool is_static = false;
	skip_spaces (kvc);
	const char *word = kvc_peekn (kvc, 7);
	if (word && !strncmp (word, "static", 6) && (isspace (word[6]) || word[6] == 0 || word[6] == ';')) {
		kvc_skipn (kvc, 6);
		skip_spaces (kvc);
		is_static = true;
	}
	KVCToken fun_name = { 0 };
	KVCToken fun_rtyp = { 0 };
	KVCToken fun_parm = { 0 };
	fun_rtyp.a = consume_word (kvc);
	if (!fun_rtyp.a) {
		// no need to error here, there's nothing to parse
		// kvc_error (kvc, "Cannot consume word for function");
		return false;
	}
	fun_rtyp.b = kvc->s.a;
	fun_name.a = fun_rtyp.a;
	if (!skip_until (kvc, '(')) {
		kvc_error (kvc, "Cannot find ( in function definition");
		// r_sys_breakpoint ();
		return false;
	}
	fun_name.b = kvc->s.a;
	fun_parm.a = kvc->s.a + 1;
	if (!skip_until (kvc, ')')) {
		kvc_error (kvc, "Cannot find ) in function definition");
		return false;
	}
	kvctoken_typename (&fun_rtyp, &fun_name);
	fun_parm.b = kvc->s.a;
	kvc_skipn (kvc, 1);
	skip_ws (kvc);
	char *fn = kvctoken_tostring (fun_name);
	char *fr = kvctoken_tostring (fun_rtyp);
	r_strbuf_appendf (kvc->sb, "%s=func\n", fn);
	apply_attributes (kvc, "func", fn);
	RStrBuf *func_args_sb = r_strbuf_new ("");
	int arg_idx = 0;
	if (fun_parm.a < fun_parm.b) {
		const char *pa = fun_parm.a;
		const char *pb = fun_parm.b;
		const char *argp = pa;
		const char *comma = NULL;
		do {
			while (pa < pb && isspace ((unsigned char)*pa)) {
				pa++;
			}
			comma = r_str_nchr (pa, ',', pb - pa);
			pa = comma? comma: pb;
			if (pa == pb) {
				// break;
			}
			KVCToken arg_type = { argp, pa };
			KVCToken arg_name = { argp, pa };
			kvctoken_typename (&arg_type, &arg_name);
			char *an = kvctoken_tostring (arg_name);
			char *at = kvctoken_tostring (arg_type);
			{
				char *full = kvctoken_tostring ((KVCToken){ argp, pa });
				r_str_trim (full);
				if (!strcmp (full, "...")) {
					// vararg, set name to varg
					free (at);
					at = full;
					free (an);
					an = strdup ("varg");
				} else if (!kvctoken_len (arg_type)) {
					// unnamed type
					free (at);
					at = full;
					free (an);
					an = r_str_newf ("arg%d", arg_idx);
				} else {
					free (full);
				}
			}
			massage_type (&at);
			if ((!an || !*an) && strcmp (at, "...") != 0) {
				free (an);
				an = r_str_newf ("arg%d", arg_idx);
			}
			if (R_STR_ISEMPTY (at) && !strcmp (an, "void") && arg_idx == 0) {
				// TODO: check if its the only arg
				arg_idx--;
			} else {
				r_strbuf_appendf (kvc->sb, "func.%s.arg.%d=%s,%s\n", fn, arg_idx, at, an);
				r_strbuf_appendf (func_args_sb, "%s%s", arg_idx? ",": "", an);
			}
			free (an);
			free (at);
			arg_idx++;
			pa++;
			argp = pa;
		} while (comma);
	}
	char *func_args = r_strbuf_drain (func_args_sb);
	r_strbuf_appendf (kvc->sb, "func.%s.cc=%s\n", fn, "cdecl");
	r_strbuf_appendf (kvc->sb, "func.%s=%s\n", fn, func_args);
	if (is_static) {
		r_strbuf_appendf (kvc->sb, "func.%s.@.static=true\n", fn);
	}
	r_strbuf_appendf (kvc->sb, "func.%s.ret=%s\n", fn, fr);
	r_strbuf_appendf (kvc->sb, "func.%s.args=%d\n", fn, arg_idx);
	free (func_args);
	free (fn);
	free (fr);
	return true;
}

static void kvcparser_init(KVCParser *kvc, const char *data) {
	kvc->line = 1;
	kvc->sb = r_strbuf_new ("");
	kvc->s.a = data;
	kvc->s.b = data + strlen (data);
}

static void kvcparser_fini(KVCParser *kvc) {
	int i;
	for (i = 0; i < (int)kvc->tdef_count; i++) {
		free (kvc->tdefs[i].name);
		free (kvc->tdefs[i].type);
	}
	kvc->tdef_count = 0;
	r_strbuf_free (kvc->sb);
}

static bool tryparse(KVCParser *kvc, const char *word, const char *type, KVCParserCallback cb) {
	if (r_str_startswith (word, type)) {
		kvc_skipn (kvc, strlen (type));
		const char ch = kvc_getch (kvc);
		if (isspace (ch)) {
			skip_spaces (kvc);
			return cb? cb (kvc, type): true;
		}
	}
	return false;
}

R_IPI char *kvc_parse(const char *header_content, char **errmsg) {
	// Initialize a preprocessing state for this parse
	PPState *pps = pp_new ();
	char *pre = pp_preprocess (pps, header_content);
	if (!pre) {
		pp_free (pps);
		return NULL;
	}
	pp_free (pps);
	KVCParser _kvc = { 0 };
	KVCParser *kvc = &_kvc;
	kvcparser_init (&_kvc, pre);
	while (!kvctoken_eof (kvc->s)) {
		skip_ws (kvc);
		const char *word = kvc_peekn (kvc, 6);
		bool hasparse = false;
		if (word) {
#if 1
			hasparse = tryparse (kvc, word, "typedef", parse_typedef);
			hasparse |= tryparse (kvc, word, "struct", parse_struct);
			hasparse |= tryparse (kvc, word, "union", parse_struct);
			hasparse |= tryparse (kvc, word, "enum", parse_enum);
#else
			hasparse = tryparse (kvc, word, "typedef", parse_typedef);
			if (!hasparse) {
				hasparse = tryparse (kvc, word, "struct", parse_struct);
			}
			if (!hasparse) {
				hasparse = tryparse (kvc, word, "union", parse_struct);
			}
			if (!hasparse) {
				hasparse = tryparse (kvc, word, "enum", parse_enum);
			}
#endif
		}
		if (hasparse) {
			continue;
		}
		if (parse_attributes (kvc)) {
			continue;
		}
		if (!parse_function (kvc)) {
			kvc_getch (kvc);
		}
	}
	char *res = NULL;
	if (kvc->error && errmsg) {
		*errmsg = strdup (kvc->error);
	} else {
		res = r_strbuf_drain (kvc->sb);
		kvc->sb = NULL;
	}
	kvcparser_fini (kvc);
	free (pre);
	return res;
}

#if MAIN
int main(int argc, char *argv[]) {
	if (argc < 2) {
		eprintf ("Usage: %s <header_file.h>\n", argv[0]);
		return 1;
	}

	char *content = r_file_slurp (argv[1], NULL);
	if (!content) {
		R_LOG_ERROR ("Failed to read file: %s", argv[1]);
		return 1;
	}

	char *result = kvc_parse ((const char *)content, NULL);
	if (result) {
		printf ("%s\n", result);
		free (result);
	}

	free (content);
	return 0;
}
#endif

/* radare - LGPL - Copyright 2024-2025 - pancake */

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
} KVCParser;

typedef bool (*KVCParserCallback)(KVCParser *, const char *);

static size_t kvctoken_len(KVCToken t) {
	R_RETURN_VAL_IF_FAIL(t.a <= t.b, 0);
	return t.b - t.a;
}

static char *kvctoken_tostring(KVCToken t) {
	if (t.a && t.b) {
		size_t len = kvctoken_len(t);
		return r_str_ndup(t.a, len);
	}
	return NULL;
}

static bool kvctoken_equals(KVCToken a, KVCToken b) {
	int alen = kvctoken_len(a);
	int blen = kvctoken_len(b);
	if (alen != blen) {
		return false;
	}
	return !memcmp(a.a, b.a, alen);
}

static void kvctoken_trim(KVCToken *t) {
	// Skip leading whitespace and semicolons
	while (isspace(*t->a) || *t->a == ';') {
		t->a++;
	}
	// Skip trailing whitespace and semicolons
	while (t->b > t->a && (isspace(t->b[-1]) || t->b[-1] == ';')) {
		t->b--;
	}
}

#include "pp.inc.c"

static inline bool kvctoken_eof(KVCToken t) {
	return t.a >= t.b;
}

static const char kvc_getch(KVCParser *kvc) {
	if (!kvctoken_eof(kvc->s)) {
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
	R_LOG_ERROR("Parsing problem at line %d: %s", kvc->line, msg);
	kvc->error = msg;
	kvc->s.a = kvc->s.b;
}

static void massage_type(char **s) {
	// Skip leading semicolons
	char *str = *s;
	while (*str == ';') {
		str++;
	}
	// Skip whitespace after semicolons
	while (isspace(*str)) {
		str++;
	}

	if (str != *s) {
		char *new_str = strdup(str);
		free(*s);
		*s = new_str;
	}

	// Handle asterisks in type
	char *star = strchr(*s, '*');
	if (star) {
		char *ostar = star;
		while (star > *s) {
			if (!isspace(*star)) {
				break;
			}
			star--;
		}
		char *type = r_str_ndup(*s, star - *s);
		r_str_trim(type);
		char *res = r_str_newf("%s %s", type, ostar);
		free(*s);
		free(type);
		*s = res;
	}
}

static const char *kvc_peekn(KVCParser *kvc, size_t amount) {
	return (kvctoken_len(kvc->s) >= amount) ? kvc->s.a : NULL;
}

static const char *kvctoken_find(KVCToken t, const char *needle) {
	size_t len = kvctoken_len(t);
	return (const char *)r_mem_mem((const ut8 *)t.a, len, (const ut8 *)needle, strlen(needle));
}

static const char *kvc_find(KVCParser *kvc, const char *needle) {
	size_t len = kvctoken_len(kvc->s);
	return (const char *)r_mem_mem((const ut8 *)kvc->s.a, len, (const ut8 *)needle, strlen(needle));
}

static inline void kvc_skipn(KVCParser *kvc, size_t amount) {
	if (amount <= kvctoken_len(kvc->s)) {
		kvc->s.a += amount;
	} else {
		// should not reach this, implies a bug somewhere else
		kvc->s.a = kvc->s.b;
	}
}

static const char *kvc_find_semicolon2(KVCParser *kvc) {
	while (!kvctoken_eof(kvc->s)) {
		const char c = kvc_peek(kvc, 0);
		if (c == ';') {
			// kvc_getch (kvc);
			return kvc->s.a;
		}
		// allow alphanumeric, space, underscore, comma, and [],*, () inside type
		if (!isalnum(c) && !isspace(c) && c != '_' && c != ',') {
			if (c != '[' && c != ']' && c != '*' && c != '(' && c != ')') {
				return NULL;
			}
		}
		kvc_getch(kvc);
	}
	return NULL;
}
static const char *kvc_find_semicolon(KVCParser *kvc) {
	while (!kvctoken_eof(kvc->s)) {
		const char c = kvc_peek(kvc, 0);
		if (c == ';') {
			// kvc_getch (kvc);
			return kvc->s.a;
		}
		if (!isalnum(c) && !isspace(c) && c != '_') {
			if (c != '[' && c != ']' && c != '*') {
				return NULL;
			}
		}
		kvc_getch(kvc);
	}
	return NULL;
}

// rename to until_but
static bool skip_until(KVCParser *kvc, char ch, char ch2) {
	while (!kvctoken_eof(kvc->s)) {
		const char c = kvc_peek(kvc, 0);
		if (!c) {
			break;
		}
		if (c == ch) {
			// kvc_getch (kvc);
			return true;
		}
		if (ch2 && c != ch2) {
			//		kvc_getch (kvc);
			return true;
		}
		kvc_getch(kvc);
	}
	return false;
}

static inline void skip_only_spaces(KVCParser *kvc) {
	while (true) {
		char ch = kvc_peek(kvc, 0);
		if (!isspace(ch)) {
			break;
		}
		kvc_getch(kvc);
	}
}

static void skip_semicolons(KVCParser *kvc) {
	while (true) {
		char ch = kvc_peek(kvc, 0);
		if (!ch) {
			break;
		}
		if (ch != ';' && !isspace(ch)) {
			break;
		}
		kvc_getch(kvc);
	}
}

static void skip_spaces(KVCParser *kvc) { // TODO: rename to skip_only_spacesand_comments
	bool havespace = false;
repeat:
	skip_only_spaces(kvc);
	const char *comment = kvc_peekn(kvc, 2);
	if (comment && r_str_startswith(comment, "/*")) {
		havespace = true;
		kvc_skipn(kvc, 2);
		const char *closing = kvc_find(kvc, "*/");
		if (!closing) {
			kvc_error(kvc, "Unclosed comment");
			return;
		}
		int delta = 1 + closing - comment;
		kvc_skipn(kvc, delta);
	}
	skip_only_spaces(kvc);
	const char *slash = kvc_peekn(kvc, 3);
	if (slash && slash[0] == '/' && slash[1] == '/' && slash[2] != '/') {
		skip_until(kvc, '\n', 0);
		havespace = true;
		skip_only_spaces(kvc);
	}
	if (havespace) {
		havespace = false;
		goto repeat;
	}
}

static const char *consume_word(KVCParser *kvc) {
	skip_only_spaces(kvc);
	const char *word = kvc->s.a;
	while (true) {
		const char ch = kvc_peek(kvc, 0);
		if (!ch) {
			return false;
		}
		if (!isalnum(ch) && ch != '_' && ch != '-') {
			break;
		}
		if (isspace(ch)) {
			break;
		}
		kvc_getch(kvc);
	}
	return word;
}

static const char *kvc_attr(KVCParser *kvc, const char *k) {
	KVCToken s = { .a = k, .b = k + strlen(k) };
	int i;
	for (i = 0; i < kvc->attrs.count; i++) {
		if (kvctoken_equals(kvc->attrs.keys[i], s)) {
			return kvctoken_tostring(kvc->attrs.values[i]);
		}
	}
	return NULL;
}

static bool parse_attributes(KVCParser *kvc) {
	const char *begin = kvc_peekn(kvc, 3);
	if (!begin) {
		return false;
	}
	if (!r_str_startswith(begin, "///")) {
		return false;
	}
	kvc_skipn(kvc, 3);

	// kvc->attrs.count = 0;
	int line = kvc->line;
	while (true) {
		line = kvc->line;
		skip_spaces(kvc);
		if (line != kvc->line) {
			// newline found
			return true;
		}
		char ch = kvc_peek(kvc, 0);
		if (ch != '@') {
			R_LOG_ERROR("unexpected attribute name must start with @ its '%c'", ch);
			break;
		}
		kvc_getch(kvc);
		KVCToken attr_name = { .a = consume_word(kvc) };
		if (!attr_name.a) {
			R_LOG_ERROR("Cannot consume word");
			return false;
		}
		attr_name.b = kvc->s.a;
		line = kvc->line;
#if 0
		skip_spaces (kvc);
		if (line != kvc->line) {
			// newline found
			return true;
		}
#endif
		ch = kvc_peek(kvc, 0);
		KVCToken attr_value = { 0 };
		if (ch == '(') {
			// parse value
			kvc_getch(kvc);
			attr_value.a = consume_word(kvc);
			if (!attr_value.a) {
				R_LOG_ERROR("Cannot consume word in value");
				return false;
			}
			// kvc->s.a = attr
			ch = kvc_peek(kvc, 0);
			if (ch != ')') {
				R_LOG_ERROR("Expected )");
				return false;
			}
			attr_value.b = kvc->s.a;
			kvc_getch(kvc);
		} else {
			// eprintf ("JKLFD PARM\n");
			attr_value.a = "true";
			attr_value.b = attr_value.a + 4;
		}
		int atidx = kvc->attrs.count;
		bool duppedkey = false;
		{
			int i;
			for (i = 0; i < kvc->attrs.count; i++) {
				if (kvctoken_equals(kvc->attrs.keys[i], attr_name)) {
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
	skip_until(kvc, '\n', 0);
	return true;
}

static void apply_attributes(KVCParser *kvc, const char *type, const char *scope) {
	int i;
	for (i = 0; i < kvc->attrs.count; i++) {
		KVCToken key = kvc->attrs.keys[i];
		KVCToken val = kvc->attrs.values[i];
		r_strbuf_appendf(kvc->sb, "%s.%s.@.", type, scope);
		r_strbuf_append_n(kvc->sb, key.a, kvctoken_len(key));
		r_strbuf_append(kvc->sb, "=");
		r_strbuf_append_n(kvc->sb, val.a, kvctoken_len(val));
		r_strbuf_append(kvc->sb, "\n");
	}
	kvc->attrs.count = 0; // Reset after applying
}

static void kvctoken_typename(KVCToken *fun_rtyp, KVCToken *fun_name) {
	fun_rtyp->b = fun_name->b;
	kvctoken_trim(fun_rtyp);
	kvctoken_trim(fun_name);
	// eprintf ("i TYPENAME t (%s)\n", kvctoken_tostring (*fun_rtyp));
	// eprintf ("i TYPENAME n (%s)\n", kvctoken_tostring (*fun_name));
	const bool accept_dots_in_function_names = true;
	const char *p = fun_rtyp->b - 1;
	while (p > fun_rtyp->a) {
		bool pass = false;
		if (accept_dots_in_function_names) {
			pass = (!isalnum(*p) && *p != '.' && *p != '_') || isspace(*p);
		} else {
			pass = (!isalnum(*p) && *p != '_') || isspace(*p);
		}
		if (pass && *p != '[' && *p != ']') {
			p++;
			break;
		}
		p--;
	}
	fun_name->a = p;
	fun_rtyp->b = p;
	kvctoken_trim(fun_rtyp);
	kvctoken_trim(fun_name);
	if (fun_name->a > fun_name->b) {
		fun_name->b = fun_name->a;
	}
	if (fun_rtyp->a > fun_rtyp->b) {
		fun_rtyp->a = fun_rtyp->b;
	}
	// eprintf ("o TYPENAME t (%s)\n", kvctoken_tostring (*fun_rtyp));
	// eprintf ("o TYPENAME n (%s)\n", kvctoken_tostring (*fun_name));
}

static int kvc_typesize(KVCParser *kvc, const char *name, int dimension) {
	if (r_str_endswith(name, "8")) {
		return 1 * dimension;
	}
	if (r_str_endswith(name, "16")) {
		return 2 * dimension;
	}
	if (r_str_endswith(name, "64")) {
		return 8 * dimension;
	}
	if (r_str_startswith(name, "int")) {
		return 4 * dimension;
	}
	if (dimension > 1) {
		// TODO: honor type size
		return dimension;
	}
	// TODO: honor alignment, packing, access types
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
	const char *p = kvc_peekn(kvc, strlen("__attribute__"));
	if (!p || !r_str_startswith(p, "__attribute__")) {
		return false;
	}
	kvc_skipn(kvc, strlen("__attribute__"));
	skip_spaces(kvc);
	// Expect double parentheses
	if (kvc_getch(kvc) != '(' || kvc_getch(kvc) != '(') {
		kvc_error(kvc, "Expected __attribute__ ( (...))");
		return false;
	}
	// Parse attribute name
	KVCToken attr_name = { .a = kvc->s.a };
	while (isalnum(*kvc->s.a) || *kvc->s.a == '_') {
		kvc_getch(kvc);
	}
	attr_name.b = kvc->s.a;
	skip_spaces(kvc);
	trim_underscores(&attr_name);
	// Parse optional value
	KVCToken attr_value = { 0 };
	if (kvc_peek(kvc, 0) == '(') {
		kvc_getch(kvc);
		attr_value.a = kvc->s.a;
		const char *close = kvc_find(kvc, ")");
		if (!close) {
			kvc_error(kvc, "Missing ')' in __attribute__");
			return false;
		}
		attr_value.b = close;
		kvc_skipn(kvc, close - kvc->s.a + 1);
	} else {
		attr_value.a = "true";
		attr_value.b = attr_value.a + strlen("true");
	}
	skip_spaces(kvc);
	if (kvc_getch(kvc) != ')') {
		kvc_error(kvc, "Expected ')' after __attribute__");
		return false;
	}
	skip_spaces(kvc);
	// PANCAKE eprintf ("AFTER ATT (%s)\n", kvc->s.a);
	// Store attribute
	int idx = kvc->attrs.count++;
	kvc->attrs.keys[idx] = attr_name;
	kvc->attrs.values[idx] = attr_value;
#if 0
	if (kvc_getch (kvc) != ')') {
		kvc_error (kvc, "Expected ')' after attribute ))");
	}
	kvc_getch (kvc); // slurp ';'

#endif
	kvc_getch(kvc); // slurp ';'
			// PANCAKE eprintf ("AFTER ATTR (%s)\n", kvc->s.a);
	return true;
}

static void kvc_register_typedef(KVCParser *kvc, const char *name, const char *type) {
	if (kvc->tdef_count < (sizeof(kvc->tdefs) / sizeof(kvc->tdefs[0]))) {
		kvc->tdefs[kvc->tdef_count].name = strdup(name);
		kvc->tdefs[kvc->tdef_count].type = strdup(type);
		kvc->tdef_count++;
	}
}

static const char *kvc_lookup_typedef(KVCParser *kvc, const char *name) {
	int i;
	for (i = 0; i < (int)kvc->tdef_count; i++) {
		if (!strcmp(kvc->tdefs[i].name, name)) {
			return kvc->tdefs[i].type;
		}
	}
	return NULL;
}

static bool parse_typedef(KVCParser *kvc, const char *unused) {
	skip_spaces(kvc);
	const char *next = kvc_peekn(kvc, 6);
	if (next && r_str_startswith(next, "struct")) {
		/* typedef struct [Tag]? { ... } Alias; */
		kvc_skipn(kvc, strlen("struct"));
		skip_spaces(kvc);
		KVCToken tag = { 0 };
		bool has_tag = false;
		if (*kvc->s.a != '{') {
			// There is a tag (or tag name) present.
			tag.a = consume_word(kvc);
			if (!tag.a) {
				kvc_error(kvc, "Expected struct tag in typedef");
				return false;
			}
			tag.b = kvc->s.a;
			has_tag = true;
			skip_spaces(kvc);
		}
		if (kvc_peek(kvc, 0) != '{') {
			/* This is a forward declaration:
			   e.g. "typedef struct Tag Alias;" */
			KVCToken alias = { .a = consume_word(kvc) };
			if (!alias.a) {
				kvc_error(kvc, "Expected alias in typedef struct forward declaration");
				return false;
			}
			alias.b = kvc->s.a;
			char *alias_str = kvctoken_tostring(alias);
			char *tag_str = has_tag ? kvctoken_tostring(tag) : strdup("");
			// r_strbuf_appendf (kvc->sb, "typedef.struct.%s=%s\n", alias_str, tag_str);
			r_strbuf_appendf(kvc->sb, "typedef.%s=struct %s\n", alias_str, tag_str);
			free(alias_str);
			free(tag_str);
			skip_semicolons(kvc);
			if (kvc_peek(kvc, 0) == ';') {
				kvc_getch(kvc);
			}
			return true;
		}
		// Here we have a definition: typedef struct [Tag]? { ... } Alias;
		kvc_getch(kvc); // Consume the '{'
		char *struct_tag = NULL;
		if (has_tag) {
			struct_tag = kvctoken_tostring(tag);
		} else {
			// Attempt to use typedef alias as struct name for anonymous struct
			char *alias_name = NULL;
			const char *closing = kvc_find(kvc, "}");
			if (closing) {
				const char *p = closing + 1;
				// Skip whitespace and semicolons
				while (p < kvc->s.b && (isspace((unsigned char)*p) || *p == ';')) {
					p++;
				}
				const char *start = p;
				while (p < kvc->s.b && (isalnum((unsigned char)*p) || *p == '_')) {
					p++;
				}
				if (p > start) {
					KVCToken alias_tok = { .a = start, .b = p };
					alias_name = kvctoken_tostring(alias_tok);
				}
			}
			if (alias_name) {
				struct_tag = alias_name;
			} else {
				struct_tag = r_str_newf("anon_struct_%d", kvc->line);
			}
		}
		/* Begin output for the struct definition */
		// r_strbuf_appendf (kvc->sb, "struct.%s=struct\n", struct_tag);
		r_strbuf_appendf(kvc->sb, "%s=struct\n", struct_tag);
		apply_attributes(kvc, "struct", struct_tag);
		RStrBuf *args_sb = r_strbuf_new("");
		int member_idx = 0;
		int off = 0;
		while (true) {
			skip_spaces(kvc);
			if (kvc_peek(kvc, 0) == '}') {
				kvc_getch(kvc); // Consume '}'
				break;
			}
			parse_attributes(kvc);
			skip_spaces(kvc);
			KVCToken member_type = { 0 };
			KVCToken member_name = { 0 };
			KVCToken member_dimm = { 0 };
			// parse member type token up to semicolon
			member_type.a = kvc->s.a;
			member_type.b = kvc_find_semicolon(kvc);
			if (!member_type.b) {
				kvc_error(kvc, "Missing semicolon in struct member");
				r_strbuf_free(args_sb);
				free(struct_tag);
				return false;
			}
			if (member_type.a == member_type.b) {
				kvc_getch(kvc);
				break;
			}
			memcpy(&member_name, &member_type, sizeof(member_name));
			kvctoken_typename(&member_type, &member_name);
#if 1
			// PANCAKE
			kvc_getch(kvc); // Skip the semicolon
#else
			// Handle trailing C-style __attribute__ before semicolon
			skip_spaces(kvc);
			while (parse_c_attributes(kvc)) {
				skip_spaces(kvc);
			}
			if (kvc_peek(kvc, 0) == ';') {
				kvc_getch(kvc);
			} else {
				kvc_error(kvc, "Expected ';' after struct field");
				return false;
			}
#endif
			kvctoken_trim(&member_type);
			// Handle possible array dimensions (e.g. "[10]"):
			// Handle possible array dimensions (e.g. "[10]"):
			const char *bracket = kvctoken_find(member_name, "[");
			if (bracket) {
				// Extract dimension and adjust member name to exclude brackets
				member_dimm.a = bracket + 1;
				member_dimm.b = member_name.b;
				// Set name end to bracket start (exclusive) to include full name
				member_name.b = bracket;
				const char *close = kvctoken_find(member_dimm, "]");
				if (close) {
					member_dimm.b = close;
				} else {
					r_strbuf_free(args_sb);
					free(struct_tag);
					kvc_error(kvc, "Missing ] in struct member dimension");
					return false;
				}
			}
			char *mt = kvctoken_tostring(member_type);
			char *mn = kvctoken_tostring(member_name);
			char *md = kvctoken_tostring(member_dimm);
			if (!*mn) {
				free(mt);
				free(mn);
				free(md);
				R_LOG_ERROR("struct field parse failed");
				break;
			}
			r_strf_var(full_scope, 512, "%s.%s", struct_tag, mn);
			// Detect if this field is a function-pointer (direct or via typedef). If so,
			// skip the generic append here and let the specialized handling emit the
			// canonical named type and func.<struct>.<member> entries.
			bool _is_fp_field = kvctoken_find(member_type, " (*");
			if (!_is_fp_field) {
				// check typedefs (mt is a heap string)
				const char *tdef_local = kvc_lookup_typedef(kvc, mt);
				if (tdef_local && (strstr(tdef_local, "* (") || strstr(tdef_local, " * ("))) {
					_is_fp_field = true;
				}
			}
			if (!_is_fp_field) {
				if (R_STR_ISNOTEMPTY(md)) {
					r_strbuf_appendf(kvc->sb, "struct.%s.%s=%s,%d,%s\n",
						struct_tag, mn, mt, off, md);
				} else {
					r_strbuf_appendf(kvc->sb, "struct.%s.%s=%s,%d,0\n",
						struct_tag, mn, mt, off);
				}
				// TODO: this is for backward compat, but imho it should be removed
				r_strbuf_appendf(kvc->sb, "struct.%s.%s.meta=0\n", struct_tag, mn);
				off += kvc_typesize(kvc, mt, 1);
				apply_attributes(kvc, "struct", full_scope);
				r_strbuf_appendf(args_sb, "%s%s", member_idx ? "," : "", mn);
				member_idx++;
				free(mt);
				free(mn);
				free(md);
				// continue with next field
				continue;
			}
			// else: it is a function-pointer field; fall through to specialized handling below
		}
		// After the closing '}', we expect the typedef alias:
		skip_spaces(kvc);
		KVCToken alias = { .a = consume_word(kvc) };
		if (!alias.a) {
			kvc_error(kvc, "Missing alias in typedef struct");
			r_strbuf_free(args_sb);
			free(struct_tag);
			return false;
		}
		alias.b = kvc->s.a;
		char *alias_str = kvctoken_tostring(alias);
		/* Record the typedef mapping: the alias now refers to our struct tag */
		r_strbuf_appendf(kvc->sb, "typedef.%s=struct %s\n", alias_str, struct_tag);
		skip_semicolons(kvc);
		if (kvc_peek(kvc, 0) == ';') {
			kvc_getch(kvc);
		}
		char *argstr = r_strbuf_drain(args_sb);
		r_strbuf_appendf(kvc->sb, "struct.%s=%s\n", struct_tag, argstr);
		r_strbuf_appendf(kvc->sb, "%s=struct\n", alias_str);
		free(argstr);
		free(struct_tag);
		free(alias_str);
		return true;
	} else if (next && r_str_startswith(next, "union")) {
		/* Similar to the struct case, you would parse:
		   typedef union [Tag]? { ... } Alias;
 (Implementation omitted for brevity) */
		kvc_error(kvc, "typedef union not implemented");
		return false;
	} else if (next && r_str_startswith(next, "enum")) {
		/* Similarly, handle typedef enum [Tag]? { ... } Alias;
 (Implementation omitted for brevity) */
		kvc_error(kvc, "typedef enum not implemented");
		return false;
	} else {
		/* Handle a “simple” typedef such as:
		   typedef int myint;
		   In this case we assume that everything from the current pointer until
		   the semicolon is the declaration, and the last word is the alias.
		   */
		const char *start = kvc->s.a;
		/* First check if this is a function-pointer typedef of the form:
		   typedef RETTYPE (*alias) (ARGS);
		*/
		KVCToken decl = { .a = start };
		/* find semicolon for decl end */
		const char *semicolon = kvc_find_semicolon2(kvc);
		if (!semicolon) {
			semicolon = kvc_find_semicolon(kvc);
		}
		decl.b = semicolon;
		if (!semicolon) {
			kvc_error(kvc, "Missing semicolon in typedef");
			return false;
		}
		/* Detect function-pointer typedefs like: typedef RET (*alias) (args); */
		const char *fp_marker = kvctoken_find(decl, " (*");
		if (fp_marker) {
			const char *name_start = fp_marker + 3;
			const char *name_end = name_start;
			while (name_end < semicolon && *name_end != ')') {
				name_end++;
			}
			if (name_end < semicolon) {
				KVCToken alias = { .a = name_start, .b = name_end };
				kvctoken_trim(&alias);
				char *alias_str = kvctoken_tostring(alias);
				KVCToken rtype_tok = { .a = start, .b = fp_marker };
				kvctoken_trim(&rtype_tok);
				char *rtype = kvctoken_tostring(rtype_tok);
				/* find args */
				const char *args_open = name_end;
				while (args_open < semicolon && *args_open != '(') {
					args_open++;
				}
				char *args_str = NULL;
				if (args_open < semicolon) {
					const char *args_end = semicolon - 1;
					while (args_end > args_open && *args_end != ')') {
						args_end--;
					}
					if (args_end > args_open) {
						KVCToken args_tok = { .a = args_open + 1, .b = args_end };
						args_str = kvctoken_tostring(args_tok);
						r_str_trim(args_str);
					}
				}
				char *fulltype = r_str_newf("%s * (%s)", rtype, args_str ? args_str : "");
				// Map typedef alias to a canonical func.<alias> handle (func entries will be emitted when the typedef
				// is actually used in a struct field so their ordering matches expectations)
				r_strbuf_appendf(kvc->sb, "typedef.%s=func.%s\n", alias_str, alias_str);
				r_strbuf_appendf(kvc->sb, "%s=typedef\n", alias_str);
				// Keep the original fulltype registered so other code can detect function-pointer typedefs
				kvc_register_typedef(kvc, alias_str, fulltype);
				kvc_skipn(kvc, semicolon - kvc->s.a);
				if (kvc_peek(kvc, 0) == ';') {
					kvc_getch(kvc);
				}
				free(alias_str);
				free(rtype);
				if (args_str) {
					free(args_str);
				}
				free(fulltype);
				return true;
			}
		}
		const char *p = semicolon - 1;
		// Skip trailing spaces before alias
		while (p > start && isspace((unsigned char)*p)) {
			p--;
		}
		// Mark end of alias
		const char *alias_end = p + 1;
		// Scan backwards over alias characters (alphanumeric and underscore)
		while (p > start && (isalnum((unsigned char)*p) || *p == '_')) {
			p--;
		}
		// If stopped on non-identifier, advance to start of alias
		if (!(isalnum((unsigned char)*p) || *p == '_')) {
			p++;
		}
		// Alias token
		KVCToken alias = { .a = p, .b = alias_end };
		// Original type spans from start up to alias start
		KVCToken orig_type = { .a = start, .b = p };
		kvctoken_trim(&alias);
		kvctoken_trim(&orig_type);
		char *alias_str = kvctoken_tostring(alias);
		char *type_str = kvctoken_tostring(orig_type);
		r_strbuf_appendf(kvc->sb, "typedef.%s=%s\n", alias_str, type_str);
		r_strbuf_appendf(kvc->sb, "%s=typedef\n", alias_str);
		/* Register simple typedef for later lookup */
		kvc_register_typedef(kvc, alias_str, type_str);
		free(alias_str);
		free(type_str);
		kvc_skipn(kvc, semicolon - kvc->s.a);
		if (kvc_peek(kvc, 0) == ';') {
			kvc_getch(kvc);
		}
		return true;
	}
}

// works for unions and structs
static bool parse_struct(KVCParser *kvc, const char *type) {
	KVCToken struct_name = { .a = consume_word(kvc) };
	if (!struct_name.a) {
		R_LOG_ERROR("Cannot consume word");
		return false;
	}
	// eprintf ("STRUCT NAME ( %s)\n", struct_name.a);
	struct_name.b = kvc->s.a;
	skip_spaces(kvc);
	const char p0 = kvc_peek(kvc, 0);
	if (p0 != '{') {
		R_LOG_ERROR("Expected { after name in struct");
		return false;
	}
	RStrBuf *args_sb = r_strbuf_new("");
	kvc_getch(kvc);
	char *sn = kvctoken_tostring(struct_name);
	r_strbuf_appendf(kvc->sb, "%s=%s\n", sn, type);
	apply_attributes(kvc, type, sn);
	// Lookahead: scan struct body for direct function-pointer members so we can
	// emit a typedef-like func handle for them (e.g. foo.fp=func)
	{
		const char *closing = kvc_find(kvc, "}");
		if (closing) {
			const char *p = kvc->s.a;
			while (p < closing) {
				const char *st = r_mem_mem((const ut8 *)p, closing - p, (const ut8 *)"(*", 2);
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
				kvctoken_trim(&mtok);
				char *mname_look = kvctoken_tostring(mtok);
				// find args parentheses after name_end
				const char *args_open = name_end;
				while (args_open < closing && *args_open != '(') {
					args_open++;
				}
				char *fnames_s = NULL;
				if (args_open < closing) {
					const char *args_close = args_open;
					int depth = 0;
					while (args_close < closing) {
						if (*args_close == '(') {
							depth++;
						} else if (*args_close == ')') {
							depth--;
							if (depth == 0) {
								break;
							}
						}
						args_close++;
					}
					if (args_close < closing && *args_close == ')') {
						KVCToken args_tok = { .a = args_open + 1, .b = args_close };
						char *args_all = kvctoken_tostring(args_tok);
						r_str_trim(args_all);
						RStrBuf *fnames = r_strbuf_new("");
						char *acopy = strdup(args_all);
						char *pp = acopy;
						int arg_idx = 0;
						while (pp) {
							char *comma = strchr(pp, ',');
							char *tok = NULL;
							if (comma) {
								tok = r_str_ndup(pp, comma - pp);
								pp = comma + 1;
							} else {
								tok = strdup(pp);
								pp = NULL;
							}
							r_str_trim(tok);
							char *last_space = strrchr(tok, ' ');
							char *arg_name = NULL;
							if (last_space) {
								arg_name = strdup(last_space + 1);
								r_str_trim(arg_name);
							} else {
								arg_name = strdup("");
							}
							r_strbuf_appendf(fnames, "%s%s", arg_idx ? "," : "", arg_name);
							free(arg_name);
							free(tok);
							arg_idx++;
						}
						fnames_s = r_strbuf_drain(fnames);
						free(acopy);
						free(args_all);
					}
				}
				if (mname_look) {
					const char *tdef = kvc_lookup_typedef(kvc, mname_look);
					if (tdef) {
						r_strbuf_appendf(kvc->sb, "%s.%s=func\n", sn, mname_look);
						if (fnames_s) {
							free(fnames_s);
						}
					}
					free(mname_look);
				}
				p = name_end + 1;
			}
		}
	}
	int member_idx = 0;
	int off = 0;
	while (true) {
		skip_spaces(kvc);
		parse_attributes(kvc);
		skip_spaces(kvc);
		// PANCAKE eprintf ("[FIELD]---> (%s)\n", kvc->s.a);
#if 0
		const char ch0 = kvc_peek (kvc, 0);
		if (ch0 == '}') {
			eprintf ("PEKA\n");
			// end of struct definition
			kvc_getch (kvc);
			kvc_getch (kvc);
			break;
		}
#endif

		KVCToken member_type = { 0 };
		KVCToken member_name = { 0 };
		KVCToken member_dimm = { 0 };

		// parse member type up to semicolon or closing '}'
		// Start parsing field type token
		member_type.a = kvc->s.a;
		// Support function pointer fields: allow parentheses when scanning semicolon
		if (kvctoken_find((KVCToken){ member_type.a, kvc->s.b }, " (*")) {
			member_type.b = kvc_find_semicolon2(kvc);
		} else {
			member_type.b = kvc_find_semicolon(kvc);
		}
		if (!member_type.b) {
			// attempt extended scan allowing parentheses (attributes or function pointers)
			const char *semi2 = kvc_find_semicolon2(kvc);
			if (!semi2) {
				const char ch0 = kvc_peek(kvc, 0);
				if (ch0 == '}') {
					// end of struct definition
					kvc_getch(kvc);
					kvc_getch(kvc);
					break;
				}
				kvc_error(kvc, "Missing semicolon in struct member");
				r_strbuf_free(args_sb);
				free(sn);
				return false;
			}
			// check for C-style attribute inside this span
			const char *attrp = kvctoken_find((KVCToken){ member_type.a, semi2 }, "__attribute");
			if (attrp) {
				member_type.b = attrp - 1;
				kvc->s.a = attrp;
				if (!parse_c_attributes(kvc)) {
					r_strbuf_free(args_sb);
					return false;
				}
				skip_spaces(kvc);
			} else {
				// function pointer: include full type span
				member_type.b = semi2;
				kvc->s.a = semi2;
			}
		}
		if (member_type.a == member_type.b) {
			kvc_getch(kvc);
			break;
		}
		memcpy(&member_name, &member_type, sizeof(member_name));
		kvctoken_typename(&member_type, &member_name);
		skip_semicolons(kvc);
		kvctoken_trim(&member_type);
		// Special-case function pointer fields
		if (kvctoken_find(member_type, " (*")) {
			// member_type spans entire function pointer declaration including args
			const char *start = member_type.a;
			const char *starp = strstr(start, " (*");
			if (starp) {
				// return type
				char *rtype = r_str_ndup(start, starp - start);
				r_str_trim(rtype);
				// member name
				const char *name_start = starp + 3;
				const char *name_end = strchr(name_start, ')');
				char *mname = NULL;
				if (name_end && name_end > name_start) {
					mname = r_str_ndup(name_start, name_end - name_start);
					r_str_trim(mname);
				}
				// argument types
				const char *args_start = NULL;
				if (name_end) {
					args_start = strchr(name_end + 1, '(');
				}
				char *args = NULL;
				if (args_start && args_start < member_type.b) {
					const char *args_end = member_type.b;
					// skip trailing ')'
					if (args_end > args_start && args_end[-1] == ')') {
						args_end--;
					}
					args = r_str_ndup(args_start + 1, args_end - args_start - 1);
					r_str_trim(args);
				}
				// build full type string
				char *fulltype = r_str_newf("%s * (%s)", rtype, args ? args : "");
				// We'll reference the function-pointer's type by a struct-prefixed name: <struct>.<member>
				char *type_name = r_str_newf("%s.%s", sn, mname);
				// Emit the struct member referring to that type name (no commas in the type)
				r_strbuf_appendf(kvc->sb, "struct.%s.%s=%s,%d,0\n", sn, mname, type_name, off);
				// Now emit a func.<struct>.<member> set of entries like regular functions (see t/j.h.txt)
				// func.<struct>.<member>=<argnames>
				// func.<struct>.<member>.arg.N=<type>,<name>
				// func.<struct>.<member>.ret=<ret type>
				// func.<struct>.<member>.cc=cdecl
				// func.<struct>.<member>.args=<count>
				// Build func args entries
				if (args) {
					// split args by comma for names list
					char *args_copy = strdup(args);
					char *p = args_copy;
					int arg_idx = 0;
					RStrBuf *fnames = r_strbuf_new("");
					while (p) {
						char *comma = strchr(p, ',');
						char *tok = NULL;
						if (comma) {
							tok = r_str_ndup(p, comma - p);
							p = comma + 1;
						} else {
							tok = strdup(p);
							p = NULL;
						}
						r_str_trim(tok);
						// now find last space in tok to split type/name
						char *last_space = strrchr(tok, ' ');
						char *arg_type = NULL;
						char *arg_name = NULL;
						if (last_space) {
							arg_type = r_str_ndup(tok, last_space - tok);
							r_str_trim(arg_type);
							arg_name = strdup(last_space + 1);
							r_str_trim(arg_name);
						} else {
							// no name, use empty
							arg_type = strdup(tok);
							r_str_trim(arg_type);
							arg_name = strdup("");
						}
						r_strbuf_appendf(fnames, "%s%s", arg_idx ? "," : "", arg_name);
						r_strbuf_appendf(kvc->sb, "func.%s.%s.arg.%d=%s,%s\n", sn, mname, arg_idx, arg_type, arg_name);
						free(arg_type);
						free(arg_name);
						free(tok);
						arg_idx++;
					}
					char *fnames_s = r_strbuf_drain(fnames);
					r_strbuf_appendf(kvc->sb, "func.%s.%s=%s\n", sn, mname, fnames_s);
					r_strbuf_appendf(kvc->sb, "func.%s.%s.cc=%s\n", sn, mname, "cdecl");
					r_strbuf_appendf(kvc->sb, "func.%s.%s.args=%d\n", sn, mname, arg_idx);
					free(fnames_s);
					free(args_copy);
				} else {
					r_strbuf_appendf(kvc->sb, "func.%s.%s=\n", sn, mname);
					r_strbuf_appendf(kvc->sb, "func.%s.%s.cc=%s\n", sn, mname, "cdecl");
					r_strbuf_appendf(kvc->sb, "func.%s.%s.args=%d\n", sn, mname, 0);
				}
				// return type
				r_strbuf_appendf(kvc->sb, "func.%s.%s.ret=%s\n", sn, mname, rtype ? rtype : "void");
				// store the canonical signature too
				r_strbuf_appendf(kvc->sb, "func.%s.%s=%s\n", sn, mname, args ? args : "");
				off += kvc_typesize(kvc, fulltype, 1);
				// add member name to struct's args list and advance index
				r_strbuf_appendf(args_sb, "%s%s", member_idx ? "," : "", mname);
				member_idx++;
				{
					r_strf_var(full_scope, 512, "%s.%s", sn, mname);
					apply_attributes(kvc, "struct", full_scope);
				}
				free(type_name);
				free(rtype);
				if (args) {
					free(args);
				}
				free(mname);
				/* mt_check is not defined in this scope */
				continue;
			}
		}
		// Check for typedef aliases that represent function pointers
		{
			char *mt_check = kvctoken_tostring(member_type);
			const char *tdef = kvc_lookup_typedef(kvc, mt_check);
			if (tdef) {
				/* If typedef stored a function-pointer like "int * (...)" treat it as function pointer */
				if (strstr(tdef, "* (") || strstr(tdef, " * (")) {
					char *mname = kvctoken_tostring(member_name);
					// split tdef into rtype and args
					const char *p = strstr(tdef, "* (");
					if (!p) {
						p = strstr(tdef, " * (");
					}
					if (p) {
						int rlen = p - tdef;
						char *rtype = r_str_ndup(tdef, rlen);
						r_str_trim(rtype);
						// find args
						const char *args_open = strchr(p, '(');
						char *args_str = NULL;
						if (args_open) {
							const char *args_close = strrchr(tdef, ')');
							if (args_close && args_close > args_open) {
								args_str = r_str_ndup(args_open + 1, args_close - args_open - 1);
								r_str_trim(args_str);
							}
						}
						// For typedef function-pointer types, reference the typedef alias as the field's type
						r_strbuf_appendf(kvc->sb, "struct.%s.%s=%s,%d,0\n", sn, mname, mt_check, off);
						off += kvc_typesize(kvc, tdef, 1);
						r_strbuf_appendf(args_sb, "%s%s", member_idx ? "," : "", mname);
						member_idx++;
						{
							r_strf_var(full_scope, 512, "%s.%s", sn, mname);
							apply_attributes(kvc, "struct", full_scope);
						}
						// Emit func.<typedef> entries for the typedef alias (so the type is available globally)
						if (args_str) {
							char *args_copy = strdup(args_str);
							char *pp = args_copy;
							int arg_idx2 = 0;
							RStrBuf *fnames2 = r_strbuf_new("");
							while (pp) {
								char *comma2 = strchr(pp, ',');
								char *tok2 = NULL;
								if (comma2) {
									tok2 = r_str_ndup(pp, comma2 - pp);
									pp = comma2 + 1;
								} else {
									tok2 = strdup(pp);
									pp = NULL;
								}
								r_str_trim(tok2);
								char *ls2 = strrchr(tok2, ' ');
								char *arg_type2 = NULL;
								char *arg_name2 = NULL;
								if (ls2) {
									arg_type2 = r_str_ndup(tok2, ls2 - tok2);
									r_str_trim(arg_type2);
									arg_name2 = strdup(ls2 + 1);
									r_str_trim(arg_name2);
								} else {
									arg_type2 = strdup(tok2);
									r_str_trim(arg_type2);
									arg_name2 = strdup("");
								}
								r_strbuf_appendf(fnames2, "%s%s", arg_idx2 ? "," : "", arg_name2);
								r_strbuf_appendf(kvc->sb, "func.%s.arg.%d=%s,%s\n", mt_check, arg_idx2, arg_type2, arg_name2);
								free(arg_type2);
								free(arg_name2);
								free(tok2);
								arg_idx2++;
							}
							char *fnames_s2 = r_strbuf_drain(fnames2);
							r_strbuf_appendf(kvc->sb, "func.%s=%s\n", mt_check, fnames_s2);
							r_strbuf_appendf(kvc->sb, "func.%s.cc=%s\n", mt_check, "cdecl");
							r_strbuf_appendf(kvc->sb, "func.%s.args=%d\n", mt_check, arg_idx2);
							free(fnames_s2);
							free(args_copy);
						} else {
							r_strbuf_appendf(kvc->sb, "func.%s=\n", mt_check);
							r_strbuf_appendf(kvc->sb, "func.%s.cc=%s\n", mt_check, "cdecl");
							r_strbuf_appendf(kvc->sb, "func.%s.args=%d\n", mt_check, 0);
						}
						r_strbuf_appendf(kvc->sb, "func.%s.ret=%s\n", mt_check, rtype);
						free(mname);
						free(mt_check);
						continue;
					}
				}
			}
			free(mt_check);
		}
#if 0
			member_type.b = kvctoken_lastspace (member_type);
		// TODO XXX dimensions shouldnt be part of the name
		if (!member_type.b) {
			char *s = kvctoken_tostring (member_name);
			R_LOG_ERROR ("Cant find space between type and field name (%s)", s);
		}
		member_name.a = member_type.b;
		member_name.b = kvc->s.a - 1;
		kvctoken_trim (&member_name);
#endif
		if (member_name.a) {
			const char *bracket = kvctoken_find(member_name, "[");
			if (bracket) {
				// parse dimensions
				member_dimm.a = bracket + 1;
				member_dimm.b = member_name.b;
				member_name.b = member_dimm.a - 1;
				member_dimm.b = kvctoken_find(member_dimm, "]");
				if (member_dimm.b) {
					// Dimensions already consumed by kvc_find_semicolon; no need to skip
				} else {
					R_LOG_ERROR("Missing ] in struct field dimension");
				}
			}
		}

		char *mt = kvctoken_tostring(member_type);
		char *mn = kvctoken_tostring(member_name);
		char *md = kvctoken_tostring(member_dimm);
		if (!*mn) {
			kvc_error(kvc, "Missing type, name or dimension in struct field");
			free(mt);
			free(mn);
			free(md);
			break;
		}
		massage_type(&mt);
		r_strf_var(full_scope, 512, "%s.%s", sn, mn);
		int dimension = 1;
		// TODO: honor packed attribute too
		const char *align_attribute = kvc_attr(kvc, "aligned");
		bool must_be_aligned = align_attribute != NULL;
		if (must_be_aligned) {
			size_t av = atoi(align_attribute);
			if (av < 1) {
				av = 4;
			}
			if (off % av) {
				const int rest = av - (off % av);
				off += rest;
			}
		}
		if (md) {
			dimension = atoi(md);
			r_strbuf_appendf(kvc->sb, "%s.%s=%s,%d,%s\n", type, full_scope, mt, off, md);
		} else {
			r_strbuf_appendf(kvc->sb, "%s.%s=%s,%d,0\n", type, full_scope, mt, off);
		}
		if (!strcmp(type, "struct")) {
			off += kvc_typesize(kvc, mt, dimension);
		}
		// eprintf ("DIMENSION %s (%d)\n", mn, dimension);
		// r_strbuf_appendf (kvc->sb, "%s.%s.meta=0\n", type, mn);
		apply_attributes(kvc, type, full_scope);
		r_strbuf_appendf(args_sb, "%s%s", member_idx ? "," : "", mn);
		member_idx++;
		free(mt);
		free(mn);
		free(md);
	}
#if 0
	if (*p == '}') {
		p++;
	}
	// p = skip_until_semicolon (p);
#endif
	// Skip trailing semicolon (s) and whitespace after struct definition
	skip_semicolons(kvc);
	char *argstr = r_strbuf_drain(args_sb);
	r_strbuf_appendf(kvc->sb, "%s.%s=%s\n", type, sn, argstr);
	free(argstr);
	free(sn);
	return true;
}

static bool parse_enum(KVCParser *kvc, const char *name) {
	parse_attributes(kvc);
	KVCToken enum_name = { .a = consume_word(kvc) };
	if (!enum_name.a) {
		R_LOG_ERROR("Cannot consume a word");
		return false;
	}
	enum_name.b = kvc->s.a;
	char *en = kvctoken_tostring(enum_name);
	r_strbuf_appendf(kvc->sb, "%s=enum\n", en);
	RStrBuf *enumstr = NULL;
	apply_attributes(kvc, "enum", en);
	skip_spaces(kvc);
	const char p0 = kvc_peek(kvc, 0);
	if (p0 != '{') {
		R_LOG_ERROR("Expected { after name in enum");
		free(en);
		return false;
	}
	kvc_getch(kvc);
	ut64 value = 0;
	bool closing = false;
	while (!closing) {
		skip_spaces(kvc);
		parse_attributes(kvc);
		skip_spaces(kvc);
		KVCToken member_name = { 0 };
		KVCToken member_value = { 0 };
		member_name.a = consume_word(kvc);
		if (!member_name.a) {
			R_LOG_ERROR("a");
			return false;
		}
		member_name.b = kvc->s.a;
		skip_spaces(kvc);
		char ch = kvc_getch(kvc);
		if (ch == '=') {
			skip_spaces(kvc);
			member_value.a = consume_word(kvc);
			if (!member_value.a) {
				R_LOG_ERROR("a");
				return false;
			}
			member_value.b = kvc->s.a;
			skip_spaces(kvc);
			ch = kvc_getch(kvc);
			// equal
		}
		if (ch == '}') {
			closing = true;
		} else if (ch == ',') {
			// next
		} else {
			kvc_error(kvc, "Expected , or } inside enum");
			free(en);
			return false;
		}

		char *mn = kvctoken_tostring(member_name);
		apply_attributes(kvc, "enum", en);
		r_strf_var(full_scope, 512, "%s.%s", en, mn);
		if (member_value.a) {
			st64 nv = r_num_get(NULL, member_value.a);
#if 0
			// new style, stuff breaks, but full enum scope makes sense imho
			r_strbuf_appendf (kvc->sb, "enum.%s=0x%"PFMT64x"\n", full_scope, nv);
			r_strbuf_appendf (kvc->sb, "enum.0x%"PFMT64x"=%s\n", nv, full_scope);
#else
#if 0
			// old style, backward compat, everything works.
			if ( (ut64)nv < 256 || ( (st64)nv > -16 && (st64)nv < 32)) {
				r_strbuf_appendf (kvc->sb, "enum.%s=%"PFMT64d"\n", full_scope, nv);
				r_strbuf_appendf (kvc->sb, "enum.%s.%"PFMT64d"=%s\n", en, nv, mn);
			} else {
				r_strbuf_appendf (kvc->sb, "enum.%s=0x%"PFMT64x"\n", full_scope, nv);
				r_strbuf_appendf (kvc->sb, "enum.%s.0x%"PFMT64x"=%s\n", en, nv, mn);
			}
#else
			r_strbuf_appendf(kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, nv);
			r_strbuf_appendf(kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", en, nv, mn);
#endif
#endif
			value = nv; // r_num_get (NULL, member_value.a);
		} else {
			r_strbuf_appendf(kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, (ut64)value);
			r_strbuf_appendf(kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", en, (ut64)value, mn);
			// r_strbuf_appendf (kvc->sb, "enum.%s=%d\n", full_scope, value);
		}
		if (enumstr) {
			r_strbuf_appendf(enumstr, ",%s", mn);
		} else {
			enumstr = r_strbuf_new(mn);
		}
		free(mn);
		value++;
	}
	if (enumstr) {
		char *es = r_strbuf_drain(enumstr);
		r_strbuf_appendf(kvc->sb, "enum.%s=%s\n", en, es);
		free(es);
	}
	char ch = kvc_peek(kvc, 0);
	if (ch == ';') {
		skip_semicolons(kvc);
		// kvc_getch (kvc);
	}
	free(en);
	return true;
}

static bool parse_function(KVCParser *kvc) {
	parse_attributes(kvc);
	// eprintf ("PARSE FUNCTION (%s)\n", kvc->s.a);
	KVCToken fun_name = { 0 };
	KVCToken fun_rtyp = { 0 };
	KVCToken fun_parm = { 0 };
	fun_rtyp.a = consume_word(kvc);
	if (!fun_rtyp.a) {
		// no need to error here, there's nothing to parse
		// kvc_error (kvc, "Cannot consume word for function");
		return false;
	}
	fun_rtyp.b = kvc->s.a;
	fun_name.a = fun_rtyp.a;
#if 0
	const char *open_paren = kvc_find (kvc, " (");
	if (!open_paren) {
		// R_LOG_ERROR ("Parsing problem at line 2: Cannot find ( in function definition")
		// If we can't find an opening parenthesis, this is not a function definition
		return false;
	}
#endif
	if (!skip_until(kvc, '(', 0)) {
		kvc_error(kvc, "Cannot find ( in function definition");
		// r_sys_breakpoint ();
		return false;
	}
	fun_name.b = kvc->s.a;
	fun_parm.a = kvc->s.a + 1;
	if (!skip_until(kvc, ')', 0)) {
		kvc_error(kvc, "Cannot find ) in function definition");
		return false;
	}
	kvctoken_typename(&fun_rtyp, &fun_name);
	fun_parm.b = kvc->s.a;
	kvc_skipn(kvc, 1);
	skip_spaces(kvc);
	skip_semicolons(kvc);

	char *fn = kvctoken_tostring(fun_name);
	char *fr = kvctoken_tostring(fun_rtyp);
	r_strbuf_appendf(kvc->sb, "%s=func\n", fn);
	apply_attributes(kvc, "func", fn);

#if 0
	eprintf ("RETURN (%s)\n", kvctoken_tostring (fun_rtyp));
	eprintf ("FNAME (%s)\n", fn);
	eprintf ("FPARM (%s)\n", kvctoken_tostring (fun_parm));
#endif

	RStrBuf *func_args_sb = r_strbuf_new("");
	int arg_idx = 0;
	if (fun_parm.a < fun_parm.b) {
		const char *pa = fun_parm.a;
		const char *pb = fun_parm.b;
		const char *argp = pa;
		const char *comma = NULL;
		do {
			while (pa < pb && isspace((unsigned char)*pa)) {
				pa++;
			}
			comma = r_str_nchr(pa, ',', pb - pa);
			pa = comma ? comma : pb;
			if (pa == pb) {
				// break;
			}
			KVCToken arg_type = { argp, pa };
			KVCToken arg_name = { argp, pa };
			kvctoken_typename(&arg_type, &arg_name);
#if 0
			// XXX how do we know this wtf
			if (!param_name.a) {
				// unnamed arguments
				param_name = r_str_newf ("arg%d", arg_idx);
			}
#endif
			char *an = kvctoken_tostring(arg_name);
			char *at = kvctoken_tostring(arg_type);
			massage_type(&at);
			if (R_STR_ISEMPTY(at) && !strcmp(an, "void") && arg_idx == 0) {
				// TODO: check if its the only arg
				arg_idx--;
			} else {
				r_strbuf_appendf(kvc->sb, "func.%s.arg.%d=%s,%s\n", fn, arg_idx, at, an);
				r_strbuf_appendf(func_args_sb, "%s%s", arg_idx ? "," : "", an);
			}
			free(an);
			free(at);
			arg_idx++;
			pa++;
			argp = pa;
		} while (comma);
	}
	char *func_args = r_strbuf_drain(func_args_sb);
	r_strbuf_appendf(kvc->sb, "func.%s.cc=%s\n", fn, "cdecl");
	r_strbuf_appendf(kvc->sb, "func.%s=%s\n", fn, func_args);
	r_strbuf_appendf(kvc->sb, "func.%s.ret=%s\n", fn, fr);
	r_strbuf_appendf(kvc->sb, "func.%s.args=%d\n", fn, arg_idx);
#if 0
	eprintf ("--> %d\n", arg_idx);
	eprintf ("--> %s\n", r_strbuf_tostring (kvc->sb));// arg_idx);
#endif
	free(func_args);
	free(fn);
	free(fr);
	return true;
}

static void kvcparser_init(KVCParser *kvc, const char *data) {
	kvc->line = 1;
	kvc->sb = r_strbuf_new("");
	kvc->s.a = data;
	kvc->s.b = data + strlen(data);
}

static void kvcparser_fini(KVCParser *kvc) {
	int i;
	for (i = 0; i < (int)kvc->tdef_count; i++) {
		free(kvc->tdefs[i].name);
		free(kvc->tdefs[i].type);
	}
	kvc->tdef_count = 0;
	r_strbuf_free(kvc->sb);
}

static bool tryparse(KVCParser *kvc, const char *word, const char *type, KVCParserCallback cb) {
	if (r_str_startswith(word, type)) {
		kvc_skipn(kvc, strlen(type));
		const char ch = kvc_getch(kvc);
		if (isspace(ch)) {
			skip_spaces(kvc);
			return cb ? cb(kvc, type) : true;
		}
	}
	return false;
}

R_IPI char *kvc_parse(const char *header_content, char **errmsg) {
	// Initialize a preprocessing state for this parse
	PPState *pps = pp_new();
	char *pre = pp_preprocess(pps, header_content);
	if (!pre) {
		pp_free(pps);
		return NULL;
	}
	pp_free(pps);
	KVCParser _kvc = { 0 };
	KVCParser *kvc = &_kvc;
	kvcparser_init(&_kvc, pre);
	while (!kvctoken_eof(kvc->s)) {
		skip_spaces(kvc);
		const char *word = kvc_peekn(kvc, 6);
		// eprintf ("WORD (%s)\n", word);
		// eprintf ("--> ( ( (%s)))\n", r_str_ndup (word, 10));
		bool hasparse = false;
		if (word) {
#if 1
			hasparse = tryparse(kvc, word, "typedef", parse_typedef);
			hasparse |= tryparse(kvc, word, "struct", parse_struct);
			hasparse |= tryparse(kvc, word, "union", parse_struct);
			hasparse |= tryparse(kvc, word, "enum", parse_enum);
#else
			hasparse = tryparse(kvc, word, "typedef", parse_typedef);
			if (!hasparse) {
				hasparse = tryparse(kvc, word, "struct", parse_struct);
			}
			if (!hasparse) {
				hasparse = tryparse(kvc, word, "union", parse_struct);
			}
			if (!hasparse) {
				hasparse = tryparse(kvc, word, "enum", parse_enum);
			}
#endif
		}
		// If a construct (typedef/struct/union/enum) was parsed, skip trailing semicolons and continue
		if (hasparse) {
			skip_semicolons(kvc);
			continue;
		}
#if 1
		// parse standalone attributes
		if (parse_attributes(kvc)) {
			continue;
		}
#endif
		skip_spaces(kvc);
		// Attempt to parse a function signature
		if (!parse_function(kvc)) {
			kvc_getch(kvc);
		}
		skip_spaces(kvc);
	}
	char *res = NULL;
	if (kvc->error && errmsg) {
		*errmsg = strdup(kvc->error);
	} else {
		res = r_strbuf_drain(kvc->sb);
		kvc->sb = NULL;
	}
	kvcparser_fini(kvc);
	free(pre);
	return res;
}

#if MAIN
int main(int argc, char *argv[]) {
	if (argc < 2) {
		eprintf("Usage: %s <header_file.h>\n", argv[0]);
		return 1;
	}

	char *content = r_file_slurp(argv[1], NULL);
	if (!content) {
		R_LOG_ERROR("Failed to read file: %s", argv[1]);
		return 1;
	}

	char *result = kvc_parse((const char *)content, NULL);
	if (result) {
		printf("%s\n", result);
		free(result);
	}

	free(content);
	return 0;
}
#endif

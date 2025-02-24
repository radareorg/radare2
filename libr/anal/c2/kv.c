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
	RStrBuf *sb;
	int line;
	AttrList attrs;
	KVCToken s;
	const char *error;
} KVCParser;

typedef bool (*KVCParserCallback)(KVCParser*, const char*);

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
	int alen = kvctoken_len (a);
	int blen = kvctoken_len (b);
	if (alen != blen) {
		return false;
	}
	return !memcmp (a.a, b.a, alen);
}

static void kvctoken_trim(KVCToken *t) {
	while (isspace (*t->a)) {
		t->a++;
	}
	while (t->b >= t->a && isspace (t->b[-1])) {
		t->b--;
	}
}

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
	R_LOG_ERROR ("Parsing problem at line %d: %s", kvc->line, msg);
	kvc->error = msg;
	kvc->s.a = kvc->s.b;
}

static const char *kvc_peekn(KVCParser *kvc, size_t amount) {
	return (kvctoken_len (kvc->s) >= amount)? kvc->s.a: NULL;
}

static const char *kvctoken_find(KVCToken t, const char *needle) {
	size_t len = kvctoken_len (t);
	return (const char *)r_mem_mem ((const ut8*)t.a, len, (const ut8*)needle, strlen (needle));
}

static const char *kvc_find(KVCParser *kvc, const char *needle) {
	size_t len = kvctoken_len (kvc->s);
	return (const char *)r_mem_mem ((const ut8*)kvc->s.a, len, (const ut8*)needle, strlen (needle));
}

static inline void kvc_skipn(KVCParser *kvc, size_t amount) {
	if (amount <= kvctoken_len (kvc->s)) {
		kvc->s.a += amount;
	} else {
		// should not reach this, implies a bug somewhere else
		kvc->s.a = kvc->s.b;
	}
}

static const char *kvc_find_semicolon(KVCParser *kvc) {
	while (!kvctoken_eof (kvc->s)) {
		const char c = kvc_peek (kvc, 0);
		if (c == ';') {
			// kvc_getch (kvc);
			return kvc->s.a;
		}
		if (!isalnum (c) && !isspace (c) && c != '_') {
			if (c != '[' && c != ']' && c != '*') {
				return NULL;
			}
		}
		kvc_getch (kvc);
	}
	return NULL;
}

// rename to until_but
static bool skip_until(KVCParser *kvc, char ch, char ch2) {
	while (!kvctoken_eof (kvc->s)) {
		const char c = kvc_peek (kvc, 0);
		if (!c) {
			break;
		}
		if (c == ch) {
	//		kvc_getch (kvc);
			return true;
		}
		if (ch2 && c != ch2) {
	//		kvc_getch (kvc);
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

static void skip_semicolons(KVCParser *kvc) {
	while (true) {
		char ch = kvc_peek (kvc, 0);
		if (!ch) {
			break;
		}
		if (ch && ch != ';' && !isspace (ch)) {
			break;
		}
		kvc_getch (kvc);
	}
}

static void skip_spaces(KVCParser *kvc) { // TODO: rename to skip_only_spacesand_comments
	bool havespace = false;
repeat:
	skip_only_spaces (kvc);
	const char *comment = kvc_peekn (kvc, 2);
	if (comment && r_str_startswith (comment, "/*")) {
		havespace = true;
		kvc_skipn (kvc, 2);
		const char *closing = kvc_find (kvc, "*/");
		if (!closing) {
			kvc_error (kvc, "Unclosed comment");
			return;
		}
		int delta = 1 + closing - comment;
		kvc_skipn (kvc, delta);
	}
	skip_only_spaces (kvc);
	const char *slash = kvc_peekn (kvc, 3);
	if (slash && slash[0] == '/' && slash[1] == '/' && slash[2] != '/') {
		skip_until (kvc, '\n', 0);
		havespace = true;
		skip_only_spaces (kvc);
	}
	if (havespace) {
		havespace = false;
		goto repeat;
	}
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

static bool parse_attributes(KVCParser *kvc) {
	const char *begin = kvc_peekn (kvc, 3);
	if (!begin) {
		return false;
	}
	if (!r_str_startswith (begin, "///")) {
		return false;
	}
	kvc_skipn (kvc, 3);

	// kvc->attrs.count = 0;
	int line = kvc->line;
	while (true) {
		line = kvc->line;
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
		line = kvc->line;
#if 0
		skip_spaces (kvc);
		if (line != kvc->line) {
		eprintf ("newlines FUUCK (%s)\n", kvc->s.a);
			// newline found
			return true;
		}
#endif
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
			eprintf ("JKLFD PARM\n");
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
	skip_until (kvc, '\n', 0);
	return true;
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
	// eprintf ("i TYPENAME t (%s)\n", kvctoken_tostring (*fun_rtyp));
	// eprintf ("i TYPENAME n (%s)\n", kvctoken_tostring (*fun_name));
	const char *p = fun_rtyp->b - 1;
	while (p > fun_rtyp->a) {
		if (!isalnum (*p) || isspace (*p)) {
			if (*p != '[' && *p != ']') {
				p++;
				break;
			}
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
	// eprintf ("o TYPENAME t (%s)\n", kvctoken_tostring (*fun_rtyp));
	// eprintf ("o TYPENAME n (%s)\n", kvctoken_tostring (*fun_name));
}

static int kvc_typesize(KVCParser *kvc, const char *name) {
	if (r_str_endswith (name, "8")) {
		return 1;
	}
	if (r_str_endswith (name, "16")) {
		return 2;
	}
	if (r_str_endswith (name, "64")) {
		return 8;
	}
	// TODO: honor alignment, packing, access types
	return 4;
}

static bool parse_typedef(KVCParser *kvc, const char *unused) {
	skip_spaces (kvc);
	const char *next = kvc_peekn (kvc, 6);
	if (next && r_str_startswith (next, "struct")) {
		/* typedef struct [Tag]? { ... } Alias; */
		kvc_skipn (kvc, strlen ("struct"));
		skip_spaces (kvc);
		KVCToken tag = {0};
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
			/* This is a forward declaration:
			   e.g. "typedef struct Tag Alias;" */
			KVCToken alias = { .a = consume_word (kvc) };
			if (!alias.a) {
				kvc_error(kvc, "Expected alias in typedef struct forward declaration");
				return false;
			}
			alias.b = kvc->s.a;
			char *alias_str = kvctoken_tostring (alias);
			char *tag_str = has_tag ? kvctoken_tostring (tag) : strdup ("");
			r_strbuf_appendf (kvc->sb, "typedef.struct.%s=%s\n", alias_str, tag_str);
			free (alias_str);
			free (tag_str);
			skip_semicolons (kvc);
			if (kvc_peek (kvc, 0) == ';') {
				kvc_getch(kvc);
			}
			return true;
		}
		// Here we have a definition: typedef struct [Tag]? { ... } Alias;
		kvc_getch (kvc);  // Consume the '{'
		char *struct_tag = has_tag ? kvctoken_tostring (tag) :
			r_str_newf ("anon_struct_%d", kvc->line);
		/* Begin output for the struct definition */
		r_strbuf_appendf (kvc->sb, "struct.%s=struct\n", struct_tag);
		apply_attributes (kvc, "struct", struct_tag);
		RStrBuf *args_sb = r_strbuf_new ("");
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
			KVCToken member_type = {0};
			KVCToken member_name = {0};
			KVCToken member_dimm = {0};
			member_type.a = kvc->s.a;
			member_type.b = kvc_find_semicolon(kvc);
			if (!member_type.b) {
				kvc_error(kvc, "Missing semicolon in struct member");
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
			kvc_getch (kvc); // Skip the semicolon
			kvctoken_trim (&member_type);
			// Handle possible array dimensions (e.g. "[10]"):
			const char *bracket = kvctoken_find (member_name, "[");
			if (bracket) {
				member_dimm.a = bracket + 1;
				member_dimm.b = member_name.b;
				member_name.b = bracket - 1;
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
			char full_scope[512];
			if (!*mn) {
				free (mt);
				free (mn);
				free (md);
				break;
			}
			snprintf (full_scope, sizeof (full_scope), "%s.%s", struct_tag, mn);
			if (R_STR_ISNOTEMPTY (md)) {
				r_strbuf_appendf (kvc->sb, "struct.%s.%s=%s,%d,%s\n",
						struct_tag, mn, mt, off, md);
			} else {
				r_strbuf_appendf (kvc->sb, "struct.%s.%s=%s,%d,0\n",
						struct_tag, mn, mt, off);
			}
			off += kvc_typesize (kvc, mt);
			apply_attributes (kvc, "struct", full_scope);
			r_strbuf_appendf (args_sb, "%s%s", member_idx ? "," : "", mn);
			member_idx++;
			free (mt);
			free (mn);
			free (md);
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
		/* Record the typedef mapping: the alias now refers to our struct tag */
		r_strbuf_appendf (kvc->sb, "typedef.struct.%s=%s\n", alias_str, struct_tag);
		skip_semicolons (kvc);
		if (kvc_peek (kvc, 0) == ';') {
			kvc_getch (kvc);
		}
		char *argstr = r_strbuf_drain (args_sb);
		r_strbuf_appendf (kvc->sb, "struct.%s=%s\n", struct_tag, argstr);
		free (argstr);
		free (struct_tag);
		free (alias_str);
		return true;
	} else if (next && r_str_startswith (next, "union")) {
		/* Similar to the struct case, you would parse:
		   typedef union [Tag]? { ... } Alias;
		   (Implementation omitted for brevity) */
		kvc_error (kvc, "typedef union not implemented");
		return false;
	} else if (next && r_str_startswith (next, "enum")) {
		/* Similarly, handle typedef enum [Tag]? { ... } Alias;
		   (Implementation omitted for brevity) */
		kvc_error (kvc, "typedef enum not implemented");
		return false;
	} else {
		/* Handle a “simple” typedef such as:
		   typedef int myint;
		   In this case we assume that everything from the current pointer until
		   the semicolon is the declaration, and the last word is the alias.
		 */
		const char *start = kvc->s.a;
		const char *semicolon = kvc_find_semicolon (kvc);
		if (!semicolon) {
			kvc_error(kvc, "Missing semicolon in typedef");
			return false;
		}
		const char *p = semicolon - 1;
		while (p > start && isspace (*p)) {
			p--;
		}
		const char *alias_end = p + 1;
		while (p > start && (isalnum (*p) || *p == '_' || *p == '*')) {
			p--;
		}
		if (!(isalnum (*p) || *p == '_' || *p == '*')) {
			p++;
		}
		KVCToken alias = { .a = p, .b = alias_end };
		KVCToken orig_type = { .a = start, .b = p };
		kvctoken_trim (&alias);
		kvctoken_trim (&orig_type);
		char *alias_str = kvctoken_tostring (alias);
		char *type_str = kvctoken_tostring (orig_type);
		r_strbuf_appendf (kvc->sb, "typedef.%s=%s\n", alias_str, type_str);
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
	const char p0 = kvc_peek (kvc, 0);
	if (p0 != '{') {
		R_LOG_ERROR ("Expected { after name in struct");
		return false;
	}
	RStrBuf *args_sb = r_strbuf_new ("");
	kvc_getch (kvc);
	char *sn = kvctoken_tostring (struct_name);
	r_strbuf_appendf (kvc->sb, "%s=%s\n", sn, type);
	apply_attributes (kvc, type, sn);
	int member_idx = 0;
	int off = 0;
	while (true) {
		skip_spaces (kvc);
		parse_attributes (kvc);
		skip_spaces (kvc);

		KVCToken member_type = {0};
		KVCToken member_name = {0};
		KVCToken member_dimm = {0};

		member_type.a = kvc->s.a;
		member_type.b = kvc_find_semicolon (kvc);
		if (!member_type.b) {
			const char ch0 = kvc_peek (kvc, 0);
			if (ch0 == '}') {
				// end of struct definition
				kvc_getch (kvc);
				kvc_getch (kvc);
				break;
			}
			if (ch0) {
				R_LOG_ERROR ("Cant find semicolon in struct field chr(%d)='%c'", ch0, ch0);
			}
			free (sn);
			r_strbuf_free (args_sb);
			return false;
		}
		if (member_type.a == member_type.b) {
			kvc_getch (kvc);
			break;
		}
		memcpy (&member_name, &member_type, sizeof (member_name));
		// eprintf ("ENTRY ((%s)))\n", kvctoken_tostring (member_type));
		kvctoken_typename (&member_type, &member_name);
		kvc_getch (kvc); // skip semicolon
		kvctoken_trim (&member_type);
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
			const char *bracket = kvctoken_find (member_name, "[");
			if (bracket) {
				// parse dimensions
				member_dimm.a = bracket + 1;
				member_dimm.b = member_name.b;
				member_name.b = member_dimm.a - 1;
				member_dimm.b = kvctoken_find (member_dimm, "]");
				if (member_dimm.b) {
					kvc_skipn (kvc, kvctoken_len (member_dimm));
				} else {
					R_LOG_ERROR ("Missing ] in struct field dimension");
				}
			}
		}

		char *mt = kvctoken_tostring (member_type);
		char *mn = kvctoken_tostring (member_name);
		char *md = kvctoken_tostring (member_dimm);
		char full_scope[512];
		if (!*mn) {
			free (mt);
			free (mn);
			free (md);
			break;
		}
		snprintf (full_scope, sizeof (full_scope), "%s.%s", sn, mn);
		if (md) {
			r_strbuf_appendf (kvc->sb, "%s.%s=%s,%d,%s\n", type, full_scope, mt, off, md);
		} else {
			r_strbuf_appendf (kvc->sb, "%s.%s=%s,%d,0\n", type, full_scope, mt, off);
		}
		if (!strcmp (type, "struct")) {
			off += kvc_typesize (kvc, mt);
		}
		apply_attributes (kvc, type, full_scope);
		r_strbuf_appendf (args_sb, "%s%s", member_idx?",":"", mn);
		member_idx++;
		free (mt);
		free (mn);
		free (md);
	}
#if 0
	if (*p == '}') {
		p++;
	}
	// p = skip_until_semicolon (p);
#endif
	kvc_find_semicolon (kvc);
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
	int value = 0;
	bool closing = false;
	while (!closing) {
		skip_spaces (kvc);
		parse_attributes (kvc);
		skip_spaces (kvc);
		KVCToken member_name = {0};
		KVCToken member_value = {0};
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

		char full_scope[512];
		char *mn = kvctoken_tostring (member_name);
		apply_attributes (kvc, "enum", en);
		snprintf (full_scope, sizeof (full_scope), "%s.%s", en, mn);
		if (member_value.a) {
			st64 nv = r_num_get (NULL, member_value.a);
			if (r_str_startswith (member_value.a, "0x")) {
				r_strbuf_appendf (kvc->sb, "enum.%s=0x%"PFMT64x"\n", full_scope, nv);
			} else {
				r_strbuf_appendf (kvc->sb, "enum.%s=%"PFMT64d"\n", full_scope, nv);
			}
			value = nv; // r_num_get (NULL, member_value.a);
		} else {
			r_strbuf_appendf (kvc->sb, "enum.%s=%d\n", full_scope, value);
		}
		if (enumstr) {
			r_strbuf_appendf (enumstr, ",%s", mn);
		} else {
			enumstr = r_strbuf_new (en);
		}
		free (mn);
		value++;
	}
	if (enumstr) {
		char *es = r_strbuf_drain (enumstr);
		r_strbuf_appendf (kvc->sb, "enum.%s=%s\n", en, es);
		free (es);
	}
	char ch = kvc_peek (kvc, 0);
	if (ch == ';') {
		skip_semicolons (kvc);
		kvc_getch (kvc);
	}
	free (en);
	return true;
}

static bool parse_function(KVCParser *kvc) {
	parse_attributes (kvc);
	// eprintf ("PARSE FUNCTION (%s)\n", kvc->s.a);
	KVCToken fun_name = {0};
	KVCToken fun_rtyp = {0};
	KVCToken fun_parm = {0};
	fun_rtyp.a = consume_word (kvc);
	if (!fun_rtyp.a) {
		// no need to error here, there's nothing to parse
		// kvc_error (kvc, "Cannot consume word for function");
		return false;
	}
	fun_rtyp.b = kvc->s.a;
	fun_name.a = fun_rtyp.a;
	if (!skip_until (kvc, '(', 0)) {
		kvc_error (kvc, "Cannot find ( in function definition");
		// r_sys_breakpoint();
		return false;
	}
	fun_name.b = kvc->s.a;
	fun_parm.a = kvc->s.a + 1;
	if (!skip_until (kvc, ')', 0)) {
		kvc_error (kvc, "Cannot find ) in function definition");
		return false;
	}
	kvctoken_typename (&fun_rtyp, &fun_name);
	fun_parm.b = kvc->s.a;
	kvc_skipn (kvc, 1);
	skip_spaces (kvc);
	char semicolon = kvc_getch (kvc);
	if (semicolon != ';') {
		eprintf ("GOT %c\n", semicolon);
		kvc_error (kvc, "Expected ; after function signature");
		return false;
	}

	char *fn = kvctoken_tostring (fun_name);
	char *fr = kvctoken_tostring (fun_rtyp);
	r_strbuf_appendf (kvc->sb, "%s=func\n", fn);
	apply_attributes (kvc, "func", fn);

#if 0
	eprintf ("RETURN (%s)\n", kvctoken_tostring (fun_rtyp));
	eprintf ("FNAME (%s)\n", fn);
	eprintf ("FPARM (%s)\n", kvctoken_tostring (fun_parm));
#endif

	RStrBuf *func_args_sb = r_strbuf_new ("");
	int arg_idx = 0;
	{
		const char *pa = fun_parm.a;
		const char *pb = fun_parm.b;
		const char *argp = pa;
		const char *comma = NULL;
		do {
			while (pa < pb && isspace (*pa)) {
				pa++;
			}
			comma = r_str_nchr (pa, ',', pb - pa);
			pa = comma? comma: pb;
			KVCToken arg_type = { argp, pa };
			KVCToken arg_name = { argp, pa };
			// kvctoken_trim (&arg_type);
			// kvctoken_trim (&arg_name);
			kvctoken_typename (&arg_type, &arg_name);
#if 0
			// XXX how do we know this wtf
			if (!param_name.a) {
				// unnamed arguments
				param_name = r_str_newf ("arg%d", arg_idx);
			}
#endif
			char *an = kvctoken_tostring (arg_name);
			char *at = kvctoken_tostring (arg_type);
			r_strbuf_appendf (kvc->sb, "func.%s.arg.%d=%s,%s\n", fn, arg_idx, at, an);
			r_strbuf_appendf (func_args_sb, "%s%s", arg_idx?",":"", an);
			free (an);
			free (at);
			arg_idx++;
			pa++;
			argp = pa;
		} while (comma);
	}
	char *func_args = r_strbuf_drain (func_args_sb);
	r_strbuf_appendf (kvc->sb, "func.%s=%s\n", fn, func_args);
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

R_IPI char* kvc_parse(const char* header_content, char **errmsg) {
	KVCParser _kvc = {0};
	KVCParser *kvc = &_kvc;
	kvcparser_init (&_kvc, header_content);
	while (!kvctoken_eof (kvc->s)) {
		skip_spaces (kvc);
		const char *word = kvc_peekn (kvc, 6);
		// eprintf ("--> (((%s)))\n", r_str_ndup (word, 10));
		bool hasparse = false;
		if (word) {
			hasparse |= tryparse (kvc, word, "typedef", parse_typedef);
			hasparse |= tryparse (kvc, word, "struct", parse_struct);
			hasparse |= tryparse (kvc, word, "union", parse_struct);
			hasparse |= tryparse (kvc, word, "enum", parse_enum);
		}
#if 1
		// parse function signature
		if (parse_attributes (kvc)) {
			continue;
		}
#endif
		skip_spaces (kvc);
		if (!hasparse) {
			skip_semicolons (kvc); // hack
			parse_function (kvc);
			skip_spaces (kvc);
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

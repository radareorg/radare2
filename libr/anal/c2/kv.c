#include <r_util.h>

#define KVLEN 256

typedef struct {
	char attr_keys[10][KVLEN];
	char attr_values[10][KVLEN];
	int count;
} AttrList;

// TODO: use this instead of fixed length buffers?
typedef struct {
#if 0
	size_t a, b;
#else
	const char *a;
	const char *b;
#endif
} KVCToken;

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

static void kvctoken_append(KVCToken t, RStrBuf *sb) {
	size_t len = kvctoken_len (t);
	r_strbuf_append_n (sb, t.a, len);
}

static void kvctoken_trim(KVCToken *t) {
	while (isspace (*t->a)) {
		t->a++;
	}
	while (t->b >= t->a && isspace (t->b[-1])) {
		t->b--;
	}
}

static const char *kvctoken_lastspace(KVCToken t) {
	const char *p = t.b;
	while (t.a < p && !isspace (*p)) {
		p--;
	}
	return p;
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
	eprintf ("Error at line %d: %s\n", kvc->line, msg);
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
		if (!isalnum (c) && !isspace (c)) {
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

static inline void skip_spaces(KVCParser *kvc) { // TODO: rename to skip_only_spacesand_comments
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

static const char *find_semicolon(const char *p) {
	while (*p && *p != ';') {
		p++;
	}
	return p;
}

static const char *skip_until_semicolon(const char *p) {
	p = find_semicolon (p);
	if (*p == ';') {
		p++;
	}
	return p;
}

static const char *consume_word(KVCParser *kvc) {
	skip_only_spaces (kvc);
	const char *word = kvc->s.a;
	const char *p = word;
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
			char *aname = kvctoken_tostring (attr_name);
			for (i = 0; i < kvc->attrs.count; i++) {
				const char *name = kvc->attrs.attr_keys[i];
				if (!strcmp (name, aname)) {
					duppedkey = true;
					atidx = i;
					break;
				}
			}
		}
		if (!duppedkey) {
			kvc->attrs.count++;
			char *an = kvc->attrs.attr_keys[atidx];
			r_str_ncpy (an, attr_name.a, kvctoken_len (attr_name) + 1);
		}
		eprintf ("KEY (%s)\n", kvctoken_tostring (attr_name));
		char *av = kvc->attrs.attr_values[atidx];
		// XXX TODO: use KVCToken too
		if (attr_value.a) {
			r_str_ncpy (av, attr_value.a, kvctoken_len (attr_value) + 1);
		} else {
			r_str_ncpy (av, "true", 5);
		}
	}
	skip_until (kvc, '\n', 0);
	return true;
}

static void apply_attributes(KVCParser *kvc, const char *type, const char *scope) {
	int i;
	for (i = 0; i < kvc->attrs.count; i++) {
		r_strbuf_appendf (kvc->sb, "%s.%s.@.%s=%s\n",
			type, scope, kvc->attrs.attr_keys[i],
			kvc->attrs.attr_values[i]);
	}
	kvc->attrs.count = 0; // Reset after applying
}

static char *parse_member_dimensions(KVCToken *name) {
	const char *o = kvctoken_find (*name, "[");
	const char *c = kvctoken_find (*name, "]");
	if (o && c) {
		if (o < c) {
			name->b = o;
			return r_str_ndup (o + 1, c - o - 2);
		}
	}
	return NULL;
}

static bool parse_member_typename(const char *b, const char *e, char **name, char **type, char **dimensions) {
	const char *d = NULL;
	*dimensions = NULL;
	if (e > b && e[-1] == ']') {
		d = e - 1;
		do {
			d--;
		} while (*d != '[');
		e = d;
		*dimensions = r_str_ndup (d + 1, e - d + 2);
	}
	const char *name_begin = e - 1;
	while (name_begin > b && !isspace (*name_begin) && *name_begin != '*') {
		name_begin--;
	}
	name_begin++;
	*name = r_str_ndup (name_begin, e - name_begin);
	*type = r_str_ndup (b, name_begin - b);
	r_str_trim (*name);
	r_str_trim (*type);
	return true;
}

static void kvctoken_typename(KVCToken *fun_rtyp, KVCToken *fun_name) {
	// readjust name and rtyp
	// kvctoken_trim (fun_rtyp);
	fun_rtyp->b = fun_name->b;
	// eprintf ("i TYPENAME t (%s)\n", kvctoken_tostring (*fun_rtyp));
	// eprintf ("i TYPENAME n (%s)\n", kvctoken_tostring (*fun_name));
	const char *p = fun_rtyp->b - 1;
	while (p > fun_rtyp->a) {
		if (!isalnum (*p) || isspace (*p)) {
			if (*p != '[' && *p != ']') {
				eprintf ("BREAK %c\n", *p);
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
	//eprintf ("o TYPENAME t (%s)\n", kvctoken_tostring (*fun_rtyp));
	// eprintf ("o TYPENAME n (%s)\n", kvctoken_tostring (*fun_name));
}

// works for unions and structs
static bool parse_struct(KVCParser *kvc, const char *type) {
	const char *p = kvc->s.a;
	KVCToken struct_name = { .a = consume_word (kvc) };
	if (!struct_name.a) {
		R_LOG_ERROR ("Cannot consume word");
		return false;
	}
	struct_name.b = kvc->s.a;
	skip_spaces (kvc);
	RStrBuf *args_sb = r_strbuf_new ("");
	const char p0 = kvc_peek (kvc, 0);
	if (p0 != '{') {
		R_LOG_ERROR ("Expected { after name in struct");
		return false;
	}
	kvc_getch (kvc);
	char *sn = kvctoken_tostring (struct_name);
	r_strbuf_appendf (kvc->sb, "%s=%s\n", sn, type);
	apply_attributes (kvc, type, sn);
	int member_idx = 0;
	while (true) {
		skip_spaces (kvc);
		parse_attributes (kvc);
		skip_spaces (kvc);

		char *dimensions = NULL;
		KVCToken member_type = {0};
		KVCToken member_name = {0};
		KVCToken member_dimm = {0};

		member_type.a = kvc->s.a;
		member_type.b = kvc_find_semicolon (kvc);
		if (!member_type.b) {
			const char ch0 = kvc_peek (kvc, 0);
			if (ch0 == '}') {
				// end of struct definition
				char ch = kvc_getch (kvc);
				kvc_getch (kvc);
				break;
			}
			if (ch0) {
				R_LOG_ERROR ("Cant find semicolon in struct field %d %c", ch0, ch0);
			}
			return false;
		}
		memcpy (&member_name, &member_type, sizeof (member_name));
		eprintf ("ENTRY ((%s)))\n", kvctoken_tostring (member_type));
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

		char *mt = kvctoken_tostring (member_type);
		char *mn = kvctoken_tostring (member_name);
		char *md = kvctoken_tostring (member_dimm);
		char array_info[256] = "";
		char full_scope[512];
		if (!*mn) {
			break;
		}
		snprintf (full_scope, sizeof (full_scope), "%s.%s", sn, mn);
		if (md) {
			r_strbuf_appendf (kvc->sb, "%s.%s=%s,0,%s\n", type, full_scope, mt, md);
		} else {
			r_strbuf_appendf (kvc->sb, "%s.%s=%s\n", type, full_scope, mt);
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
	apply_attributes (kvc, "enum", en);
	free (en);
	const char *name_start = kvc->s.a;
	skip_spaces (kvc);
	const char p0 = kvc_peek (kvc, 0);
	if (p0 != '{') {
		R_LOG_ERROR ("Expected { after name in enum");
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
			return false;
		}

		char full_scope[512];
		char *en = kvctoken_tostring (enum_name);
		char *mn = kvctoken_tostring (member_name);
		apply_attributes (kvc, "enum", en);
		snprintf (full_scope, sizeof (full_scope), "%s.%s", en, mn);
		if (member_value.a) {
			int nv = atoi (member_value.a);
			r_strbuf_appendf (kvc->sb, "enum.%s=%d\n", full_scope, nv);
			value = nv;
		} else {
			r_strbuf_appendf (kvc->sb, "enum.%s=%d\n", full_scope, value);
		}
		value++;
	}
	// if (*p == '}') { p++; }
	char ch = kvc_peek (kvc, 0);
	if (ch == ';') {
		kvc_getch (kvc);
	}
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

	eprintf ("RETURN (%s)\n", kvctoken_tostring (fun_rtyp));
	eprintf ("FNAME (%s)\n", fn);
	eprintf ("FPARM (%s)\n", kvctoken_tostring (fun_parm));

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
			arg_idx++;
			argp = ++pa;
		} while (comma);
	}
	char *func_args = r_strbuf_drain (func_args_sb);
	r_strbuf_appendf (kvc->sb, "func.%s=%s\n", fn, func_args);
	r_strbuf_appendf (kvc->sb, "func.%s.ret=%s\n", fn, fr);
	r_strbuf_appendf (kvc->sb, "func.%s.args=%d\n", fn, arg_idx);
	free (func_args);
	free (fn);
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

char* parse_header(const char* header_content) {
	KVCParser _kvc = {0};
	KVCParser *kvc = &_kvc;
	kvcparser_init (&_kvc, header_content);
	const char *p = header_content;
	while (!kvctoken_eof (kvc->s)) {
		skip_spaces (kvc);
		const char *word = kvc_peekn (kvc, 6);
		// eprintf ("--> (((%s)))\n", r_str_ndup (word, 10));
		bool hasparse = false;
		if (word) {
			hasparse |= tryparse (kvc, word, "typedef", NULL);
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
			parse_function (kvc);
		}
		skip_spaces (kvc);
	}
	char *res = r_strbuf_drain (kvc->sb);
	kvc->sb = NULL;
	kvcparser_fini (kvc);
	return res;
}

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

	char *result = parse_header ((const char *)content);
	if (result) {
		printf ("%s\n", result);
		free (result);
	}

	free (content);
	return 0;
}
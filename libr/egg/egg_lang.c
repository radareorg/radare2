/* radare - LGPL - Copyright 2010-2026 - pancake */

#include <r_egg.h>

#define CTX egg->context

static inline bool is_var(char *x) {
	return x[0] == '.' || ((x[0] == '*' || x[0] == '&') && x[1] == '.');
}

static inline bool is_space(char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static bool is_escaped(const char *start, const char *pos) {
	bool escaped = false;
	while (pos > start && pos[-1] == '\\') {
		escaped = !escaped;
		pos--;
	}
	return escaped;
}

static inline int is_op(char x) {
	switch (x) {
	case '-':
	case '+':
		return 1;
	case '*':
	case '/':
		return 2;
	case '^':
	case '|':
	case '&':
		return 3;
	default:
		return 0;
	}
}

static inline int get_op(char **pos) {
	while (**pos && ! (is_op (**pos) && !is_var (*pos))) {
		(*pos)++;
	}
	return (**pos)? ((is_op (**pos)) + 1): 0;
}

static bool rcc_pushstr(REgg *egg, char *str, bool filter);
static void rcc_context(REgg *egg, int delta);
static void rcc_capture(REgg *egg, int mode, const char *name);

static void rcc_error(REgg *egg, const char *msg, const char *arg) {
	R_LOG_ERROR ("%s:%d: %s%s", egg->lang.file, egg->lang.line, msg, r_str_get (arg));
	egg->lang.failed = true;
}

// raw assembly text (`: lines`, labels, @data) goes to the backend hook or the output buffer
static void rcc_raw(REgg *egg, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
static void rcc_raw(REgg *egg, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *text = r_str_newvf (fmt, ap);
	va_end (ap);
	if (egg->remit->raw) {
		egg->remit->raw (egg, text);
	} else {
		r_buf_append_string (egg->buf, text);
	}
	free (text);
}

enum {
	LANG_MODE_NORMAL = 0,
	LANG_MODE_ALIAS,
	LANG_MODE_INCLUDE,
	LANG_MODE_DATA,
	LANG_MODE_INLINE,
	LANG_MODE_NAKED,
	LANG_MODE_FASTCALL,
	LANG_MODE_SYSCALL,
	LANG_MODE_SYSCALLBODY,
	LANG_MODE_GOTO,
	LANG_MODE_EXTERN,
	LANG_MODE_LAST
};

static char *find_include(REgg *egg, const char *prefix, const char *file) {
	char *env_prefix = NULL;
	if (prefix && *prefix == '$') {
		prefix = env_prefix = r_sys_getenv (prefix + 1);
	}
	char *relative = R_STR_ISEMPTY (prefix) || r_file_is_abspath (file)
		? strdup (file): r_str_newf ("%s" R_SYS_DIR "%s", prefix, file);
	free (env_prefix);
	if (!relative || r_file_is_abspath (relative)) {
		return relative;
	}
	const char *source = egg->lang.file;
	if (source && (strchr (source, '/') || strchr (source, '\\'))) {
		char *dir = r_file_dirname (source);
		char *path = dir? r_file_new (dir, relative, NULL): NULL;
		free (dir);
		if (path && r_file_exists (path)) {
			free (relative);
			return path;
		}
		free (path);
	}
	char *env = r_sys_getenv (R_EGG_INCDIR_ENV);
	char *dir = env;
	while (dir) {
		char *next = strchr (dir, ':');
		if (next) {
			*next++ = 0;
		}
		char *path = r_file_new (*dir? dir: ".", relative, NULL);
		if (path && r_file_exists (path)) {
			free (env);
			free (relative);
			return path;
		}
		free (path);
		dir = next;
	}
	free (env);
	return relative;
}

R_API void r_egg_lang_init(REgg *egg) {
	egg->lang.varsize = 'l';
	/* do call or inline it? */ // BOOL
	egg->lang.docall = 1;
	egg->lang.line = 1;
	if (!egg->lang.file) {
		egg->lang.file = strdup ("stdin");
	}
	egg->lang.oc = '\n';
	egg->lang.mode = LANG_MODE_NORMAL;
}

R_API void r_egg_lang_fini(REgg *egg) {
	int i, j, len;
	for (i = 0; i < R_ARRAY_SIZE (egg->lang.ifelse_table); i++) {
		for (j = 0; j < R_ARRAY_SIZE (egg->lang.ifelse_table[i]); j++) {
			R_FREE (egg->lang.ifelse_table[i][j]);
		}
	}

	for (i = 0; i < egg->lang.nsyscalls; i++) {
		R_FREE (egg->lang.syscalls[i].name);
		R_FREE (egg->lang.syscalls[i].arg);
	}
	for (i = 0; i < egg->lang.nalias; i++) {
		R_FREE (egg->lang.aliases[i].name);
		R_FREE (egg->lang.aliases[i].content);
	}
	for (i = 0; i < egg->lang.ninlines; i++) {
		R_FREE (egg->lang.inlines[i].name);
		R_FREE (egg->lang.inlines[i].body);
	}
	len = sizeof (egg->lang.ctxpush) / sizeof (char *);
	for (i = 0; i < len; i++) {
		R_FREE (egg->lang.ctxpush[i]);
	}
	len = sizeof (egg->lang.inlines) / sizeof (egg->lang.inlines[0]);
	for (i = 0; i < len; i++) {
		R_FREE (egg->lang.inlines[i].name);
		R_FREE (egg->lang.inlines[i].body);
	}
	len = sizeof (egg->lang.aliases) / sizeof (egg->lang.aliases[0]);
	for (i = 0; i < len; i++) {
		R_FREE (egg->lang.aliases[i].name);
		R_FREE (egg->lang.aliases[i].content);
	}
	len = sizeof (egg->lang.nested) / sizeof (char *);
	for (i = 0; i < len; i++) {
		R_FREE (egg->lang.nested[i]);
	}
	len = sizeof (egg->lang.nested_callname) / sizeof (char *);
	for (i = 0; i < len; i++) {
		R_FREE (egg->lang.nested_callname[i]);
	}
	R_FREE (egg->lang.conditionstr);
	r_strbuf_fini (&egg->lang.elem);
	r_strbuf_free (egg->lang.capture);
	egg->lang.capture = NULL;
	R_FREE (egg->lang.syscallbody);
	R_FREE (egg->lang.includefile);
	R_FREE (egg->lang.setenviron);
	R_FREE (egg->lang.mathline);
	R_FREE (egg->lang.callname);
	R_FREE (egg->lang.endframe);
	R_FREE (egg->lang.file);
	R_FREE (egg->lang.dstvar);
	R_FREE (egg->lang.dstval);
	R_FREE (egg->lang.includedir);
}

R_API void r_egg_lang_include_path(REgg *egg, const char *path) {
	char *tmp_ptr = NULL;
	char *env = r_sys_getenv (R_EGG_INCDIR_ENV);
	if (!env || !*env) {
		r_egg_lang_include_init (egg);
		free (env);
		env = r_sys_getenv (R_EGG_INCDIR_ENV);
		tmp_ptr = env;
	}
	env = r_str_appendf (NULL, "%s:%s", path, env);
	free (tmp_ptr);
	r_sys_setenv (R_EGG_INCDIR_ENV, env);
	free (env);
}

R_API void r_egg_lang_include_init(REgg *egg) {
	char *pfx = r_sys_prefix (NULL);
	char *s = r_str_newf (".:%s/%s", pfx, R_EGG_INCDIR_PATH);
	free (pfx);
	r_sys_setenv (R_EGG_INCDIR_ENV, s);
	free (s);
}

static void rcc_set_callname(REgg *egg, const char *s) {
	R_FREE (egg->lang.callname);
	egg->lang.nargs = 0;
	egg->lang.callname = r_str_trim_dup (s);
	egg->lang.pushargs = ! ((!strcmp (s, "goto")) || (!strcmp (s, "break")));
}

static void rcc_reset_callname(REgg *egg) {
	R_FREE (egg->lang.callname);
	egg->lang.nargs = 0;
}

static void rcc_fastcall(REgg *egg, bool with_body) {
	REggEmit *e = egg->remit;
	char *value = egg->lang.dstval? r_str_trim_dup (egg->lang.dstval): NULL;
	if (!with_body && egg->lang.dstvar && R_STR_ISNOTEMPTY (value)) {
		e->equ (egg, egg->lang.dstvar, value);
	}
	if (with_body && egg->lang.dstvar) {
		rcc_raw (egg, "%s:\n", egg->lang.dstvar);
		rcc_context (egg, 1);
	}
	R_FREE (value);
	R_FREE (egg->lang.dstvar);
	R_FREE (egg->lang.dstval);
	egg->lang.mode = LANG_MODE_NORMAL;
	r_strbuf_set (&egg->lang.elem, "");
	egg->lang.slurp = 0;
}

#define SYNTAX_ATT 0
#if SYNTAX_ATT
#define FRAME_FMT ".LC%d_%d_frame%d"
#define FRAME_END_FMT ".LC%d_%d_end_frame%d"
#else
#define FRAME_FMT "__%d_%d_frame%d"
#define FRAME_END_FMT "__%d_%d_end_frame%d"
#endif

static const char *find_alias(REgg *egg, const char *str) {
	// do not forget to free return strings to avoid memory leak
	char *p = (char *)str;
	int i;
	if (*str == '"') {
		return strdup (str);
	}
	// strings could not means aliases
	while (*p && !is_space (*p)) {
		p++;
	}
	*p = '\x00';
	for (i = 0; i < egg->lang.nalias; i++) {
		const char *name = egg->lang.aliases[i].name;
		if (name && !strcmp (str, name)) {
			return strdup (egg->lang.aliases[i].content);
		}
	}
	return NULL;
	// only strings or alias could return valuable data
}

static void rcc_internal_mathop(REgg *egg, const char *ptr, char *ep, char op) {
	char *q, *oldp;
	const char *p;
	char *allocated = NULL; // extra heap pointer that needs freeing
	char type = ' ';
	oldp = q = strdup (ptr);
	if (get_op (&q)) {
		*q = '\x00';
	}
	REggEmit *e = egg->remit;
	p = r_str_trim_head_ro (oldp);
	/* also strip trailing whitespace in-place (we own oldp) */
	{
		char *end = (char *)p + strlen (p);
		while (end > p && (end[-1] == ' ' || end[-1] == '\t')) {
			end--;
			*end = '\0';
		}
	}
	if (is_var ((char *)p)) {
		allocated = r_egg_mkvar (egg, r_strs_from (p), 0);
		p = allocated;
		if (egg->lang.varxs == '*') {
			e->load (egg, p, egg->lang.varsize);
			R_FREE (allocated);
			allocated = strdup (e->regs (egg, 0));
			p = allocated;
			// XXX: which will go wrong in arm
			// for reg used in emit.load in arm is r7 not r0
		} else if (egg->lang.varxs == '&') {
			e->load_ptr (egg, p);
			R_FREE (allocated);
			allocated = strdup (e->regs (egg, 0));
			p = allocated;
		}
		type = ' ';
	} else {
		type = '$';
	}
	if (R_STR_ISNOTEMPTY (p)) {
		e->mathop (egg, op, egg->lang.varsize, type, p, ep);
	}
	R_FREE (allocated);
	R_FREE (oldp);
	R_FREE (ep);
}

/*
 * level 2: + -
 * level 3: * /
 * level 4: ^ $ |
 */
static void rcc_mathop(REgg *egg, char **pos, int level) {
	REggEmit *e = egg->remit;
	int op_ret = level;
	char op, *next_pos;

	*pos = (char *)r_str_trim_head_ro (*pos);
	next_pos = *pos + 1;

	do {
		op = (is_op (**pos) && ! (is_var (*pos)))? **pos: '=';
		*pos = (is_op (**pos) && ! (is_var (*pos)))? *pos + 1: *pos;
		op_ret = get_op (&next_pos);
		if (op_ret > level) {
			rcc_mathop (egg, pos, op_ret);
			rcc_internal_mathop (egg, e->regs (egg, op_ret - 1),
				strdup (e->regs (egg, level - 1)), op);
			next_pos = *pos + 1;
		} else {
			rcc_internal_mathop (egg, *pos, strdup (e->regs (egg, level - 1)), op);
			*pos = next_pos;
			next_pos++;
		}
	} while (**pos && op_ret >= level);

	/* following code block sould not handle '-' and '/' well
		if (op_ret < level) {
			rcc_internal_mathop (egg, p, strdup (e->regs (egg, level-1)), '=');
			return;
		}
		op = *pos, *pos = '\x00', (*pos)++;
		rcc_mathop (egg, pos, op_ret);
		if (op_ret > level) {
			rcc_internal_mathop (egg, p, strdup (e->regs (egg, op_ret-1)), op);
			rcc_internal_mathop (egg, (char *)e->regs (egg, op_ret-1),
					strdup (e->regs (egg, level-1)), '=');
		} else { rcc_internal_mathop (egg, p, strdup (e->regs (egg, level-1)), op); }
	 */
}

static void rcc_pusharg(REgg *egg, RStrs arg) {
	REggEmit *e = egg->remit;
	char *p = r_egg_mkvar (egg, arg, 0);
	if (!p) {
		return;
	}
	R_FREE (egg->lang.ctxpush[CTX]);
	egg->lang.ctxpush[CTX] = strdup (p); // INDEX IT WITH NARGS OR CONTEXT? !?
	egg->lang.nargs++;
	if (egg->lang.pushargs) {
		e->push_arg (egg, egg->lang.varxs, egg->lang.nargs, p);
	}
	// egg->lang.ctxpush[context+egg->lang.nbrackets] = strdup (str); // use egg->lang.nargs??? (in callname)
	free (p);
}

static void rcc_element(REgg *egg, char *str) {
	if (!egg || !str) {
		return;
	}
	REggEmit *e = egg->remit;
	char *ptr, *p = str + strlen (str);
	const char *end = p;
	int inside = 0;
	int num, num2;
	int i;

	if (CTX) {
		if (egg->lang.slurp == '"') {
			if (egg->lang.mode == LANG_MODE_NORMAL) {
				if (!egg->lang.dstvar) {
					egg->lang.dstvar = strdup (".fix0");
				}
				rcc_pushstr (egg, str, 1);
			}
		} else {
			if (egg->lang.callname) {
				if (!strcmp (egg->lang.callname, "while") || !strcmp (egg->lang.callname, "if")) {
					free (egg->lang.conditionstr);
					egg->lang.conditionstr = strdup (str);
				}
			}
			egg->lang.nargs = 0;
			if (egg->lang.mode == LANG_MODE_GOTO) {
				egg->lang.mode = LANG_MODE_NORMAL; // XXX
			}
			while (p > str) {
				p--;
				if ((*p == '"' || *p == '\'') && !is_escaped (str, p)) {
					if (!inside || inside == *p) {
						inside = inside? 0: *p;
					}
				} else if (*p == ',' && !inside) {
					rcc_pusharg (egg, r_strs_new (p + 1, end));
					end = p;
				}
			}
			rcc_pusharg (egg, r_strs_new (str, end));
		}
	} else {
		switch (egg->lang.mode) {
		case LANG_MODE_ALIAS:
			if (!egg->lang.dstvar) {
				R_LOG_ERROR ("does not set name or content for alias");
				break;
			}
			e->equ (egg, egg->lang.dstvar, str);
			if (egg->lang.nalias > 255) {
				R_LOG_ERROR ("global-buffer-overflow in aliases");
				break;
			}
			for (i = 0; i < egg->lang.nalias; i++) {
				const char *name = egg->lang.aliases[i].name;
				if (name && !strcmp (egg->lang.dstvar, name)) {
					R_FREE (egg->lang.aliases[i].name);
					R_FREE (egg->lang.aliases[i].content);
					break;
				}
			}
			egg->lang.aliases[i].name = strdup (egg->lang.dstvar);
			egg->lang.aliases[i].content = strdup (str);
			egg->lang.nalias = (i == egg->lang.nalias)? (egg->lang.nalias + 1): egg->lang.nalias;
			// allow alias overwrite
			R_FREE (egg->lang.dstvar);
			egg->lang.mode = LANG_MODE_NORMAL;
			break;
		case LANG_MODE_SYSCALL: {
			if (!egg->lang.dstvar) {
				R_LOG_ERROR ("does not set name or arg for syscall");
				break;
			}
			if (egg->lang.nsyscalls > 255) {
				R_LOG_ERROR ("global-buffer-overflow in syscalls");
				break;
			}
			char syscall_number[32];
			r_str_trim (str);
			if (r_name_check (str)) {
				char *alias = (char *)find_alias (egg, str);
				if (alias) {
					free (alias);
				} else {
					int number = egg->syscall->db? r_syscall_get_num (egg->syscall, str): -1;
					if (number < 0) {
						rcc_error (egg, "unknown syscall for this target ", str);
						break;
					}
					snprintf (syscall_number, sizeof (syscall_number), "%d", number);
					str = syscall_number;
				}
			}
			{
				bool found = false;
				int idx = egg->lang.nsyscalls;
				for (i = 0; i < egg->lang.nsyscalls; i++) {
					if (egg->lang.syscalls[i].name && !strcmp (egg->lang.dstvar, egg->lang.syscalls[i].name)) {
						idx = i;
						found = true;
						break;
					}
				}
				// XXX the mem for name and arg are not freed - MEMLEAK
				R_FREE (egg->lang.syscalls[idx].name);
				R_FREE (egg->lang.syscalls[idx].arg);
				egg->lang.syscalls[idx].name = strdup (egg->lang.dstvar);
				egg->lang.syscalls[idx].arg = strdup (str);
				if (!found) {
					egg->lang.nsyscalls++;
				}
				R_FREE (egg->lang.dstvar);
			}
			break;
		}
		case LANG_MODE_GOTO:
			e->jmp (egg, str, 0);
			break;
		case LANG_MODE_INCLUDE:
			str = ptr = (char *)find_alias (egg, r_str_trim_head_ro (str));
			if (ptr) {
				if (strchr (ptr, '"')) {
					ptr = strchr (ptr, '"') + 1;
					if ((p = strchr (ptr, '"'))) {
						*p = '\x00';
					} else {
						R_LOG_ERROR ("loss back quote in include directory");
					}
					egg->lang.includedir = strdup (ptr);
				} else {
					R_LOG_ERROR ("wrong include syntax");
					// for must use string to symbolize directory
					egg->lang.includedir = NULL;
				}
			} else {
				egg->lang.includedir = NULL;
			}
			R_FREE (str);
			break;
		case LANG_MODE_FASTCALL:
			R_FREE (egg->lang.dstval);
			egg->lang.dstval = r_str_trim_dup (str);
			break;
		case LANG_MODE_EXTERN:
			if (e->declare) {
				e->declare (egg, egg->lang.dstvar, str);
			}
			R_FREE (egg->lang.dstvar);
			egg->lang.mode = LANG_MODE_NORMAL;
			break;
		default:
			p = strchr (str, ',');
			if (p) {
				*p = '\0';
				num2 = atoi (p + 1);
			} else {
				num2 = 0;
			}
			num = atoi (str) + num2;
			egg->lang.stackframe = num;
			egg->lang.stackfixed = num2;
			if (egg->lang.mode != LANG_MODE_NAKED) {
				e->frame (egg, egg->lang.stackframe + egg->lang.stackfixed);
			}
		}
	}
}

static bool rcc_pushstr(REgg *egg, char *str, bool filter) {
	REggEmit *e = egg->remit;
	e->comment (egg, "encode %s string (%s) (%s)",
		filter? "filtered": "unfiltered", str, egg->lang.callname);
	const int len = filter? r_str_unescape (str): strlen (str);
	if (!len && *str) {
		rcc_error (egg, "invalid string literal ", str);
		return false;
	}
	e->set_string (egg, egg->lang.dstvar, r_strs_from_len (str, len));
	R_FREE (egg->lang.dstvar);
	return true;
}

/* Emit a branch-target label in a backend-appropriate form. Backends that
 * assemble to native code keep the classic ".S" style "name:\n"; backends
 * like ESIL override the callback to drop labels entirely. */
static void emit_label(REgg *egg, const char *name) {
	if (egg->remit && egg->remit->label) {
		egg->remit->label (egg, name);
	} else {
		rcc_raw (egg, "%s:\n", name);
	}
}

// leading decimal or 0x number, ignoring trailing tokens like "=="
static int parse_leading_idx(RStrs s) {
	const bool hex = r_strs_startswith (s, "0x") || r_strs_startswith (s, "0X");
	int n = 0;
	for (r_strs_advance (&s, hex? 2: 0); !r_strs_empty (s); s.a++) {
		const int ch = tolower ((ut8)*s.a);
		const int digit = isdigit (ch)? ch - '0': (hex && ch >= 'a' && ch <= 'f')? ch - 'a' + 10: -1;
		if (digit < 0) {
			break;
		}
		n = n * (hex? 16: 10) + digit;
	}
	return n;
}

static int parse_idx_after(RStrs name, size_t skip) {
	r_strs_advance (&name, skip);
	return parse_leading_idx (name);
}

static bool mkvar_local(REgg *egg, RStrBuf *out, RStrs name, int delta) {
	REggEmit *e = egg->remit;
	const int kind = r_strs_startswith (name, "fix")? 'f': r_strs_startswith (name, "var")? 'v'
		: (r_strs_startswith (name, "arg") && r_strs_len (name) > 3)? 'a': 0;
	if (!kind) {
		return false;
	}
	const int idx = parse_idx_after (name, 3);
	if (e->get_local) {
		e->get_local (egg, out, kind, idx);
	} else if (kind != 'a') {
		e->get_var (egg, 0, out, idx + delta + e->size - (kind == 'f'? egg->lang.stackfixed: 0));
	} else if (egg->lang.stackframe == 0) {
		e->get_var (egg, 1, out, 4);
	} else {
		e->get_var (egg, 2, out, idx + delta + e->size + 4);
	}
	return true;
}

static void mkvar_name(REgg *egg, RStrBuf *out, RStrs name, int delta) {
	REggEmit *e = egg->remit;
	int i;
	if (mkvar_local (egg, out, name, delta)) {
		return;
	}
	if (r_strs_at (name, 0) == '%') {
		// `.%name` is a raw native register, copied verbatim without alias lookup
		r_strbuf_append_n (out, name.a + 1, r_strs_len (name) - 1);
	} else if (r_strs_startswith (name, "ret")) {
		r_strbuf_set (out, e->retvar);
	} else if (r_strs_startswith (name, "rarg")) {
		if (e->get_arg) {
			e->get_arg (egg, out, parse_idx_after (name, 4));
		}
	} else if (r_strs_startswith (name, "arg")) {
		if (egg->lang.callname) {
			for (i = 0; i < egg->lang.nsyscalls; i++) {
				const char *scname = egg->lang.syscalls[i].name;
				if (scname && !strcmp (scname, egg->lang.callname)) {
					r_strbuf_set (out, r_str_get (egg->lang.syscalls[i].arg));
					return;
				}
			}
			R_LOG_ERROR ("Unknown arg for syscall '%s'", r_str_get (egg->lang.callname));
		} else {
			R_LOG_WARN ("No CallName '%s'", r_str_get (egg->lang.callname));
		}
	} else if (r_strs_startswith (name, "reg")) {
		const char *reg = e->regs (egg, parse_idx_after (name, 3));
		r_strbuf_setf (out, "%s%s", egg->lang.attsyntax? "%": "", reg);
	} else {
		for (i = 0; i < egg->lang.nalias; i++) {
			const char *aname = egg->lang.aliases[i].name;
			if (aname && r_strs_equals_str (name, aname)) {
				r_strbuf_set (out, r_str_get (egg->lang.aliases[i].content));
				return;
			}
		}
		const int len = r_strs_len (name);
		R_LOG_ERROR ("Unknown name '.%.*s' (use .%%%.*s for a raw register or `%.*s@alias(...)`)",
			len, name.a, len, name.a, len, name.a);
	}
}

static bool mkvar_buf(REgg *egg, RStrBuf *out, RStrs str, int delta) {
	if (!str.a) {
		return false;
	}
	r_strs_trim (&str);
	const char quote = (r_strs_at (str, 0) == '"' || r_strs_at (str, 0) == '\'')? *str.a: 0;
	RStrs size;
	egg->lang.varsize = 'l';
	if (!quote && r_strs_split (str, ':', &str, &size)) {
		r_strs_trim (&size);
		egg->lang.varsize = parse_leading_idx (size) == 1? 'b': 'l';
	}
	RStrs name = str;
	const char modifier = r_strs_at (name, 0);
	egg->lang.varxs = (modifier == '*' || modifier == '&')? modifier: 0;
	r_strs_advance (&name, egg->lang.varxs? 1: 0);
	if (r_strs_at (name, 0) == '.') {
		r_strs_advance (&name, 1);
		mkvar_name (egg, out, name, delta + egg->lang.stackfixed);
		return true;
	}
	if (!quote) {
		r_strbuf_append_n (out, str.a, r_strs_len (str));
		return true;
	}
	if (r_strs_len (str) < 2 || r_strs_lastch (str) != quote) {
		return false;
	}
	char *literal = r_strs_tostring (r_strs_sub (str, 1, r_strs_len (str) - 1));
	const int len = r_strs_len (str) - 2;
	if (!egg->remit->get_local && (!egg->lang.stackfixed || egg->lang.stackfixed < len)) {
		R_LOG_WARN ("No room in the static stackframe! (%d must be %d)", egg->lang.stackfixed, len);
	}
	char *fix = r_str_newf (".fix%d", egg->lang.nargs * 16);
	char *dstvar = egg->lang.dstvar;
	egg->lang.dstvar = strdup (fix);
	bool ret = rcc_pushstr (egg, literal, quote == '"');
	free (egg->lang.dstvar);
	egg->lang.dstvar = dstvar;
	ret = ret && mkvar_buf (egg, out, r_strs_from (fix), 0);
	free (fix);
	free (literal);
	return ret;
}

R_API char *r_egg_mkvar(REgg *egg, RStrs str, int delta) {
	RStrBuf *sb = r_strbuf_new ("");
	if (!mkvar_buf (egg, sb, str, delta)) {
		r_strbuf_free (sb);
		return NULL;
	}
	return r_strbuf_drain (sb);
}

static bool rcc_fun(REgg *egg, char *str) {
	char *ptr, *ptr2;
	REggEmit *e = egg->remit;
	if (CTX) {
		ptr = strchr (str, '=');
		if (ptr) {
			*ptr++ = '\0';
			free (egg->lang.dstvar);
			egg->lang.dstvar = r_str_trim_dup (str);
			const char *callname = r_str_trim_head_ro (ptr);
			if (*callname) {
				rcc_set_callname (egg, callname);
			}
		} else {
			rcc_set_callname (egg, str);
			egg->remit->comment (egg, "rcc_fun %d (%s)", CTX, egg->lang.callname);
		}
	} else {
		r_str_trim (str);
		ptr = strchr (str, '@');
		if (ptr) {
			*ptr++ = '\0';
			egg->lang.mode = LANG_MODE_NORMAL;
			if (strstr (ptr, "env")) {
				// eprintf ("SETENV (%s)\n", str);
				free (egg->lang.setenviron);
				egg->lang.setenviron = r_str_trim_dup (str);
				egg->lang.slurp = 0;
			} else if (strstr (ptr, "extern")) {
				if (!e->declare) {
					R_LOG_ERROR ("@extern for '%s' requires the LLVM backend (-a llvm)", str);
					return false;
				}
				free (egg->lang.dstvar);
				egg->lang.dstvar = r_str_trim_dup (str);
				egg->lang.mode = LANG_MODE_EXTERN;
			} else if (strstr (ptr, "fastcall")) {
				free (egg->lang.dstvar);
				egg->lang.dstvar = r_str_trim_dup (str);
				R_FREE (egg->lang.dstval);
				egg->lang.mode = LANG_MODE_FASTCALL;
			} else if (strstr (ptr, "syscall")) {
				if (*str) {
					egg->lang.mode = LANG_MODE_SYSCALL;
					free (egg->lang.dstvar);
					egg->lang.dstvar = r_str_trim_dup (str);
				} else {
					// a nameless inline body replaces the backend @syscall payload
					rcc_capture (egg, LANG_MODE_INLINE, NULL);
				}
			} else if (strstr (ptr, "include")) {
				egg->lang.mode = LANG_MODE_INCLUDE;
				free (egg->lang.includefile);
				egg->lang.includefile = r_str_trim_dup (str);
				// egg->lang.slurp = 0;
				// try to deal with alias
			} else if (strstr (ptr, "alias")) {
				egg->lang.mode = LANG_MODE_ALIAS;
				ptr2 = egg->lang.dstvar = r_str_trim_dup (str);
				while (*ptr2 && !is_space (*ptr2)) {
					ptr2++;
				}
				*ptr2 = '\x00';
				// for aliases must be valid and accurate strings
			} else if (strstr (ptr, "data")) {
				rcc_capture (egg, LANG_MODE_DATA, str);
			} else if (strstr (ptr, "naked")) {
				egg->lang.mode = LANG_MODE_NAKED;
				rcc_raw (egg, "%s:\n", str);
			} else if (strstr (ptr, "inline")) {
				rcc_capture (egg, LANG_MODE_INLINE, str);
			} else if (e->function) {
				e->function (egg, str, ptr);
			} else {
				if (*ptr) {
					rcc_raw (egg, "\n.%s %s\n", ptr, str);
				}
				rcc_raw (egg, "%s:\n", str);
			}
		} else {
			// e->jmp (egg, egg->lang.ctxpush[context], 0);
			if (CTX > 0) {
				// WTF?
				eprintf ("LABEL %d\n", CTX);
				rcc_raw (egg, "\n%s:\n", str);
			} else {
				if (!strcmp (str, "goto")) {
					egg->lang.mode = LANG_MODE_GOTO;
				} else {
					// call () // or maybe jmp?
					e->call (egg, str, 0);
				}
			}
		}
	}
	return true;
}

#if 0
static void shownested(void) {
	int i;
	eprintf ("[[[NESTED %d]]] ", context);
	for (i = 0; egg->lang.nested[i]; i++) {
		eprintf ("%s ", egg->lang.nested[i]);
	}
	eprintf ("\n");
}
#endif

static void set_nested(REgg *egg, const char *s) {
	int i = 0;
	if (CTX < 1) {
		return;
	}
	free (egg->lang.nested[CTX]);
	egg->lang.nested[CTX] = strdup (s);
	// egg->lang.nestedi[c]++;
	// seems not need to increase egg->lang.nestedi[c]
	/** clear inner levels **/
	for (i = 1; i < 10 && CTX + i < R_ARRAY_SIZE (egg->lang.nested); i++) {
		// egg->lang.nestedi[context+i] = 0;
		R_FREE (egg->lang.nested[CTX + i]);
	}
}

// nestedi[ctx] counts every block opened at that level, ifelse_table[ctx] only has room for the first 32
static char **ifelse_slot(REgg *egg, int ctx) {
	int col = egg->lang.nestedi[ctx] - 1;
	if (col < 0 || col >= R_ARRAY_SIZE (egg->lang.ifelse_table[ctx])) {
		R_LOG_ERROR ("%s:%d too many blocks in this scope for an if", egg->lang.file, egg->lang.line);
		return NULL;
	}
	return &egg->lang.ifelse_table[ctx][col];
}

static REggCond rcc_condition(const char *s) {
	const char *less = strchr (s, '<');
	const char *greater = strchr (s, '>');
	const char *equal = strchr (s, '=');
	const char *bang = strchr (s, '!');
	const char *op = less? less: greater? greater: equal;
	REggCond cond = { .lhs = r_strs_from (s), .rhs = R_STRS_LIT ("0"), .inclusive = equal, .negate = bang };
	if (op) {
		cond.cmp = *op;
		cond.lhs = r_strs_new (s, (!less && !greater && bang && bang < equal)? bang: op);
		cond.rhs = r_strs_from (op + 1 + (op[1] == '='));
	}
	r_strs_trim (&cond.lhs);
	r_strs_trim (&cond.rhs);
	if (!op && r_strs_at (cond.lhs, 0) == '!') {
		r_strs_advance (&cond.lhs, 1);
	}
	return cond;
}

static void rcc_context(REgg *egg, int delta) {
	REggEmit *emit = egg->remit;

	if (CTX > 31 || CTX < 0) {
		return;
	}

	if (delta > 0) {
		egg->lang.nestedi[CTX]++;
		R_FREE (egg->lang.nested_callname[CTX]);
		if (egg->lang.callname) {
			egg->lang.nested_callname[CTX] = strdup (egg->lang.callname);
		}
	}
	if (egg->lang.callname && CTX > 0) { // && delta>0) {
		// set_nested (callname);
		// eprintf (" - - - - - - -  set nested d=%d c=%d (%s)\n", delta, context-1, callname);
		// shownested ();
	}
	CTX += delta;
	egg->lang.lastctxdelta = delta;

	if (CTX == 0 && delta < 0) {
		if (egg->lang.mode != LANG_MODE_NAKED) {
			emit->frame_end (egg, egg->lang.stackframe + egg->lang.stackfixed, egg->lang.nbrackets);
		}
		if (egg->lang.mode == LANG_MODE_NORMAL) {
			egg->lang.stackframe = 0;
			egg->lang.stackfixed = 0; // reset both so the fixed area doesn't leak into the next function's frame_end
		}
		egg->lang.mode = LANG_MODE_NORMAL;
	} else {
		/* conditional block */
		// eprintf ("Callname is (%s)\n", callname);
		const char *elm = r_str_trim_head_ro (r_strbuf_get (&egg->lang.elem));
		// const char *cn = callname;
		// seems cn is useless in nowadays content
// if (egg->lang.nested[context-1])
#if 0
		if (delta < 0 && context > 0) {
			eprintf ("close bracket foo!!!\n");
			shownested ();
			cn = strdup (egg->lang.nested[context - 1]);
			eprintf ("STATEMENT cn=(%s) idx=%d (%s)\n", cn, context - 1, egg->lang.nested[context - 1]);
			eprintf ("CNTXXXPUSH (%s)\n", egg->lang.ctxpush[context - 1]);
#if 0
			if (!strcmp (cn, "while")) {
				emit->while_end (egg, get_frame_label (context - 1));
				// char *var = get_frame_label (0);
				// emit->jmp (egg, var, 0);
				return;
			}
#endif
		}
#endif
		// eprintf ("ELEM (%s)\n", elm);
		// eprintf ("END BLOCK %d, (%s)\n", context, egg->lang.nested[context-1]);
		// eprintf ("CN = (%s) %d (%s) delta=%d\n", cn, context, egg->lang.nested[context-1], delta);
		if (egg->lang.callname) {
			/* TODO: this must be an array */
			emit->comment (egg, "cond frame %s (%s)", egg->lang.callname, elm);
			if (!strcmp (egg->lang.callname, "while")) {
				char *lab = r_str_newf ("__begin_%d_%d_%d", egg->lang.nfunctions,
					CTX - 1, egg->lang.nestedi[CTX - 1] - 1);
				// the egg->lang.nestedi[CTX-1] has increased
				// so we should decrease it in label
				RStrBuf frame;
				r_strbuf_init (&frame);
				emit->get_while_end (egg, &frame, egg->lang.ctxpush[CTX - 1], lab); // get_frame_label (2));
				// get_frame_label (2));
				// eprintf ("------ (%s)\n", egg->lang.ctxpush[context-1]);
				// free (egg->lang.endframe);
				// XXX: egg->lang.endframe is deprecated, must use set_nested only
				if (delta > 0) {
					set_nested (egg, R_STRBUF_SAFEGET (&frame));
				}
				r_strbuf_fini (&frame);
				free (lab);
				rcc_set_callname (egg, "if"); // append 'if' body
			}
			if (!strcmp (egg->lang.callname, "if")) {
				// HACK HACK :D
				// nestede[CTX-1] = strdup (str);
				// where give nestede value
				char *label = r_str_newf ("__end_%d_%d_%d", egg->lang.nfunctions, CTX - 1, egg->lang.nestedi[CTX - 1] - 1);
				const REggCond cond = rcc_condition (r_str_get (egg->lang.conditionstr));
				emit->branch (egg, &cond, egg->lang.varsize, label);
				free (label);
				if (CTX > 0) {
					/* XXX .. */
				}
				rcc_reset_callname (egg);
				R_FREE (egg->lang.conditionstr);
			} // else eprintf ("Unknown statement (%s)(%s)\n", cn, elem);
		} // handle '{ ..'
	}
}

// @data and @inline bodies are collected verbatim until their closing brace
static void rcc_capture(REgg *egg, int mode, const char *name) {
	free (egg->lang.dstvar);
	egg->lang.dstvar = name? strdup (name): NULL;
	r_strbuf_free (egg->lang.capture);
	egg->lang.capture = r_strbuf_new ("");
	egg->lang.mode = mode;
}

// returns the captured text once the body closes, NULL while still capturing
static char *capture_char(REgg *egg, char c) {
	RStrBuf *sb = egg->lang.capture;
	if (c == '{') {
		rcc_context (egg, 1);
		if (++egg->lang.inlinectr == 1) {
			r_strbuf_set (sb, "");
			return NULL;
		}
	} else if (c == '}' && egg->lang.inlinectr && CTX < 2) {
		rcc_context (egg, -1);
		egg->lang.slurp = 0;
		egg->lang.mode = LANG_MODE_NORMAL;
		egg->lang.inlinectr = 0;
		egg->lang.capture = NULL;
		return r_strbuf_drain (sb);
	}
	r_strbuf_append_n (sb, &c, 1);
	return NULL;
}

static int parsedatachar(REgg *egg, char c) {
	if (!egg->lang.inlinectr && c == ')') {
		// foo@data(NNN) { ... } takes the element count from the parenthesis
		egg->lang.stackframe = atoi (r_strbuf_get (egg->lang.capture));
		r_strbuf_set (egg->lang.capture, "");
		return 0;
	}
	if (!egg->lang.inlinectr && c != '{') {
		r_strbuf_append_n (egg->lang.capture, &c, 1);
		return 0;
	}
	char *value = capture_char (egg, c);
	if (!value) {
		return 0;
	}
	egg->remit->comment (egg, "data (%s)(%s)size=(%d)\n", egg->lang.dstvar, value, egg->lang.stackframe);
	const int count = R_MAX (egg->lang.stackframe, 1);
	const bool ascii = *r_str_trim_head_ro (value) == '"';
	rcc_raw (egg, ".data\n%s:\n", egg->lang.dstvar);
	int i;
	for (i = 1; i <= count; i++) {
		if (ascii) {
			rcc_raw (egg, ".ascii %s%s\n", value, (i == count)? "\"\\x00\"": "");
		} else {
			rcc_raw (egg, ".long %s\n", value);
		}
	}
	rcc_raw (egg, ".text\n");
	R_FREE (egg->lang.dstvar);
	free (value);
	CTX = 0;
	return 1;
}

static int parseinlinechar(REgg *egg, char c) {
	if (!egg->lang.inlinectr && c != '{') {
		return 0;
	}
	char *body = capture_char (egg, c);
	if (!body) {
		return 0;
	}
	if (!egg->lang.dstvar) {
		free (egg->lang.syscallbody);
		egg->lang.syscallbody = body;
		return 1;
	}
	if (egg->lang.ninlines >= R_ARRAY_SIZE (egg->lang.inlines)) {
		R_LOG_ERROR ("Too many inline functions");
		R_FREE (egg->lang.dstvar);
		free (body);
		return -1;
	}
	r_str_trim_head (body);
	egg->lang.inlines[egg->lang.ninlines].name = egg->lang.dstvar;
	egg->lang.inlines[egg->lang.ninlines].body = body;
	egg->lang.ninlines++;
	egg->lang.dstvar = NULL;
	return 1;
}

static int rcc_parse(REgg *egg, const char *s) {
	for (; *s; s++) {
		if (r_egg_lang_parsechar (egg, *s) < 0) {
			return -1;
		}
	}
	return 0;
}

static int rcc_target_matches(REgg *egg, RStrs expression) {
	const struct {
		const char *name;
		bool enabled;
	} targets[] = {
		{ "LLVM", !strcmp (egg->remit->arch, "llvm") },
		{ "DARWIN", egg->os == R_EGG_OS_DARWIN || egg->os == R_EGG_OS_OSX || egg->os == R_EGG_OS_MACOS },
		{ "LINUX", egg->os == R_EGG_OS_LINUX },
		{ "ARM64", egg->arch == R_SYS_ARCH_ARM && egg->bits == 64 },
		{ "X86_64", egg->arch == R_SYS_ARCH_X86 && egg->bits == 64 },
	};
	bool matches = true;
	bool more;
	do {
		RStrs target;
		more = r_strs_split_strs (expression, R_STRS_LIT ("&&"), &target, &expression);
		r_strs_trim (&target);
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (targets); i++) {
			if (r_strs_equals_str (target, targets[i].name)) {
				matches &= targets[i].enabled;
				break;
			}
		}
		if (i == R_ARRAY_SIZE (targets)) {
			rcc_error (egg, "expected an RCC target in preprocessor condition", NULL);
			return -1;
		}
	} while (more);
	return matches;
}

typedef struct {
	bool parent_active;
	bool matched;
	bool seen_else;
} RCCConditional;

R_IPI bool r_egg_lang_parse_source(REgg *egg, const char *source) {
	RCCConditional frames[32];
	int depth = 0;
	bool active = true;
	while (*source) {
		const char *end = strchr (source, '\n');
		if (!end) {
			end = source + strlen (source);
		}
		RStrs line = r_strs_new (source, end);
		r_strs_trim (&line);
		bool directive = false;
		if (r_strs_at (line, 0) == '#' && !egg->lang.commentmode && !egg->lang.slurp
				&& egg->lang.mode != LANG_MODE_INLINE && egg->lang.mode != LANG_MODE_DATA) {
			r_strs_advance (&line, 1);
			RStrs keyword;
			r_strs_next_token (&line, " \t", &keyword);
			r_strs_trim (&line);
			bool opens = r_strs_equals_str (keyword, "if");
			bool alternate = r_strs_equals_str (keyword, "elif");
			bool otherwise = r_strs_equals_str (keyword, "else");
			bool closes = r_strs_equals_str (keyword, "endif");
			bool error = r_strs_equals_str (keyword, "error");
			directive = opens || alternate || otherwise || closes || error;
			if ((opens && depth == R_ARRAY_SIZE (frames))
					|| ((alternate || otherwise || closes) && !depth)
					|| ((alternate || otherwise) && frames[depth - 1].seen_else)
					|| ((otherwise || closes) && !r_strs_empty (line))) {
				rcc_error (egg, "invalid preprocessor conditional", NULL);
				return false;
			}
			if (opens) {
				frames[depth++] = (RCCConditional) { .parent_active = active };
			}
			if (opens || alternate || otherwise) {
				int matches = otherwise? 1: rcc_target_matches (egg, line);
				if (matches < 0) {
					return false;
				}
				RCCConditional *frame = &frames[depth - 1];
				active = frame->parent_active && !frame->matched && matches;
				frame->matched |= matches;
				frame->seen_else = otherwise;
			} else if (closes) {
				active = frames[--depth].parent_active;
			} else if (error && active) {
				R_LOG_ERROR ("%s:%d: %.*s", egg->lang.file, egg->lang.line,
					(int)R_MIN (r_strs_len (line), INT_MAX), line.a);
				return false;
			}
		}
		if (active && !directive) {
			for (; source < end; source++) {
				if (r_egg_lang_parsechar (egg, *source) < 0) {
					return false;
				}
			}
		}
		source = end;
		if (*source && r_egg_lang_parsechar (egg, *source++) < 0) {
			return false;
		}
	}
	if (depth) {
		rcc_error (egg, "unterminated preprocessor conditional", NULL);
		return false;
	}
	return !egg->lang.quoteline || r_egg_lang_parsechar (egg, '\n') >= 0;
}

/* TODO: split this function into several ones..quite long fun */
static int rcc_statement(REgg *egg, char *elem) {
	const char *ocn;
	REggEmit *e = egg->remit;
	char *str = NULL, *p, *ptr;
	int i, ret = 0;

	if (egg->lang.setenviron) {
		// drop the closing parenthesis of `name@env(value)`
		elem[R_MAX (strlen (elem), 1) - 1] = 0;
		r_sys_setenv (egg->lang.setenviron, elem);
		R_FREE (egg->lang.setenviron);
		return 0;
	}
	if (egg->lang.includefile) {
		char *path = find_include (egg, egg->lang.includedir, egg->lang.includefile);
		char *source = path? r_file_slurp (path, NULL): NULL;
		if (!source) {
			R_LOG_ERROR ("Cannot load include file '%s'", path? path: egg->lang.includefile);
			free (path);
			return -1;
		}
		R_FREE (egg->lang.includefile);
		R_FREE (egg->lang.includedir);
		rcc_reset_callname (egg);
		egg->lang.mode = LANG_MODE_NORMAL;
		char *previous_file = egg->lang.file;
		int previous_line = egg->lang.line;
		egg->lang.file = path;
		egg->lang.line = 1;
		egg->lang.oc = '\n';
		ret = r_egg_lang_parse_source (egg, source)? 0: -1;
		egg->lang.file = previous_file;
		egg->lang.line = previous_line;
		free (source);
		free (path);
		return ret;
	}
	egg->lang.docall = 1;
	if (egg->lang.callname) {
		if (!strcmp (egg->lang.callname, "goto")) {
			if (egg->lang.nargs != 1) {
				R_LOG_ERROR ("Invalid number of arguments for goto()");
				return 0;
			}
			e->jmp (egg, egg->lang.ctxpush[CTX], 0);
			rcc_reset_callname (egg);
			return 0;
		}
		if (!strcmp (egg->lang.callname, "break")) {
			e->trap (egg);
			rcc_reset_callname (egg);
			return 0;
		}
		ptr = strchr (egg->lang.callname, '=');
		if (ptr) {
			*ptr = '\0';
			// ocn = ptr+1; // what is the point of this?
		}
		ocn = r_str_trim_head_ro (egg->lang.callname);
		if (!ocn) {
			return 0;
		}
		str = r_egg_mkvar (egg, r_strs_from (ocn), 0);
		if (!str) {
			R_LOG_ERROR ("Cannot mkvar");
			return 0;
		}
		if (*ocn == '.') {
			e->call (egg, str, 1);
			egg->lang.docall = 0;
		}
		if (!strcmp (str, "while")) {
			if (egg->lang.lastctxdelta >= 0) {
				R_LOG_ERROR ("Unsupported while syntax");
				free (str);
				return 0;
			}
			char *var = r_str_newf ("__begin_%d_%d_%d\n", egg->lang.nfunctions, CTX, egg->lang.nestedi[CTX - 1]);
			e->while_end (egg, var); // get_frame_label (1));
			free (var);
#if 0
			eprintf ("------------------------------------------ lastctx: %d\n", egg->lang.lastctxdelta);
			// TODO: the pushvar is required for the if () {} while (); constructions
			// char *pushvar = egg->lang.ctxpush[context+egg->lang.nbrackets-1];
			/* TODO: support to compare more than one expression (LOGICAL OR) */
			rcc_printf ("  pop %%eax\n");
			rcc_printf ("  cmp $0, %%eax\n");	// XXX MUST SUPPORT != 0 COMPARE HERE
			/* TODO : Simplify!! */
			// if (pushvar)
			// printf ("  push %s /* while push */\n", pushvar);
			if (egg->lang.lastctxdelta < 0) {
				rcc_printf ("  jnz %s\n", get_frame_label (1));
			} else {
				rcc_printf ("  jnz %s\n", get_frame_label (0));
			}
			// if (pushvar)
			// printf ("  pop %%"R_AX" /* while pop */\n");
#endif
			egg->lang.nargs = 0;
		} else {
			for (i = 0; i < egg->lang.nsyscalls; i++) {
				const char *name = egg->lang.syscalls[i].name;
				if (name && !strcmp (str, name)) {
					p = egg->lang.syscallbody;
					e->comment (egg, "set syscall args");
					e->syscall_args (egg, egg->lang.nargs);
					egg->lang.docall = 0;
					e->comment (egg, "syscall");
					r_egg_lang_parsechar (egg, '\n'); /* FIX parsing issue */
					if (p) {
						ret = rcc_parse (egg, p);
					} else {
						char *s = e->syscall (egg, egg->lang.nargs);
						if (s) {
							ret = rcc_parse (egg, s);
							free (s);
						} else {
							R_LOG_ERROR ("Cannot get @syscall payload");
							ret = -1;
						}
					}
					if (ret < 0) {
						goto beach;
					}
					egg->lang.docall = 0;
					break;
				}
			}
			if (egg->lang.docall) {
				for (i = 0; i < egg->lang.ninlines; i++) {
					if (!strcmp (str, egg->lang.inlines[i].name)) {
						char *body = egg->lang.inlines[i].body;
						egg->lang.docall = 0;
						if (!body) {
							R_LOG_ERROR ("Recursive expansion of inline '%s'", str);
							break;
						}
						// take the body out while expanding it, so an inline cannot call itself forever
						egg->lang.inlines[i].body = NULL;
						rcc_reset_callname (egg);
						e->comment (egg, "inline");
						r_egg_lang_parsechar (egg, '\n'); /* FIX parsing issue */
						ret = rcc_parse (egg, body);
						egg->lang.inlines[i].body = body;
						if (ret < 0) {
							goto beach;
						}
						egg->lang.docall = 0;
						break;
					}
				}
			}
			if (egg->lang.docall) {
				e->comment (egg, "call in egg->lang.mode %d", egg->lang.mode);
				e->call (egg, str, 0);
			}
		}
		if (egg->lang.nargs > 0) {
			e->restore_stack (egg, egg->lang.nargs * e->size);
		}

		/* store result of call */
		if (egg->lang.dstvar) {
			// if (egg->lang.mode != LANG_MODE_NAKED) {
			free (str);
			str = r_egg_mkvar (egg, r_strs_from (egg->lang.dstvar), 0);
			if (R_STR_ISEMPTY (str)) {
				R_LOG_ERROR ("Cannot resolve variable '%s'", egg->lang.dstvar);
			} else {
				e->get_result (egg, str);
			}
			//}
			R_FREE (egg->lang.dstvar);
		}
		rcc_reset_callname (egg);
	} else { // handle mathop
		int vs = 'l';
		char type, *eq, *tmp;
		char compound_op = 0; // 0 = plain '=', otherwise +,-,*,/,|,&,^
		char *ptr = (char *)r_str_trim_head_ro (elem);
		if (*ptr) {
			eq = strchr (ptr, '=');
			if (eq && eq > ptr) {
				/* detect compound operators: +=, -=, *=, /=, |=, &=, ^= */
				char prev = eq[-1];
				if (prev == '+' || prev == '-' || prev == '*' || prev == '/'
				    || prev == '|' || prev == '&' || prev == '^') {
					compound_op = prev;
					eq[-1] = '\x00'; /* chop the operator off the LHS */
				}
			}
			if (eq) {
				vs = egg->lang.varsize;
				*eq = '\x00';
				e->mathop (egg, '=', vs, '$', "0", e->regs (egg, 1));
				// avoid situation that egg->lang.mathline starts with a single '-'
				egg->lang.mathline = r_str_trim_dup (eq + 1);
				tmp = egg->lang.mathline;
				if (R_STR_ISEMPTY (tmp)) {
					R_FREE (egg->lang.mathline);
					rcc_error (egg, "expected an expression after '='", NULL);
					return -1;
				}
				rcc_mathop (egg, &tmp, 2);
				R_FREE (egg->lang.mathline);
				tmp = NULL;
				// following code block is too ugly, oh noes
				char *p = r_egg_mkvar (egg, r_strs_from (ptr), 0);
				if (is_var (p)) {
					char *q = r_egg_mkvar (egg, r_strs_from (p), 0);
					if (q) {
						free (p);
						p = q;
					}
					if (egg->lang.varxs == '*' || egg->lang.varxs == '&') {
						R_LOG_ERROR ("not support for *ptr in egg->lang.dstvar");
					}
					// XXX: Not support for pointer
					type = ' ';
				} else {
					type = '$';
				}
				if (compound_op) {
					/* emit: p <compound_op>= tmpreg */
					e->mathop (egg, compound_op, vs, type, e->regs (egg, 1), p);
				} else {
					e->mathop (egg, '=', vs, type, e->regs (egg, 1), p);
				}
				free (p);
			} else {
				if (!strcmp (ptr, "break")) { // handle 'break;'
					e->trap (egg);
					rcc_reset_callname (egg);
				} else if (tmp = ptr, get_op (&tmp)) {
					e->mathop (egg, '=', vs, '$', "0", e->regs (egg, 1));
					rcc_mathop (egg, &ptr, 2);
					e->mathop (egg, '=', vs, ' ', e->regs (egg, 1), NULL);
				} else {
					char *value = r_egg_mkvar (egg, r_strs_from (ptr), 0);
					e->mathop (egg, '=', vs, is_var (ptr)? ' ': '$', r_str_get (value), NULL);
					free (value);
				}
			}
		}
	}
beach:
	free (str);
	/* expanded inlines and includes may leave text behind */
	r_strbuf_set (&egg->lang.elem, "");
	return ret;
}

static int rcc_next(REgg *egg) {
	char *elem = r_strbuf_drain_nofree (&egg->lang.elem);
	const int ret = rcc_statement (egg, elem);
	free (elem);
	return ret;
}

static void rcc_element_append(REgg *egg, char c) {
	r_strbuf_append_n (&egg->lang.elem, &c, 1);
}

// `: line` passes raw assembly through, expanding `.var` references between backticks
static void rcc_asm_line(REgg *egg) {
	RStrBuf *sb = r_strbuf_new ("");
	RStrs line = r_strs_from (r_strbuf_get (&egg->lang.elem)), head, var;
	for (;;) {
		const bool tick = r_strs_split (line, '`', &head, &line);
		r_strbuf_append_n (sb, head.a, r_strs_len (head));
		if (!tick) {
			break;
		}
		r_strs_split (line, '`', &var, &line);
		char *value = r_egg_mkvar (egg, var, 0);
		r_strbuf_append (sb, r_str_get (value));
		free (value);
	}
	rcc_raw (egg, "%s\n", r_strbuf_get (sb));
	r_strbuf_free (sb);
	egg->lang.quoteline = 0;
}

R_API int r_egg_lang_parsechar(REgg *egg, char c) {
	REggEmit *e = egg->remit;
	if (egg->lang.quoteline) {
		if (c != '\n') {
			rcc_element_append (egg, c);
			return 0;
		}
		rcc_asm_line (egg);
	}
	char *tmp_ptr = NULL;
	int i, j;
	if (c == '\n') {
		egg->lang.line++;
		r_strbuf_set (&egg->lang.elem, "");
	}
	/* comments */
	if (egg->lang.skipline) {
		if (c != '\n') {
			egg->lang.oc = c;
			return 0;
		}
		egg->lang.skipline = 0;
	}
	if (egg->lang.mode == LANG_MODE_DATA) {
		return parsedatachar (egg, c);
	}
	if (egg->lang.mode == LANG_MODE_INLINE) {
		return parseinlinechar (egg, c);
	}
	if (egg->lang.mode == LANG_MODE_FASTCALL && CTX == 0) {
		switch (c) {
		case ';':
		case '\n':
			rcc_fastcall (egg, false);
			if (c != '\t' && c != ' ') {
				egg->lang.oc = c;
			}
			return 0;
		case '{':
			rcc_fastcall (egg, true);
			if (c != '\t' && c != ' ') {
				egg->lang.oc = c;
			}
			return 0;
		}
	}
	if (egg->lang.commentmode) {
		if (c == '/' && egg->lang.oc == '*') {
			egg->lang.commentmode = 0;
		}
		egg->lang.oc = c;
		return 0;
	} else if (c == '*' && egg->lang.oc == '/') {
		egg->lang.commentmode = 1;
	}
	if (egg->lang.slurp) {
		const char *elem = r_strbuf_get (&egg->lang.elem);
		const bool escaped = is_escaped (elem, elem + r_strbuf_length (&egg->lang.elem));
		if (egg->lang.slurp == ')' && (c == '"' || c == '\'') && !escaped) {
			if (egg->lang.slurpin == '(' || egg->lang.slurpin == c) {
				egg->lang.slurpin = egg->lang.slurpin == '('? c: '(';
			}
		}
		const bool in_arg_string = egg->lang.slurp == ')' && egg->lang.slurpin != '(';
		if (egg->lang.slurp != '"' && c == egg->lang.slurpin && !in_arg_string) { // only happend when (... (...)...)
			R_LOG_ERROR ("%s:%d Nesting of expressions not yet supported",
				egg->lang.file, egg->lang.line);
			return -1;
		}
		if (c == egg->lang.slurp && !escaped && !in_arg_string) { // close egg->lang.slurp
			char *element = r_strbuf_drain_nofree (&egg->lang.elem);
			if (*element) {
				rcc_element (egg, element);
			} else if (CTX == 0 && egg->lang.mode != LANG_MODE_FASTCALL) {
				e->frame (egg, 0);
			}
			free (element);
			egg->lang.slurp = 0;
		} else {
			rcc_element_append (egg, c);
		}
	} else {
		switch (c) {
		case ';':
			if (rcc_next (egg) < 0) {
				return -1;
			}
			break;
		case '"':
			egg->lang.slurp = '"';
			break;
		case '(':
			egg->lang.slurpin = '(';
			egg->lang.slurp = ')';
			break;
		case '{':
			if (CTX < 0 || CTX >= R_ARRAY_SIZE (egg->lang.nested) - 1) {
				rcc_error (egg, "too many nested blocks", NULL);
				return -1;
			}
			if (CTX > 0) {
				// r_egg_printf (egg, " %s:\n", get_frame_label (0));
				if (egg->lang.nested_callname[CTX] && strstr (egg->lang.nested_callname[CTX], "if") &&
					strstr (r_strbuf_get (&egg->lang.elem), "else")) {
					r_strbuf_set (&egg->lang.elem, "");
					char **slot = ifelse_slot (egg, CTX);
					if (slot) {
						free (*slot);
						*slot = r_str_newf ("  __end_%d_%d_%d",
							egg->lang.nfunctions, CTX, egg->lang.nestedi[CTX]);
					}
				}
					tmp_ptr = r_str_newf ("__begin_%d_%d_%d",
						egg->lang.nfunctions, CTX, egg->lang.nestedi[CTX]);
					emit_label (egg, tmp_ptr);
					R_FREE (tmp_ptr);
			}
			rcc_context (egg, 1);
			break;
		case '}':
			if (CTX <= 0) {
				rcc_error (egg, "unexpected closing brace", NULL);
				return -1;
			}
			if (egg->lang.nested[CTX]) {
				rcc_raw (egg, "%s", egg->lang.nested[CTX]);
				R_FREE (egg->lang.nested[CTX]);
			}
			if (CTX > 1) {
				if (egg->lang.nested_callname[CTX - 1] && strstr (egg->lang.nested_callname[CTX - 1], "if")) {
					tmp_ptr = r_str_newf ("__ifelse_%d_%d", CTX - 1, egg->lang.nestedi[CTX - 1] - 1);
					e->jmp (egg, tmp_ptr, 0);
					R_FREE (tmp_ptr);
					char **slot = ifelse_slot (egg, CTX - 1);
					if (!slot) {
						return -1;
					}
					if (!*slot) {
						*slot = r_str_newf ("__end_%d_%d_%d",
							egg->lang.nfunctions, CTX - 1, egg->lang.nestedi[CTX - 1] - 1);
					}
				}
				tmp_ptr = r_str_newf ("__end_%d_%d_%d",
					egg->lang.nfunctions, CTX - 1, egg->lang.nestedi[CTX - 1] - 1);
				emit_label (egg, tmp_ptr);
				R_FREE (tmp_ptr);
			}
			if (CTX > 0) {
				egg->lang.nbrackets++;
			}
			rcc_context (egg, -1);
			if (CTX == 0) {
				rcc_raw (egg, "\n");
				// edit this unnessary jmp to bypass tests
				for (i = 0; i < 32; i++) {
					for (j = 0; j < egg->lang.nestedi[i] && j < 32; j++) {
						if (egg->lang.ifelse_table[i][j]) {
							tmp_ptr = r_str_newf ("__ifelse_%d_%d", i, j);
							emit_label (egg, tmp_ptr);
							R_FREE (tmp_ptr);
							e->jmp (egg, egg->lang.ifelse_table[i][j], 0);
							R_FREE (egg->lang.ifelse_table[i][j]);
						}
					}
				}
				// r_egg_printf (egg, "  __end_%d:\n\n", egg->lang.nfunctions);
				// edit this unnessary jmp to bypass tests
				egg->lang.nbrackets = 0;
				egg->lang.nfunctions++;
				memset (egg->lang.nestedi, 0, sizeof (egg->lang.nestedi));
			}
			break;
		case ':':
			if (egg->lang.oc == '\n' || egg->lang.oc == '}') {
				r_strbuf_set (&egg->lang.elem, "");
				egg->lang.quoteline = '\n';
			} else {
				rcc_element_append (egg, c);
			}
			break;
		case '#':
			if (egg->lang.oc == '\n') {
				egg->lang.skipline = 1;
			}
			break;
		case '/':
			if (egg->lang.oc == '/') {
				egg->lang.skipline = 1;
			} else {
				rcc_element_append (egg, c);
			}
			break;
		default:
			rcc_element_append (egg, c);
		}
		if (egg->lang.slurp) {
			char *element = r_strbuf_drain_nofree (&egg->lang.elem);
			bool ok = !*element || rcc_fun (egg, (char *)r_str_trim_head_ro (element));
			free (element);
			if (!ok) {
				return -1;
			}
		}
	}
	if (c != '\t' && c != ' ') {
		egg->lang.oc = c;
	}
	return 0;
}

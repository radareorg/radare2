/* Basic C Preprocessor implementation using KVCToken and r_strbuf */

#define PP_DEFAULT_CAP 16
#define PP_MAX_IF_NEST 64
#define PP_DEFAULT_RECURSION_LIMIT 16

typedef struct {
	char **keys;
	char **values;
	size_t count, cap;
	bool if_skip[PP_MAX_IF_NEST];
	size_t if_count;
	size_t rec_depth;
	size_t rec_limit;
} PPState;

R_API char *pp_preprocess(PPState *st, const char *source);

// Allocate a new PPState object
R_API PPState *pp_new(void) {
	PPState *st = R_NEW0 (PPState);
	st->keys = NULL;
	st->values = NULL;
	st->count = st->cap = 0;
	st->if_count = 0;
	memset (st->if_skip, 0, sizeof (st->if_skip));
	st->rec_depth = 0;
	st->rec_limit = PP_DEFAULT_RECURSION_LIMIT;
	return st;
}

static void pp_clear_defines(PPState *st) {
	size_t i;
	for (i = 0; i < st->count; i++) {
		free (st->keys[i]);
		free (st->values[i]);
	}
	free (st->keys);
	free (st->values);
	st->keys = NULL;
	st->values = NULL;
	st->count = st->cap = 0;
}

// Initialize or reset an existing PPState object (clears defines and conditional state)
R_API void pp_init(PPState *st) {
	if (!st) {
		return;
	}
	pp_clear_defines (st);
	st->if_count = 0;
	memset (st->if_skip, 0, sizeof (st->if_skip));
	st->rec_depth = 0;
}

// Finalize a PPState object (clears defines)
R_API void pp_fini(PPState *st) {
	pp_clear_defines (st);
}

// Free a PPState object and its resources
R_API void pp_free(PPState *st) {
	if (!st) {
		return;
	}
	pp_fini (st);
	free (st);
}

R_API void pp_set_define(PPState *st, const char *name, const char *value) {
	size_t i;
	for (i = 0; i < st->count; i++) {
		if (!strcmp (st->keys[i], name)) {
			free (st->values[i]);
			st->values[i] = strdup (value);
			return;
		}
	}
	if (st->count == st->cap) {
		size_t newcap = st->cap? st->cap * 2: PP_DEFAULT_CAP;
		st->keys = realloc (st->keys, newcap * sizeof (char *));
		st->values = realloc (st->values, newcap * sizeof (char *));
		st->cap = newcap;
	}
	st->keys[st->count] = strdup (name);
	st->values[st->count] = strdup (value);
	st->count++;
}

R_API const char *pp_get_define(PPState *st, const char *name) {
	size_t i;
	for (i = 0; i < st->count; i++) {
		if (!strcmp (st->keys[i], name)) {
			return st->values[i];
		}
	}
	return NULL;
}

static inline bool is_identifier_char(char c) {
	return isalnum ((unsigned char)c) || c == '_';
}

static void skip_whitespace(const char **p, const char *end) {
	while (*p < end && isspace ((unsigned char)**p)) {
		(*p)++;
	}
}

static char *parse_identifier(const char **p, const char *end) {
	skip_whitespace (p, end);
	const char *start = *p;
	while (*p < end && is_identifier_char (**p)) {
		(*p)++;
	}
	size_t len = *p - start;
	return len? r_str_ndup (start, len): NULL;
}

static char *parse_to_end(const char *p, const char *end) {
	skip_whitespace (&p, end);
	size_t len = end - p;
	return r_str_ndup (p, len);
}

static bool pp_eval_defined(PPState *st, const char *p, const char **endptr) {
	p = r_str_trim_head_ro (p);
	if (*p != '(') {
		if (endptr) {
			*endptr = p;
		}
		return false;
	}
	p++;
	p = r_str_trim_head_ro (p);
	const char *name_start = p;
	while (is_identifier_char (*p)) {
		p++;
	}
	size_t name_len = p - name_start;
	char *name = r_str_ndup (name_start, name_len);
	p = r_str_trim_head_ro (p);
	if (*p == ')') {
		p++;
	}
	if (endptr) {
		*endptr = p;
	}
	bool def = pp_get_define (st, name) != NULL;
	free (name);
	return def;
}

static void pp_handle_define(PPState *st, const char *q, const char *line_end) {
	char *name = parse_identifier (&q, line_end);
	if (!name) {
		return;
	}
	char *value = r_str_trim_ndup (q, line_end - q);
	pp_set_define (st, name, value);
	free (name);
	free (value);
}

static void pp_handle_undef(PPState *st, const char *q, const char *line_end) {
	char *name = parse_identifier (&q, line_end);
	if (!name) {
		return;
	}
	size_t i;
	for (i = 0; i < st->count; i++) {
		if (!strcmp (st->keys[i], name)) {
			free (st->keys[i]);
			free (st->values[i]);
			memmove (&st->keys[i], &st->keys[i + 1], (st->count - i - 1) * sizeof (char *));
			memmove (&st->values[i], &st->values[i + 1], (st->count - i - 1) * sizeof (char *));
			st->count--;
			break;
		}
	}
	free (name);
}

static void pp_handle_ifdef(PPState *st, const char *q, const char *line_end, bool is_ifdef) {
	char *name = parse_identifier (&q, line_end);
	if (!name) {
		return;
	}
	bool defined = pp_get_define (st, name) != NULL;
	free (name);
	bool cond = is_ifdef? defined: !defined;
	bool outer = st->if_count? st->if_skip[st->if_count - 1]: false;
	bool new_skip = outer || !cond;
	if (st->if_count < PP_MAX_IF_NEST) {
		st->if_skip[st->if_count++] = new_skip;
	}
}

static void pp_handle_if(PPState *st, const char *q, const char *line_end) {
	skip_whitespace (&q, line_end);
	bool cond = false;
	if (r_str_startswith (q, "defined")) {
		const char *end;
		cond = pp_eval_defined (st, q, &end);
		q = end;
	}
	bool outer = st->if_count? st->if_skip[st->if_count - 1]: false;
	bool new_skip = outer || !cond;
	if (st->if_count < PP_MAX_IF_NEST) {
		st->if_skip[st->if_count++] = new_skip;
	}
}

static void pp_handle_elif(PPState *st, const char *q, const char *line_end) {
	if (!st->if_count) {
		return;
	}
	bool outer = st->if_count > 1? st->if_skip[st->if_count - 2]: false;
	skip_whitespace (&q, line_end);
	bool cond = false;
	if (r_str_startswith (q, "defined")) {
		const char *end;
		cond = pp_eval_defined (st, q, &end);
		q = end;
	}
	bool new_skip = outer || !cond;
	st->if_skip[st->if_count - 1] = new_skip;
}

static void pp_handle_else(PPState *st) {
	if (!st->if_count) {
		return;
	}
	bool outer = st->if_count > 1? st->if_skip[st->if_count - 2]: false;
	bool prev = st->if_skip[st->if_count - 1];
	bool new_skip = outer || (!prev && !outer);
	st->if_skip[st->if_count - 1] = new_skip;
}

static void pp_handle_endif(PPState *st) {
	if (st->if_count) {
		st->if_count--;
	}
}

static void pp_handle_warning(PPState *st, const char *q, const char *line_end) {
	char *s = parse_to_end (q, line_end);
	R_LOG_WARN ("cpp: %s", s);
	free (s);
}

static void pp_handle_error(PPState *st, const char *q, const char *line_end) {
	char *s = parse_to_end (q, line_end);
	R_LOG_ERROR ("cpp: %s", s);
	free (s);
}

static char *pp_handle_include(PPState *st, const char *q, const char *line_end) {
	skip_whitespace (&q, line_end);
	char delim = *q;
	if (delim != '"' && delim != '<') {
		return NULL;
	}
	q++;
	const char *fn_start = q;
	char end_delim = delim == '"'? '"': '>';
	while (q < line_end && *q != end_delim) {
		q++;
	}
	size_t fn_len = q - fn_start;
	char *filename = r_str_ndup (fn_start, fn_len);
	char *fcontent = r_file_slurp (filename, NULL);
	free (filename);
	if (!fcontent) {
		return NULL;
	}
	char *inc_pp = pp_preprocess (st, fcontent);
	free (fcontent);
	return inc_pp;
}

static bool pp_handle_directive(PPState *st, RStrBuf *out, const char *dir, const char *q, const char *line_end, bool skip) {
	if (!strcmp (dir, "define") && !skip) {
		pp_handle_define (st, q, line_end);
	} else if (!strcmp (dir, "undef") && !skip) {
		pp_handle_undef (st, q, line_end);
	} else if (!strcmp (dir, "ifdef") || !strcmp (dir, "ifndef")) {
		pp_handle_ifdef (st, q, line_end, !strcmp (dir, "ifdef"));
	} else if (!strcmp (dir, "if")) {
		pp_handle_if (st, q, line_end);
	} else if (!strcmp (dir, "elif")) {
		pp_handle_elif (st, q, line_end);
	} else if (!strcmp (dir, "else")) {
		pp_handle_else (st);
	} else if (!strcmp (dir, "endif")) {
		pp_handle_endif (st);
	} else if (!strcmp (dir, "warning") && !skip) {
		pp_handle_warning (st, q, line_end);
	} else if (!strcmp (dir, "error") && !skip) {
		pp_handle_error (st, q, line_end);
		return false;
	} else if (!strcmp (dir, "include") && !skip) {
		char *inc = pp_handle_include (st, q, line_end);
		if (inc) {
			r_strbuf_append (out, inc);
			free (inc);
		}
	}
	return true;
}

static void pp_process_line(PPState *st, RStrBuf *out, const char *line_start, const char *line_end) {
	const char *rptr = line_start;
	while (rptr < line_end) {
		if (is_identifier_char (*rptr)) {
			const char *id_start = rptr;
			while (rptr < line_end && is_identifier_char (*rptr)) {
				rptr++;
			}
			KVCToken tok = { id_start, rptr };
			char *name = kvctoken_tostring (tok);
			const char *val = pp_get_define (st, name);
			if (val) {
				r_strbuf_append (out, val);
			} else {
				r_strbuf_append_n (out, tok.a, kvctoken_len (tok));
			}
			free (name);
		} else {
			r_strbuf_append_n (out, rptr, 1);
			rptr++;
		}
	}
}

R_API char *pp_preprocess(PPState *st, const char *source) {
	if (!st || !source) {
		return NULL;
	}
	if (st->rec_depth >= st->rec_limit) {
		return strdup ("");
	}
	st->rec_depth++;
	memset (st->if_skip, 0, sizeof (st->if_skip));
	st->if_count = 0;
	RStrBuf *out = r_strbuf_new ("");
	const char *p = source;
	const char *end = source + strlen (source);
	while (p < end) {
		const char *line_start = p;
		const char *newline = memchr (p, '\n', end - p);
		const char *line_end = newline? newline: end;
		const char *q = line_start;
		while (q < line_end && (*q == ' ' || *q == '\t')) {
			q++;
		}
		bool skip = st->if_count? st->if_skip[st->if_count - 1]: false;
		if (q < line_end && *q == '#') {
			q++;
			skip_whitespace (&q, line_end);
			const char *dir_start = q;
			while (q < line_end && isalpha ((unsigned char)*q)) {
				q++;
			}
			size_t dir_len = q - dir_start;
			char *dir = r_str_ndup (dir_start, dir_len);
			if (!pp_handle_directive (st, out, dir, q, line_end, skip)) {
				free (dir);
				goto failure;
			}
			free (dir);
			if (newline) {
				r_strbuf_append (out, "\n");
			}
		} else {
			if (!skip) {
				pp_process_line (st, out, line_start, line_end);
			}
			if (newline) {
				r_strbuf_append (out, "\n");
			}
		}
		p = line_end + (newline? 1: 0);
	}
	char *result = r_strbuf_drain (out);
	st->rec_depth--;
	return result;
failure:
	r_strbuf_free (out);
	return NULL;
}

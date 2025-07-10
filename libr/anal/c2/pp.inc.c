/* Basic C Preprocessor implementation using KVCToken and r_strbuf */

enum { PP_DEFAULT_CAP = 16, PP_MAX_IF_NEST = 64, PP_DEFAULT_RECURSION_LIMIT = 16 };

typedef struct {
	char **keys;
	char **values;
	size_t count, cap;
	bool if_skip[PP_MAX_IF_NEST];
	size_t if_count;
	size_t rec_depth;
	size_t rec_limit;
} PPState;
// Forward declaration for clear function
static void pp_clear_defines(PPState *st);

// Removed global state to allow multiple independent PPState instances

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

R_API void pp_set_define(PPState *st, const char *name, const char *value) {
	size_t i;
	for (i = 0; i < st->count; i++) {
		if (!strcmp (st->keys[i], name)) {
			free (st->values[i]);
			st->values[i] = strdup(value);
			return;
		}
	}
	if (st->count == st->cap) {
		size_t newcap = st->cap ? st->cap * 2 : PP_DEFAULT_CAP;
		st->keys = realloc (st->keys, newcap * sizeof (char*));
		st->values = realloc (st->values, newcap * sizeof (char*));
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

static bool pp_eval_defined(PPState *st, const char *p, const char **endptr) {
	while (isspace ((unsigned char)*p)) { p++; }
	if (*p != '(') {
		if (endptr) { *endptr = p; }
		return false;
	}
	p++;
	while (isspace ((unsigned char)*p)) { p++; }
	const char *name_start = p;
	while (is_identifier_char (*p)) { p++; }
	size_t name_len = p - name_start;
	char *name = r_str_ndup (name_start, name_len);
	while (isspace ((unsigned char)*p)) { p++; }
	if (*p == ')') { p++; }
	if (endptr) { *endptr = p; }
	bool def = pp_get_define(st, name) != NULL;
	free (name);
	return def;
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
	RStrBuf *out = r_strbuf_new("");
	const char *p = source;
	const char *end = source + strlen(source);
	while (p < end) {
		const char *line_start = p;
		const char *newline = memchr (p, '\n', end - p);
		const char *line_end = newline ? newline : end;
		const char *q = line_start;
		while (q < line_end && (*q == ' ' || *q == '\t')) { q++; }
		bool skip = st->if_count ? st->if_skip[st->if_count-1] : false;
		if (q < line_end && *q == '#') {
			q++;
			while (q < line_end && isspace ((unsigned char)*q)) { q++; }
			const char *dir_start = q;
			while (q < line_end && isalpha((unsigned char)*q)) { q++; }
			size_t dir_len = q - dir_start;
			char dir[16] = {0};
			if (dir_len < sizeof (dir)) { memcpy (dir, dir_start, dir_len); }
			if (!strcmp (dir, "define") && !skip) {
				while (q < line_end && isspace ((unsigned char)*q)) { q++; }
				const char *name_start = q;
				while (q < line_end && is_identifier_char (*q)) { q++; }
				size_t name_len = q - name_start;
				char *name = r_str_ndup (name_start, name_len);
				while (q < line_end && isspace ((unsigned char)*q)) { q++; }
				const char *val_start = q;
				size_t val_len = line_end - q;
				char *value = r_str_ndup (val_start, val_len);
				r_str_trim (value);
				pp_set_define (st, name, value);
				free (name);
				free (value);
			} else if (!strcmp (dir, "undef") && !skip) {
				while (q < line_end && isspace ((unsigned char)*q)) { q++; }
				const char *name_start = q;
				while (q < line_end && is_identifier_char(*q)) { q++; }
				size_t name_len = q - name_start;
				char *name = r_str_ndup(name_start, name_len);
				size_t i;
				for (i = 0; i < st->count; i++) {
					if (!strcmp (st->keys[i], name)) {
						free (st->keys[i]);
						free (st->values[i]);
						memmove (&st->keys[i], &st->keys[i+1], (st->count - i - 1) * sizeof (char*));
						memmove (&st->values[i], &st->values[i+1], (st->count - i - 1) * sizeof (char*));
						st->count--;
						break;
					}
				}
				free (name);
			} else if ((!strcmp (dir, "ifdef") || !strcmp (dir, "ifndef"))) {
				while (q < line_end && isspace ((unsigned char)*q)) { q++; }
				const char *name_start = q;
				while (q < line_end && is_identifier_char(*q)) { q++; }
				size_t name_len = q - name_start;
				char *name = r_str_ndup(name_start, name_len);
				bool defined = pp_get_define (st, name) != NULL;
				free (name);
				bool cond = !strcmp (dir, "ifdef") ? defined : !defined;
				bool outer = st->if_count ? st->if_skip[st->if_count-1] : false;
				bool new_skip = outer || !cond;
				if (st->if_count < PP_MAX_IF_NEST) { st->if_skip[st->if_count++] = new_skip; }
			} else if (!strcmp (dir, "if")) {
				while (q < line_end && isspace ((unsigned char)*q)) { q++; }
				bool cond = false;
				if (!strncmp (q, "defined", 7)) { cond = pp_eval_defined(st, q, &q); }
				bool outer = st->if_count ? st->if_skip[st->if_count-1] : false;
				bool new_skip = outer || !cond;
				if (st->if_count < PP_MAX_IF_NEST) { st->if_skip[st->if_count++] = new_skip; }
			} else if (!strcmp (dir, "elif") && st->if_count) {
				bool outer = st->if_count > 1 ? st->if_skip[st->if_count-2] : false;
				while (q < line_end && isspace ((unsigned char)*q)) { q++; }
				bool cond = false;
				if (!strncmp (q, "defined", 7)) { cond = pp_eval_defined(st, q, &q); }
				bool new_skip = outer || !cond;
				st->if_skip[st->if_count-1] = new_skip;
			} else if (!strcmp (dir, "else") && st->if_count) {
				bool outer = st->if_count > 1 ? st->if_skip[st->if_count-2] : false;
				bool prev = st->if_skip[st->if_count-1];
				bool new_skip = outer || (!prev && !outer);
				st->if_skip[st->if_count-1] = new_skip;
			} else if (!strcmp (dir, "endif") && st->if_count) {
				st->if_count--;
			} else if (!strcmp (dir, "warning") && !skip) {
				char *s = r_str_ndup (q, (line_end - q));
				R_LOG_WARN ("cpp: %s", s);
				free (s);
			} else if (!strcmp (dir, "error") && !skip) {
				char *s = r_str_ndup (q, (line_end - q));
				R_LOG_ERROR ("cpp: %s", s);
				free (s);
				goto failure;
			} else if (!strcmp (dir, "include") && !skip) {
				while (q < line_end && isspace ((unsigned char)*q)) { q++; }
				char delim = *q;
				if (delim == '"' || delim == '<') {
					q++;
					const char *fn_start = q;
					while (q < line_end && *q != (delim == '"' ? '"' : '>')) { q++; }
					size_t fn_len = q - fn_start;
					char *filename = r_str_ndup (fn_start, fn_len);
					char *fcontent = r_file_slurp (filename, NULL);
					if (fcontent) {
						char *inc_pp = pp_preprocess(st, fcontent);
						r_strbuf_append (out, inc_pp);
						free (inc_pp);
						free (fcontent);
					}
					free (filename);
				}
			}
			// Remove directive lines starting with '#' from output, preserve line breaks
			if (newline) {
				r_strbuf_append (out, "\n");
			}
		} else {
			if (!skip) {
				const char *rptr = line_start;
				while (rptr < line_end) {
					if (is_identifier_char (*rptr)) {
						const char *id_start = rptr;
						while (rptr < line_end && is_identifier_char(*rptr)) { rptr++; }
						KVCToken tok = { id_start, rptr };
						char *name = kvctoken_tostring (tok);
						const char *val = pp_get_define(st, name);
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
			if (newline) {
				r_strbuf_append (out, "\n");
			}
		}
		p = line_end + (newline ? 1 : 0);
	}
	char *result = r_strbuf_drain (out);
	st->rec_depth--;
	return result;
failure:
	r_strbuf_free (out);
	return NULL;
}

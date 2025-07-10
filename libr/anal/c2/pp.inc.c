/* Basic C Preprocessor implementation using KVCToken and r_strbuf */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "r_util.h"

enum { PP_DEFAULT_CAP = 16, PP_MAX_IF_NEST = 64 };

typedef struct {
	char **keys;
	char **values;
	size_t count, cap;
	bool if_skip[PP_MAX_IF_NEST];
	size_t if_count;
} PPState;

static PPState pp_state = {0};

static void pp_clear_defines(void) {
	size_t i;
	for (i = 0; i < pp_state.count; i++) {
		free (pp_state.keys[i]);
		free (pp_state.values[i]);
	}
	free (pp_state.keys);
	free (pp_state.values);
	pp_state.keys = NULL;
	pp_state.values = NULL;
	pp_state.count = pp_state.cap = 0;
}

R_API void pp_set_define(const char *name, const char *value) {
	size_t i;
	for (i = 0; i < pp_state.count; i++) {
		if (!strcmp (pp_state.keys[i], name)) {
			free (pp_state.values[i]);
			pp_state.values[i] = strdup (value);
			return;
		}
	}
	if (pp_state.count == pp_state.cap) {
		size_t newcap = pp_state.cap ? pp_state.cap * 2 : PP_DEFAULT_CAP;
		pp_state.keys = realloc (pp_state.keys, newcap * sizeof (char*));
		pp_state.values = realloc (pp_state.values, newcap * sizeof (char*));
		pp_state.cap = newcap;
	}
	pp_state.keys[pp_state.count] = strdup (name);
	pp_state.values[pp_state.count] = strdup (value);
	pp_state.count++;
}

R_API const char *pp_get_define(const char *name) {
	size_t i;
	for (i = 0; i < pp_state.count; i++) {
		if (!strcmp (pp_state.keys[i], name)) {
			return pp_state.values[i];
		}
	}
	return NULL;
}

static inline bool is_identifier_char(char c) {
	return isalnum ((unsigned char)c) || c == '_';
}

static bool pp_eval_defined(const char *p, const char **endptr) {
	while (isspace ((unsigned char)*p)) { p++; }
	if (*p != '(') {
		if (endptr) { *endptr = p; }
		return false;
	}
	p++;
	while (isspace((unsigned char)*p)) { p++; }
	const char *name_start = p;
	while (is_identifier_char(*p)) { p++; }
	size_t name_len = p - name_start;
	char *name = r_str_ndup(name_start, name_len);
	while (isspace((unsigned char)*p)) { p++; }
	if (*p == ')') { p++; }
	if (endptr) { *endptr = p; }
	bool def = pp_get_define(name) != NULL;
	free(name);
	return def;
}

R_API char *pp_preprocess(const char *source) {
	PPState *st = &pp_state;
	memset (st->if_skip, 0, sizeof(st->if_skip));
	st->if_count = 0;
	RStrBuf *out = r_strbuf_new("");
	const char *p = source;
	const char *end = source + strlen(source);
	while (p < end) {
		const char *line_start = p;
		const char *newline = memchr(p, '\n', end - p);
		const char *line_end = newline ? newline : end;
		const char *q = line_start;
		while (q < line_end && (*q == ' ' || *q == '\t')) { q++; }
		bool skip = st->if_count ? st->if_skip[st->if_count-1] : false;
		if (q < line_end && *q == '#') {
			q++;
			while (q < line_end && isspace((unsigned char)*q)) { q++; }
			const char *dir_start = q;
			while (q < line_end && isalpha((unsigned char)*q)) { q++; }
			size_t dir_len = q - dir_start;
			char dir[16] = {0};
			if (dir_len < sizeof(dir)) { memcpy(dir, dir_start, dir_len); }
			if (!strcmp(dir, "define") && !skip) {
				while (q < line_end && isspace((unsigned char)*q)) { q++; }
				const char *name_start = q;
				while (q < line_end && is_identifier_char(*q)) { q++; }
				size_t name_len = q - name_start;
				char *name = r_str_ndup(name_start, name_len);
				while (q < line_end && isspace((unsigned char)*q)) { q++; }
				const char *val_start = q;
				size_t val_len = line_end - q;
				char *value = r_str_ndup(val_start, val_len);
				r_str_trim (value);
				pp_set_define (name, value);
				free (name);
				free (value);
			} else if (!strcmp(dir, "undef") && !skip) {
				while (q < line_end && isspace((unsigned char)*q)) { q++; }
				const char *name_start = q;
				while (q < line_end && is_identifier_char(*q)) { q++; }
				size_t name_len = q - name_start;
				char *name = r_str_ndup(name_start, name_len);
				size_t i;
				for (i = 0; i < st->count; i++) {
					if (!strcmp(st->keys[i], name)) {
						free(st->keys[i]);
						free(st->values[i]);
						memmove(&st->keys[i], &st->keys[i+1], (st->count - i - 1) * sizeof(char*));
						memmove(&st->values[i], &st->values[i+1], (st->count - i - 1) * sizeof(char*));
						st->count--;
						break;
					}
				}
				free(name);
			} else if ((!strcmp(dir, "ifdef") || !strcmp(dir, "ifndef"))) {
				while (q < line_end && isspace((unsigned char)*q)) { q++; }
				const char *name_start = q;
				while (q < line_end && is_identifier_char(*q)) { q++; }
				size_t name_len = q - name_start;
				char *name = r_str_ndup(name_start, name_len);
				bool defined = pp_get_define(name) != NULL;
				free(name);
				bool cond = !strcmp(dir, "ifdef") ? defined : !defined;
				bool outer = st->if_count ? st->if_skip[st->if_count-1] : false;
				bool new_skip = outer || !cond;
				if (st->if_count < PP_MAX_IF_NEST) { st->if_skip[st->if_count++] = new_skip; }
			} else if (!strcmp(dir, "if")) {
				while (q < line_end && isspace((unsigned char)*q)) { q++; }
				bool cond = false;
				if (!strncmp(q, "defined", 7)) { cond = pp_eval_defined(q, &q); }
				bool outer = st->if_count ? st->if_skip[st->if_count-1] : false;
				bool new_skip = outer || !cond;
				if (st->if_count < PP_MAX_IF_NEST) { st->if_skip[st->if_count++] = new_skip; }
			} else if (!strcmp(dir, "elif") && st->if_count) {
				bool outer = st->if_count > 1 ? st->if_skip[st->if_count-2] : false;
				while (q < line_end && isspace((unsigned char)*q)) { q++; }
				bool cond = false;
				if (!strncmp(q, "defined", 7)) { cond = pp_eval_defined(q, &q); }
				bool new_skip = outer || !cond;
				st->if_skip[st->if_count-1] = new_skip;
			} else if (!strcmp(dir, "else") && st->if_count) {
				bool outer = st->if_count > 1 ? st->if_skip[st->if_count-2] : false;
				bool prev = st->if_skip[st->if_count-1];
				bool new_skip = outer || (!prev && !outer);
				st->if_skip[st->if_count-1] = new_skip;
			} else if (!strcmp(dir, "endif") && st->if_count) {
				st->if_count--;
			} else if (!strcmp(dir, "include") && !skip) {
				while (q < line_end && isspace((unsigned char)*q)) { q++; }
				char delim = *q;
				if (delim == '"' || delim == '<') {
					q++;
					const char *fn_start = q;
					while (q < line_end && *q != (delim == '"' ? '"' : '>')) { q++; }
					size_t fn_len = q - fn_start;
					char *filename = r_str_ndup (fn_start, fn_len);
					char *fcontent = r_file_slurp (filename, NULL);
					if (fcontent) {
						char *inc_pp = pp_preprocess(fcontent);
						r_strbuf_append(out, inc_pp);
						free(inc_pp);
						free(fcontent);
					}
					free(filename);
				}
			}
			if (!skip) {
				r_strbuf_append_n(out, line_start, line_end - line_start);
				if (newline) { r_strbuf_append(out, "\n"); }
			} else {
				if (newline) { r_strbuf_append(out, "\n"); }
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
						const char *val = pp_get_define (name);
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
	return r_strbuf_drain (out);
}

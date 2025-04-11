/* radare - LGPL - Copyright 2009-2025 - pancake, nibble */

#include <r_cons.h>
#include <r_util/r_print.h>
#include <r_util/r_json.h>
#include <r_util/r_strbuf.h>
#include <sdb/sdb.h>

// R2R db/cmd/cons_grep

#define I(x) r_cons_singleton ()->x

static char *strchr_ns(char *s, const char ch) {
	if (!s) {
		return NULL;
	}

	char *p;
	while ((p = strchr (s, ch)) != NULL) {
		if (p > s && *(p - 1) == '\\') {
			memmove (p - 1, p, strlen (p) + 1);
			s = p;
		} else {
			return p;
		}
	}
	return NULL;
}

static void r_cons_grep_word_free(RConsGrepWord *gw) {
	if (gw) {
		free (gw->str);
		free (gw);
	}
}

static RCoreHelpMessage help_detail_tilde = {
	"Usage: [command]~[modifier][word,word][endmodifier][[column]][:line]\n"
	"modifier:", "", "",
	" &",        "", "all words must match to grep the line",
	" $[n]",     "", "sort numerically / alphabetically the Nth column",
	" $",        "", "sort in alphabetic order",
	" $$",       "", "sort + uniq",
	" $!",       "", "inverse alphabetical sort",
	" $!!",      "", "reverse the lines (like the `tac` tool)",
	" ,",        "", "token to define another keyword",
	" +",        "", "case insensitive grep (grep -i)",
	" *",        "", "zoom level",
	" ^",        "", "words must be placed at the beginning of line",
	" !",        "", "negate grep",
	" ?",        "", "count number of matching lines",
	" ?.",       "", "count number chars",
	" ??",       "", "show this help message",
	" ?ea",      "", "convert text into seven segment style ascii art",
	" :s..e",    "", "show lines s-e",
	" ..",       "", "internal 'less'",
	" ...",      "", "internal 'hud' (like V_)",
	" ....",     "", "internal 'hud' in one line",
	" :)",       "", "parse C-like output from decompiler",
	" :))",      "", "code syntax highlight",
	" <50",      "", "perform zoom to the given text width on the buffer",
	" <>",       "", "xml indentation",
	" {:",       "", "human friendly indentation (yes, it's a smiley)",
	" {:..",     "", "less the output of {:",
	" {:...",    "", "hud the output of {:",
	" {}",       "", "json indentation",
	" {}..",     "", "less json indentation",
	" {}...",    "", "hud json indentation",
	" {=}",       "", "gron-like output (key=value)",
	" {path}",   "", "json path grep",
	"endmodifier:", "", "",
	" $",        "", "words must be placed at the end of line",
	"column:", "", "",
	" [n]",      "", "show only column n",
	" [n-m]",    "", "show column n to m",
	" [n-]",     "", "show all columns starting from column n",
	" [i,j,k]",  "", "show the columns i, j and k",
	"Examples:", "", "",
	" i~:0",     "", "show first line of 'i' output",
	" i~:-2",    "", "show the second to last line of 'i' output",
	" i~:0..3",  "", "show first three lines of 'i' output",
	" pd~mov",   "", "disasm and grep for mov",
	" pi~[0]",   "", "show only opcode",
	" i~0x400$", "", "show lines ending with 0x400",
	NULL
};

R_API void r_cons_grep_help(void) {
	r_cons_cmd_help (help_detail_tilde, true);
}

R_API void r_cons_grep_expression(const char *str) {
	if (R_STR_ISEMPTY(str)) {
		return;
	}

	RCons *cons = r_cons_singleton ();
	RConsContext *ctx = cons->context;
	RConsGrep *grep = &ctx->grep;

	size_t str_len = strlen (str);
	size_t buf_len = str_len;
	bool has_counter = str_len > 0 && str[str_len - 1] == '?';

	if (has_counter) {
		grep->counter = 1;
		buf_len--;
	}

	char *buf = malloc (buf_len + 1);
	if (!buf) {
		R_LOG_ERROR ("r_cons_grep: cannot allocate buffer");
		return;
	}

	memcpy (buf, str, buf_len);
	buf[buf_len] = '\0';

	char *ptrs[R_CONS_GREP_COUNT];
	size_t ptrs_length = 1;
	ptrs[0] = buf;
	char *ptr = buf;

	while ((ptrs[ptrs_length] = strchr (ptr, '~'))) {
		*(ptrs[ptrs_length]) = '\0';
		ptrs[ptrs_length]++;
		ptr = ptrs[ptrs_length];
		ptrs_length++;
		if (ptrs_length >= R_CONS_GREP_COUNT) {
			R_LOG_ERROR ("too many nested greps");
			goto cleanup;
		}
	}

	R_FREE (grep->str);
	bool first = true;
	ctx->sorted_column = 0;
	size_t i;
	for (i = 0; i < ptrs_length; i++) {
		bool gw_begin = false;
		bool gw_neg = false;
		bool gw_end = false;
		ptr = ptrs[i];
		char *end_ptr = NULL, *ptr2 = NULL, *ptr3 = NULL;
		while (*ptr) {
			switch (*ptr) {
			case ':':
				if (ptr[1] == ')') { // ":)"
					if (ptr[2] == ')') { // ":))"
						grep->colorcode = true;
						ptr++;
					}
					grep->code = true;
					ptr++;
				}
				goto while_end;
			case '.':
				if (ptr[1] == '.') {
					if (ptr[2] == '.') {
						if (ptr[3] == '.') {
							grep->less = 3;
						} else {
							grep->less = 2;
						}
					} else {
						grep->less = 1;
					}
					goto cleanup;
				}
				ptr++;
				break;
			case '{':
				if (ptr[1] == ':') {
					grep->human = true; // human friendly indentation ij~{:
					grep->json = true;
					if (r_str_startswith (ptr, "{:...")) {
						grep->hud = true;
					} else if (r_str_startswith (ptr, "{:..")) {
						grep->less = 1;
					}
				} else if (ptr[1] == '=' && ptr[2] == '}') {
					grep->gron = true;
					ptr += 2;
				} else if (ptr[1] == '}') {
					// standard json indentation
					grep->json = true;
					if (r_str_startswith (ptr, "{}...")) {
						grep->hud = true;
					} else if (r_str_startswith (ptr, "{}..")) {
						grep->less = 1;
					}
				} else {
					char *jsonPath = strdup (ptr + 1);
					char *jsonPathEnd = strchr (jsonPath, '}');
					if (jsonPathEnd) {
						*jsonPathEnd = 0;
						free (grep->json_path);
						grep->json_path = jsonPath;
						grep->json = true;
					} else {
						free (jsonPath);
					}
					goto cleanup;
				}
				ptr++;
				break;
			case '$':
				ptr++;
				grep->sort = 0;
				if (*ptr == '!') {
					if (ptr[1] == '!') {
						grep->sort = -1;
						ptr++;
					}
					grep->sort_invert = true;
					ptr++;
				} else if (*ptr == '$') {
					grep->sort_uniq = true;
				} else {
					grep->sort_invert = false;
				}
				while (*ptr && isdigit (*ptr)) {
					ptr++;
				}
				if (*ptr == ':') {
					ptr++;
					grep->sort_row = atoi (ptr);
					ptr++;
				}
				break;
			case '&':
				ptr++;
				grep->amp = 1;
				break;
			case '<':
				ptr++;
				if (*ptr == '>') {
					grep->xml = true;
				} else {
					grep->zoom = atoi (ptr);
				}
				break;
			case '+':
				if (first) {
					ptr++;
					grep->icase = true;
				} else {
					goto while_end;
				}
				break;
			case '^':
				ptr++;
				gw_begin = true;
				break;
			case '!':
				ptr++;
				gw_neg = true;
				break;
			case '?':
				ptr++;
				grep->counter = 1;
				if (*ptr == '.') {
					grep->charCounter = true;
					ptr++;
				} else if (!strcmp (ptr, "ea")) {
					grep->ascart = true;
				} else if (*ptr == '?') {
					cons->context->filter = true;
					r_cons_grep_help ();
					goto cleanup;
				}
				break;
			default:
				goto while_end;
			}
			first = false;
		}
while_end:
		ptr2 = strchr (ptr, '[');
		ptr3 = strchr (ptr, ']');
		int is_range = 0, num_is_parsed = 0;
		bool fail = false;
		ut64 range_begin = -1, range_end = -1;

		if (ptr2 && ptr3) {
			end_ptr = ptr2;
			char last = ptr3[1];
			ptr3[1] = '\0';
			ptr2++;
			for (; ptr2 <= ptr3; ptr2++) {
				if (fail) {
					ZERO_FILL(grep->tokens);
					grep->tokens_used = 0;
					break;
				}
				switch (*ptr2) {
				case '-':
					is_range = 1;
					num_is_parsed = 0;
					range_end = -1;
					break;
				case ']': // fallthrough to handle ']' like ','
				case ',':
					for (; range_begin <= range_end; range_begin++) {
						if (range_begin >= R_CONS_GREP_TOKENS) {
							fail = true;
							break;
						}
						grep->tokens[range_begin] = 1;
						grep->tokens_used = 1;
					}
					if (*ptr2 == ']' && is_range && !num_is_parsed) {
						num_is_parsed = true;
						range_end = -1;
					} else {
						is_range = 0;
						num_is_parsed = 0;
					}
					break;
				default:
					if (!num_is_parsed) {
						if (is_range) {
							range_end = r_num_get (cons->num, ptr2);
							if (range_end == 0 && *ptr2 != '0') {
								range_end = -1;
							}
						} else {
							range_begin = range_end = r_num_get (cons->num, ptr2);
						}
						num_is_parsed = true;
					}
				}
			}
			ptr3[1] = last;
		}

		ptr2 = strchr_ns (ptr, ':'); // line number
		grep->range_line = 2; // there is no :
		if (ptr2 && ptr2[1] != ':' && ptr2[1] && (isdigit (ptr2[1]) || ptr2[1] == '-' || ptr2[1] == '.')) {
			end_ptr = end_ptr ? R_MIN (end_ptr, ptr2) : ptr2;
			char *p, *token = ptr2 + 1;
			p = strstr(token, "..");
			if (!p) {
				grep->line = r_num_get (cons->num, ptr2 + 1);
				grep->range_line = 0;
			} else {
				*p = '\0';
				grep->range_line = 1;
				grep->f_line = *token ? r_num_get (cons->num, token) : 0;
				grep->l_line = p[2] ? r_num_get (cons->num, p + 2) : 0;
			}
		}
		if (end_ptr) {
			*end_ptr = '\0';
		}

		int len = strlen (ptr);
		if (len > 1 && ptr[len - 1] == '$' && ptr[len - 2] != '\\') {
			gw_end = true;
			ptr[len - 1] = '\0';
		}

		if (*ptr) {
			if (!grep->str) {
				grep->str = strdup (ptr);
			} else {
				char *s = r_str_newf (",%s", ptr);
				grep->str = r_str_append (grep->str, s);
				free(s);
			}
			char *optr;
			do {
				optr = ptr;
				ptr = strchr (ptr, ','); // grep keywords
				if (ptr) {
					*ptr++ = '\0';
				}
				int wlen = strlen(optr);
				if (!wlen) {
					continue;
				}
				RConsGrepWord *gw = R_NEW0 (RConsGrepWord);
				gw->str = strdup (optr);
				gw->begin = gw_begin;
				gw->neg = gw_neg;
				gw->end = gw_end;
				gw_end = false;
				r_list_append (grep->strings, gw);
			} while (ptr);
		}
	}

	if (!grep->str) {
		RConsGrepWord *gw = R_NEW0 (RConsGrepWord);
		gw->str = strdup ("");
		grep->str = strdup ("");
		r_list_append (grep->strings, gw);
	}
cleanup:
	free (buf);
}

// Finds and returns next intgrep expression,
// unescapes escaped twiddles
static char *find_next_intgrep(char *cmd, const char *quotes) {
	do {
		char *p = (char *)r_str_firstbut (cmd, '~', quotes);
		if (!p) {
			break;
		}
		if (p == cmd || *(p - 1) != '\\') {
			return (char *)p;
		}
		// twiddle unescape
		r_str_cpy (p - 1, p);
		cmd = p + 1;
	} while (*cmd);
	return NULL;
}

/*
 * Removes grep part from *cmd* and returns newly allocated string
 * with reshaped grep expression.
*/
static char *preprocess_filter_expr(char *cmd, const char *quotes) {
	char *p2, *ns = NULL;
	const char *strsep = "&";
	int i;

	char *p1 = find_next_intgrep (cmd, quotes);
	if (!p1) {
		return NULL;
	}

	int len = strlen (p1);
	if (len > 4 && r_str_endswith (p1, "~?") && p1[len - 3] != '\\') {
		p1[len - 2] = '\0';
		ns = r_str_append (ns, "?");
	}

	*p1 = '\0'; // remove grep part from cmd

	i = 0;
	// parse words between '~'
	while ((p2 = find_next_intgrep (p1 + 1, quotes))) {
		ns = r_str_append (ns, strsep);
		ns = r_str_appendlen (ns, p1 + 1, (int)(p2 - p1 - 1));
		p1 = p2;
		strsep = "~";
		i++;
	}

	if (i > 0) {
		ns = r_str_append (ns, "~");
	}

	return r_str_append (ns, p1 + 1);
}

R_API void r_cons_grep_parsecmd(char *cmd, const char *quotestr) {
	R_RETURN_IF_FAIL (cmd && quotestr);
	char *ptr = preprocess_filter_expr (cmd, quotestr);
	if (ptr) {
		r_str_trim (cmd);
		r_cons_grep_expression (ptr);
		free (ptr);
	}
}

R_API char *r_cons_grep_strip(char *cmd, const char *quotestr) {
	char *ptr = NULL;
	if (cmd) {
		ptr = preprocess_filter_expr (cmd, quotestr);
		r_str_trim (cmd);
	}
	return ptr;
}

static int cmp(const void *a, const void *b) {
	char *da = NULL;
	char *db = NULL;
	const char *ca = r_str_trim_head_ro (a);
	const char *cb = r_str_trim_head_ro (b);
	if (!a || !b) {
		ptrdiff_t diff = (char*)a - (char*)b;
		if (diff > INT_MAX) {
			return INT_MAX;
		}
		if (diff < INT_MIN) {
			return INT_MIN;
		}
		return (int)diff;
	}
	RConsContext *ctx = r_cons_context ();
	if (ctx->sorted_column > 0) {
		da = strdup (ca);
		db = strdup (cb);
		int colsa = r_str_word_set0 (da);
		int colsb = r_str_word_set0 (db);
		ca = (colsa > ctx->sorted_column)? r_str_word_get0 (da, ctx->sorted_column): "";
		cb = (colsb > ctx->sorted_column)? r_str_word_get0 (db, ctx->sorted_column): "";
	}
	if (isdigit (*ca) && isdigit (*cb)) {
		ut64 na = r_num_get (NULL, ca);
		ut64 nb = r_num_get (NULL, cb);
		int ret = (na > nb) - (na < nb);
		free (da);
		free (db);
		return ret;
	}
	if (da && db) {
		a = ca;
		b = cb;
	}
	int res = strcmp (a, b);
	free (da);
	free (db);
	return res;
}

static bool gron(RStrBuf *sb, RJson *node, const char *root) {
	R_RETURN_VAL_IF_FAIL (sb && node && root, false);
	switch (node->type) {
	case R_JSON_ARRAY:
		{
			RJson *cn = node->children.first;
			int n = 0;
			r_strbuf_appendf (sb, "%s = [];\n", root);
			while (cn) {
				char *newroot = r_str_newf ("%s[%d]", root, n);
				gron (sb, cn, newroot);
				free (newroot);
				cn = cn->next;
				n++;
			}
		}
		break;
	case R_JSON_OBJECT:
		{
			RJson *cn = node->children.first;
			r_strbuf_appendf (sb, "%s = {};\n", root);
			while (cn) {
				char *newroot = r_str_newf ("%s.%s", root, cn->key);
				gron (sb, cn, newroot);
				cn = cn->next;
			}
		}
		break;
	case R_JSON_STRING:
		{
			size_t l = strlen (node->str_value);
			char *estr = r_str_encoded_json (node->str_value, l, PJ_ENCODING_STR_DEFAULT);
			r_strbuf_appendf (sb, "%s = \"%s\";\n", root, estr);
			free (estr);
		}
		break;
	case R_JSON_BOOLEAN:
		r_strbuf_appendf (sb, "%s = %s;\n", root, r_str_bool (node->num.u_value));
		break;
	case R_JSON_INTEGER:
		r_strbuf_appendf (sb, "%s = %"PFMT64d";\n", root, node->num.u_value);
		break;
	case R_JSON_NULL:
		r_strbuf_appendf (sb, "%s = null;\n", root);
		break;
	case R_JSON_DOUBLE:
		r_strbuf_appendf (sb, "%s = %lf;\n", root, node->num.dbl_value);
		break;
	default:
		R_LOG_WARN ("unknown json type %s", r_json_type (node));
		break;
	}
	return true;
}

static inline ut64 cmpstrings(const void *a) {
	return r_str_hash64 (a);
}

static char *colorword(char *res, const char *k, const char *color) {
	char *tv = r_str_newf ("~~[%s]~~", k);
	r_str_case (tv, true);
	char *nv = r_str_newf ("%s%s"Color_RESET, color, k);
	res = r_str_replace_all (res, k, tv);
	res = r_str_replace_all (res, tv, nv);
	free (nv);
	free (tv);
	return res;
}

static void colorcode(void) {
	// TODO : dupped from libr/util/print_code.c r_print_code_tocolor
	RCons *cons = r_cons_singleton ();
	int i;
	char *res = r_str_ndup (cons->context->buffer, cons->context->buffer_len);
	if (res) {
		bool linecomment = false;
		bool comment = false;
		bool string = false;
		RStrBuf *sb = r_strbuf_new ("");
		for (i = 0; res[i]; i++) {
			const char ch = res[i];
			const char ch2 = res[i + 1];
			if (linecomment) {
				if (ch == '\n') {
					r_strbuf_append (sb, Color_RESET);
					r_strbuf_append_n (sb, &ch, 1);
					linecomment = false;
				} else {
					r_strbuf_append_n (sb, &ch, 1);
				}
			} else if (comment) {
				if (ch == '*' && res[i + 1] == '/') {
					r_strbuf_append_n (sb, &ch, 1);
					r_strbuf_append_n (sb, &ch2, 1);
					r_strbuf_append (sb, Color_RESET);
					comment = false;
					i++;
				} else {
					r_strbuf_append_n (sb, &ch, 1);
				}
			} else if (string) {
				if (ch == '\\') {
					if (res[i + 1]) {
						r_strbuf_append_n (sb, &ch, 1);
						r_strbuf_append_n (sb, &ch2, 1);
						i++;
					} else {
						r_strbuf_append_n (sb, &ch, 1);
					}
				} else if (ch == '"') {
					r_strbuf_append_n (sb, &ch, 1);
					r_strbuf_append (sb, Color_RESET);
					string = false;
				} else {
					r_strbuf_append_n (sb, &ch, 1);
				}
			} else {
				if (i == 0 && ch == '#') {
					r_strbuf_append (sb, Color_BLUE);
					r_strbuf_append_n (sb, &ch, 1);
					linecomment = true;
				} else if (ch == '\n') {
					if (ch2 == '#') {
						r_strbuf_append_n (sb, &ch, 1);
						r_strbuf_append (sb, Color_BLUE);
						r_strbuf_append_n (sb, &ch2, 1);
						linecomment = true;
						i++;
						i++;
					} else {
						r_strbuf_append_n (sb, &ch, 1);
					}
				} else if (ch == '/') {
					if (ch2 == '*') {
						comment = true;
						r_strbuf_append (sb, Color_BLUE);
						r_strbuf_append_n (sb, &ch, 1);
					} else if (ch2 == '/') {
						linecomment = true;
						r_strbuf_append (sb, Color_BLUE);
						r_strbuf_append_n (sb, &ch, 1);
					} else {
						r_strbuf_append_n (sb, &ch, 1);
					}
				} else if (ch == '"') {
					string = true;
					r_strbuf_append (sb, Color_RED);
					r_strbuf_append_n (sb, &ch, 1);
				} else {
					r_strbuf_append_n (sb, &ch, 1);
				}
			}
		}
		free (res);
		res = r_strbuf_drain (sb);
		// ugly temporary hack
#if 0
		res = colorword (res, "if ", Color_RED);
		res = colorword (res, " else ", Color_RED);
#endif
		res = colorword (res, "for ", Color_RED);
		res = colorword (res, "while ", Color_RED);
		res = colorword (res, "switch ", Color_RED);
		res = colorword (res, "static ", Color_RED);
		res = colorword (res, "inline ", Color_RED);
		// res = colorword (res, " -> ", Color_RED);
		res = colorword (res, "return", Color_RED);
		res = colorword (res, "string ", Color_RED);
		res = colorword (res, "number ", Color_RED);

		res = colorword (res, "void ", Color_GREEN);
		res = colorword (res, "bool ", Color_GREEN);
		res = colorword (res, "ut64 ", Color_GREEN);
		res = colorword (res, "uint32_t", Color_GREEN);
		res = colorword (res, "uint64_t", Color_GREEN);
		res = colorword (res, "int32_t", Color_GREEN);
		res = colorword (res, "int64_t", Color_GREEN);
		res = colorword (res, "int8_t", Color_GREEN);
		res = colorword (res, "uint8_t", Color_GREEN);
		res = colorword (res, "int ", Color_GREEN);
		res = colorword (res, "char ", Color_GREEN);
		res = colorword (res, "const ", Color_GREEN);
#if 0
		res = colorword (res, "{", Color_YELLOW);
		res = colorword (res, "}", Color_YELLOW);
#endif
		// bring back the colorized buffer
		cons->context->buffer_len = strlen (res);
		cons->context->buffer_sz = cons->context->buffer_len;
		free (cons->context->buffer);
		cons->context->buffer = res;
	}
}

R_API void r_cons_grepbuf(void) {
	RCons *cons = r_cons_singleton ();
	const char *buf = cons->context->buffer;
	size_t len = cons->context->buffer_len;
	RConsGrep *grep = &cons->context->grep;
	const char *in = buf;
	int ret, l = 0, tl = 0;
	bool show = false;
	if (cons->context->filter) {
		cons->context->buffer_len = 0;
		R_FREE (cons->context->buffer);
		return;
	}
	if (grep->colorcode) {
		colorcode ();
		grep->sort = 0;
		grep->code = false;
		return;
	}
	if (grep->code) {
		char *sbuf = r_str_ndup (cons->context->buffer, cons->context->buffer_len);
		if (sbuf) {
			char *res = r_str_tokenize_json (sbuf);
			if (!res) {
				return;
			}
			char *nres = r_print_json_indent (res, I(context->color_mode), "  ", NULL);
			free (res);
			res = r_str_newf ("%s\n", nres);
			free (nres);
			free (sbuf);
			if (res) {
				cons->context->buffer_len = strlen (res);
				cons->context->buffer_sz = cons->context->buffer_len;
				free (cons->context->buffer);
				cons->context->buffer = res;
			} else {
				cons->context->buffer_len = 0;
				cons->context->buffer_sz = 0;
				free (cons->context->buffer);
				cons->context->buffer = strdup ("");
			}
		}
		return;
	}

	if ((!len || R_STR_ISEMPTY (buf)) && (grep->json || grep->less)) {
		grep->json = false;
		grep->hud = false;
		grep->less = 0;
		return;
	}
	if (grep->ascart) {
		char *sbuf = strdup (cons->context->buffer);
		r_str_ansi_filter (sbuf, NULL, NULL, -1);
		char *out = r_str_ss (sbuf, NULL, 0);
		free (sbuf);
		free (cons->context->buffer);
		cons->context->buffer = out;
		cons->context->buffer_len = strlen (out);
		cons->context->buffer_sz = cons->context->buffer_len;
		return;
	}
	if (grep->zoom) {
		char *sin = calloc (cons->context->buffer_len + 2, 4);
		if (R_UNLIKELY (!sin)) {
			grep->zoom = 0;
			grep->zoomy = 0;
			return;
		}
		strcpy (sin, cons->context->buffer);
		char *out = r_str_scale (in, grep->zoom * 2, grep->zoomy? grep->zoomy: grep->zoom);
		if (out) {
			free (cons->context->buffer);
			cons->context->buffer = out;
			cons->context->buffer_len = strlen (out);
			cons->context->buffer_sz = cons->context->buffer_len;
		}
		grep->zoom = 0;
		grep->zoomy = 0;
		free (sin);
		return;
	}
	if (grep->gron) {
		char *a = strdup (cons->context->buffer);
		RJson *node = r_json_parse (a);
		RStrBuf *sb = r_strbuf_new ("");
		gron (sb, node, "json");
		char *s = r_strbuf_drain (sb);
		R_FREE (cons->context->buffer);
		cons->context->buffer_len = 0;
		cons->context->buffer_sz = 0;
		r_cons_print (s);
		in = buf = cons->context->buffer;
		len = cons->context->buffer_len;
		r_json_free (node);
		free (a);
		free (s);
		goto continuation;
	}
	if (grep->xml) {
		// parse and indent xml
		char *x = r_str_ndup (buf, len);
		char *xi = r_xml_indent (x);
		free (cons->context->buffer);
		in = buf = cons->context->buffer = xi;
		len = cons->context->buffer_len = strlen (xi);
		free (x);
		return;
	}
	if (grep->json) {
		if (grep->json_path) {
			char *u = sdb_json_get_str (cons->context->buffer, grep->json_path);
			if (u) {
				cons->context->buffer = u;
				cons->context->buffer_len = strlen (u);
				cons->context->buffer_sz = cons->context->buffer_len + 1;
				grep->json = false;
				r_cons_newline ();
			}
			R_FREE (grep->json_path);
		} else {
			const char *palette[] = {
				cons->context->pal.graph_false, // f
				cons->context->pal.graph_true, // t
				cons->context->pal.num, // k
				cons->context->pal.comment, // v
				Color_RESET,
				NULL
			};
			char *bb = strdup (buf);
			r_str_ansi_filter (bb, NULL, NULL, -1);
			char *out = (cons->context->grep.human)
				? r_print_json_human (bb)
				: r_print_json_indent (bb, I (context->color_mode), "  ", palette);
			free (bb);
			if (!out) {
				return;
			}
			free (cons->context->buffer);
			cons->context->buffer = out;
			cons->context->buffer_len = strlen (out);
			cons->context->buffer_sz = cons->context->buffer_len + 1;
			grep->json = false;
			in = buf = out;
			len = cons->context->buffer_len;
			cons->context->grep_color = true;
			// R2R db/cmd/cmd_iz
			R_FREE (grep->str);
			cons->context->grep_color = false;
			RConsGrepWord *gw = r_list_pop_head (grep->strings);
			r_cons_grep_word_free (gw);
			if (grep->hud) {
				grep->hud = false;
				r_cons_hud_string (cons->context->buffer);
				return;
			}
			if (grep->less) {
				grep->less = 0;
				r_cons_less_str (cons->context->buffer, NULL);
				return;
			}
		}
		if (r_list_empty (grep->strings)) {
			return;
		}
		buf = cons->context->buffer;
		len = cons->context->buffer_len;
		grep->range_line = 1;
		goto continuation;
		// cons->lines = ?? return 3;
	}
	if (grep->less) {
		int less = grep->less;
		grep->less = 0;
		if (less == 3) {
			char *res = r_cons_hud_line_string (buf);
			if (res) {
				r_cons_println (res);
				free (res);
			}
		} else if (less == 2) {
			char *res = r_cons_hud_string (buf);
			if (res) {
				r_cons_println (res);
				free (res);
			}
		} else {
			r_cons_less_str (buf, NULL);
			cons->context->buffer_len = 0;
			cons->context->buffer_sz = 0;
			R_FREE (cons->context->buffer);
		}
		return;
	}
	RStrBuf *ob = NULL;
continuation:
	ob = r_strbuf_new ("");
	// if we modify cons->lines we should update I.context->buffer too
	cons->lines = 0;
	// used to count lines and change negative grep.line values
	if ((!grep->range_line && grep->line < 0) || grep->range_line) {
		int total_lines = 0;
		while ((int) (size_t) (in - buf) < len) {
			char *p = strchr (in, '\n');
			if (!p) {
				break;
			}
			l = p - in;
			if (l > 0) {
				in += l + 1;
			} else {
				in++;
			}
			total_lines++;
		}
		if (!grep->range_line && grep->line < 0) {
			grep->line = total_lines + grep->line;
		}
		if (grep->range_line == 1) {
			if (grep->f_line < 0) {
				grep->f_line = total_lines + grep->f_line;
			}
			if (grep->l_line <= 0) {
				grep->l_line = total_lines + grep->l_line;
			}
		}
	}
	bool is_range_line_grep_only = grep->range_line != 2 && grep->str && *grep->str == '\0';

	in = buf;
	while ((int) (size_t) (in - buf) < len) {
		char *p = strchr (in, '\n');
		if (!p) {
			break;
		}
		l = p - in;
		if ((!l && is_range_line_grep_only) || l > 0) {
			char *tline = r_str_ndup (in, l);
			if (cons->context->grep_color) {
				tl = l;
			} else {
				tl = r_str_ansi_filter (tline, NULL, NULL, l);
			}
			if (tl < 0) {
				ret = -1;
			} else {
				ret = r_cons_grep_line (tline, tl);
				if (!grep->range_line) {
					if (grep->line == cons->lines) {
						show = true;
					}
				} else if (grep->range_line == 1) {
					if (grep->f_line == cons->lines) {
						show = true;
					}
					if (grep->l_line == cons->lines) {
						show = false;
					}
				} else {
					show = true;
				}
			}
			if (grep->counter) {
				show = false;
			}
			if ((!ret && is_range_line_grep_only) || ret > 0) {
				if (show) {
					char *str = r_str_ndup (tline, ret);
					if (cons->context->grep_highlight) {
						RListIter *iter;
						RConsGrepWord *gw;
						r_list_foreach (grep->strings, iter, gw) {
							char *newstr = r_str_newf (Color_INVERT"%s"Color_RESET, gw->str);
							if (str && newstr) {
								if (grep->icase) {
									str = r_str_replace_icase (str, gw->str, newstr, 1, 1);
								} else {
									str = r_str_replace (str, gw->str, newstr, 1);
								}
							}
							free (newstr);
						}
					}
					if (str) {
						r_strbuf_append (ob, str);
						r_strbuf_append (ob, "\n");
						free (str);
					}
				}
				if (!grep->range_line) {
					show = false;
				}
				cons->lines++;
			} else if (ret < 0) {
				free (tline);
				r_strbuf_free (ob);
				return;
			}
			free (tline);
			in += l + 1;
		} else {
			in++;
		}
	}

	int ob_len = r_strbuf_length (ob);
	cons->context->buffer_len = ob_len;

	// count before uniq
	// XXX dupe from the code below
	if (grep->counter && !grep->sort_uniq) {
		int cnt = grep->charCounter? strlen (cons->context->buffer): cons->lines;
		free (cons->context->buffer);
		char *cntstr = r_str_newf ("%d\n", cnt);
		size_t cntstr_len = cntstr? strlen (cntstr): 0;
		cons->context->buffer = cntstr;
		cons->context->buffer_len = cntstr_len;
		cons->context->buffer_sz = cntstr_len + 1;
		cons->num->value = cons->lines;
		r_strbuf_free (ob);
		return;
	}
	if (ob_len >= cons->context->buffer_sz) {
		cons->context->buffer_sz = ob_len + 1;
		cons->context->buffer = r_strbuf_drain (ob);
	} else {
		memcpy (cons->context->buffer, r_strbuf_getbin (ob, NULL), ob_len);
		cons->context->buffer[ob_len] = 0;
		r_strbuf_free (ob);
		ob = NULL;
	}
	if (grep->sort != -1 || grep->sort_invert) {
#define INSERT_LINES(list) \
		if (list) { \
			*ptr = 0; \
			r_list_foreach (list, iter, str) { \
				int slen = strlen (str); \
				if (slen > 0) { \
					memcpy (ptr, str, slen); \
					memcpy (ptr + slen, "\n", 2); \
					ptr += slen + 1; \
				} \
			} \
		}
		RListIter *iter;
		char *ptr = cons->context->buffer;
		char *str;
		RConsContext *ctx = cons->context;
		ctx->sorted_column = grep->sort;

		if (ctx->sorted_lines) {
			if (grep->sort != -1) {
				r_list_sort (ctx->sorted_lines, cmp);
			}
			if (grep->sort_invert) {
				r_list_reverse (ctx->sorted_lines);
			}
			if (grep->sort_uniq) {
				r_list_uniq_inplace (ctx->sorted_lines, cmpstrings);
				r_list_free (ctx->unsorted_lines);
				ctx->unsorted_lines = NULL;
			}
			const int nl = r_list_length (ctx->sorted_lines);
			cons->context->buffer_len = 0;
			INSERT_LINES (ctx->unsorted_lines);
			INSERT_LINES (ctx->sorted_lines);
			cons->context->buffer_len = (ptr - cons->context->buffer);
			cons->lines = nl;
			r_list_free (ctx->sorted_lines);
			ctx->sorted_lines = NULL;
			r_list_free (ctx->unsorted_lines);
			ctx->unsorted_lines = NULL;
		}
	}
	// count after uniq
	if (grep->counter && grep->sort_uniq) {
		int cnt = grep->charCounter? strlen (cons->context->buffer): cons->lines;
		free (cons->context->buffer);
		char *cntstr = r_str_newf ("%d\n", cnt);
		size_t cntstr_len = cntstr? strlen (cntstr): 0;
		cons->context->buffer = cntstr;
		cons->context->buffer_len = cntstr_len;
		cons->context->buffer_sz = cntstr_len + 1;
		cons->num->value = cons->lines;
		r_strbuf_free (ob);
		return;
	}
}

R_API int r_cons_grep_line(char *buf, int len) {
	R_RETURN_VAL_IF_FAIL (buf && len >= 0, 0);
	RCons *cons = r_cons_singleton ();
	RConsGrep *grep = &cons->context->grep;
	const char *delims = " |,;=\t";
	char *tok = NULL;
	char *save_ptr = NULL;
	bool hit = true;
	int outlen = 0;
	bool use_tok = false;
	size_t i;

	char *in = calloc (1, len + 1);
	if (!in) {
		return 0;
	}
	char *out = calloc (1, len + 2);
	if (!out) {
		free (in);
		return 0;
	}
	memcpy (in, buf, len);
	const bool have_strings = !r_list_empty (grep->strings);

	if (have_strings) {
		bool all_hits = true;
		if (grep->icase) {
			r_str_case (in, false);
		}
		RListIter *iter;
		RConsGrepWord *gw;
		r_list_foreach (grep->strings, iter, gw) {
			char *str = gw->str;
			if (grep->icase) {
				r_str_case (str, false);
			}
			const char *p = r_strstr_ansi (in, gw->str);
			if (!p) {
				hit = gw->neg;
				all_hits &= hit;
				continue;
			}
			hit = gw->begin
				? gw->neg
					? p != in
					: p == in
				: !gw->neg;

			// TODO: optimize without strlen without breaking t/feat_grep (grep end)
			if (gw->end && (strlen (gw->str) != strlen (p))) {
				hit = false;
			}
			all_hits &= hit;
			if (!grep->amp) {
				break;
			}
		}
		if (grep->amp) {
			hit = all_hits;
		}
	} else {
		hit = true;
	}

	RConsContext *ctx = r_cons_context ();
	if (hit) {
		if (!grep->range_line) {
			if (grep->line == cons->lines) {
				use_tok = true;
			}
		} else if (grep->range_line == 1) {
			use_tok = R_BETWEEN (grep->f_line, cons->lines, grep->l_line);
		} else {
			use_tok = true;
		}
		if (use_tok && grep->tokens_used) {
			for (i = 0; i < R_CONS_GREP_TOKENS; i++) {
				tok = r_str_tok_r (i? NULL: in, delims, &save_ptr);
				if (tok) {
					if (grep->tokens[i]) {
						const size_t toklen = strlen (tok);
						memcpy (out + outlen, tok, toklen);
						memcpy (out + outlen + toklen, " ", 2);
						outlen += toklen + 1;
						if (*out == 0) {
							free (in);
							free (out);
							return -1;
						}
					}
				} else {
					if (*out) {
						break;
					}
					free (in);
					free (out);
					return 0;
				}
			}
			outlen = outlen > 0? outlen - 1: 0;
			if (outlen > len) { // should never happen
				R_LOG_ERROR ("r_cons_grep_line: wtf, how you reach this?");
				free (in);
				free (out);
				return -1;
			}
			memcpy (buf, out, len);
			len = outlen;
		}
	} else {
		len = 0;
	}
	free (in);
	free (out);
	if (grep->sort_invert && grep->sort == -1) {
		const char ch = buf[len];
		buf[len] = 0;
		if (!ctx->sorted_lines) {
			ctx->sorted_lines = r_list_newf (free);
		}
		if (!ctx->unsorted_lines) {
			ctx->unsorted_lines = r_list_newf (free);
		}
		r_list_append (ctx->sorted_lines, strdup (buf));
		buf[len] = ch;
	} else if (grep->sort != -1) {
		const char ch = buf[len];
		buf[len] = 0;
		if (!ctx->sorted_lines) {
			ctx->sorted_lines = r_list_newf (free);
		}
		if (!ctx->unsorted_lines) {
			ctx->unsorted_lines = r_list_newf (free);
		}
		RList *target = (cons->lines >= grep->sort_row)?
			ctx->sorted_lines: ctx->unsorted_lines;
		r_list_append (target, strdup (buf));
		buf[len] = ch;
	}

	return len;
}

R_API void r_cons_grep(const char *grep) {
	R_RETURN_IF_FAIL (grep);
	r_cons_grep_expression (grep);
	r_cons_grepbuf ();
}

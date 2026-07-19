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
	" :}",       "", "indent C code honoring braces",
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
	" [-n]",     "", "show only column n from the end",
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

static void grep_word_free(RConsGrepWord *gw) {
	if (gw) {
		free (gw->str);
		free (gw);
	}
}

static bool grep_token_parse_columns(RCons *cons, RConsGrep *grep, char *str);

R_API void r_cons_grep_help(RCons *cons) {
	r_cons_cmd_help (cons, help_detail_tilde, true);
}

static void grep_parse_range(RCons *cons, RConsGrep *grep, char *token) {
	char *sep = strstr (token, "..");
	if (sep) {
		*sep = '\0';
	}
	int first = *token? r_num_get (cons->num, token): 0;
	int last = sep? (sep[2]? r_num_get (cons->num, sep + 2): 0): first + 1;
	int begin = grep->range_line != 2? grep->f_line: 0;
	int end = grep->range_line != 2? grep->l_line: 0;
	grep->f_line = first < 0? end + first: begin + first;
	grep->l_line = last <= 0? end + last: begin + last;
	if (end && ((end < 0) == (grep->l_line < 0))) {
		grep->l_line = R_MIN (end, grep->l_line);
	}
	grep->range_line = 1;
}

R_API void r_cons_grep_expression(RCons *cons, const char *str) {
	if (R_STR_ISEMPTY (str)) {
		return;
	}
	RConsContext *ctx = cons->context;
	RConsGrep *grep = &ctx->grep;
	char *buf = strdup (str);
	if (!buf) {
		R_LOG_ERROR ("r_cons_grep: cannot allocate buffer");
		return;
	}
	size_t buf_len = strlen (buf);
	if (buf[buf_len - 1] == '?') {
		grep->counter = 1;
		buf[buf_len - 1] = '\0';
	}

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
	if (!grep->strings) {
		grep->strings = r_list_newf ((RListFree)grep_word_free);
	}
	grep->range_line = 2; // there is no :
	int range_stage = -1;
	int token_stage = -1;
	for (i = 0; i < ptrs_length; i++) {
		bool gw_begin = false;
		bool gw_neg = false;
		bool gw_end = false;
		bool gw_amp = false;
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
				} else if (ptr[1] == '}') { // ":}"
					grep->codindent = true;
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
					ptr++;
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
					ptr++;
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
				ptr = r_str_trim_head_digits (ptr);
				if (*ptr == ':') {
					ptr++;
					grep->sort_row = atoi (ptr);
					ptr = r_str_trim_head_digits (ptr);
				}
				break;
			case '&':
				ptr++;
				gw_amp = true;
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
					r_cons_grep_help (cons);
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

		if (ptr2 && ptr3 && ptr2 < ptr3) {
			token_stage = (int)i;
			end_ptr = ptr2;
			ptrdiff_t cols_len = ptr3 - ptr2 - 1;
			char *cols = cols_len > INT_MAX? NULL: r_str_ndup (ptr2 + 1, (int)cols_len);
			if (!cols || !grep_token_parse_columns (cons, grep, cols)) {
				ZERO_FILL (grep->tokens);
				grep->tokens_used = 0;
			}
			free (cols);
		}

		ptr2 = strchr_ns (ptr, ':'); // line number
		if (ptr2 && ptr2[1] != ':' && ptr2[1] && (isdigit (ptr2[1]) || ptr2[1] == '-' || ptr2[1] == '.')) {
			range_stage = (int)i;
			end_ptr = end_ptr ? R_MIN (end_ptr, ptr2) : ptr2;
			grep_parse_range (cons, grep, ptr2 + 1);
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
				free (s);
			}
			char *optr;
			do {
				optr = ptr;
				ptr = strchr (ptr, ','); // grep keywords
				if (ptr) {
					*ptr++ = '\0';
				}
				int wlen = strlen (optr);
				if (!wlen) {
					continue;
				}
				RConsGrepWord *gw = R_NEW0 (RConsGrepWord);
				gw->str = strdup (optr);
				gw->group = (int)i;
				gw->amp = gw_amp;
				gw->begin = gw_begin;
				gw->neg = gw_neg;
				gw->end = gw_end;
				r_list_append (grep->strings, gw);
			} while (ptr);
		}
	}
	if (range_stage >= 0 && range_stage < token_stage) {
		grep->range_line = -1;
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

// Finds and returns next intgrep expression, unescapes escaped twiddles
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
	char *p1 = find_next_intgrep (cmd, quotes);
	if (!p1) {
		return NULL;
	}
	*p1 = '\0'; // remove grep part from cmd
	char *p2;
	char *ns = NULL;
	// parse words between '~'
	while ((p2 = find_next_intgrep (p1 + 1, quotes))) {
		ns = r_str_appendlen (ns, p1 + 1, (int)(p2 - p1 - 1));
		ns = r_str_append (ns, "~");
		p1 = p2;
	}
	return r_str_append (ns, p1 + 1);
}

R_API void r_cons_grep_parsecmd(RCons *cons, char *cmd, const char *quotestr) {
	R_RETURN_IF_FAIL (cmd && quotestr);
	char *ptr = preprocess_filter_expr (cmd, quotestr);
	if (ptr) {
		r_str_trim (cmd);
		r_cons_grep_expression (cons, ptr);
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
	RCons *cons = r_cons_singleton ();
	RConsContext *ctx = cons->context;
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

#include <r_core.h>


#define GREP_TOKEN_BIAS 128
#define GREP_TOKEN_OPEN R_CONS_GREP_TOKENS

static int grep_token_pack(int begin, int end) {
	return ((begin + GREP_TOKEN_BIAS) << 16) | (end + GREP_TOKEN_BIAS);
}

static void grep_token_unpack(int token, int *begin, int *end) {
	*begin = (token >> 16) - GREP_TOKEN_BIAS;
	*end = (token & 0xffff) - GREP_TOKEN_BIAS;
}

static bool grep_token_in_bounds(int n) {
	return n >= -R_CONS_GREP_TOKENS && n < R_CONS_GREP_TOKENS;
}

static bool grep_token_parse_number(RCons *cons, const char *str, int *n) {
	if (R_STR_ISEMPTY (str)) {
		return false;
	}
	if ((*str == '-' || *str == '+') && !str[1]) {
		return false;
	}
	*n = (int)r_num_get (cons->num, str);
	return grep_token_in_bounds (*n);
}

static bool grep_token_add(RConsGrep *grep, int begin, int end) {
	if (grep->tokens_used >= R_CONS_GREP_TOKENS || !grep_token_in_bounds (begin)) {
		return false;
	}
	if (end != GREP_TOKEN_OPEN && !grep_token_in_bounds (end)) {
		return false;
	}
	grep->tokens[grep->tokens_used++] = grep_token_pack (begin, end);
	return true;
}

static char *grep_token_range_sep(char *str) {
	char *p = str;
	if (*p == '-' || *p == '+') {
		p++;
	}
	for (; *p; p++) {
		if (*p == '-') {
			return p;
		}
	}
	return NULL;
}

static bool grep_token_parse_columns(RCons *cons, RConsGrep *grep, char *str) {
	char *next = str;
	while (next) {
		char *item = next;
		char *comma = strchr (item, ',');
		if (comma) {
			*comma = '\0';
			next = comma + 1;
		} else {
			next = NULL;
		}
		r_str_trim (item);
		if (!*item) {
			continue;
		}
		int begin = 0;
		int end = 0;
		char *sep = grep_token_range_sep (item);
		if (sep) {
			*sep = '\0';
			r_str_trim (item);
			if (!grep_token_parse_number (cons, item, &begin)) {
				return false;
			}
			char *endstr = sep + 1;
			r_str_trim (endstr);
			if (*endstr) {
				if (!grep_token_parse_number (cons, endstr, &end)) {
					return false;
				}
			} else {
				end = GREP_TOKEN_OPEN;
			}
		} else {
			if (!grep_token_parse_number (cons, item, &begin)) {
				return false;
			}
			end = begin;
		}
		if (!grep_token_add (grep, begin, end)) {
			return false;
		}
	}
	return true;
}

static bool grep_token_resolve(int token, int col, int cols) {
	int begin = 0;
	int end = 0;
	grep_token_unpack (token, &begin, &end);
	begin = begin < 0 ? cols + begin : begin;
	if (end == GREP_TOKEN_OPEN) {
		end = cols - 1;
	} else {
		end = end < 0 ? cols + end : end;
	}
	return R_BETWEEN (begin, col, end);
}

static bool grep_token_selected(RConsGrep *grep, int col, int cols) {
	size_t i;
	for (i = 0; i < grep->tokens_used; i++) {
		if (grep_token_resolve (grep->tokens[i], col, cols)) {
			return true;
		}
	}
	return false;
}

static void colorcode(RCons *cons) {
	char *res = r_str_ndup (cons->context->buffer, cons->context->buffer_len);
	RConsCodeColors codepal = r_cons_codecolors (cons);
	char *cres = r_print_code_tocolor (res, &codepal);
	free (res);
	free (cons->context->buffer);
	cons->context->buffer = cres;
	cons->context->buffer_len = strlen (cres);
	cons->context->buffer_sz = cons->context->buffer_len;
}

static void grep_set_count(RCons *cons, int count) {
	RConsContext *ctx = cons->context;
	free (ctx->buffer);
	ctx->buffer = r_str_newf ("%d\n", count);
	ctx->buffer_len = ctx->buffer? strlen (ctx->buffer): 0;
	ctx->buffer_sz = ctx->buffer_len + 1;
	if (cons->num) {
		cons->num->value = count;
	}
}

R_API void r_cons_grepbuf(RCons *cons) {
	const char *buf = cons->context->buffer;
	size_t len = cons->context->buffer_len;
	RConsGrep *grep = &cons->context->grep;
	bool count_range = grep->charCounter && grep->range_line != 2;
	bool generated_range = false;
	const char *in = buf;
	int ret, l = 0, tl = 0;
	bool show = false;
	if (cons->context->filter) {
		cons->context->buffer_len = 0;
		R_FREE (cons->context->buffer);
		return;
	}
	if (grep->codindent) {
		char *sbuf = r_str_ndup (cons->context->buffer, cons->context->buffer_len);
		if (sbuf) {
			char *res = r_print_code_indent (sbuf);
			free (sbuf);
			if (res) {
				cons->context->buffer_len = strlen (res);
				cons->context->buffer_sz = cons->context->buffer_len;
				free (cons->context->buffer);
				cons->context->buffer = res;
			}
		}
		return;
	}
	if (grep->colorcode) {
		colorcode (cons);
		grep->sort = 0;
		grep->code = false;
		return;
	}
	if (grep->code) {
		char *sbuf = r_str_ndup (cons->context->buffer, cons->context->buffer_len);
		if (sbuf) {
			char *res = r_str_tokenize_json (sbuf);
			if (!res) {
				free (sbuf);
				return;
			}
			char *nres = r_print_json_indent (res, I(context->color_mode), "  ", NULL);
			free (res);
			free (sbuf);
			if (nres) {
				nres = r_str_append (nres, "\n");
				free (cons->context->buffer);
				cons->context->buffer = nres;
				cons->context->buffer_len = strlen (nres);
				cons->context->buffer_sz = cons->context->buffer_len;
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
		char *sbuf = r_str_ndup (cons->context->buffer, cons->context->buffer_len);
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
		char *out = r_str_scale (in, grep->zoom * 2, grep->zoomy? grep->zoomy: grep->zoom);
		if (out) {
			free (cons->context->buffer);
			cons->context->buffer = out;
			cons->context->buffer_len = strlen (out);
			cons->context->buffer_sz = cons->context->buffer_len;
		}
		grep->zoom = 0;
		grep->zoomy = 0;
		return;
	}
	if (grep->gron) {
		RJson *node = r_json_parsedup (cons->context->buffer);
		RStrBuf *sb = r_strbuf_new ("");
		gron (sb, node, "json");
		char *s = r_strbuf_drain (sb);
		r_json_free (node);
		R_FREE (cons->context->buffer);
		cons->context->buffer_len = 0;
		cons->context->buffer_sz = 0;
		r_cons_print (cons, s);
		in = buf = cons->context->buffer;
		len = cons->context->buffer_len;
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
		cons->context->buffer_sz = len + 1;
		free (x);
		return;
	}
	if (grep->json) {
		if (grep->json_path) {
			char *u = sdb_json_get_str (cons->context->buffer, grep->json_path);
			if (u) {
				free (cons->context->buffer);
				cons->context->buffer = u;
				cons->context->buffer_len = strlen (u);
				cons->context->buffer_sz = cons->context->buffer_len + 1;
				grep->json = false;
				r_cons_newline (cons);
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
			char *bb = r_str_ndup (buf, len);
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
			cons->context->grep_color = false;
			if (grep->hud) {
				grep->hud = false;
				r_cons_hud_string (cons, cons->context->buffer);
				return;
			}
			if (grep->less) {
				grep->less = 0;
				r_cons_less_str (cons, cons->context->buffer, NULL);
				return;
			}
		}
		if (r_list_empty (grep->strings)) {
			return;
		}
		buf = cons->context->buffer;
		len = cons->context->buffer_len;
		grep->range_line = 1;
		generated_range = true;
		goto continuation;
		// cons->lines = ?? return 3;
	}
	if (grep->less) {
		int less = grep->less;
		grep->less = 0;
		if (less == 3) {
			char *res = r_cons_hud_line_string (cons, buf);
			if (res) {
				r_cons_println (cons, res);
				free (res);
			}
		} else if (less == 2) {
			char *res = r_cons_hud_string (cons, buf);
			if (res) {
				r_cons_println (cons, res);
				free (res);
			}
		} else {
			r_cons_less_str (cons, buf, NULL);
			cons->context->buffer_len = 0;
			cons->context->buffer_sz = 0;
			R_FREE (cons->context->buffer);
		}
		return;
	}
	RStrBuf *ob = NULL;
continuation:
	ob = r_strbuf_new ("");
	int char_count = 0;
	int selected_lines = 0;
	// if we modify cons->lines we should update I.context->buffer too
	cons->lines = 0;
	// resolve negative line ranges
	if (grep->range_line != 2) {
		int total_lines = 0;
		while ((int) (size_t) (in - buf) < len) {
			const char *p = strchr (in, '\n');
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
		if (grep->f_line < 0) {
			grep->f_line = total_lines + grep->f_line;
		}
		if (grep->l_line <= 0) {
			grep->l_line = total_lines + grep->l_line;
		}
	}
	bool is_range_line_grep_only = grep->range_line != 2 && grep->str && *grep->str == '\0';

	in = buf;
	while ((int) (size_t) (in - buf) < len) {
		const char *p = strchr (in, '\n');
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
				ret = r_cons_grep_line (cons, tline, tl);
				if (grep->range_line != 2) {
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
			if ((!ret && is_range_line_grep_only && !grep->tokens_used) || ret > 0) {
				if (grep->charCounter && show) {
					char_count += ret + 1;
				}
				if (show && !grep->counter) {
					if (cons->context->grep_highlight) {
						char *str = r_str_ndup (tline, ret);
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
						if (str) {
							r_strbuf_append (ob, str);
							r_strbuf_append (ob, "\n");
							free (str);
						}
					} else {
						r_strbuf_append_n (ob, tline, ret);
						r_strbuf_append (ob, "\n");
					}
				}
				selected_lines += generated_range || show;
				cons->lines++;
			} else if (!ret && is_range_line_grep_only && grep->range_line < 0) {
				cons->lines++;
			} else if (ret < 0) {
				free (tline);
				r_strbuf_free (ob);
				return;
			}
			if (grep->counter && !count_range) {
				show = false;
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
	if (grep->counter && !grep->sort_uniq) {
		grep_set_count (cons, grep->charCounter? char_count: selected_lines);
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
	}
	ob = NULL;
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
					output_lines++; \
				} \
			} \
		}
		RListIter *iter;
		char *ptr = cons->context->buffer;
		char *str;
		int output_lines = 0;
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
			cons->context->buffer_len = 0;
			INSERT_LINES (ctx->unsorted_lines);
			INSERT_LINES (ctx->sorted_lines);
			cons->context->buffer_len = (ptr - cons->context->buffer);
			cons->lines = output_lines;
			r_list_free (ctx->sorted_lines);
			ctx->sorted_lines = NULL;
			r_list_free (ctx->unsorted_lines);
			ctx->unsorted_lines = NULL;
		}
	}
	// count after uniq
	if (grep->counter && grep->sort_uniq) {
		grep_set_count (cons, grep->charCounter? cons->context->buffer_len: cons->lines);
	}
}

R_API int r_cons_grep_line(RCons *cons, char *buf, int len) {
	R_RETURN_VAL_IF_FAIL (buf && len >= 0, 0);
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
	char *out = NULL;
	memcpy (in, buf, len);
	const bool have_strings = !r_list_empty (grep->strings);

	if (have_strings) {
		if (grep->icase) {
			r_str_case (in, false);
		}
		RListIter *iter;
		RConsGrepWord *gw;
		int group = -1;
		bool group_hit = false;
		r_list_foreach (grep->strings, iter, gw) {
			if (group != gw->group) {
				if (group >= 0 && !group_hit) {
					hit = false;
					break;
				}
				group = gw->group;
				group_hit = gw->amp || gw->neg;
			}
			if (grep->icase) {
				r_str_case (gw->str, false);
			}
			const char *p = r_strstr_ansi (in, gw->str);
			bool word_hit = p != NULL;
			if (word_hit && gw->begin) {
				word_hit = p == in;
			}
			if (word_hit && gw->end) {
				word_hit = r_str_endswith (in, gw->str);
			}
			word_hit = gw->neg? !word_hit: word_hit;
			group_hit = gw->amp || gw->neg
				? group_hit && word_hit
				: group_hit || word_hit;
		}
		if (hit) {
			hit = group_hit;
		}
	} else {
		hit = true;
	}

	RConsContext *ctx = cons->context;
	if (hit) {
		if (grep->range_line != 2) {
			use_tok = R_BETWEEN (grep->f_line, cons->lines, grep->l_line);
		} else {
			use_tok = true;
		}
		if (use_tok && grep->tokens_used) {
			out = calloc (1, len + 2);
			if (!out) {
				free (in);
				return 0;
			}
			int cols_count = 0;
			while (true) {
				tok = r_str_tok_r (cols_count? NULL: in, delims, &save_ptr);
				if (!tok) {
					break;
				}
				cols_count++;
			}
			memcpy (in, buf, len);
			save_ptr = NULL;
			for (i = 0; i < cols_count; i++) {
				tok = r_str_tok_r (i? NULL: in, delims, &save_ptr);
				if (!tok) {
					break;
				}
				if (!grep_token_selected (grep, i, cols_count)) {
					continue;
				}
				const size_t toklen = strlen (tok);
				memcpy (out + outlen, tok, toklen);
				memcpy (out + outlen + toklen, " ", 2);
				outlen += toklen + 1;
			}
			if (!outlen) {
				free (in);
				free (out);
				return 0;
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

#if 0
R_API void r_cons_grep(RCons * R_NONNULL cons, const char *grep) {
	R_RETURN_IF_FAIL (grep);
	r_cons_grep_expression (cons, grep);
	r_cons_grepbuf (cons);
}
#endif

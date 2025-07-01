/* radare - LGPL - Copyright 2015-2025 - pancake */

#include <r_core.h>

// R2R db/cmd/cmd_pdc

typedef enum {
	TYPE_NONE = 0,
	TYPE_STR = 1,
	TYPE_SYM = 2
} RFindType;

static inline bool is_string(const char *x, const char *end) {
	return ((x) + 3 < end && r_str_startswith (x, "str."));
}

static inline bool is_symbol(const char *x, const char *end) {
	return ((x) + 3 < end && r_str_startswith (x, "sym."));
}

typedef struct _find_ctx {
	char *comment;
	char *left;
	char *right;
	char *linebegin;
	int leftlen;
	int rightlen;
	int leftpos;
	int leftcolor;
	int commentcolor;
	int rightcolor;
	int linecount;
	int type;
} RFindCTX;

static void swap_strings(RFindCTX *ctx) {
	char* copy = NULL;
	size_t len;
	if (!ctx->right || !ctx->left || ctx->rightlen <= 0 || ctx->leftlen <= 0) {
		return;
	}
	if (ctx->leftlen > ctx->rightlen) {
		// Left string is longer than right string
		len = ctx->leftlen;
		copy = R_NEWS (char, len);
		if (!copy) {
			return;
		}
		memmove (copy, ctx->left, len);
		memmove (ctx->left, ctx->right, ctx->rightlen);
		memset (ctx->left + ctx->rightlen, ' ', ctx->leftlen - ctx->rightlen);
		memmove (ctx->comment - ctx->leftlen + ctx->rightlen, ctx->comment, ctx->right - ctx->comment);
		memmove (ctx->right - ctx->leftlen + ctx->rightlen, copy, ctx->leftlen);
	} else if (ctx->leftlen < ctx->rightlen) {
		if (ctx->linecount < 1) {
			// Right string is longer than left string
			len = ctx->rightlen;
			copy = R_NEWS (char, len);
			if (!copy) {
				return;
			}
			memcpy (copy, ctx->right, len);
			memcpy (ctx->right + ctx->rightlen - ctx->leftlen, ctx->left, ctx->leftlen);
			memmove (ctx->comment + ctx->rightlen - ctx->leftlen, ctx->comment, ctx->right - ctx->comment);
			memmove (ctx->left + ctx->rightlen - ctx->leftlen, copy, ctx->rightlen);
		} else {
			// Special case handling
			memset (ctx->right - ctx->leftpos, ' ', ctx->leftpos);
			*(ctx->right - ctx->leftpos - 1) = '\n';
			memset (ctx->left, ' ', ctx->leftlen);
			memset (ctx->linebegin - ctx->leftlen, ' ', ctx->leftlen);
		}
	} else {
		// Equal length strings - simple swap
		len = ctx->leftlen;
		copy = R_NEWS (char, len);
		if (!copy) {
			return;
		}
		memcpy (copy, ctx->right, len);
		memcpy (ctx->right, ctx->left, len);
		memcpy (ctx->left, copy, len);
	}

	free (copy);
}

static void find_and_change(char* in, int len) {
	// just to avoid underflows.. len can't be < then len(padding).
	if (!in || len < 1) {
		return;
	}
	RFindCTX ctx = {0};
	char *end = in + len;
//	type = TYPE_NONE;
	for (ctx.linebegin = in; in < end; in++) {
		if (*in == '\n' || !*in) {
			if (ctx.type == TYPE_SYM && ctx.linecount < 1) {
				ctx.linecount++;
				ctx.linebegin = in + 1;
				continue;
			}
			if (ctx.type != TYPE_NONE && ctx.right && ctx.left && ctx.rightlen > 0 && ctx.leftlen > 0) {
				swap_strings(&ctx);
			}
			memset (&ctx, 0, sizeof (ctx));
			ctx.linebegin = in + 1;
		} else if (!ctx.comment && *in == ';' && in[1] == ' ') {
			ctx.comment = in - 1;
			ctx.comment[1] = '/';
			ctx.comment[2] = '/';
		} else if (!ctx.comment && ctx.type == TYPE_NONE) {
			if (is_string(in, end)) {
				ctx.type = TYPE_STR;
				ctx.left = in;
				while (!isspace (*(ctx.left - ctx.leftcolor))) {
					ctx.leftcolor++;
				}
				ctx.leftcolor--;
				ctx.leftpos = ctx.left - ctx.linebegin;
			} else if (is_symbol(in, end)) {
				ctx.type = TYPE_SYM;
				ctx.left = in;
				while (!isspace (*(ctx.left - ctx.leftcolor))) {
					ctx.leftcolor++;
				}
				ctx.leftcolor--;
				ctx.leftpos = ctx.left - ctx.linebegin;
			}
		} else if (ctx.type == TYPE_STR) {
			if (!ctx.leftlen && ctx.left && isspace (*in)) {
				ctx.leftlen = in - ctx.left;
			} else if (ctx.comment && *in == '"' && in[-1] != '\\') {
				if (!ctx.right) {
					ctx.right = in;
					while (!isspace (*(ctx.right - ctx.rightcolor))) {
						ctx.rightcolor++;
					}
					ctx.rightcolor--;
				} else {
					ctx.rightlen = in - ctx.right + 1;
				}
			}
		} else if (ctx.type == TYPE_SYM) {
			if (!ctx.leftlen && ctx.left && isspace (*in)) {
				ctx.leftlen = in - ctx.left + 3;
			} else if (ctx.comment && *in == '(' && isalpha (in[-1]) && !ctx.right) {
				// ok so i've found a function written in this way:
				// type = [const|void|int|float|double|short|long]
				// type fcn_name (type arg1, type arg2, ...)
				// right now 'in' points at '(', but the function name is before, so i'll go back
				// till a space is found
				// 'int print(const char*, ...)'
				ctx.right = in - 1;
				while (isalpha (*ctx.right) || *ctx.right == '_' || *ctx.right == '*') {
					ctx.right--;
				}
				// 'int print(const char*, ...)'
				// right now 'in' points at ' ' before 'p' , but there can be a return value
				// like 'int' in 'int print(const char*, ...)'.
				// so to find for example 'int' we have to go back till a space is found.
				// if a non alpha is found, then we can cut from the function name
				if (*ctx.right == ' ') {
					ctx.right--;
					while (isalpha (*ctx.right) || *ctx.right == '_' || *ctx.right == '*') {
						ctx.right--;
					}
					// moving forward since it points now to non alpha.
					ctx.right++;
				}
				while (!isspace (*(ctx.right - ctx.rightcolor))) {
					ctx.rightcolor++;
				}
				ctx.rightcolor--;
			} else if (ctx.comment && *in == ')' && in[1] != '\'') {
				ctx.rightlen = in - ctx.right + 1;
			}
		}
	}
}

#if 0
static int cmpnbbs(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	ut64 as = a->addr;
	ut64 bs = b->addr;
	return (as> bs)? -1: (as< bs)? 1: 0;
}
#endif

static RCoreHelpMessage help_msg_pdc = {
	"Usage: pdc[oj]", "", "experimental, unreliable and hacky pseudo-decompiler",
	"pdc", "", "pseudo decompile function in current offset",
	"pdca", "", "side by side comparing assembly and pseudo",
	"pdcc", "", "pseudo-decompile with C helpers around",
	"pdco", "", "show associated offset next to pseudecompiled output",
	"pdcj", "", "in json format for codemeta annotations (used by frontends like iaito)",
	NULL
};

static void unvisit(RList *visited, RAnalBlock *bb) {
	RListIter *iter;
	RAnalBlock *b;
	r_list_foreach (visited, iter, b) {
		if (b->addr == bb->addr) {
			r_list_delete (visited, iter);
			break;
		}
	}
}

static char *cleancomments(char *s) {
	// trim newline+spaces before //
	char *p = s;
	char *nl = NULL;
	int spaces = 0;
	bool ispfx = false;
	while (*p) {
		if (*p == '\n') {
			nl = p;
			spaces = 0;
			ispfx = true;
		} else if (r_str_startswith (p, "//")) {
			char *dsnl = strchr (p, '\n');
			if (r_str_startswith (p, "// goto")) {
				memmove (p, dsnl + 1, strlen (dsnl + 1) + 1);
				p = dsnl;
				continue;
			}
			if (nl && spaces > 4) {
				*nl = ' ';
				if (0) {
					char *nnl = strchr (p, '\n');
					char *port = r_str_ndup (p, nnl - p);
					R_LOG_INFO ("newline port (%s)", port);
					free (port);
				}
				memmove (nl + 1, p, strlen (p) + 1);
				p = strchr (nl + 1, '\n');
				if (!p) {
					break;
				}
				spaces = 0;
				nl = p;
			}
		} else if (*p == ' ') {
			if (ispfx) {
				spaces++;
			}
		} else {
			ispfx = false;
			spaces = 0;
		}
		p++;
	}
	// remove empty lines
	s = r_str_replace (s, "\n\n", "\n", true);
	p = s;
	while (*p) {
		char *nlnl = strstr (p, "  \n");
		if (!nlnl) {
			break;
		}
		char *prev = (char *)r_str_rchr (p, nlnl, '\n');
		if (!prev) {
			break;
		}
		memmove (prev + 1, nlnl + 3, strlen (nlnl + 3) + 1);
		p = prev + 2;
	}
	return s;
}

static char *disat(RCore *core, ut64 addr, int *pad) {
	char *s = r_core_cmd_strf (core, "pi 1 @e:scr.color=0@e:asm.pseudo=0@e:asm.addr=1@ 0x%08"PFMT64x, addr);
	r_str_trim (s);
	*pad = 30 - r_str_ansi_len (s);
	return s;
}

#define I_TAB 2
#define K_MARK(x) r_strf ("mark.%"PFMT64x,x)
#define K_ELSE(x) r_strf ("else.%"PFMT64x,x)
#define K_INDENT(x) r_strf ("loc.%"PFMT64x,x)
#define SET_INDENT(x) { (x) = (x)>0?(x):0; memset (indentstr, ' ', sizeof (indentstr)); indentstr [((x) * I_TAB)] = 0; }
R_API int r_core_pseudo_code(RCore *core, const char *input) {
	bool show_c_headers = *input == 'c';
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_pdc);
		return false;
	}
	RStrBuf *out = r_strbuf_new ("");
#define PRINTF(a, ...) {\
	if (pj) {\
		r_strbuf_appendf (codestr, a, ##__VA_ARGS__);\
	} else {\
		r_strbuf_appendf (out, a, ##__VA_ARGS__);\
	}}
#define NEWLINE(a,i) {\
	size_t eos = R_MIN ((i) * 2, sizeof (indentstr) - 2);\
	if (eos < 1) { eos = 0; }\
	memset (indentstr, ' ', sizeof (indentstr)); indentstr [(eos * 2)] = 0;\
	if (pj) {\
		if (show_asm) { int asm_pad; char *asm_str = disat (core, a, &asm_pad); \
			r_strbuf_appendf (codestr, "\n0x%08"PFMT64x" | %s%s%s", a, asm_str, r_str_pad (' ', asm_pad), indentstr); \
			free (asm_str); }\
		else if (show_addr) { r_strbuf_appendf (codestr, "\n0x%08"PFMT64x" | %s", a, indentstr); }\
		else { r_strbuf_appendf (codestr, "\n%s", indentstr); }\
	} else {\
		r_strbuf_append (out, "\n");\
		if (show_asm) { int asm_pad; char *asm_str = disat (core, a, &asm_pad); \
			r_strbuf_appendf (codestr, "XX 0x%08"PFMT64x" | %s%s%s", a, asm_str, r_str_pad (' ', asm_pad), indentstr); \
			free (asm_str); }\
		else if (show_addr) { r_strbuf_appendf (out, " 0x%08"PFMT64x" | %s", a, indentstr); }\
		else { r_strbuf_append (out, indentstr); } }\
	}
#define PRINTGOTO(y, x) if (x != UT64_MAX && y != x) { NEWLINE (x, indent); \
		if (show_asm) { PRINTF (" 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30)); }\
	PRINTF (" goto loc_0x%08"PFMT64x, x); }
	const char *cmdPdc = r_config_get (core->config, "cmd.pdc");
	if (R_STR_ISNOTEMPTY (cmdPdc) && !strstr (cmdPdc, "pdc")) {
		if (strstr (cmdPdc, "!*") || strstr (cmdPdc, "#!")) {
			if (!strcmp (input, "*")) {
				input = " -r2";
			} else if (!strcmp (input, "=")) {
				input = " -a";
			} else if (!strcmp (input, "?")) {
				input = " -h";
			}
		}
		return r_core_cmdf (core, "%s%s", cmdPdc, input);
	}
	const bool show_json = (*input == 'j');
	const bool show_asm = (*input == 'a');
	const bool show_addr = show_asm || (*input == 'o');

	Sdb *db;
	ut64 queuegoto = 0LL;
	const char *blocktype = "else";
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return false;
	}
	r_config_hold (hc, "asm.pseudo", "asm.decode", "asm.lines", "asm.bytes", "asm.stackptr", NULL);
	r_config_hold (hc, "asm.addr", "asm.flags", "asm.lines.fcn", "asm.comments", NULL);
	r_config_hold (hc, "asm.functions", "asm.section", "asm.cmt.col", "asm.sub.names", NULL);
	r_config_hold (hc, "scr.color", "emu.str", "asm.emu", "emu.write", NULL);
	r_config_hold (hc, "io.cache", "asm.syntax", NULL);
	if (!fcn) {
		R_LOG_ERROR ("Cannot find function in 0x%08"PFMT64x, core->addr);
		r_config_hold_free (hc);
		return false;
	}
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "asm.stackptr", false);
	r_config_set_b (core->config, "asm.pseudo", true);
	r_config_set_b (core->config, "asm.decode", false);
	r_config_set_b (core->config, "asm.sub.names", true);
	r_config_set_b (core->config, "asm.lines", false);
	r_config_set_b (core->config, "asm.bytes", false);
	r_config_set_b (core->config, "asm.addr", true);
	r_config_set_b (core->config, "asm.flags", false);
	r_config_set_b (core->config, "asm.emu", true);
	r_config_set_b (core->config, "emu.str", true);
	r_config_set_b (core->config, "emu.write", true);
	r_config_set_b (core->config, "asm.lines.fcn", false);
	r_config_set_b (core->config, "asm.comments", true);
	r_config_set_b (core->config, "asm.functions", false);
	r_config_set_i (core->config, "asm.tabs", 0);
	r_config_set_b (core->config, "asm.section", false);
	r_config_set_i (core->config, "asm.cmt.col", 30);
	r_config_set_b (core->config, "io.cache", true);
	r_config_set (core->config, "asm.syntax", "intel");
	r_core_cmd0 (core, "aeim");

	r_strf_buffer (64);
	RStrBuf *codestr = r_strbuf_new ("");
	db = sdb_new0 ();
	// walk all basic blocks
	// define depth level for each block
	// use it for indentation
	// asm.pseudo=true
	// asm.decode=true
	RAnalBlock *bb = r_list_first (fcn->bbs);
	char indentstr[1024] = {0};
	int indent = 0;
	int nindent = 1;
	// XXX sorting basic blocks is nice for the reader, but introduces conceptual problems
	// when the entrypoint is not starting at the lowest address. // r_list_sort (fcn->bbs, cmpnbbs);
	int n_bb = r_list_length (fcn->bbs);
	PJ *pj = NULL;
	if (show_json) {
		pj = r_core_pj_new (core);
		pj_o (pj);
		pj_ka (pj, "annotations");
	}
	const char *cc = fcn->callconv ? fcn->callconv: "default";
	const char *cc_a0 = r_anal_cc_arg (core->anal, cc, 0, -1);
	const char *cc_a1 = r_anal_cc_arg (core->anal, cc, 1, -1);
	const char *a0 = cc_a0? cc_a0: r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_A0);
	const char *a1 = cc_a1? cc_a1: r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_A1);
	const char *r0 = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_R0);
	if (show_c_headers) {
		// NEWLINE (fcn->addr, indent);
		PRINTF ("// global registers\n");
		// only print the used registers
		PRINTF ("int stack[1024];\n");
		PRINTF ("unsigned long long *qword = &stack;\n");
		PRINTF ("unsigned int *dword = &stack;\n");
		PRINTF ("unsigned short *word = &stack;\n");
		PRINTF ("unsigned char *byte = &stack;\n");
		PRINTF ("int %s, %s;\n", a0, a1);
		PRINTF ("// This function contains %d basic blocks and its %d long.",
			n_bb, (int)r_anal_function_realsize (fcn));
		NEWLINE (fcn->addr, indent);
		const char *S0 = "esp";
		PRINTF ("static inline void push(int reg) {%s -= %d; stack[%s] = reg; }\n", S0, (int)sizeof (int), S0);
		PRINTF ("static inline int pop() {int r = stack[%s]; %s += %d; return r; }\n", S0, S0, (int)sizeof (int));
		PRINTF ("\n");
	}

	char *fs = r_core_cmd_strf (core, "afs@0x%08"PFMT64x, fcn->addr);
	{
		char *cc = r_core_cmd_strf (core, "afci@0x%08"PFMT64x, fcn->addr);
		r_str_trim (cc);
		if (show_addr || show_asm) {
			PRINTF (" 0x%08"PFMT64x " | %s | ", fcn->addr, r_str_pad (' ', 30));
		}
		if (R_STR_ISNOTEMPTY (cc)) {
			PRINTF ("// callconv: %s\n", cc);
		}
		free (cc);
	}
	if (show_addr || show_asm) {
		PRINTF (" 0x%08"PFMT64x " | %s | ", fcn->addr, r_str_pad (' ', 30));
	}
	if (R_STR_ISEMPTY (fs) || (r_str_startswith (fs, "void") && strstr (fs, "()"))) {
		if (!strcmp (a0, a1)) {
			PRINTF ("int %s (int %s) {", fcn->name, a0);
		} else {
			PRINTF ("int %s (int %s, int %s) {", fcn->name, a0, a1);
		}
	} else {
		r_str_replace_char (fs, ';', ' ');
		r_str_trim (fs);
		PRINTF ("%s {", fs);
	}
	free (fs);
	indent++;
	RList *visited = r_list_newf (NULL);
	ut64 addr = fcn->addr;
	while (bb) {
		r_list_append (visited, bb);
		r_cons_push (core->cons);
		bool html = r_config_get_b (core->config, "scr.html");
		r_config_set_b (core->config, "scr.html", false);
		char *code = r_core_cmd_str (core, r_strf ("pD %"PFMT64d" @ 0x%08"PFMT64x, bb->size, bb->addr));
		r_cons_pop (core->cons);
		r_config_set_b (core->config, "scr.html", html);
		indent = 2;

		if (R_STR_ISEMPTY (code)) {
			free (code);
			R_LOG_ERROR ("Empty code here");
			break;
		}
		// SET_INDENT (indent);
		// PRINTF ("\n---\n");
		code = r_str_replace (code, "\n\n", "\n", true);
		code = r_str_replace (code, ";", "//", true);
		code = cleancomments (code);
		size_t len = strlen (code);
		if (len < 1) {
			free (code);
			R_LOG_ERROR ("Empty code here");
			break;
		}
		code[len - 1] = 0; // chop last newline
		find_and_change (code, len);
		if (!sdb_const_get (db, K_MARK (bb->addr), 0)) {
			bool mustprint = !queuegoto || queuegoto != bb->addr || bb->jump == bb->addr;
			if (mustprint) {
				if (queuegoto && queuegoto != UT64_MAX) {
					// NEWLINE (bb->addr, indent);
					// PRINTF ("3goto loc_0x%"PFMT64x, queuegoto);
					queuegoto = 0LL;
				}
				NEWLINE (bb->addr, indent - 1);
				if (show_asm) {
					PRINTF (" 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
				}
				PRINTF ("loc_0x%08"PFMT64x":", bb->addr);
				// foreach lines
				RList *lines = r_str_split_list (code, "\n", 0);
				RListIter *iter;
				const char *line;
				addr = bb->addr;
				r_list_foreach (lines, iter, line) {
					if (*line == '0') {
						ut64 at = r_num_get (NULL, line);
						if (at && at != UT64_MAX) {
							addr = at;
						}
						char *s = strchr (line, ' ');
						if (s) {
							line = r_str_trim_head_ro (s + 1);
						} else {
							line = "";
						}
					}
					if (pj) {
						pj_o (pj);
						pj_kn (pj, "start", r_strbuf_length (codestr));
						pj_kn (pj, "end", r_strbuf_length (codestr));
						pj_kn (pj, "offset", addr);
						pj_ks (pj, "type", "offset");
						pj_end (pj);
					}
					if (R_STR_ISNOTEMPTY (line)) {
						NEWLINE (addr, indent);
						if (show_asm) {
							// OK
							ut64 at = addr;
							int asm_pad; char *asm_str = disat (core, at, &asm_pad);
							char *newline = r_str_newf (" 0x%08"PFMT64x" | %s%s | %s",
									at, asm_str, r_str_pad (' ', asm_pad), line);
							PRINTF ("%s", newline);
							free (newline);
						} else {
							PRINTF ("%s", line);
						}
					}
				}
				r_list_free (lines);
				free (code);
				sdb_num_set (db, K_MARK (bb->addr), 1, 0);
			}
		}
		bool closed = false;
		ut64 gotoaddr = UT64_MAX;
		if (bb->fail == UT64_MAX) {
			if (bb->jump != UT64_MAX) {
#if 1
				gotoaddr = bb->jump;
				// PRINTGOTO (UT64_MAX, bb->jump);
#endif
			} else {
				closed = true;
#if 0
				NEWLINE (bb->addr, indent);
				PRINTF ("return; ");
#endif
			}
		} else {
			NEWLINE (bb->addr, indent);
			if (show_asm) {
				PRINTF (" 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
			}
			PRINTF ("goto loc_0x%08"PFMT64x";", bb->fail);
		}
		if (sdb_const_get (db, K_INDENT (bb->addr), 0)) {
			// already analyzed, go pop and continue
			// XXX check if can't pop
			unvisit (visited, bb);
			R_LOG_DEBUG ("%s// 0x%08"PFMT64x" already analyzed", indentstr, bb->addr);
			ut64 addr = sdb_array_pop_num (db, "indent", NULL);
			if (addr == UT64_MAX) {
				nindent = 1;
#if 0
				int i;
				for (i = indent; i != nindent && i > 0; i--) {
					NEWLINE (bb->addr, i);
				//	PRINTF ("}");
					closed = true;
				}
#else
				closed = true;
#endif
				if (closed) {
					NEWLINE (bb->addr, indent);
					if (show_asm) {
						PRINTF (" 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
					}
					if (r0) {
						PRINTF ("return %s;", r0);
					} else {
						PRINTF ("return;");
					}
#if 0
					if (show_asm) {
						NEWLINE (bb->addr, indent);
						PRINTF (" 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
					}
#endif
				} else if (bb->fail != UT64_MAX) {
					NEWLINE (bb->addr, indent);
					if (show_asm) {
						PRINTF (" 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
					}
					PRINTF ("goto loc_0x%08"PFMT64x";", bb->fail);
				}
				RAnalBlock *nbb = r_anal_bb_from_offset (core->anal, bb->fail);
				if (r_list_contains (visited, nbb)) {
					nbb = r_anal_bb_from_offset (core->anal, bb->jump);
					if (bb->jump == bb->addr) {
						R_LOG_DEBUG ("Basic block loop found at 0x%08"PFMT64x, bb->jump);
						if (r_list_contains (visited, nbb)) {
							break;
						}
						r_list_append (visited, nbb);
					} else if (r_list_contains (visited, nbb)) {
						nbb = NULL;
					}
				}
				if (!nbb) {
					break;
				}
				PRINTGOTO (nbb->addr, gotoaddr);
				bb = nbb;
				indent--;
				continue;
			}
#if 0
			if (sdb_num_get (db, K_ELSE (bb->addr), 0)) {
				NEWLINE (addr, indent);
				if (!strcmp (blocktype, "else")) {
					PRINTF (" // %s", blocktype);
				} else {
					PRINTF (" // %s ();", blocktype);
				}
			}
#endif
			if (addr != bb->addr) {
				queuegoto = addr;
				// r_cons_printf ("\n%s  goto loc_0x%"PFMT64x, indentstr, addr);
			}
			bb = r_anal_bb_from_offset (core->anal, addr);
			if (!bb) {
				R_LOG_ERROR ("failed block");
				break;
			}
			nindent = sdb_num_get (db, K_INDENT (addr), NULL);
			if (indent > nindent && !strcmp (blocktype, "else")) {
				int i;
				for (i = indent; i != nindent; i--) {
					NEWLINE (addr, i);
					PRINTF ("}");
				}
			}
			indent = nindent - 1;
		} else {
			sdb_set (db, K_INDENT (bb->addr), "passed", 0);
			if (bb->jump != UT64_MAX) {
				int swap = 1;
				// TODO: determine which branch take first
				ut64 jump = swap ? bb->jump : bb->fail;
				ut64 fail = swap ? bb->fail : bb->jump;
				// if its from another function chop it!
				RAnalFunction *curfcn = r_anal_get_fcn_in (core->anal, jump, R_ANAL_FCN_TYPE_NULL);
				if (curfcn != fcn) {
					// chop that branch
					NEWLINE (jump, indent);
					PRINTF ("// chop");
					// break;
				}
				if (sdb_get (db, K_INDENT (jump), 0)) {
					// already tracekd
					if (!sdb_get (db, K_INDENT (fail), 0)) {
						bb = r_anal_bb_from_offset (core->anal, fail);
					} else {
						R_LOG_ERROR ("pdc: unknown branch from 0x%08"PFMT64x, jump);
					}
				} else {
					bb = r_anal_bb_from_offset (core->anal, jump);
					if (!bb) {
						R_LOG_ERROR ("Failed to retrieve block at 0x%"PFMT64x, jump);
						break;
					}
					if (fail != UT64_MAX) {
						// do not push if already pushed
						indent++;
						if (sdb_get (db, K_INDENT (bb->fail), 0)) {
							/* do nothing here */
							R_LOG_DEBUG ("There's already a block at 0x%"PFMT64x, bb->addr);
						} else {
							// r_cons_printf (" { RADICAL %llx\n", bb->addr);
							sdb_array_push_num (db, "indent", fail, 0);
							sdb_num_set (db, K_INDENT (fail), indent, 0);
							sdb_num_set (db, K_ELSE (fail), 1, 0);
				//			NEWLINE (bb->addr, indent);
						}
					} else {
						sdb_array_push_num (db, "indent", jump, 0);
						sdb_num_set (db, K_INDENT (jump), indent, 0);
						sdb_num_set (db, K_ELSE (jump), 1, 0);
						if (jump <= bb->addr) {
							blocktype = "while";
						} else {
							blocktype = "else";
						}
						NEWLINE (bb->addr, indent);
						// PRINTF ("do {");
						indent++;
						indent++;
					}
				}
			} else if (!closed) {
				ut64 addr = sdb_array_pop_num (db, "indent", NULL);
				if (addr == UT64_MAX) {
					NEWLINE (bb->addr, indent);
					PRINTF ("break;");
					break;
				}
				bb = r_anal_bb_from_offset (core->anal, addr);
				nindent = sdb_num_get (db, K_INDENT (addr), NULL);
				if (indent > nindent) {
					int i;
					for (i = indent; i != nindent; i--) {
						NEWLINE (bb->addr, i);
						PRINTF ("}");
					}
				}
				PRINTF ("goto loc_0x%08"PFMT64x";", bb->fail);
#if 0
				if (nindent != indent) {
					NEWLINE (bb->addr, indent);
					PRINTF ("} else {");
				}
#endif
				indent = nindent;
			}
			if (bb) {
				PRINTGOTO (bb->addr, gotoaddr);
			} else {
				PRINTGOTO (UT64_MAX, gotoaddr);
			}
		}
	}
	RListIter *iter;
	bool use_html = r_config_get_b (core->config, "scr.html");
	r_list_foreach (fcn->bbs, iter, bb) {
		if (r_list_contains (visited, bb)) {
			continue;
		}
		ut64 nextbbaddr = UT64_MAX;
		if (iter->n) {
			RListIter *nit = (RListIter*)(iter->n);
			RAnalBlock *nbb = (RAnalBlock*)(nit->data);
			nextbbaddr = nbb->addr;
		}
		if (use_html) {
			r_config_set_b (core->config, "scr.html", false);
		}
		char *s = r_core_cmd_strf (core, "pdb@0x%08"PFMT64x"@e:asm.addr=%d", bb->addr, show_addr);
		if (use_html) {
			r_config_set_b (core->config, "scr.html", true);
		}
		s = r_str_replace (s, ";", "//", true);
#if 0
		char *lastgoto = strstr (s, "goto ");
		if (lastgoto) {
			if (!strchr (lastgoto, '\n')) {
				*s = 0;
			}
		}
#endif
		s = r_str_replace (s, "goto ", "// goto loc_", true);
		s = cleancomments (s);
		if (show_asm) {
			RList *rows = r_str_split_list (s, "\n", 0);
			char *row;
			RStrBuf *sb = r_strbuf_new ("");
			RListIter *iter;
			ut64 oldat = 0;
			r_list_foreach (rows, iter, row) {
				if (R_STR_ISEMPTY (row)) {
					continue;
				}
				ut64 at = r_num_math (NULL, row);
				if (!at) {
					at = oldat;
				}
				oldat = at;
				char *space = strchr (row, ' ');
				if (space) {
					row = (char *)r_str_trim_head_ro (space + 1);
				}
				int asm_pad; char *asm_str = disat (core, at, &asm_pad);
				r_strbuf_appendf (sb, " 0x%08"PFMT64x" | %s%s | %s\n",
					at, asm_str, r_str_pad (' ', asm_pad), row);
				free (asm_str);
			}
			free (s);
			r_list_free (rows);
			s = r_strbuf_drain (sb);
		} else if (show_addr) {
			// indent with | or stgh
			char *os = r_str_prefix_all (s, " ");
			free (s);
			s = os;
		} else {
			int eos = indent;
			memset (indentstr, ' ', sizeof (indentstr)); indentstr [(eos * 2)] = 0;
			char *os = r_str_prefix_all (s, indentstr);
			free (s);
			s = os;
		}
		size_t codelen = r_strbuf_length (codestr);
		if (pj) {
			pj_o (pj);
			pj_kn (pj, "start", codelen);
			r_strbuf_append (codestr, s);
			pj_kn (pj, "end", codelen);
			pj_kn (pj, "offset", addr);
			pj_ks (pj, "type", "offset");
			pj_end (pj);
		} else {
			r_strbuf_append (codestr, s);
			// PRINTF ("goto loc_0x%"PFMT64x";", bb->fail);
		}
		if (codelen > 0) {
			if (show_asm) {
				ut64 a = bb->addr;
				int asm_pad; char *asm_str = disat (core, a, &asm_pad);
				r_strbuf_appendf (codestr, "\n 0x%08"PFMT64x" | %s%s%s", a, asm_str, r_str_pad (' ', asm_pad), indentstr);
				free (asm_str);
			} else if (show_addr) {
				r_strbuf_appendf (out, "\n 0x%08"PFMT64x" | ", bb->addr);
			} else {
				NEWLINE (bb->addr, 1);
			}
			RFlagItem *fi = r_flag_get_in (core->flags, bb->addr);
			if (show_asm) {
				r_strbuf_appendf (codestr, "\n0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
			}
			if (fi && r_str_startswith (fi->name, "case.")) {
				const char *val = r_str_lchr (fi->name, '.') + 1;
				char *hex = r_str_newf ("0x%s", val);
				int nval = r_num_get (NULL, hex);
				free (hex);
				if (IS_PRINTABLE (nval)) {
					PRINTF ("loc_0x%08"PFMT64x": // case '%c'\n%s", bb->addr, nval, s);
				} else {
					PRINTF ("loc_0x%08"PFMT64x": // case %s\n%s", bb->addr, val, s);
				}
			} else {
				PRINTF ("loc_0x%08"PFMT64x": // orphan\n%s", bb->addr, s);
			}
			ut64 nbbaddr = nextbbaddr; // UT64_MAX;
#if 0
			eprintf ("iter %p %p\n", iter, iter->n);
			if (nextbbaddr) {
			}
			if (iter->n) {
				RAnalBlock *nbb = (RAnalBlock*)(iter->n);
				nbbaddr = nbb->addr;
			}
#endif
			if (bb->jump == UT64_MAX) {
				NEWLINE (bb->addr, indent);
				if (show_asm) {
					PRINTF (" 0x%08"PFMT64x" | ret%s | ", bb->addr, r_str_pad (' ', 30 -3));
				}
				if (r0) {
					PRINTF ("return %s;", r0);
				} else {
					PRINTF ("return;");
				}
				if (show_asm) {
					PRINTF ("\n 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
				}
			} else {
				PRINTGOTO (nbbaddr, bb->jump);
			}
		}
		free (s);
	}
	r_list_free (visited);
	indent = 0;
	NEWLINE (addr, indent);
	if (show_asm) {
		PRINTF ("\n 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
	}
	PRINTF ("}\n");
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	if (pj) {
		pj_end (pj);
		char *kode = r_strbuf_drain (codestr);
		pj_ks (pj, "code", kode);
		pj_end (pj);
		char *j = pj_drain (pj);
		r_cons_printf (core->cons, "%s\n", j);
		free (kode);
		free (j);
		r_strbuf_free (out);
	} else {
		char *s = r_strbuf_drain (out);
		if (r_config_get_i (core->config, "scr.color") > 0) {
			char *ss = r_print_code_tocolor (s);
			free (s);
			s = ss;
		}
		r_cons_printf (core->cons, "%s\n", s);
		free (s);
		r_strbuf_free (codestr);
	}
	sdb_free (db);
	return true;
}

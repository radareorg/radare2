/* radare - LGPL - Copyright 2015-2025 - pancake */

#include <r_core.h>

// R2R db/cmd/cmd_pdc

// Structure to hold state for decompilation
typedef struct {
	RCore *core;
	RStrBuf *out;
	RStrBuf *codestr;
	PJ *pj;
	bool show_asm;
	bool show_addr;
	Sdb *goto_cache;  // Cache to avoid duplicate goto statements
	Sdb *db;          // General purpose DB for the algorithm
	RAnalFunction *fcn;
	char indentstr[1024];
} PDCState;

typedef enum {
	TYPE_NONE = 0,
	TYPE_STR = 1,
	TYPE_SYM = 2
} RFindType;

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

static inline bool is_string(const char *x, const char *end) {
	return ((x) + 3 < end && r_str_startswith (x, "str."));
}

static inline bool is_symbol(const char *x, const char *end) {
	return ((x) + 3 < end && r_str_startswith (x, "sym."));
}

static void set_left_token(RFindCTX *ctx, char *token) {
	ctx->left = token;
	while (!isspace (*(ctx->left - ctx->leftcolor))) {
		ctx->leftcolor++;
	}
	ctx->leftcolor--;
	ctx->leftpos = ctx->left - ctx->linebegin;
}

static void set_right_token(RFindCTX *ctx, char *token) {
	ctx->right = token;
	while (!isspace (*(ctx->right - ctx->rightcolor))) {
		ctx->rightcolor++;
	}
	ctx->rightcolor--;
}

static void set_left_length(RFindCTX *ctx, const char *in, int extra) {
	if (!ctx->leftlen && ctx->left && isspace(*in)) {
		ctx->leftlen = in - ctx->left + extra;
	}
}

static void set_right_length(RFindCTX *ctx, const char *in, int extra) {
	if (ctx->right) {
		ctx->rightlen = in - ctx->right + extra;
	}
}

static void find_function_name(RFindCTX *ctx, const char *in) {
	if (!ctx->comment || *in != '(' || !isalpha(in[-1]) || ctx->right) {
		return;
	}

	// Navigate back to find function name
	ctx->right = (char *)(in - 1);
	while (isalpha(*ctx->right) || *ctx->right == '_' || *ctx->right == '*') {
		ctx->right--;
	}

	// Handle return type if present
	if (*ctx->right == ' ') {
		ctx->right--;
		while (isalpha(*ctx->right) || *ctx->right == '_' || *ctx->right == '*') {
			ctx->right--;
		}
		// Move back to start of function name
		ctx->right++;
	}

	// Set color offset for the right token
	set_right_token(ctx, ctx->right);
}

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
				set_left_token(&ctx, in);
			} else if (is_symbol(in, end)) {
				ctx.type = TYPE_SYM;
				set_left_token(&ctx, in);
			}
		} else if (ctx.type == TYPE_STR) {
			set_left_length(&ctx, in, 0);
			if (ctx.comment && *in == '"' && in[-1] != '\\') {
				if (!ctx.right) {
					set_right_token(&ctx, in);
				} else {
					set_right_length(&ctx, in, 1);
				}
			}
		} else if (ctx.type == TYPE_SYM) {
			set_left_length(&ctx, in, 3);
			if (ctx.comment && *in == '(' && isalpha (in[-1]) && !ctx.right) {
				// Handle function definition format: "type fcn_name(args)"
				find_function_name(&ctx, in);
			} else if (ctx.comment && *in == ')' && in[1] != '\'') {
				set_right_length(&ctx, in, 1);
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

static void handle_goto_comments(char **p) {
	if (r_str_startswith(*p, "// goto")) {
		char *dsnl = strchr(*p, '\n');
		if (dsnl) {
			memmove(*p, dsnl + 1, strlen(dsnl + 1) + 1);
			*p = dsnl;
		}
	}
}

static void handle_indented_comments(char **p, char *nl, int spaces) {
	if (nl && spaces > 4) {
		*nl = ' ';
		memmove(nl + 1, *p, strlen(*p) + 1);
		*p = strchr(nl + 1, '\n');
	}
}

static void remove_double_spaces(char *s) {
	char *p = s;
	while (*p) {
		char *nlnl = strstr (p, "  \n");
		if (!nlnl) {
			break;
		}
		char *prev = (char *)r_str_rchr(p, nlnl, '\n');
		if (!prev) {
			break;
		}
		memmove(prev + 1, nlnl + 3, strlen(nlnl + 3) + 1);
		p = prev + 2;
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
		} else if (r_str_startswith(p, "//")) {
			if (r_str_startswith(p, "// goto")) {
				handle_goto_comments(&p);
				continue;
			}
			handle_indented_comments(&p, nl, spaces);
			if (!p) {
				break;
			}
			spaces = 0;
			nl = p;
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
	s = r_str_replace(s, "\n\n", "\n", true);
	remove_double_spaces(s);
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

// Function declarations
static void print_str(PDCState *state, const char *fmt, ...);
static void print_newline(PDCState *state, ut64 addr, int indent);
static void print_goto(PDCState *state, RAnalBlock *bb, ut64 dst_addr, ut64 curr_addr, int indent);
static void print_goto_direct(PDCState *state, RAnalBlock *bb, ut64 dst_addr, ut64 curr_addr, int indent);

// Function implementations
static void print_str(PDCState *state, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	if (state->pj) {
		r_strbuf_vappendf (state->codestr, fmt, ap);
	} else {
		r_strbuf_vappendf (state->out, fmt, ap);
	}
	va_end(ap);
}

static void print_newline(PDCState *state, ut64 addr, int indent) {
	size_t indentstr_size = sizeof (state->indentstr);
	size_t eos = R_MIN (indent * 2, indentstr_size - 2);
	if (eos < 1) {
		eos = 0;
	}

	memset (state->indentstr, ' ', indentstr_size);
	size_t eospos = R_MIN (sizeof (state->indentstr) - 1, eos * 2);
	state->indentstr[eospos] = '\0';

	if (state->pj) {
		if (state->show_asm) {
			int asm_pad;
			char *asm_str = disat(state->core, addr, &asm_pad);
			r_strbuf_appendf (state->codestr, "\n0x%08"PFMT64x" | %s%s%s", addr, asm_str, r_str_pad(' ', asm_pad), state->indentstr);
			free (asm_str);
		} else if (state->show_addr) {
			r_strbuf_appendf (state->codestr, "\n0x%08"PFMT64x" | %s", addr, state->indentstr);
		} else {
			r_strbuf_appendf (state->codestr, "\n%s", state->indentstr);
		}
	} else {
		r_strbuf_append(state->out, "\n");
		if (state->show_asm) {
			int asm_pad;
			char *asm_str = disat(state->core, addr, &asm_pad);
			r_strbuf_appendf (state->out, "0x%08"PFMT64x" | %s%s%s", addr, asm_str, r_str_pad(' ', asm_pad), state->indentstr);
			free (asm_str);
		} else if (state->show_addr) {
			r_strbuf_appendf (state->out, " 0x%08"PFMT64x" | %s", addr, state->indentstr);
		} else {
			r_strbuf_append(state->out, state->indentstr);
		}
	}
}

static void print_goto(PDCState *state, RAnalBlock *bb, ut64 dst_addr, ut64 curr_addr, int indent) {
	// Early exit checks:
	// 1. Invalid destination address (UT64_MAX)
	// 2. Self-referential goto (destination equals current address)
	if (dst_addr == UT64_MAX || curr_addr == dst_addr) {
		return;
	}

	// Create keys for tracking different patterns of duplication
	// Track source address -> destination address (prevents same goto from same bb)
	char *src_dst_key = r_str_newf ("%"PFMT64x".to.%"PFMT64x, bb->addr, dst_addr);
	// Track curr_addr -> destination (prevents multiple gotos at same address)
	char *addr_dst_key = r_str_newf ("%"PFMT64x".to.%"PFMT64x, curr_addr, dst_addr);
	// Create a unique key for just this destination
	char *dst_key = r_str_newf ("%"PFMT64x, dst_addr);
	// Create a mark key for checking if this destination is already marked
	char *mark_key = r_str_newf ("mark.%"PFMT64x, dst_addr);
	// Check if we've already printed a goto from this source address
	char *src_key = r_str_newf ("%"PFMT64x".src", curr_addr);
	// Check if we've already printed a return statement for this block
	char *return_key = r_str_newf ("return.%"PFMT64x, bb->addr);

	// Don't print goto if:
	// 1. We've already printed a goto from this exact source to this exact destination, OR
	// 2. We've already printed a goto from the current address, OR
	// 3. We've already printed a goto with this current address to this destination, OR
	// 4. The destination already has a label (marked as a location we've seen), OR
	// 5. We've already printed a return statement for this block
	if (!sdb_exists (state->goto_cache, src_dst_key) &&
	    !sdb_exists (state->goto_cache, addr_dst_key) &&
	    !sdb_exists (state->goto_cache, src_key) &&
	    !sdb_const_get(state->db, mark_key, 0) &&
	    !sdb_exists (state->goto_cache, return_key)) {
		// Mark all our tracking keys to prevent duplicates
		sdb_set (state->goto_cache, src_dst_key, "1", 0);
		sdb_set (state->goto_cache, addr_dst_key, "1", 0);
		sdb_set (state->goto_cache, src_key, "1", 0);
		sdb_set (state->goto_cache, dst_key, "1", 0);

		// Only print if this isn't a self-referential goto (which would be useless)
		if (dst_addr != bb->addr) {
			print_newline (state, curr_addr, indent);
			if (state->show_asm) {
				print_str (state, " 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad(' ', 30));
			}
			print_str (state, " goto loc_0x%08"PFMT64x, dst_addr);
		}
	}

	// Free all allocated keys
	free (src_dst_key);
	free (addr_dst_key);
	free (dst_key);
	free (mark_key);
	free (src_key);
	free (return_key);
}

// Helper function for direct goto prints with semicolon
static void print_goto_direct(PDCState *state, RAnalBlock *bb, ut64 dst_addr, ut64 curr_addr, int indent) {
	// Skip invalid addresses
	if (dst_addr == UT64_MAX) {
		return;
	}

	// Create a key to track this specific goto
	char *src_addr_key = r_str_newf ("%"PFMT64x".addr", curr_addr);

	// Only print if we haven't already printed a goto at this address
	if (!sdb_exists (state->goto_cache, src_addr_key)) {
		// Mark this source address as having a goto
		sdb_set (state->goto_cache, src_addr_key, "1", 0);

		// Print the goto statement
		print_newline(state, curr_addr, indent);
		if (state->show_asm) {
			print_str (state, " 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad(' ', 30));
		}
		print_str (state, "goto loc_0x%08"PFMT64x";", dst_addr);
	}

	free (src_addr_key);
}

// Define macros that call these functions
#define PRINTF(...) print_str (&state, __VA_ARGS__)
#define NEWLINE(addr, indent) print_newline(&state, addr, indent)
#define PRINTGOTO(dst_addr, curr_addr) print_goto(&state, bb, dst_addr, curr_addr, indent)
#define PRINTGOTO_DIRECT(dst_addr, curr_addr) print_goto_direct(&state, bb, dst_addr, curr_addr, indent)

R_API int r_core_pseudo_code(RCore *core, const char *input) {
	bool show_c_headers = *input == 'c';
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_pdc);
		return false;
	}

	// Initialize state structure
	PDCState state = {0};
	state.core = core;
	state.out = r_strbuf_new("");
	state.codestr = r_strbuf_new("");
	state.goto_cache = sdb_new0(); // Cache for avoiding duplicate goto statements

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
	state.pj = (*input == 'j') ? r_core_pj_new(core) : NULL;
	state.show_asm = (*input == 'a');
	state.show_addr = state.show_asm || (*input == 'o');

	state.db = sdb_new0();
	ut64 queuegoto = 0LL;
	const char *blocktype = "else";
	state.fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		sdb_free (state.db);
		sdb_free (state.goto_cache);
		r_strbuf_free (state.out);
		r_strbuf_free (state.codestr);
		return false;
	}
	r_config_hold (hc, "asm.pseudo", "asm.decode", "asm.lines", "asm.bytes", "asm.stackptr", NULL);
	r_config_hold (hc, "asm.addr", "asm.flags", "asm.lines.fcn", "asm.comments", NULL);
	r_config_hold (hc, "asm.functions", "asm.section", "asm.cmt.col", "asm.sub.names", NULL);
	r_config_hold (hc, "scr.color", "emu.str", "asm.emu", "emu.write", NULL);
	r_config_hold (hc, "io.cache", "asm.syntax", NULL);
	if (!state.fcn) {
		R_LOG_ERROR ("Cannot find function in 0x%08"PFMT64x, core->addr);
		r_config_hold_free (hc);
		sdb_free (state.db);
		sdb_free (state.goto_cache);
		r_strbuf_free (state.out);
		r_strbuf_free (state.codestr);
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
	// walk all basic blocks
	// define depth level for each block
	// use it for indentation
	// asm.pseudo=true
	// asm.decode=true
	RAnalBlock *bb = r_list_first (state.fcn->bbs);
	int indent = 0;
	int nindent = 1;
	// XXX sorting basic blocks is nice for the reader, but introduces conceptual problems
	// when the entrypoint is not starting at the lowest address. // r_list_sort (fcn->bbs, cmpnbbs);
	int n_bb = r_list_length (state.fcn->bbs);

	if (state.pj) {
		pj_o (state.pj);
		pj_ka (state.pj, "annotations");
	}
	const char *cc = state.fcn->callconv ? state.fcn->callconv : "default";
	const char *cc_a0 = r_anal_cc_arg (state.core->anal, cc, 0, -1);
	const char *cc_a1 = r_anal_cc_arg (state.core->anal, cc, 1, -1);
	const char *a0 = cc_a0 ? cc_a0 : r_reg_alias_getname (state.core->anal->reg, R_REG_ALIAS_A0);
	const char *a1 = cc_a1 ? cc_a1 : r_reg_alias_getname (state.core->anal->reg, R_REG_ALIAS_A1);
	const char *r0 = r_reg_alias_getname (state.core->anal->reg, R_REG_ALIAS_R0);
	if (show_c_headers) {
		// NEWLINE (state.fcn->addr, indent);
		PRINTF ("// global registers\n");
		// only print the used registers
		PRINTF ("int stack[1024];\n");
		PRINTF ("unsigned long long *qword = &stack;\n");
		PRINTF ("unsigned int *dword = &stack;\n");
		PRINTF ("unsigned short *word = &stack;\n");
		PRINTF ("unsigned char *byte = &stack;\n");
		PRINTF ("int %s, %s;\n", a0, a1);
		PRINTF ("// This function contains %d basic blocks and its %d long.",
			n_bb, (int)r_anal_function_realsize (state.fcn));
		NEWLINE (state.fcn->addr, indent);
		const char *S0 = "esp";
		PRINTF ("static inline void push(int reg) {%s -= %d; stack[%s] = reg; }\n", S0, (int)sizeof (int), S0);
		PRINTF ("static inline int pop() {int r = stack[%s]; %s += %d; return r; }\n", S0, S0, (int)sizeof (int));
		PRINTF ("\n");
	}

	char *fs = r_core_cmd_strf (core, "afs@0x%08"PFMT64x, state.fcn->addr);
	{
		char *cc = r_core_cmd_strf (core, "afci@0x%08"PFMT64x, state.fcn->addr);
		r_str_trim (cc);
		if (state.show_addr || state.show_asm) {
			PRINTF (" 0x%08"PFMT64x " | %s | ", state.fcn->addr, r_str_pad (' ', 30));
		}
		if (R_STR_ISNOTEMPTY (cc)) {
			PRINTF ("// callconv: %s\n", cc);
		}
		free (cc);
	}
	if (state.show_addr || state.show_asm) {
		PRINTF (" 0x%08"PFMT64x " | %s | ", state.fcn->addr, r_str_pad (' ', 30));
	}
	if (R_STR_ISEMPTY (fs) || (r_str_startswith (fs, "void") && strstr (fs, "()"))) {
		if (!strcmp (a0, a1)) {
			PRINTF ("int %s (int %s) {", state.fcn->name, a0);
		} else {
			PRINTF ("int %s (int %s, int %s) {", state.fcn->name, a0, a1);
		}
	} else {
		r_str_replace_char (fs, ';', ' ');
		r_str_trim (fs);
		PRINTF ("%s {", fs);
	}
	free (fs);
	indent++;
	RList *visited = r_list_newf (NULL);
	ut64 addr = state.fcn->addr;
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
		if (!sdb_const_get (state.db, K_MARK (bb->addr), 0)) {
			bool mustprint = !queuegoto || queuegoto != bb->addr || bb->jump == bb->addr;
			if (mustprint) {
				if (queuegoto && queuegoto != UT64_MAX) {
					// NEWLINE (bb->addr, indent);
					// PRINTF ("3goto loc_0x%"PFMT64x, queuegoto);
					queuegoto = 0LL;
				}
				NEWLINE (bb->addr, indent - 1);
				if (state.show_asm) {
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
					if (state.pj) {
						pj_o (state.pj);
						pj_kn (state.pj, "start", r_strbuf_length (state.codestr));
						pj_kn (state.pj, "end", r_strbuf_length (state.codestr));
						pj_kn (state.pj, "offset", addr);
						pj_ks (state.pj, "type", "offset");
						pj_end (state.pj);
					}
					if (R_STR_ISNOTEMPTY (line)) {
						NEWLINE (addr, indent);
						if (state.show_asm) {
							// OK
							ut64 at = addr;
							int asm_pad; char *asm_str = disat (state.core, at, &asm_pad);
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
				sdb_num_set (state.db, K_MARK (bb->addr), 1, 0);
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
			// Use our goto helper to avoid duplicates
			PRINTGOTO_DIRECT(bb->fail, bb->addr);
		}
		if (sdb_const_get (state.db, K_INDENT (bb->addr), 0)) {
			// already analyzed, go pop and continue
			// XXX check if can't pop
			unvisit (visited, bb);
			R_LOG_DEBUG ("// 0x%08"PFMT64x" already analyzed", bb->addr);
			ut64 addr = sdb_array_pop_num (state.db, "indent", NULL);
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
					if (state.show_asm) {
						PRINTF (" 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
					}
					if (r0) {
						PRINTF ("return %s;", r0);
					} else {
						PRINTF ("return;");
					}
					// Mark that we've printed a return for this block to avoid following gotos
					char *return_key = r_str_newf ("return.%"PFMT64x, bb->addr);
					sdb_set (state.goto_cache, return_key, "1", 0);
					free (return_key);
#if 0
					if (state.show_asm) {
						NEWLINE (bb->addr, indent);
						PRINTF (" 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
					}
#endif
				} else if (bb->fail != UT64_MAX) {
					NEWLINE (bb->addr, indent);
					if (state.show_asm) {
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
			if (sdb_num_get (state.db, K_ELSE (bb->addr), 0)) {
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
			nindent = sdb_num_get (state.db, K_INDENT (addr), NULL);
			if (indent > nindent && !strcmp (blocktype, "else")) {
				int i;
				for (i = indent; i != nindent; i--) {
					NEWLINE (addr, i);
					PRINTF ("}");
				}
			}
			indent = nindent - 1;
		} else {
			sdb_set (state.db, K_INDENT (bb->addr), "passed", 0);
			if (bb->jump != UT64_MAX) {
				int swap = 1;
				// TODO: determine which branch take first
				ut64 jump = swap ? bb->jump : bb->fail;
				ut64 fail = swap ? bb->fail : bb->jump;
				// if its from another function chop it!
				RAnalFunction *curfcn = r_anal_get_fcn_in (core->anal, jump, R_ANAL_FCN_TYPE_NULL);
				if (curfcn != state.fcn) {
					// chop that branch
					NEWLINE (jump, indent);
					PRINTF ("// chop");
					// break;
				}
				if (sdb_get (state.db, K_INDENT (jump), 0)) {
					// already tracekd
					if (!sdb_get (state.db, K_INDENT (fail), 0)) {
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
						if (sdb_get (state.db, K_INDENT (bb->fail), 0)) {
							/* do nothing here */
							R_LOG_DEBUG ("There's already a block at 0x%"PFMT64x, bb->addr);
						} else {
							// r_cons_printf (" { RADICAL %llx\n", bb->addr);
							sdb_array_push_num (state.db, "indent", fail, 0);
							sdb_num_set (state.db, K_INDENT (fail), indent, 0);
							sdb_num_set (state.db, K_ELSE (fail), 1, 0);
				//			NEWLINE (bb->addr, indent);
						}
					} else {
						sdb_array_push_num (state.db, "indent", jump, 0);
						sdb_num_set (state.db, K_INDENT (jump), indent, 0);
						sdb_num_set (state.db, K_ELSE (jump), 1, 0);
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
				ut64 addr = sdb_array_pop_num (state.db, "indent", NULL);
				if (addr == UT64_MAX) {
					NEWLINE (bb->addr, indent);
					PRINTF ("break;");
					break;
				}
				bb = r_anal_bb_from_offset (core->anal, addr);
				nindent = sdb_num_get (state.db, K_INDENT (addr), NULL);
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
	r_list_foreach (state.fcn->bbs, iter, bb) {
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
		char *s = r_core_cmd_strf (state.core, "pdb@0x%08"PFMT64x"@e:asm.addr=%d", bb->addr, state.show_addr);
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
		if (state.show_asm) {
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
				int asm_pad; char *asm_str = disat (state.core, at, &asm_pad);
				r_strbuf_appendf (sb, " 0x%08"PFMT64x" | %s%s | %s\n",
					at, asm_str, r_str_pad (' ', asm_pad), row);
				free (asm_str);
			}
			free (s);
			r_list_free (rows);
			s = r_strbuf_drain (sb);
		} else if (state.show_addr) {
			// indent with | or stgh
			char *os = r_str_prefix_all (s, " ");
			free (s);
			s = os;
		} else {
			int eos = indent;
			memset (state.indentstr, ' ', sizeof (state.indentstr)); state.indentstr [(eos * 2)] = 0;
			char *os = r_str_prefix_all (s, state.indentstr);
			free (s);
			s = os;
		}
		size_t codelen = r_strbuf_length (state.codestr);
		if (state.pj) {
			pj_o (state.pj);
			pj_kn (state.pj, "start", codelen);
			r_strbuf_append (state.codestr, s);
			pj_kn (state.pj, "end", codelen);
			pj_kn (state.pj, "offset", addr);
			pj_ks (state.pj, "type", "offset");
			pj_end (state.pj);
		} else {
			r_strbuf_append (state.codestr, s);
			// PRINTF ("goto loc_0x%"PFMT64x";", bb->fail);
		}
		if (codelen > 0) {
			if (state.show_asm) {
				ut64 a = bb->addr;
				int asm_pad; char *asm_str = disat (core, a, &asm_pad);
				r_strbuf_appendf (state.codestr, "\n 0x%08"PFMT64x" | %s%s%s", a, asm_str, r_str_pad (' ', asm_pad), state.indentstr);
				free (asm_str);
			} else if (state.show_addr) {
				r_strbuf_appendf (state.out, "\n 0x%08"PFMT64x" | ", bb->addr);
			} else {
				NEWLINE (bb->addr, 1);
			}
			RFlagItem *fi = r_flag_get_in (core->flags, bb->addr);
			if (state.show_asm) {
				r_strbuf_appendf (state.codestr, "\n0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
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
				if (state.show_asm) {
					PRINTF (" 0x%08"PFMT64x" | ret%s | ", bb->addr, r_str_pad (' ', 30 -3));
				}
				if (r0) {
					PRINTF ("return %s;", r0);
				} else {
					PRINTF ("return;");
				}
				// Mark that we've printed a return for this block to avoid following gotos
				char *return_key = r_str_newf ("return.%"PFMT64x, bb->addr);
				sdb_set (state.goto_cache, return_key, "1", 0);
				free (return_key);
				if (state.show_asm) {
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
	if (state.show_asm) {
		PRINTF ("\n 0x%08"PFMT64x" | %s | ", bb->addr, r_str_pad (' ', 30));
	}
	PRINTF ("}\n");
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	if (state.pj) {
		pj_end (state.pj);
		char *kode = r_strbuf_drain (state.codestr);
		pj_ks (state.pj, "code", kode);
		pj_end (state.pj);
		char *j = pj_drain (state.pj);
		r_cons_printf (state.core->cons, "%s\n", j);
		free (kode);
		free (j);
		r_strbuf_free (state.out);
	} else {
		char *s = r_strbuf_drain (state.out);
		if (r_config_get_i (state.core->config, "scr.color") > 0) {
			char *ss = r_print_code_tocolor (s);
			free (s);
			s = ss;
		}
		r_cons_printf (state.core->cons, "%s\n", s);
		free (s);
		r_strbuf_free (state.codestr);
	}
	sdb_free (state.db);
	sdb_free (state.goto_cache);
	return true;
}

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
	Sdb *goto_cache; // Cache to avoid duplicate goto statements
	Sdb *db; // General purpose DB for the algorithm
	RAnalFunction *fcn;
	const char *r0; // return-value register alias name
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
	if (!ctx->leftlen && ctx->left && isspace (*in)) {
		ctx->leftlen = in - ctx->left + extra;
	}
}

static void set_right_length(RFindCTX *ctx, const char *in, int extra) {
	if (ctx->right) {
		ctx->rightlen = in - ctx->right + extra;
	}
}

static void find_function_name(RFindCTX *ctx, const char *in) {
	if (!ctx->comment || *in != '(' || !isalpha (in[-1]) || ctx->right) {
		return;
	}

	// Navigate back to find function name
	ctx->right = (char *) (in - 1);
	while (isalpha (*ctx->right) || *ctx->right == '_' || *ctx->right == '*') {
		ctx->right--;
	}

	// Handle return type if present
	if (*ctx->right == ' ') {
		ctx->right--;
		while (isalpha (*ctx->right) || *ctx->right == '_' || *ctx->right == '*') {
			ctx->right--;
		}
		// Move back to start of function name
		ctx->right++;
	}

	// Set color offset for the right token
	set_right_token (ctx, ctx->right);
}

static void swap_strings(RFindCTX *ctx) {
	char *copy = NULL;
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

static void find_and_change(char *in, int len) {
	// just to avoid underflows.. len can't be < then len(padding).
	if (!in || len < 1) {
		return;
	}
	RFindCTX ctx = { 0 };
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
				swap_strings (&ctx);
			}
			memset (&ctx, 0, sizeof (ctx));
			ctx.linebegin = in + 1;
		} else if (!ctx.comment && *in == ';' && in[1] == ' ') {
			ctx.comment = in - 1;
			ctx.comment[1] = '/';
			ctx.comment[2] = '/';
		} else if (!ctx.comment && ctx.type == TYPE_NONE && in + 3 < end) {
			if (r_str_startswith (in, "str.")) {
				ctx.type = TYPE_STR;
				set_left_token (&ctx, in);
			} else if (r_str_startswith (in, "sym.")) {
				ctx.type = TYPE_SYM;
				set_left_token (&ctx, in);
			}
		} else if (ctx.type == TYPE_STR) {
			set_left_length (&ctx, in, 0);
			if (ctx.comment && *in == '"' && in[-1] != '\\') {
				if (!ctx.right) {
					set_right_token (&ctx, in);
				} else {
					set_right_length (&ctx, in, 1);
				}
			}
		} else if (ctx.type == TYPE_SYM) {
			set_left_length (&ctx, in, 3);
			if (ctx.comment && *in == '(' && isalpha (in[-1]) && !ctx.right) {
				// Handle function definition format: "type fcn_name(args)"
				find_function_name (&ctx, in);
			} else if (ctx.comment && *in == ')' && in[1] != '\'') {
				set_right_length (&ctx, in, 1);
			}
		}
	}
}

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
	if (r_str_startswith (*p, "// goto")) {
		char *dsnl = strchr (*p, '\n');
		if (dsnl) {
			memmove (*p, dsnl + 1, strlen (dsnl + 1) + 1);
			*p = dsnl;
		}
	}
}

static void handle_indented_comments(char **p, char *nl, int spaces) {
	if (nl && spaces > 4) {
		*nl = ' ';
		memmove (nl + 1, *p, strlen (*p) + 1);
		*p = strchr (nl + 1, '\n');
	}
}

static void remove_double_spaces(char *s) {
	char *p = s;
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
			if (r_str_startswith (p, "// goto")) {
				handle_goto_comments (&p);
				continue;
			}
			handle_indented_comments (&p, nl, spaces);
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
	s = r_str_replace (s, "\n\n", "\n", true);
	remove_double_spaces (s);
	return s;
}

static char *disat(RCore *core, ut64 addr, int *pad) {
	char *s = r_core_cmd_strf (core, "pi 1 @e:scr.color=0@e:asm.pseudo=0@e:asm.addr=1@ 0x%08" PFMT64x, addr);
	r_str_trim (s);
	*pad = 30 - r_str_ansi_len (s);
	return s;
}

#define K_MARK(x) r_strf("mark.%" PFMT64x, x)
#define K_ELSE(x) r_strf("else.%" PFMT64x, x)
#define K_INDENT(x) r_strf("loc.%" PFMT64x, x)

static inline RStrBuf *state_sb(PDCState *state) {
	return state->pj? state->codestr: state->out;
}

static void print_str(PDCState *state, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	r_strbuf_vappendf (state_sb (state), fmt, ap);
	va_end (ap);
}

static void asm_append(RStrBuf *sb, RCore *core, ut64 addr, const char *prefix) {
	int pad;
	char *s = disat (core, addr, &pad);
	r_strbuf_appendf (sb, "%s0x%08" PFMT64x " | %s", prefix, addr, s);
	r_strbuf_pad (sb, ' ', pad);
	free (s);
}

static void print_pipe_header(PDCState *state, ut64 addr) {
	print_str (state, " 0x%08" PFMT64x " | ", addr);
	r_strbuf_pad (state_sb (state), ' ', 30);
	print_str (state, " | ");
}

static void print_newline(PDCState *state, ut64 addr, int indent) {
	const size_t isz = sizeof (state->indentstr);
	size_t pos = R_MIN (isz - 1, (size_t) R_MAX (indent, 0) * 4);
	memset (state->indentstr, ' ', isz);
	state->indentstr[pos] = '\0';

	RStrBuf *sb = state_sb (state);
	r_strbuf_append (sb, "\n");
	if (state->show_asm) {
		asm_append (sb, state->core, addr, "");
		r_strbuf_append (sb, state->indentstr);
	} else if (state->show_addr) {
		const char *lead = state->pj? "": " ";
		r_strbuf_appendf (sb, "%s0x%08" PFMT64x " | %s", lead, addr, state->indentstr);
	} else {
		r_strbuf_append (sb, state->indentstr);
	}
}

static bool bb_addr_is_goto_target(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter, *cit;
	RAnalBlock *b;
	RAnalCaseOp *co;
	r_list_foreach (fcn->bbs, iter, b) {
		if (b->jump == addr || b->fail == addr) {
			return true;
		}
		RAnalSwitchOp *sop = b->switch_op;
		if (!sop) {
			continue;
		}
		if (sop->def_val == addr) {
			return true;
		}
		r_list_foreach (sop->cases, cit, co) {
			if (co->jump == addr) {
				return true;
			}
		}
	}
	return false;
}

static int bb_last_op_type(RCore *core, RAnalBlock *bb);

static bool pdc_is_ret_only_bb(RCore *core, ut64 addr) {
	if (addr == UT64_MAX) {
		return false;
	}
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, addr);
	if (!bb || bb->jump != UT64_MAX || bb->fail != UT64_MAX) {
		return false;
	}
	int t = bb_last_op_type (core, bb);
	return t == R_ANAL_OP_TYPE_RET || t == R_ANAL_OP_TYPE_CRET;
}

static void print_goto_or_return(PDCState *state, ut64 dst_addr, const char *prefix) {
	if (pdc_is_ret_only_bb (state->core, dst_addr)) {
		if (state->r0) {
			print_str (state, "%sreturn %s;", prefix, state->r0);
		} else {
			print_str (state, "%sreturn;", prefix);
		}
	} else {
		print_str (state, "%sgoto loc_0x%08" PFMT64x ";", prefix, dst_addr);
	}
}

static void print_goto(PDCState *state, RAnalBlock *bb, ut64 dst_addr, ut64 curr_addr, int indent) {
	if (dst_addr == UT64_MAX || curr_addr == dst_addr) {
		return;
	}
	r_strf_buffer (64);
	Sdb *gc = state->goto_cache;
	if (sdb_exists (gc, r_strf ("%" PFMT64x ".to.%" PFMT64x, bb->addr, dst_addr))
		|| sdb_exists (gc, r_strf ("%" PFMT64x ".to.%" PFMT64x, curr_addr, dst_addr))
		|| sdb_exists (gc, r_strf ("return.%" PFMT64x, bb->addr))) {
		return;
	}
	sdb_set (gc, r_strf ("%" PFMT64x ".to.%" PFMT64x, bb->addr, dst_addr), "1", 0);
	sdb_set (gc, r_strf ("%" PFMT64x ".to.%" PFMT64x, curr_addr, dst_addr), "1", 0);

	if (dst_addr != bb->addr) {
		print_newline (state, curr_addr, indent);
		if (state->show_asm) {
			print_pipe_header (state, bb->addr);
		}
		print_goto_or_return (state, dst_addr, " ");
	}
}

static void print_goto_direct(PDCState *state, RAnalBlock *bb, ut64 dst_addr, ut64 curr_addr, int indent) {
	if (dst_addr == UT64_MAX) {
		return;
	}
	r_strf_buffer (64);
	const char *key = r_strf ("%" PFMT64x ".addr", curr_addr);
	if (!sdb_exists (state->goto_cache, key)) {
		sdb_set (state->goto_cache, key, "1", 0);
		print_newline (state, curr_addr, indent);
		if (state->show_asm) {
			print_pipe_header (state, bb->addr);
		}
		print_goto_or_return (state, dst_addr, "");
	}
}

// Define macros that call these functions
#define PRINTF(...) print_str(&state, __VA_ARGS__)
#define NEWLINE(addr, indent) print_newline(&state, addr, indent)
#define PRINTGOTO(dst_addr, curr_addr) print_goto(&state, bb, dst_addr, curr_addr, indent)
#define PRINTGOTO_DIRECT(dst_addr, curr_addr) print_goto_direct(&state, bb, dst_addr, curr_addr, indent)

static int bb_last_op_type(RCore *core, RAnalBlock *bb) {
	if (!bb || bb->ninstr < 1) {
		return -1;
	}
	ut64 last_addr = r_anal_bb_opaddr_i (bb, bb->ninstr - 1);
	if (last_addr == UT64_MAX) {
		return -1;
	}
	RAnalOp *lop = r_core_anal_op (core, last_addr, R_ARCH_OP_MASK_BASIC);
	if (!lop) {
		return -1;
	}
	int t = lop->type & R_ANAL_OP_TYPE_MASK;
	r_anal_op_free (lop);
	return t;
}

static bool bb_ends_in_tail_jmp(RCore *core, RAnalBlock *bb) {
	int t = bb_last_op_type (core, bb);
	return t == R_ANAL_OP_TYPE_JMP || t == R_ANAL_OP_TYPE_UJMP;
}

static bool bb_ends_with_terminator(RCore *core, RAnalBlock *bb) {
	int t = bb_last_op_type (core, bb);
	return t == R_ANAL_OP_TYPE_JMP || t == R_ANAL_OP_TYPE_UJMP
		|| t == R_ANAL_OP_TYPE_RET || t == R_ANAL_OP_TYPE_CRET;
}

static char *fetch_bb_pseudo(PDCState *state, RAnalBlock *bb) {
	r_cons_push (state->core->cons);
	bool html = r_config_get_b (state->core->config, "scr.html");
	r_config_set_b (state->core->config, "scr.html", false);
	char *code = r_core_cmd_strf (state->core, "pD %" PFMT64d " @ 0x%08" PFMT64x, bb->size, bb->addr);
	r_cons_pop (state->core->cons);
	r_config_set_b (state->core->config, "scr.html", html);
	if (R_STR_ISEMPTY (code)) {
		free (code);
		return NULL;
	}
	code = r_str_replace (code, "\n\n", "\n", true);
	code = r_str_replace (code, ";", "//", true);
	code = cleancomments (code);
	size_t len = strlen (code);
	if (len < 1) {
		free (code);
		return NULL;
	}
	code[len - 1] = 0;
	find_and_change (code, len);
	return code;
}

static ut64 emit_code_lines(PDCState *state, char *code, ut64 start_addr, int indent, bool emit_pj) {
	RList *lines = r_str_split_list (code, "\n", 0);
	RListIter *iter;
	const char *line;
	ut64 addr = start_addr;
	r_list_foreach (lines, iter, line) {
		if (*line == '0') {
			ut64 at = r_num_get (NULL, line);
			if (at && at != UT64_MAX) {
				addr = at;
			}
			const char *s = strchr (line, ' ');
			line = s? r_str_trim_head_ro (s + 1): "";
		}
		if (emit_pj && state->pj) {
			pj_o (state->pj);
			pj_kn (state->pj, "start", r_strbuf_length (state->codestr));
			pj_kn (state->pj, "end", r_strbuf_length (state->codestr));
			pj_kn (state->pj, "offset", addr);
			pj_ks (state->pj, "type", "offset");
			pj_end (state->pj);
		}
		if (R_STR_ISNOTEMPTY (line)) {
			print_newline (state, addr, indent);
			if (state->show_asm) {
				RStrBuf *sb = state_sb (state);
				asm_append (sb, state->core, addr, " ");
				r_strbuf_appendf (sb, " | %s", line);
			} else {
				print_str (state, "%s", line);
			}
		}
	}
	r_list_free (lines);
	return addr;
}

static void emit_close_braces(PDCState *state, ut64 addr, int from, int to) {
	int i;
	for (i = from; i > to; i--) {
		print_newline (state, addr, i);
		print_str (state, "}");
	}
}

static void mark_bb_visited(PDCState *state, RList *visited, RAnalBlock *cbb) {
	if (!cbb) {
		return;
	}
	r_strf_buffer (64);
	sdb_num_set (state->db, r_strf ("mark.%" PFMT64x, cbb->addr), 1, 0);
	if (!r_list_contains (visited, cbb)) {
		r_list_append (visited, cbb);
	}
}

typedef struct {
	ut64 value;
	ut64 jump;
} PDCSwCase;

static int pdc_case_cmp(const void *a, const void *b) {
	const PDCSwCase *ca = a;
	const PDCSwCase *cb = b;
	return (ca->value > cb->value) - (ca->value < cb->value);
}

static char *find_switch_expr(RCore *core, RAnalFunction *fcn, RAnalBlock *sw_bb) {
	RListIter *iter;
	RAnalBlock *pred;
	char *result = NULL;
	r_list_foreach (fcn->bbs, iter, pred) {
		if (pred == sw_bb) {
			continue;
		}
		if (pred->jump != sw_bb->addr && pred->fail != sw_bb->addr) {
			continue;
		}
		int ninstr = (pred->ninstr > 0)? pred->ninstr: 8;
		char *dis = r_core_cmd_strf (core, "pi %d @e:asm.pseudo=0@e:scr.color=0@ 0x%08" PFMT64x, ninstr, pred->addr);
		if (R_STR_ISEMPTY (dis)) {
			free (dis);
			continue;
		}
		RList *lines = r_str_split_list (dis, "\n", 0);
		RListIter *liter;
		char *line;
		r_list_foreach (lines, liter, line) {
			const char *t = r_str_trim_head_ro (line);
			if (!r_str_startswith (t, "cmp ")) {
				continue;
			}
			const char *sp = strchr (t, ' ');
			if (!sp) {
				continue;
			}
			const char *op1 = r_str_trim_head_ro (sp + 1);
			const char *comma = strchr (op1, ',');
			if (!comma || comma <= op1) {
				continue;
			}
			free (result);
			result = r_str_ndup (op1, comma - op1);
			if (result) {
				r_str_trim (result);
			}
		}
		r_list_free (lines);
		free (dis);
		if (result) {
			return result;
		}
	}
	return strdup ("switch_var");
}

static void render_case_body_lines(PDCState *state, ut64 case_addr, int indent) {
	RAnalBlock *cbb = r_anal_bb_from_offset (state->core->anal, case_addr);
	if (!cbb) {
		return;
	}
	char *code = fetch_bb_pseudo (state, cbb);
	if (!code) {
		return;
	}
	emit_code_lines (state, code, cbb->addr, indent, false);
	free (code);
}

static void emit_case_label(PDCState *state, ut64 value, ut64 target, int indent) {
	print_newline (state, target, indent);
	if (IS_PRINTABLE (value)) {
		print_str (state, "case %" PFMT64d ": // '%c' 0x%08" PFMT64x,
			value, (int)value, target);
	} else {
		print_str (state, "case %" PFMT64d ": // 0x%08" PFMT64x, value, target);
	}
}

static void emit_case_range_label(PDCState *state, ut64 lo, ut64 hi, ut64 target, int indent) {
	print_newline (state, target, indent);
	if (IS_PRINTABLE (lo) && IS_PRINTABLE (hi)) {
		print_str (state, "case %" PFMT64d "...%" PFMT64d ": // '%c'..'%c' 0x%08" PFMT64x,
			lo, hi, (int)lo, (int)hi, target);
	} else {
		print_str (state, "case %" PFMT64d "...%" PFMT64d ": // 0x%08" PFMT64x,
			lo, hi, target);
	}
}

static bool pdc_range_is_contiguous(const PDCSwCase *arr, int from, int to) {
	int i;
	for (i = from; i < to; i++) {
		if (arr[i + 1].value != arr[i].value + 1) {
			return false;
		}
	}
	return true;
}

static void render_arm_body(PDCState *state, RList *visited, ut64 target, int indent) {
	if (target == UT64_MAX) {
		return;
	}
	RAnalBlock *cbb = r_anal_bb_from_offset (state->core->anal, target);
	if (cbb && r_anal_function_contains (state->fcn, target) && !r_list_contains (visited, cbb)) {
		render_case_body_lines (state, target, indent);
		if (!bb_ends_with_terminator (state->core, cbb)) {
			print_newline (state, target, indent);
			print_str (state, "break;");
		}
		mark_bb_visited (state, visited, cbb);
	} else {
		print_newline (state, target, indent);
		print_goto_or_return (state, target, "");
	}
}

static void render_switch(PDCState *state, RAnalBlock *sw_bb, RList *visited, int indent) {
	RAnalSwitchOp *sop = sw_bb->switch_op;
	if (!sop || !sop->cases) {
		return;
	}
	int n = r_list_length (sop->cases);
	if (n < 1) {
		return;
	}
	char *expr = find_switch_expr (state->core, state->fcn, sw_bb);
	print_newline (state, sw_bb->addr, indent);
	print_str (state, "switch (%s) { // jump table of %d cases at 0x%08" PFMT64x,
		expr, n, sw_bb->addr);
	free (expr);

	PDCSwCase *arr = calloc (n, sizeof (PDCSwCase));
	if (!arr) {
		print_newline (state, sw_bb->addr, indent);
		print_str (state, "}");
		return;
	}
	int i = 0;
	RListIter *iter;
	RAnalCaseOp *co;
	r_list_foreach (sop->cases, iter, co) {
		if (i >= n) {
			break;
		}
		arr[i].value = co->value;
		arr[i].jump = co->jump;
		i++;
	}
	qsort (arr, i, sizeof (PDCSwCase), pdc_case_cmp);

	int c = 0;
	while (c < i) {
		int k = c;
		while (k + 1 < i && arr[k + 1].jump == arr[c].jump) {
			k++;
		}
		ut64 target = arr[c].jump;
		if (k - c >= 2 && pdc_range_is_contiguous (arr, c, k)) {
			emit_case_range_label (state, arr[c].value, arr[k].value, target, indent + 1);
		} else {
			int j;
			for (j = c; j <= k; j++) {
				emit_case_label (state, arr[j].value, target, indent + 1);
			}
		}
		render_arm_body (state, visited, target, indent + 2);
		c = k + 1;
	}

	if (sop->def_val != UT64_MAX) {
		print_newline (state, sop->def_val, indent + 1);
		print_str (state, "default: // 0x%08" PFMT64x, sop->def_val);
		render_arm_body (state, visited, sop->def_val, indent + 2);
	}

	print_newline (state, sw_bb->addr, indent);
	print_str (state, "}");
	free (arr);
}

R_API int r_core_pseudo_code(RCore *core, const char *input) {
	bool show_c_headers = *input == 'c';
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_pdc);
		return false;
	}

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

	PDCState state = { 0 };
	state.core = core;
	state.out = r_strbuf_new ("");
	state.codestr = r_strbuf_new ("");
	state.goto_cache = sdb_new0 ();
	state.db = sdb_new0 ();
	state.pj = (*input == 'j')? r_core_pj_new (core): NULL;
	state.show_asm = (*input == 'a');
	state.show_addr = state.show_asm || (*input == 'o');
	state.fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);

	ut64 queuegoto = 0LL;
	const char *blocktype = "else";
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc || !state.fcn) {
		if (!state.fcn) {
			R_LOG_ERROR ("Cannot find function in 0x%08" PFMT64x, core->addr);
		}
		r_config_hold_free (hc);
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
	const char *cc = state.fcn->callconv? state.fcn->callconv: "default";
	const char *cc_a0 = r_anal_cc_arg (state.core->anal, cc, 0, -1);
	const char *cc_a1 = r_anal_cc_arg (state.core->anal, cc, 1, -1);
	const char *a0 = cc_a0? cc_a0: r_reg_alias_getname (state.core->anal->reg, R_REG_ALIAS_A0);
	const char *a1 = cc_a1? cc_a1: r_reg_alias_getname (state.core->anal->reg, R_REG_ALIAS_A1);
	state.r0 = r_reg_alias_getname (state.core->anal->reg, R_REG_ALIAS_R0);
	const char *r0 = state.r0;
	if (show_c_headers) {
		PRINTF ("// global registers\n");
		PRINTF ("int stack[1024];\n");
		PRINTF ("unsigned long long *qword = &stack;\n");
		PRINTF ("unsigned int *dword = &stack;\n");
		PRINTF ("unsigned short *word = &stack;\n");
		PRINTF ("unsigned char *byte = &stack;\n");
		PRINTF ("int %s, %s;\n", a0, a1);
		PRINTF ("// This function contains %d basic blocks and its %d long.",
			n_bb,
			(int)r_anal_function_realsize (state.fcn));
		NEWLINE (state.fcn->addr, indent);
		const char *S0 = "esp";
		PRINTF ("static inline void push(int reg) {%s -= %d; stack[%s] = reg; }\n", S0, (int)sizeof (int), S0);
		PRINTF ("static inline int pop() {int r = stack[%s]; %s += %d; return r; }\n", S0, S0, (int)sizeof (int));
		PRINTF ("\n");
	}

	char *fs = r_core_cmd_strf (core, "afs@0x%08" PFMT64x, state.fcn->addr);
	{
		char *cc = r_core_cmd_strf (core, "afci@0x%08" PFMT64x, state.fcn->addr);
		r_str_trim (cc);
		if (state.show_addr || state.show_asm) {
			print_pipe_header (&state, state.fcn->addr);
		}
		if (R_STR_ISNOTEMPTY (cc)) {
			PRINTF ("// callconv: %s\n", cc);
		}
		free (cc);
	}
	if (state.show_addr || state.show_asm) {
		print_pipe_header (&state, state.fcn->addr);
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
		indent = 2;
		char *code = fetch_bb_pseudo (&state, bb);
		if (!code) {
			R_LOG_ERROR ("Empty code here");
			break;
		}
		if (!sdb_const_get (state.db, K_MARK (bb->addr), 0)) {
			bool mustprint = !queuegoto || queuegoto != bb->addr || bb->jump == bb->addr;
			if (mustprint) {
				if (queuegoto && queuegoto != UT64_MAX) {
					queuegoto = 0LL;
				}
				if (bb_addr_is_goto_target (state.fcn, bb->addr)) {
					NEWLINE (bb->addr, indent - 1);
					if (state.show_asm) {
						print_pipe_header (&state, bb->addr);
					}
					PRINTF ("loc_0x%08" PFMT64x ":", bb->addr);
				}
				addr = emit_code_lines (&state, code, bb->addr, indent, true);
				sdb_num_set (state.db, K_MARK (bb->addr), 1, 0);
			}
		}
		free (code);
		bool closed = false;
		bool resume_from_indent = false;
		ut64 gotoaddr = UT64_MAX;
		const bool has_jump = bb->jump != UT64_MAX;
		if (bb->fail != UT64_MAX) {
			PRINTGOTO_DIRECT (bb->fail, bb->addr);
		} else if (has_jump) {
			gotoaddr = bb->jump;
		} else {
			closed = true;
		}
		if (sdb_const_get (state.db, K_INDENT (bb->addr), 0)) {
			// already analyzed, go pop and continue
			unvisit (visited, bb);
			R_LOG_DEBUG ("// 0x%08" PFMT64x " already analyzed", bb->addr);
			ut64 addr = sdb_array_pop_num (state.db, "indent", NULL);
			if (addr == UT64_MAX) {
				closed = true;
				if (!bb_ends_in_tail_jmp (core, bb)) {
					NEWLINE (bb->addr, indent);
					if (state.show_asm) {
						print_pipe_header (&state, bb->addr);
					}
					PRINTF (r0? "return %s;": "return;", r0);
					sdb_set (state.goto_cache, r_strf ("return.%" PFMT64x, bb->addr), "1", 0);
				}
				RAnalBlock *nbb = r_anal_bb_from_offset (core->anal, bb->fail);
				if (r_list_contains (visited, nbb)) {
					nbb = r_anal_bb_from_offset (core->anal, bb->jump);
					if (bb->jump == bb->addr) {
						R_LOG_DEBUG ("Basic block loop found at 0x%08" PFMT64x, bb->jump);
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
			if (addr != bb->addr) {
				queuegoto = addr;
			}
			bb = r_anal_bb_from_offset (core->anal, addr);
			if (!bb) {
				R_LOG_ERROR ("failed block");
				break;
			}
			nindent = sdb_num_get (state.db, K_INDENT (addr), NULL);
			if (indent > nindent && !strcmp (blocktype, "else")) {
				emit_close_braces (&state, addr, indent, nindent);
			}
			indent = nindent - 1;
		} else {
			sdb_set (state.db, K_INDENT (bb->addr), "passed", 0);
			if (has_jump) {
				int swap = 1;
				// TODO: determine which branch take first
				ut64 jump = swap? bb->jump: bb->fail;
				ut64 fail = swap? bb->fail: bb->jump;
				// If a conditional branch leaves the current function, do not
				// descend into the foreign CFG. Prefer the in-function branch.
				const bool jump_in_fcn = jump != UT64_MAX && r_anal_function_contains (state.fcn, jump);
				if (!jump_in_fcn) {
					NEWLINE (jump, indent);
					PRINTF ("// chop");
					const bool fail_in_fcn = fail != UT64_MAX && r_anal_function_contains (state.fcn, fail);
					if (fail_in_fcn) {
						jump = fail;
						fail = UT64_MAX;
					} else {
						break;
					}
				}
				if (sdb_get (state.db, K_INDENT (jump), 0)) {
					// already tracekd
					if (fail != UT64_MAX && !sdb_get (state.db, K_INDENT (fail), 0)) {
						bb = r_anal_bb_from_offset (core->anal, fail);
					} else if (fail == UT64_MAX) {
						resume_from_indent = true;
					} else {
						R_LOG_ERROR ("pdc: unknown branch from 0x%08" PFMT64x, jump);
					}
				} else {
					bb = r_anal_bb_from_offset (core->anal, jump);
					if (!bb) {
						R_LOG_ERROR ("Failed to retrieve block at 0x%" PFMT64x, jump);
						break;
					}
					if (fail != UT64_MAX) {
						indent++;
						if (sdb_get (state.db, K_INDENT (bb->fail), 0)) {
							R_LOG_DEBUG ("There's already a block at 0x%" PFMT64x, bb->addr);
						} else {
							sdb_array_push_num (state.db, "indent", fail, 0);
							sdb_num_set (state.db, K_INDENT (fail), indent, 0);
							sdb_num_set (state.db, K_ELSE (fail), 1, 0);
						}
					} else {
						sdb_array_push_num (state.db, "indent", jump, 0);
						sdb_num_set (state.db, K_INDENT (jump), indent, 0);
						sdb_num_set (state.db, K_ELSE (jump), 1, 0);
						blocktype = (jump <= bb->addr)? "while": "else";
						NEWLINE (bb->addr, indent);
						indent += 2;
					}
				}
			}
			if ((!has_jump && !closed) || resume_from_indent) {
				ut64 addr = sdb_array_pop_num (state.db, "indent", NULL);
				if (addr == UT64_MAX) {
					NEWLINE (bb->addr, indent);
					PRINTF ("break;");
					break;
				}
				bb = r_anal_bb_from_offset (core->anal, addr);
				nindent = sdb_num_get (state.db, K_INDENT (addr), NULL);
				if (indent > nindent) {
					emit_close_braces (&state, bb->addr, indent, nindent);
				}
				PRINTF ("goto loc_0x%08" PFMT64x ";", addr);
				indent = nindent;
			}
			PRINTGOTO (bb? bb->addr: UT64_MAX, gotoaddr);
		}
	}
	RListIter *iter;
	bool use_html = r_config_get_b (core->config, "scr.html");
	r_list_foreach (state.fcn->bbs, iter, bb) {
		if (r_list_contains (visited, bb)) {
			continue;
		}
		if (bb->switch_op) {
			render_switch (&state, bb, visited, 2);
			r_list_append (visited, bb);
		}
		ut64 nextbbaddr = UT64_MAX;
		if (iter->n) {
			RListIter *nit = (RListIter *) (iter->n);
			RAnalBlock *nbb = (RAnalBlock *) (nit->data);
			nextbbaddr = nbb->addr;
		}
		if (use_html) {
			r_config_set_b (core->config, "scr.html", false);
		}
		char *s = r_core_cmd_strf (state.core, "pdb@0x%08" PFMT64x "@e:asm.addr=%d", bb->addr, state.show_addr);
		if (use_html) {
			r_config_set_b (core->config, "scr.html", true);
		}
		s = r_str_replace (s, ";", "//", true);
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
				asm_append (sb, state.core, at, " ");
				r_strbuf_appendf (sb, " | %s\n", row);
			}
			free (s);
			r_list_free (rows);
			s = r_strbuf_drain (sb);
		} else if (state.show_addr) {
			char *os = r_str_prefix_all (s, " ");
			free (s);
			s = os;
		} else {
			memset (state.indentstr, ' ', sizeof (state.indentstr));
			state.indentstr[indent * 2] = 0;
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
		}
		if (codelen > 0) {
			if (state.show_asm) {
				asm_append (state.codestr, core, bb->addr, "\n ");
				r_strbuf_append (state.codestr, state.indentstr);
			} else if (state.show_addr) {
				r_strbuf_appendf (state.out, "\n 0x%08" PFMT64x " | ", bb->addr);
			} else {
				NEWLINE (bb->addr, 1);
			}
			RFlagItem *fi = r_flag_get_in (core->flags, bb->addr);
			if (state.show_asm) {
				r_strbuf_appendf (state.codestr, "\n0x%08" PFMT64x " | ", bb->addr);
				r_strbuf_pad (state.codestr, ' ', 30);
				r_strbuf_append (state.codestr, " | ");
			}
			if (bb_addr_is_goto_target (state.fcn, bb->addr)) {
				char tagbuf[32];
				const char *tag = "orphan";
				if (fi && r_str_startswith (fi->name, "case.")) {
					const char *val = r_str_lchr (fi->name, '.') + 1;
					char *hex = r_str_newf ("0x%s", val);
					int nval = r_num_get (NULL, hex);
					free (hex);
					if (IS_PRINTABLE (nval)) {
						snprintf (tagbuf, sizeof (tagbuf), "case '%c'", nval);
					} else {
						snprintf (tagbuf, sizeof (tagbuf), "case %s", val);
					}
					tag = tagbuf;
				}
				PRINTF ("loc_0x%08" PFMT64x ": // %s\n%s", bb->addr, tag, s);
			} else {
				PRINTF ("%s", s);
			}
			if (bb->jump == UT64_MAX) {
				if (!bb_ends_in_tail_jmp (core, bb)) {
					NEWLINE (bb->addr, indent);
					if (state.show_asm) {
						PRINTF (" 0x%08" PFMT64x " | ret", bb->addr);
						r_strbuf_pad (state_sb (&state), ' ', 30 - 3);
						PRINTF (" | ");
					}
					PRINTF (r0? "return %s;": "return;", r0);
					sdb_set (state.goto_cache, r_strf ("return.%" PFMT64x, bb->addr), "1", 0);
					if (state.show_asm) {
						PRINTF ("\n");
						print_pipe_header (&state, bb->addr);
					}
				}
			} else {
				PRINTGOTO (nextbbaddr, bb->jump);
			}
		}
		free (s);
	}
	r_list_free (visited);
	indent = 0;
	NEWLINE (addr, indent);
	if (state.show_asm && bb) {
		PRINTF ("\n");
		print_pipe_header (&state, bb->addr);
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
			RConsCodeColors codecolors = r_cons_codecolors (core->cons);
			char *ss = r_print_code_tocolor (s, &codecolors);
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

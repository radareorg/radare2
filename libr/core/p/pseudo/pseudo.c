/* radare - LGPL - Copyright 2015-2026 - pancake */

#include <r_core.h>
#include "pdc_ast.h"

// R2R db/cmd/cmd_pdc

typedef struct {
	RCore *core;
	RStrBuf *out;
	RStrBuf *codestr;
	PJ *pj;
	bool show_asm;
	bool show_addr;
	bool structured;
	Sdb *goto_cache;
	Sdb *db;
	RBitset *marked;
	RBitset *switch_addrs;
	RAnalFunction *fcn;
	ut64 bb_jump; // edges of the block being rendered, owned by its region in structured mode
	ut64 bb_fail;
	HtUP *conds; // block addr => recovered condition, recovered once per block
	const char *r0;
} PDCState;

static const char *pseudo_arg_name(RAnal *anal, const char *arg) {
	const char *first = r_anal_cc_location_first (anal, arg);
	if (first) {
		arg = first;
	}
	if (!strcmp (arg, "^") || !strcmp (arg, "^-")) {
		return "stack";
	}
	return arg;
}

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
	if (!ctx->leftlen && isspace (*in)) {
		ctx->leftlen = in - ctx->left + extra;
	}
}

static void set_right_length(RFindCTX *ctx, const char *in, int extra) {
	if (ctx->right) {
		ctx->rightlen = in - ctx->right + extra;
	}
}

static void find_function_name(RFindCTX *ctx, const char *in) {
	ctx->right = (char *) (in - 1);
	while (isalpha (*ctx->right) || *ctx->right == '_' || *ctx->right == '*') {
		ctx->right--;
	}
	if (*ctx->right == ' ') {
		ctx->right--;
		while (isalpha (*ctx->right) || *ctx->right == '_' || *ctx->right == '*') {
			ctx->right--;
		}
		ctx->right++;
	}
	set_right_token (ctx, ctx->right);
}

static void swap_strings(RFindCTX *ctx) {
	char *copy = NULL;
	size_t len;
	if (ctx->leftlen > ctx->rightlen) {
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
			memset (ctx->right - ctx->leftpos, ' ', ctx->leftpos);
			*(ctx->right - ctx->leftpos - 1) = '\n';
			memset (ctx->left, ' ', ctx->leftlen);
			memset (ctx->linebegin - ctx->leftlen, ' ', ctx->leftlen);
		}
	} else {
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

// r2 renders comments as "<whitespace>; text", arch pseudo templates emit ';' with no space before it
static bool is_comment_semicolon(const char *begin, const char *p) {
	return *p == ';' && (p == begin || IS_WHITECHAR (p[-1]));
}

static void find_and_change(char *in, int len) {
	if (len < 1) {
		return;
	}
	RFindCTX ctx = { 0 };
	char *start = in;
	char *end = in + len;
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
		} else if (!ctx.comment && in > start && in[1] == ' ' && is_comment_semicolon (start, in)) {
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
				find_function_name (&ctx, in);
			} else if (ctx.comment && *in == ')' && in[1] != '\'') {
				set_right_length (&ctx, in, 1);
			}
		}
	}
}

static bool word_in(const char *s, const char *w) {
	size_t wl = strlen (w);
	const char *p = s;
	while ((p = strstr (p, w))) {
		bool lb = (p == s) || (!isalnum ((ut8)p[-1]) && p[-1] != '_');
		bool rb = !isalnum ((ut8)p[wl]) && p[wl] != '_';
		if (lb && rb) {
			return true;
		}
		p += wl;
	}
	return false;
}

typedef struct {
	char reg[16];
	int line;
	bool folded;
	bool used;
} PDCPendingRef;

static void pending_resolve(PDCPendingRef *p, bool *drop) {
	if (p->reg[0] && p->folded && !p->used) {
		drop[p->line] = true;
	}
	p->reg[0] = 0;
}

// matches the ppc64 toc idiom "rX = r2 + (imm << 16)" and returns the dst register length, or 0
static size_t toc_setup_reg(const char *body) {
	const char *eq = strstr (body, " = r2 + (");
	if (!eq) {
		return 0;
	}
	const char *imm = eq + strlen (" = r2 + (");
	if (*imm == '-') {
		imm++;
	}
	bool hex = imm[0] == '0' && imm[1] == 'x';
	size_t dl = strspn (hex? imm + 2: imm, hex? "0123456789abcdef": "0123456789");
	const char *end = (hex? imm + 2: imm) + dl;
	if (dl < 1 || !r_str_startswith (end, " << 16)")) {
		return 0;
	}
	size_t reglen = eq - body;
	size_t k = 0;
	while (k < reglen && (isalnum ((ut8)body[k]) || body[k] == '_')) {
		k++;
	}
	return (k == reglen)? reglen: 0;
}

static RFlagItem *pdc_flag_at(RCore *core, ut64 addr) {
	if (addr == UT64_MAX) {
		return NULL;
	}
	RFlagItem *fi = r_core_flag_get_by_spaces (core->flags, false, addr);
	return fi? fi: r_flag_get_in (core->flags, addr);
}

static RFlagItem *pdc_ref_flag(RCore *core, ut64 addr) {
	if (addr == UT64_MAX) {
		return NULL;
	}
	RVecAnalRef *refs = r_anal_refs_get (core->anal, addr);
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			int rt = R_ANAL_REF_TYPE_MASK (ref->type);
			if (rt == R_ANAL_REF_TYPE_DATA || rt == R_ANAL_REF_TYPE_STRN) {
				RFlagItem *fi = pdc_flag_at (core, ref->addr);
				if (fi) {
					RVecAnalRef_free (refs);
					return fi;
				}
			}
		}
		RVecAnalRef_free (refs);
	}
	RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_VAL);
	if (!op) {
		return NULL;
	}
	RFlagItem *fi = op->ptr != UT64_MAX? pdc_flag_at (core, op->ptr): NULL;
	r_anal_op_free (op);
	return fi;
}

// rewrites "dst = [reg +/- off]" into "dst = [name]" when analysis resolved the target.
static char *fold_line(RCore *core, const char *line, const char *body, ut64 addr, const char *pending_reg, char *base, size_t basesz) {
	const char *br = strchr (body, '[');
	const char *cb = br? strchr (br, ']'): NULL;
	if (!br || !cb || !isalpha ((ut8)br[1])) {
		return NULL;
	}
	size_t bl = 0;
	while (bl < basesz - 1 && (isalnum ((ut8)br[1 + bl]) || br[1 + bl] == '_')) {
		base[bl] = br[1 + bl];
		bl++;
	}
	if (!r_reg_get (core->anal->reg, base, -1)) {
		return NULL;
	}
	bool named = memchr (br + 1, '.', cb - (br + 1));
	bool global_base = !strcmp (base, "gp") || (pending_reg && *pending_reg && !strcmp (base, pending_reg));
	if (!named && !global_base) {
		return NULL;
	}
	const char *cmt = strstr (cb, "//");
	RFlagItem *fi = pdc_ref_flag (core, addr);
	if (!fi) {
		return NULL;
	}
	char *pfx = r_str_ndup (line, br - line);
	const char *mid_end = cmt? cmt: line + strlen (line);
	char *mid = r_str_ndup (cb + 1, mid_end - (cb + 1));
	r_str_trim (mid);
	char *res = NULL;
	if (cmt && r_str_startswith (fi->name, "str.")) {
		const char *q1 = strchr (cmt, '"');
		const char *q2 = q1? strchr (q1 + 1, '"'): NULL;
		// the loaded value is the string itself: drop the deref
		if (q2 && R_STR_ISEMPTY (mid) && br - line > 2 && !strncmp (br - 2, "= ", 2)) {
			res = r_str_newf ("%s%.*s", pfx, (int)(q2 + 1 - q1), q1);
		}
	}
	if (!res) {
		res = r_str_newf ("%s[%s]%s%s", pfx, fi->name, *mid? " ": "", mid);
	}
	free (pfx);
	free (mid);
	return res;
}

static char *fold_resolved_refs(RCore *core, char *code) {
	int n = r_str_char_count (code, '\n') + 1;
	char **out = R_NEWS0 (char *, n);
	bool *drop = R_NEWS0 (bool, n);
	if (!out || !drop) {
		free (out);
		free (drop);
		return code;
	}
	PDCPendingRef pend = {0};
	const char *ptr = code;
	ut64 addr = UT64_MAX;
	int i;
	for (i = 0; i < n; i++) {
		const char *lend = strchr (ptr, '\n');
		size_t ll = lend? (size_t)(lend - ptr): strlen (ptr);
		char *line = r_str_ndup (ptr, ll);
		ptr = lend? lend + 1: ptr + ll;
		out[i] = line;
		const char *body = r_str_trim_head_ro (line);
		if (r_str_startswith (body, "0x")) {
			ut64 at = r_num_get (NULL, body);
			if (at != UT64_MAX) {
				addr = at;
			}
			const char *sp = strchr (body, ' ');
			if (sp) {
				body = r_str_trim_head_ro (sp);
			}
		}
		// the addis rX,r2,hi seed; the paired ld/st carries the resolved target
		size_t reglen = toc_setup_reg (body);
		if (reglen > 0 && reglen < sizeof (pend.reg)) {
			pending_resolve (&pend, drop);
			r_str_ncpy (pend.reg, body, reglen + 1);
			pend.line = i;
			continue;
		}
		char base[16] = {0};
		char *folded = fold_line (core, line, body, addr, pend.reg, base, sizeof (base));
		if (folded) {
			free (out[i]);
			out[i] = folded;
			if (pend.reg[0] && !strcmp (base, pend.reg)) {
				pend.folded = true;
				// base reg overwritten by its own load: liveness ends here
				if (word_in (folded, pend.reg)) {
					pending_resolve (&pend, drop);
				}
			}
		} else if (pend.reg[0] && word_in (body, pend.reg)) {
			// a plain write to the reg ends liveness without being a use
			size_t rl = strlen (pend.reg);
			bool wr = !strncmp (body, pend.reg, rl)
				&& !strncmp (body + rl, " = ", 3)
				&& !word_in (body + rl + 3, pend.reg);
			pend.used = !wr;
			pending_resolve (&pend, drop);
		}
	}
	pending_resolve (&pend, drop);
	RStrBuf *sb = r_strbuf_new ("");
	bool first = true;
	for (i = 0; i < n; i++) {
		if (!drop[i] && out[i]) {
			if (!first) {
				r_strbuf_append (sb, "\n");
			}
			first = false;
			r_strbuf_append (sb, out[i]);
		}
		free (out[i]);
	}
	free (out);
	free (drop);
	free (code);
	return r_strbuf_drain (sb);
}

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

static char *next_comment(char *s, char *line_end) {
	char *next = strstr (s, " // ");
	return next && (!line_end || next < line_end)? next: NULL;
}

static void dedup_comments(char *s) {
	char *line = s;
	while (*line) {
		char *line_end = strchr (line, '\n');
		char *comment = next_comment (line, line_end);
		while (comment) {
			char *next = next_comment (comment + 4, line_end);
			if (!next) {
				break;
			}
			char *after = next_comment (next + 4, line_end);
			char *next_end = after? after: line_end;
			if (!next_end) {
				next_end = next + strlen (next);
			}
			const char *text = comment + 4;
			const char *next_text = next + 4;
			size_t text_len = next - text;
			size_t next_len = next_end - next_text;
			bool repeated = text_len == next_len && !strncmp (text, next_text, text_len);
			if (!repeated && text_len < next_len && next_text[text_len] == '(') {
				repeated = !strncmp (text, next_text, text_len);
			}
			if (repeated) {
				size_t removed = next - comment;
				memmove (comment, next, strlen (next) + 1);
				if (line_end) {
					line_end -= removed;
				}
				continue;
			}
			comment = next;
		}
		if (!line_end) {
			break;
		}
		line = line_end + 1;
	}
}

static char *comments_to_c(char *s) {
	if (!strchr (s, ';')) {
		return s;
	}
	RStrBuf *sb = r_strbuf_new ("");
	const char *chunk = s;
	const char *p;
	for (p = s; *p; p++) {
		if (is_comment_semicolon (s, p)) {
			r_strbuf_append_n (sb, chunk, p - chunk);
			r_strbuf_append (sb, "//");
			chunk = p + 1;
		}
	}
	r_strbuf_append_n (sb, chunk, p - chunk);
	free (s);
	return r_strbuf_drain (sb);
}

static char *cleancomments(char *s) {
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
	s = r_str_replace (s, "\n\n", "\n", true);
	remove_double_spaces (s);
	dedup_comments (s);
	return s;
}

static char *disat(RCore *core, ut64 addr, int *pad) {
	char *s = r_core_cmd_strf (core, "pi 1 @e:scr.color=0@e:asm.pseudo=0@e:asm.addr=1@ 0x%08" PFMT64x, addr);
	r_str_trim (s);
	*pad = 30 - r_str_ansi_len (s);
	return s;
}

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

static void annotate_offset(PDCState *state, size_t start, ut64 addr) {
	if (state->pj) {
		pj_o (state->pj);
		pj_kn (state->pj, "start", start);
		pj_kn (state->pj, "end", r_strbuf_length (state->codestr));
		pj_kn (state->pj, "offset", addr);
		pj_ks (state->pj, "type", "offset");
		pj_end (state->pj);
	}
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

static void print_newline(PDCState *state, ut64 addr, int indent, bool synthetic) {
	RStrBuf *sb = state_sb (state);
	r_strbuf_append (sb, "\n");
	if (state->show_asm) {
		if (synthetic) {
			print_pipe_header (state, addr);
		} else {
			asm_append (sb, state->core, addr, " ");
			r_strbuf_append (sb, " | ");
		}
	} else if (state->show_addr) {
		const char *lead = state->pj? "": " ";
		r_strbuf_appendf (sb, "%s0x%08" PFMT64x " | ", lead, addr);
	}
	r_strbuf_pad (sb, ' ', indent * 4);
}

static void print_line(PDCState *state, ut64 addr, int indent, const char *fmt, ...) {
	print_newline (state, addr, indent, false);
	va_list ap;
	va_start (ap, fmt);
	r_strbuf_vappendf (state_sb (state), fmt, ap);
	va_end (ap);
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
		if (valid_addr (sop->def_val) && sop->def_val == addr) {
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

// a case flag names the orphan it labels, renames included, so never truncate it
static char *orphan_tag(RCore *core, ut64 addr) {
	RFlagItem *fi = r_flag_get_in (core->flags, addr);
	if (!fi || !r_str_startswith (fi->name, "case.")) {
		return strdup ("orphan");
	}
	const char *val = r_str_lchr (fi->name, '.') + 1;
	// the jmptbl flag carries the case value in decimal, as disasm reads it
	const int nval = atoi (val);
	if (IS_PRINTABLE (nval)) {
		return r_str_newf ("case '%c'", nval);
	}
	return r_str_newf ("case %s", val);
}

static bool pdc_is_ret_only_bb(RCore *core, ut64 addr) {
	RAnalBlock *bb = addr != UT64_MAX? r_anal_bb_from_offset (core->anal, addr): NULL;
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
	sdb_setf (gc, "1", 0, "%" PFMT64x ".to.%" PFMT64x, bb->addr, dst_addr);
	sdb_setf (gc, "1", 0, "%" PFMT64x ".to.%" PFMT64x, curr_addr, dst_addr);

	if (dst_addr != bb->addr) {
		print_newline (state, bb->addr, indent, true);
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
		print_newline (state, bb->addr, indent, true);
		print_goto_or_return (state, dst_addr, "");
	}
}

#define PRINTF(...) print_str(&state, __VA_ARGS__)
#define NEWLINE(addr, indent) print_newline(&state, addr, indent, false)
#define PRINTGOTO(dst_addr, curr_addr) print_goto(&state, bb, dst_addr, curr_addr, indent)
#define PRINTGOTO_DIRECT(dst_addr, curr_addr) print_goto_direct(&state, bb, dst_addr, curr_addr, indent)

static int bb_last_op_type(RCore *core, RAnalBlock *bb) {
	ut64 last_addr = bb->ninstr > 0? r_anal_bb_opaddr_i (bb, bb->ninstr - 1): UT64_MAX;
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

static bool bb_ends_with_terminator(RCore *core, RAnalBlock *bb) {
	int t = bb_last_op_type (core, bb);
	return t == R_ANAL_OP_TYPE_JMP || t == R_ANAL_OP_TYPE_UJMP
		|| t == R_ANAL_OP_TYPE_RET || t == R_ANAL_OP_TYPE_CRET;
}

static char *fetch_bb_pseudo(PDCState *state, RAnalBlock *bb) {
	RCons *cons = r_core_get_cons (state->core);
	r_cons_push (cons);
	bool html = r_config_get_b (state->core->config, "scr.html");
	r_config_set_b (state->core->config, "scr.html", false);
	char *code = r_core_cmd_strf (state->core, "pD %" PFMT64d " @ 0x%08" PFMT64x, bb->size, bb->addr);
	r_cons_pop (cons);
	r_config_set_b (state->core->config, "scr.html", html);
	if (R_STR_ISEMPTY (code)) {
		free (code);
		return NULL;
	}
	code = r_str_replace (code, "\n\n", "\n", true);
	code = comments_to_c (code);
	code = cleancomments (code);
	size_t len = strlen (code);
	if (len < 1) {
		free (code);
		return NULL;
	}
	code[len - 1] = 0;
	find_and_change (code, len);
	return fold_resolved_refs (state->core, code);
}

static bool is_known_loop_header(PDCState *state, ut64 addr) {
	return sdb_num_getf (state->db, NULL, "loop_header.%" PFMT64x, addr) != 0;
}

static bool line_is_goto(const char *line) {
	return r_str_startswith (line, "goto ") || r_str_startswith (line, "jmp ");
}

static bool line_is_cond_goto(const char *line) {
	return r_str_startswith (line, "if ") && strstr (line, "goto ");
}

// a rendered goto target: loc_ label, bare number or flag name, else UT64_MAX
static ut64 goto_target(PDCState *state, const char *tok) {
	tok = r_str_trim_head_ro (tok);
	if (r_str_startswith (tok, "loc_")) {
		tok += 4;
	}
	if (isdigit ((unsigned char)*tok)) {
		return r_num_get (NULL, tok);
	}
	char *name = r_str_ndup (tok, strcspn (tok, " \t;"));
	RFlagItem *fi = name? r_flag_get (state->core->flags, name): NULL;
	free (name);
	return fi? fi->addr: UT64_MAX;
}

// only the block's own two edges belong to its region, so a tail call, an indirect jump
// or a call rendered as `jmp` (riscv jal) is the sole remaining transfer and must survive
static bool line_targets_own_edge(PDCState *state, const char *line) {
	const char *p = strstr (line, "goto ");
	if (p) {
		p += 5;
	} else {
		p = strstr (line, "jmp ");
		if (!p) {
			return false;
		}
		p += 4;
	}
	const ut64 dst = goto_target (state, p);
	// an unset jump or fail edge is UT64_MAX too, so it must not match
	return dst != UT64_MAX && (dst == state->bb_jump || dst == state->bb_fail);
}

static bool line_is_known_loop_goto(PDCState *state, const char *line) {
	const char *num = line_is_goto (line)? strstr (line, "0x"): NULL;
	ut64 dst = num? r_num_get (NULL, num): 0;
	return dst && dst != UT64_MAX && is_known_loop_header (state, dst);
}

static bool part_of_a_switch(PDCState *state, ut64 addr) {
	return state->switch_addrs && r_bitset_test (state->switch_addrs, addr);
}

static void collect_switch_addrs(PDCState *state) {
	state->switch_addrs = r_bitset_new ();
	if (!state->fcn || !state->fcn->bbs) {
		return;
	}
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (state->fcn->bbs, iter, bb) {
		RAnalSwitchOp *sop = bb->switch_op;
		if (!sop) {
			continue;
		}
		if (sop->addr != UT64_MAX) {
			r_bitset_set (state->switch_addrs, sop->addr);
		}
		if (sop->jump_addr != UT64_MAX) {
			r_bitset_set (state->switch_addrs, sop->jump_addr);
		}
		int i;
		for (i = 0; i < sop->deps_count; i++) {
			r_bitset_set (state->switch_addrs, sop->deps[i]);
		}
	}
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
		if (part_of_a_switch (state, addr)) {
			continue;
		}
		if (R_STR_ISNOTEMPTY (line)) {
			const char *t = r_str_trim_head_ro (line);
			if (state->structured && (line_is_goto (t) || line_is_cond_goto (t))
					&& line_targets_own_edge (state, t)) {
				continue;
			}
			// drop tail goto into a structured loop header (the while/do owns that edge)
			if (line_is_goto (t) && (strstr (t, "switch table")
					|| line_is_known_loop_goto (state, t))) {
				continue;
			}
		}
		const size_t start = r_strbuf_length (state->codestr);
		if (R_STR_ISNOTEMPTY (line)) {
			print_newline (state, addr, indent, false);
			print_str (state, "%s", line);
		}
		if (emit_pj) {
			annotate_offset (state, start, addr);
		}
	}
	r_list_free (lines);
	return addr;
}

static void emit_close_braces(PDCState *state, ut64 addr, int from, int to) {
	int i;
	for (i = from; i > to; i--) {
		print_newline (state, addr, i, false);
		print_str (state, "}");
	}
}

static char *pdc_prefix_lines(const char *s, const char *prefix, bool addr_pipe) {
	if (R_STR_ISEMPTY (s)) {
		return strdup (prefix);
	}
	RStrBuf *sb = r_strbuf_new ("");
	while (*s) {
		if (!addr_pipe) {
			// the prefix replaces pdb's own leading indent
			s += strspn (s, " \t");
		}
		const char *end = s + strcspn (s, "\n");
		r_strbuf_append (sb, prefix);
		if (addr_pipe && end - s > 2 && r_str_startswith (s, "0x")) {
			const char *p = s + 2;
			while (p < end && IS_HEXCHAR (*p)) {
				p++;
			}
			if (p > s + 2) {
				r_strbuf_append_n (sb, s, p - s);
				r_strbuf_append (sb, " |");
				s = p;
			}
		}
		r_strbuf_append_n (sb, s, end - s);
		if (*end == '\n') {
			r_strbuf_append (sb, "\n");
			s = end + 1;
		} else {
			break;
		}
	}
	return r_strbuf_drain (sb);
}

static void mark_bb_visited(PDCState *state, RList *visited, RAnalBlock *cbb) {
	r_bitset_set (state->marked, cbb->addr);
	if (!r_list_contains (visited, cbb)) {
		r_list_append (visited, cbb);
	}
}

typedef struct {
	ut64 value;
	ut64 jump;
	bool first; // no lower value shares this target, so this run owns the body
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
			const char *op1 = r_str_trim_head_ro (t + 4);
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

static void render_bb_body_lines(PDCState *state, RAnalBlock *bb, int indent) {
	char *code = fetch_bb_pseudo (state, bb);
	// mark only once the body is in hand, so a failed fetch leaves the block to the orphan pass
	if (code) {
		r_bitset_set (state->marked, bb->addr);
		state->bb_jump = bb->jump;
		state->bb_fail = bb->fail;
		emit_code_lines (state, code, bb->addr, indent, false);
		state->bb_jump = state->bb_fail = UT64_MAX;
		free (code);
	}
}

static void emit_case_label(PDCState *state, ut64 lo, ut64 hi, ut64 target, int indent) {
	print_newline (state, target, indent, false);
	if (lo == hi && IS_PRINTABLE (lo)) {
		print_str (state, "case %" PFMT64d ": // '%c' 0x%08" PFMT64x,
			lo, (int)lo, target);
	} else if (lo == hi) {
		print_str (state, "case %" PFMT64d ": // 0x%08" PFMT64x, lo, target);
	} else if (IS_PRINTABLE (lo) && IS_PRINTABLE (hi)) {
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
		render_bb_body_lines (state, cbb, indent);
		if (!bb_ends_with_terminator (state->core, cbb)) {
			print_newline (state, target, indent, false);
			print_str (state, "break;");
		}
		mark_bb_visited (state, visited, cbb);
	} else {
		print_newline (state, target, indent, false);
		print_goto_or_return (state, target, "");
	}
}

// value-sorted, de-duplicated case table; *n returns its length, caller frees
static PDCSwCase *switch_cases(RAnalSwitchOp *sop, int *n) {
	*n = 0;
	const int ncases = sop->cases? r_list_length (sop->cases): 0;
	if (ncases < 1) {
		return NULL;
	}
	PDCSwCase *arr = R_NEWS0 (PDCSwCase, ncases);
	if (!arr) {
		return NULL;
	}
	int i = 0;
	RListIter *iter;
	RAnalCaseOp *co;
	r_list_foreach (sop->cases, iter, co) {
		// build_switch skips unresolved entries too, so neither side invents an arm
		if (co->jump == UT64_MAX) {
			continue;
		}
		arr[i].value = co->value;
		arr[i].jump = co->jump;
		i++;
	}
	qsort (arr, i, sizeof (PDCSwCase), pdc_case_cmp);
	HtUU *seen = ht_uu_new0 ();
	int w = 0;
	int r;
	for (r = 0; r < i; r++) {
		if (w > 0 && arr[w - 1].value == arr[r].value
				&& arr[w - 1].jump == arr[r].jump) {
			continue;
		}
		arr[w] = arr[r];
		arr[w].first = !seen || !ht_uu_find (seen, arr[r].jump, NULL);
		if (seen) {
			ht_uu_insert (seen, arr[r].jump, 1);
		}
		w++;
	}
	ht_uu_free (seen);
	*n = w;
	return arr;
}

// where a jump table arm comes from: the region AST, or the linear walk
typedef struct {
	RList *visited;
	PdcRegion *sw;
	RBitset *gotos;
} PdcArms;

static void render_switch_cases(PDCState *state, RAnalBlock *sw_bb, PdcArms *arms, int indent);

static void render_switch(PDCState *state, RAnalBlock *sw_bb, RList *visited, int indent) {
	PdcArms arms = { .visited = visited };
	render_switch_cases (state, sw_bb, &arms, indent);
}

static char *extract_loop_cond(PDCState *state, RAnalBlock *test_bb, ut64 back_target) {
	// size-bounded like fetch_bb_pseudo: ninstr desyncs on overlapping blocks
	char *code = r_core_cmd_strf (state->core,
		"pD %" PFMT64d " @e:asm.pseudo=1@e:scr.color=0@e:asm.addr=0@e:asm.comments=0@ 0x%08" PFMT64x,
		test_bb->size, test_bb->addr);
	if (R_STR_ISEMPTY (code)) {
		free (code);
		return NULL;
	}
	char *result = NULL;
	char *vexpr = NULL;
	RList *lines = r_str_split_list (code, "\n", 0);
	RListIter *iter;
	char *line;
	r_list_foreach (lines, iter, line) {
		const char *t = r_str_trim_head_ro (line);
		if (r_str_startswith (t, "v = ")) {
			free (vexpr);
			vexpr = strdup (t + 4);
			continue;
		}
		if (!r_str_startswith (t, "if ")) {
			continue;
		}
		const char *g = strstr (t, "goto ");
		if (!g || goto_target (state, g + 5) != back_target) {
			continue;
		}
		const char *open = strchr (t, '(');
		if (!open) {
			continue;
		}
		int depth = 0;
		const char *p, *close = NULL;
		for (p = open; *p; p++) {
			if (*p == '(') {
				depth++;
			} else if (*p == ')' && --depth == 0) {
				close = p;
				break;
			}
		}
		if (close && close > open + 1) {
			free (result);
			result = r_str_ndup (open + 1, close - open - 1);
			if (result) {
				r_str_trim (result);
			}
		}
	}
	r_list_free (lines);
	free (code);
	if (result && vexpr) {
		const char *minus = strstr (vexpr, " - ");
		char *vlhs = minus? r_str_ndup (vexpr, minus - vexpr): NULL;
		const char *vrhs = minus? r_str_trim_head_ro (minus + 3): NULL;
		char *folded = NULL;
		if (!strcmp (result, "v")) {
			folded = strdup (vexpr);
		} else if (!strcmp (result, "!v")) {
			folded = vlhs? r_str_newf ("%s == %s", vlhs, vrhs): r_str_newf ("!(%s)", vexpr);
		} else if (r_str_startswith (result, "v ") && vlhs && r_str_endswith (result, " 0")) {
			char *op = r_str_ndup (result + 2, strlen (result + 2) - 2);
			r_str_trim (op);
			folded = r_str_newf ("%s %s %s", vlhs, op, vrhs);
			free (op);
		} else if (r_str_startswith (result, "v ")) {
			folded = r_str_newf ("(%s)%s", vexpr, result + 1);
		}
		free (vlhs);
		if (folded) {
			free (result);
			result = folded;
		}
	}
	free (vexpr);
	return result;
}

static void cond_kvfree(HtUPKv *kv) {
	free (kv->value);
}

// recovery costs a pi command and a parse, and every caller wants the same one
static const char *cond_at(PDCState *state, RAnalBlock *bb) {
	bool found = false;
	char *cond = ht_up_find (state->conds, bb->addr, &found);
	if (!found) {
		cond = extract_loop_cond (state, bb, bb->jump);
		ht_up_insert (state->conds, bb->addr, cond);
	}
	return cond;
}

static char *invert_cond(const char *cond);

// an unrecovered condition is named after its block, keeping the branch sense
static char *cond_or_addr(const char *cond, ut64 addr, bool invert) {
	if (!cond) {
		return r_str_newf ("%scond_0x%08" PFMT64x, invert? "!": "", addr);
	}
	return invert? invert_cond (cond): strdup (cond);
}

static char *cond_str(PDCState *state, RAnalBlock *bb, bool invert) {
	return cond_or_addr (cond_at (state, bb), bb->addr, invert);
}

static bool line_is_branch_to(const char *line, const char *target_hex) {
	const char *t = r_str_trim_head_ro (line);
	return strstr (t, target_hex) && (line_is_goto (t) || line_is_cond_goto (t));
}

static RAnalBlock *render_loop_while(PDCState *state, RAnalBlock *test_bb, RList *visited, int indent);

static void emit_bb_body_no_back_jump(PDCState *state, RAnalBlock *bb, ut64 back_target, int indent) {
	char *code = fetch_bb_pseudo (state, bb);
	if (!code) {
		return;
	}
	RList *lines = r_str_split_list (code, "\n", 0);
	RListIter *iter;
	const char *line;
	ut64 addr = bb->addr;
	char back_hex[32];
	snprintf (back_hex, sizeof (back_hex), "0x%08" PFMT64x, back_target);
	char back_hex_short[32];
	snprintf (back_hex_short, sizeof (back_hex_short), "0x%" PFMT64x, back_target);
	r_list_foreach (lines, iter, line) {
		const char *rendered = line;
		if (*rendered == '0') {
			ut64 at = r_num_get (NULL, rendered);
			if (at && at != UT64_MAX) {
				addr = at;
			}
			const char *s = strchr (rendered, ' ');
			rendered = s? r_str_trim_head_ro (s + 1): "";
		}
		if (R_STR_ISEMPTY (rendered)) {
			continue;
		}
		if (part_of_a_switch (state, addr)) {
			continue;
		}
		if (line_is_branch_to (rendered, back_hex)
				|| line_is_branch_to (rendered, back_hex_short)) {
			continue;
		}
		if (line_is_known_loop_goto (state, r_str_trim_head_ro (rendered))) {
			continue;
		}
		print_newline (state, addr, indent, false);
		print_str (state, "%s", rendered);
	}
	r_list_free (lines);
	free (code);
}

// Renders body+tail-test as while, single-bb self-loop as do/while; returns post-loop exit bb or NULL.
static RAnalBlock *render_loop_while(PDCState *state, RAnalBlock *test_bb, RList *visited, int indent) {
	if (test_bb->jump == UT64_MAX || test_bb->fail == UT64_MAX
			|| !r_anal_function_contains (state->fcn, test_bb->jump)
			|| !r_anal_function_contains (state->fcn, test_bb->fail)) {
		return NULL;
	}
	bool self_loop = (test_bb->jump == test_bb->addr);
	if (!self_loop && test_bb->jump >= test_bb->addr) {
		return NULL;
	}
	char *cond = extract_loop_cond (state, test_bb, test_bb->jump);
	print_newline (state, test_bb->addr, indent, false);
	if (self_loop) {
		print_str (state, "do {");
	} else {
		char *c = cond_or_addr (cond, test_bb->addr, false);
		print_str (state, "while (%s) {", c);
		free (c);
	}
	if (self_loop) {
		emit_bb_body_no_back_jump (state, test_bb, test_bb->addr, indent + 1);
		mark_bb_visited (state, visited, test_bb);
		print_newline (state, test_bb->addr, indent, false);
		char *c = cond_or_addr (cond, test_bb->addr, false);
		print_str (state, "} while (%s);", c);
		free (c);
	} else {
		ut64 body_start = test_bb->jump;
		ut64 body_end = test_bb->addr;
		RList *sorted = r_list_new ();
		RListIter *iter;
		RAnalBlock *b;
		if (sorted) {
			r_list_foreach (state->fcn->bbs, iter, b) {
				if (b->addr >= body_start && b->addr < body_end) {
					r_list_append (sorted, b);
				}
			}
		}
		// nested loop tests: bbs in [body_start,body_end) whose back-jump stays inside.
		ut64 owned_lo[16];
		ut64 owned_hi[16];
		int nowned = 0;
		r_list_foreach (sorted, iter, b) {
			if (b->jump != UT64_MAX && b->fail != UT64_MAX
					&& b->jump < b->addr
					&& b->jump >= body_start
					&& b->addr < body_end
					&& nowned < 16) {
				owned_lo[nowned] = b->jump;
				owned_hi[nowned] = b->addr;
				nowned++;
			}
		}
		r_list_foreach (sorted, iter, b) {
			if (r_bitset_test (state->marked, b->addr)) {
				continue;
			}
			bool is_nested_test = false;
			int oi;
			for (oi = 0; oi < nowned; oi++) {
				if (owned_hi[oi] == b->addr) {
					is_nested_test = true;
					break;
				}
			}
			if (is_nested_test) {
				render_loop_while (state, b, visited, indent + 1);
				continue;
			}
			bool owned = false;
			for (oi = 0; oi < nowned; oi++) {
				if (b->addr >= owned_lo[oi] && b->addr < owned_hi[oi]) {
					owned = true;
					break;
				}
			}
			if (owned) {
				continue;
			}
			if (b->switch_op) {
				render_switch (state, b, visited, indent + 1);
				mark_bb_visited (state, visited, b);
				continue;
			}
			if (b->fail != UT64_MAX) {
				RAnalBlock *fb = r_anal_bb_from_offset (state->core->anal, b->fail);
				if (fb && fb->switch_op) {
					emit_bb_body_no_back_jump (state, b, test_bb->addr, indent + 1);
					mark_bb_visited (state, visited, b);
					render_switch (state, fb, visited, indent + 1);
					mark_bb_visited (state, visited, fb);
					continue;
				}
			}
			emit_bb_body_no_back_jump (state, b, test_bb->addr, indent + 1);
			mark_bb_visited (state, visited, b);
		}
		r_list_free (sorted);
		mark_bb_visited (state, visited, test_bb);
		print_newline (state, test_bb->addr, indent, false);
		print_str (state, "}");
	}
	free (cond);
	return r_anal_bb_from_offset (state->core->anal, test_bb->fail);
}

static int pdc_argnum_cmp(RAnalVar *const *a, RAnalVar *const *b) {
	return r_anal_var_get_argnum (*a) - r_anal_var_get_argnum (*b);
}

// "type name, type name, ..." for the true args (isarg) ordered by argnum
static char *pdc_signature_args(RAnal *anal, RAnalFunction *fcn) {
	RVecAnalVarPtr *vars = r_anal_function_vars (anal, fcn);
	if (!vars) {
		return NULL;
	}
	RVecAnalVarPtr_sort (vars, pdc_argnum_cmp);
	RStrBuf *sb = r_strbuf_new ("");
	RAnalVar **it;
	bool first = true;
	R_VEC_FOREACH (vars, it) {
		RAnalVar *var = *it;
		if (!var->isarg) {
			continue;
		}
		const char *nm = R_STR_ISNOTEMPTY (var->name)? var->name: var->regname;
		const char *ty = R_STR_ISNOTEMPTY (var->type)? var->type: "int";
		r_strbuf_appendf (sb, "%s%s %s", first? "": ", ", ty, nm? nm: "arg");
		first = false;
	}
	RVecAnalVarPtr_free (vars);
	return r_strbuf_drain (sb);
}

static char *pdc_return_type(const char *fs, const char *name) {
	if (R_STR_ISEMPTY (fs)) {
		return NULL;
	}
	const char *paren = strchr (fs, '(');
	const char *nm = NULL;
	const char *p = fs;
	while ((p = strstr (p, name))) {
		if (paren && p >= paren) {
			break;
		}
		nm = p;
		p += strlen (name);
	}
	if (!nm || nm == fs) {
		return NULL;
	}
	char *ret = r_str_ndup (fs, nm - fs);
	r_str_trim (ret);
	return ret;
}

static bool pdc_comment_line_is_meaningful(const char *line) {
	if (R_STR_ISEMPTY (line) || !strcmp (line, "{") || !strcmp (line, "}")) {
		return false;
	}
	return !r_str_startswith (line, "// callconv:");
}

static void pdc_print_comment_cmds(RCore *core, const char *s) {
	while (R_STR_ISNOTEMPTY (s)) {
		const char *end = strchr (s, '\n');
		size_t len = end? (size_t)(end - s): strlen (s);
		char *line = r_str_ndup (s, len);
		if (!line) {
			return;
		}
		const char *p = r_str_trim_head_ro (line);
		if (r_str_startswith (p, "0x")) {
			const char *q = p + 2;
			while (IS_HEXCHAR (*q)) {
				q++;
			}
			if (q > p + 2) {
				ut64 addr = r_num_get (core->num, p);
				while (*q == ' ') {
					q++;
				}
				if (*q == '|') {
					const char *body = r_str_trim_head_ro (q + 1);
					if (*body == '|') {
						body = r_str_trim_head_ro (body + 1);
					}
					char *comment = strdup (body);
					if (comment) {
						r_str_trim_tail (comment);
						if (pdc_comment_line_is_meaningful (comment)) {
							char *b64 = r_base64_encode_dyn ((const ut8 *)comment, -1);
							if (b64) {
								r_cons_printf (r_core_get_cons (core), "CCu base64:%s @ 0x%08" PFMT64x "\n", b64, addr);
								free (b64);
							}
						}
						free (comment);
					}
				}
			}
		}
		free (line);
		if (!end) {
			break;
		}
		s = end + 1;
	}
}

static bool case_table_has(const PDCSwCase *arr, int n, ut64 target) {
	int i;
	for (i = 0; i < n; i++) {
		if (arr[i].jump == target) {
			return true;
		}
	}
	return false;
}

static void collect_goto_targets(PDCState *state, PdcRegion *r, RBitset *gotos) {
	if (r->type == PDC_R_GOTO) {
		r_bitset_set (gotos, r->addr);
	}
	if (r->type == PDC_R_SWITCH) {
		RAnalBlock *bb = r_anal_get_block_at (state->core->anal, r->addr);
		int n = 0;
		PDCSwCase *arr = bb && bb->switch_op? switch_cases (bb->switch_op, &n): NULL;
		int c;
		// mid-run entries repeat their own target, so only run starts count
		for (c = 0; c < n; c++) {
			const bool run_start = !c || arr[c].jump != arr[c - 1].jump;
			if (run_start && !arr[c].first) {
				r_bitset_set (gotos, arr[c].jump);
			}
		}
		if (arr && valid_addr (bb->switch_op->def_val)
				&& case_table_has (arr, n, bb->switch_op->def_val)) {
			r_bitset_set (gotos, bb->switch_op->def_val);
		}
		free (arr);
	}
	PdcRegion **it;
	R_VEC_FOREACH (&r->children, it) {
		collect_goto_targets (state, *it, gotos);
	}
}

// invert a condition by flipping its top-level comparison; fall back to !(cond)
static char *invert_cond(const char *cond) {
	static const char *const ops[][2] = {
		{ "==", "!=" }, { "!=", "==" }, { "<=", ">" }, { ">=", "<" }, { "<", ">=" }, { ">", "<=" }
	};
	// an already negated condition inverts by unwrapping, not by stacking another !
	if (r_str_startswith (cond, "!(") && r_str_endswith (cond, ")")) {
		int depth = 0;
		const char *p;
		for (p = cond + 1; *p; p++) {
			depth += (*p == '(') - (*p == ')');
			if (!depth) {
				break;
			}
		}
		// only when the negation spans the whole condition, so `!(a) == b` is left alone
		if (*p && !p[1]) {
			return r_str_ndup (cond + 2, p - cond - 2);
		}
	}
	// flipping one operand of a compound condition needs De Morgan, so negate it whole
	if (strstr (cond, "&&") || strstr (cond, "||")) {
		return r_str_newf ("!(%s)", cond);
	}
	int depth = 0;
	const char *p;
	for (p = cond; *p; p++) {
		if (*p == '(') {
			depth++;
		} else if (*p == ')') {
			depth--;
		} else if (depth == 0 && p > cond && p[-1] == ' ') {
			size_t i;
			for (i = 0; i < R_ARRAY_SIZE (ops); i++) {
				const size_t olen = strlen (ops[i][0]);
				// flip only space-delimited operators so `<<`, `>>` or `->` never match
				if (!strncmp (p, ops[i][0], olen) && p[olen] == ' ') {
					char *lhs = r_str_ndup (cond, p - cond);
					r_str_trim (lhs);
					const char *rhs = r_str_trim_head_ro (p + olen);
					char *res = r_str_newf ("%s %s %s", lhs, ops[i][1], rhs);
					free (lhs);
					return res;
				}
			}
		}
	}
	return r_str_newf ("!(%s)", cond);
}

static void render_region(PDCState *state, PdcRegion *r, int indent, RBitset *gotos);
static void render_ifelse(PDCState *state, PdcRegion *r, RAnalBlock *bb, int indent, RBitset *gotos);
static void render_switch_region(PDCState *state, PdcRegion *r, RAnalBlock *bb, int indent, RBitset *gotos);

static PdcRegion *region_first_child(PdcRegion *r) {
	PdcRegion **first = RVecPdcRegionPtr_at (&r->children, 0);
	return first? *first: NULL;
}

static PdcRegion *region_child_at(PdcRegion *r, ut64 addr) {
	PdcRegion **it;
	R_VEC_FOREACH (&r->children, it) {
		if ((*it)->addr == addr) {
			return *it;
		}
	}
	return NULL;
}

// whether the region's last statement already transfers control elsewhere
static bool region_tail_transfers(PDCState *state, PdcRegion *r) {
	switch (r->type) {
	case PDC_R_GOTO:
	case PDC_R_BREAK:
	case PDC_R_CONTINUE:
		return true;
	case PDC_R_SEQ: {
		PdcRegion **last = RVecPdcRegionPtr_last (&r->children);
		return last? region_tail_transfers (state, *last): false;
	}
	case PDC_R_BB: {
		RAnalBlock *bb = r_anal_get_block_at (state->core->anal, r->addr);
		// a jump to the block's own edge is dropped, a ret or ujmp is not
		const int t = bb? bb_last_op_type (state->core, bb): -1;
		return t == R_ANAL_OP_TYPE_RET || t == R_ANAL_OP_TYPE_CRET
			|| t == R_ANAL_OP_TYPE_UJMP;
	}
	case PDC_R_IFELSE: {
		// both arms must leave, or control falls out of the conditional
		PdcRegion **a = RVecPdcRegionPtr_at (&r->children, 0);
		PdcRegion **b = RVecPdcRegionPtr_at (&r->children, 1);
		return a && b && region_tail_transfers (state, *a)
			&& region_tail_transfers (state, *b);
	}
	default:
		return false;
	}
}

static bool region_emits_cond(PdcRegion *r, RAnalBlock *bb) {
	switch (r->type) {
	case PDC_R_IF:
	case PDC_R_IFELSE:
		return true;
	case PDC_R_WHILE:
	case PDC_R_DOWHILE:
		// a bodyless loop renders a do/while test only as a self edge
		return region_first_child (r)? r->type == PDC_R_WHILE: bb->jump == bb->addr;
	default:
		return false;
	}
}

// the header carries work too, so emit while (true) plus an explicit break
static void render_loop(PDCState *state, PdcRegion *r, RAnalBlock *bb, int indent, RBitset *gotos) {
	PdcRegion *body = region_first_child (r);
	if (!body && !region_emits_cond (r, bb)) {
		// no body and no self edge: degrade rather than emit an empty loop
		render_bb_body_lines (state, bb, indent);
		return;
	}
	if (!body) {
		print_line (state, bb->addr, indent, "do {");
		render_bb_body_lines (state, bb, indent + 1);
		char *tc = cond_str (state, bb, false);
		print_line (state, bb->addr, indent, "} while (%s);", tc);
		free (tc);
		return;
	}
	print_line (state, bb->addr, indent, "while (true) {");
	if (body->role != PDC_ROLE_HEAD) {
		// a body that heads the loop block is its conditional, and renders it
		render_bb_body_lines (state, bb, indent + 1);
	}
	if (region_emits_cond (r, bb)) {
		// the header picks between body and exit; break on the exit edge
		char *ec = cond_str (state, bb, body->role == PDC_ROLE_JUMP);
		print_line (state, bb->addr, indent + 1, "if (%s) {", ec);
		print_line (state, bb->addr, indent + 2, "break;");
		print_line (state, bb->addr, indent + 1, "}");
		free (ec);
	}
	if (body->role == PDC_ROLE_HEAD) {
		// the loop region already emitted this block's label and owns its lines
		if (body->type == PDC_R_SWITCH) {
			render_switch_region (state, body, bb, indent + 1, gotos);
		} else {
			render_ifelse (state, body, bb, indent + 1, gotos);
		}
	} else {
		render_region (state, body, indent + 1, gotos);
	}
	print_line (state, bb->addr, indent, "}");
}

static void render_arm(PDCState *state, PdcArms *arms, ut64 target, int indent, bool owns_body) {
	if (!arms->sw) {
		render_arm_body (state, arms->visited, target, indent);
		return;
	}
	if (!owns_body) {
		print_newline (state, target, indent, false);
		print_goto_or_return (state, target, "");
		return;
	}
	PdcRegion *arm = region_child_at (arms->sw, target);
	if (arm) {
		render_region (state, arm, indent, arms->gotos);
		if (region_tail_transfers (state, arm)) {
			return;
		}
	}
	print_line (state, target, indent, "break;");
}

// jump table emitter shared by the linear and the region renderers
static void render_switch_cases(PDCState *state, RAnalBlock *sw_bb, PdcArms *arms, int indent) {
	RAnalSwitchOp *sop = sw_bb->switch_op;
	int n = 0;
	PDCSwCase *arr = switch_cases (sop, &n);
	if (!arr) {
		return;
	}
	char *expr = find_switch_expr (state->core, state->fcn, sw_bb);
	const ut64 table_addr = valid_addr (sop->daddr)? sop->daddr: sw_bb->addr;
	print_line (state, sw_bb->addr, indent,
		"switch (%s) { // jump table of %d cases at 0x%08" PFMT64x,
		expr, n, table_addr);
	free (expr);
	int c = 0;
	while (c < n) {
		int k = c;
		while (k + 1 < n && arr[k + 1].jump == arr[c].jump) {
			k++;
		}
		const ut64 target = arr[c].jump;
		if (k - c >= 2 && pdc_range_is_contiguous (arr, c, k)) {
			emit_case_label (state, arr[c].value, arr[k].value, target, indent + 1);
		} else {
			int j;
			for (j = c; j <= k; j++) {
				emit_case_label (state, arr[j].value, arr[j].value, target, indent + 1);
			}
		}
		render_arm (state, arms, target, indent + 2, arr[c].first);
		c = k + 1;
	}
	if (valid_addr (sop->def_val)) {
		print_line (state, sop->def_val, indent + 1,
			"default: // 0x%08" PFMT64x, sop->def_val);
		render_arm (state, arms, sop->def_val, indent + 2,
			!case_table_has (arr, n, sop->def_val));
	}
	print_line (state, sw_bb->addr, indent, "}");
	free (arr);
}

static void render_switch_region(PDCState *state, PdcRegion *r, RAnalBlock *bb, int indent, RBitset *gotos) {
	render_bb_body_lines (state, bb, indent);
	// mark even on a failed body fetch, or the hoist pass emits the table twice
	r_bitset_set (state->marked, bb->addr);
	PdcArms arms = { .sw = r, .gotos = gotos };
	render_switch_cases (state, bb, &arms, indent);
}

static void render_ifelse(PDCState *state, PdcRegion *r, RAnalBlock *bb, int indent, RBitset *gotos) {
	render_bb_body_lines (state, bb, indent);
	PdcRegion *then_arm = *RVecPdcRegionPtr_at (&r->children, 0);
	PdcRegion *else_arm = (r->type == PDC_R_IFELSE)? *RVecPdcRegionPtr_at (&r->children, 1): NULL;
	// pseudo says `if (cond) goto jump`, so the fall-through arm reads as the then
	if (else_arm && then_arm->role == PDC_ROLE_JUMP && else_arm->role == PDC_ROLE_FAIL) {
		PdcRegion *tmp = then_arm;
		then_arm = else_arm;
		else_arm = tmp;
	}
	char *cond = cond_str (state, bb, then_arm->role == PDC_ROLE_FAIL);
	print_line (state, bb->addr, indent, "if (%s) {", cond);
	render_region (state, then_arm, indent + 1, gotos);
	if (else_arm) {
		print_line (state, bb->addr, indent, "} else {");
		render_region (state, else_arm, indent + 1, gotos);
	}
	print_line (state, bb->addr, indent, "}");
	free (cond);
}

static void render_region(PDCState *state, PdcRegion *r, int indent, RBitset *gotos) {
	if (r->type == PDC_R_SEQ) {
		PdcRegion **it;
		R_VEC_FOREACH (&r->children, it) {
			render_region (state, *it, indent, gotos);
		}
		return;
	}
	if (r->type == PDC_R_BREAK || r->type == PDC_R_CONTINUE) {
		print_line (state, r->addr, indent, "%s;", (r->type == PDC_R_BREAK)? "break": "continue");
		return;
	}
	if (r->type == PDC_R_GOTO) {
		print_line (state, r->addr, indent, "goto loc_0x%08" PFMT64x ";", r->addr);
		return;
	}
	RAnalBlock *bb = r_anal_get_block_at (state->core->anal, r->addr);
	if (!bb) {
		return;
	}
	if (r_bitset_test (gotos, r->addr)) {
		print_line (state, r->addr, indent, "loc_0x%08" PFMT64x ":", r->addr);
	}
	switch (r->type) {
	case PDC_R_IF:
	case PDC_R_IFELSE:
		render_ifelse (state, r, bb, indent, gotos);
		return;
	case PDC_R_WHILE:
	case PDC_R_DOWHILE:
		render_loop (state, r, bb, indent, gotos);
		return;
	case PDC_R_SWITCH:
		render_switch_region (state, r, bb, indent, gotos);
		return;
	default:
		render_bb_body_lines (state, bb, indent);
		return;
	}
}

// a conditional heading a block anal no longer knows would drop an arm
static bool regions_have_blocks(PDCState *state, PdcRegion *r) {
	const bool loop = r->type == PDC_R_WHILE || r->type == PDC_R_DOWHILE;
	if (loop || r->type == PDC_R_IF || r->type == PDC_R_IFELSE) {
		if (!r_anal_get_block_at (state->core->anal, r->addr)) {
			return false;
		}
	}
	PdcRegion **it;
	R_VEC_FOREACH (&r->children, it) {
		if (!regions_have_blocks (state, *it)) {
			return false;
		}
	}
	return true;
}

// renders the whole function from the region AST, or returns false to defer to the linear pass
static bool pdc_structured_body(PDCState *state, int indent) {
	PdcPlan *plan = pdc_plan_build (state->core, state->fcn);
	if (!plan || !plan->root) {
		pdc_plan_free (plan);
		return false;
	}
	PdcRegion *root = plan->root;
	state->conds = ht_up_new (NULL, cond_kvfree, NULL);
	const bool reducible = plan->complete && regions_have_blocks (state, root);
	if (reducible) {
		// scoped to this walk: the later orphan switch pass renders blocks no region owns
		const bool was_structured = state->structured;
		state->structured = true;
		RBitset *gotos = r_bitset_new ();
		collect_goto_targets (state, root, gotos);
		render_region (state, root, indent, gotos);
		r_bitset_free (gotos);
		state->structured = was_structured;
	}
	ht_up_free (state->conds);
	state->conds = NULL;
	pdc_plan_free (plan);
	return reducible;
}

R_IPI bool pdc_decompile(RCore *core, const char *input) {
	RCons *cons = r_core_get_cons (core);
	bool show_c_headers = *input == 'c';
	if (*input == 't') {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
		if (!fcn) {
			R_LOG_ERROR ("Cannot find function at 0x%08" PFMT64x, core->addr);
			return false;
		}
		char *dump = pdc_ast_dump (core, fcn);
		if (dump) {
			r_cons_print (cons, dump);
			free (dump);
		}
		return true;
	}

	const char *cmdPdc = r_config_get (core->config, "cmd.pdc");
	if (R_STR_ISNOTEMPTY (cmdPdc) && !strstr (cmdPdc, "pdc")) {
		RConfigHold *hc = r_config_hold_new (core->config);
		if (hc) {
			r_config_hold (hc, "asm.addr.relto", "asm.addr.base", NULL);
			r_config_set (core->config, "asm.addr.relto", "");
			r_config_set_i (core->config, "asm.addr.base", 16);
		}
		if (strstr (cmdPdc, "!*") || strstr (cmdPdc, "#!")) {
			if (!strcmp (input, "*")) {
				input = " -r2";
			} else if (!strcmp (input, "=")) {
				input = " -a";
			}
		}
		const bool ok = r_core_cmdf (core, "%s%s", cmdPdc, input) == 0;
		r_config_hold_restore (hc);
		r_config_hold_free (hc);
		return ok;
	}

	PDCState state = { 0 };
	state.core = core;
	state.out = r_strbuf_new ("");
	state.codestr = r_strbuf_new ("");
	state.goto_cache = sdb_new0 ();
	state.db = sdb_new0 ();
	state.marked = r_bitset_new ();
	state.pj = (*input == 'j')? r_core_pj_new (core): NULL;
	state.show_asm = (*input == 'a');
	const bool comment_cmds = *input == '*';
	state.show_addr = state.show_asm || (*input == 'o') || comment_cmds;
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
		r_bitset_free (state.marked);
		if (state.switch_addrs) {
			r_bitset_free (state.switch_addrs);
		}
		r_strbuf_free (state.out);
		r_strbuf_free (state.codestr);
		return false;
	}
	collect_switch_addrs (&state);
	r_config_hold (hc, "asm.pseudo", "asm.decode", "asm.lines", "asm.bytes", "asm.stackptr", NULL);
	r_config_hold (hc, "asm.addr", "asm.flags", "asm.lines.fcn", "asm.comments", NULL);
	r_config_hold (hc, "asm.functions", "asm.section", "asm.cmt.col", "asm.sub.names", NULL);
	r_config_hold (hc, "scr.color", "emu.str", "asm.emu", "emu.write", NULL);
	r_config_hold (hc, "io.cache", "asm.syntax", "asm.addr.relto", "asm.addr.base", NULL);
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
	r_config_set (core->config, "asm.addr.relto", "");
	r_config_set_i (core->config, "asm.addr.base", 16);
	r_core_cmd0 (core, "aeim");

	r_strf_buffer (64);
	RAnalBlock *bb = r_list_first (state.fcn->bbs);
	int indent = 0;
	int nindent = 1;
	int n_bb = r_list_length (state.fcn->bbs);

	if (state.pj) {
		pj_o (state.pj);
		pj_ka (state.pj, "annotations");
	}
	const char *fcncc = r_anal_function_cc (state.fcn);
	const char *cc = fcncc? fcncc: "default";
	const char *cc_a0 = r_anal_cc_argloc (state.core->anal, cc, 0, 0, -1);
	const char *cc_a1 = r_anal_cc_argloc (state.core->anal, cc, 1, 0, -1);
	const char *a0 = cc_a0? pseudo_arg_name (state.core->anal, cc_a0): r_reg_alias_getname (state.core->anal->reg, R_REG_ALIAS_A0);
	const char *a1 = cc_a1? pseudo_arg_name (state.core->anal, cc_a1): r_reg_alias_getname (state.core->anal->reg, R_REG_ALIAS_A1);
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
	if (R_STR_ISNOTEMPTY (fs) && !(r_str_startswith (fs, "void") && strstr (fs, "()"))) {
		// afs carries a real prototype (named/typed args): use it verbatim
		r_str_replace_char (fs, ';', ' ');
		r_str_trim (fs);
		PRINTF ("%s {", fs);
	} else {
		char *params = pdc_signature_args (core->anal, state.fcn);
		char *rettype = pdc_return_type (fs, state.fcn->name);
		PRINTF ("%s %s (%s) {", R_STR_ISNOTEMPTY (rettype)? rettype: "int", state.fcn->name,
			R_STR_ISNOTEMPTY (params)? params: "void");
		free (params);
		free (rettype);
	}
	free (fs);
	indent++;
	RList *visited = r_list_newf (NULL);
	ut64 addr = state.fcn->addr;
	// structured if/else emission for fully reducible functions; the linear
	// worklist below is skipped (finalize closes the brace) when it succeeds
	if (r_config_get_b (core->config, "pdc.structured")) {
		if (!state.pj && !state.show_asm && !comment_cmds && pdc_structured_body (&state, indent)) {
			bb = NULL;
		}
	}
	// pre-pass: mark loop header bbs so emit_code_lines can strip stale gotos to them
	{
		RListIter *piter;
		RAnalBlock *pbb;
		r_list_foreach (state.fcn->bbs, piter, pbb) {
			if (pbb->jump != UT64_MAX && pbb->fail != UT64_MAX
					&& pbb->jump <= pbb->addr
					&& r_anal_function_contains (state.fcn, pbb->jump)
					&& r_anal_function_contains (state.fcn, pbb->fail)) {
				sdb_num_setf (state.db, 1, 0, "loop_header.%" PFMT64x, pbb->addr);
			}
		}
	}
	while (bb) {
		r_list_append (visited, bb);
		indent = 2;
		// drain indent stack after a structural renderer to avoid spurious trailing returns
		if (r_bitset_test (state.marked, bb->addr)
				&& sdb_num_get (state.db,
					r_strf ("structured.%" PFMT64x, bb->addr), 0)) {
			RAnalBlock *next = NULL;
			while (true) {
				ut64 pop_addr = sdb_array_pop_num (state.db, "indent", NULL);
				if (pop_addr == UT64_MAX) {
					break;
				}
				if (r_bitset_test (state.marked, pop_addr)) {
					continue;
				}
				next = r_anal_bb_from_offset (core->anal, pop_addr);
				if (next) {
					break;
				}
			}
			if (!next) {
				break;
			}
			bb = next;
			continue;
		}
		// body+tail-test loop pattern: bb's back-edge points into an earlier body bb
		if (!r_bitset_test (state.marked, bb->addr)
				&& bb->fail != UT64_MAX
				&& bb->jump != UT64_MAX
				&& bb->jump <= bb->addr
				&& r_anal_function_contains (state.fcn, bb->jump)
				&& r_anal_function_contains (state.fcn, bb->fail)) {
			ut64 test_addr = bb->addr;
			RAnalBlock *exit_bb = render_loop_while (&state, bb, visited, indent - 1);
			if (exit_bb) {
				sdb_setf (state.goto_cache, "1", 0, "%" PFMT64x ".addr", test_addr);
				r_bitset_set (state.marked, test_addr);
				sdb_num_setf (state.db, 1, 0, "structured.%" PFMT64x, test_addr);
				sdb_num_setf (state.db, 1, 0, "structured.%" PFMT64x, exit_bb->addr);
				if (r_bitset_test (state.marked, exit_bb->addr)) {
					break;
				}
				bb = exit_bb;
				continue;
			}
		}
		char *code = fetch_bb_pseudo (&state, bb);
		if (!code) {
			R_LOG_ERROR ("Empty code here");
			break;
		}
		if (!r_bitset_test (state.marked, bb->addr)) {
			bool mustprint = !queuegoto || queuegoto != bb->addr || bb->jump == bb->addr;
			if (mustprint) {
				if (queuegoto && queuegoto != UT64_MAX) {
					queuegoto = 0LL;
				}
				if (bb_addr_is_goto_target (state.fcn, bb->addr)) {
					print_newline (&state, bb->addr, indent - 1, true);
					PRINTF ("loc_0x%08" PFMT64x ":", bb->addr);
				}
				addr = emit_code_lines (&state, code, bb->addr, indent, true);
				r_bitset_set (state.marked, bb->addr);
			}
		}
		free (code);
		{
			RAnalBlock *sw_bb = NULL;
			if (bb->switch_op) {
				sw_bb = bb;
			} else if (bb->fail != UT64_MAX) {
				RAnalBlock *fb = r_anal_bb_from_offset (core->anal, bb->fail);
				if (fb && fb->switch_op) {
					sw_bb = fb;
				}
			}
			if (sw_bb) {
				render_switch (&state, sw_bb, visited, indent - 1);
				r_bitset_set (state.marked, sw_bb->addr);
				sdb_num_setf (state.db, 1, 0, "structured.%" PFMT64x, sw_bb->addr);
				if (!r_list_contains (visited, sw_bb)) {
					r_list_append (visited, sw_bb);
				}
				sdb_setf (state.goto_cache, "1", 0, "%" PFMT64x ".addr", bb->addr);
				sdb_setf (state.goto_cache, "1", 0, "%" PFMT64x ".to.%" PFMT64x, bb->addr, sw_bb->addr);
				break;
			}
		}
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
		if (sdb_const_getf (state.db, 0, "loc.%" PFMT64x, bb->addr)) {
			unvisit (visited, bb);
			R_LOG_DEBUG ("// 0x%08" PFMT64x " already analyzed", bb->addr);
			ut64 addr = sdb_array_pop_num (state.db, "indent", NULL);
			if (addr == UT64_MAX) {
				closed = true;
				if (!bb_ends_with_terminator (core, bb)) {
					print_newline (&state, bb->addr, indent, true);
					PRINTF (r0? "return %s;": "return;", r0);
					sdb_setf (state.goto_cache, "1", 0, "return.%" PFMT64x, bb->addr);
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
			nindent = sdb_num_getf (state.db, NULL, "loc.%" PFMT64x, addr);
			if (indent > nindent && !strcmp (blocktype, "else")) {
				emit_close_braces (&state, addr, indent, nindent);
			}
			indent = nindent - 1;
		} else {
			sdb_set (state.db, K_INDENT (bb->addr), "passed", 0);
			if (has_jump) {
				int swap = 1;
				ut64 jump = swap? bb->jump: bb->fail;
				ut64 fail = swap? bb->fail: bb->jump;
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
				if (sdb_const_getf (state.db, 0, "loc.%" PFMT64x, jump)) {
					if (fail != UT64_MAX && !sdb_const_getf (state.db, 0, "loc.%" PFMT64x, fail)) {
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
						if (sdb_const_getf (state.db, 0, "loc.%" PFMT64x, bb->fail)) {
							R_LOG_DEBUG ("There's already a block at 0x%" PFMT64x, bb->addr);
						} else {
							sdb_array_push_num (state.db, "indent", fail, 0);
							sdb_num_set (state.db, K_INDENT (fail), indent, 0);
						}
					} else {
						sdb_array_push_num (state.db, "indent", jump, 0);
						sdb_num_set (state.db, K_INDENT (jump), indent, 0);
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
				nindent = sdb_num_getf (state.db, NULL, "loc.%" PFMT64x, addr);
				if (indent > nindent) {
					emit_close_braces (&state, bb->addr, indent, nindent);
				}
				print_newline (&state, addr, nindent, true);
				PRINTF ("goto loc_0x%08" PFMT64x ";", addr);
				indent = nindent;
			}
			PRINTGOTO (bb? bb->addr: UT64_MAX, gotoaddr);
		}
	}
	RListIter *iter;
	bool use_html = r_config_get_b (core->config, "scr.html");
	// hoist unconsumed switch dispatchers before orphan labels
	r_list_foreach (state.fcn->bbs, iter, bb) {
		if (!bb->switch_op) {
			continue;
		}
		if (r_list_contains (visited, bb)) {
			continue;
		}
		if (r_bitset_test (state.marked, bb->addr)) {
			continue;
		}
		render_switch (&state, bb, visited, 2);
		r_list_append (visited, bb);
		r_bitset_set (state.marked, bb->addr);
	}
	// orphans render at the walk depth: labels one level in, statements two
	indent = 2;
	r_list_foreach (state.fcn->bbs, iter, bb) {
		if (r_list_contains (visited, bb)) {
			continue;
		}
		if (r_bitset_test (state.marked, bb->addr)) {
			continue;
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
		s = comments_to_c (s);
		s = r_str_replace (s, "goto ", "// goto loc_", true);
		s = cleancomments (s);
		s = fold_resolved_refs (core, s);
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
			char *os = pdc_prefix_lines (s, " ", true);
			free (s);
			s = os;
		} else {
			char *ind = r_str_pad (NULL, 0, ' ', indent * 4);
			char *os = pdc_prefix_lines (s, r_str_get (ind), false);
			free (ind);
			free (s);
			s = os;
		}
		if (R_STR_ISNOTEMPTY (r_str_trim_head_ro (s))) {
			const size_t start = r_strbuf_length (state.codestr);
			const bool labeled = bb_addr_is_goto_target (state.fcn, bb->addr);
			if (!labeled && (state.show_asm || state.show_addr)) {
				// without a label the block starts on its body lines, which carry their own columns
				PRINTF ("\n");
			} else if (state.show_asm) {
				print_newline (&state, bb->addr, 0, true);
			} else if (state.show_addr) {
				NEWLINE (bb->addr, 0);
			} else {
				NEWLINE (bb->addr, labeled? 1: 0);
			}
			if (labeled) {
				char *tag = orphan_tag (core, bb->addr);
				PRINTF ("loc_0x%08" PFMT64x ": // %s\n%s", bb->addr, tag, s);
				free (tag);
			} else {
				PRINTF ("%s", s);
			}
			if (bb->jump == UT64_MAX) {
				if (!bb_ends_with_terminator (core, bb)) {
					print_newline (&state, bb->addr, indent, true);
					PRINTF (r0? "return %s;": "return;", r0);
					sdb_setf (state.goto_cache, "1", 0, "return.%" PFMT64x, bb->addr);
				}
			} else {
				PRINTGOTO (nextbbaddr, bb->jump);
			}
			annotate_offset (&state, start, bb->addr);
		}
		free (s);
	}
	r_list_free (visited);
	indent = 0;
	if (state.show_asm && bb) {
		print_newline (&state, bb->addr, indent, true);
	} else {
		NEWLINE (addr, indent);
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
		r_cons_println (cons, j);
		free (kode);
		free (j);
		r_strbuf_free (state.out);
	} else {
		char *s = r_strbuf_drain (state.out);
		if (comment_cmds) {
			pdc_print_comment_cmds (core, s);
		} else if (r_config_get_i (state.core->config, "scr.color") > 0) {
			RConsCodeColors codecolors = r_cons_codecolors (cons);
			char *ss = r_print_code_tocolor (s, &codecolors);
			free (s);
			s = ss;
		}
		if (!comment_cmds) {
			r_cons_println (cons, s);
		}
		free (s);
		r_strbuf_free (state.codestr);
	}
	sdb_free (state.db);
	sdb_free (state.goto_cache);
	r_bitset_free (state.marked);
	if (state.switch_addrs) {
		r_bitset_free (state.switch_addrs);
	}
	return true;
}

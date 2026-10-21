/* radare - LGPL - Copyright 2026 - pancake */

#include "pdc_opt.h"

// R2R db/cmd/cmd_pdc_opt

// The register profile owns these items throughout the pass.
static RRegItem *find_reg(RReg *regs, const char *name) {
	RRegItem *reg = r_reg_get (regs, name, -1);
	r_unref (reg);
	return reg;
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
	RListIter *line;
	char reg[16];
	bool folded;
	bool used;
} PDCPendingRef;

static void pending_resolve(PDCPendingRef *p, RList *lines) {
	if (p->reg[0] && p->folded && !p->used) {
		r_list_delete (lines, p->line);
	}
	memset (p, 0, sizeof (*p));
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
	if (!find_reg (core->anal->reg, base)) {
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

static char *drain_lines(RList *lines, char *code) {
	RStrBuf *out = r_strbuf_new ("");
	RListIter *it;
	char *line;
	bool first = true;
	r_list_foreach (lines, it, line) {
		if (line) {
			if (!first) {
				r_strbuf_append (out, "\n");
			}
			r_strbuf_append (out, line);
			first = false;
		}
	}
	r_list_free (lines);
	free (code);
	return r_strbuf_drain (out);
}

static char *fold_resolved_refs(RCore *core, char *code) {
	RList *lines = r_str_split_duplist (code, "\n", false);
	PDCPendingRef pend = {0};
	ut64 addr = UT64_MAX;
	RListIter *it;
	char *line;
	r_list_foreach (lines, it, line) {
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
			pending_resolve (&pend, lines);
			r_str_ncpy (pend.reg, body, reglen + 1);
			pend.line = it;
			continue;
		}
		char base[16] = {0};
		char *folded = fold_line (core, line, body, addr, pend.reg, base, sizeof (base));
		if (folded) {
			free (line);
			it->data = folded;
			if (pend.reg[0] && !strcmp (base, pend.reg)) {
				pend.folded = true;
				// base reg overwritten by its own load: liveness ends here
				if (word_in (folded, pend.reg)) {
					pending_resolve (&pend, lines);
				}
			}
		} else if (pend.reg[0] && word_in (body, pend.reg)) {
			// a plain write to the reg ends liveness without being a use
			size_t rl = strlen (pend.reg);
			bool wr = !strncmp (body, pend.reg, rl)
				&& !strncmp (body + rl, " = ", 3)
				&& !word_in (body + rl + 3, pend.reg);
			pend.used = !wr;
			pending_resolve (&pend, lines);
		}
	}
	pending_resolve (&pend, lines);
	return drain_lines (lines, code);
}

const char *pdc_skip_quoted(const char *s) {
	const char quote = *s++;
	while (*s && *s != '\n') {
		if (*s == quote) {
			return s + 1;
		}
		if (*s == '\\' && s[1]) {
			s++;
		}
		s++;
	}
	return s;
}

typedef struct {
	char *body;
	char *rhs;
	RRegItem *dst;
	ut64 addr;
} PdcExpr;

static bool reg_dead(RBitset *dead, RRegItem *reg, int action) {
	if (reg->offset < 0 || reg->size < 1) {
		return false;
	}
	ut64 bit = ((ut64)reg->arena << 32) + reg->offset;
	int i;
	for (i = 0; i < reg->size; i++) {
		if (action > 0) {
			r_bitset_set (dead, bit + i);
		} else if (action < 0) {
			r_bitset_unset (dead, bit + i);
		} else if (!r_bitset_test (dead, bit + i)) {
			return false;
		}
	}
	return true;
}

// Count uses including overlapping register aliases, ignoring names and quoted strings.
static int expr_regs(RReg *regs, char *text, RBitset *dead, int action, RRegItem *needle, char **use) {
	int count = 0;
	char *p = text;
	while (*p) {
		if (*p == '"' || *p == '\'') {
			p = (char *)pdc_skip_quoted (p);
		} else if (isalnum ((ut8)*p) || strchr ("_.$:", *p)) {
			char *name = p;
			while (*p && (isalnum ((ut8)*p) || strchr ("_.$:", *p))) {
				p++;
			}
			char saved = *p;
			*p = 0;
			RRegItem *reg = find_reg (regs, name);
			if (reg && dead) {
				reg_dead (dead, reg, action);
			}
			if (reg && needle && reg->arena == needle->arena
					&& reg->offset < (st64)needle->offset + needle->size
					&& needle->offset < (st64)reg->offset + reg->size) {
				count += !strcmp (name, needle->name)? 1: 2;
				*use = name;
			}
			*p = saved;
		} else {
			p++;
		}
	}
	return count;
}

static const char *expr_end(const char *s) {
	char close = *s == '['? ']': ')';
	char open = *s;
	int depth = 0;
	const char *p;
	for (p = s; *p; p++) {
		if (*p == '"' || *p == '\'') {
			p = pdc_skip_quoted (p) - 1;
		} else if (*p == open) {
			depth++;
		} else if (*p == close && !--depth) {
			return p;
		}
	}
	return NULL;
}

static bool expr_atom(const char *rhs) {
	if (R_STR_ISEMPTY (rhs)) {
		return false;
	}
	if (strspn (rhs, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.$:") == strlen (rhs)
			|| ((*rhs == '"' || *rhs == '\'') && !*pdc_skip_quoted (rhs))) {
		return true;
	}
	static const char *sizes[] = { "byte ", "word ", "dword ", "qword ", "oword ", "xmmword ", "ymmword ", "zmmword " };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sizes); i++) {
		if (r_str_startswith (rhs, sizes[i])) {
			rhs += strlen (sizes[i]);
			break;
		}
	}
	return (*rhs == '[' || *rhs == '(') && expr_end (rhs) == rhs + strlen (rhs) - 1;
}

static PdcExpr parse_expr(RCore *core, char *line) {
	PdcExpr expr = { .body = (char *)r_str_trim_head_ro (line), .addr = UT64_MAX };
	if (r_str_startswith (expr.body, "0x")) {
		expr.addr = r_num_get (NULL, expr.body);
		char *space = strchr (expr.body, ' ');
		if (space) {
			expr.body = (char *)r_str_trim_head_ro (space);
		}
	}
	char *space = strchr (expr.body, ' ');
	if (!space) {
		return expr;
	}
	*space = 0;
	expr.dst = find_reg (core->anal->reg, expr.body);
	*space = ' ';
	const char *rhs = r_str_trim_head_ro (space);
	char compound = *rhs && strchr ("+|-", *rhs)? *rhs++: 0;
	if (!expr.dst || !r_str_startswith (rhs, "= ")) {
		expr.dst = NULL;
		return expr;
	}
	rhs = r_str_trim_head_ro (rhs + 2);
	const char *end = rhs;
	while (*end && strncmp (end, " //", 3)) {
		if (*end == '"' || *end == '\'') {
			end = pdc_skip_quoted (end);
			continue;
		}
		end++;
	}
	expr.rhs = r_str_ndup (rhs, end - rhs);
	if (expr.rhs) {
		r_str_trim (expr.rhs);
	}
	if (compound && expr.rhs) {
		bool atom = expr_atom (expr.rhs);
		char *value = r_str_newf ("%s %c %s%s%s", expr.dst->name, compound, atom? "": "(", expr.rhs, atom? "": ")");
		free (expr.rhs);
		expr.rhs = value;
	}
	return expr;
}

// Only move instructions whose ESIL writes the destination and optional internal temporaries.
static bool prepare_expr(RAnalOp *op, PdcExpr *expr) {
	RRegItem *dst = expr->dst;
	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_LOAD:
		break;
	default:
		return false;
	}
	const char *esil = r_strbuf_get (&op->esil);
	if (R_STR_ISEMPTY (esil) || strstr (esil, "?{")) {
		return false;
	}
	RList *tokens = r_str_split_duplist (esil, ",", false);
	RListIter *it;
	char *token;
	bool writes_dst = false;
	bool pure = true;
	r_list_foreach (tokens, it, token) {
		// Pseudo |= hides the field-clearing mask of movt/movk.
		if (op->type == R_ANAL_OP_TYPE_MOV && !strcmp (token, "&") && !strchr (expr->rhs, '&')) {
			const char *tail = strstr (expr->rhs, " | ");
			const char *mask = it->p && it->p->p? it->p->p->data: "";
			bool masked_move = tail && tail - expr->rhs == strlen (dst->name)
				&& it->p && !strcmp (it->p->data, dst->name)
				&& *mask && strspn (mask, "0123456789abcdefABCDEFxX") == strlen (mask);
			char *rhs = masked_move? r_str_newf ("(%s & %s)%s", dst->name, mask, tail): NULL;
			if (!rhs) {
				pure = false;
				break;
			}
			free (expr->rhs);
			expr->rhs = rhs;
		}
		if (strchr (token, '=')) {
			const char *name = it->p? it->p->data: "";
			if (strcmp (token, "=") || (strcmp (name, dst->name) && strcmp (name, "tmp"))) {
				pure = false;
				break;
			}
			if (!strcmp (name, dst->name)) {
				pure &= !writes_dst;
				writes_dst = true;
			}
		}
	}
	r_list_free (tokens);
	return pure && writes_dst;
}

static void call_dead(RCore *core, RBitset *dead, RBitset *live, RAnalOp *op) {
	const char *cc = r_anal_call_convention (core->anal, op);
	if (!cc) {
		r_bitset_reset (dead);
		return;
	}
	RListIter *it;
	RRegItem *reg;
	r_list_foreach (r_reg_get_list (core->anal->reg, R_REG_TYPE_ALL), it, reg) {
		if (r_anal_cc_isclobber (core->anal, cc, reg->name)) {
			if (reg->offset >= 0 && reg->size > 0) {
				ut64 bit = ((ut64)reg->arena << 32) + reg->offset;
				int i;
				for (i = 0; i < reg->size; i++) {
					if (!r_bitset_test (live, bit + i)) {
						r_bitset_set (dead, bit + i);
					}
				}
			}
		}
	}
	int i;
	const int maxarg = r_anal_cc_max_arg (core->anal, cc);
	static const char *roles[] = { "self", "error", "sret" };
	for (i = 0; i < maxarg + R_ARRAY_SIZE (roles); i++) {
		const char *loc = i < maxarg? r_anal_cc_argloc (core->anal, cc, i, 0, -1):
			r_anal_cc_roleloc (core->anal, cc, roles[i - maxarg]);
		char *arg = loc? strdup (loc): NULL;
		if (arg) {
			expr_regs (core->anal->reg, arg, dead, -1, NULL, NULL);
			free (arg);
		}
	}
}

static char *fold_number(RCore *core, const char *value, int bits) {
	if (R_STR_ISEMPTY (value) || strspn (value, "0123456789abcdefABCDEFxX ()+-|<&") != strlen (value)) {
		return NULL;
	}
	// r_num evaluates shifts and bitwise operations left to right.
	ut8 operators[64] = {0};
	int depth = 0;
	char previous = 0;
	bool calculated = false;
	const char *p;
	for (p = value; *p; p++) {
		if (*p == '(') {
			if (++depth == R_ARRAY_SIZE (operators)) {
				return NULL;
			}
			operators[depth] = 0;
		} else if (*p == ')') {
			if (!depth--) {
				return NULL;
			}
		} else if (strchr ("+-|<&", *p) && !((*p == '+' || *p == '-')
				&& (!previous || strchr ("(+-|<&", previous)))) {
			calculated = true;
			ut8 kind = *p == '-'? '+': *p;
			if (operators[depth] && operators[depth] != kind) {
				return NULL;
			}
			operators[depth] = kind;
		}
		if (!IS_WHITECHAR (*p)) {
			previous = *p;
		}
	}
	if (!calculated) {
		return NULL;
	}
	const char *err = NULL;
	ut64 number = r_num_math_err (NULL, value, &err);
	if (err || depth) {
		return NULL;
	}
	if (bits > 0 && bits < 64) {
		number &= UT64_MAX >> (64 - bits);
	}
	RFlagItem *flag = pdc_flag_at (core, number);
	return flag? strdup (flag->name): r_str_newf ("0x%" PFMT64x, number);
}

static char *fold_value(RCore *core, char *rhs, RRegItem *dst) {
	char *constant = fold_number (core, rhs, dst->size);
	if (constant) {
		free (rhs);
		return constant;
	}
	char *p;
	for (p = rhs; *p; p++) {
		if (*p == '"' || *p == '\'') {
			p = (char *)pdc_skip_quoted (p) - 1;
		} else if (*p == '[' || *p == '(') {
			const char *end = expr_end (p);
			char *value = end? r_str_ndup (p + 1, end - p - 1): NULL;
			constant = fold_number (core, value, r_config_get_i (core->config, "asm.bits"));
			free (value);
			if (constant) {
				char *result = r_str_newf ("%.*s%s%s", (int)(p + 1 - rhs), rhs, constant, end);
				free (constant);
				if (result) {
					free (rhs);
					return result;
				}
			}
		}
	}
	return rhs;
}

static bool freeze_pc(RCore *core, RAnalOp *op, PdcExpr *expr, RRegItem *pc) {
	if (!pc) {
		return true;
	}
	char *use = NULL;
	int count = expr_regs (core->anal->reg, expr->rhs, NULL, 0, pc, &use);
	if (!count) {
		return true;
	}
	size_t length = strspn (use, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.$:");
	bool exact = length == strlen (pc->name) && !strncmp (use, pc->name, length);
	if (count != (exact? 1: 2)) {
		return false;
	}
	char saved = use[length];
	use[length] = 0;
	RRegItem *source = find_reg (core->anal->reg, use);
	use[length] = saved;
	const char *arch = r_config_get (core->config, "asm.arch");
	ut64 value;
	bool arm = !strcmp (arch, "arm") && r_config_get_i (core->config, "asm.bits") == 32;
	if (!strcmp (arch, "x86")) {
		value = op->addr + op->size;
	} else if (arm && op->size == 4 && (op->type == R_ANAL_OP_TYPE_ADD
			|| op->type == R_ANAL_OP_TYPE_SUB || op->type == R_ANAL_OP_TYPE_MOV)) {
		value = op->addr + 8;
	} else {
		return false;
	}
	if (source->size > 0 && source->size < 64) {
		value &= UT64_MAX >> (64 - source->size);
	}
	char *rhs = r_str_newf ("%.*s0x%" PFMT64x "%s", (int)(use - expr->rhs), expr->rhs, value, use + length);
	if (!rhs) {
		return false;
	}
	// ARM's shifted register operands can observe a different architectural PC.
	if (arm && strspn (rhs, "0123456789abcdefABCDEFxX ()+-") != strlen (rhs)) {
		free (rhs);
		return false;
	}
	free (expr->rhs);
	expr->rhs = rhs;
	return true;
}

static void expr_live(RCore *core, PdcExpr *expr, RBitset *live) {
	if (expr->dst) {
		reg_dead (live, expr->dst, -1);
	}
	expr_regs (core->anal->reg, expr->rhs? expr->rhs: expr->body, live, 1, NULL, NULL);
}

static bool preserves_load_order(const char *rhs, const char *use) {
	const char *p;
	for (p = rhs; *p; p++) {
		if (*p == '"' || *p == '\'') {
			p = pdc_skip_quoted (p) - 1;
		} else if (*p == '[') {
			const char *end = expr_end (p);
			if (!end || use < p || use > end) {
				return false;
			}
		}
	}
	return true;
}

char *pdc_optimize(RCore *core, char *code) {
	code = fold_resolved_refs (core, code);
	if (!r_config_get_b (core->config, "pdc.optimize")) {
		return code;
	}
	RList *lines = r_str_split_duplist (code, "\n", false);
	RBitset *dead = r_bitset_new ();
	RBitset *live = r_bitset_new ();
	RRegItem *sp = find_reg (core->anal->reg, "SP");
	RRegItem *bp = find_reg (core->anal->reg, "BP");
	RRegItem *pc = find_reg (core->anal->reg, "PC");
	const int bits = r_config_get_i (core->config, "asm.bits");
	RListIter *it;
	char *line;
	PdcExpr next = {0};
	RListIter *consumer = NULL;
	bool next_safe = false;
	RAnalOp *op = NULL;
	// Unknown live-outs stay live; a write makes a register dead until its next read.
	r_list_foreach_prev (lines, it, line) {
		PdcExpr expr = parse_expr (core, line);
		if (!op && expr.addr != UT64_MAX) {
			op = r_core_anal_op (core, expr.addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL);
		}
		// Delayed transfers and their slots are barriers; reuse the decoded previous op.
		PdcExpr before = it->p? parse_expr (core, it->p->data): (PdcExpr) { .addr = UT64_MAX };
		RAnalOp *previous = before.addr == UT64_MAX? NULL: r_core_anal_op (core, before.addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL);
		free (before.rhs);
		bool delayed = (op && op->delay) || (previous && previous->delay);
		bool pure = op && !delayed && expr.dst && expr.dst->type == R_REG_TYPE_GPR
			&& expr.dst->size == bits && op->stackop == R_ANAL_STACK_NULL
			&& (!sp || expr.dst->arena != sp->arena || expr.dst->offset != sp->offset)
			&& (!bp || expr.dst->arena != bp->arena || expr.dst->offset != bp->offset)
			&& expr.rhs && !strpbrk (expr.rhs, ";=?") && prepare_expr (op, &expr)
			&& freeze_pc (core, op, &expr, pc);
		bool call = op && !delayed && expr.dst && expr.rhs && (op->type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_CALL;
		char *use = NULL;
		bool remove = false;
		bool fold = pure && next_safe && next.rhs && reg_dead (dead, expr.dst, 0)
			&& expr_regs (core->anal->reg, next.rhs, NULL, 0, expr.dst, &use) == 1
			&& (!strchr (expr.rhs, '[') || preserves_load_order (next.rhs, use))
			&& strlen (expr.rhs) + strlen (next.rhs) < 1024;
		if (fold) {
			bool atom = expr_atom (expr.rhs);
			char *rhs = r_str_newf ("%.*s%s%s%s%s", (int)(use - next.rhs), next.rhs, atom? "": "(", expr.rhs, atom? "": ")", use + strlen (expr.dst->name));
			if (rhs) {
				rhs = fold_value (core, rhs, next.dst);
			}
			char *replacement = rhs? r_str_newf ("%.*s%s = %s", (int)(next.body - (char *)consumer->data), (char *)consumer->data, next.dst->name, rhs): NULL;
			if (replacement) {
				free (consumer->data);
				consumer->data = replacement;
				free (next.rhs);
				next = parse_expr (core, replacement);
				remove = true;
			} else {
				fold = false;
			}
			free (rhs);
		}
		if (!fold) {
			if (next.rhs) {
				expr_regs (core->anal->reg, next.rhs, dead, -1, NULL, NULL);
			}
			if (pure && reg_dead (dead, expr.dst, 0) && !strchr (r_strbuf_get (&op->esil), '[')) {
				remove = true;
			} else {
				expr_live (core, &expr, live);
				free (next.rhs);
				next = expr;
				expr.rhs = NULL;
				consumer = it;
				next_safe = pure || call;
				if (!next_safe) {
					r_bitset_reset (dead);
				} else {
					if (call) {
						call_dead (core, dead, live, op);
					}
					reg_dead (dead, next.dst, 1);
				}
			}
		} else {
			expr_live (core, &expr, live);
		}
		if (remove) {
			free (line);
			it->data = NULL;
		}
		free (expr.rhs);
		r_anal_op_free (op);
		op = previous;
	}
	r_anal_op_free (op);
	free (next.rhs);
	r_bitset_free (dead);
	r_bitset_free (live);
	return drain_lines (lines, code);
}

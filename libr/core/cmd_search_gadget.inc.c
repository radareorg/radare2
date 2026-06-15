/* radare - LGPL - Copyright 2009-2016 - Alexandru Caciulescu */


#if R_INCLUDE_BEGIN

typedef enum {
	R_CORE_GADGET_ESIL_COND_NONE,
	R_CORE_GADGET_ESIL_COND_ALWAYS,
	R_CORE_GADGET_ESIL_COND_NEVER,
	R_CORE_GADGET_ESIL_COND_CONTROLLED,
	R_CORE_GADGET_ESIL_COND_UNKNOWN,
} RCoreGadgetEsilCond;

typedef enum {
	R_CORE_GADGET_TARGET_NONE,
	R_CORE_GADGET_TARGET_DIRECT,
	R_CORE_GADGET_TARGET_COMPUTED,
	R_CORE_GADGET_TARGET_MEMORY,
} RCoreGadgetTargetKind;

typedef enum {
	R_CORE_GADGET_CLASS_RET = 1 << 0,
	R_CORE_GADGET_CLASS_JOP = 1 << 1,
	R_CORE_GADGET_CLASS_COP = 1 << 2,
	R_CORE_GADGET_CLASS_COND_ALWAYS = 1 << 3,
	R_CORE_GADGET_CLASS_COND_CONTROLLED = 1 << 4,
	R_CORE_GADGET_CLASS_SYSCALL = 1 << 5,
	R_CORE_GADGET_CLASS_PIVOT = 1 << 6,
	R_CORE_GADGET_CLASS_MEMREAD = 1 << 7,
	R_CORE_GADGET_CLASS_MEMWRITE = 1 << 8,
	R_CORE_GADGET_CLASS_WRITE_WHAT_WHERE = 1 << 9,
	R_CORE_GADGET_CLASS_READ_WHAT_WHERE = 1 << 10,
	R_CORE_GADGET_CLASS_SIGNAL = 1 << 11,
	R_CORE_GADGET_CLASS_MOV = 1 << 12,
	R_CORE_GADGET_CLASS_LOAD_CONST = 1 << 13,
	R_CORE_GADGET_CLASS_ARITHM = 1 << 14,
	R_CORE_GADGET_CLASS_LOGIC = 1 << 15,
	R_CORE_GADGET_CLASS_SHIFT = 1 << 16,
	R_CORE_GADGET_CLASS_CMP = 1 << 17,
	R_CORE_GADGET_CLASS_NOP = 1 << 18,
	R_CORE_GADGET_CLASS_ARITHM_CONST = 1 << 19,
} RCoreGadgetClass;

typedef struct {
	bool conditional;
	RCoreGadgetEsilCond condition;
	bool target_set;
	RCoreGadgetTargetKind target_kind;
	ut64 target;
	ut32 classes;
	char target_source[64];
	char mov_detail[128];
	char ldconst_detail[128];
	char arithm_detail[128];
	char logic_detail[128];
} RCoreGadgetEsilInfo;

typedef struct {
	bool ok;
	bool taken;
	bool target_set;
	bool trapped;
	ut64 target;
} RCoreGadgetEsilRun;

typedef struct {
	REsil *esil;
	RIOBind iob;
} RCoreGadgetEsilSaved;

static const char *gadget_esil_cond_tostring(RCoreGadgetEsilCond cond) {
	switch (cond) {
	case R_CORE_GADGET_ESIL_COND_ALWAYS:
		return "always";
	case R_CORE_GADGET_ESIL_COND_NEVER:
		return "never";
	case R_CORE_GADGET_ESIL_COND_CONTROLLED:
		return "controlled";
	case R_CORE_GADGET_ESIL_COND_UNKNOWN:
		return "unknown";
	default:
		return "none";
	}
}

static const char *gadget_target_kind_tostring(RCoreGadgetTargetKind kind) {
	switch (kind) {
	case R_CORE_GADGET_TARGET_DIRECT:
		return "direct";
	case R_CORE_GADGET_TARGET_COMPUTED:
		return "computed";
	case R_CORE_GADGET_TARGET_MEMORY:
		return "memory";
	default:
		return "none";
	}
}

typedef struct {
	ut32 bit;
	const char *name;
} RCoreGadgetClassName;

static const RCoreGadgetClassName gadget_class_names[] = {
	{ R_CORE_GADGET_CLASS_RET, "ret" },
	{ R_CORE_GADGET_CLASS_JOP, "jop" },
	{ R_CORE_GADGET_CLASS_COP, "cop" },
	{ R_CORE_GADGET_CLASS_COND_ALWAYS, "cond.always" },
	{ R_CORE_GADGET_CLASS_COND_CONTROLLED, "cond.controlled" },
	{ R_CORE_GADGET_CLASS_SYSCALL, "syscall" },
	{ R_CORE_GADGET_CLASS_PIVOT, "pivot" },
	{ R_CORE_GADGET_CLASS_MEMREAD, "memread" },
	{ R_CORE_GADGET_CLASS_MEMWRITE, "memwrite" },
	{ R_CORE_GADGET_CLASS_WRITE_WHAT_WHERE, "www" },
	{ R_CORE_GADGET_CLASS_READ_WHAT_WHERE, "rww" },
	{ R_CORE_GADGET_CLASS_SIGNAL, "signal" },
	{ R_CORE_GADGET_CLASS_MOV, "mov" },
	{ R_CORE_GADGET_CLASS_LOAD_CONST, "ldconst" },
	{ R_CORE_GADGET_CLASS_ARITHM, "arithm" },
	{ R_CORE_GADGET_CLASS_LOGIC, "logic" },
	{ R_CORE_GADGET_CLASS_SHIFT, "shift" },
	{ R_CORE_GADGET_CLASS_CMP, "cmp" },
	{ R_CORE_GADGET_CLASS_NOP, "nop" },
	{ R_CORE_GADGET_CLASS_ARITHM_CONST, "arithm_ct" },
};

static void gadget_info_set_target(RCoreGadgetEsilInfo *info, ut64 target, RCoreGadgetTargetKind kind, const char *source) {
	info->target = target;
	info->target_set = true;
	info->target_kind = kind;
	if (R_STR_ISNOTEMPTY (source)) {
		r_str_ncpy (info->target_source, source, sizeof (info->target_source));
	}
}

static bool is_conditional_end_gadget(const RAnalOp *aop, int gadget_type) {
	return (aop->type & R_ANAL_OP_TYPE_COND)
		&& is_end_gadget (aop, gadget_type, true)
		&& !is_end_gadget (aop, gadget_type, false);
}

static bool gadget_anal_op_for_hit(RCore *core, RCoreAsmHit *hit, RAnalOp *op, int mask) {
	if (!hit || hit->len < 1) {
		return false;
	}
	ut8 *buf = malloc (hit->len);
	if (!buf) {
		return false;
	}
	r_io_read_at (core->io, hit->addr, buf, hit->len);
	int ret = r_anal_op (core->anal, op, hit->addr, buf, hit->len, mask);
	free (buf);
	return ret > 0;
}

static bool gadget_esil_assigns_reg(const char *expr, const char *reg) {
	if (R_STR_ISEMPTY (expr) || R_STR_ISEMPTY (reg)) {
		return false;
	}
	char *needle = r_str_newf (",%s,", reg);
	if (!needle) {
		return false;
	}
	const char *p = expr;
	const size_t len = strlen (needle);
	while ((p = strstr (p, needle))) {
		const char *op = p + len;
		if (op[0] == '=' || (op[0] == ':' && op[1] == '=')
				|| (op[0] && op[1] == '=')
				|| (op[0] == '<' && op[1] == '<' && op[2] == '=')
				|| (op[0] == '>' && op[1] == '>' && op[2] == '=')) {
			free (needle);
			return true;
		}
		p += len;
	}
	free (needle);
	return false;
}

static bool gadget_esil_has_mem_read(const char *expr) {
	const char *p = expr;
	while (p && (p = strchr (p, '['))) {
		if (p == expr || p[-1] != '=') {
			return true;
		}
		p++;
	}
	return false;
}

static bool gadget_esil_has_mem_write(const char *expr) {
	return R_STR_ISNOTEMPTY (expr) && strstr (expr, "=[");
}

static const char *gadget_esil_prev_token(const char *expr, const char *end, char *buf, size_t buf_len) {
	if (!expr || !end || end <= expr || buf_len < 1) {
		return NULL;
	}
	const char *p = end;
	while (p > expr && (p[-1] == ',' || p[-1] == ' ')) {
		p--;
	}
	const char *q = p;
	while (q > expr && q[-1] != ',') {
		q--;
	}
	if (q >= p) {
		return NULL;
	}
	size_t len = R_MIN ((size_t)(p - q), buf_len - 1);
	memcpy (buf, q, len);
	buf[len] = 0;
	return q;
}

static bool gadget_esil_token_is_controlled(const char *token) {
	if (R_STR_ISEMPTY (token)) {
		return false;
	}
	if (r_str_startswith (token, "0x") || IS_DIGIT (*token)
			|| ((*token == '-' || *token == '+') && IS_DIGIT (token[1]))) {
		return false;
	}
	return true;
}

static bool gadget_esil_next_token(const char **expr, char *buf, size_t buf_len) {
	if (!expr || R_STR_ISEMPTY (*expr) || buf_len < 1) {
		return false;
	}
	const char *p = *expr;
	const char *comma = strchr (p, ',');
	size_t len = comma? (size_t)(comma - p): strlen (p);
	len = R_MIN (len, buf_len - 1);
	memcpy (buf, p, len);
	buf[len] = 0;
	*expr = comma? comma + 1: p + len;
	return true;
}

static bool gadget_esil_is_write_what_where(const char *expr) {
	const char *write = strstr (expr, "=[");
	if (!write) {
		return false;
	}
	if (write > expr && write[-1] != ',') {
		return false;
	}
	char what[64], where[64];
	const char *where_start = gadget_esil_prev_token (expr, write, where, sizeof (where));
	if (!where_start || where_start <= expr) {
		return false;
	}
	const char *what_start = gadget_esil_prev_token (expr, where_start - 1, what, sizeof (what));
	if (!what_start) {
		return false;
	}
	return gadget_esil_token_is_controlled (what) && gadget_esil_token_is_controlled (where);
}

static bool gadget_esil_is_read_what_where(const char *expr) {
	const char *read = expr;
	while ((read = strchr (read, '['))) {
		if (read == expr || read[-1] != '=') {
			break;
		}
		read++;
	}
	if (!read) {
		return false;
	}
	char where[64], dst[64];
	const char *where_start = gadget_esil_prev_token (expr, read, where, sizeof (where));
	if (!where_start) {
		return false;
	}
	const char *assign = strchr (read, '=');
	if (!assign) {
		return false;
	}
	const char *dst_start = gadget_esil_prev_token (expr, assign, dst, sizeof (dst));
	if (!dst_start) {
		return false;
	}
	return gadget_esil_token_is_controlled (where) && gadget_esil_token_is_controlled (dst);
}

static bool gadget_esil_is_const_assignment(const char *expr) {
	if (R_STR_ISEMPTY (expr)) {
		return false;
	}
	const char *comma = strchr (expr, ',');
	if (!comma) {
		return false;
	}
	char token[64];
	size_t len = R_MIN ((size_t)(comma - expr), sizeof (token) - 1);
	memcpy (token, expr, len);
	token[len] = 0;
	return !gadget_esil_token_is_controlled (token) && strstr (comma, ",=");
}

static bool gadget_esil_starts_with_const(const char *expr) {
	char token[64];
	const char *p = expr;
	return gadget_esil_next_token (&p, token, sizeof (token))
		&& !gadget_esil_token_is_controlled (token);
}

static bool gadget_esil_find_cond_end(RCore *core, RList *hitlist, int gadget_type, ut64 *addr) {
	RListIter *iter;
	RCoreAsmHit *hit;
	bool found = false;

	r_list_foreach (hitlist, iter, hit) {
		RAnalOp op = {0};
		if (gadget_anal_op_for_hit (core, hit, &op, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT)) {
			if (is_conditional_end_gadget (&op, gadget_type)) {
				*addr = hit->addr;
				found = true;
			}
		}
		r_anal_op_fini (&op);
	}
	return found;
}

static REsil *gadget_esil_new(RCore *core) {
	RAnal *anal = core->anal;
	REsilOptions opt = r_esil_options (NULL, NULL);
	opt.stacksize = r_config_get_i (core->config, "esil.stack.depth");
	opt.iotrap = r_config_get_b (core->config, "esil.iotrap");
	opt.addrsize = r_config_get_i (core->config, "esil.addr.size");
	REsil *esil = r_esil_new (&opt);
	if (esil) {
		esil->anal = anal;
		anal->esil = esil;
		r_io_bind (core->io, &anal->iob);
		bool nonull = r_config_get_b (core->config, "esil.nonull");
		if (!r_esil_setup (esil, anal, true, false, nonull)) {
			r_esil_free (esil);
			return NULL;
		}
		esil->nowrite = true;
	}
	return esil;
}

static void gadget_esil_restore(RCore *core, const RCoreGadgetEsilSaved *saved, REsil *esil) {
	r_esil_free (esil);
	core->anal->esil = saved->esil;
	core->anal->iob = saved->iob;
}

static void gadget_esil_seed_registers(RCore *core, ut64 seed) {
	RListIter *iter;
	RRegItem *reg_item;
	RList *regs = r_reg_get_list (core->anal->reg, R_REG_TYPE_GPR);
	int nr = 1;

	r_list_foreach (regs, iter, reg_item) {
		ut64 value = seed? seed + (nr * 0x11111111ULL): 0;
		r_reg_set_value (core->anal->reg, reg_item, value);
		nr++;
	}
}

static bool gadget_esil_eval_run(RCore *core, RList *hitlist, ut64 cond_addr, ut64 seed, RCoreGadgetEsilRun *run) {
	RListIter *iter;
	RCoreAsmHit *hit;
	bool found = false;
	bool ok = true;
	RAnal *anal = core->anal;
	RCoreGadgetEsilSaved saved = {
		.esil = anal->esil,
		.iob = anal->iob,
	};
	REsil *esil = gadget_esil_new (core);

	memset (run, 0, sizeof (*run));
	if (!esil) {
		gadget_esil_restore (core, &saved, NULL);
		return false;
	}
	if (!r_reg_arena_push (anal->reg)) {
		gadget_esil_restore (core, &saved, esil);
		return false;
	}
	gadget_esil_seed_registers (core, seed);
	r_list_foreach (hitlist, iter, hit) {
		RAnalOp op = {0};
		if (!gadget_anal_op_for_hit (core, hit, &op,
				R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT)) {
			ok = false;
			r_anal_op_fini (&op);
			break;
		}
		const char *expr = R_STRBUF_SAFEGET (&op.esil);
		const ut64 next = op.addr + op.size;
		r_reg_setv (core->anal->reg, "PC", next);
		esil->addr = op.addr;
		esil->jump_target = UT64_MAX;
		esil->jump_target_set = 0;
		esil->trap = 0;
		if (R_STR_ISNOTEMPTY (expr)) {
			ok = r_esil_parse (esil, expr);
			r_esil_stack_free (esil);
			if (esil->trap) {
				run->trapped = true;
				ok = false;
			}
			if (!ok) {
				r_anal_op_fini (&op);
				break;
			}
		}
		if (hit->addr == cond_addr) {
			ut64 pc = r_reg_getv (core->anal->reg, "PC");
			if (pc == op.addr) {
				pc = next;
			}
			const ut64 fail = op.fail != UT64_MAX? op.fail: next;
			run->target = pc;
			run->target_set = pc != UT64_MAX;
			run->taken = pc != fail;
			found = true;
			r_anal_op_fini (&op);
			break;
		}
		r_anal_op_fini (&op);
	}
	r_reg_arena_pop (anal->reg);
	gadget_esil_restore (core, &saved, esil);
	run->ok = ok && found && !run->trapped;
	return run->ok;
}

static bool gadget_esil_classify_condition(RCore *core, RList *hitlist, int gadget_type, bool crop, RCoreGadgetEsilInfo *info) {
	static const ut64 seeds[] = {
		0,
		1,
		5,
		UT64_MAX
	};
	RCoreGadgetEsilRun first = {0};
	bool have = false;
	bool unknown = false;
	bool controlled = false;
	ut64 cond_addr = UT64_MAX;
	size_t i;

	if (!gadget_esil_find_cond_end (core, hitlist, gadget_type, &cond_addr)) {
		return true;
	}
	info->conditional = true;
	info->condition = R_CORE_GADGET_ESIL_COND_UNKNOWN;
	for (i = 0; i < R_ARRAY_SIZE (seeds); i++) {
		RCoreGadgetEsilRun run = {0};
		if (!gadget_esil_eval_run (core, hitlist, cond_addr, seeds[i], &run)) {
			unknown = true;
			continue;
		}
		if (!have) {
			first = run;
			have = true;
			continue;
		}
		if (run.taken != first.taken || run.target != first.target || run.target_set != first.target_set) {
			controlled = true;
		}
	}
	if (!have) {
		info->condition = R_CORE_GADGET_ESIL_COND_UNKNOWN;
	} else if (unknown) {
		info->condition = R_CORE_GADGET_ESIL_COND_UNKNOWN;
	} else if (controlled) {
		info->condition = R_CORE_GADGET_ESIL_COND_CONTROLLED;
		if (first.target_set) {
			gadget_info_set_target (info, first.target,
				info->target_kind? info->target_kind: R_CORE_GADGET_TARGET_DIRECT,
				info->target_source[0]? info->target_source: "branch");
		}
	} else {
		info->condition = first.taken
			? R_CORE_GADGET_ESIL_COND_ALWAYS
			: R_CORE_GADGET_ESIL_COND_NEVER;
		if (first.target_set) {
			gadget_info_set_target (info, first.target,
				info->target_kind? info->target_kind: R_CORE_GADGET_TARGET_DIRECT,
				info->target_source[0]? info->target_source: "branch");
		}
	}
	return crop || info->condition != R_CORE_GADGET_ESIL_COND_UNKNOWN;
}

static bool gadget_op_is_syscall(const RAnalOp *op) {
	return op->type == R_ANAL_OP_TYPE_SWI || op->type == R_ANAL_OP_TYPE_CSWI;
}

static bool gadget_op_is_jump(const RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_MJMP:
		return true;
	default:
		return is_jump_gadget (op, true);
	}
}

static bool gadget_op_is_call(const RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_CCALL:
		return true;
	default:
		return is_call_gadget (op, true);
	}
}

static bool gadget_op_is_mov(const RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_RMOV:
	case R_ANAL_OP_TYPE_CMOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_ULEA:
		return true;
	default:
		return false;
	}
}

static bool gadget_op_is_arithm(const RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_MOD:
		return true;
	default:
		return false;
	}
}

static bool gadget_op_is_logic(const RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_NOR:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_CPL:
		return true;
	default:
		return false;
	}
}

static bool gadget_op_is_shift(const RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_ROR:
		return true;
	default:
		return false;
	}
}

static bool gadget_op_is_cmp(const RAnalOp *op) {
	return op->type == R_ANAL_OP_TYPE_CMP || op->type == R_ANAL_OP_TYPE_ACMP;
}

static bool gadget_op_is_nop(const RAnalOp *op) {
	return op->type == R_ANAL_OP_TYPE_NOP;
}

static void gadget_info_append_detail(char *dst, size_t dst_len, const char *detail) {
	if (R_STR_ISEMPTY (detail) || strstr (dst, detail)) {
		return;
	}
	size_t used = strlen (dst);
	if (used + 3 >= dst_len) {
		return;
	}
	if (used) {
		dst[used++] = ';';
		dst[used++] = ' ';
		dst[used] = 0;
	}
	r_str_ncpy (dst + used, detail, dst_len - used);
}

static void gadget_info_append_detailf(char *dst, size_t dst_len, const char *fmt, ...) R_PRINTF_CHECK(3, 4);
static void gadget_info_append_detailf(char *dst, size_t dst_len, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *detail = r_str_newvf (fmt, ap);
	va_end (ap);
	if (!detail) {
		return;
	}
	gadget_info_append_detail (dst, dst_len, detail);
	free (detail);
}

static void gadget_info_collect_simple_detail(RCoreGadgetEsilInfo *info, const RAnalOp *op, const char *expr) {
	char src[64], dst[64], esil_op[16];
	const char *p = expr;
	if (!gadget_esil_next_token (&p, src, sizeof (src))
			|| !gadget_esil_next_token (&p, dst, sizeof (dst))
			|| !gadget_esil_next_token (&p, esil_op, sizeof (esil_op))) {
		return;
	}
	if (!strcmp (esil_op, "=")) {
		if (!gadget_esil_token_is_controlled (src) && gadget_esil_token_is_controlled (dst)) {
			const ut64 value = r_num_get (NULL, src);
			gadget_info_append_detailf (info->ldconst_detail,
				sizeof (info->ldconst_detail), "dst=%s value=0x%"PFMT64x, dst, value);
		} else if (gadget_op_is_mov (op) && gadget_esil_token_is_controlled (src) && gadget_esil_token_is_controlled (dst)) {
			gadget_info_append_detailf (info->mov_detail, sizeof (info->mov_detail), "dst=%s src=%s", dst, src);
		}
		return;
	}
	const size_t len = strlen (esil_op);
	if (len < 2 || esil_op[len - 1] != '=' || !gadget_esil_token_is_controlled (dst)) {
		return;
	}
	esil_op[len - 1] = 0;
	if (gadget_op_is_arithm (op)) {
		char src_detail[64];
		if (gadget_esil_token_is_controlled (src)) {
			r_str_ncpy (src_detail, src, sizeof (src_detail));
		} else {
			r_strf_var (num, 64, "0x%"PFMT64x, r_num_get (NULL, src));
			r_str_ncpy (src_detail, num, sizeof (src_detail));
		}
		gadget_info_append_detailf (info->arithm_detail,
			sizeof (info->arithm_detail), "dst=%s op=%s src=%s", dst, esil_op, src_detail);
	} else if (gadget_op_is_logic (op)) {
		gadget_info_append_detailf (info->logic_detail,
			sizeof (info->logic_detail), "dst=%s op=%s src=%s", dst, esil_op, src);
	}
}

static bool gadget_flag_name_is_signal(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	const char *base = strrchr (name, '.');
	base = base? base + 1: name;
	return !strcmp (base, "signal")
		|| !strcmp (base, "sigaction")
		|| !strcmp (base, "sigreturn")
		|| !strcmp (base, "sigprocmask")
		|| !strcmp (base, "raise")
		|| !strcmp (base, "kill")
		|| !strcmp (base, "pthread_kill")
		|| !strcmp (base, "abort");
}

static bool gadget_op_is_signal_call(RCore *core, const RAnalOp *op) {
	if (!gadget_op_is_call (op) || op->jump == UT64_MAX) {
		return false;
	}
	RFlagItem *fi = r_flag_get_in (core->flags, op->jump);
	if (!fi) {
		fi = r_flag_get_at (core->flags, op->jump, false);
	}
	return fi && (gadget_flag_name_is_signal (fi->name)
		|| gadget_flag_name_is_signal (fi->realname)
		|| gadget_flag_name_is_signal (fi->rawname));
}

static bool gadget_op_has_explicit_mem_read(const RAnalOp *op, const char *expr) {
	if (op->stackop != R_ANAL_STACK_NULL || is_ret_gadget (op, true) || gadget_op_is_call (op)) {
		return false;
	}
	return (op->direction & R_ANAL_OP_DIR_READ) || gadget_esil_has_mem_read (expr);
}

static bool gadget_op_has_explicit_mem_write(const RAnalOp *op, const char *expr) {
	if (op->stackop != R_ANAL_STACK_NULL || is_ret_gadget (op, true) || gadget_op_is_call (op)) {
		return false;
	}
	return (op->direction & R_ANAL_OP_DIR_WRITE) || gadget_esil_has_mem_write (expr);
}

static bool gadget_op_writes_reg(const RAnalOp *op, const char *reg) {
	RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
	return dst && dst->reg && !strcmp (dst->reg, reg);
}

static bool gadget_op_is_pivot(RCore *core, const RAnalOp *op, const char *expr) {
	if (is_ret_gadget (op, true) || gadget_op_is_call (op)) {
		return false;
	}
	const char *sp = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_SP);
	return R_STR_ISNOTEMPTY (sp)
		&& gadget_esil_assigns_reg (expr, sp)
		&& (gadget_op_writes_reg (op, sp)
			|| op->stackop == R_ANAL_STACK_NULL
			|| gadget_op_is_mov (op)
			|| gadget_op_is_arithm (op));
}

static void gadget_info_set_target_source(RCoreGadgetEsilInfo *info, RCoreGadgetTargetKind kind, const char *source) {
	if (info->target_kind == R_CORE_GADGET_TARGET_NONE) {
		info->target_kind = kind;
	}
	if (!info->target_source[0] && R_STR_ISNOTEMPTY (source)) {
		r_str_ncpy (info->target_source, source, sizeof (info->target_source));
	}
}

static bool gadget_source_reg_defined(RCore *core, RList *hitlist, ut64 end_addr, const char *reg, bool *memory_backed) {
	RListIter *iter;
	RCoreAsmHit *hit;
	bool found = false;

	if (memory_backed) {
		*memory_backed = false;
	}
	r_list_foreach (hitlist, iter, hit) {
		if (hit->addr == end_addr) {
			break;
		}
		RAnalOp op = {0};
		if (gadget_anal_op_for_hit (core, hit, &op,
				R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT)) {
			const char *expr = R_STRBUF_SAFEGET (&op.esil);
			if (gadget_esil_assigns_reg (expr, reg)) {
				found = true;
				if (memory_backed && gadget_op_has_explicit_mem_read (&op, expr)) {
					*memory_backed = true;
				}
			}
		}
		r_anal_op_fini (&op);
	}
	return found;
}

static void gadget_analyze_static(RCore *core, RList *hitlist, RCoreGadgetEsilInfo *info, RCoreAsmHit **end_hit) {
	RListIter *iter;
	RCoreAsmHit *hit;
	RCoreAsmHit *last = r_list_last (hitlist);

	if (end_hit) {
		*end_hit = last;
	}
	r_list_foreach (hitlist, iter, hit) {
		RAnalOp op = {0};
		if (!gadget_anal_op_for_hit (core, hit, &op,
				R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT)) {
			r_anal_op_fini (&op);
			continue;
		}
		const char *expr = R_STRBUF_SAFEGET (&op.esil);
		if (gadget_op_is_syscall (&op)) {
			info->classes |= R_CORE_GADGET_CLASS_SYSCALL;
		}
		if (gadget_op_is_signal_call (core, &op)) {
			info->classes |= R_CORE_GADGET_CLASS_SIGNAL;
		}
		if (gadget_op_is_mov (&op)) {
			info->classes |= R_CORE_GADGET_CLASS_MOV;
			if (!gadget_op_has_explicit_mem_read (&op, expr) && gadget_esil_is_const_assignment (expr)) {
				info->classes |= R_CORE_GADGET_CLASS_LOAD_CONST;
			}
		}
		if (gadget_op_is_arithm (&op)) {
			info->classes |= R_CORE_GADGET_CLASS_ARITHM;
			if (gadget_esil_starts_with_const (expr)) {
				info->classes |= R_CORE_GADGET_CLASS_ARITHM_CONST;
			}
		}
		if (gadget_op_is_logic (&op)) {
			info->classes |= R_CORE_GADGET_CLASS_LOGIC;
		}
		if (gadget_op_is_shift (&op)) {
			info->classes |= R_CORE_GADGET_CLASS_SHIFT;
		}
		if (gadget_op_is_cmp (&op)) {
			info->classes |= R_CORE_GADGET_CLASS_CMP;
		}
		if (gadget_op_is_nop (&op)) {
			info->classes |= R_CORE_GADGET_CLASS_NOP;
		}
		gadget_info_collect_simple_detail (info, &op, expr);
		if (gadget_op_has_explicit_mem_read (&op, expr)) {
			info->classes |= R_CORE_GADGET_CLASS_MEMREAD;
			if ((op.type == R_ANAL_OP_TYPE_LOAD || gadget_op_is_mov (&op))
					&& gadget_esil_is_read_what_where (expr)) {
				info->classes |= R_CORE_GADGET_CLASS_READ_WHAT_WHERE;
			}
		}
		if (gadget_op_has_explicit_mem_write (&op, expr)) {
			info->classes |= R_CORE_GADGET_CLASS_MEMWRITE;
			if (gadget_esil_is_write_what_where (expr)) {
				info->classes |= R_CORE_GADGET_CLASS_WRITE_WHAT_WHERE;
			}
		}
		if (gadget_op_is_pivot (core, &op, expr)) {
			info->classes |= R_CORE_GADGET_CLASS_PIVOT;
		}
		if (hit == last) {
			if (is_ret_gadget (&op, true)) {
				info->classes |= R_CORE_GADGET_CLASS_RET;
			} else if (gadget_op_is_call (&op)) {
				info->classes |= R_CORE_GADGET_CLASS_COP;
			} else if (gadget_op_is_jump (&op)) {
				info->classes |= R_CORE_GADGET_CLASS_JOP;
			}
			if (op.jump != UT64_MAX) {
				gadget_info_set_target (info, op.jump, R_CORE_GADGET_TARGET_DIRECT, "branch");
			} else if (R_STR_ISNOTEMPTY (op.reg)) {
				gadget_info_set_target_source (info, R_CORE_GADGET_TARGET_COMPUTED, op.reg);
			} else if (R_STR_ISNOTEMPTY (op.ireg)) {
				gadget_info_set_target_source (info, R_CORE_GADGET_TARGET_COMPUTED, op.ireg);
			} else if (gadget_op_has_explicit_mem_read (&op, expr)) {
				gadget_info_set_target_source (info, R_CORE_GADGET_TARGET_MEMORY, "memory");
			}
		}
		r_anal_op_fini (&op);
	}
}

static void gadget_info_apply_condition_class(RCoreGadgetEsilInfo *info) {
	if (!info->conditional) {
		return;
	}
	switch (info->condition) {
	case R_CORE_GADGET_ESIL_COND_ALWAYS:
		info->classes |= R_CORE_GADGET_CLASS_COND_ALWAYS;
		break;
	case R_CORE_GADGET_ESIL_COND_CONTROLLED:
		info->classes |= R_CORE_GADGET_CLASS_COND_CONTROLLED;
		break;
	default:
		break;
	}
}

static bool gadget_esil_resolve_target(RCore *core, RList *hitlist, RCoreAsmHit *end_hit, RCoreGadgetEsilInfo *info) {
	static const ut64 seeds[] = {
		0,
		1,
		5,
		UT64_MAX
	};
	if (!end_hit || (info->target_set && info->target_kind == R_CORE_GADGET_TARGET_DIRECT)) {
		return true;
	}
	RAnalOp op = {0};
	if (!gadget_anal_op_for_hit (core, end_hit, &op,
			R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT)) {
		r_anal_op_fini (&op);
		return false;
	}
	char source_buf[64] = {0};
	if (R_STR_ISNOTEMPTY (op.reg)) {
		r_str_ncpy (source_buf, op.reg, sizeof (source_buf));
	} else if (R_STR_ISNOTEMPTY (op.ireg)) {
		r_str_ncpy (source_buf, op.ireg, sizeof (source_buf));
	}
	const char *source = source_buf;
	const char *expr = R_STRBUF_SAFEGET (&op.esil);
	bool memory_backed = false;
	bool resolvable = false;
	if (R_STR_ISNOTEMPTY (source)) {
		resolvable = gadget_source_reg_defined (core, hitlist, end_hit->addr, source, &memory_backed);
	} else if (gadget_op_has_explicit_mem_read (&op, expr)) {
		r_str_ncpy (source_buf, "memory", sizeof (source_buf));
		memory_backed = true;
		resolvable = true;
	}
	r_anal_op_fini (&op);
	if (!resolvable) {
		return false;
	}

	bool have = false;
	RCoreGadgetEsilRun first = {0};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (seeds); i++) {
		RCoreGadgetEsilRun run = {0};
		if (!gadget_esil_eval_run (core, hitlist, end_hit->addr, seeds[i], &run)) {
			return false;
		}
		if (!run.target_set) {
			return false;
		}
		if (!have) {
			first = run;
			have = true;
		} else if (run.target != first.target) {
			return false;
		}
	}
	if (have) {
		gadget_info_set_target (info, first.target,
			memory_backed? R_CORE_GADGET_TARGET_MEMORY: R_CORE_GADGET_TARGET_COMPUTED,
			source);
	}
	return have;
}

static bool gadget_analyze_info(RCore *core, RList *hitlist, int gadget_type, bool crop, bool gadget_esil, RCoreGadgetEsilInfo *info) {
	RCoreAsmHit *end_hit = NULL;
	memset (info, 0, sizeof (*info));
	info->condition = R_CORE_GADGET_ESIL_COND_NONE;
	gadget_analyze_static (core, hitlist, info, &end_hit);
	if (gadget_esil) {
		if (!gadget_esil_classify_condition (core, hitlist, gadget_type, crop, info)) {
			return false;
		}
		gadget_esil_resolve_target (core, hitlist, end_hit, info);
	}
	gadget_info_apply_condition_class (info);
	return true;
}

static void gadget_info_json(PJ *pj, const RCoreGadgetEsilInfo *info) {
	if (!info) {
		return;
	}
	if (info->conditional) {
		pj_ks (pj, "condition", gadget_esil_cond_tostring (info->condition));
	}
	if (info->target_set) {
		pj_kN (pj, "target", info->target);
	}
	if (info->target_source[0]) {
		pj_ks (pj, "target_source", info->target_source);
	}
	if (info->target_kind != R_CORE_GADGET_TARGET_NONE) {
		pj_ks (pj, "target_kind", gadget_target_kind_tostring (info->target_kind));
	}
	if (info->classes) {
		size_t i;
		pj_ka (pj, "classes");
		for (i = 0; i < R_ARRAY_SIZE (gadget_class_names); i++) {
			if (info->classes & gadget_class_names[i].bit) {
				pj_s (pj, gadget_class_names[i].name);
			}
		}
		pj_end (pj);
	}
}

static const char *gadget_info_class_detail(const RCoreGadgetEsilInfo *info, const char *klass) {
	if (!info) {
		return NULL;
	}
	if (!strcmp (klass, "mov")) {
		return info->mov_detail;
	}
	if (!strcmp (klass, "ldconst")) {
		return info->ldconst_detail;
	}
	if (!strcmp (klass, "arithm")) {
		return info->arithm_detail;
	}
	if (!strcmp (klass, "arithm_ct")) {
		return info->arithm_detail;
	}
	if (!strcmp (klass, "logic")) {
		return info->logic_detail;
	}
	return NULL;
}

static char *gadget_sdb_value(const RCoreGadgetEsilInfo *info, unsigned int size, const char *klass) {
	char *s = r_str_newf ("0x%x %s", size, klass);
	if (!s) {
		return NULL;
	}
	const char *detail = gadget_info_class_detail (info, klass);
	if (R_STR_ISNOTEMPTY (detail)) {
		char *n = r_str_newf ("%s %s", s, detail);
		if (!n) {
			free (s);
			return NULL;
		}
		free (s);
		s = n;
	}
	if (info && info->target_set) {
		char *n = r_str_newf ("%s target=0x%08"PFMT64x, s, info->target);
		if (!n) {
			free (s);
			return NULL;
		}
		free (s);
		s = n;
	}
	if (info && info->target_source[0]) {
		char *n = r_str_newf ("%s target_source=%s", s, info->target_source);
		if (!n) {
			free (s);
			return NULL;
		}
		free (s);
		s = n;
	}
	if (info && info->target_kind != R_CORE_GADGET_TARGET_NONE) {
		char *n = r_str_newf ("%s target_kind=%s", s, gadget_target_kind_tostring (info->target_kind));
		if (!n) {
			free (s);
			return NULL;
		}
		free (s);
		s = n;
	}
	return s;
}

static void gadget_store_classes(Sdb *db, const RCoreGadgetEsilInfo *info, const char *key, unsigned int size) {
	if (!db || !info || !info->classes) {
		return;
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (gadget_class_names); i++) {
		if (!(info->classes & gadget_class_names[i].bit)) {
			continue;
		}
		char *gkey = r_str_newf ("%s_%s", gadget_class_names[i].name, key);
		if (!gkey) {
			return;
		}
		char *value = gadget_sdb_value (info, size, gadget_class_names[i].name);
		if (value) {
			sdb_set (db, gkey, value, 0);
			free (value);
		}
		free (gkey);
	}
}

static const char *gadget_kuery_flat_class(const char *key, char *klass, size_t klass_len) {
	const char *sep = strstr (key, "_0x");
	if (!sep || sep == key || klass_len < 1) {
		return NULL;
	}
	size_t len = R_MIN ((size_t)(sep - key), klass_len - 1);
	memcpy (klass, key, len);
	klass[len] = 0;
	return sep + 1;
}

static bool gadget_kuery_print_class(RCore *core, Sdb *db, const char *klass) {
	SdbListIter *sdb_iter;
	SdbList *sdb_list = sdb_foreach_list (db, false);
	SdbKv *kv;
	bool found = false;
	ls_foreach (sdb_list, sdb_iter, kv) {
		char key_klass[64];
		const char *addr = gadget_kuery_flat_class (sdbkv_key (kv), key_klass, sizeof (key_klass));
		if (addr && !strcmp (klass, key_klass)) {
			r_cons_printf (core->cons, "%s=%s\n", addr, sdbkv_value (kv));
			found = true;
		}
	}
	return found;
}

static void gadget_kuery_json(PJ *pj, Sdb *db_gadget) {
	SdbListIter *sdb_iter;
	SdbList *sdb_list;
	SdbKv *kv;

	pj_o (pj);
	pj_ka (pj, "gadgets");
	if (db_gadget) {
		sdb_list = sdb_foreach_list (db_gadget, false);
		ls_foreach (sdb_list, sdb_iter, kv) {
			char key_klass[64];
			const char *addr = gadget_kuery_flat_class (sdbkv_key (kv), key_klass, sizeof (key_klass));
			if (!addr) {
				continue;
			}
			char *dup = strdup (sdbkv_value (kv));
			if (!dup) {
				continue;
			}
			char *save_ptr = NULL;
			char *size = r_str_tok_r (dup, " ", &save_ptr);
			const char *effect = save_ptr? r_str_trim_head_ro (save_ptr): "";
			pj_o (pj);
			pj_ks (pj, "address", addr);
			pj_ks (pj, "size", size);
			pj_ks (pj, "type", key_klass);
			pj_ks (pj, "effect", effect);
			pj_end (pj);
			free (dup);
		}
	}
	pj_end (pj);
	pj_end (pj);
}

static void rop_kuery(void *data, const char *input, PJ *pj) {
	RCore *core = (RCore *) data;
	SdbListIter *sdb_iter;
	SdbList *sdb_list;
	SdbKv *kv;

	Sdb *db_gadget = sdb_ns (core->sdb, "gadget", false);
	if (!db_gadget) {
		R_LOG_ERROR ("could not find SDB 'gadget' namespace");
		return;
	}

	switch (*input) {
	case 'q':
		sdb_list = sdb_foreach_list (db_gadget, false);
		ls_foreach (sdb_list, sdb_iter, kv) {
			char key_klass[64];
			const char *addr = gadget_kuery_flat_class (sdbkv_key (kv), key_klass, sizeof (key_klass));
			if (addr) {
				r_cons_printf (core->cons, "%s ", addr);
			}
		}
		break;
	case 'j':
		gadget_kuery_json (pj, db_gadget);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_slash_Gk);
		break;
	case ' ':
		if (gadget_kuery_print_class (core, db_gadget, input + 1)) {
			break;
		}
		R_LOG_ERROR ("Invalid gadget class");
		break;
	default:
		sdb_list = sdb_foreach_list (db_gadget, false);
		ls_foreach (sdb_list, sdb_iter, kv) {
			char key_klass[64];
			const char *addr = gadget_kuery_flat_class (sdbkv_key (kv), key_klass, sizeof (key_klass));
			if (addr) {
				r_cons_printf (core->cons, "%s.%s=%s\n", key_klass, addr, sdbkv_value (kv));
			}
		}
		break;
	}
}

#endif

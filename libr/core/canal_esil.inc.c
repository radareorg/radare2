typedef struct {
	int arena;
	int offset;
	int size;
} EsilRegTaint;

R_VEC_TYPE(RVecEsilRegTaint, EsilRegTaint);

static void cccb(void *u) {
	RCore *core = (RCore *)u;
	core->esil_anal_stop = false;
	r_cons_context_break (NULL);
	eprintf ("^C\n");
}

// dup with isValidAddress wtf
static bool myvalid(RCore *core, ut64 addr) {
	RIO *io = core->io;
#if 1
	RFlagItem *fi = r_flag_get_in (core->flags, addr);
	if (fi && strchr (fi->name, '.')) {
		return true;
	}
#endif
	if (addr < 0x100) {
		return false;
	}
	if (addr == UT32_MAX || addr == UT64_MAX) { // the best of the best of the best :(
		return false;
	}
	if (!r_io_is_valid_offset (io, addr, 0)) {
		return false;
	}
	return true;
}

typedef struct {
	bool enabled;
	RVecEsilRegTaint reg_taints;
	EsilRegTaint pc_span;
	EsilRegTaint read_tainted_span;
	int read_tainted_reads;
	bool read_tainted_other;
	char read_tainted_reg[64];
	bool read_clobbered;
	bool read_clean_mem;
	char *delayed_call_cc;
	int delayed_call_slots;
	int delayed_taint_clear_slots;
} EsilClobCtx;

typedef struct {
	RAnalOp *op;
	RAnal *anal;
	RAnalFunction *fcn;
	char *spname;
	ut64 initial_sp;
	ut64 last_read;
	ut64 last_data;
	ut64 ntarget;
	EsilClobCtx clob;
} EsilBreakCtx;

typedef int RPerm;

static bool esil_reg_taint_overlap_item(const EsilRegTaint *taint, const RRegItem *item) {
	if (taint->arena != item->arena || taint->size < 1 || item->size < 1) {
		return false;
	}
	const int taint_end = taint->offset + taint->size;
	const int item_end = item->offset + item->size;
	return taint->offset < item_end && item->offset < taint_end;
}

static bool esil_reg_taint_has_item(EsilBreakCtx *ctx, const RRegItem *item) {
	EsilRegTaint *taint;
	R_VEC_FOREACH (&ctx->clob.reg_taints, taint) {
		if (esil_reg_taint_overlap_item (taint, item)) {
			return true;
		}
	}
	return false;
}

static void esil_reg_taint_add_item(EsilBreakCtx *ctx, const RRegItem *item) {
	if (item->size < 1) {
		return;
	}
	EsilRegTaint span = {
		.arena = item->arena,
		.offset = item->offset,
		.size = item->size,
	};
	EsilRegTaint *taint;
	R_VEC_FOREACH (&ctx->clob.reg_taints, taint) {
		if (taint->arena != span.arena) {
			continue;
		}
		const int taint_end = taint->offset + taint->size;
		const int span_end = span.offset + span.size;
		if (taint->offset < span_end && span.offset < taint_end) {
			const int start = R_MIN (taint->offset, span.offset);
			const int end = R_MAX (taint_end, span_end);
			taint->offset = start;
			taint->size = end - start;
			return;
		}
	}
	RVecEsilRegTaint_push_back (&ctx->clob.reg_taints, &span);
}

static void esil_reg_taint_clear_item(EsilBreakCtx *ctx, const RRegItem *item) {
	if (item->size < 1) {
		return;
	}
	const int clear_start = item->offset;
	const int clear_end = item->offset + item->size;
	size_t i = 0;
	while (i < RVecEsilRegTaint_length (&ctx->clob.reg_taints)) {
		EsilRegTaint *taint = RVecEsilRegTaint_at (&ctx->clob.reg_taints, i);
		if (!esil_reg_taint_overlap_item (taint, item)) {
			i++;
			continue;
		}
		const int taint_start = taint->offset;
		const int taint_end = taint->offset + taint->size;
		if (clear_start <= taint_start && clear_end >= taint_end) {
			RVecEsilRegTaint_remove (&ctx->clob.reg_taints, i);
			continue;
		}
		if (clear_start <= taint_start) {
			taint->offset = clear_end;
			taint->size = taint_end - clear_end;
			i++;
			continue;
		}
		if (clear_end >= taint_end) {
			taint->size = clear_start - taint_start;
			i++;
			continue;
		}
		EsilRegTaint tail = {
			.arena = taint->arena,
			.offset = clear_end,
			.size = taint_end - clear_end,
		};
		taint->size = clear_start - taint_start;
		RVecEsilRegTaint_push_back (&ctx->clob.reg_taints, &tail);
		i++;
	}
}

static void esil_clear_flow_taint(EsilBreakCtx *ctx) {
	RVecEsilRegTaint_clear (&ctx->clob.reg_taints);
	R_FREE (ctx->clob.delayed_call_cc);
	ctx->clob.delayed_call_slots = 0;
	ctx->clob.delayed_taint_clear_slots = 0;
}

static void clob_reset(EsilBreakCtx *ctx) {
	ctx->clob.read_clobbered = false;
	ctx->clob.read_clean_mem = false;
	ctx->clob.read_tainted_other = false;
	ctx->clob.read_tainted_reads = 0;
	ctx->clob.read_tainted_reg[0] = 0;
}

static void esilbreak_ctx_fini(REsil *esil, EsilBreakCtx *ctx) {
	esil->cb.hook_mem_read = NULL;
	esil->cb.hook_mem_write = NULL;
	esil->cb.hook_reg_read = NULL;
	esil->cb.hook_reg_write = NULL;
	esil->user = NULL;
	RVecEsilRegTaint_fini (&ctx->clob.reg_taints);
	free (ctx->clob.delayed_call_cc);
	free (ctx->spname);
}

static bool esilbreak_skip_ref_op(int type) {
	type &= R_ANAL_OP_TYPE_MASK;
	return type == R_ANAL_OP_TYPE_LEA || type == R_ANAL_OP_TYPE_ADD || type == R_ANAL_OP_TYPE_LOAD;
}

static void esil_havoc_clobbers_by_cc(RAnal *anal, EsilBreakCtx *ctx, const char *cc) {
	if (!anal || !anal->reg || !cc) {
		return;
	}
	RRegSet *rs = &anal->reg->regset[R_REG_TYPE_GPR];
	RRegItem *item;
	RListIter *iter;
	r_list_foreach (rs->regs, iter, item) {
		if (r_anal_cc_isclobber (anal, cc, item->name)) {
			esil_reg_taint_add_item (ctx, item);
		}
	}
}

static bool esil_delay_call_clobbers(RAnal *anal, EsilBreakCtx *ctx, RAnalOp *op) {
	if (op->jump != UT64_MAX && op->fail != UT64_MAX && op->jump == op->fail) {
		// Calls to the fallthrough address are PC materialization, not ABI calls.
		return false;
	}
	const char *cc = r_anal_call_convention (anal, op);
	if (!cc) {
		cc = r_anal_cc_default (anal);
	}
	if (!cc) {
		return false;
	}
	if (op->delay < 1) {
		esil_havoc_clobbers_by_cc (anal, ctx, cc);
		return false;
	}
	free (ctx->clob.delayed_call_cc);
	ctx->clob.delayed_call_cc = strdup (cc);
	ctx->clob.delayed_call_slots = ctx->clob.delayed_call_cc? op->delay + 1: 0;
	return ctx->clob.delayed_call_slots > 0;
}

static void esil_step_delayed_call_clobbers(RAnal *anal, EsilBreakCtx *ctx) {
	if (!ctx->clob.delayed_call_cc || ctx->clob.delayed_call_slots < 1) {
		return;
	}
	ctx->clob.delayed_call_slots--;
	if (ctx->clob.delayed_call_slots > 0) {
		return;
	}
	esil_havoc_clobbers_by_cc (anal, ctx, ctx->clob.delayed_call_cc);
	R_FREE (ctx->clob.delayed_call_cc);
}

static void esil_delay_flow_taint_clear(EsilBreakCtx *ctx, RAnalOp *op) {
	const int type = op->type & R_ANAL_OP_TYPE_MASK;
	if ((type & R_ANAL_OP_TYPE_COND) || (type != R_ANAL_OP_TYPE_JMP && type != R_ANAL_OP_TYPE_UJMP)) {
		return;
	}
	ctx->clob.delayed_taint_clear_slots = op->delay + 1;
}

static void esil_step_delayed_flow_taint_clear(EsilBreakCtx *ctx) {
	if (ctx->clob.delayed_taint_clear_slots < 1) {
		return;
	}
	ctx->clob.delayed_taint_clear_slots--;
	if (ctx->clob.delayed_taint_clear_slots > 0) {
		return;
	}
	esil_clear_flow_taint (ctx);
}

static void clob_op_begin(EsilBreakCtx *ctx, RAnalOp *op, ut64 cur) {
	if (!ctx->clob.enabled) {
		return;
	}
	esil_step_delayed_call_clobbers (ctx->anal, ctx);
	esil_step_delayed_flow_taint_clear (ctx);
	if (RVecEsilRegTaint_length (&ctx->clob.reg_taints) > 0 && r_anal_get_function_at (ctx->anal, cur)) {
		esil_clear_flow_taint (ctx);
	}
	clob_reset (ctx);
	const int type = op->type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_TYPE_COND;
	if (type == R_ANAL_OP_TYPE_RET) {
		esil_clear_flow_taint (ctx);
	}
	esil_delay_flow_taint_clear (ctx, op);
}

static const char *reg_name_for_access(RAnalOp* op, RPerm type) {
	if (type == R_PERM_W) {
		RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
		if (dst) {
			return dst->reg;
		}
	} else {
		RAnalValue *src = RVecRArchValue_at (&op->srcs, 0);
		if (src) {
			return src->reg;
		}
	}
	return NULL;
}

static ut64 delta_for_access(RAnalOp *op, RPerm type) {
	RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
	RAnalValue *src0 = RVecRArchValue_at (&op->srcs, 0);
	RAnalValue *src1 = RVecRArchValue_at (&op->srcs, 1);
	if (type == R_PERM_W) {
		if (dst) {
			return dst->imm + dst->delta;
		}
	} else {
		if (src1 && (src1->imm || src1->delta)) {
			return src1->imm + src1->delta;
		}
		if (src0) {
			return src0->imm + src0->delta;
		}
	}
	return 0;
}

static char *esilbreak_clobbered_varname(RAnalOp *op, RPerm type, int stack_off) {
	ut64 delta = delta_for_access (op, type);
	return r_str_newf (VARPREFIX"_clob_%"PFMT64x"h", delta? delta: (ut64)R_ABS (stack_off));
}

static bool esilbreak_is_default_stack_var(const char *name) {
	return r_str_startswith (name, VARPREFIX"_") && !r_str_startswith (name, VARPREFIX"_clob_");
}

static void handle_var_stack_access(REsil *esil, ut64 addr, RPerm type, int len, bool clobbered_write) {
	R_RETURN_IF_FAIL (esil && esil->user);
	EsilBreakCtx *ctx = esil->user;
	const char *regname = reg_name_for_access (ctx->op, type);
	RAnalFunction *fcn = ctx->fcn;
	if (!fcn || !regname) {
		return;
	}
	ut64 spaddr = r_reg_getv (esil->anal->reg, ctx->spname);
	if (addr < spaddr || addr >= ctx->initial_sp) {
		return;
	}
	int stack_off = addr - ctx->initial_sp;
	RAnalVar *var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_SPV, stack_off);
	if (!var) {
		var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_BPV, stack_off);
	}
	if (!var && stack_off >= -fcn->maxstack) {
		char *varname = clobbered_write
			? esilbreak_clobbered_varname (ctx->op, type, stack_off)
			: fcn->anal->opt.varname_stack
			? r_str_newf (VARPREFIX"_%xh", R_ABS (stack_off))
			: r_anal_function_autoname_var (fcn, R_ANAL_VAR_KIND_SPV, VARPREFIX, delta_for_access (ctx->op, type));
		var = r_anal_function_set_var (fcn, stack_off, R_ANAL_VAR_KIND_SPV, NULL, len, false, varname);
		free (varname);
	}
	if (var && clobbered_write && esilbreak_is_default_stack_var (var->name)) {
		char *varname = esilbreak_clobbered_varname (ctx->op, type, stack_off);
		r_anal_var_rename (fcn->anal, var, varname);
		free (varname);
	}
	if (var) {
		r_anal_var_set_access (fcn->anal, var, regname, ctx->op->addr, type, delta_for_access (ctx->op, type));
	}
}

static bool is_stack(RIO *io, ut64 addr) {
	RIOMap *map = r_io_map_get_at (io, addr);
	return map && map->name && r_str_startswith (map->name, "mem.0x");
}

// only taint on the address register matters here: a stale stored value does
// not make the write target wrong. when the destination operand is unknown
// (op->dsts is only filled for some archs in this loop) do not suppress:
// tainted reads evaluate as zero, so a stale address degrades to the bare
// displacement, which the myvalid() check filters out
static bool esilbreak_addr_tainted(REsil *esil, RPerm type) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal && esil->user, false);
	EsilBreakCtx *ctx = esil->user;
	if (!ctx->clob.enabled || RVecEsilRegTaint_length (&ctx->clob.reg_taints) < 1) {
		return false;
	}
	const char *regname = reg_name_for_access (ctx->op, type);
	if (!regname) {
		return false;
	}
	RRegItem *item = r_reg_get (esil->anal->reg, regname, -1);
	if (!item) {
		return false;
	}
	const bool tainted = esil_reg_taint_has_item (ctx, item);
	r_unref (item);
	return tainted;
}

static void esilbreak_note_tainted_read(EsilBreakCtx *ctx, const char *regname, const RRegItem *item) {
	if (!ctx->clob.read_tainted_reg[0]) {
		r_str_ncpy (ctx->clob.read_tainted_reg, regname, sizeof (ctx->clob.read_tainted_reg));
		ctx->clob.read_tainted_span.arena = item->arena;
		ctx->clob.read_tainted_span.offset = item->offset;
		ctx->clob.read_tainted_span.size = item->size;
	} else if (!esil_reg_taint_overlap_item (&ctx->clob.read_tainted_span, item)) {
		ctx->clob.read_tainted_other = true;
	}
	ctx->clob.read_tainted_reads++;
}

// v^v and v-v do not depend on v: a xor or sub that combines the overwritten
// register with itself defines a clean value, like the "xor eax, eax" idiom
static bool esilbreak_erasing_write(EsilBreakCtx *ctx, const RAnalOp *op, const RRegItem *item) {
	const int type = op->type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_TYPE_COND;
	return (type == R_ANAL_OP_TYPE_XOR || type == R_ANAL_OP_TYPE_SUB)
		&& ctx->clob.read_tainted_reads > 1 && !ctx->clob.read_tainted_other
		&& esil_reg_taint_overlap_item (&ctx->clob.read_tainted_span, item);
}

static bool iscall(const RAnalOp *op) {
	switch (op->type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_TYPE_COND) {
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_IRCALL:
		return true;
	default:
		return false;
	}
}

static bool clob_op_end(EsilBreakCtx *ctx, RAnalOp *op) {
	if (!ctx->clob.enabled) {
		return false;
	}
	if (iscall (op)) {
		esil_delay_call_clobbers (ctx->anal, ctx, op);
	}
	return ctx->clob.read_clobbered;
}

static bool esilbreak_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal && esil->user, false);
	EsilBreakCtx *ctx = esil->user;
	RCore *core = esil->anal->coreb.core;
	const bool clobbered_write = ctx->clob.enabled && ctx->clob.read_clobbered;
	handle_var_stack_access (esil, addr, R_PERM_W, len, clobbered_write);
	if (esilbreak_addr_tainted (esil, R_PERM_W)) {
		return true;
	}
	// ignore writes in stack
	if (myvalid (core, addr) && r_io_read_at (core->io, addr, (ut8*)buf, len)) {
		if (!is_stack (core->io, addr)) {
			r_anal_xrefs_set (core->anal, esil->addr, addr, R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_WRITE);
			/** resolve ptr */
			//if (ntarget == UT64_MAX || ntarget == addr || (ntarget == UT64_MAX && !validRef)) {
	//			r_anal_xrefs_set (core->anal, esil->addr, addr, R_ANAL_REF_TYPE_DATA);
			//}
		}
	}
	return true;
}

// TODO differentiate endian-aware mem_read with other reads; move ntarget handling to another function
static bool esilbreak_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal && esil->user, false);
	EsilBreakCtx *ctx = esil->user;
	if (ctx->clob.enabled && ctx->clob.read_clobbered) {
		ctx->last_read = UT64_MAX;
		ctx->last_data = UT64_MAX;
		if (buf && len > 0) {
			memset (buf, 0, len);
		}
		return true;
	}
	RCore *core = esil->anal->coreb.core;
	ut8 str[128];
	if (addr != UT64_MAX) {
		ctx->last_read = addr;
		if (ctx->clob.enabled) {
			ctx->clob.read_clean_mem = true;
		}
	}
	handle_var_stack_access (esil, addr, R_PERM_R, len, false);
	if (myvalid (core, addr) && r_io_read_at (core->io, addr, (ut8*)buf, len)) {
		ut64 refptr = UT64_MAX;
		bool trace = true;
		switch (len) {
		case 2:
			ctx->last_data = refptr = (ut64)r_read_ble16 (buf,
				R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config));
			break;
		case 4:
			ctx->last_data = refptr = (ut64)r_read_ble32 (buf,
				R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config));
			break;
		case 8:
			ctx->last_data = refptr = r_read_ble64 (buf,
				R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config));
			break;
		default:
			trace = false;
			r_io_read_at (core->io, addr, (ut8*)buf, len);
			break;
		}
		if (trace && myvalid (core, refptr) && (ctx->ntarget == UT64_MAX || ctx->ntarget == refptr)) {
			str[0] = 0;
			if (r_io_read_at (core->io, refptr, str, sizeof (str)) < 1) {
				str[0] = 0;
			} else {
				r_anal_xrefs_set (core->anal, esil->addr, refptr, R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ);
				str[sizeof (str) - 1] = 0;
				add_string_ref (core, esil->addr, refptr);
				ctx->last_data = UT64_MAX;
			}
		}
		if (myvalid (core, addr) && r_io_read_at (core->io, addr, (ut8*)buf, len) && !is_stack (core->io, addr)) {
			r_anal_xrefs_set (core->anal, esil->addr, addr, R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ);
		}
	}
	return false; // fallback
}

static bool esilbreak_reg_read(REsil *esil, const char *name, ut64 *res, int *size) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal && esil->user && name, false);
	EsilBreakCtx *ctx = esil->user;
	if (!ctx->clob.enabled || RVecEsilRegTaint_length (&ctx->clob.reg_taints) < 1) {
		return false;
	}
	RRegItem *item = r_reg_get (esil->anal->reg, name, -1);
	if (!item) {
		return false;
	}
	const bool tainted = esil_reg_taint_has_item (ctx, item);
	if (tainted) {
		ctx->clob.read_clobbered = true;
		esilbreak_note_tainted_read (ctx, name, item);
		if (res) {
			*res = 0;
		}
		if (size) {
			*size = item->size;
		}
	}
	r_unref (item);
	return tainted;
}

// compare register storage instead of names: esil expressions use "pc"
// while the profile alias can resolve to another name like "r15" on arm
static void esil_reg_pc_span(RAnal *anal, EsilRegTaint *span) {
	const char *pcname = r_reg_alias_getname (anal->reg, R_REG_ALIAS_PC);
	if (R_STR_ISEMPTY (pcname)) {
		return;
	}
	RRegItem *pc = r_reg_get (anal->reg, pcname, -1);
	if (!pc) {
		return;
	}
	*span = (EsilRegTaint) {
		.arena = pc->arena,
		.offset = pc->offset,
		.size = pc->size,
	};
	r_unref (pc);
}

static bool esilbreak_reg_write(REsil *esil, const char *name, ut64 *val) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal && esil->user, false);
	RAnal *anal = esil->anal;
	EsilBreakCtx *ctx = esil->user;
	RAnalOp *op = ctx->op;
	const bool is_arm = r_str_startswith (anal->config->arch, "arm");
	const bool is_arm_non64 = is_arm && anal->config->bits != 64;
	const bool is_arm64 = is_arm && anal->config->bits == 64;
	if (ctx->clob.enabled && (ctx->clob.read_clobbered || RVecEsilRegTaint_length (&ctx->clob.reg_taints) > 0)) {
		RRegItem *item = r_reg_get (anal->reg, name, -1);
		if (item) {
			RRegItem *clear_item = item;
			RRegItem *xitem = NULL;
			if (is_arm64 && item->type == R_REG_TYPE_GPR && item->size == 32 && item->name[0] == 'w') {
				r_strf_var (xname, 8, "x%s", item->name + 1);
				xitem = r_reg_get (anal->reg, xname, -1);
				if (xitem && xitem->arena == item->arena && xitem->offset == item->offset && xitem->size > item->size) {
					clear_item = xitem;
				}
			}
			if (ctx->clob.read_clobbered) {
				// strip the COND bit: if this hook fired for a conditional
				// load then the esil condition held and the load did happen
				if ((ctx->clob.read_clean_mem && (op->type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_TYPE_COND) == R_ANAL_OP_TYPE_LOAD)
						|| esilbreak_erasing_write (ctx, op, item)) {
					esil_reg_taint_clear_item (ctx, clear_item);
				} else if (ctx->clob.pc_span.size < 1
						|| !esil_reg_taint_overlap_item (&ctx->clob.pc_span, item)) {
					esil_reg_taint_clear_item (ctx, clear_item);
					esil_reg_taint_add_item (ctx, item);
				}
				r_unref (xitem);
				r_unref (item);
				return false;
			}
			esil_reg_taint_clear_item (ctx, clear_item);
			r_unref (xitem);
			r_unref (item);
		}
	}
	handle_var_stack_access (esil, *val, R_PERM_NONE, esil->anal->config->bits / 8, false);
	//specific case to handle blx/bx cases in arm through emulation
	// XXX this thing creates a lot of false positives
	ut64 at = *val;
	if (is_arm) {
		if (anal->opt.armthumb) {
			if (is_arm_non64 && !strcmp (name, "pc") && op) {
				const bool is_ubranch = (op->type == R_ANAL_OP_TYPE_UCALL || op->type == R_ANAL_OP_TYPE_UJMP);
				if (is_ubranch) {
					if ((*val & 1)) {
						ut64 snv = r_reg_getv (anal->reg, "pc");
						if (snv != UT32_MAX && snv != UT64_MAX) {
							if (r_io_is_valid_offset (anal->iob.io, *val, 1)) {
								r_anal_hint_set_bits (anal, *val - 1, 16);
							}
						}
					} else {
						r_anal_hint_set_bits (anal, *val, 32);
					}
				}
			}
		}
		if (anal->config->bits == 32) {
			if ((!(at & 1)) && r_io_is_valid_offset (anal->iob.io, at, 0)) { //  !core->anal->opt.noncode)) {
				add_string_ref (anal->coreb.core, esil->addr, at);
			}
		}
	} else {
		// intel, sparc and others
		if (op->type != R_ANAL_OP_TYPE_RMOV) {
			if (r_io_is_valid_offset (anal->iob.io, at, 0)) {
				add_string_ref (anal->coreb.core, esil->addr, at);
			}
		}
	}
	return 0;
}

static void getpcfromstack(RCore *core, REsil *esil) {
	ut64 cur;
	ut64 size;
	int idx;
	REsil esil_cpy;
	RAnalOp op = {0};
	ut8 *buf = NULL;
	char *tmp_esil_str = NULL;
	int tmp_esil_str_len;
	const int maxaddrlen = 20;
	const char *spname = NULL;
	if (!esil) {
		return;
	}

	memcpy (&esil_cpy, esil, sizeof (esil_cpy));
	ut64 addr = cur = esil_cpy.cur;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn) {
		return;
	}

	size = r_anal_function_linear_size (fcn);
	if (size <= 0) {
		return;
	}

	buf = malloc (size + 2);
	if (!buf) {
		r_sys_perror ("malloc");
		return;
	}

	r_io_read_at (core->io, addr, buf, size + 1);

	// TODO Hardcoding for 2 instructions (mov e_p,[esp];ret). More work needed
	idx = 0;
	if (r_anal_op (core->anal, &op, cur, buf + idx, size - idx, R_ARCH_OP_MASK_ESIL) <= 0 ||
			op.size <= 0 ||
			(op.type != R_ANAL_OP_TYPE_MOV && op.type != R_ANAL_OP_TYPE_CMOV)) {
		goto err_anal_op;
	}

	r_asm_set_pc (core->rasm, cur);
	const char *esilstr = R_STRBUF_SAFEGET (&op.esil);
	if (!esilstr) {
		goto err_anal_op;
	}
	// Ugly code
	// This is a hack, since ESIL doesn't always preserve values pushed on the stack. That probably needs to be rectified
	spname = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_SP);
	if (R_STR_ISEMPTY (spname)) {
		goto err_anal_op;
	}
	tmp_esil_str_len = strlen (esilstr) + strlen (spname) + maxaddrlen;
	tmp_esil_str = (char*) malloc (tmp_esil_str_len);
	if (!tmp_esil_str) {
		goto err_anal_op;
	}
	tmp_esil_str[tmp_esil_str_len - 1] = '\0';
	snprintf (tmp_esil_str, tmp_esil_str_len - 1, "%s,[", spname);
	if (!*esilstr || (strncmp (esilstr, tmp_esil_str, strlen (tmp_esil_str)))) {
		free (tmp_esil_str);
		goto err_anal_op;
	}

	snprintf (tmp_esil_str, tmp_esil_str_len - 1, "%20" PFMT64u "%s", esil_cpy.old, &esilstr[strlen (spname) + 4]);
	r_str_trim (tmp_esil_str);
	idx += op.size;
	r_esil_set_pc (&esil_cpy, cur);
	r_esil_parse (&esil_cpy, tmp_esil_str);
	r_esil_stack_free (&esil_cpy);
	free (tmp_esil_str);

	cur = addr + idx;
	r_anal_op_fini (&op);
	if (r_anal_op (core->anal, &op, cur, buf + idx, size - idx, R_ARCH_OP_MASK_ESIL) <= 0 ||
			op.size <= 0 ||
			(op.type != R_ANAL_OP_TYPE_RET && op.type != R_ANAL_OP_TYPE_CRET)) {
		goto err_anal_op;
	}
	r_asm_set_pc (core->rasm, cur);

	esilstr = R_STRBUF_SAFEGET (&op.esil);
	r_esil_set_pc (&esil_cpy, cur);
	if (R_STR_ISEMPTY (esilstr)) {
		goto err_anal_op;
	}
	r_esil_parse (&esil_cpy, esilstr);
	r_esil_stack_free (&esil_cpy);

	memcpy (esil, &esil_cpy, sizeof (esil_cpy));

 err_anal_op:
	r_anal_op_fini (&op);
	free (buf);
}

typedef struct {
	ut64 start_addr;
	ut64 end_addr;
	RAnalFunction *fcn;
	RAnalBlock *cur_bb;
	RList *bbl, *path, *switch_path;
} IterCtx;

static int find_bb(ut64 *addr, RAnalBlock *bb) {
	return *addr != bb->addr;
}

static bool get_next_i(IterCtx *ctx, size_t *next_i) {
	(*next_i)++;
	ut64 cur_addr = *next_i + ctx->start_addr;
	if (ctx->fcn) {
		if (!ctx->cur_bb) {
			ctx->path = r_list_new ();
			ctx->switch_path = r_list_new ();
			ctx->bbl = r_list_clone (ctx->fcn->bbs, NULL);
			ctx->cur_bb = r_anal_get_block_at (ctx->fcn->anal, ctx->fcn->addr);
			if (!ctx->cur_bb) {
				return false;
			}
			r_list_push (ctx->path, ctx->cur_bb);
		}
		RAnalBlock *bb = ctx->cur_bb;
		if (cur_addr >= bb->addr + bb->size) {
			r_reg_arena_push (ctx->fcn->anal->reg);
			RListIter *bbit = NULL;
			if (bb->switch_op) {
				RAnalCaseOp *cop = r_list_first (bb->switch_op->cases);
				bbit = r_list_find (ctx->bbl, &cop->jump, (RListComparator)find_bb);
				if (bbit) {
					r_list_push (ctx->switch_path, bb->switch_op->cases->head);
				}
			} else {
				bbit = r_list_find (ctx->bbl, &bb->jump, (RListComparator)find_bb);
				if (!bbit && bb->fail != UT64_MAX) {
					bbit = r_list_find (ctx->bbl, &bb->fail, (RListComparator)find_bb);
				}
			}
			if (!bbit) {
				RListIter *cop_it = r_list_last (ctx->switch_path);
				RAnalBlock *prev_bb = NULL;
				do {
					r_reg_arena_pop (ctx->fcn->anal->reg);
					prev_bb = r_list_pop (ctx->path);
					if (prev_bb->fail != UT64_MAX) {
						bbit = r_list_find (ctx->bbl, &prev_bb->fail, (RListComparator)find_bb);
						if (bbit) {
							r_reg_arena_push (ctx->fcn->anal->reg);
							r_list_push (ctx->path, prev_bb);
						}
					}
					if (!bbit && cop_it) {
						RAnalCaseOp *cop = cop_it->data;
						if (cop->jump == prev_bb->addr && cop_it->n) {
							cop = cop_it->n->data;
							r_list_pop (ctx->switch_path);
							r_list_push (ctx->switch_path, cop_it->n);
							cop_it = cop_it->n;
							bbit = r_list_find (ctx->bbl, &cop->jump, (RListComparator)find_bb);
						}
					}
					if (cop_it && !cop_it->n) {
						r_list_pop (ctx->switch_path);
						cop_it = r_list_last (ctx->switch_path);
					}
				} while (!bbit && !r_list_empty (ctx->path));
			}
			if (!bbit) {
				r_list_free (ctx->path);
				r_list_free (ctx->switch_path);
				r_list_free (ctx->bbl);
				ctx->path = NULL;
				ctx->switch_path = NULL;
				ctx->bbl = NULL;
				return false;
			}
			if (!bbit->data) {
				return false;
			}
			if (!bbit->data) {
				return false;
			}
			ctx->cur_bb = bbit->data;
			r_list_push (ctx->path, ctx->cur_bb);
			r_list_delete (ctx->bbl, bbit);
			*next_i = ctx->cur_bb->addr - ctx->start_addr;
		}
	} else if (cur_addr >= ctx->end_addr) {
		return false;
	}
	if (*next_i == 0) {
		return false;
	}
	return true;
}

static ut64 pulldata(RCore *core, ut8 *buf, size_t buf_size, ut64 start, ut64 end, size_t i, ut64 *buf_addr, size_t buf_i) {
	const size_t maxopsize = 64; // just in case
	size_t maxsize = R_MIN (buf_size, end - i + maxopsize);
	if (start >= end) {
		// fix division by zero
		return 0;
	}
	if (buf_i + 128 >= maxsize || i == 0) {
		if (r_config_get_b (core->config, "scr.interactive")) { // or maybe scr.demo?
			const int pc = i * 100 / (end - start);
			eprintf (" > aae: %d%%\r", pc);
		}
		const ut64 newaddr = start + i;
		r_io_read_at (core->io, newaddr, buf, maxsize);
		*buf_addr = newaddr;
		return 0;
	}
	ut64 new_buf_i = start + i - *buf_addr;
	if (new_buf_i > buf_size) {
		const ut64 newaddr = start + i;
		r_io_read_at (core->io, newaddr, buf, maxsize);
		new_buf_i = 0;
	}
	return new_buf_i;
}

R_API void r_core_anal_esil(RCore *core, const char *str /* len */, const char *target /* addr */) {
	bool cfg_anal_strings = r_config_get_b (core->config, "anal.strings");
	bool emu_lazy = r_config_get_b (core->config, "emu.lazy");
	const bool gp_fixed = r_config_get_b (core->config, "anal.fixed.gp");
	bool newstack = r_config_get_b (core->config, "anal.var.newstack");
	REsil *ESIL = core->anal->esil;
	ut64 refptr = 0LL;
	ut64 ntarget = UT64_MAX;
	RAnalOp op = {0};
	bool end_address_set = false;
	int iend;
	int minopsize = 4; // XXX this depends on asm->mininstrsize
	bool archIsArm = false;
	const bool archIsX86 = r_str_startswith (core->anal->config->arch, "x86");
	// ut64 addr = core->addr;
	ut64 start = core->addr;
	ut64 end = 0LL;
	core->esil_anal_stop = false;

	if (!strcmp (str, "?")) {
		R_LOG_INFO ("should never happen");
		return;
	}
#define CHECKREF(x) ((refptr && (x) == refptr) || !refptr)
	bool xrefs_only = false;
	if (target && !strcmp (target, "+x")) {
		xrefs_only = true;
		ntarget = core->addr;
		refptr = 0LL;
		target = NULL;
	} else if (target) {
		const char *expr = r_str_trim_head_ro (target);
		if (*expr) {
			ntarget = r_num_math (core->num, expr);
			if (ntarget && ntarget != UT64_MAX) {
				refptr = ntarget;
			} else {
				refptr = start;
				ntarget = start;
			}
		} else {
			ntarget = UT64_MAX;
			refptr = 0LL;
		}
//		start = ntarget;
		end_address_set = true;
	} else {
		ntarget = core->addr;
		refptr = 0LL;
	}

	if (!end_address_set || !end) {
		if (R_STR_ISNOTEMPTY (str)) { // str[0] == ' ') {
			end = start + r_num_math (core->num, str);
		} else {
			RIOMap *map = r_io_map_get_at (core->io, start);
			if (map) {
				end = r_io_map_end (map);
			} else {
				end = start + core->blocksize;
			}
		}
	}
	RAnalFunction *fcn = NULL;
	if (!strcmp (str, "f")) {
		fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
		if (fcn) {
			ut64 ls = r_anal_function_linear_size (fcn);
			ut64 fs = r_anal_function_realsize (fcn);
			if (ls > fs + 4096) {
				R_LOG_DEBUG ("Function 0x%08"PFMT64x" (%s) is sparse, analyzing each basic block",
					fcn->addr, fcn->name? fcn->name: "?");
				// Sparse function: analyze each basic block separately using full ESIL analysis
				// (not r_core_anal_esil_function which uses simpler hooks and misses some xrefs)
				bool (*old_write_at)(RIO *io, ut64 addr, const ut8 *buf, int len) = core->anal->iob.write_at;
				core->anal->iob.write_at = r_io_vwrite_to_overlay_at;
				RListIter *iter;
				RAnalBlock *bb;
				r_list_foreach (fcn->bbs, iter, bb) {
					char szbuf[32];
					snprintf (szbuf, sizeof (szbuf), "%"PFMT64u, (ut64)bb->size);
					r_core_seek (core, bb->addr, true);
					r_core_anal_esil (core, szbuf, NULL);
				}
				core->anal->iob.write_at = old_write_at;
				return;
			}
			start = r_anal_function_min_addr (fcn);
			if (start != UT64_MAX) {
				start = fcn->addr;
				end = r_anal_function_max_addr (fcn);
				end_address_set = true;
			}
		}
	}

	R_LOG_DEBUG ("aae length (%s) 0x%"PFMT64x, str, end);
	R_LOG_DEBUG ("aae addr (%s) 0x%"PFMT64x, target, start);
	if (end < start) {
		R_LOG_DEBUG ("end < start");
		return;
	}
	iend = end - start;
	if (iend < 1) {
		return;
	}
	if (iend > r_config_get_i (core->config, "emu.maxsize")) {
		char *s = r_num_units (NULL, 0, iend);
		R_LOG_WARN ("Not going to analyze %s bytes. See 'e emu.maxsize'", s);
		free (s);
		return;
	}
	ut8 *buf = NULL;
	// maybe r_core_call (core, "aeim");
	const char *kspname = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_SP);
	if (R_STR_ISEMPTY (kspname)) {
		R_LOG_ERROR ("No =SP defined in the reg profile");
		return;
	}
	char *spname = strdup (kspname);
	EsilBreakCtx ctx = {
		.op = &op,
		.anal = core->anal,
		.fcn = fcn,
		.spname = spname,
		.initial_sp = r_reg_getv (core->anal->reg, spname),
		.last_read = UT64_MAX,
		.last_data = UT64_MAX,
		.ntarget = ntarget,
		.clob.enabled = r_config_get_b (core->config, "anal.vars.clobber"),
	};
	RVecEsilRegTaint_init (&ctx.clob.reg_taints);
	if (ctx.clob.enabled) {
		esil_reg_pc_span (core->anal, &ctx.clob.pc_span);
		ESIL->cb.hook_reg_read = &esilbreak_reg_read;
	}
	ESIL->cb.hook_reg_write = &esilbreak_reg_write;
	//this is necessary for the hook to read the id of analop
	ESIL->user = &ctx;
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	ESIL->cb.hook_mem_write = &esilbreak_mem_write;
	// r_core_cmd0 (core, "e io.cache=true;wc++");

	if (fcn && fcn->reg_save_area) {
		ut64 v = newstack?  fcn->reg_save_area: ctx.initial_sp - fcn->reg_save_area;
		r_reg_setv (core->anal->reg, ctx.spname, v);
	}
	//eprintf ("Analyzing ESIL refs from 0x%"PFMT64x" - 0x%"PFMT64x"\n", addr, end);
	// TODO: backup/restore register state before/after analysis
	core->esil_anal_stop = false;
	r_cons_break_push (core->cons, cccb, core);

	int arch = -1;
	if (!strcmp (core->anal->config->arch, "arm")) {
		switch (core->anal->config->bits) {
		case 64: arch = R2_ARCH_ARM64; break;
		case 32: arch = R2_ARCH_ARM32; break;
		case 16: arch = R2_ARCH_THUMB; break;
		}
		archIsArm = true;
	}

	const ut64 gp = r_config_get_i (core->config, "anal.gp");
	const char *gp_reg = NULL;
	if (!strcmp (core->anal->config->arch, "mips")) {
		gp_reg = "gp";
		arch = R2_ARCH_MIPS;
	} else if (arch == R2_ARCH_ARM64) {
		RBinInfo *info = r_bin_get_info (core->bin);
		if (info && info->lang && !strcmp (info->lang, "dart")) {
			gp_reg = "x27";
		}
	}
	const bool archIsMips32 = (core->anal->config->bits == 32 && arch == R2_ARCH_MIPS);
	const bool is_thumb = arch == R2_ARCH_THUMB;
	bool needOpVals = false;
	if (archIsMips32 || archIsArm) {
		needOpVals = true;
	}

	r_reg_arena_push (core->anal->reg);
	char *sn = (char *)r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_SN);
	if (sn) {
		sn = strdup (sn);
	} else {
		R_LOG_WARN ("No SN reg alias for '%s'", r_config_get (core->config, "asm.arch"));
	}
	// Use linear iteration (NULL fcn) instead of graph traversal to ensure all instructions are analyzed
	IterCtx ictx = { start, end, NULL, NULL };
	size_t i = 0; // addr - start;
	size_t i_old = 0;
	size_t buf_size = 128 * 1024; // 512KB
	const size_t maxopsz = r_arch_info (core->anal->arch, R_ARCH_INFO_MAXOP_SIZE);
	ut64 buf_addr = start;
	buf = malloc (buf_size);
	if (!buf) {
		free (sn);
		esilbreak_ctx_fini (ESIL, &ctx);
		r_cons_break_pop (core->cons);
		r_reg_arena_pop (core->anal->reg);
		return;
	}
	size_t buf_i = 0;

	int opflags = R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT;
	if (needOpVals) {
		opflags |= R_ARCH_OP_MASK_VAL;
	}
	opflags |= R_ARCH_OP_MASK_DISASM;

	do {
		if (core->esil_anal_stop || r_cons_is_breaked (core->cons)) {
			break;
		}
		buf_i = pulldata (core,
				buf, buf_size,
				start, end, i,
				&buf_addr, buf_i);
		// rename cur to opaddr?
		ut64 cur = start + i;
		if (!r_io_is_valid_offset (core->io, cur, 0)) {
			break;
		}
		/* realign address if needed */
		r_core_seek_arch_bits (core, cur);
		int opalign = core->anal->config->codealign;
		if (opalign > 0) {
			cur -= (cur % opalign);
		}
		i_old = i;
		if (i >= iend) {
			goto repeat;
		}
		if (buf_i >= buf_size) {
			break;
		}
		size_t opsz = R_MIN (buf_size - buf_i, maxopsz);
		if (!r_anal_op (core->anal, &op, cur, buf + buf_i, opsz, opflags)) {
			i += minopsize - 1;
			goto repeat;
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_ILL:
		case R_ANAL_OP_TYPE_UNK:
		case R_ANAL_OP_TYPE_NULL:
			if (is_thumb) {
				R_LOG_DEBUG ("thumb unaligned or invalid instructions at 0x%08"PFMT64x, cur);
				i++; // codelalign is not always the best option to catch unaligned instructions
				goto repeat;
			} else {
				R_LOG_DEBUG ("invalid instructions at 0x%08"PFMT64x, cur);
			}
			break;
		}
		// we need to check again i because buf+i may goes beyond its boundaries
		// because of i += minopsize - 1
		if (op.size < 1) {
			i += minopsize - 1;
			goto repeat;
		}
		clob_op_begin (&ctx, &op, cur);
		// TODO: rename emu.lazy to emu.slow ? or just reuse anal.slow
		if (emu_lazy) {
			if (op.type & R_ANAL_OP_TYPE_REP) {
				i += op.size - 1;
				goto repeat;
			}
			switch (op.type & R_ANAL_OP_TYPE_MASK) {
			case R_ANAL_OP_TYPE_CALL:
				clob_op_end (&ctx, &op);
				i += op.size - 1;
				goto repeat;
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_RET:
			case R_ANAL_OP_TYPE_ILL:
			case R_ANAL_OP_TYPE_NOP:
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_IO:
			case R_ANAL_OP_TYPE_LEAVE:
			case R_ANAL_OP_TYPE_CRYPTO:
			case R_ANAL_OP_TYPE_CPL:
			case R_ANAL_OP_TYPE_SYNC:
			case R_ANAL_OP_TYPE_SWI:
			case R_ANAL_OP_TYPE_CMP:
			case R_ANAL_OP_TYPE_ACMP:
			case R_ANAL_OP_TYPE_NULL:
			case R_ANAL_OP_TYPE_CSWI:
			case R_ANAL_OP_TYPE_TRAP:
			case R_ANAL_OP_TYPE_PUSH:
			case R_ANAL_OP_TYPE_POP:
				i += op.size - 1;
				goto repeat;
			}
		}
		if (sn && op.type == R_ANAL_OP_TYPE_SWI) {
			// check if aligned
			// check if conditional (done by R_ANAL_OP_MASK_COND) CSWI exists but its not used properly on arm16
			r_strf_buffer (64);
			int snv = (arch == R2_ARCH_THUMB)? op.val: (int)r_reg_getv (core->anal->reg, sn);
			if (snv > 0 && snv < 0xFFFF) {
				r_flag_space_set (core->flags, R_FLAGS_FS_SYSCALLS);
				RSyscallItem *si = r_syscall_get (core->anal->syscall, snv, -1);
				if (si) {
					r_flag_set_next (core->flags, r_strf ("syscall.%s", si->name), cur, 1);
					r_syscall_item_free (si);
				} else {
					r_flag_set_next (core->flags, r_strf ("syscall.%d", snv), cur, 1);
				}
				r_flag_space_set (core->flags, NULL);
			}
		}
		const char *esilstr = R_STRBUF_SAFEGET (&op.esil);
		i += op.size - 1;
		if (R_STR_ISEMPTY (esilstr)) {
			goto repeat;
		}
		r_esil_set_pc (ESIL, cur);
		// R2_590 - if roregs is set we dont need to set that value everytime
		r_reg_setv (core->anal->reg, "PC", cur + op.size);
		if (gp_fixed && gp_reg) {
			r_reg_setv (core->anal->reg, gp_reg, gp);
		}
		(void)r_esil_parse (ESIL, esilstr);
		const bool skip_ref = clob_op_end (&ctx, &op);
		if (skip_ref && esilbreak_skip_ref_op (op.type)) {
			r_esil_stack_free (ESIL);
			goto repeat;
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_LEA:
			// arm64
			if (cur && arch == R2_ARCH_ARM64) {
				if (CHECKREF (ESIL->cur)) {
					int type = core_type_by_addr (core, ESIL->cur);
					if (type == R_ANAL_REF_TYPE_NULL) {
						type = R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ;
					} else if (type == R_ANAL_REF_TYPE_ICOD) {
						type |= R_ANAL_REF_TYPE_EXEC;
					} else {
						type |= R_ANAL_REF_TYPE_READ;
					}
					r_anal_xrefs_setf (core->anal, fcn, cur, ESIL->cur, type);
				}
			} else if (archIsX86) {
				const ut64 dst = op.ptr? op.ptr: ESIL->cur;
				if ((target && dst == ctx.ntarget) || !target) {
					if (CHECKREF (dst)) {
						if (dst && r_io_is_valid_offset (core->io, dst, !core->anal->opt.noncode)) {
							r_anal_xrefs_setf (core->anal, fcn, cur, dst, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
						} else {
							r_anal_xrefs_setf (core->anal, fcn, cur, ESIL->cur, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
						}
					}
				}
			} else if ((target && op.ptr == ctx.ntarget) || !target) {
				if (CHECKREF (ESIL->cur)) {
					if (op.ptr && r_io_is_valid_offset (core->io, op.ptr, !core->anal->opt.noncode)) {
						r_anal_xrefs_setf (core->anal, fcn, cur, op.ptr, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
					} else {
						r_anal_xrefs_setf (core->anal, fcn, cur, ESIL->cur, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
					}
				}
			}
			if (cfg_anal_strings) {
				add_string_ref (core, op.addr, op.ptr);
			}
			break;
		case R_ANAL_OP_TYPE_SUB:
			if (newstack && core->anal->cur && archIsArm) {
				if (strstr (op.mnemonic, " sp,")) {
					ctx.initial_sp -= op.val;
				}
			}
			break;
		case R_ANAL_OP_TYPE_ADD:
			/* TODO: test if this is valid for other archs too */
			if (archIsArm) {
				/* This code is known to work on Thumb, ARM and ARM64 */
				ut64 dst = ESIL->cur;
				if ((target && dst == ctx.ntarget) || !target) {
					if (CHECKREF (dst)) {
						const int type = core_type_by_addr (core, dst);
						RAnalRefType ref_type = (type == -1)? R_ANAL_REF_TYPE_CODE : type;
						ref_type |= R_ANAL_REF_TYPE_READ; // maybe ICOD instead of CODE
						r_anal_xrefs_setf (core->anal, fcn, cur, dst, ref_type);
					}
				}
				if (cfg_anal_strings) {
					add_string_ref (core, op.addr, dst);
				}
			} else if (archIsMips32) {
				if (!needOpVals) {
					R_LOG_ERROR ("Inconsistent needvals state");
					break;
				}
				ut64 dst = ESIL->cur;
				RAnalValue *opsrc0 = RVecRArchValue_at (&op.srcs, 0);
				RAnalValue *opsrc1 = RVecRArchValue_at (&op.srcs, 1);
				if (!opsrc0 || !opsrc0->reg) {
					break;
				}
				if (!strcmp (opsrc0->reg, "sp")) {
					break;
				}
				if (!strcmp (opsrc0->reg, "zero")) {
					break;
				}
				if ((target && dst == ctx.ntarget) || !target) {
					if (dst > 0xffff && opsrc1 && (dst & 0xffff) == (opsrc1->imm & 0xffff) && myvalid (core, dst)) {
						RFlagItem *f;
						char str[STRSZ] = {0};
						if (CHECKREF (dst) || CHECKREF (cur)) {
							r_anal_xrefs_setf (core->anal, fcn, cur, dst, R_ANAL_REF_TYPE_DATA);
							if (cfg_anal_strings) {
								add_string_ref (core, op.addr, dst);
							}
							if ((f = r_core_flag_get_by_spaces (core->flags, false, dst))) {
								r_meta_set_string (core->anal, R_META_TYPE_COMMENT, cur, f->name);
						} else if (is_string_at (core, dst, str, NULL)) {
							char *str2 = r_str_newf ("esilref: '%s'", str);
								// HACK avoid format string inside string used later as format
								// string crashes disasm inside agf under some conditions.
								// https://github.com/radareorg/radare2/issues/6937
								r_str_replace_char (str2, '%', '&');
								r_meta_set_string (core->anal, R_META_TYPE_COMMENT, cur, str2);
								free (str2);
							}
						}
					}
				}
			}
			break;
		case R_ANAL_OP_TYPE_LOAD:
			{
				ut64 dst = ctx.last_read;
				if (dst != UT64_MAX && CHECKREF (dst)) {
					if (myvalid (core, dst)) {
						r_anal_xrefs_setf (core->anal, fcn, cur, dst, R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ);
						if (cfg_anal_strings) {
							add_string_ref (core, op.addr, dst);
						}
					}
				}
				dst = ctx.last_data;
				if (dst != UT64_MAX && CHECKREF (dst)) {
					if (myvalid (core, dst)) {
						r_anal_xrefs_setf (core->anal, fcn, cur, dst, R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ);
						if (cfg_anal_strings) {
							add_string_ref (core, op.addr, dst);
						}
					}
				}
			}
			break;
		case R_ANAL_OP_TYPE_JMP:
			{
				ut64 dst = op.jump;
				if (CHECKREF (dst)) {
					if (myvalid (core, dst)) {
						r_anal_xrefs_setf (core->anal, fcn, cur, dst, R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_EXEC);
					}
				}
			}
			break;
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_CCALL:
			{
				ut64 dst = op.jump;
				if (CHECKREF (dst) || (target && dst == ctx.ntarget)) {
					if (myvalid (core, dst)) {
						r_anal_xrefs_setf (core->anal, fcn, cur, dst, R_ANAL_REF_TYPE_CALL | R_ANAL_REF_TYPE_EXEC);
					}
					ESIL->old = cur + op.size;
					getpcfromstack (core, ESIL);
				}
			}
			break;
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_IRCALL:
		case R_ANAL_OP_TYPE_MJMP:
		case R_ANAL_OP_TYPE_UCCALL:
			{
				ut64 dst = core->anal->esil->jump_target;
				if (dst == 0 || dst == UT64_MAX) {
					dst = r_reg_getv (core->anal->reg, "PC");
				}
				// the type mask preserves the COND bit, strip it too so
				// conditional variants like UCCALL are handled as calls
				const int utype = op.type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_TYPE_COND;
				if (!skip_ref && CHECKREF (dst)) {
					if (myvalid (core, dst)) {
						RAnalRefType ref = utype == R_ANAL_OP_TYPE_UCALL
							? R_ANAL_REF_TYPE_CALL
							: R_ANAL_REF_TYPE_CODE;
						r_anal_xrefs_setf (core->anal, fcn, cur, dst, ref | R_ANAL_REF_TYPE_EXEC);
						if (!xrefs_only) {
							r_core_anal_fcn (core, dst, UT64_MAX, R_ANAL_REF_TYPE_NULL, 1);
						}
					}
				}
			}
			break;
		default:
			break;
		}
		r_esil_stack_free (ESIL);
repeat:
		r_anal_op_fini (&op);
		if (!r_anal_get_block_at (core->anal, cur)) {
			size_t fcn_i;
			for (fcn_i = i_old + 1; fcn_i <= i; fcn_i++) {
				if (r_anal_get_function_at (core->anal, start + fcn_i)) {
					i = fcn_i - 1;
					break;
				}
			}
		}
		if (i >= iend) {
			break;
		}
	} while (get_next_i (&ictx, &i));
	free (sn);
	r_list_free (ictx.bbl);
	r_list_free (ictx.path);
	r_list_free (ictx.switch_path);
	free (buf);
	esilbreak_ctx_fini (ESIL, &ctx);
	r_anal_op_fini (&op);
	r_cons_break_pop (core->cons);
	r_reg_arena_pop (core->anal->reg);
}

// Private helpers for /as syscall search. Included by cmd_search.inc.c.

static const char *get_syscall_register(RCore *core) {
	const char *sn = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_SN);
	RArchConfig *cfg = R_UNWRAP3 (core, anal, config);
	const char *arch = cfg? cfg->arch: NULL;
	if (arch && !strcmp (arch, "arm") && cfg->bits == 64) {
		const char *os = cfg->os;
		if (R_STR_ISEMPTY (os)) {
			os = r_config_get (core->config, "asm.os");
		}
		if (R_STR_ISEMPTY (os)) {
			return sn;
		}
		if (!strcmp (os, "linux") || !strcmp (os, "android")) {
			sn = "x8";
		} else if (!strcmp (os, "macos")) {
			sn = "x16";
		}
	}
	return sn;
}

typedef enum {
	SYSREG_VAL_UNKNOWN,
	SYSREG_VAL_CONST,
} SyscallRegValueKind;

typedef struct {
	SyscallRegValueKind kind;
	ut64 value;
} SyscallRegValue;

typedef struct {
	const char *name;
	int offset;
	int size;
} SyscallRegSlot;

R_VEC_TYPE (RVecSyscallRegSlot, SyscallRegSlot);

typedef struct {
	RReg *reg;
	RVecSyscallRegSlot slots;
} SyscallRegMap;

typedef struct {
	bool reachable;
	SyscallRegValue *regs;
	int regs_count;
} SyscallRegState;

typedef struct {
	ut64 addr;
	bool known;
	ut64 value;
} SyscallNumberHit;

R_VEC_TYPE (RVecSyscallNumberHit, SyscallNumberHit);

typedef enum {
	SYSNUM_AT_NONE,
	SYSNUM_AT_UNKNOWN,
	SYSNUM_AT_KNOWN
} SyscallNumberAt;

typedef struct {
	RAnalFunction *fcn;
	RVecSyscallNumberHit hits;
} SyscallFunctionCache;

static void syscall_function_cache_fini(SyscallFunctionCache *cache);

R_VEC_TYPE_WITH_FINI (RVecSyscallFunctionCache, SyscallFunctionCache, syscall_function_cache_fini);

typedef struct {
	RCore *core;
	RAnalFunction *fcn;
	SyscallRegMap *regmap;
	RAnalBlock **blocks;
	SyscallRegState *states;
	int blocks_count;
	RVecSyscallNumberHit *hits;
	int *queue;
	bool *queued;
	int queue_len;
} SyscallFunctionAnalysis;

static SyscallRegValue syscall_reg_unknown(void) {
	SyscallRegValue ret = { SYSREG_VAL_UNKNOWN, 0 };
	return ret;
}

static SyscallRegValue syscall_reg_const(ut64 value) {
	SyscallRegValue ret = { SYSREG_VAL_CONST, value };
	return ret;
}

static ut64 syscall_reg_mask_value(ut64 value, int bits) {
	if (bits > 0 && bits < 64) {
		return value & (((ut64)1 << bits) - 1);
	}
	return value;
}

static bool syscall_reg_overlap(int off_a, int size_a, int off_b, int size_b) {
	return off_a < off_b + size_b && off_b < off_a + size_a;
}

static void syscall_regmap_fini(SyscallRegMap *map) {
	RVecSyscallRegSlot_fini (&map->slots);
	memset (map, 0, sizeof (*map));
}

static int syscall_regmap_find_offset(SyscallRegMap *map, int offset) {
	int i;
	const int count = RVecSyscallRegSlot_length (&map->slots);
	for (i = 0; i < count; i++) {
		SyscallRegSlot *slot = RVecSyscallRegSlot_at (&map->slots, i);
		if (slot && slot->offset == offset) {
			return i;
		}
	}
	return -1;
}

static bool syscall_regmap_init(SyscallRegMap *map, RReg *reg) {
	RListIter *iter;
	RRegItem *item;

	memset (map, 0, sizeof (*map));
	map->reg = reg;
	RVecSyscallRegSlot_init (&map->slots);
	RList *regs = r_reg_get_list (reg, R_REG_TYPE_GPR);
	if (!regs) {
		return false;
	}
	r_list_foreach (regs, iter, item) {
		if (!item || !item->name || item->size < 1) {
			continue;
		}
		int idx = syscall_regmap_find_offset (map, item->offset);
		SyscallRegSlot *slot = NULL;
		if (idx < 0) {
			slot = RVecSyscallRegSlot_emplace_back (&map->slots);
			slot->offset = item->offset;
		} else {
			slot = RVecSyscallRegSlot_at (&map->slots, idx);
		}
		if (slot && item->size > slot->size) {
			slot->name = item->name;
			slot->size = item->size;
		}
	}
	if (RVecSyscallRegSlot_empty (&map->slots)) {
		syscall_regmap_fini (map);
		return false;
	}
	return true;
}

static RRegItem *syscall_reg_item(SyscallRegMap *map, const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	return r_reg_get (map->reg, name, R_REG_TYPE_GPR);
}

static int syscall_regmap_slot_for_item(SyscallRegMap *map, RRegItem *item) {
	int i;
	if (!item) {
		return -1;
	}
	const int count = RVecSyscallRegSlot_length (&map->slots);
	for (i = 0; i < count; i++) {
		SyscallRegSlot *slot = RVecSyscallRegSlot_at (&map->slots, i);
		if (slot && slot->offset == item->offset) {
			return i;
		}
	}
	return -1;
}

static int syscall_regmap_slot_containing_item(SyscallRegMap *map, RRegItem *item) {
	int i;
	if (!item) {
		return -1;
	}
	const int item_end = item->offset + item->size;
	const int count = RVecSyscallRegSlot_length (&map->slots);
	for (i = 0; i < count; i++) {
		SyscallRegSlot *slot = RVecSyscallRegSlot_at (&map->slots, i);
		if (slot && item->offset >= slot->offset && item_end <= slot->offset + slot->size) {
			return i;
		}
	}
	return -1;
}

static bool syscall_state_init(SyscallRegState *state, SyscallRegMap *map, bool reachable) {
	state->regs_count = RVecSyscallRegSlot_length (&map->slots);
	state->regs = calloc (state->regs_count, sizeof (*state->regs));
	if (!state->regs) {
		return false;
	}
	state->reachable = reachable;
	return true;
}

static void syscall_state_fini(SyscallRegState *state) {
	free (state->regs);
	memset (state, 0, sizeof (*state));
}

static void syscall_state_set_unknown(SyscallRegState *state, bool reachable) {
	int i;
	state->reachable = reachable;
	for (i = 0; i < state->regs_count; i++) {
		state->regs[i] = syscall_reg_unknown ();
	}
}

static void syscall_state_copy(SyscallRegState *dst, const SyscallRegState *src) {
	dst->reachable = src->reachable;
	memcpy (dst->regs, src->regs, sizeof (*dst->regs) * dst->regs_count);
}

static bool syscall_state_join(SyscallRegState *dst, const SyscallRegState *src) {
	bool changed = false;
	int i;

	if (!src->reachable) {
		return false;
	}
	if (!dst->reachable) {
		syscall_state_copy (dst, src);
		return true;
	}
	for (i = 0; i < dst->regs_count; i++) {
		SyscallRegValue *d = &dst->regs[i];
		const SyscallRegValue *s = &src->regs[i];
		if (d->kind == SYSREG_VAL_UNKNOWN) {
			continue;
		}
		if (s->kind == SYSREG_VAL_UNKNOWN || d->value != s->value) {
			*d = syscall_reg_unknown ();
			changed = true;
		}
	}
	return changed;
}

static void syscall_state_kill_overlapping(SyscallRegMap *map, SyscallRegState *state, RRegItem *item) {
	int i;
	if (!item) {
		return;
	}
	const int count = RVecSyscallRegSlot_length (&map->slots);
	for (i = 0; i < count; i++) {
		SyscallRegSlot *slot = RVecSyscallRegSlot_at (&map->slots, i);
		if (slot && syscall_reg_overlap (item->offset, item->size, slot->offset, slot->size)) {
			state->regs[i] = syscall_reg_unknown ();
		}
	}
}

static void syscall_state_write(SyscallRegMap *map, SyscallRegState *state, const char *reg, SyscallRegValue value) {
	RRegItem *item = syscall_reg_item (map, reg);
	int idx = syscall_regmap_slot_for_item (map, item);
	if (!item) {
		return;
	}
	if (idx < 0) {
		idx = syscall_regmap_slot_containing_item (map, item);
	}
	SyscallRegSlot *slot = idx >= 0? RVecSyscallRegSlot_at (&map->slots, idx): NULL;
	SyscallRegValue prev = slot? state->regs[idx]: syscall_reg_unknown ();
	syscall_state_kill_overlapping (map, state, item);
	if (!slot) {
		return;
	}
	if (item->size < 32) {
		// Narrow writes are constant only when the containing register was already known.
		if (value.kind != SYSREG_VAL_CONST || prev.kind != SYSREG_VAL_CONST) {
			return;
		}
		const int shift = item->offset - slot->offset;
		if (shift < 0 || shift >= 64 || item->size + shift > 64) {
			return;
		}
		ut64 mask = (((ut64)1 << item->size) - 1) << shift;
		value.value = (prev.value & ~mask) | ((value.value << shift) & mask);
		value.value = syscall_reg_mask_value (value.value, slot->size);
		state->regs[idx] = value;
		return;
	}
	if (value.kind == SYSREG_VAL_CONST) {
		value.value = syscall_reg_mask_value (value.value, item->size);
	}
	state->regs[idx] = value;
}

static SyscallRegValue syscall_state_read(SyscallRegMap *map, SyscallRegState *state, const char *reg) {
	RRegItem *item = syscall_reg_item (map, reg);
	int idx = syscall_regmap_slot_for_item (map, item);
	if (!item) {
		return syscall_reg_unknown ();
	}
	if (idx < 0) {
		idx = syscall_regmap_slot_containing_item (map, item);
	}
	SyscallRegSlot *slot = idx >= 0? RVecSyscallRegSlot_at (&map->slots, idx): NULL;
	if (!slot) {
		return syscall_reg_unknown ();
	}
	SyscallRegValue value = state->regs[idx];
	if (value.kind == SYSREG_VAL_CONST) {
		const int shift = item->offset - slot->offset;
		if (shift < 0 || shift >= 64) {
			return syscall_reg_unknown ();
		}
		value.value >>= shift;
		value.value = syscall_reg_mask_value (value.value, item->size);
		return value;
	}
	if (item->size < slot->size) {
		return syscall_reg_unknown ();
	}
	return value;
}

static bool syscall_arch_value_is_mem(RAnalValue *value) {
	return value && value->memref;
}

static bool syscall_arch_value_is_reg(RAnalValue *value) {
	return value && value->reg && !value->memref;
}

static bool syscall_op_imm(RAnalOp *op, RAnalValue *src, ut64 *value) {
	if (op->val != UT64_MAX) {
		*value = op->val;
		return true;
	}
	if (src && !src->reg && !src->regdelta && !src->memref && src->imm) {
		*value = src->imm;
		return true;
	}
	return false;
}

static bool syscall_same_reg(SyscallRegMap *map, const char *a, const char *b) {
	RRegItem *ai = syscall_reg_item (map, a);
	RRegItem *bi = syscall_reg_item (map, b);
	return ai && bi && ai->offset == bi->offset && ai->size == bi->size;
}

static bool syscall_value_from_src(SyscallRegMap *map, SyscallRegState *state, RAnalOp *op, RAnalValue *src, SyscallRegValue *value) {
	ut64 imm = 0;
	if (!src) {
		return false;
	}
	if (syscall_arch_value_is_mem (src)) {
		return false;
	}
	if (syscall_arch_value_is_reg (src)) {
		*value = syscall_state_read (map, state, src->reg);
		return value->kind == SYSREG_VAL_CONST;
	}
	if (syscall_op_imm (op, src, &imm)) {
		*value = syscall_reg_const (imm);
		return true;
	}
	return false;
}

static bool syscall_value_from_lea(SyscallRegMap *map, SyscallRegState *state, RAnalValue *src, SyscallRegValue *value) {
	ut64 acc = 0;
	SyscallRegValue part;

	if (!src) {
		return false;
	}
	if (src->reg) {
		part = syscall_state_read (map, state, src->reg);
		if (part.kind != SYSREG_VAL_CONST) {
			return false;
		}
		acc += part.value;
	}
	if (src->regdelta) {
		part = syscall_state_read (map, state, src->regdelta);
		if (part.kind != SYSREG_VAL_CONST) {
			return false;
		}
		acc += part.value * (src->mul? src->mul: 1);
	}
	acc += src->delta;
	*value = syscall_reg_const (acc);
	return true;
}

static void syscall_state_kill_all(SyscallRegState *state) {
	int i;
	for (i = 0; i < state->regs_count; i++) {
		state->regs[i] = syscall_reg_unknown ();
	}
}

static void syscall_state_kill_reg(SyscallRegMap *map, SyscallRegState *state, const char *reg) {
	syscall_state_write (map, state, reg, syscall_reg_unknown ());
}

static void syscall_state_kill_regs(SyscallRegMap *map, SyscallRegState *state, const char * const *regs) {
	int i;
	for (i = 0; regs[i]; i++) {
		syscall_state_kill_reg (map, state, regs[i]);
	}
}

static void syscall_state_kill_call(RCore *core, SyscallRegMap *map, SyscallRegState *state) {
	RArchConfig *cfg = R_UNWRAP3 (core, anal, config);
	const char *arch = cfg? cfg->arch: NULL;
	int bits = cfg? cfg->bits: 0;
	if (r_str_startswith (arch, "x86")) {
		if (bits == 64) {
			static const char * const regs[] = {
				"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", NULL
			};
			syscall_state_kill_regs (map, state, regs);
		} else {
			static const char * const regs[] = { "eax", "ecx", "edx", NULL };
			syscall_state_kill_regs (map, state, regs);
		}
		return;
	}
	if (r_str_startswith (arch, "arm") || r_str_startswith (arch, "aarch64")) {
		if (bits == 64) {
			static const char * const regs[] = {
				"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
				"x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18",
				"x30", "lr", NULL
			};
			syscall_state_kill_regs (map, state, regs);
		} else {
			static const char * const regs[] = { "r0", "r1", "r2", "r3", "r12", "lr", NULL };
			syscall_state_kill_regs (map, state, regs);
		}
		return;
	}
	if (r_str_startswith (arch, "mips")) {
		static const char * const regs[] = {
			"v0", "v1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
			"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "ra", NULL
		};
		syscall_state_kill_regs (map, state, regs);
		return;
	}
	if (r_str_startswith (arch, "riscv")) {
		static const char * const regs[] = {
			"ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
			"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", NULL
		};
		syscall_state_kill_regs (map, state, regs);
		return;
	}
	syscall_state_kill_all (state);
}

static void syscall_transfer_binary(SyscallRegMap *map, SyscallRegState *state, RAnalOp *op, int type) {
	RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
	RAnalValue *src = RVecRArchValue_at (&op->srcs, 0);
	SyscallRegValue lhs;
	SyscallRegValue rhs;
	ut64 imm = 0;

	if (!dst || !dst->reg || dst->memref) {
		return;
	}
	lhs = syscall_state_read (map, state, dst->reg);
	if (src && syscall_arch_value_is_reg (src)) {
		rhs = syscall_state_read (map, state, src->reg);
	} else if (syscall_op_imm (op, src, &imm)) {
		rhs = syscall_reg_const (imm);
	} else {
		syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
		return;
	}
	if (lhs.kind != SYSREG_VAL_CONST || rhs.kind != SYSREG_VAL_CONST) {
		syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
		return;
	}
	switch (type) {
	case R_ANAL_OP_TYPE_ADD:
		lhs.value += rhs.value;
		break;
	case R_ANAL_OP_TYPE_SUB:
		lhs.value -= rhs.value;
		break;
	case R_ANAL_OP_TYPE_AND:
		lhs.value &= rhs.value;
		break;
	case R_ANAL_OP_TYPE_OR:
		lhs.value |= rhs.value;
		break;
	case R_ANAL_OP_TYPE_XOR:
		lhs.value ^= rhs.value;
		break;
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SAL:
		if (rhs.value >= 64) {
			syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
			return;
		}
		lhs.value <<= rhs.value;
		break;
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SAR:
		if (rhs.value >= 64) {
			syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
			return;
		}
		lhs.value >>= rhs.value;
		break;
	default:
		syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
		return;
	}
	syscall_state_write (map, state, dst->reg, lhs);
}

static void syscall_transfer_op(RCore *core, SyscallRegMap *map, SyscallRegState *state, RAnalOp *op, const char *screg) {
	RAnalValue *dst, *src;
	SyscallRegValue value;
	int type;

	if (!state->reachable) {
		return;
	}
	type = op->type & R_ANAL_OP_TYPE_MASK;
	dst = RVecRArchValue_at (&op->dsts, 0);
	src = RVecRArchValue_at (&op->srcs, 0);
	switch (type) {
	case R_ANAL_OP_TYPE_MOV:
		if (dst && dst->reg && !dst->memref) {
			value = syscall_reg_unknown ();
			if (syscall_value_from_src (map, state, op, src, &value)) {
				syscall_state_write (map, state, dst->reg, value);
			} else {
				syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
			}
		}
		break;
	case R_ANAL_OP_TYPE_CMOV:
		if (dst && dst->reg && !dst->memref) {
			SyscallRegValue cur = syscall_state_read (map, state, dst->reg);
			if (!syscall_value_from_src (map, state, op, src, &value)
					|| cur.kind != SYSREG_VAL_CONST || value.value != cur.value) {
				value = syscall_reg_unknown ();
			}
			syscall_state_write (map, state, dst->reg, value);
		}
		break;
	case R_ANAL_OP_TYPE_LEA:
		if (dst && dst->reg && !dst->memref) {
			if (syscall_value_from_lea (map, state, src, &value)) {
				syscall_state_write (map, state, dst->reg, value);
			} else {
				syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
			}
		}
		break;
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_SUB:
		if (dst && src && dst->reg && src->reg && !dst->memref && !src->memref
				&& syscall_same_reg (map, dst->reg, src->reg)) {
			syscall_state_write (map, state, dst->reg, syscall_reg_const (0));
		} else {
			syscall_transfer_binary (map, state, op, type);
		}
		break;
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
		syscall_transfer_binary (map, state, op, type);
		break;
	case R_ANAL_OP_TYPE_SWI:
		syscall_state_write (map, state, screg, syscall_reg_unknown ());
		if (dst && dst->reg && !dst->memref) {
			syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
		}
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_UCALL:
		syscall_state_kill_call (core, map, state);
		break;
	case R_ANAL_OP_TYPE_POP:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_XCHG:
		if (dst && dst->reg && !dst->memref) {
			syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
		}
		if (src && src->reg && !src->memref) {
			syscall_state_write (map, state, src->reg, syscall_reg_unknown ());
		}
		break;
	default:
		if (dst && dst->reg && !dst->memref && type != R_ANAL_OP_TYPE_CMP && type != R_ANAL_OP_TYPE_ACMP) {
			syscall_state_write (map, state, dst->reg, syscall_reg_unknown ());
		}
		break;
	}
}

static bool syscall_record_hit(RVecSyscallNumberHit *hits, ut64 addr, SyscallRegValue value) {
	SyscallNumberHit *hit;
	R_VEC_FOREACH (hits, hit) {
		if (hit->addr == addr) {
			if (!hit->known || value.kind != SYSREG_VAL_CONST || hit->value != value.value) {
				hit->known = false;
			}
			return true;
		}
	}
	hit = RVecSyscallNumberHit_emplace_back (hits);
	hit->addr = addr;
	if (value.kind == SYSREG_VAL_CONST) {
		hit->known = true;
		hit->value = value.value;
	}
	return true;
}

static int syscall_block_index(SyscallFunctionAnalysis *analysis, RAnalBlock *bb) {
	int i;
	for (i = 0; i < analysis->blocks_count; i++) {
		if (analysis->blocks[i] == bb) {
			return i;
		}
	}
	return -1;
}

static int syscall_block_index_at(SyscallFunctionAnalysis *analysis, ut64 addr) {
	RAnalBlock *bb = r_anal_function_bbget_at (analysis->core->anal, analysis->fcn, addr);
	if (!bb) {
		bb = r_anal_function_bbget_in (analysis->core->anal, analysis->fcn, addr);
	}
	return syscall_block_index (analysis, bb);
}

static void syscall_queue_block(SyscallFunctionAnalysis *analysis, int idx) {
	if (idx < 0 || idx >= analysis->blocks_count || analysis->queued[idx]) {
		return;
	}
	analysis->queue[analysis->queue_len++] = idx;
	analysis->queued[idx] = true;
}

typedef struct {
	SyscallFunctionAnalysis *analysis;
	SyscallRegState *state;
} SyscallSuccessorCtx;

static bool syscall_successor_cb(ut64 addr, void *user) {
	SyscallSuccessorCtx *ctx = (SyscallSuccessorCtx *)user;
	int idx = syscall_block_index_at (ctx->analysis, addr);
	if (idx >= 0 && syscall_state_join (&ctx->analysis->states[idx], ctx->state)) {
		syscall_queue_block (ctx->analysis, idx);
	}
	return true;
}

static bool syscall_analyze_block(SyscallFunctionAnalysis *analysis, int idx, const char *screg) {
	RAnalBlock *bb = analysis->blocks[idx];
	SyscallRegState out;
	ut8 *buf;
	RAnalOp op = {0};
	int i;

	if (!syscall_state_init (&out, analysis->regmap, false)) {
		return false;
	}
	syscall_state_copy (&out, &analysis->states[idx]);
	if (bb->size < 1 || bb->size > ST32_MAX) {
		syscall_state_fini (&out);
		return true;
	}
	buf = malloc (bb->size);
	if (!buf) {
		syscall_state_fini (&out);
		return false;
	}
	r_io_read_at (analysis->core->io, bb->addr, buf, bb->size);
	for (i = 0; i < bb->ninstr; i++) {
		ut16 pos = r_anal_bb_offset_inst (bb, i);
		ut64 op_addr = r_anal_bb_opaddr_i (bb, i);
		int ret;
		if (pos == UT16_MAX || op_addr == UT64_MAX || pos >= bb->size) {
			break;
		}
		ret = r_anal_op (analysis->core->anal, &op, op_addr, buf + pos, bb->size - pos,
			R_ARCH_OP_MASK_VAL);
		if (ret > 0) {
			int type = op.type & R_ANAL_OP_TYPE_MASK;
			if (type == R_ANAL_OP_TYPE_SWI) {
				if (!syscall_record_hit (analysis->hits, op_addr,
						syscall_state_read (analysis->regmap, &out, screg))) {
					r_anal_op_fini (&op);
					free (buf);
					syscall_state_fini (&out);
					return false;
				}
			}
			syscall_transfer_op (analysis->core, analysis->regmap, &out, &op, screg);
		}
		r_anal_op_fini (&op);
	}
	SyscallSuccessorCtx sctx = { analysis, &out };
	r_anal_block_successor_addrs_foreach (bb, syscall_successor_cb, &sctx);
	free (buf);
	syscall_state_fini (&out);
	return true;
}

static void syscall_function_cache_fini(SyscallFunctionCache *cache) {
	if (cache) {
		RVecSyscallNumberHit_fini (&cache->hits);
		memset (cache, 0, sizeof (*cache));
	}
}

static bool syscall_function_cache_init(SyscallFunctionCache *cache, RCore *core, SyscallRegMap *regmap, RAnalFunction *fcn, const char *screg) {
	SyscallFunctionAnalysis analysis = {0};
	RListIter *iter;
	RAnalBlock *bb;
	int entry_idx = -1;
	int i;

	R_RETURN_VAL_IF_FAIL (cache && core && regmap && fcn && fcn->bbs, false);
	if (r_list_empty (fcn->bbs)) {
		return false;
	}
	memset (cache, 0, sizeof (*cache));
	cache->fcn = fcn;
	RVecSyscallNumberHit_init (&cache->hits);
	analysis.core = core;
	analysis.fcn = fcn;
	analysis.regmap = regmap;
	analysis.blocks_count = r_list_length (fcn->bbs);
	analysis.hits = &cache->hits;
	analysis.blocks = calloc (analysis.blocks_count, sizeof (*analysis.blocks));
	analysis.states = calloc (analysis.blocks_count, sizeof (*analysis.states));
	analysis.queue = calloc (analysis.blocks_count, sizeof (*analysis.queue));
	analysis.queued = calloc (analysis.blocks_count, sizeof (*analysis.queued));
	if (!analysis.blocks || !analysis.states || !analysis.queue || !analysis.queued) {
		goto fail;
	}
	i = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		analysis.blocks[i] = bb;
		if (!syscall_state_init (&analysis.states[i], regmap, false)) {
			goto fail;
		}
		if (r_anal_block_contains (bb, fcn->addr)) {
			entry_idx = i;
		}
		i++;
	}
	if (entry_idx < 0) {
		entry_idx = syscall_block_index_at (&analysis, fcn->addr);
	}
	if (entry_idx < 0) {
		entry_idx = 0;
	}
	syscall_state_set_unknown (&analysis.states[entry_idx], true);
	syscall_queue_block (&analysis, entry_idx);
	while (analysis.queue_len > 0) {
		int idx = analysis.queue[--analysis.queue_len];
		analysis.queued[idx] = false;
		if (!syscall_analyze_block (&analysis, idx, screg)) {
			goto fail;
		}
	}
	for (i = 0; i < analysis.blocks_count; i++) {
		syscall_state_fini (&analysis.states[i]);
	}
	free (analysis.blocks);
	free (analysis.states);
	free (analysis.queue);
	free (analysis.queued);
	return true;
fail:
	if (analysis.states) {
		for (i = 0; i < analysis.blocks_count; i++) {
			syscall_state_fini (&analysis.states[i]);
		}
	}
	free (analysis.blocks);
	free (analysis.states);
	free (analysis.queue);
	free (analysis.queued);
	syscall_function_cache_fini (cache);
	return false;
}

static SyscallFunctionCache *syscall_function_cache_find(RVecSyscallFunctionCache *caches, RAnalFunction *fcn) {
	SyscallFunctionCache *cache;
	R_VEC_FOREACH (caches, cache) {
		if (cache->fcn == fcn) {
			return cache;
		}
	}
	return NULL;
}

static SyscallNumberAt syscall_function_number_at(RCore *core, SyscallRegMap *regmap, RVecSyscallFunctionCache *caches, RAnalFunction *fcn, const char *screg, ut64 at, int *num) {
	SyscallFunctionCache *cache = syscall_function_cache_find (caches, fcn);
	SyscallNumberHit *hit;
	if (!cache) {
		SyscallFunctionCache tmp;
		if (!syscall_function_cache_init (&tmp, core, regmap, fcn, screg)) {
			return SYSNUM_AT_NONE;
		}
		cache = RVecSyscallFunctionCache_emplace_back (caches);
		*cache = tmp;
	}
	R_VEC_FOREACH (&cache->hits, hit) {
		if (hit->addr == at) {
			if (hit->known && hit->value <= 0xFFFFF) {
				*num = (int)hit->value;
				return SYSNUM_AT_KNOWN;
			}
			return SYSNUM_AT_UNKNOWN;
		}
	}
	return SYSNUM_AT_NONE;
}

static RAnalFunction *syscall_function_covered_at(RCore *core, ut64 at, ut64 *covered_until) {
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, at);
	if (!bb || !bb->fcns || r_list_empty (bb->fcns)) {
		*covered_until = 0;
		return NULL;
	}
	if (bb->size > UT64_MAX - bb->addr) {
		*covered_until = UT64_MAX;
	} else {
		*covered_until = bb->addr + bb->size;
	}
	if (*covered_until <= at) {
		*covered_until = at + 1;
	}
	return r_list_first (bb->fcns);
}

typedef enum {
	SYSCALL_SEARCH_UNSUPPORTED,
	SYSCALL_SEARCH_X86,
	SYSCALL_SEARCH_ARM64,
	SYSCALL_SEARCH_ARM32,
	SYSCALL_SEARCH_THUMB
} SyscallSearchKind;

static int syscall_addr_cmp(const ut64 *a, const ut64 *b) {
	return (*a > *b)? 1: (*a < *b)? -1: 0;
}

static bool syscall_candidate_aligned(ut64 addr, int natural_align, int search_align) {
	if (natural_align > 1 && (addr % natural_align)) {
		return false;
	}
	return search_align <= 1 || !(addr % search_align);
}

static bool syscall_candidate_add(RVecSearchAddr *candidates, ut64 addr) {
	ut64 *slot = RVecSearchAddr_emplace_back (candidates);
	if (!slot) {
		return false;
	}
	*slot = addr;
	return true;
}

static SyscallSearchKind syscall_search_kind(RCore *core) {
	RArchConfig *cfg = R_UNWRAP3 (core, anal, config);
	const char *arch = cfg? cfg->arch: NULL;
	if (r_str_startswith (arch, "x86")) {
		return SYSCALL_SEARCH_X86;
	}
	if (arch && !strcmp (arch, "arm")) {
		if (cfg->bits == 64) {
			return SYSCALL_SEARCH_ARM64;
		}
		if (cfg->bits == 16) {
			return SYSCALL_SEARCH_THUMB;
		}
		if (cfg->bits == 32) {
			return SYSCALL_SEARCH_ARM32;
		}
	}
	return SYSCALL_SEARCH_UNSUPPORTED;
}

static bool syscall_x86_prefix_byte(ut8 b, int bits) {
	if (b == 0xf0 || b == 0xf2 || b == 0xf3 || b == 0x2e || b == 0x36 || b == 0x3e
			|| b == 0x26 || b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67) {
		return true;
	}
	return bits == 64 && b >= 0x40 && b <= 0x4f;
}

static int syscall_x86_prefix_len(const ut8 *buf, int len, int bits) {
	int i = 0;
	while (i < len && i < 14 && syscall_x86_prefix_byte (buf[i], bits)) {
		i++;
	}
	return i;
}

static int syscall_first_aligned_offset(ut64 base, int align) {
	int rem = base % align;
	return rem? align - rem: 0;
}

static bool syscall_collect_x86(RVecSearchAddr *candidates, ut64 base, const ut8 *buf, int scan_len, int read_len, int search_align, int bits) {
	int i;
	for (i = 0; i < scan_len; i++) {
		ut64 addr = base + i;
		if (!syscall_candidate_aligned (addr, 1, search_align)) {
			continue;
		}
		if (i + 1 < read_len && buf[i] == 0x0f && (buf[i + 1] == 0x05 || buf[i + 1] == 0x34)) {
			if (!syscall_candidate_add (candidates, addr)) {
				return false;
			}
		}
		if (i + 1 < read_len && buf[i] == 0xcd) {
			if (!syscall_candidate_add (candidates, addr)) {
				return false;
			}
		}
		if (buf[i] == 0xf1 || buf[i] == 0xce) {
			if (!syscall_candidate_add (candidates, addr)) {
				return false;
			}
		}
		int prefix_len = syscall_x86_prefix_len (buf + i, read_len - i, bits);
		if (prefix_len > 0 && i + prefix_len + 1 < read_len
				&& buf[i + prefix_len] == 0x0f
				&& (buf[i + prefix_len + 1] == 0x05 || buf[i + prefix_len + 1] == 0x34)) {
			if (!syscall_candidate_add (candidates, addr)) {
				return false;
			}
		}
	}
	return true;
}

static bool syscall_collect_arm64(RVecSearchAddr *candidates, ut64 base, const ut8 *buf, int scan_len, int read_len, int search_align, bool be) {
	int i = syscall_first_aligned_offset (base, 4);
	for (; i < scan_len && i + 4 <= read_len; i += 4) {
		ut64 addr = base + i;
		if (!syscall_candidate_aligned (addr, 4, search_align)) {
			continue;
		}
		ut32 word = be? r_read_be32 (buf + i): r_read_le32 (buf + i);
		if ((word & 0xffe0001f) == 0xd4000001) {
			if (!syscall_candidate_add (candidates, addr)) {
				return false;
			}
		}
	}
	return true;
}

static bool syscall_collect_arm32(RVecSearchAddr *candidates, ut64 base, const ut8 *buf, int scan_len, int read_len, int search_align, bool be) {
	int i = syscall_first_aligned_offset (base, 4);
	for (; i < scan_len && i + 4 <= read_len; i += 4) {
		ut64 addr = base + i;
		if (!syscall_candidate_aligned (addr, 4, search_align)) {
			continue;
		}
		ut32 word = be? r_read_be32 (buf + i): r_read_le32 (buf + i);
		if ((word & 0x0f000000) == 0x0f000000) {
			if (!syscall_candidate_add (candidates, addr)) {
				return false;
			}
		}
	}
	return true;
}

static bool syscall_collect_thumb(RVecSearchAddr *candidates, ut64 base, const ut8 *buf, int scan_len, int read_len, int search_align, bool be) {
	int i = syscall_first_aligned_offset (base, 2);
	for (; i < scan_len && i + 2 <= read_len; i += 2) {
		ut64 addr = base + i;
		if (!syscall_candidate_aligned (addr, 2, search_align)) {
			continue;
		}
		ut16 word = be? r_read_be16 (buf + i): r_read_le16 (buf + i);
		if ((word & 0xff00) == 0xdf00) {
			if (!syscall_candidate_add (candidates, addr)) {
				return false;
			}
		}
	}
	return true;
}

static bool syscall_collect_candidates(RCore *core, RVecSearchAddr *candidates, SyscallSearchKind kind, ut64 from, ut64 to, int search_align) {
	RArchConfig *cfg = R_UNWRAP3 (core, anal, config);
	const bool be = cfg && R_ARCH_CONFIG_IS_BIG_ENDIAN (cfg);
	const int bits = cfg? cfg->bits: 0;
	const int bsize = R_MAX (4096, core->blocksize);
	const int lookahead = kind == SYSCALL_SEARCH_X86? 16: 4;
	ut8 *buf = malloc ((size_t)bsize + lookahead);
	ut64 at = from;

	if (!buf) {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", bsize + lookahead);
		return false;
	}
	while (at < to) {
		ut64 left = to - at;
		int scan_len = (int)R_MIN ((ut64)bsize, left);
		int read_len = (int)R_MIN ((ut64)bsize + lookahead, left);
		bool ok = false;
		r_io_read_at (core->io, at, buf, read_len);
		switch (kind) {
		case SYSCALL_SEARCH_X86:
			ok = syscall_collect_x86 (candidates, at, buf, scan_len, read_len, search_align, bits);
			break;
		case SYSCALL_SEARCH_ARM64:
			ok = syscall_collect_arm64 (candidates, at, buf, scan_len, read_len, search_align, be);
			break;
		case SYSCALL_SEARCH_ARM32:
			ok = syscall_collect_arm32 (candidates, at, buf, scan_len, read_len, search_align, be);
			break;
		case SYSCALL_SEARCH_THUMB:
			ok = syscall_collect_thumb (candidates, at, buf, scan_len, read_len, search_align, be);
			break;
		default:
			ok = false;
			break;
		}
		if (!ok) {
			free (buf);
			return false;
		}
		at += scan_len;
	}
	free (buf);
	RVecSearchAddr_sort (candidates, syscall_addr_cmp);
	RVecSearchAddr_uniq (candidates, syscall_addr_cmp);
	return true;
}

static int syscall_read_op(RCore *core, ut64 at, ut64 to, ut8 *buf, int buflen) {
	if (at >= to) {
		return 0;
	}
	int len = (int)R_MIN ((ut64)buflen, to - at);
	r_io_read_at (core->io, at, buf, len);
	return len;
}

static bool syscall_handle_hit(RCore *core, struct search_parameters *param, SyscallRegMap *regmap, RVecSyscallFunctionCache *fcn_cache, const char *screg, RAnalOp *op, int oplen, int kwidx, int *count, bool isx86, RAnalFunction *fcn, SyscallRegValue fallback, bool have_fallback) {
	int scVector = op->val; // int 0x80, svc 0x70, ...
	int scNumber = -1; // r0/eax/...
	SyscallNumberAt fcn_num = SYSNUM_AT_NONE;
	if (fcn) {
		fcn_num = syscall_function_number_at (core, regmap, fcn_cache, fcn, screg, op->addr, &scNumber);
	}
	if (fcn && fcn_num == SYSNUM_AT_NONE) {
		return true;
	}
	if (fcn_num == SYSNUM_AT_NONE && have_fallback) {
		scNumber = (fallback.kind == SYSREG_VAL_CONST && fallback.value <= 0xFFFFF)
			? (int)fallback.value: -1;
	}
	if (isx86 && op->val == 0 && op->bytes && (op->bytes[0] == 0xcd || op->bytes[0] == 0x64)) {
		return true;
	}
	if (scNumber < 0 || scNumber > 0xFFFFF) {
		if (isx86 && fcn_num == SYSNUM_AT_UNKNOWN) {
			return true;
		}
		scNumber = op->val;
		if (scNumber < 0 || scNumber > 0xFFFFF) {
			R_LOG_DEBUG ("Invalid syscall number %d at 0x%08"PFMT64x, scNumber, op->addr);
			return true;
		}
	}
	scVector = (op->val > 0)? op->val: -1; // int 0x80 (op->val = 0x80)
	RSyscallItem *item = r_syscall_get (core->anal->syscall, scNumber, scVector);
	if (!item && !isx86 && scVector > 10 && scVector < 200) {
		item = r_syscall_get (core->anal->syscall, scVector, -1);
	}
	if (item) {
		if (param->pj) {
			pj_o (param->pj);
			pj_kn (param->pj, "addr", op->addr);
			pj_ks (param->pj, "name", item->name);
			pj_kn (param->pj, "sysnum", item->num);
			if (op->val && op->val != UT64_MAX) {
				pj_kn (param->pj, "num", op->val);
			}
			pj_end (param->pj);
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x" %s\n", op->addr, item->name);
		}
	} else {
		R_LOG_DEBUG ("Cant find an syscall for %d %d", scNumber, scVector);
	}
	if (param->searchflags) {
		char *flag = r_str_newf ("%s%d_%d.%s", param->searchprefix, kwidx, *count, item? item->name: "syscall");
		r_flag_set (core->flags, flag, op->addr, oplen);
		free (flag);
	}
	r_syscall_item_free (item);
	if (*param->cmd_hit) {
		ut64 here = core->addr;
		r_core_seek (core, op->addr, true);
		r_core_cmd (core, param->cmd_hit, 0);
		r_core_seek (core, here, true);
	}
	(*count)++;
	return core->search->maxhits <= 0 || *count < core->search->maxhits;
}

static int syscall_natural_align(SyscallSearchKind kind) {
	switch (kind) {
	case SYSCALL_SEARCH_ARM64:
	case SYSCALL_SEARCH_ARM32:
		return 4;
	case SYSCALL_SEARCH_THUMB:
		return 2;
	default:
		return 1;
	}
}

static bool syscall_process_function_block_candidates(RCore *core, struct search_parameters *param, SyscallRegMap *regmap, RVecSyscallFunctionCache *fcn_cache, const char *screg, RVecSearchAddr *candidates, size_t *candidate_idx, RAnalBlock *bb, int kwidx, int *count, bool isx86) {
	const size_t candidate_count = RVecSearchAddr_length (candidates);
	ut64 block_end = bb->size > UT64_MAX - bb->addr? UT64_MAX: bb->addr + bb->size;
	bool keep_going = true;

	while (*candidate_idx < candidate_count) {
		ut64 *candidate = RVecSearchAddr_at (candidates, *candidate_idx);
		if (!candidate || *candidate >= block_end) {
			break;
		}
		if (*candidate < bb->addr) {
			(*candidate_idx)++;
			continue;
		}
		if (r_anal_block_op_starts_at (bb, *candidate)) {
			RAnalOp op = {0};
			ut8 opbuf[64];
			int len = syscall_read_op (core, *candidate, block_end, opbuf, sizeof (opbuf));
			int oplen = r_anal_op (core->anal, &op, *candidate, opbuf, len, R_ARCH_OP_MASK_VAL);
			if (oplen > 0 && (op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_SWI) {
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, *candidate, 0);
				keep_going = syscall_handle_hit (core, param, regmap, fcn_cache, screg,
					&op, oplen, kwidx, count, isx86, fcn, syscall_reg_unknown (), false);
			}
			r_anal_op_fini (&op);
			if (!keep_going) {
				break;
			}
		}
		(*candidate_idx)++;
	}
	return keep_going;
}

static bool syscall_search_candidates(RCore *core, struct search_parameters *param, RIOMap *map, SyscallSearchKind kind, SyscallRegMap *regmap, RVecSyscallFunctionCache *fcn_cache, const char *screg, int kwidx, int *count, bool isx86) {
	RVecSearchAddr candidates;
	ut64 from = r_io_map_begin (map);
	ut64 to = r_io_map_end (map);
	SyscallRegState local_state;
	const int mininstrsz = r_arch_info (core->anal->arch, R_ARCH_INFO_MINOP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	const int natural_align = syscall_natural_align (kind);
	int bsize = R_MAX (64, core->blocksize);
	ut8 *buf;
	size_t candidate_idx = 0;
	size_t candidate_count;
	ut64 last_candidate;
	ut64 at;
	ut64 buf_at = UT64_MAX;
	bool keep_going = true;

	RVecSearchAddr_init (&candidates);
	if (!syscall_collect_candidates (core, &candidates, kind, from, to, core->search->align)) {
		RVecSearchAddr_fini (&candidates);
		return false;
	}
	candidate_count = RVecSearchAddr_length (&candidates);
	if (candidate_count < 1) {
		RVecSearchAddr_fini (&candidates);
		return true;
	}
	if (!syscall_state_init (&local_state, regmap, true)) {
		RVecSearchAddr_fini (&candidates);
		return false;
	}
	syscall_state_set_unknown (&local_state, true);
	buf = malloc (bsize);
	if (!buf) {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", bsize);
		syscall_state_fini (&local_state);
		RVecSearchAddr_fini (&candidates);
		return false;
	}
	last_candidate = *RVecSearchAddr_last (&candidates);
	at = from;
	if (natural_align > 1 && (at % natural_align)) {
		at += natural_align - (at % natural_align);
	}
	while (at < to && at <= last_candidate) {
		RAnalOp op = {0};
		RAnalBlock *bb;
		int ret = 0;
		int buf_delta;
		int step;
		if (r_cons_is_breaked (core->cons)) {
			keep_going = false;
			break;
		}
		while (candidate_idx < candidate_count) {
			ut64 *candidate = RVecSearchAddr_at (&candidates, candidate_idx);
			if (candidate && *candidate >= at) {
				break;
			}
			candidate_idx++;
		}
		if (candidate_idx >= candidate_count) {
			break;
		}
		bb = r_anal_bb_from_offset (core->anal, at);
		if (bb && bb->fcns && !r_list_empty (bb->fcns)) {
			keep_going = syscall_process_function_block_candidates (core, param, regmap,
				fcn_cache, screg, &candidates, &candidate_idx, bb, kwidx, count, isx86);
			syscall_state_set_unknown (&local_state, true);
			if (!keep_going) {
				break;
			}
			if (bb->size > UT64_MAX - bb->addr) {
				break;
			}
			if (bb->addr + bb->size <= at) {
				at++;
			} else {
				at = bb->addr + bb->size;
			}
			buf_at = UT64_MAX;
			continue;
		}
		if (buf_at == UT64_MAX || at < buf_at || at - buf_at >= (ut64)(bsize - 32)) {
			buf_at = at;
			r_io_read_at (core->io, at, buf, bsize);
		}
		buf_delta = (int)(at - buf_at);
		ret = r_anal_op (core->anal, &op, at, buf + buf_delta, bsize - buf_delta, R_ARCH_OP_MASK_VAL);
		if (ret > 0 && candidate_idx < candidate_count) {
			ut64 *candidate = RVecSearchAddr_at (&candidates, candidate_idx);
			if (candidate && *candidate == at && (op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_SWI) {
				RAnalBlock *opbb = r_anal_bb_from_offset (core->anal, at);
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, at, 0);
				SyscallRegValue fallback = syscall_state_read (regmap, &local_state, screg);
				if (!opbb || r_anal_block_op_starts_at (opbb, at)) {
					keep_going = syscall_handle_hit (core, param, regmap, fcn_cache, screg,
						&op, ret, kwidx, count, isx86, fcn, fallback, !fcn);
				}
				candidate_idx++;
			}
		}
		if (ret > 0) {
			syscall_transfer_op (core, regmap, &local_state, &op, screg);
		}
		step = ret > 0? ret: minopcode;
		if (step < 1) {
			step = 1;
		}
		at += step;
		r_anal_op_fini (&op);
		if (!keep_going) {
			break;
		}
	}
	free (buf);
	syscall_state_fini (&local_state);
	RVecSearchAddr_fini (&candidates);
	return keep_going;
}

static bool syscall_search_decode_scan(RCore *core, struct search_parameters *param, RIOMap *map, SyscallRegMap *regmap, RVecSyscallFunctionCache *fcn_cache, const char *screg, int kwidx, int *count, bool isx86) {
	RAnalOp op = {0};
	SyscallRegState local_state;
	ut64 from = r_io_map_begin (map);
	ut64 to = r_io_map_end (map);
	ut64 at;
	int i, ret, bsize = R_MAX (64, core->blocksize);
	const int mininstrsz = r_arch_info (core->anal->arch, R_ARCH_INFO_MINOP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	const int cfg_align = core->search->align;
	const bool use_align = cfg_align > 0;
	const int align = use_align? cfg_align: 1;
	ut8 *buf = malloc (bsize);
	bool keep_going = true;
	bool linear_in_function = false;
	ut64 covered_until = 0;
	RAnalFunction *covered_fcn = NULL;

	if (!buf) {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", bsize);
		return false;
	}
	if (!syscall_state_init (&local_state, regmap, true)) {
		free (buf);
		return false;
	}
	syscall_state_set_unknown (&local_state, true);
	for (i = 0, at = from; at < to; at++, i++) {
		if (r_cons_is_breaked (core->cons)) {
			keep_going = false;
			break;
		}
		if (i >= (bsize - 32)) {
			i = 0;
		}
		if (use_align && align > 1 && (at % align)) {
			continue;
		}
		if (!i) {
			r_io_read_at (core->io, at, buf, bsize);
		}
		ret = r_anal_op (core->anal, &op, at, buf + i, bsize - i, R_ARCH_OP_MASK_VAL);
		bool op_in_function = false;
		RAnalFunction *op_fcn = NULL;
		if (ret > 0) {
			if (covered_fcn && at < covered_until) {
				op_fcn = covered_fcn;
			} else {
				covered_fcn = syscall_function_covered_at (core, at, &covered_until);
				op_fcn = covered_fcn;
			}
			op_in_function = op_fcn != NULL;
			if (op_in_function != linear_in_function) {
				syscall_state_set_unknown (&local_state, true);
				linear_in_function = op_in_function;
			}
		}
		if (((op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_SWI) && ret > 0) {
			RAnalFunction *fcn = op_fcn? op_fcn: r_anal_get_fcn_in (core->anal, at, 0);
			SyscallRegValue fallback = syscall_state_read (regmap, &local_state, screg);
			keep_going = syscall_handle_hit (core, param, regmap, fcn_cache, screg,
				&op, ret, kwidx, count, isx86, fcn, fallback, !fcn);
		}
		int inc = use_align? align - 1: ret - 1;
		if (inc < 0) {
			inc = minopcode;
		}
		if (ret > 0 && !op_in_function) {
			syscall_transfer_op (core, regmap, &local_state, &op, screg);
		}
		i += inc;
		at += inc;
		r_anal_op_fini (&op);
		if (!keep_going) {
			break;
		}
	}
	free (buf);
	syscall_state_fini (&local_state);
	return keep_going;
}

static void do_syscall_search(RCore *core, struct search_parameters *param) {
	int count = 0;
	int kwidx = core->search->n_kws;
	RIOMap *map;
	RListIter *iter;
	RArchConfig *cfg = R_UNWRAP3 (core, anal, config);
	const bool isx86 = r_str_startswith (cfg? cfg->arch: NULL, "x86");
	const SyscallSearchKind kind = syscall_search_kind (core);
	SyscallRegMap regmap;
	RVecSyscallFunctionCache fcn_cache;
	const char *screg = get_syscall_register (core);

	if (!syscall_regmap_init (&regmap, core->anal->reg)) {
		return;
	}
	RVecSyscallFunctionCache_init (&fcn_cache);
	r_cons_break_push (core->cons, NULL, NULL);
	if (param->pj) {
		pj_o (param->pj);
		pj_ks (param->pj, "cmd", "/asj");
		pj_ka (param->pj, "results");
	}
	r_list_foreach (param->boundaries, iter, map) {
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		bool keep_going;
		if (from >= to) {
			R_LOG_ERROR ("from must be lower than to");
			break;
		}
		if (to == UT64_MAX) {
			R_LOG_ERROR ("Invalid destination boundary");
			break;
		}
		if (kind == SYSCALL_SEARCH_UNSUPPORTED) {
			keep_going = syscall_search_decode_scan (core, param, map, &regmap, &fcn_cache,
				screg, kwidx, &count, isx86);
		} else {
			keep_going = syscall_search_candidates (core, param, map, kind, &regmap, &fcn_cache,
				screg, kwidx, &count, isx86);
		}
		if (!keep_going) {
			break;
		}
	}
	if (param->pj) {
		pj_end (param->pj);
		pj_end (param->pj);
	}
	r_cons_break_pop (core->cons);
	RVecSyscallFunctionCache_fini (&fcn_cache);
	syscall_regmap_fini (&regmap);
}

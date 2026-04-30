/* radare - LGPL - Copyright 2010-2026 - pancake */

#include <r_anal.h>
#include <r_anal_priv.h>

#include <r_vec.h>

#define JMPTBL_DISPATCH_LOOKBACK 16
#define SWITCH_SDB_NS "switches"

R_VEC_TYPE(RVecUT64, ut64);

typedef struct {
	RIOMap *switch_map;
	HtUP *validated_targets;
} JmptblTargetCtx;

R_IPI void r_anal_jmptbl_leaddrs_bump(RList *leaddrs, const char *reg, ut64 delta) {
	R_RETURN_IF_FAIL (leaddrs && reg);
	RListIter *iter;
	RLeaddrPair *la;
	r_list_foreach_prev (leaddrs, iter, la) {
		if (la->reg && !strcmp (la->reg, reg)) {
			la->leaddr += delta;
			return;
		}
	}
}

static RLeaddrPair *leaddrs_find_before(RList *leaddrs, const char *reg, ut64 before) {
	RListIter *iter;
	RLeaddrPair *la;
	r_list_foreach_prev (leaddrs, iter, la) {
		if (la->reg && !strcmp (la->reg, reg) && la->op_addr < before) {
			return la;
		}
	}
	return NULL;
}

static bool arm64_resolve_dispatch(RAnal *anal, RList *leaddrs, ut64 br_addr, const char *target_reg, ut64 *opaddr, ut64 *basptr, ut64 *tblptr) {
	R_RETURN_VAL_IF_FAIL (anal && leaddrs && target_reg && opaddr && basptr && tblptr, false);
	const ut64 lookback_bytes = JMPTBL_DISPATCH_LOOKBACK * 4;
	if (br_addr < lookback_bytes) {
		return false;
	}
	ut8 buf[JMPTBL_DISPATCH_LOOKBACK * 4];
	const ut64 scan_base = br_addr - lookback_bytes;
	if (!anal->iob.read_at (anal->iob.io, scan_base, buf, sizeof (buf))) {
		return false;
	}
	// Locate the `add Rdst, Rs0, Rs1[, lsl N]` whose destination matches
	// the indirect branch's target register. Scan the most recent instructions
	char add_s0[32] = { 0 };
	char add_s1[32] = { 0 };
	ut64 add_addr = UT64_MAX;
	int add_idx = -1;
	int i;
	for (i = JMPTBL_DISPATCH_LOOKBACK - 1; i >= 0; i--) {
		RAnalOp op = { 0 };
		if (r_anal_op (anal, &op, scan_base + i * 4, buf + i * 4, 4, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL) > 0 && (op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_ADD) {
			RAnalValue *d = RVecRArchValue_at (&op.dsts, 0);
			if (d && d->reg && !strcmp (d->reg, target_reg)) {
				RAnalValue *s0 = RVecRArchValue_at (&op.srcs, 0);
				RAnalValue *s1 = RVecRArchValue_at (&op.srcs, 1);
				if (s0 && s0->reg) {
					r_str_ncpy (add_s0, s0->reg, sizeof (add_s0));
				}
				if (s1 && s1->reg) {
					r_str_ncpy (add_s1, s1->reg, sizeof (add_s1));
				}
				add_addr = scan_base + i * 4;
				add_idx = i;
				r_anal_op_fini (&op);
				break;
			}
		}
		r_anal_op_fini (&op);
	}
	if (add_idx < 0 || (!*add_s0 && !*add_s1)) {
		return false;
	}
	// Walk back from the add to find the `ldr* Rload, [Rtable, ...]`
	// whose destination is one of the add's sources.
	char table_reg[32] = { 0 };
	char load_reg[32] = { 0 };
	ut64 load_addr = UT64_MAX;
	for (i = add_idx - 1; i >= 0; i--) {
		RAnalOp op = { 0 };
		if (r_anal_op (anal, &op, scan_base + i * 4, buf + i * 4, 4, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL) > 0 && (op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_LOAD) {
			RAnalValue *ld = RVecRArchValue_at (&op.dsts, 0);
			RAnalValue *ls = RVecRArchValue_at (&op.srcs, 0);
			if (ld && ld->reg && ls && ls->reg && ((*add_s0 && !strcmp (add_s0, ld->reg)) || (*add_s1 && !strcmp (add_s1, ld->reg)))) {
				r_str_ncpy (load_reg, ld->reg, sizeof (load_reg));
				r_str_ncpy (table_reg, ls->reg, sizeof (table_reg));
				load_addr = scan_base + i * 4;
				r_anal_op_fini (&op);
				break;
			}
		}
		r_anal_op_fini (&op);
	}
	if (!*load_reg || !*table_reg) {
		return false;
	}
	// The dispatch base is the add source that is not the loaded value.
	const char *base_reg = (*add_s0 && strcmp (add_s0, load_reg))? add_s0
		: (*add_s1 && strcmp (add_s1, load_reg))? add_s1
								: NULL;
	if (!base_reg) {
		return false;
	}
	RLeaddrPair *bp = leaddrs_find_before (leaddrs, base_reg, add_addr);
	RLeaddrPair *tp = leaddrs_find_before (leaddrs, table_reg, load_addr);
	if (!bp || !tp) {
		return false;
	}
	*opaddr = bp->op_addr;
	*basptr = bp->leaddr;
	*tblptr = tp->leaddr;
	return true;
}

static inline ut64 get_mips_gp_base(RAnal *anal, ut64 ip) {
	ut64 gp = anal->gp;
	if (!gp && anal->reg) {
		gp = r_reg_getv (anal->reg, "gp");
	}
	if (!gp && anal->config) {
		gp = anal->config->gp;
	}
	if (!gp || gp == UT64_MAX) {
		return ip & 0xfffff;
	}
	return gp;
}

static void jmptbl_target_ctx_init(JmptblTargetCtx *ctx, RAnal *anal, ut64 switch_addr) {
	ctx->switch_map = anal->iob.map_get_at
		? anal->iob.map_get_at (anal->iob.io, switch_addr)
		: NULL;
	ctx->validated_targets = ht_up_new0 ();
}

static void jmptbl_target_ctx_fini(JmptblTargetCtx *ctx) {
	ht_up_free (ctx->validated_targets);
	ctx->validated_targets = NULL;
	ctx->switch_map = NULL;
}

static bool check_jmptbl_case_target(RAnal *anal, JmptblTargetCtx *ctx, ut64 case_addr) {
	if (!anal->iob.is_valid_offset (anal->iob.io, case_addr, 0)) {
		return false;
	}
	if (anal->iob.map_get_at) {
		RIOMap *case_map = anal->iob.map_get_at (anal->iob.io, case_addr);
		if (!case_map) {
			return false;
		}
		// Keep jump-table targets in the same map as the dispatcher, matching direct-jump behavior.
		if (ctx->switch_map && !r_io_map_contain (ctx->switch_map, case_addr)) {
			return false;
		}
	}
	ut8 probe[32];
	if (!anal->iob.read_at (anal->iob.io, case_addr, probe, sizeof (probe))) {
		return false;
	}
	return !r_anal_is_invalid_code (anal, probe, sizeof (probe), true);
}

static bool is_valid_jmptbl_case_target(RAnal *anal, JmptblTargetCtx *ctx, ut64 case_addr) {
	if (!anal->iob.io) {
		return false;
	}
	bool found = false;
	void *v = ht_up_find (ctx->validated_targets, case_addr, &found);
	if (found) {
		return v == (void *)1;
	}
	bool valid = check_jmptbl_case_target (anal, ctx, case_addr);
	ht_up_insert (ctx->validated_targets, case_addr, valid? (void *)1: (void *)2);
	return valid;
}

static void apply_case(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, ut64 switch_addr, ut64 offset_sz, ut64 case_addr, ut64 id, ut64 case_addr_loc, bool case_is_insn) {
	// eprintf ("case!\n");
	// eprintf ("** apply_case: 0x%"PFMT64x " from 0x%"PFMT64x "\n", case_addr, case_addr_loc);
	/*
	 * In the case of ARM-style jump table (as in walkthrough_arm_jmptbl_style)
	 * Do not treat the case as data, since it is in fact, instruction.
	 */
	if (!case_is_insn) {
		r_meta_set_data_at (anal, case_addr_loc, offset_sz);
		r_anal_hint_set_immbase (anal, case_addr_loc, 10);
	}
	r_anal_xrefs_setf (anal, fcn, switch_addr, case_addr, R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_EXEC);
	if (block) {
		r_anal_block_add_switch_case (block, switch_addr, id, case_addr);
	}
	if (anal->flb.set) {
		const int iid = R_ABS ((int)id);
		r_strf_var (flagname, 64, "case.0x%" PFMT64x ".%d", (ut64)switch_addr, iid);
		anal->flb.set (anal->flb.f, flagname, case_addr, 1);
	}
}

static void update_switch_op(RAnalBlock *block, ut64 switch_addr, ut64 default_case_addr, ut64 cases_count) {
	if (!block || !block->switch_op) {
		return;
	}
	RAnalSwitchOp *sop = block->switch_op;
	sop->def_val = default_case_addr;
	sop->amount = cases_count;
	if (!sop->cases || r_list_empty (sop->cases)) {
		return;
	}
	RListIter *iter;
	RAnalCaseOp *caseop;
	sop->min_val = UT64_MAX;
	sop->max_val = 0;
	r_list_foreach (sop->cases, iter, caseop) {
		if (caseop->value < sop->min_val) {
			sop->min_val = caseop->value;
		}
		if (caseop->value > sop->max_val) {
			sop->max_val = caseop->value;
		}
	}
}

// Mirror the spec into the persisted RAnalSwitchOp on `block`.
// Called by apply_switch () once the case list is finalised.
static void switch_op_apply_spec(RAnalBlock *block, const RAnalSwitchSpec *spec) {
	if (!block || !block->switch_op || !spec) {
		return;
	}
	RAnalSwitchOp *sop = block->switch_op;
	sop->daddr = spec->jtbl_addr;
	sop->dsize = spec->esize;
	sop->vtbl_addr = spec->vtbl_addr;
	sop->vsize = spec->vsize;
	sop->shift = spec->shift;
	sop->lowcase = spec->lowcase;
	sop->flags = spec->flags;
	if (spec->flags & R_ANAL_SWITCH_F_BASE) {
		sop->baddr = spec->base;
	}
	sop->reg = spec->reg;
}

// Read one little-endian entry from `raw`. `signed_entry` controls
// sign-extension when esize < 8.
static ut64 switch_read_entry(const ut8 *raw, ut8 esize, bool signed_entry) {
	ut64 v;
	switch (esize) {
	case 1:
		v = signed_entry? (ut64) (st64) (st8)raw[0]: (ut64)raw[0];
		break;
	case 2:
		v = signed_entry? (ut64) (st64) (st16)r_read_le16 (raw): (ut64)r_read_le16 (raw);
		break;
	case 4:
		v = signed_entry? (ut64) (st64) (st32)r_read_le32 (raw): (ut64)r_read_le32 (raw);
		break;
	case 8:
		v = r_read_le64 (raw);
		break;
	default:
		v = r_read_le32 (raw);
		break;
	}
	return v;
}

typedef enum {
	SWITCH_TARGET_STOP,
	SWITCH_TARGET_SKIP,
	SWITCH_TARGET_OK,
} SwitchTargetResult;

// Compute the target address for a single jump-table entry given the
// flags. Mirrors IDA's `target = elbase ± (entry << shift)` formula
// plus SELFREL (target = entry_addr + entry).
static SwitchTargetResult switch_compute_target(const RAnalSwitchSpec *spec,
	ut64 entry_addr,
	ut64 raw_entry,
	ut64 *out) {
	if (raw_entry == 0 && ! (spec->flags & R_ANAL_SWITCH_F_SELFREL)) {
		if (spec->flags & R_ANAL_SWITCH_F_SPARSE) {
			return SWITCH_TARGET_SKIP;
		}
		return SWITCH_TARGET_STOP;
	}
	ut64 shifted = raw_entry;
	if (spec->shift) {
		shifted = (spec->flags & R_ANAL_SWITCH_F_SIGNED)
			? (ut64) ((st64)raw_entry << spec->shift)
			: (raw_entry << spec->shift);
	}
	if (spec->flags & R_ANAL_SWITCH_F_SELFREL) {
		*out = entry_addr + (st64)shifted;
		return SWITCH_TARGET_OK;
	}
	const ut64 base = (spec->flags & R_ANAL_SWITCH_F_BASE)
		? spec->base
		: spec->jtbl_addr;
	if (spec->flags & R_ANAL_SWITCH_F_SUBTRACT) {
		*out = base - shifted;
	} else {
		*out = base + shifted;
	}
	return SWITCH_TARGET_OK;
}

static void apply_switch(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, ut64 switch_addr, ut64 jmptbl_addr, ut64 cases_count, ut64 default_case_addr, int esize) {
	char tmp[64];
	snprintf (tmp, sizeof (tmp), "switch table (%" PFMT64u " cases) at 0x%" PFMT64x, cases_count, jmptbl_addr);
	r_meta_set_string (anal, R_META_TYPE_COMMENT, switch_addr, tmp);
	update_switch_op (block, switch_addr, default_case_addr, cases_count);
	// Always populate the table address and element size so afbt-style
	// introspection sees real values even when the switch was discovered
	// by the legacy walkers.
	if (block && block->switch_op) {
		block->switch_op->daddr = jmptbl_addr;
		if (esize > 0) {
			block->switch_op->dsize = esize;
		}
	}
	if (anal->flb.set) {
		snprintf (tmp, sizeof (tmp), "switch.0x%08" PFMT64x, switch_addr);
		anal->flb.set (anal->flb.f, tmp, switch_addr, 1);
		if (default_case_addr != UT64_MAX) {
			r_anal_xrefs_setf (anal, fcn, switch_addr, default_case_addr, R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_EXEC);
			snprintf (tmp, sizeof (tmp), "case.default.0x%" PFMT64x, switch_addr);
			anal->flb.set (anal->flb.f, tmp, default_case_addr, 1);
		}
	}
}

// analyze a jmptablle inside a function // maybe rename to r_anal_function_jmptbl ()?
R_API bool r_anal_jmptbl(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, ut64 jmpaddr, ut64 table, ut64 tablesize, ut64 default_addr) {
	const int depth = 50;
	return r_anal_jmptbl_walk (anal, fcn, block, depth, jmpaddr, 0, table, table, tablesize, tablesize, default_addr, false);
}

static inline void analyze_new_case(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, ut64 ip, ut64 jmpptr, int depth) {
	const ut64 block_size = block? block->size: 0;
	r_anal_function_materialize_switch_case (anal, fcn, jmpptr, depth);
	if (block && block->size != block_size) {
		// block was split during anal and does not contain the
		// jmp instruction anymore, so we need to search for it and get it again
		RAnalSwitchOp *sop = block->switch_op;
		block = r_anal_get_block_at (anal, ip);
		if (!block) {
			block = r_anal_bb_from_offset (anal, ip);
			if (!block) {
				R_LOG_ERROR ("Major disaster at 0x%08" PFMT64x, ip);
				return;
			}
			if (block->addr != ip) {
				if (anal->opt.jmptbl_split) {
					// split the block so switch instruction is at the start of its block
					RAnalBlock *newblock = r_anal_block_split (block, ip);
					if (newblock) {
						r_unref (newblock);
						block = r_anal_get_block_at (anal, ip);
					}
					if (!block) {
						R_LOG_ERROR ("Failed to split block for switch at 0x%08" PFMT64x, ip);
						return;
					}
				} else {
					st64 d = block->addr - ip;
					R_LOG_WARN ("Cannot find basic block case for jmptbl switch from 0x%08" PFMT64x " bbdelta = %d. Try -e anal.jmptbl.split=true and let us know", ip, (int)R_ABS (d));
					block = NULL;
					return;
				}
			}
		}
		block->switch_op = sop;
	}
}


// --- Persistence ---------------------------------------------------------
// User-pinned switch overrides live in a flat sdb namespace under
// anal->sdb, keyed by the dispatching insn address. Format:
//   "j=<jtbl>,e=<esize>,n=<ncases>,s=<shift>,b=<base>,d=<def>,
//    v=<vtbl>,V=<vsize>,L=<lowcase>,F=<flags>[,r=<reg>]"
// Missing keys keep their default. Order is irrelevant; unknown keys
// are silently skipped.

static Sdb *switch_sdb(RAnal *anal, bool create) {
	return sdb_ns (anal->sdb, SWITCH_SDB_NS, create);
}

static ut32 switch_spec_ncases(const RAnalSwitchSpec *spec) {
	return spec->ncases? R_MIN (spec->ncases, (ut32)R_ANAL_SWITCH_MAXCASES): R_ANAL_SWITCH_MAXCASES;
}

static char *switch_spec_serialize(const RAnalSwitchSpec *spec) {
	RStrBuf *sb = r_strbuf_new (NULL);
	// clang-format off
	r_strbuf_appendf (sb,
		"j=0x%" PFMT64x ",e=%u,n=%u,"
		"s=%u,b=0x%" PFMT64x ",d=0x%" PFMT64x ",v=0x%" PFMT64x
		",V=%u,L=%" PFMT64d ",F=0x%x",
		spec->jtbl_addr, (unsigned)spec->esize, (unsigned)spec->ncases,
		(unsigned)spec->shift, spec->base, spec->defjump, spec->vtbl_addr,
		(unsigned)spec->vsize, spec->lowcase, (unsigned)spec->flags);
	// clang-format on
	if (spec->reg) {
		r_strbuf_appendf (sb, ",r=%s", spec->reg);
	}
	return r_strbuf_drain (sb);
}

static void switch_spec_deserialize(RAnal *anal, const char *s, RAnalSwitchSpec *out) {
	r_anal_switch_spec_init (out);
	if (R_STR_ISEMPTY (s)) {
		return;
	}
	char *dup = strdup (s);
	char *save = NULL;
	char *tok;
	for (tok = r_str_tok_r (dup, ",", &save); tok; tok = r_str_tok_r (NULL, ",", &save)) {
		if (tok[0] == '\0' || tok[1] != '=') {
			continue;
		}
		const char *v = tok + 2;
		switch (tok[0]) {
		case 'j': out->jtbl_addr = r_num_get (NULL, v); break;
		case 'e': out->esize = (ut8)r_num_get (NULL, v); break;
		case 'n': out->ncases = (ut32)r_num_get (NULL, v); break;
		case 's': out->shift = (ut8)r_num_get (NULL, v); break;
		case 'b': out->base = r_num_get (NULL, v); break;
		case 'd': out->defjump = r_num_get (NULL, v); break;
		case 'v': out->vtbl_addr = r_num_get (NULL, v); break;
		case 'V': out->vsize = (ut8)r_num_get (NULL, v); break;
		case 'L': out->lowcase = (st64)r_num_get (NULL, v); break;
		case 'F': out->flags = (ut32)r_num_get (NULL, v); break;
		case 'r': out->reg = r_str_constpool_get (&anal->constpool, v); break;
		default: break;
		}
	}
	free (dup);
}

R_API bool r_anal_switch_set(RAnal *anal, ut64 startea, const RAnalSwitchSpec *spec) {
	R_RETURN_VAL_IF_FAIL (anal && spec, false);
	Sdb *db = switch_sdb (anal, true);
	r_strf_var (key, 32, "0x%" PFMT64x, startea);
	char *value = switch_spec_serialize (spec);
	return sdb_set_owned (db, key, value, 0) != 0;
}

R_API bool r_anal_switch_get(RAnal *anal, ut64 startea, RAnalSwitchSpec *out) {
	R_RETURN_VAL_IF_FAIL (anal && out, false);
	Sdb *db = switch_sdb (anal, false);
	r_strf_var (key, 32, "0x%" PFMT64x, startea);
	const char *v = sdb_const_get (db, key, NULL);
	switch_spec_deserialize (anal, v, out);
	out->startea = startea;
	return true;
}

R_API void r_anal_switch_unset(RAnal *anal, ut64 startea) {
	R_RETURN_IF_FAIL (anal);
	Sdb *db = switch_sdb (anal, false);
	r_strf_var (key, 32, "0x%" PFMT64x, startea);
	sdb_unset (db, key, 0);
}

// Flag-driven walker: handles the cases the legacy walker can't express
// (SELFREL, SUBTRACT, explicit BASE, signed entries, INSN-as-element,
// INDIRECT with vsize > 1, SPARSE).
static bool switch_apply_flagged(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, const RAnalSwitchSpec *spec) {
	JmptblTargetCtx target_ctx = { 0 };
	const ut32 ncases = switch_spec_ncases (spec);
	if (spec->jtbl_addr == UT64_MAX) {
		R_LOG_DEBUG ("Invalid JumpTable location");
		return false;
	}
	if (ncases < 1 || ncases > ST32_MAX) {
		R_LOG_DEBUG ("Invalid JumpTable size at 0x%08" PFMT64x, spec->startea);
		return false;
	}
	const ut8 esize = spec->esize? spec->esize: 4;
	const ut64 jtblsz = (ut64)ncases * esize;
	if (jtblsz < 1 || jtblsz > ST32_MAX) {
		R_LOG_DEBUG ("Invalid jump table size at 0x%08" PFMT64x, spec->jtbl_addr);
		return false;
	}
	ut8 *jmptbl = calloc (ncases, esize);
	if (!jmptbl) {
		return false;
	}
	if (!anal->iob.read_at (anal->iob.io, spec->jtbl_addr, jmptbl, jtblsz)) {
		free (jmptbl);
		return false;
	}
	const bool indirect = (spec->flags & R_ANAL_SWITCH_F_INDIRECT) != 0;
	const bool sparse = (spec->flags & R_ANAL_SWITCH_F_SPARSE) != 0;
	const bool defintbl = (spec->flags & R_ANAL_SWITCH_F_DEFINTBL) != 0;
	const bool need_vtbl = indirect || sparse;
	const ut8 vsize = need_vtbl? (spec->vsize? spec->vsize: 1): 0;
	ut8 *vtbl = NULL;
	if (need_vtbl) {
		if (spec->vtbl_addr == UT64_MAX) {
			R_LOG_DEBUG ("Switch with no vtbl_addr at 0x%08" PFMT64x, spec->startea);
			free (jmptbl);
			return false;
		}
		vtbl = calloc (ncases, vsize);
		if (!vtbl || !anal->iob.read_at (anal->iob.io, spec->vtbl_addr, vtbl, (ut64)ncases * vsize)) {
			free (jmptbl);
			free (vtbl);
			return false;
		}
	}
	jmptbl_target_ctx_init (&target_ctx, anal, spec->startea);
	const bool signed_entry = (spec->flags & R_ANAL_SWITCH_F_SIGNED) != 0;
	const bool insn_entry = (spec->flags & R_ANAL_SWITCH_F_INSN) != 0;
	const bool inverse = (spec->flags & R_ANAL_SWITCH_F_INVERSE) != 0;
	// DEFINTBL: one entry of jtbl is the default jump, not a real case.
	// With INVERSE the default sits at index 0; otherwise at the tail.
	const ut32 default_slot = defintbl? (inverse? 0: ncases - 1): UT32_MAX;
	ut64 def_jump = spec->defjump;
	if (defintbl) {
		const ut64 entry_addr = spec->jtbl_addr + (ut64)default_slot * esize;
		ut64 raw = switch_read_entry (jmptbl + (ut64)default_slot * esize, esize, signed_entry);
		ut64 jmpptr = UT64_MAX;
		if (insn_entry) {
			jmpptr = entry_addr;
		} else if (switch_compute_target (spec, entry_addr, raw, &jmpptr) != SWITCH_TARGET_OK) {
			jmpptr = UT64_MAX;
		}
		if (jmpptr != UT64_MAX) {
			if (def_jump == UT64_MAX || def_jump == 0) {
				def_jump = jmpptr;
			}
			if (!insn_entry) {
				r_meta_set_data_at (anal, entry_addr, esize);
				r_anal_hint_set_immbase (anal, entry_addr, 10);
			}
		}
	}
	ut32 i;
	ut32 last_applied = 0;
	for (i = 0; i < ncases; i++) {
		const ut32 idx = inverse? (ncases - 1 - i): i;
		if (idx == default_slot) {
			continue;
		}
		ut32 jtbl_idx = idx;
		st64 casenum = (st64)i + spec->lowcase;
		if (sparse) {
			// Parallel arrays: vtbl[idx] holds the case key, jtbl[idx]
			// the target. Element size is vsize; keys are signed iff
			// the spec asked for signed entries.
			casenum = (st64)switch_read_entry (vtbl + (ut64)idx * vsize, vsize, signed_entry);
			const ut64 vloc = spec->vtbl_addr + (ut64)idx * vsize;
			r_meta_set_data_at (anal, vloc, vsize);
			r_anal_hint_set_immbase (anal, vloc, 10);
		} else if (indirect) {
			ut64 v_raw = switch_read_entry (vtbl + (ut64)idx * vsize, vsize, false);
			if (v_raw >= ncases) {
				R_LOG_DEBUG ("INDIRECT entry out of range at idx %u", idx);
				break;
			}
			jtbl_idx = (ut32)v_raw;
			const ut64 vloc = spec->vtbl_addr + (ut64)idx * vsize;
			r_meta_set_data_at (anal, vloc, vsize);
			r_anal_hint_set_immbase (anal, vloc, 10);
		}
		const ut64 entry_addr = spec->jtbl_addr + (ut64)jtbl_idx * esize;
		ut64 raw = switch_read_entry (jmptbl + (ut64)jtbl_idx * esize, esize, signed_entry);
		ut64 jmpptr;
		if (insn_entry) {
			// The entry IS an inline branch instruction: its address is
			// what the dispatcher branches to.
			jmpptr = entry_addr;
		} else {
			SwitchTargetResult target_result = switch_compute_target (spec, entry_addr, raw, &jmpptr);
			if (target_result == SWITCH_TARGET_STOP) {
				break;
			}
			if (target_result == SWITCH_TARGET_SKIP) {
				r_meta_set_data_at (anal, entry_addr, esize);
				r_anal_hint_set_immbase (anal, entry_addr, 10);
				continue;
			}
		}
		if (anal->limit && (jmpptr < anal->limit->from || jmpptr > anal->limit->to)) {
			break;
		}
		if (!insn_entry) {
			r_meta_set_data_at (anal, entry_addr, esize);
			r_anal_hint_set_immbase (anal, entry_addr, 10);
		}
		if (!is_valid_jmptbl_case_target (anal, &target_ctx, jmpptr)) {
			continue;
		}
		apply_case (anal, fcn, block, spec->startea, esize, jmpptr, (ut64)casenum, entry_addr, insn_entry);
		analyze_new_case (anal, fcn, block, spec->startea, jmpptr, depth);
		last_applied = i + 1;
	}
	if (last_applied > 0) {
		ut64 def = def_jump;
		if (def == 0) {
			def = UT64_MAX;
		}
		apply_switch (anal, fcn, block, spec->startea, spec->jtbl_addr, last_applied, def, esize);
		switch_op_apply_spec (block, spec);
	}
	free (jmptbl);
	free (vtbl);
	jmptbl_target_ctx_fini (&target_ctx);
	return last_applied > 0;
}

// Predicate: returns true when the spec carries fields the legacy
// r_anal_jmptbl_walk cannot express. In that case we go through the
// flag-driven walker; otherwise we forward to the legacy walker so the
// well-tested per-arch heuristics (Thumb-2 TBB/TBH, MIPS gp-relative,
// x86 sz==2 sign-extension) keep working unchanged.
static bool spec_needs_flag_walker(const RAnalSwitchSpec *spec) {
	const ut32 mask = R_ANAL_SWITCH_F_SIGNED | R_ANAL_SWITCH_F_SUBTRACT | R_ANAL_SWITCH_F_INSN | R_ANAL_SWITCH_F_SELFREL | R_ANAL_SWITCH_F_SPARSE | R_ANAL_SWITCH_F_INVERSE | R_ANAL_SWITCH_F_DEFINTBL;
	if (spec->flags & mask) {
		return true;
	}
	// INDIRECT with vsize > 1 cannot be expressed by try_walkthrough_casetbl
	if ((spec->flags & R_ANAL_SWITCH_F_INDIRECT) && spec->vsize > 1) {
		return true;
	}
	// Explicit base different from the table address requires the new path.
	if ((spec->flags & R_ANAL_SWITCH_F_BASE) && spec->base != spec->jtbl_addr) {
		return true;
	}
	return false;
}

R_API bool r_anal_switch_apply(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, const RAnalSwitchSpec *spec) {
	R_RETURN_VAL_IF_FAIL (anal && spec, false);
	RAnalSwitchSpec limited_spec;
	if (spec->ncases > R_ANAL_SWITCH_MAXCASES) {
		limited_spec = *spec;
		limited_spec.ncases = R_ANAL_SWITCH_MAXCASES;
		spec = &limited_spec;
		R_LOG_DEBUG ("Limiting JumpTable size at 0x%08" PFMT64x " to %u cases",
			spec->startea, (unsigned)R_ANAL_SWITCH_MAXCASES);
	}
	if (spec->jtbl_addr == UT64_MAX) {
		return false;
	}
	if (spec_needs_flag_walker (spec)) {
		// INDIRECT goes through the flag walker too (handles vsize > 1).
		return switch_apply_flagged (anal, fcn, block, depth, spec);
	}
	if (spec->flags & R_ANAL_SWITCH_F_INDIRECT) {
		// vsize == 1: the legacy 2-stage walker handles this.
		const ut64 default_case = (spec->defjump == UT64_MAX)? 0: spec->defjump;
		const bool ret = try_walkthrough_casetbl (anal, fcn, block, depth, spec->startea, spec->lowcase, spec->jtbl_addr, spec->vtbl_addr, spec->jtbl_addr, spec->esize? spec->esize: 4, spec->ncases, default_case, false);
		if (ret) {
			switch_op_apply_spec (block, spec);
		}
		return ret;
	}
	// Default path: legacy single-table walker preserves all per-arch
	// heuristics. Forward through r_anal_jmptbl_walk and then patch the
	// switch_op with whatever extras the spec carries (lowcase, reg, etc).
	const ut64 jmptbl_off = (spec->flags & R_ANAL_SWITCH_F_BASE)
		? spec->base
		: spec->jtbl_addr;
	const ut64 default_case = (spec->defjump == UT64_MAX)? 0: spec->defjump;
	const bool ret = r_anal_jmptbl_walk (anal, fcn, block, depth, spec->startea, spec->lowcase, spec->jtbl_addr, jmptbl_off, spec->esize? spec->esize: 4, spec->ncases, default_case, false);
	if (ret) {
		switch_op_apply_spec (block, spec);
	}
	return ret;
}

typedef struct {
	bool arm;
	bool x86;
	bool mips;
	bool v850;
} JmptblArch;

static bool jmptbl_detect_arch(RAnal *anal, JmptblArch *a) {
	const char *sarch = R_UNWRAP3 (anal, config, arch);
	if (!sarch) {
		R_LOG_DEBUG ("Cannot find any valid arch");
		return false;
	}
	a->arm = r_str_startswith (sarch, "arm");
	a->x86 = !a->arm && r_str_startswith (sarch, "x86");
	a->mips = !a->arm && !a->x86 && r_str_startswith (sarch, "mips");
	a->v850 = !a->arm && !a->x86 && (r_str_startswith (sarch, "v850") || r_str_startswith (anal->coreb.cfgGet (anal->coreb.core, "asm.cpu"), "v850"));
	return true;
}

// Translate a raw jump-table entry into its real target. Returns false to stop the walk.
static bool jmptbl_fixup_jmpptr(RAnal *anal, const JmptblArch *a, ut64 ip, ut64 sz, ut64 jmptbl_off, ut64 *jmpptr) {
	if (sz == 2 && (a->arm || a->v850)) {
		*jmpptr = ip + 4 + (*jmpptr * 2); // tbh [pc, r2, lsl 1]
		return true;
	}
	if (sz == 1 && a->arm) {
		*jmpptr = ip + 4 + (*jmpptr * 2); // ldrb [pc, r2]
		return true;
	}
	bool valid = anal->iob.is_valid_offset (anal->iob.io, *jmpptr, 0);
	if (!valid && a->mips) {
		ut64 base = get_mips_gp_base (anal, ip);
		st64 rel;
		switch (sz) {
		case 2: rel = (st16)*jmpptr; break;
		case 8: rel = (st64)*jmpptr; break;
		default: rel = (st32)*jmpptr; break;
		}
		*jmpptr = base + rel;
		valid = anal->iob.is_valid_offset (anal->iob.io, *jmpptr, 0);
	}
	if (!valid) {
		// jump tables where sign extended movs are used
		*jmpptr = jmptbl_off + (st32)*jmpptr;
		return anal->iob.is_valid_offset (anal->iob.io, *jmpptr, 0);
	}
	if (sz == 2 && a->x86) {
		// jump tables where sign extended movs are used
		*jmpptr = jmptbl_off + (st32)*jmpptr;
	}
	return true;
}

R_API bool try_walkthrough_casetbl(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_loc, ut64 casetbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0) {
	bool ret = ret0;
	JmptblTargetCtx target_ctx = { 0 };
	if (jmptbl_size == 0) {
		jmptbl_size = R_ANAL_SWITCH_MAXCASES;
	}
	if (jmptbl_loc == UT64_MAX) {
		R_LOG_DEBUG ("Invalid JumpTable location 0x%08" PFMT64x, jmptbl_loc);
		return false;
	}
	if (casetbl_loc == UT64_MAX) {
		R_LOG_DEBUG ("Invalid CaseTable location 0x%08" PFMT64x, jmptbl_loc);
		return false;
	}
	if (jmptbl_size < 1 || jmptbl_size > ST32_MAX) {
		R_LOG_DEBUG ("Invalid JumpTable size at 0x%08" PFMT64x, ip);
		return false;
	}
	ut64 jmpptr, case_idx, jmpptr_idx;
	ut8 *jmptbl = calloc (jmptbl_size, sz);
	if (!jmptbl || !anal->iob.read_at (anal->iob.io, jmptbl_loc, jmptbl, jmptbl_size * sz)) {
		free (jmptbl);
		return false;
	}
	ut8 *casetbl = calloc (jmptbl_size, sizeof (ut8));
	if (!casetbl || !anal->iob.read_at (anal->iob.io, casetbl_loc, casetbl, jmptbl_size)) {
		free (jmptbl);
		free (casetbl);
		return false;
	}
	JmptblArch a;
	if (!jmptbl_detect_arch (anal, &a)) {
		free (jmptbl);
		free (casetbl);
		return false;
	}
	jmptbl_target_ctx_init (&target_ctx, anal, ip);
	for (case_idx = 0; case_idx < jmptbl_size; case_idx++) {
		jmpptr_idx = casetbl[case_idx];
		if (jmpptr_idx >= jmptbl_size) {
			ret = false;
			break;
		}
		switch (sz) {
		case 1:
			jmpptr = r_read_le8 (jmptbl + jmpptr_idx);
			break;
		case 2:
			jmpptr = r_read_le16 (jmptbl + jmpptr_idx * 2);
			break;
		case 4:
			jmpptr = r_read_le32 (jmptbl + jmpptr_idx * 4);
			break;
		default:
			jmpptr = r_read_le64 (jmptbl + jmpptr_idx * 8);
			break;
		}
		if (jmpptr == 0 || jmpptr == UT32_MAX || jmpptr == UT64_MAX) {
			break;
		}
		if (!jmptbl_fixup_jmpptr (anal, &a, ip, sz, jmptbl_off, &jmpptr)) {
			break;
		}
		if (anal->limit) {
			if (jmpptr < anal->limit->from || jmpptr > anal->limit->to) {
				break;
			}
		}
		const ut64 jmpptr_idx_off = casetbl_loc + case_idx;
		r_meta_set_data_at (anal, jmpptr_idx_off, 1);
		r_anal_hint_set_immbase (anal, jmpptr_idx_off, 10);
		if (!is_valid_jmptbl_case_target (anal, &target_ctx, jmpptr)) {
			continue;
		}

		int casenum = case_idx + start_casenum_shift;
		apply_case (anal, fcn, block, ip, jmptbl_loc == jmptbl_off? 1: sz, jmpptr, casenum, jmptbl_loc == jmptbl_off? casetbl_loc + case_idx: jmptbl_loc + jmpptr_idx * sz, false);
		analyze_new_case (anal, fcn, block, ip, jmpptr, depth);
	}

	if (case_idx > 0) {
		if (default_case == 0) {
			default_case = UT64_MAX;
		}
		apply_switch (anal, fcn, block, ip, jmptbl_loc == jmptbl_off? casetbl_loc: jmptbl_loc, case_idx, default_case, jmptbl_loc == jmptbl_off? 1: sz);
	}

	free (jmptbl);
	free (casetbl);
	jmptbl_target_ctx_fini (&target_ctx);
	return ret;
}

R_API bool r_anal_jmptbl_walk(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0) {
	bool ret = ret0;
	ut64 default_target = default_case;
	JmptblTargetCtx target_ctx = { 0 };
	// jmptbl_size can not always be determined
	if (jmptbl_size == 0) {
		jmptbl_size = R_ANAL_SWITCH_MAXCASES;
	}
	if (jmptbl_loc == UT64_MAX) {
		R_LOG_DEBUG ("Invalid JumpTable location 0x%08" PFMT64x, jmptbl_loc);
		return false;
	}
	if (jmptbl_size < 1 || jmptbl_size > ST32_MAX) {
		R_LOG_DEBUG ("Invalid JumpTable size at 0x%08" PFMT64x, ip);
		return false;
	}
	ut64 jmpptr, offs;
	const ut64 jmptblsz = jmptbl_size * sz;
	if (jmptblsz < 1 || jmptblsz > ST32_MAX) {
		R_LOG_DEBUG ("Invalid jump table size at 0x%08" PFMT64x, jmptbl_loc);
		return false;
	}
	ut8 *jmptbl = calloc (jmptbl_size, sz);
	if (!jmptbl) {
		return false;
	}
	JmptblArch a;
	if (!jmptbl_detect_arch (anal, &a)) {
		free (jmptbl);
		return false;
	}
	jmptbl_target_ctx_init (&target_ctx, anal, ip);
	// eprintf ("JMPTBL AT 0x%"PFMT64x"\n", jmptbl_loc);
	anal->iob.read_at (anal->iob.io, jmptbl_loc, jmptbl, jmptblsz);
	for (offs = 0; offs + sz - 1 < jmptblsz; offs += sz) {
		switch (sz) {
		case 1:
			jmpptr = r_read_le8 (jmptbl + offs);
			break;
		case 2:
			jmpptr = r_read_le16 (jmptbl + offs);
			break;
		case 8:
			jmpptr = r_read_le64 (jmptbl + offs);
			break;
		default:
			jmpptr = r_read_le32 (jmptbl + offs);
			break;
		}
		if (a.arm && anal->config->bits == 64 && ip > 4096 && jmpptr < 4096 && jmpptr < ip) {
			jmpptr += ip;
		}
		// if we don't check for 0 here, the next check with ptr+jmpptr
		// will obviously be a good offset since it will be the start
		// of the table, which is not what we want
		if (jmpptr == 0 || jmpptr == UT32_MAX || jmpptr == UT64_MAX) {
			break;
		}
		if (!jmptbl_fixup_jmpptr (anal, &a, ip, sz, jmptbl_off, &jmpptr)) {
			break;
		}
		if (anal->limit) {
			if (jmpptr < anal->limit->from || jmpptr > anal->limit->to) {
				break;
			}
		}
		r_meta_set_data_at (anal, jmptbl_loc + offs, sz);
		r_anal_hint_set_immbase (anal, jmptbl_loc + offs, 10);
		if (!is_valid_jmptbl_case_target (anal, &target_ctx, jmpptr)) {
			continue;
		}
		int case_idx = offs / sz;
		int casenum = case_idx + start_casenum_shift;
		apply_case (anal, fcn, block, ip, sz, jmpptr, casenum, jmptbl_loc + offs, false);
		analyze_new_case (anal, fcn, block, ip, jmpptr, depth);
	}
	if (a.mips) {
		// default case for mips is right after the 'jr v0' instruction unless specified otherwise
		ut64 mips_default = default_target != UT64_MAX? default_target: ip + 8;
		apply_case (anal, fcn, block, ip, sz, mips_default, -1, jmptbl_loc + offs, false);
		analyze_new_case (anal, fcn, block, ip, mips_default, depth);
		default_target = mips_default;
	}

	if (offs > 0) {
		if (default_target == 0) {
			default_target = UT64_MAX;
		}
		apply_switch (anal, fcn, block, ip, jmptbl_loc, offs / sz, default_target, sz);
	}

	free (jmptbl);
	jmptbl_target_ctx_fini (&target_ctx);
	return ret;
}

static bool detect_casenum_shift(RAnalOp *op, const char **cmp_reg, st64 *start_casenum_shift) {
	if (!*cmp_reg) {
		return true;
	}
	RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
	RAnalValue *src = RVecRArchValue_at (&op->srcs, 0);
	if (dst && dst->reg && !strcmp (dst->reg, *cmp_reg)) {
		if (op->type == R_ANAL_OP_TYPE_LEA && op->ptr == UT64_MAX) {
			*start_casenum_shift = - (st64)op->disp;
		} else if (op->val != UT64_MAX) {
			if (op->type == R_ANAL_OP_TYPE_ADD) {
				*start_casenum_shift = - (st64)op->val;
			} else if (op->type == R_ANAL_OP_TYPE_SUB) {
				*start_casenum_shift = op->val;
			}
		} else if (op->type == R_ANAL_OP_TYPE_MOV) {
			*cmp_reg = src->reg;
			return false;
		}
		return true;
	}
	return false;
}

R_API bool try_get_delta_jmptbl_info(RAnal *anal, RAnalFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift) {
	if (lea_addr > jmp_addr) {
		return false;
	}
	int search_sz = jmp_addr - lea_addr;
	ut8 *buf = malloc (search_sz);
	if (!buf) {
		return false;
	}
	bool isValid = false;
	RVecUT64 v;
	RVecUT64_init (&v);
	RAnalOp tmp_aop = { 0 };
	// search for a cmp register with a reasonable size
	if (!anal->iob.read_at (anal->iob.io, lea_addr, buf, search_sz)) {
		R_LOG_ERROR ("Cannot read at 0x%08" PFMT64x, lea_addr);
		goto out;
	}

	bool foundCmp = false;
	int len = 0;
	const char *cmp_reg = NULL;
	ut64 cmp_val = 0;
	ut64 i;
	for (i = 0; i + 8 < search_sz; i += len) {
		len = r_anal_op (anal, &tmp_aop, lea_addr + i, buf + i, search_sz - i, R_ARCH_OP_MASK_BASIC);
		if (len < 1) {
			len = 1;
		}

		if (foundCmp) {
			if (tmp_aop.type != R_ANAL_OP_TYPE_CJMP) {
				r_anal_op_fini (&tmp_aop);
				continue;
			}
			// pick the fall-through edge as default when the jump targets the table dispatcher
			const ut64 fallthrough = lea_addr + i + len;
			*default_case = (tmp_aop.jump == fallthrough)? tmp_aop.fail: tmp_aop.jump;
			if (tmp_aop.cond == R_ANAL_CONDTYPE_HI) {
				*table_size = cmp_val;
			}
			r_anal_op_fini (&tmp_aop);
			break;
		}

		ut32 type = tmp_aop.type & R_ANAL_OP_TYPE_MASK;
		if (type != R_ANAL_OP_TYPE_CMP) {
			r_anal_op_fini (&tmp_aop);
			continue;
		}
		// get the value of the cmp
		// for operands in op, check if type is immediate and val is sane
		// TODO: How? opex?

		// for the time being, this seems to work
		// might not actually have a value, let the next step figure out the size then
		if (tmp_aop.val == UT64_MAX && tmp_aop.refptr == 0) {
			isValid = true;
			*table_size = 0;
			cmp_val = 0;
		} else if (tmp_aop.refptr == 0) {
			isValid = tmp_aop.val < 0x200;
			*table_size = tmp_aop.val + 1;
			cmp_val = tmp_aop.val;
		} else {
			isValid = tmp_aop.refptr < 0x200;
			*table_size = tmp_aop.refptr + 1;
			cmp_val = tmp_aop.refptr;
		}
		RVecUT64_push_back (&v, &i);
		r_anal_op (anal, &tmp_aop, lea_addr + i, buf + i, search_sz - i, R_ARCH_OP_MASK_VAL);
		RAnalValue *tmp_src = RVecRArchValue_at (&tmp_aop.srcs, 0);
		RAnalValue *tmp_dst = RVecRArchValue_at (&tmp_aop.dsts, 0);
		if (tmp_dst && tmp_dst->reg) {
			cmp_reg = tmp_dst->reg;
		} else if (tmp_aop.reg) {
			cmp_reg = tmp_aop.reg;
		} else if (tmp_src && tmp_src->reg) {
			cmp_reg = tmp_src->reg;
		}
		r_anal_op_fini (&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		foundCmp = true;
	}
	if (isValid) {
		*start_casenum_shift = 0;
		ut64 *it;
		R_VEC_FOREACH_PREV (&v, it) {
			const ut64 op_off = *it;
			ut64 op_addr = lea_addr + op_off;
			r_anal_op (anal, &tmp_aop, op_addr, buf + op_off, search_sz - op_off, R_ARCH_OP_MASK_VAL);
			if (detect_casenum_shift (&tmp_aop, &cmp_reg, start_casenum_shift)) {
				r_anal_op_fini (&tmp_aop);
				break;
			}
			r_anal_op_fini (&tmp_aop);
		}
	}
out:
	RVecUT64_fini (&v);
	free (buf);
	return isValid;
}

// TODO: find a better function name
R_API int walkthrough_arm_jmptbl_style(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 sz, ut64 jmptbl_size, ut64 default_case, int ret0) {
	/*
	 * Example about arm jump table
	 *
	 * 0x000105b4      060050e3       cmp r0, 3
	 * 0x000105b8      00f18f90       addls pc, pc, r0, lsl 2
	 * 0x000105bc      0d0000ea       b loc.000105f8
	 * 0x000105c0      050000ea       b 0x105dc
	 * 0x000105c4      050000ea       b 0x105e0
	 * 0x000105c8      060000ea       b 0x105e8
	 * ; CODE XREF from loc._a_7 (+0x10)
	 * 0x000105dc      b6ffffea       b sym.input_1
	 * ; CODE XREF from loc._a_7 (+0x14)
	 * 0x000105e0      b9ffffea       b sym.input_2
	 * ; CODE XREF from loc._a_7 (+0x28)
	 * 0x000105e4      ccffffea       b sym.input_7
	 * ; CODE XREF from loc._a_7 (+0x18)
	 * 0x000105e8      bbffffea       b sym.input_3
	 */

	ut64 offs, jmpptr;
	int ret = ret0;
	JmptblTargetCtx target_ctx = { 0 };
	jmptbl_target_ctx_init (&target_ctx, anal, ip);

	if (jmptbl_size == 0) {
		jmptbl_size = R_ANAL_SWITCH_MAXCASES;
	}

	for (offs = 0; offs + sz - 1 < jmptbl_size * sz; offs += sz) {
		jmpptr = jmptbl_loc + offs;
		if (!is_valid_jmptbl_case_target (anal, &target_ctx, jmpptr)) {
			continue;
		}
		apply_case (anal, fcn, block, ip, sz, jmpptr, offs / sz, jmptbl_loc + offs, true);
		analyze_new_case (anal, fcn, block, ip, jmpptr, depth);
	}

	if (offs > 0) {
		if (default_case == 0 || default_case == UT32_MAX) {
			default_case = UT64_MAX;
		}
		apply_switch (anal, fcn, block, ip, jmptbl_loc, offs / sz, default_case, sz);
	}
	jmptbl_target_ctx_fini (&target_ctx);
	return ret;
}

R_API bool try_get_jmptbl_info(RAnal *anal, RAnalFunction *fcn, ut64 addr, RAnalBlock *my_bb, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift) {
	bool isValid = false;
	int i;
	RListIter *iter;
	RAnalBlock *tmp_bb, *prev_bb;
	prev_bb = 0;
	if (!fcn->bbs) {
		return false;
	}

	/* if UJMP is in .plt section just skip it */
	RBinSection *s = anal->binb.get_vsect_at (anal->binb.bin, addr);
	if (s && s->name[0]) {
		bool in_plt = strstr (s->name, ".plt");
		if (!in_plt && strstr (s->name, "_stubs")) {
			/* for mach0 */
			in_plt = true;
		}
		if (in_plt) {
			return false;
		}
	}

	// search for the predecessor bb
	r_list_foreach (fcn->bbs, iter, tmp_bb) {
		if (tmp_bb->jump == my_bb->addr || tmp_bb->fail == my_bb->addr) {
			prev_bb = tmp_bb;
			break;
		}
	}
	// predecessor must be a conditional jump
	if (!prev_bb || !prev_bb->jump || !prev_bb->fail) {
		R_LOG_DEBUG ("[anal.jmptbl] Missing predecesessor cjmp bb at 0x%08" PFMT64x, addr);
		return false;
	}

	// default case is the jump target of the unconditional jump
	*default_case = prev_bb->jump == my_bb->addr? prev_bb->fail: prev_bb->jump;

	RAnalHint *hint = r_anal_hint_get (anal, addr);
	if (hint) {
		ut64 val = hint->val;
		r_anal_hint_free (hint);
		if (val != UT64_MAX) {
			*table_size = val;
			return true;
		}
	}

	RAnalOp tmp_aop = { 0 };
	ut8 *bb_buf = calloc (1, prev_bb->size);
	if (!bb_buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	anal->iob.read_at (anal->iob.io, prev_bb->addr, (ut8 *)bb_buf, prev_bb->size);
	isValid = false;

	const char *cmp_reg = NULL;
	ut64 cmp_val = 0;
	for (i = prev_bb->ninstr - 1; i >= 0; i--) {
		const ut64 prev_pos = r_anal_bb_offset_inst (prev_bb, i);
		const ut64 op_addr = r_anal_bb_opaddr_i (prev_bb, i);
		if (prev_pos >= prev_bb->size) {
			continue;
		}
		int buflen = prev_bb->size - prev_pos;
		int len = r_anal_op (anal, &tmp_aop, op_addr, bb_buf + prev_pos, buflen, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
		ut32 type = tmp_aop.type & R_ANAL_OP_TYPE_MASK;
		if (len < 1 || type != R_ANAL_OP_TYPE_CMP) {
			r_anal_op_fini (&tmp_aop);
			continue;
		}
		// get the value of the cmp
		// for operands in op, check if type is immediate and val is sane
		// TODO: How? opex?

		// for the time being, this seems to work
		// might not actually have a value, let the next step figure out the size then
		if (tmp_aop.val == UT64_MAX && tmp_aop.refptr == 0) {
			isValid = true;
			*table_size = 0;
			cmp_val = 0;
		} else if (tmp_aop.refptr == 0 || tmp_aop.val != UT64_MAX) {
			isValid = tmp_aop.val < 0x200;
			*table_size = tmp_aop.val + 1;
			cmp_val = tmp_aop.val;
		} else {
			isValid = tmp_aop.refptr < 0x200;
			*table_size = tmp_aop.refptr + 1;
			cmp_val = tmp_aop.refptr;
		}
		if (tmp_aop.cond == R_ANAL_CONDTYPE_HI) {
			*table_size = cmp_val;
			r_anal_op_fini (&tmp_aop);
			break;
		}
		if (isValid) {
			r_anal_op_fini (&tmp_aop);
			r_anal_op (anal, &tmp_aop, op_addr, bb_buf + prev_pos, buflen, R_ARCH_OP_MASK_VAL);
			RAnalValue *tmp_dst = RVecRArchValue_at (&tmp_aop.dsts, 0);
			RAnalValue *tmp_src = RVecRArchValue_at (&tmp_aop.srcs, 0);
			if (tmp_dst && tmp_dst->reg) {
				cmp_reg = tmp_dst->reg;
			} else if (tmp_aop.reg) {
				cmp_reg = tmp_aop.reg;
			} else if (tmp_src && tmp_src->reg) {
				cmp_reg = tmp_src->reg;
			}
		}
		r_anal_op_fini (&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		break;
	}
	if (isValid) {
		*start_casenum_shift = 0;
		for (i--; i >= 0; i--) {
			const ut64 prev_pos = r_anal_bb_offset_inst (prev_bb, i);
			const ut64 op_addr = r_anal_bb_opaddr_i (prev_bb, i);
			if (prev_pos >= prev_bb->size) {
				continue;
			}
			int buflen = prev_bb->size - prev_pos;
			r_anal_op (anal, &tmp_aop, op_addr, bb_buf + prev_pos, buflen, R_ARCH_OP_MASK_VAL);
			if (detect_casenum_shift (&tmp_aop, &cmp_reg, start_casenum_shift)) {
				r_anal_op_fini (&tmp_aop);
				break;
			}

			r_anal_op_fini (&tmp_aop);
		}
	}
	free (bb_buf);
	// eprintf ("switch at 0x%" PFMT64x "\n\tdefault case 0x%" PFMT64x "\n\t#cases: %d\n",
	// 		addr,
	// 		*default_case,
	// 		*table_size);
	return isValid;
}

R_API void r_anal_jmptbl_list(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb, ut64 saddr, ut64 jaddr, RList *cases, int loadsz) {
	RAnalCaseOp *kase;
	RListIter *iter;
	SetU *s = set_u_new ();
	r_list_foreach (cases, iter, kase) {
		if (set_u_contains (s, kase->jump)) {
			continue;
		}
		apply_case (anal, fcn, bb, saddr, loadsz, kase->jump, kase->value, kase->jump, true);
		set_u_add (s, kase->jump);
		// 	eprintf ("%d %llx -> 0x%llx\n", i, saddr, kase->jump);
		analyze_new_case (anal, fcn, bb, saddr, kase->jump, 999);
	}
	apply_switch (anal, fcn, bb, saddr, jaddr, r_list_length (cases), UT64_MAX, loadsz);
	set_u_free (s);
}

R_IPI bool r_anal_jmptbl_arm64_from_br(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb, int depth, RAnalOp *op, int loadsize) {
	if (!anal || !op || !op->reg || !anal->leaddrs) {
		return false;
	}
	if (loadsize != 1 && loadsize != 2 && loadsize != 4) {
		return false;
	}
	ut64 opaddr = UT64_MAX, basptr = UT64_MAX, tblptr = UT64_MAX;
	if (!arm64_resolve_dispatch (anal, anal->leaddrs, op->addr, op->reg, &opaddr, &basptr, &tblptr)) {
		return false;
	}
	// anal->cmpval can be stale (clobbered by another branch of the
	// function that was analysed first); when the predecessor-bb walker
	// yields a clearly larger count, trust that one instead.
	ut64 table_size = anal->cmpval;
	ut64 alt_size = 0, alt_default = 0;
	st64 alt_shift = 0;
	if (try_get_jmptbl_info (anal, fcn, op->addr, bb, &alt_size, &alt_default, &alt_shift) && alt_size > anal->cmpval + 1) {
		table_size = alt_size;
	}
	if (table_size == 0 || table_size == UT64_MAX) {
		return false;
	}
	const size_t table_bytes = R_MIN ((size_t)table_size * loadsize, 4096);
	ut8 *table = calloc (1, table_bytes);
	if (!table) {
		return false;
	}
	if (!anal->iob.read_at (anal->iob.io, tblptr, table, table_bytes)) {
		free (table);
		return false;
	}
	RList *kases = r_list_newf (free);
	const size_t max = table_bytes / loadsize;
	size_t i;
	for (i = 0; i < max; i++) {
		st64 delta;
		ut64 caseaddr;
		switch (loadsize) {
		case 1:
			delta = ((st8 *)table)[i];
			caseaddr = basptr + (delta << 2);
			break;
		case 2:
			delta = (st16)r_read_le16 (table + i * 2);
			caseaddr = basptr + (delta << 1);
			break;
		default:
			delta = (st32)r_read_le32 (table + i * 4);
			caseaddr = basptr + delta;
			break;
		}
		if (!anal->iob.is_valid_offset (anal->iob.io, caseaddr, 0)) {
			continue;
		}
		RAnalCaseOp *kase = R_NEW0 (RAnalCaseOp);
		kase->addr = caseaddr;
		kase->jump = caseaddr;
		kase->value = i;
		r_list_append (kases, kase);
	}
	r_anal_jmptbl_list (anal, fcn, bb, opaddr, tblptr, kases, loadsize);
	r_list_free (kases);
	free (table);
	return true;
}

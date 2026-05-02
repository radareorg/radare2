/* radare - LGPL - Copyright 2010-2026 - pancake */

#include <r_anal.h>
#include <r_anal_priv.h>

#define JMPTBL_DISPATCH_LOOKBACK 16
#define SWITCH_SDB_NS "switches"

typedef struct {
	RIOMap *switch_map;
	HtUP *validated_targets;
	HtUP *analyzed_targets;
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
	char add_s0[32] = { 0 };
	char add_s1[32] = { 0 };
	char table_reg[32] = { 0 };
	char load_reg[32] = { 0 };
	ut64 add_addr = UT64_MAX;
	ut64 load_addr = UT64_MAX;
	bool found_add = false;
	int i;
	for (i = JMPTBL_DISPATCH_LOOKBACK - 1; i >= 0; i--) {
		RAnalOp op = { 0 };
		bool stop = false;
		if (r_anal_op (anal, &op, scan_base + i * 4, buf + i * 4, 4, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL) > 0) {
			const ut32 type = op.type & R_ANAL_OP_TYPE_MASK;
			if (found_add) {
				if (type == R_ANAL_OP_TYPE_LOAD) {
					RAnalValue *ld = RVecRArchValue_at (&op.dsts, 0);
					RAnalValue *ls = RVecRArchValue_at (&op.srcs, 0);
					if (ld && ld->reg && ls && ls->reg && ((*add_s0 && !strcmp (add_s0, ld->reg)) || (*add_s1 && !strcmp (add_s1, ld->reg)))) {
						r_str_ncpy (load_reg, ld->reg, sizeof (load_reg));
						r_str_ncpy (table_reg, ls->reg, sizeof (table_reg));
						load_addr = scan_base + i * 4;
						stop = true;
					}
				}
			} else if (type == R_ANAL_OP_TYPE_ADD) {
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
					found_add = true;
					stop = !*add_s0 && !*add_s1;
				}
			}
		}
		r_anal_op_fini (&op);
		if (stop) {
			break;
		}
	}
	if (!found_add || (!*add_s0 && !*add_s1)) {
		return false;
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
	ctx->analyzed_targets = ht_up_new0 ();
}

static void jmptbl_target_ctx_fini(JmptblTargetCtx *ctx) {
	ht_up_free (ctx->validated_targets);
	ht_up_free (ctx->analyzed_targets);
	ctx->validated_targets = NULL;
	ctx->analyzed_targets = NULL;
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

static inline bool jmptbl_entry_size_ok(ut64 sz) {
	return sz == 1 || sz == 2 || sz == 4 || sz == 8;
}

static bool jmptbl_table_bytes(ut64 entries, ut64 sz, ut64 *bytes) {
	if (!jmptbl_entry_size_ok (sz) || entries < 1 || entries > ST32_MAX) {
		return false;
	}
	return !r_mul_overflow (entries, sz, bytes) && *bytes > 0 && *bytes <= ST32_MAX;
}

static ut8 *jmptbl_read_table(RAnal *anal, ut64 addr, ut64 entries, ut64 sz, ut64 *bytes) {
	ut64 table_bytes;
	if (jmptbl_table_bytes (entries, sz, &table_bytes)) {
		ut8 *table = malloc (table_bytes);
		if (table) {
			if (anal->iob.read_at (anal->iob.io, addr, table, table_bytes)) {
				if (bytes) {
					*bytes = table_bytes;
				}
				return table;
			}
			free (table);
		}
	}
	return NULL;
}

typedef enum {
	SWITCH_TARGET_STOP,
	SWITCH_TARGET_SKIP,
	SWITCH_TARGET_OK,
} SwitchTargetResult;

// Compute the target address for a single jump-table entry
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

static void analyze_new_case_once(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, JmptblTargetCtx *ctx, ut64 ip, ut64 jmpptr, int depth) {
	if (ht_up_find_kv (ctx->analyzed_targets, jmpptr, NULL)) {
		return;
	}
	ht_up_insert (ctx->analyzed_targets, jmpptr, (void *)1);
	analyze_new_case (anal, fcn, block, ip, jmpptr, depth);
}

static bool function_has_ret_between(RAnal *anal, RAnalFunction *fcn, ut64 from, ut64 to) {
	if (!anal || !fcn || !fcn->bbs || to <= from) {
		return false;
	}
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->ninstr < 1) {
			continue;
		}
		const ut64 addr = r_anal_bb_opaddr_i (bb, bb->ninstr - 1);
		if (addr <= from || addr >= to) {
			continue;
		}
		ut8 buf[32];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			continue;
		}
		RAnalOp op = { 0 };
		const int len = r_anal_op (anal, &op, addr, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
		const ut32 type = op.type & R_ANAL_OP_TYPE_MASK;
		r_anal_op_fini (&op);
		if (len > 0 && type == R_ANAL_OP_TYPE_RET) {
			return true;
		}
	}
	return false;
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
	const ut8 esize = spec->esize? spec->esize: 4;
	ut8 *jmptbl = jmptbl_read_table (anal, spec->jtbl_addr, ncases, esize, NULL);
	if (!jmptbl) {
		R_LOG_DEBUG ("Invalid jump table size at 0x%08" PFMT64x, spec->jtbl_addr);
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
		vtbl = jmptbl_read_table (anal, spec->vtbl_addr, ncases, vsize, NULL);
		if (!vtbl) {
			free (jmptbl);
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
		analyze_new_case_once (anal, fcn, block, &target_ctx, spec->startea, jmpptr, depth);
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
			spec->startea,
			(unsigned)R_ANAL_SWITCH_MAXCASES);
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

typedef enum {
	JMPTBL_WALK_STOP,
	JMPTBL_WALK_SKIP,
	JMPTBL_WALK_APPLY,
} JmptblWalkResult;

static JmptblWalkResult jmptbl_apply_legacy_case(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, JmptblTargetCtx *target_ctx, const JmptblArch *a, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_off, ut64 sz, ut64 jmpptr, ut64 case_idx, ut64 meta_loc, ut64 meta_sz, ut64 case_addr_loc, ut64 case_addr_sz, bool arm64_ip_relative) {
	if (arm64_ip_relative && a->arm && anal->config->bits == 64 && ip > 4096 && jmpptr < 4096 && jmpptr < ip) {
		jmpptr += ip;
	}
	// if we don't check for 0 here, the next check with ptr+jmpptr
	// will obviously be a good offset since it will be the start
	// of the table, which is not what we want
	if (jmpptr == 0 || jmpptr == UT32_MAX || jmpptr == UT64_MAX) {
		return JMPTBL_WALK_STOP;
	}
	if (!jmptbl_fixup_jmpptr (anal, a, ip, sz, jmptbl_off, &jmpptr)) {
		return JMPTBL_WALK_STOP;
	}
	if (anal->limit && (jmpptr < anal->limit->from || jmpptr > anal->limit->to)) {
		return JMPTBL_WALK_STOP;
	}
	r_meta_set_data_at (anal, meta_loc, meta_sz);
	r_anal_hint_set_immbase (anal, meta_loc, 10);
	if (!is_valid_jmptbl_case_target (anal, target_ctx, jmpptr)) {
		return JMPTBL_WALK_SKIP;
	}
	int casenum = case_idx + start_casenum_shift;
	apply_case (anal, fcn, block, ip, case_addr_sz, jmpptr, casenum, case_addr_loc, false);
	analyze_new_case_once (anal, fcn, block, target_ctx, ip, jmpptr, depth);
	return JMPTBL_WALK_APPLY;
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
	ut8 *jmptbl = jmptbl_read_table (anal, jmptbl_loc, jmptbl_size, sz, NULL);
	if (!jmptbl) {
		return false;
	}
	ut8 *casetbl = jmptbl_read_table (anal, casetbl_loc, jmptbl_size, 1, NULL);
	if (!casetbl) {
		free (jmptbl);
		return false;
	}
	JmptblArch a;
	if (!jmptbl_detect_arch (anal, &a)) {
		free (jmptbl);
		free (casetbl);
		return false;
	}
	jmptbl_target_ctx_init (&target_ctx, anal, ip);
	ut64 case_idx;
	for (case_idx = 0; case_idx < jmptbl_size; case_idx++) {
		const ut64 jmpptr_idx = casetbl[case_idx];
		if (jmpptr_idx >= jmptbl_size) {
			ret = false;
			break;
		}
		const ut64 entry_off = jmpptr_idx * sz;
		const ut64 case_addr_sz = jmptbl_loc == jmptbl_off? 1: sz;
		const ut64 case_addr_loc = jmptbl_loc == jmptbl_off? casetbl_loc + case_idx: jmptbl_loc + entry_off;
		const ut64 jmpptr = switch_read_entry (jmptbl + entry_off, (ut8)sz, false);
		JmptblWalkResult walk = jmptbl_apply_legacy_case (anal, fcn, block, &target_ctx, &a, depth, ip, start_casenum_shift, jmptbl_off, sz, jmpptr, case_idx, casetbl_loc + case_idx, 1, case_addr_loc, case_addr_sz, false);
		if (walk == JMPTBL_WALK_STOP) {
			break;
		}
		ret |= walk == JMPTBL_WALK_APPLY;
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
	const bool autosize = jmptbl_size == 0;
	// jmptbl_size can not always be determined
	if (jmptbl_size == 0) {
		jmptbl_size = R_ANAL_SWITCH_MAXCASES;
	}
	if (jmptbl_loc == UT64_MAX) {
		R_LOG_DEBUG ("Invalid JumpTable location 0x%08" PFMT64x, jmptbl_loc);
		return false;
	}
	ut8 *jmptbl = jmptbl_read_table (anal, jmptbl_loc, jmptbl_size, sz, NULL);
	if (!jmptbl) {
		R_LOG_DEBUG ("Invalid jump table size at 0x%08" PFMT64x, jmptbl_loc);
		return false;
	}
	JmptblArch a;
	if (!jmptbl_detect_arch (anal, &a)) {
		free (jmptbl);
		return false;
	}
	jmptbl_target_ctx_init (&target_ctx, anal, ip);
	ut64 case_idx;
	for (case_idx = 0; case_idx < jmptbl_size; case_idx++) {
		const ut64 offs = case_idx * sz;
		const ut64 jmpptr = switch_read_entry (jmptbl + offs, (ut8)sz, false);
		ut64 autosize_target = UT64_MAX;
		if (autosize && sz == 4 && !anal->iob.is_valid_offset (anal->iob.io, jmpptr, 0)) {
			autosize_target = jmptbl_off + (st32)jmpptr;
		}
		if (autosize_target != UT64_MAX && case_idx > 0 && function_has_ret_between (anal, fcn, ip, autosize_target)) {
			break;
		}
		JmptblWalkResult walk = jmptbl_apply_legacy_case (anal, fcn, block, &target_ctx, &a, depth, ip, start_casenum_shift, jmptbl_off, sz, jmpptr, case_idx, jmptbl_loc + offs, sz, jmptbl_loc + offs, sz, true);
		if (walk == JMPTBL_WALK_STOP) {
			break;
		}
		ret |= walk == JMPTBL_WALK_APPLY;
	}
	const ut64 stop_off = case_idx * sz;
	if (a.mips) {
		// default case for mips is right after the 'jr v0' instruction unless specified otherwise
		ut64 mips_default = default_target != UT64_MAX? default_target: ip + 8;
		apply_case (anal, fcn, block, ip, sz, mips_default, -1, jmptbl_loc + stop_off, false);
		analyze_new_case_once (anal, fcn, block, &target_ctx, ip, mips_default, depth);
		default_target = mips_default;
		ret = true;
	}

	if (case_idx > 0) {
		if (default_target == 0) {
			default_target = UT64_MAX;
		}
		apply_switch (anal, fcn, block, ip, jmptbl_loc, case_idx, default_target, sz);
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

static bool jmptbl_cmp_info(RAnalOp *op, bool prefer_refptr, ut64 *table_size, ut64 *cmp_val, const char **cmp_reg) {
	if (cmp_reg) {
		RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
		RAnalValue *src = RVecRArchValue_at (&op->srcs, 0);
		if (dst && dst->reg) {
			*cmp_reg = dst->reg;
		} else if (op->reg) {
			*cmp_reg = op->reg;
		} else if (src && src->reg) {
			*cmp_reg = src->reg;
		}
	}
	if (op->val == UT64_MAX && op->refptr == 0) {
		*table_size = 0;
		*cmp_val = 0;
		return true;
	}
	const bool use_refptr = prefer_refptr
		? op->refptr != 0
		: op->refptr != 0 && op->val == UT64_MAX;
	const ut64 value = use_refptr? op->refptr: op->val;
	*table_size = value + 1;
	*cmp_val = value;
	return value < 0x200;
}

static bool cmp_bound_reg(RAnalOp *op, char *reg, size_t regsz) {
	RAnalValue *src0 = RVecRArchValue_at (&op->srcs, 0);
	RAnalValue *src1 = RVecRArchValue_at (&op->srcs, 1);
	const char *name = (src1 && src1->reg && src1->type != R_ANAL_VAL_MEM && !src1->memref)? src1->reg
		: (src0 && src0->reg && src0->type != R_ANAL_VAL_MEM && !src0->memref)? src0->reg
		: op->reg;
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	r_str_ncpy (reg, name, regsz);
	return true;
}

static bool backtrack_small_bound(RAnal *anal, RAnalBlock *bb, ut8 *bb_buf, int from, const char *reg, ut64 *cmp_val) {
	char bound_reg[32];
	if (R_STR_ISEMPTY (reg)) {
		return false;
	}
	r_str_ncpy (bound_reg, reg, sizeof (bound_reg));
	RAnalOp op = { 0 };
	int i;
	for (i = from; i >= 0; i--) {
		const ut64 pos = r_anal_bb_offset_inst (bb, i);
		const ut64 op_addr = r_anal_bb_opaddr_i (bb, i);
		if (pos >= bb->size) {
			continue;
		}
		const int buflen = bb->size - pos;
		if (r_anal_op (anal, &op, op_addr, bb_buf + pos, buflen, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL) < 1) {
			r_anal_op_fini (&op);
			continue;
		}
		RAnalValue *dst = RVecRArchValue_at (&op.dsts, 0);
		RAnalValue *src = RVecRArchValue_at (&op.srcs, 0);
		const char *dst_reg = (dst && dst->reg)? dst->reg: op.reg;
		if (!dst_reg || strcmp (dst_reg, bound_reg)) {
			r_anal_op_fini (&op);
			continue;
		}
		const ut32 type = op.type & R_ANAL_OP_TYPE_MASK;
		if (type == R_ANAL_OP_TYPE_LEA && op.disp > 0 && op.disp < 0x200) {
			*cmp_val = op.disp;
			r_anal_op_fini (&op);
			return true;
		}
		if ((type == R_ANAL_OP_TYPE_ADD || type == R_ANAL_OP_TYPE_MOV) && op.val != UT64_MAX && op.val < 0x200) {
			*cmp_val = op.val;
			r_anal_op_fini (&op);
			return true;
		}
		if (type == R_ANAL_OP_TYPE_MOV && src && src->reg) {
			r_str_ncpy (bound_reg, src->reg, sizeof (bound_reg));
			r_anal_op_fini (&op);
			continue;
		}
		r_anal_op_fini (&op);
		return false;
	}
	return false;
}

R_API bool try_get_delta_jmptbl_info(RAnal *anal, RAnalFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift) {
	if (lea_addr > jmp_addr) {
		return false;
	}
	const ut64 search_sz64 = jmp_addr - lea_addr;
	if (search_sz64 < 9 || search_sz64 > ST32_MAX) {
		return false;
	}
	const int search_sz = (int)search_sz64;
	ut8 *buf = malloc (search_sz);
	if (!buf) {
		return false;
	}
	bool isValid = false;
	RAnalOp tmp_aop = { 0 };
	// search for a cmp register with a reasonable size
	if (!anal->iob.read_at (anal->iob.io, lea_addr, buf, search_sz)) {
		R_LOG_ERROR ("Cannot read at 0x%08" PFMT64x, lea_addr);
		free (buf);
		return false;
	}

	bool foundCmp = false;
	int len = 0;
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
		isValid = jmptbl_cmp_info (&tmp_aop, true, table_size, &cmp_val, NULL);
		r_anal_op_fini (&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		foundCmp = true;
	}
	if (isValid) {
		*start_casenum_shift = 0;
	}
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

	int ret = ret0;
	JmptblTargetCtx target_ctx = { 0 };
	jmptbl_target_ctx_init (&target_ctx, anal, ip);

	if (jmptbl_size == 0) {
		jmptbl_size = R_ANAL_SWITCH_MAXCASES;
	}

	ut64 jmptblsz;
	if (!jmptbl_table_bytes (jmptbl_size, sz, &jmptblsz)) {
		jmptbl_target_ctx_fini (&target_ctx);
		return false;
	}
	ut64 case_idx;
	for (case_idx = 0; case_idx < jmptbl_size; case_idx++) {
		const ut64 offs = case_idx * sz;
		const ut64 jmpptr = jmptbl_loc + offs;
		if (!is_valid_jmptbl_case_target (anal, &target_ctx, jmpptr)) {
			continue;
		}
		apply_case (anal, fcn, block, ip, sz, jmpptr, case_idx, jmptbl_loc + offs, true);
		analyze_new_case_once (anal, fcn, block, &target_ctx, ip, jmpptr, depth);
		ret = true;
	}

	if (case_idx > 0) {
		if (default_case == 0 || default_case == UT32_MAX) {
			default_case = UT64_MAX;
		}
		apply_switch (anal, fcn, block, ip, jmptbl_loc, case_idx, default_case, sz);
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
	ut8 *bb_buf = malloc (prev_bb->size);
	if (!bb_buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	if (!anal->iob.read_at (anal->iob.io, prev_bb->addr, bb_buf, prev_bb->size)) {
		free (bb_buf);
		return false;
	}
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
		int len = r_anal_op (anal, &tmp_aop, op_addr, bb_buf + prev_pos, buflen, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_VAL);
		ut32 type = tmp_aop.type & R_ANAL_OP_TYPE_MASK;
		if (len < 1 || type != R_ANAL_OP_TYPE_CMP) {
			r_anal_op_fini (&tmp_aop);
			continue;
		}
		isValid = jmptbl_cmp_info (&tmp_aop, false, table_size, &cmp_val, &cmp_reg);
		if (isValid && tmp_aop.val == UT64_MAX) {
			char bound_reg[32];
			ut64 bound = UT64_MAX;
			if (cmp_bound_reg (&tmp_aop, bound_reg, sizeof (bound_reg))
					&& backtrack_small_bound (anal, prev_bb, bb_buf, i - 1, bound_reg, &bound)) {
				cmp_val = bound;
				const bool table_on_jump = prev_bb->jump == my_bb->addr;
				const bool equal_skips_table = prev_bb->cond
					&& ((table_on_jump && prev_bb->cond->type == R_ANAL_CONDTYPE_NE)
						|| (!table_on_jump && prev_bb->cond->type == R_ANAL_CONDTYPE_EQ));
				*table_size = equal_skips_table? bound: bound + 1;
			}
		}
		if (tmp_aop.cond == R_ANAL_CONDTYPE_HI) {
			*table_size = cmp_val;
			r_anal_op_fini (&tmp_aop);
			break;
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
	return isValid;
}

static void jmptbl_apply_caseop(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb, SetU *s, ut64 saddr, int loadsz, const RAnalCaseOp *kase) {
	if (set_u_contains (s, kase->jump)) {
		return;
	}
	apply_case (anal, fcn, bb, saddr, loadsz, kase->jump, kase->value, kase->jump, true);
	set_u_add (s, kase->jump);
	analyze_new_case (anal, fcn, bb, saddr, kase->jump, 999);
}

R_API void r_anal_jmptbl_list(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb, ut64 saddr, ut64 jaddr, RList *cases, int loadsz) {
	SetU *s = set_u_new ();
	RAnalCaseOp *kase;
	RListIter *iter;
	r_list_foreach (cases, iter, kase) {
		jmptbl_apply_caseop (anal, fcn, bb, s, saddr, loadsz, kase);
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
	const size_t max = (size_t)R_MIN (table_size, (ut64) (4096 / loadsize));
	ut8 *table = jmptbl_read_table (anal, tblptr, max, loadsize, NULL);
	if (!table) {
		return false;
	}
	const ut8 esize = (ut8)loadsize;
	const st64 delta_scale = loadsize == 1? 4: loadsize == 2? 2: 1;
	SetU *s = set_u_new ();
	size_t valid_cases = 0;
	size_t i;
	for (i = 0; i < max; i++) {
		const st64 delta = (st64)switch_read_entry (table + i * esize, esize, true);
		const ut64 caseaddr = basptr + (ut64)(delta * delta_scale);
		if (!anal->iob.is_valid_offset (anal->iob.io, caseaddr, 0)) {
			continue;
		}
		RAnalCaseOp kase = { 0 };
		kase.addr = caseaddr;
		kase.jump = caseaddr;
		kase.value = i;
		jmptbl_apply_caseop (anal, fcn, bb, s, opaddr, loadsize, &kase);
		valid_cases++;
	}
	apply_switch (anal, fcn, bb, opaddr, tblptr, valid_cases, UT64_MAX, loadsize);
	set_u_free (s);
	free (table);
	return true;
}
